"""Real bounded ADD-derived addresses, taints, rollback and boosting (no hardware).

GNU/ELF/Unicorn and the data generator are production components. Memory hooks
and wrappers around real rollback only observe execution; they do not supply it.
See arm64/README.add-address.md for the complete typed trace oracle and limits.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
import shutil
import struct
import tempfile
from typing import List, Tuple
import unittest
from unittest.mock import patch

import numpy as np
import unicorn as uc  # type: ignore[import-untyped]
import unicorn.arm64_const as ucc  # type: ignore[import-untyped]

from rvzr import factory
from rvzr.config import CONF
from rvzr.isa_spec import InstructionSet
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.tc_components.instruction import ImmediateOp, RegisterOp
from rvzr.tc_components.test_case_data import InputData, InputTaint
from rvzr.traces import CTrace, CTraceEntry
from tests.unit_arm64_contract_slice import software_environment
from tests.unit_arm64_conditional_contract import make_input, make_model


_ARM = Path(__file__).resolve().parent / "arm64"
_DATA, _CODE, _MAIN = 0x109000, 0x200000, 0x10a000
_U64 = (1 << 64) - 1
_PAIRS = ((0, 0), (128, 0), (0, 128), (64, 64))
_REGS = (ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1, ucc.UC_ARM64_REG_X2,
         ucc.UC_ARM64_REG_X3, ucc.UC_ARM64_REG_X4, ucc.UC_ARM64_REG_X5,
         ucc.UC_ARM64_REG_NZCV, ucc.UC_ARM64_REG_X20)
_Event = Tuple[int, int, int, int, bool]


def address_input(selector: int, left: int, right: int) -> InputData:
    input_ = make_input(selector)
    input_[0]["gpr"][1:3] = (left, right)
    return input_


def expected_trace(selector: int, offset: int, speculative: bool) -> List[CTraceEntry]:
    """Independent typed oracle: fixed instruction PCs plus bounded data addresses."""
    prefix = [CTraceEntry("pc", pc) for pc in (12, 16, 20, 24, 28)]
    fall = [CTraceEntry("pc", 32), CTraceEntry("pc", 36), CTraceEntry("mem", 4096),
            CTraceEntry("pc", 40), CTraceEntry("mem", 4096), CTraceEntry("pc", 44),
            CTraceEntry("pc", 48)]
    computed = [CTraceEntry("pc", 52), CTraceEntry("pc", 56),
                CTraceEntry("mem", 4096 + offset), CTraceEntry("pc", 60),
                CTraceEntry("mem", 4096 + offset), CTraceEntry("pc", 64)]
    join = [CTraceEntry("pc", 68), CTraceEntry("pc", 72)]
    correct, wrong = (computed, fall) if selector == 0 else (fall, computed)
    return prefix + (wrong + join + [CTraceEntry("pc", 84)] if speculative else []) \
        + correct + join


class ARM64AddAddressTest(unittest.TestCase):
    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(
            prefix="rvzr-arm64-add-address-")))
        stack.enter_context(software_environment(directory))
        CONF.model_max_spec_window = 32
        CONF.data_generator_entropy_bits = 8
        CONF.input_gen_probability_of_special_value = 0.0
        template = directory / "add-address.asm"
        shutil.copyfile(_ARM / "asm/add_address_contract.asm", template)
        isa = InstructionSet(str(_ARM / "min_arm64.json"))
        self.case = factory.get_program_generator(1, isa).create_test_case_from_template(
            str(template))

    def assert_taint(self, taint: InputTaint, computed_observed: bool) -> None:
        expected = [1024, 1030]  # X0 branch source; initial NZCV is conservative overtaint.
        if computed_observed:
            expected += [1025, 1026, 1028]  # X1/X2 sources; initial X4 is overtaint.
        self.assertTrue(taint[0]["gpr"][0], "CMP's branch-selector dependency must survive AND")
        self.assertEqual(np.flatnonzero(taint.linear_view(0)).tolist(), sorted(expected))

    def assert_final_state(self, model: ARM64UnicornModel, input_: InputData) -> None:
        selector, left, right = (int(value) for value in input_[0]["gpr"][:3])
        offset = ((left + right) & _U64) & 128
        actual_offset, marker = (offset, 22) if selector == 0 else (0, 11)
        loaded = int(input_[0]["main"][actual_offset // 8])
        self.assertEqual(tuple(int(model.emulator.reg_read(reg)) for reg in _REGS),
                         (selector, left, right, (marker + loaded) & _U64, _MAIN + offset,
                          loaded, 0x60000000 if selector == 0 else 0x80000000, _MAIN))
        expected_memory = bytearray(input_.tobytes()[:4096])
        struct.pack_into("<Q", expected_memory, actual_offset, marker)
        self.assertEqual(bytes(model.emulator.mem_read(_MAIN, 4096)), expected_memory)
        self.assertFalse(model.speculator.in_speculation())
        self.assertEqual(model.speculator.nesting(), 0)
        self.assertEqual(model.state.pending_fault, 0)
        self.assertFalse(model.state.had_arch_fault)
        self.assertEqual(model._taint_tracker._checkpoints, [])

    def observe(self, model: ARM64UnicornModel, input_: InputData,
                speculative: bool) -> Tuple[CTrace, InputTaint]:
        # Explicit independent register/memory/dependency oracles keep the observer inspectable.
        # pylint: disable=too-many-locals
        selector, left, right = (int(value) for value in input_[0]["gpr"][:3])
        offset = ((left + right) & _U64) & 128
        self.assertIn(offset, (0, 128))
        self.assertLessEqual(offset + 8, 4096)
        original = input_.tobytes()
        flags = 0x60000000 if selector == 0 else 0x20000000
        events: List[_Event] = []
        restored: List[int] = []
        tracker = model._taint_tracker
        rollback = model.speculator.rollback

        def observe_memory(emulator: uc.Uc, access: int, address: int, size: int,
                           value: int, _context: object) -> None:
            pc = int(emulator.reg_read(ucc.UC_ARM64_REG_PC)) - _CODE
            computed = pc in (56, 60)
            self.assertIn(pc, (36, 40, 56, 60))
            self.assertEqual(address, _MAIN + (offset if computed else 0))
            self.assertEqual(size, 8)
            self.assertEqual(emulator.reg_read(ucc.UC_ARM64_REG_X4), _MAIN + offset)
            # CMP -> ADD -> AND -> ADD must preserve actual NZCV, including transiently.
            self.assertEqual(emulator.reg_read(ucc.UC_ARM64_REG_NZCV), flags)
            self.assertEqual(emulator.reg_read(ucc.UC_ARM64_REG_X3), 22 if computed else 11)
            self.assertEqual(emulator.reg_read(ucc.UC_ARM64_REG_X5),
                             int(input_[0]["gpr"][5]) if access == uc.UC_MEM_READ else
                             int(input_[0]["main"][(offset if computed else 0) // 8]))
            if access == uc.UC_MEM_WRITE:
                self.assertEqual(value, 22 if computed else 11)
            events.append((pc, access, address - _DATA, size,
                           model.speculator.in_speculation()))

        def observe_rollback() -> int:
            wrong_offset, marker = (0, 11) if selector == 0 else (offset, 22)
            loaded = int(input_[0]["main"][wrong_offset // 8])
            self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X3),
                             (marker + loaded) & _U64)
            self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X5), loaded)
            self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_NZCV),
                             0x80000000 if selector == 0 else 0x60000000)
            wrong_memory = bytearray(original[:4096])
            struct.pack_into("<Q", wrong_memory, wrong_offset, marker)
            self.assertEqual(bytes(model.emulator.mem_read(_MAIN, 4096)), wrong_memory)
            saved_dependencies = deepcopy(tracker._checkpoints[-1])
            resume = rollback()  # Actual register/memory/taint rollback, never replaced.
            self.assertEqual(tuple(int(model.emulator.reg_read(reg)) for reg in _REGS),
                             (selector, left, right, int(input_[0]["gpr"][3]), _MAIN + offset,
                              int(input_[0]["gpr"][5]), flags, _MAIN))
            self.assertEqual(bytes(model.emulator.mem_read(_MAIN, 4096)), original[:4096])
            for kind in ("reg", "flag", "mem"):
                self.assertEqual(getattr(tracker._dependencies, kind),
                                 getattr(saved_dependencies, kind))
            restored.append(resume - _CODE)
            return resume

        hook = model.emulator.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, observe_memory)
        try:
            with patch.object(model.speculator, "rollback", side_effect=observe_rollback):
                traces, taints = model.trace_test_case_with_taints([input_], nesting=1)
        finally:
            model.emulator.hook_del(hook)
        correct = (56, 60, 4096 + offset) if selector == 0 else (36, 40, 4096)
        wrong = (36, 40, 4096) if selector == 0 else (56, 60, 4096 + offset)
        paths = [(wrong, True), (correct, False)] if speculative else [(correct, False)]
        self.assertEqual(events, [event for (load, store, address), transient in paths
                                  for event in ((load, uc.UC_MEM_READ, address, 8, transient),
                                                (store, uc.UC_MEM_WRITE, address, 8, transient))])
        self.assertEqual(restored, [52 if selector == 0 else 32] if speculative else [])
        self.assertEqual(traces[0].get_typed(), expected_trace(selector, offset, speculative))
        self.assert_final_state(model, input_)
        self.assertEqual(input_.tobytes(), original)
        return traces[0], taints[0]

    def test_independent_sources_actual_execution_flags_taints_and_rollback(self) -> None:
        for clause in ("seq", "cond"):
            model = make_model(clause, self.case)
            for selector in (0, 1):
                traces = []
                for left, right in _PAIRS:
                    with self.subTest(clause=clause, selector=selector, pair=(left, right)):
                        trace, taint = self.observe(model, address_input(selector, left, right),
                                                    speculative=clause == "cond")
                        traces.append(trace)
                        self.assert_taint(taint, selector == 0 or clause == "cond")
                self.assertEqual(traces[1].get_typed(), traces[2].get_typed())
                self.assertEqual(traces[1].get_typed(), traces[3].get_typed())
                # Counterfactual negative controls change only X1 or only X2.
                for changed in traces[1:3]:
                    if selector == 0 or clause == "cond":
                        self.assertNotEqual(traces[0].get_typed(), changed.get_typed())
                    else:
                        self.assertEqual(traces[0].get_typed(), changed.get_typed())
        self.assert_address_metadata()

    def assert_address_metadata(self) -> None:
        instructions = self.case.get_obj().instruction_map()[0]
        self.assertEqual(sorted(instructions), list(range(0, 88, 4)))
        for pc, name, operands in ((16, "add", ("x4", "x1", "x2")),
                                   (20, "and", ("x4", "x4", "#128")),
                                   (24, "add", ("x4", "x20", "x4"))):
            instruction = instructions[pc]
            self.assertEqual(instruction.name, name)
            self.assertEqual(tuple(op.value for op in instruction.operands), operands)
            for index, operand in enumerate(instruction.operands):
                self.assertIsInstance(operand, ImmediateOp if name == "and" and index == 2
                                      else RegisterOp)
                assert isinstance(operand, (RegisterOp, ImmediateOp))
                self.assertEqual(operand.width, 64)
            self.assertEqual([(op.src, op.dest) for op in instruction.operands],
                             [(False, True), (True, False), (True, False)])
            self.assertIsNone(instruction.get_flags_operand())
            self.assertEqual(instruction.implicit_operands, [])

    def test_repetition_and_transient_dependency_reset(self) -> None:
        model = make_model("cond", self.case)
        input_ = address_input(1, 64, 64)
        traces, taints = model.trace_test_case_with_taints([input_], nesting=1)
        saved = taints[0].copy()
        self.assert_taint(taints[0], True)
        sequential, clean = model.trace_test_case_with_taints([input_], nesting=0)
        self.assertEqual(sequential[0].get_typed(), expected_trace(1, 128, False))
        self.assert_taint(clean[0], False)
        self.assert_final_state(model, input_)
        repeated, repeated_taints = model.trace_test_case_with_taints([input_, input_], nesting=1)
        self.assertEqual([trace.get_typed() for trace in repeated], [traces[0].get_typed()] * 2)
        for taint in repeated_taints:
            np.testing.assert_array_equal(taint, saved)
        np.testing.assert_array_equal(taints[0], saved)
        self.assert_final_state(model, input_)

    def test_real_boosting_and_independent_full_retracing(self) -> None:
        # Keep parent/mask/candidate/retraced values together for independent copy checks.
        # pylint: disable=too-many-locals
        for clause in ("seq", "cond"):
            model = make_model(clause, self.case)
            inputs = [address_input(selector, left, right)
                      for selector in (0, 1) for left, right in _PAIRS]
            before = [input_.tobytes() for input_ in inputs]
            traces, taints = model.trace_test_case_with_taints(inputs, nesting=1)
            for index, taint in enumerate(taints):
                self.assert_taint(taint, index < 4 or clause == "cond")
                self.assertEqual(traces[index].get_typed(), expected_trace(
                    index // 4, 0 if index % 4 == 0 else 128, clause == "cond"))
            generator = factory.get_data_generator(123)
            expanded = generator.generate_boosted(inputs, taints, inputs_per_class=2)
            repeated = generator.generate_boosted(inputs, taints, inputs_per_class=2)
            self.assertEqual(len(expanded), 16)
            self.assertEqual([item.tobytes() for item in expanded],
                             [item.tobytes() for item in repeated])
            for index, input_ in enumerate(expanded):
                parent = index % len(inputs)
                mask = taints[parent].linear_view(0)
                old, new = inputs[parent].linear_view(0), input_.linear_view(0)
                np.testing.assert_array_equal(new[mask], old[mask])
                if index >= len(inputs):
                    self.assertTrue(np.any(new[~mask] != old[~mask]))
                # Each call executes Unicorn; no reused/fast traces or hardware boundary.
                actual = model.trace_test_case([input_], nesting=1)[0]
                self.assertEqual(actual.get_typed(), traces[parent].get_typed())
                self.assert_final_state(model, input_)
            self.assertEqual([input_.tobytes() for input_ in inputs], before)
