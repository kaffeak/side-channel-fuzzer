"""Real ARM64 conditional speculation; no kernel or hardware execution.

The independent memory hook witnesses transient loads/stores. Rollback observation
delegates to the real method and inspects state immediately before/after it.
Code-hook C-traces describe model observations, not physical instruction retirement.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from typing import List, Tuple
import unittest
from unittest.mock import patch

from elftools.elf.elffile import ELFFile
import numpy as np
import unicorn as uc  # type: ignore[import-untyped]
import unicorn.arm64_const as ucc  # type: ignore[import-untyped]

from rvzr import factory
from rvzr.config import CONF
from rvzr.isa_spec import InstructionSet
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.model_unicorn.speculators_basic import ARM64CondSpeculator, SeqSpeculator
from rvzr.model_unicorn.tracer import CTTracer
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData
from rvzr.traces import CTraceEntry
from tests.unit_arm64_contract_slice import software_environment


_ARM = Path(__file__).resolve().parent / "arm64"
_DATA, _CODE, _MAIN = 0x109000, 0x200000, 0x10a000
_REGS = (ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1, ucc.UC_ARM64_REG_X2,
         ucc.UC_ARM64_REG_X3, ucc.UC_ARM64_REG_X4, ucc.UC_ARM64_REG_NZCV)
_PREFIX = [CTraceEntry("pc", offset) for offset in (12, 16, 20)]
_FALL = [CTraceEntry("pc", 24), CTraceEntry("pc", 28), CTraceEntry("mem", 4096),
         CTraceEntry("pc", 32), CTraceEntry("mem", 4096), CTraceEntry("pc", 36),
         CTraceEntry("pc", 40)]
_TAKEN = [CTraceEntry("pc", 44), CTraceEntry("pc", 48), CTraceEntry("mem", 4224),
          CTraceEntry("pc", 52), CTraceEntry("mem", 4224), CTraceEntry("pc", 56)]
_JOIN = [CTraceEntry("pc", 60), CTraceEntry("pc", 64)]
_MemoryEvent = Tuple[int, int, int, int, bool]


def assemble_case(directory: Path) -> TestCaseProgram:
    template = directory / "conditional.asm"
    shutil.copyfile(_ARM / "asm/conditional_contract_slice.asm", template)
    isa = InstructionSet(str(_ARM / "min_arm64.json"))
    return factory.get_program_generator(1, isa).create_test_case_from_template(str(template))


def make_input(selector: int) -> InputData:
    input_ = InputData(1)
    input_.view(np.uint8).fill(0)
    input_[0]["gpr"][0] = selector
    input_[0]["main"][0] = 7
    input_[0]["main"][16] = 19
    return input_


def make_model(clause: str, case: TestCaseProgram) -> ARM64UnicornModel:
    CONF.contract_execution_clause = [clause]
    model = factory.get_model((_DATA, _CODE))
    if not isinstance(model, ARM64UnicornModel):
        raise TypeError("Expected actual ARM64 Unicorn model")
    model.load_test_case(case)
    return model


class ARM64ConditionalContractTest(unittest.TestCase):
    def test_real_conditional_trace_and_rollback_both_directions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rvzr-arm64-cond-") as temporary:
            directory = Path(temporary)
            with software_environment(directory):
                CONF.model_max_spec_window = 32
                case = assemble_case(directory)
                sequential = make_model("seq", case)
                speculative = make_model("cond", case)
                self.assertIsInstance(sequential.speculator, SeqSpeculator)
                self.assertIsInstance(speculative.speculator, ARM64CondSpeculator)
                self.assertIsInstance(speculative.tracer, CTTracer)
                self.exercise_paths(sequential, speculative)

    def exercise_paths(self, sequential: ARM64UnicornModel,
                       speculative: ARM64UnicornModel) -> None:
        # pylint: disable=too-many-locals
        events: List[_MemoryEvent] = []
        rollbacks = []
        rollback = speculative.speculator.rollback

        def observe_memory(emulator: uc.Uc, access: int, address: int, size: int,
                           _value: int, _context: object) -> None:
            events.append((int(emulator.reg_read(ucc.UC_ARM64_REG_PC)) - _CODE,
                           access, address - _DATA, size,
                           speculative.speculator.in_speculation()))

        def observe_rollback() -> int:
            before = tuple(int(speculative.emulator.reg_read(reg)) for reg in _REGS)
            memory_before = bytes(speculative.emulator.mem_read(_MAIN, 4096))
            resume = rollback()
            after = tuple(int(speculative.emulator.reg_read(reg)) for reg in _REGS)
            memory_after = bytes(speculative.emulator.mem_read(_MAIN, 4096))
            rollbacks.append((before, memory_before, resume - _CODE, after, memory_after))
            return resume

        hook = speculative.emulator.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,
                                             observe_memory)
        try:
            with patch.object(speculative.speculator, "rollback", side_effect=observe_rollback):
                for iteration, selector in enumerate((0, 1, 0, 1)):
                    with self.subTest(selector=selector, repetition=iteration):
                        events.clear()
                        input_ = make_input(selector)
                        original = input_.tobytes()
                        seq_trace = sequential.trace_test_case([input_], nesting=1)[0]
                        cond_trace = speculative.trace_test_case([input_], nesting=1)[0]
                        correct, wrong = (_TAKEN, _FALL) if selector == 0 else (_FALL, _TAKEN)
                        self.assertEqual(seq_trace.get_typed(), _PREFIX + correct + _JOIN)
                        self.assertEqual(cond_trace.get_typed(),
                                         _PREFIX + wrong + _JOIN + [CTraceEntry("pc", 76)]
                                         + correct + _JOIN)
                        self.assertNotEqual(seq_trace, cond_trace)
                        expected_registers = (selector, 22, 19, 41, _MAIN + 128, 0x60000000) \
                            if selector == 0 else (selector, 11, 7, 18, _MAIN + 128, 0x80000000)
                        for model in (sequential, speculative):
                            self.assertEqual(tuple(int(model.emulator.reg_read(r)) for r in _REGS),
                                             expected_registers)
                            self.assertFalse(model.speculator.in_speculation())
                            self.assertEqual(model.speculator.nesting(), 0)
                            self.assertEqual(model.state.pending_fault, 0)
                        expected_memory = bytearray(original[:4096])
                        struct.pack_into("<Q", expected_memory, 128 if selector == 0 else 0,
                                         22 if selector == 0 else 11)
                        for model in (sequential, speculative):
                            self.assertEqual(bytes(model.emulator.mem_read(_MAIN, 4096)),
                                             bytes(expected_memory))
                        self.assertEqual(input_.tobytes(), original)
                        # These are actual emulated memory accesses, independently witnessed.
                        paths = [(28, 32, 4096, True), (48, 52, 4224, False)] \
                            if selector == 0 else [(48, 52, 4224, True), (28, 32, 4096, False)]
                        self.assertEqual(events, [event for load, store, addr, transient in paths
                                                  for event in ((load, uc.UC_MEM_READ, addr, 8,
                                                                 transient),
                                                                (store, uc.UC_MEM_WRITE, addr, 8,
                                                                 transient))])
                        before, memory_before, resume, after, memory_after = rollbacks[-1]
                        self.assertEqual(len(rollbacks), iteration + 1)
                        self.assertEqual(before, (selector, 11, 7, 18, _MAIN + 128, 0x80000000)
                                         if selector == 0 else
                                         (selector, 22, 19, 41, _MAIN + 128, 0x60000000))
                        self.assertNotEqual(memory_before, original[:4096])
                        self.assertEqual(resume, 44 if selector == 0 else 24)
                        self.assertEqual(after, (selector, 0, 0, 0, _MAIN + 128,
                                                 0x60000000 if selector == 0 else 0x20000000))
                        self.assertEqual(memory_after, original[:4096])
        finally:
            speculative.emulator.hook_del(hook)

    def test_window_expiry_and_disabled_nesting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rvzr-arm64-window-") as temporary:
            directory = Path(temporary)
            with software_environment(directory):
                CONF.model_max_spec_window = 2
                case = assemble_case(directory)
                model = make_model("cond", case)
                for nesting in (0, 1):
                    for selector in (0, 1):
                        with self.subTest(nesting=nesting, selector=selector):
                            correct, wrong = (_TAKEN, _FALL) if selector == 0 else (_FALL, _TAKEN)
                            with patch.object(model.speculator, "rollback",
                                              wraps=model.speculator.rollback) as rollback:
                                trace = model.trace_test_case([make_input(selector)], nesting)[0]
                            # At window expiry the next store's PC is observed before emu_stop,
                            # but the store itself is not executed and contributes no mem event.
                            expected = _PREFIX + (wrong[:4] if nesting else []) + correct + _JOIN
                            self.assertEqual(trace.get_typed(), expected)
                            self.assertEqual(rollback.call_count, nesting)
                            expected_memory = bytearray(make_input(selector).tobytes()[:4096])
                            struct.pack_into("<Q", expected_memory, 128 if selector == 0 else 0,
                                             22 if selector == 0 else 11)
                            self.assertEqual(bytes(model.emulator.mem_read(_MAIN, 4096)),
                                             bytes(expected_memory))
                            self.assertFalse(model.speculator.in_speculation())
                            self.assertEqual(model.state.pending_fault, 0)

    def test_isb_terminates_wrong_path_before_join_add(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rvzr-arm64-barrier-") as temporary:
            directory = Path(temporary)
            with software_environment(directory):
                CONF.model_max_spec_window = 32
                template = directory / "barrier.asm"
                template.write_text((_ARM / "asm/conditional_contract_slice.asm").read_text(
                    encoding="ascii").replace(".join:\n", ".join:\n    isb\n"), encoding="ascii")
                isa = InstructionSet(str(_ARM / "min_arm64.json"))
                case = factory.get_program_generator(1, isa).create_test_case_from_template(
                    str(template))
                model = make_model("cond", case)
                before: List[int] = []
                rollback = model.speculator.rollback

                def observe_rollback() -> int:
                    before.append(int(model.emulator.reg_read(ucc.UC_ARM64_REG_X3)))
                    return rollback()

                for selector in (0, 1):
                    with self.subTest(selector=selector):
                        before.clear()
                        with patch.object(model.speculator, "rollback",
                                          side_effect=observe_rollback):
                            trace = model.trace_test_case([make_input(selector)], nesting=1)[0]
                        correct, wrong = (_TAKEN, _FALL) if selector == 0 else (_FALL, _TAKEN)
                        self.assertEqual(trace.get_typed(),
                                         _PREFIX + wrong + [CTraceEntry("pc", 60)]
                                         + correct + [CTraceEntry("pc", pc) for pc in (60, 64, 68)])
                        self.assertEqual(before, [0])  # wrong-path ADD at 64 never ran
                        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X3),
                                         41 if selector == 0 else 18)
                        self.assertFalse(model.speculator.in_speculation())
                        self.assertEqual(model.state.pending_fault, 0)

    def test_branch_decoder_matches_single_step_unicorn(self) -> None:
        """Real assembler/Unicorn oracle for flags, scaling, sign and register widths.

        This tests decoding separately from full Revizor tracing; no instruction
        encodings or speculative observations are synthesized by the test.
        """
        # The explicit ISA/flags/target cross-product keeps the oracle transparent.
        # pylint: disable=too-many-locals,too-many-nested-blocks
        with tempfile.TemporaryDirectory(prefix="rvzr-arm64-decode-") as temporary:
            directory = Path(temporary)
            with software_environment(directory):
                model = make_model("cond", assemble_case(directory))
                self.assertIsInstance(model.speculator, ARM64CondSpeculator)
                assert isinstance(model.speculator, ARM64CondSpeculator)
                # Normal trace startup refreshes the emulator after load_test_case().
                model.speculator.reset()
                branches = ["b." + condition for condition in
                            ("eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls",
                             "ge", "lt", "gt", "le", "al", "nv")]
                branches += [f"{op} {reg}," for op in ("cbz", "cbnz")
                             for reg in ("x0", "w0", "x29", "x30", "xzr", "wzr")]
                branches += [f"{op} {reg}, #{bit}," for op in ("tbz", "tbnz")
                             for reg, bit in (("w0", 0), ("w0", 31), ("x0", 32), ("x0", 63),
                                              ("x29", 0), ("x30", 63), ("xzr", 32))]
                # A separate, hook-free Unicorn instance supplies architectural branch outcomes.
                oracle = uc.Uc(uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)
                oracle.mem_map(_CODE, 4096)
                source, obj = directory / "branches.s", directory / "branches.o"
                lines = [".text"]
                for branch in branches:
                    for target in ("1b", ".", "2f", "3f"):
                        lines += ["1: nop", f"{branch} {target}", "2: nop", "nop", "3: nop"]
                source.write_text("\n".join(lines) + "\n", encoding="ascii")
                subprocess.run(["as", str(source), "-o", str(obj)], check=True,
                               capture_output=True, timeout=10)
                with obj.open("rb") as file:
                    section = ELFFile(file).get_section_by_name(".text")
                    assert section is not None
                    payload = section.data()
                oracle.mem_write(_CODE, payload)
                for index, branch in enumerate(branches):
                    for direction, target_offset in enumerate((-4, 0, 4, 12)):
                        offset_in_code = (index * 4 + direction) * 20 + 4
                        address = _CODE + offset_in_code
                        code = payload[offset_in_code:offset_in_code + 4]
                        # Nonzero high word, bit boundaries, sign and zero-register cases.
                        for value in (0, 1, 1 << 31, 1 << 32, 1 << 63):
                            for flags in range(16):
                                nzcv = flags << 28
                                for emulator in (oracle, model.emulator):
                                    emulator.reg_write(ucc.UC_ARM64_REG_NZCV, nzcv)
                                    for reg in (ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X29,
                                                ucc.UC_ARM64_REG_X30):
                                        emulator.reg_write(reg, value)
                                oracle.emu_start(address, _CODE + 4096, count=1)
                                actual_pc = int(oracle.reg_read(ucc.UC_ARM64_REG_PC))
                                offset, taken = model.speculator.decode(bytearray(code), nzcv)
                                with self.subTest(branch=branch, target=target_offset,
                                                  value=value, flags=flags):
                                    self.assertEqual(offset, target_offset - 4)
                                    self.assertEqual(address + 4 + offset if taken else address + 4,
                                                     actual_pc)
