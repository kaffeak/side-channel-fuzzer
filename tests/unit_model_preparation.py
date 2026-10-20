"""Host-only candidate reconstruction, not kernel allocation/lifetime validation.

Uses the real factory, ARM64 target/services, binary loader and Unicorn engine.
Only CPU identification is replaced during successful preparation. Tiny owned
binary fixtures bypass assemblers/ELF discovery; selected tests emulate their
instructions in Unicorn, never execute native ARM64 instructions or touch sysfs.
Failure tests inject errors at constructor/loading boundaries. No fuzzer call
ordering changes are exercised or implied by these isolated candidate tests.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access
# pylint: disable=too-many-public-methods

from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from dataclasses import replace
from io import StringIO
import json
from pathlib import Path
import tempfile
from typing import Any, Dict, Type
import unittest
from unittest.mock import patch

import numpy as np
from unicorn import Uc, UcError, UC_ERR_MAP, UC_ERR_NOMEM  # type: ignore[import-untyped]

from rvzr import factory
from rvzr.arch.arm64.target_desc import ARM64TargetDesc
from rvzr.config import CONF, ConfigException
from rvzr.fuzzer import Fuzzer
from rvzr.logs import update_logging_after_config_change
from rvzr.model_unicorn.interpreter import ARMExtraInterpreter
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.model_unicorn.preparation import prepare_unicorn_model
from rvzr.model_unicorn.speculator_abc import UnicornSpeculator
from rvzr.model_unicorn.speculators_basic import ARM64CondSpeculator, SeqSpeculator, \
    StoreBpasSpeculator
from rvzr.model_unicorn.speculators_fault import ARMUnicornDEH, SequentialAssistSpeculator
from rvzr.model_unicorn.tracer import CTTracer, MemoryTracer
from rvzr.sandbox import DataArea
from rvzr.sandbox_descriptor import SandboxDescriptor, ExecutionEligibilityError, parse_descriptor
from rvzr.target_desc import CPUDesc
from rvzr.tc_components.actor import Actor, ActorMode, ActorPL
from rvzr.tc_components.instruction import Instruction, LabelOp, MemoryOp, RegisterOp
from rvzr.tc_components.test_case_binary import SymbolTableEntry, TestCaseBinary
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData
from rvzr.traces import CTraceEntry
from tests.unit_sandbox_descriptor import _fixture


class ModelPreparationTest(unittest.TestCase):
    DATA_A = 0x109000  # main is 8 KB aligned, as required by the legacy descriptor.
    DATA_B = 0x309000
    CODE_A = 0x200000
    CODE_B = 0x400000

    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(update_logging_after_config_change)
        self.addCleanup(stack.close)
        for name, value in {
                "instruction_set": "arm64", "model_backend": "unicorn", "_handled_faults": [],
                "contract_execution_clause": ["seq"], "contract_observation_clause": "ct",
                "coverage_type": "model_instructions", "logging_modes": [],
        }.items():
            stack.enter_context(patch.object(CONF, name, value))
        update_logging_after_config_change()
        # Keep target construction and every interpreter real; replace host CPU discovery only.
        stack.enter_context(patch.object(ARM64TargetDesc, "_build_cpu_desc",
                                         return_value=CPUDesc("ARM", 0, 8, 0)))
        for boundary in ("get_executor", "get_fuzzer"):
            stack.enter_context(patch.object(factory, boundary,
                                             side_effect=AssertionError("Unexpected executor I/O")))
        for boundary in ("km_write", "open"):
            stack.enter_context(patch("rvzr.executor." + boundary, create=True,
                                      side_effect=AssertionError("Unexpected executor I/O")))
        temporary = stack.enter_context(tempfile.TemporaryDirectory(prefix="rvzr-model-prepare-"))
        self.directory = Path(temporary)

    def descriptor(self, actors: int = 2, *, data: int = DATA_A, code: int = CODE_A,
                   generation: int = 7) -> SandboxDescriptor:
        value = _fixture()
        value.update(actor_count=actors, generation=generation)
        value["bases"] = {"data": f"0x{data:016x}", "code": f"0x{code:016x}",
                          "entry": f"0x{code:016x}", "utility": f"0x{data - 36864:016x}"}
        return parse_descriptor(json.dumps(value))

    def make_test_case(self, actors: int = 2) -> TestCaseProgram:
        # NOP macro placeholders, MOV X0,X20, LDR X1,[X20], NOP end placeholder.
        # These are emulated only; no assembler, ELF parser or hardware is involved.
        code = bytes.fromhex("1f2003d5 e00314aa 810240f9 1f2003d5")
        binary = self.directory / f"actors-{actors}.bin"
        binary.write_bytes(code * actors)
        test_case = TestCaseProgram("synthetic-only.asm")
        for actor_id in range(actors):
            actor = Actor(ActorMode.HOST, ActorPL.KERNEL,
                          "main" if actor_id == 0 else f"actor{actor_id}", data_properties=1)
            test_case.add_actor_with_section(actor, allow_overwrite=actor_id == 0)
            actor.code_section().assign_elf_data(actor_id * len(code), len(code), actor_id)
        test_case.assign_obj(str(binary))
        symbols = []
        instructions: Dict[int, Dict[int, Instruction]] = {}
        for actor_id in range(actors):
            start = Instruction("macro", is_instrumentation=True)
            start.add_op(LabelOp(".measurement_start"))
            move = Instruction("mov")
            move.add_op(RegisterOp("x0", 64, False, True))
            move.add_op(RegisterOp("x20", 64, True, False))
            load = Instruction("ldr")
            load.add_op(RegisterOp("x1", 64, False, True))
            load.add_op(MemoryOp("x20", 64, True, False))
            end = Instruction("macro", is_instrumentation=True)
            end.add_op(LabelOp(".measurement_end"))
            instructions[actor_id] = {0: start, 4: move, 8: load, 12: end}
            symbols.extend([SymbolTableEntry(actor_id, 0, 1, 0),
                            SymbolTableEntry(actor_id, 12, 2, 0)])
        test_case.get_obj().assign_elf_data(symbols, instructions)
        test_case.mark_as_assembled()
        return test_case

    def prepare(self, allocation: SandboxDescriptor, test_case: TestCaseProgram,
                **arguments: Any) -> ARM64UnicornModel:
        return prepare_unicorn_model(test_case, allocation,
                                     expected_payload_byte_order="little", **arguments)

    def assert_graph(self, model: ARM64UnicornModel, descriptor: SandboxDescriptor,
                     test_case: TestCaseProgram) -> None:
        self.assertIsInstance(model, ARM64UnicornModel)
        bases = descriptor.bases
        assert bases is not None
        self.assertEqual(model._bases, (bases.data, bases.code))
        self.assertEqual((model.layout.data_start(), model.layout.code_start()),
                         (bases.data, bases.code))
        self.assertEqual(model.layout.data_size, test_case.n_actors() * 16384)
        self.assertEqual(model.layout.code_size, test_case.n_actors() * 12288)
        self.assertEqual(model._taint_tracker._data_start, bases.data)
        self.assertEqual(model.state.exit_addr, bases.code + 15)
        self.assertEqual(model.state.fault_handler_addr, bases.code + 15)
        self.assertIs(model.state._layout, model.layout)
        self.assertIs(model.state.current_test_case(), test_case)
        self.assertIsNone(model.state.previous_context)
        self.assertIs(model._log.model_layout, model.layout)
        self.assertIs(model.tracer._model, model)
        self.assertIs(model.speculator._model, model)
        self.assertIs(model.speculator._emulator, model.emulator)
        self.assertIs(model.speculator._taint_tracker, model._taint_tracker)
        self.assertIs(model.tracer._taint_tracker, model._taint_tracker)
        dispatcher = model._dispatcher
        self.assertIs(dispatcher._tracer, model.tracer)
        self.assertIs(dispatcher._speculator, model.speculator)
        self.assertIs(dispatcher._taint_tracker, model._taint_tracker)
        interpreter = dispatcher._interpreter
        self.assertIsInstance(interpreter, ARMExtraInterpreter)
        assert isinstance(interpreter, ARMExtraInterpreter)
        self.assertIs(interpreter._model, model)
        self.assertIs(interpreter._macro_interpreter._model, model)
        self.assertIs(interpreter._fault_interpreter._model, model)
        self.assertEqual(model.state.page_permissions,
                         {actor: (True, True) for actor in range(test_case.n_actors())})
        self.assertEqual(sorted(model.emulator.mem_regions()), sorted([
            (bases.data, bases.data + 16384 * test_case.n_actors() - 1, 7),
            (bases.code, bases.code + 12288 * test_case.n_actors() - 1, 7)]))
        self.assertEqual(model.emulator.mem_read(bases.code, 16),
                         bytes.fromhex("1f2003d5 e00314aa 810240f9 1f2003d5"))

    def assert_independent(self, old: ARM64UnicornModel, new: ARM64UnicornModel) -> None:
        for name in ("layout", "state", "emulator", "_taint_tracker", "tracer", "speculator",
                     "_dispatcher", "_log"):
            self.assertIsNot(getattr(old, name), getattr(new, name))
        self.assertIsNot(old._dispatcher._interpreter, new._dispatcher._interpreter)
        self.assertIsNot(old._dispatcher.coverage, new._dispatcher.coverage)

    def test_legacy_preparation_delegates_to_real_factory_and_loads_real_services(self) -> None:
        descriptor, test_case = self.descriptor(), self.make_test_case()
        with patch.object(factory, "get_model", wraps=factory.get_model) as construct:
            model = self.prepare(descriptor, test_case)
        construct.assert_called_once_with(
            (self.DATA_A, self.CODE_A), enable_mismatch_check_mode=False)
        self.assert_graph(model, descriptor, test_case)
        self.assertIsInstance(model.tracer, CTTracer)

    def test_reconstructs_independently_at_identical_addresses(self) -> None:
        descriptor, test_case = self.descriptor(), self.make_test_case()
        old, new = self.prepare(descriptor, test_case), self.prepare(descriptor, test_case)
        self.assert_independent(old, new)
        self.assert_graph(old, descriptor, test_case)
        self.assert_graph(new, descriptor, test_case)

    def test_reconstructs_after_data_only_relocation(self) -> None:
        self.check_relocation(data=self.DATA_B, code=self.CODE_A)

    def test_reconstructs_after_code_only_relocation(self) -> None:
        self.check_relocation(data=self.DATA_A, code=self.CODE_B)

    def test_reconstructs_after_both_addresses_change(self) -> None:
        self.check_relocation(data=self.DATA_B, code=self.CODE_B)

    def check_relocation(self, *, data: int, code: int) -> None:
        test_case = self.make_test_case()
        old_descriptor, descriptor = self.descriptor(), self.descriptor(data=data, code=code)
        old = self.prepare(old_descriptor, test_case)
        new = self.prepare(descriptor, test_case)
        self.assert_independent(old, new)
        self.assert_graph(new, descriptor, test_case)
        self.assert_graph(old, old_descriptor, test_case)
        tracker = new._taint_tracker
        tracker.set_enable_tracking(True)
        tracker.reset()
        tracker.track_instruction(test_case.get_obj().instruction_map()[0][8])
        tracker.track_memory_access(data + 4104, 8, is_write=False)
        assert tracker._instruction is not None
        self.assertEqual(tracker._instruction.src_mems, {hex(4104)})

    def test_actor_count_growth_shrinkage_and_repetition_rebuild_mappings(self) -> None:
        previous = None
        for actors in (1, 3, 1, 1):
            with self.subTest(actors=actors):
                descriptor, test_case = self.descriptor(actors), self.make_test_case(actors)
                model = self.prepare(descriptor, test_case)
                self.assert_graph(model, descriptor, test_case)
                if previous is not None:
                    self.assert_independent(previous, model)
                previous = model

    def test_new_generation_with_same_addresses_still_constructs_fresh_model(self) -> None:
        test_case = self.make_test_case()
        first, second = self.descriptor(), self.descriptor(generation=8)
        old, new = self.prepare(first, test_case), self.prepare(second, test_case)
        self.assertEqual(first.bases, second.bases)
        self.assert_independent(old, new)
        self.assert_graph(new, second, test_case)
        # The generation is producer-supplied fixture data, not a kernel lease.

    def test_normal_and_architectural_modes_preserve_speculator_selection(self) -> None:
        cases: Dict[str, Type[UnicornSpeculator]] = {
            "seq": SeqSpeculator, "cond": ARM64CondSpeculator, "bpas": StoreBpasSpeculator,
            "seq-assist": SequentialAssistSpeculator, "delayed-exception-handling": ARMUnicornDEH,
        }
        test_case, descriptor = self.make_test_case(), self.descriptor()
        for clause, expected in cases.items():
            for mismatch in (False, True):
                with self.subTest(clause=clause, mismatch=mismatch), \
                        patch.object(CONF, "contract_execution_clause", [clause]):
                    model = self.prepare(descriptor, test_case, enable_mismatch_check_mode=mismatch)
                    self.assertIsInstance(model.speculator, expected)
                    self.assertEqual(model.is_speculative, not expected.is_sequential)
                    self.assertEqual(model._enable_mismatch_check_mode, mismatch)
                    self.assert_graph(model, descriptor, test_case)

    def test_observation_selection_is_delegated_to_factory(self) -> None:
        with patch.object(CONF, "contract_observation_clause", "memory"):
            model = self.prepare(self.descriptor(), self.make_test_case())
        self.assertIsInstance(model.tracer, MemoryTracer)

    def test_real_unicorn_trace_and_raw_pointer_results_follow_relocated_bases(self) -> None:
        test_case = self.make_test_case()
        input_ = InputData(2)
        input_.view(np.uint8).fill(0)
        input_[0]["main"][0] = 42
        for data, code in ((self.DATA_A, self.CODE_A), (self.DATA_B, self.CODE_B)):
            for mismatch in (False, True):
                with self.subTest(data=data, mismatch=mismatch):
                    descriptor = self.descriptor(data=data, code=code)
                    model = self.prepare(descriptor, test_case, enable_mismatch_check_mode=mismatch)
                    traces, _ = model.trace_test_case_with_taints([input_], nesting=1)
                    self.assertEqual(traces[0].get_untyped(),
                                     [data + 4096, 42, 0, 0, 0, 0] if mismatch
                                     else [4, 8, 4096, 12])
                    self.assertIsNotNone(model.state.previous_context)
                    self.assertIs(model.speculator._emulator, model.emulator)

    def test_old_memory_contexts_speculation_and_coverage_are_not_copied(self) -> None:
        descriptor, test_case = self.descriptor(), self.make_test_case()
        old = self.prepare(descriptor, test_case)
        input_ = InputData(2)
        input_.view(np.uint8).fill(0)
        old.trace_test_case([input_], nesting=1)
        old.speculator._checkpoint(self.CODE_A + 8)
        main = old.layout.get_data_addr(DataArea.MAIN, 0)
        old.speculator._store_logs[-1].append((main, b"old-data"))
        old.emulator.mem_write(main, b"old-data")
        old.tracer.trace.append(CTraceEntry("val", 123))
        old._dispatcher.coverage.finish_test_case()
        coverage = dict(old._dispatcher.coverage._cov)
        self.assertTrue(coverage)

        new = self.prepare(descriptor, test_case)
        self.assert_independent(old, new)
        self.assert_graph(new, descriptor, test_case)
        self.assertEqual(new.emulator.mem_read(main, 8), bytes(8))
        self.assertEqual(new.speculator._checkpoints, [])
        self.assertEqual(new.speculator._store_logs, [])
        self.assertFalse(new.speculator.in_speculation())
        self.assertEqual(new.tracer.trace, [])
        self.assertEqual(new._dispatcher.coverage._cov, {})
        self.assertEqual(old.emulator.mem_read(main, 8), b"old-data")
        self.assertEqual(len(old.speculator._checkpoints), 1)
        self.assertEqual(old._dispatcher.coverage._cov, coverage)
        self.assertIsNotNone(old.state.previous_context)

    def test_candidate_16k_is_rejected_before_construction_even_when_enabled(self) -> None:
        for enabled in (False, True):
            value = _fixture(candidate=True)
            value["execution_enabled"] = enabled
            self.reject_descriptor(parse_descriptor(json.dumps(value)))

    def test_incompatible_actor_count_architecture_byte_order_and_readiness(self) -> None:
        descriptor = self.descriptor()
        for changes in ({"actor_count": 1}, {"architecture": "x86-64"},
                        {"payload_byte_order": "big"}, {"ready": False},
                        {"execution_enabled": False}, {"bases": None}):
            with self.subTest(changes=changes):
                self.reject_descriptor(replace(descriptor, **changes))

    def reject_descriptor(self, descriptor: SandboxDescriptor) -> None:
        with patch.object(factory, "get_model", wraps=factory.get_model) as construct:
            with self.assertRaises(ExecutionEligibilityError):
                self.prepare(descriptor, self.make_test_case())
            construct.assert_not_called()

    def test_expected_byte_order_is_caller_supplied_and_big_endian_is_unsupported(self) -> None:
        test_case, descriptor = self.make_test_case(), self.descriptor()
        for allocation in (descriptor, replace(descriptor, payload_byte_order="big")):
            with self.subTest(byte_order=allocation.payload_byte_order), \
                    patch.object(factory, "get_model", wraps=factory.get_model) as construct:
                with self.assertRaises(ExecutionEligibilityError):
                    prepare_unicorn_model(test_case, allocation, expected_payload_byte_order="big")
                construct.assert_not_called()

    def test_wrong_factory_configuration_fails_without_mutating_configuration(self) -> None:
        for name, value in (("instruction_set", "x86-64"), ("model_backend", "dummy")):
            with self.subTest(name=name), patch.object(CONF, name, value), \
                    patch.object(factory, "get_model", wraps=factory.get_model) as construct:
                with self.assertRaises(ConfigException):
                    self.prepare(self.descriptor(), self.make_test_case())
                construct.assert_not_called()
                self.assertEqual(getattr(CONF, name), value)

    def test_constructor_failure_propagates_without_retry_or_loading(self) -> None:
        test_case = self.make_test_case()
        failure = UcError(UC_ERR_NOMEM)
        with patch("rvzr.model_unicorn.model.Uc", side_effect=failure) as create_engine, \
                patch.object(TestCaseBinary, "to_bytes",
                             wraps=test_case.get_obj().to_bytes) as load:
            with self.assertRaises(UcError) as caught:
                self.prepare(self.descriptor(), test_case)
            self.assertIs(caught.exception, failure)
            create_engine.assert_called_once()
            load.assert_not_called()

    def test_binary_load_failure_propagates(self) -> None:
        with patch.object(TestCaseBinary, "to_bytes", side_effect=ValueError("synthetic load")):
            with self.assertRaisesRegex(ValueError, "synthetic load"):
                self.prepare(self.descriptor(), self.make_test_case())

    def test_mapping_and_hook_failures_preserve_system_exit(self) -> None:
        for method in ("mem_map", "hook_add"):
            with self.subTest(method=method), redirect_stdout(StringIO()), \
                    patch.object(Uc, method, side_effect=UcError(UC_ERR_MAP)) as operation:
                with self.assertRaises(SystemExit) as caught:
                    self.prepare(self.descriptor(), self.make_test_case())
                self.assertEqual(caught.exception.code, 1)
                operation.assert_called_once()

    def test_post_load_refresh_failure_propagates(self) -> None:
        original_reset = SeqSpeculator.reset
        calls = 0

        def reset(speculator: SeqSpeculator) -> None:
            nonlocal calls
            calls += 1
            original_reset(speculator)
            if calls == 2:
                raise RuntimeError("synthetic post-load refresh failure")

        with patch.object(SeqSpeculator, "reset", autospec=True, side_effect=reset):
            with self.assertRaisesRegex(RuntimeError, "synthetic post-load refresh failure"):
                self.prepare(self.descriptor(), self.make_test_case())
        self.assertEqual(calls, 2)  # Constructor reset, then post-load reset; no retry.

    def test_returns_candidate_without_publication_input_loading_or_execution(self) -> None:
        descriptor, test_case = self.descriptor(), self.make_test_case()
        previous = self.prepare(descriptor, test_case)
        owner = Fuzzer.__new__(Fuzzer)  # Existing owner only; do not invoke executor construction.
        owner.model = previous
        owner.arch_model = previous
        before = deepcopy(CONF.__dict__)
        with patch.object(ARM64UnicornModel, "trace_test_case") as trace, \
                patch.object(ARM64UnicornModel, "trace_test_case_with_taints") as taint_trace, \
                patch.object(ARM64UnicornModel, "_load_input") as load_input, \
                patch.object(ARM64UnicornModel, "_run_state_machine") as execute:
            candidate = self.prepare(self.descriptor(data=self.DATA_B), test_case)
            for operation in (trace, taint_trace, load_input, execute):
                operation.assert_not_called()
        self.assertIs(owner.model, previous)
        self.assertIs(owner.arch_model, previous)
        self.assertIsNot(candidate, previous)
        self.assertEqual(CONF.__dict__, before)


if __name__ == "__main__":
    unittest.main()
