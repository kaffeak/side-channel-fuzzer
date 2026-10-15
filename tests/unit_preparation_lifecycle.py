"""Host-only characterization of the legacy preparation lifecycle, not a safety contract.

The future invariant is that model, taint tracker, and executor all use the same
completed allocation before tracing. These tests deliberately record the current
risk so a future lifecycle fix must update the relocation expectations.

Real Fuzzer/_RoundManager, Executor adapter, ARM64 Unicorn model, layout, tracer,
and taint tracker are used. Sysfs transport and instruction execution are replaced
with synthetic stimuli. A relocation during RCBF upload is an injected condition,
not a reproduction of kernel allocation policy (including actor-count changes).
No target instructions execute, and no kernel interface is accessed.

Kernel allocation/cleanup failures, PTE state, concurrent clients, and atomic
generation checks cannot be established here. Utility addresses are not exposed
by the legacy Python interface. This suite does not validate 16 KB execution.
"""
# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access
# pylint: disable=too-many-instance-attributes

from contextlib import ExitStack
from io import StringIO
from typing import Any, Iterator, List, Tuple, cast
import unittest
from unittest.mock import MagicMock, patch

import numpy as np
from unicorn import UC_MEM_READ

from rvzr.arch.arm64.target_desc import ARM64TargetDesc, ARM64UnicornTargetDesc
from rvzr.config import CONF
from rvzr.executor import Executor
from rvzr.fuzzer import Fuzzer, _RoundManager
from rvzr.logs import STAT, update_logging_after_config_change
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.model_unicorn.speculators_basic import SeqSpeculator
from rvzr.model_unicorn.tracer import CTTracer
from rvzr.sandbox import BaseAddrTuple, DataArea
from rvzr.target_desc import TargetDesc
from rvzr.tc_components.instruction import Instruction
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData
from rvzr.traces import CTraceEntry


class PreparationLifecycleTest(unittest.TestCase):
    # Data bases make the legacy main address 8 KB aligned; code/data are disjoint.
    BASES_A: BaseAddrTuple = (0x1001000, 0x8000)
    BASES_B: BaseAddrTuple = (0x2001000, 0x18000)

    def setUp(self) -> None:
        stack = ExitStack()
        self._patches = stack
        self.addCleanup(update_logging_after_config_change)
        self.addCleanup(stack.close)
        for name, value in {
                "instruction_set": "arm64", "_handled_faults": [],
                "contract_observation_clause": "ct", "executor_sample_sizes": [1],
                "inputs_per_class": 1, "enable_fast_path_model": True,
                "executor_mode": "P+P", "logging_modes": [],
        }.items():
            stack.enter_context(patch.object(CONF, name, value))
        stack.enter_context(patch.object(STAT, "executor_reruns", 0))
        update_logging_after_config_change()

        self.events: List[str] = []
        self.hardware_bases = self.BASES_A
        self.upload_bases = self.BASES_A
        self.test_case = MagicMock(spec=TestCaseProgram)
        self.test_case.n_actors.return_value = 2
        self.test_case.find_actor.return_value.get_id.return_value = 0
        self.test_case.find_section.return_value.get_elf_data.return_value = {"size": 4}
        obj = self.test_case.get_obj.return_value
        obj.get_macro_offset.return_value = -1
        # Opaque bytes are mapped, never executed; no assembler or ELF parser needed.
        obj.to_bytes.side_effect = lambda padded_section_size, padding_byte: \
            bytes(2 * padded_section_size)
        obj.save_rcbf.side_effect = self._upload_test_case
        input_ = InputData(2)
        input_.view(np.uint8).fill(0)
        self.inputs = [input_]

        # Hardware/host discovery boundaries only; unexpected sysfs access fails closed.
        stack.enter_context(patch("rvzr.executor.open", self._open_sysfs, create=True))
        stack.enter_context(patch("rvzr.executor.km_write", self._configure))
        stack.enter_context(patch("rvzr.executor.warning"))
        stack.enter_context(patch("rvzr.executor.save_input_sequence_as_rdbf",
                                  self._upload_inputs))
        stack.enter_context(patch("rvzr.executor._read_trace", self._read_trace))
        stack.enter_context(patch("rvzr.fuzzer.InstructionSet"))
        for name in ("get_program_generator", "get_data_generator", "get_asm_parser",
                     "get_elf_parser"):
            stack.enter_context(patch("rvzr.fuzzer.factory." + name))
        analyser = stack.enter_context(patch("rvzr.fuzzer.factory.get_analyser"))
        analyser.return_value.filter_violations.return_value = []
        stack.enter_context(patch("rvzr.fuzzer.factory.get_executor", self._make_executor))
        stack.enter_context(patch("rvzr.fuzzer.factory.get_model", self._make_model))

        # Exercise the real constructor, including both initial address acquisitions.
        self.fuzzer = Fuzzer("unused-isa.json", "")
        self.model = cast(ARM64UnicornModel, self.fuzzer.model)
        self.arch_model = cast(ARM64UnicornModel, self.fuzzer.arch_model)

    def _make_executor(self, enable_mismatch_check_mode: bool = False) -> Executor:
        mode = "arch" if enable_mismatch_check_mode else "normal"
        self.events.append("executor.create." + mode)
        return Executor(enable_mismatch_check_mode, skip_setup=True)

    def _make_model(
            self, bases: BaseAddrTuple,
            enable_mismatch_check_mode: bool = False) -> ARM64UnicornModel:
        mode = "arch" if enable_mismatch_check_mode else "normal"
        self.events.append("model.create." + mode)
        target = MagicMock(spec=TargetDesc)
        target.uc_target_desc = ARM64UnicornTargetDesc()
        target.macro_specs = TargetDesc.macro_specs
        target.reg_normalized = ARM64TargetDesc.reg_normalized
        model = ARM64UnicornModel(
            bases, target, SeqSpeculator, CTTracer, MagicMock(), enable_mismatch_check_mode)
        load = model.load_test_case
        trace = model.trace_test_case

        def record_load(*args: Any, **kwargs: Any) -> Any:
            self.events.append("model.load." + mode)
            return load(*args, **kwargs)

        def record_trace(*args: Any, **kwargs: Any) -> Any:
            self.events.append("model.trace." + mode)
            return trace(*args, **kwargs)

        def inject_execution_observations() -> None:
            # Synthetic semantics: x0 receives a sandbox pointer. All other results
            # are zero from the real input loader. This is not an executed program.
            main = model.layout.get_data_addr(DataArea.MAIN, 0)
            model.emulator.reg_write(model._uc_target_desc.usable_registers[0], main)
            model.tracer.enable_tracing = True
            model.tracer.observe_instruction(model.layout.code_start() + 4, 4)
            model.tracer.observe_mem_access(UC_MEM_READ, main + 8, 8, 0)

        self._patches.enter_context(patch.object(
            model, "load_test_case", side_effect=record_load))
        self._patches.enter_context(patch.object(
            model, "trace_test_case", side_effect=record_trace))
        self._patches.enter_context(patch.object(
            model, "_run_state_machine", side_effect=inject_execution_observations))
        return model

    def _open_sysfs(self, path: str, mode: str) -> StringIO:
        self.assertEqual(mode, "r")
        if path == "/sys/rvzr_executor/print_data_base":
            self.events.append("read.data")
            return StringIO(hex(self.hardware_bases[0]) + "\n")
        if path == "/sys/rvzr_executor/print_code_base":
            self.events.append("read.code")
            return StringIO(hex(self.hardware_bases[1]) + "\n")
        self.assertEqual(path, "/sys/rvzr_executor/inputs")
        self.events.append("inputs.ready")
        return StringIO("1\n")

    def _configure(self, value: str, path: str) -> None:
        self.assertEqual(path, "/sys/rvzr_executor/enable_dbg_gpr_mode")
        self.assertIn(value, ("0", "1"))
        self.events.append("configure.arch" if value == "1" else "configure.normal")

    def _upload_test_case(self, path: str) -> None:
        self.assertEqual(path, "/sys/rvzr_executor/test_case")
        self.events.append("upload.test_case")
        self.hardware_bases = self.upload_bases

    def _upload_inputs(self, inputs: List[InputData], path: str) -> None:
        self.assertEqual(inputs, self.inputs)
        self.assertEqual(path, "/sys/rvzr_executor/inputs")
        self.events.append("inputs.upload")

    def _read_trace(self, n_reps: int, n_inputs: int, arch_mode: bool) -> Iterator[
            Tuple[int, int, Tuple[int, int, int, int, int, int]]]:
        self.assertEqual((n_reps, n_inputs), (1, 1))
        self.events.append("hardware.trace.arch" if arch_mode else "hardware.trace.normal")
        # In normal mode this is just an opaque cache-trace fixture. Only the arch
        # path interprets it as x0 followed by five register results.
        yield 0, 0, (self.hardware_bases[0] + 4096, 0, 0, 0, 0, 0)

    def _assert_model_addresses(self, model: Any, bases: BaseAddrTuple) -> None:
        self.assertEqual(model._bases, bases)
        self.assertEqual((model.layout.data_start(), model.layout.code_start()), bases)
        self.assertEqual(model._taint_tracker._data_start, bases[0])
        self.assertEqual(model.state.exit_addr, bases[1] + 3)
        self.assertEqual(model.state.fault_handler_addr, bases[1] + 3)
        self.assertEqual(model.layout.get_data_addr(DataArea.MAIN, 1), bases[0] + 20480)
        self.assertIs(model.state._layout, model.layout)
        self.assertIs(model._log.model_layout, model.layout)
        self.assertIs(model.tracer._model, model)
        self.assertEqual(
            sorted((start, end) for start, end, _ in model.emulator.mem_regions()),
            sorted([(bases[0], bases[0] + model.layout.data_size - 1),
                    (bases[1], bases[1] + model.layout.code_size - 1)]))

    def test_startup_acquires_addresses_before_constructing_both_models(self) -> None:
        self.assertEqual(self.events, [
            "executor.create.normal", "read.data", "read.code", "model.create.normal",
            "executor.create.arch", "read.data", "read.code", "model.create.arch",
        ])
        self.assertEqual(self.model._bases, self.BASES_A)
        self.assertEqual(self.arch_model._taint_tracker._data_start, self.BASES_A[0])

    def test_ordinary_round_order_with_unchanged_allocation(self) -> None:
        self.events.clear()
        manager = _RoundManager(self.fuzzer, self.test_case, self.inputs)
        manager.execute_stage("fast")
        self.assertEqual(self.events, [
            "model.load.normal", "configure.normal", "upload.test_case", "model.trace.normal",
            "inputs.upload", "inputs.ready", "hardware.trace.normal",
        ])
        self._assert_model_addresses(self.fuzzer.model, self.hardware_bases)
        self.assertEqual(manager.ctraces[0].get_untyped(), [4, 4104])
        self.assertFalse(manager.violations)

    def test_legacy_risk_ordinary_round_retains_startup_addresses_after_relocation(self) -> None:
        self.upload_bases = self.BASES_B
        self.events.clear()
        manager = _RoundManager(self.fuzzer, self.test_case, self.inputs)
        manager.execute_stage("fast")
        self.assertEqual(self.events, [
            "model.load.normal", "configure.normal", "upload.test_case", "model.trace.normal",
            "inputs.upload", "inputs.ready", "hardware.trace.normal",
        ])
        self.assertEqual(self.hardware_bases, self.BASES_B)
        self._assert_model_addresses(self.fuzzer.model, self.BASES_A)
        # Normalization can conceal the absolute-base discrepancy in a contract
        # trace; this asserts no equivalence to real cache measurements.
        self.assertEqual(manager.ctraces[0].get_untyped(), [4, 4104])

    def test_legacy_risk_repeated_model_loading_does_not_refresh_addresses(self) -> None:
        _RoundManager(self.fuzzer, self.test_case, self.inputs)
        old_emulator = self.model.emulator
        old_state = self.model.state
        self.upload_bases = self.BASES_B
        self.events.clear()
        _RoundManager(self.fuzzer, self.test_case, self.inputs)
        _RoundManager(self.fuzzer, self.test_case, self.inputs)
        self.assertEqual(self.events, [
            "model.load.normal", "configure.normal", "upload.test_case",
            "model.load.normal", "configure.normal", "upload.test_case",
        ])
        self.assertIsNot(self.model.emulator, old_emulator)
        self.assertIsNot(self.model.state, old_state)
        self.assertEqual(self.hardware_bases, self.BASES_B)
        self._assert_model_addresses(self.fuzzer.model, self.BASES_A)

    def test_failed_upload_propagates_after_model_load_without_collecting_traces(self) -> None:
        def reject_upload(path: str) -> None:
            self.assertEqual(path, "/sys/rvzr_executor/test_case")
            self.events.append("upload.failed")
            raise IOError("synthetic transport failure")

        # Only Python error propagation is characterized. No assertion about kernel
        # readiness, rollback, or partially allocated memory follows from this.
        self.test_case.get_obj.return_value.save_rcbf.side_effect = reject_upload
        self.events.clear()
        with self.assertRaisesRegex(IOError, "synthetic transport failure"):
            _RoundManager(self.fuzzer, self.test_case, self.inputs)
        self.assertEqual(self.events, [
            "model.load.normal", "configure.normal", "upload.failed",
        ])
        self._assert_model_addresses(self.model, self.BASES_A)
        self.assertIsNone(self.fuzzer.executor._curr_test_case)

    def _architectural_round(self, relocate: bool) -> _RoundManager:
        manager = _RoundManager(self.fuzzer, self.test_case, self.inputs)
        self.upload_bases = self.BASES_B if relocate else self.BASES_A
        self.events.clear()
        manager.execute_stage("arch_mismatch")
        self.assertEqual(self.events, [
            "model.load.arch", "configure.arch", "upload.test_case", "inputs.upload",
            "inputs.ready", "hardware.trace.arch", "model.trace.arch",
        ])
        self._assert_model_addresses(self.fuzzer.arch_model, self.BASES_A)
        return manager

    def test_architectural_check_unchanged_allocation_matches_raw_pointer_results(self) -> None:
        manager = self._architectural_round(relocate=False)
        self.assertFalse(manager.arch_violations)

    def test_legacy_risk_architectural_check_compares_unadjusted_pointer_results(self) -> None:
        manager = self._architectural_round(relocate=True)
        self.assertEqual(self.hardware_bases, self.BASES_B)
        self.assertEqual(len(manager.arch_violations), 1)
        # The real comparison reports a mismatch for injected pointer results.
        # It does not establish that any particular ARM64 program produces them.
        measurement = manager.arch_violations[0].measurements[0]
        self.assertEqual(measurement.ctrace.get_untyped(), [self.BASES_A[0] + 4096] + [0] * 5)
        self.assertEqual(list(measurement.htrace.get_raw_readings()[0]),
                         [self.BASES_B[0] + 4096] + [0] * 5)

    def test_legacy_risk_changing_bases_and_reloading_leaves_taint_origin_stale(self) -> None:
        model = self.model
        model.load_test_case(self.test_case)
        tracker = model._taint_tracker
        # Test-only mutation demonstrates why it is not a complete proposed fix.
        model._bases = self.BASES_B
        model.load_test_case(self.test_case)
        model.trace_test_case(self.inputs, nesting=1)
        self.assertEqual(model.layout.data_start(), self.BASES_B[0])
        self.assertEqual(model.state.exit_addr, self.BASES_B[1] + 3)
        self.assertIs(model._taint_tracker, tracker)
        self.assertEqual(tracker._data_start, self.BASES_A[0])
        self.assertIs(model._log.model_layout, model.layout)
        self.assertIs(model.speculator._emulator, model.emulator)
        tracker.set_enable_tracking(True)
        tracker.reset()
        tracker.track_instruction(Instruction("ldr"))
        tracker.track_memory_access(self.BASES_B[0] + 4096, 8, is_write=False)
        assert tracker._instruction is not None
        self.assertEqual(tracker._instruction.src_mems,
                         {hex(self.BASES_B[0] - self.BASES_A[0] + 4096)})
        self.assertNotIn(hex(4096), tracker._instruction.src_mems)

    def test_tracer_normalizes_address_events_but_preserves_pointer_values(self) -> None:
        model = self.model
        results = []
        for bases in (self.BASES_A, self.BASES_B):
            model._bases = bases  # Isolated tracer probe, not a rebinding strategy.
            model.load_test_case(self.test_case)
            pointer = bases[0] + 4096
            model.tracer.trace = [
                CTraceEntry("pc", bases[1] + 4), CTraceEntry("mem", pointer + 8),
                CTraceEntry("reg", pointer), CTraceEntry("val", pointer),
            ]
            results.append(model.tracer.get_trace().get_untyped())
        self.assertEqual(results[0][:2], [4, 4104])
        self.assertEqual(results[1][:2], results[0][:2])
        self.assertEqual(results[0][2:], [self.BASES_A[0] + 4096] * 2)
        self.assertEqual(results[1][2:], [self.BASES_B[0] + 4096] * 2)
        self.assertNotEqual(results[0][2:], results[1][2:])


if __name__ == "__main__":
    unittest.main()
