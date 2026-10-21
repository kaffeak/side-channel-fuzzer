"""Coverage finalization/reporting and current instruction-shape regressions.

Signatures are computed without an object-ID cache. Mutation and collection
checks do not depend on nondeterministically reusing a Python object ID.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access
# pylint: disable=too-many-public-methods

from contextlib import ExitStack
from copy import deepcopy
import gc
from pathlib import Path
import tempfile
from typing import Dict
import unittest
from unittest.mock import patch
import weakref

import numpy as np

from rvzr.model_unicorn import coverage
from rvzr.model_unicorn.preparation import prepare_unicorn_model
from rvzr.tc_components.instruction import (
    AgenOp, CondOp, FlagsOp, ImmediateOp, Instruction, LabelOp, MemoryOp, RegisterOp,
)
from rvzr.tc_components.test_case_data import InputData
from tools.probe_unicorn_model_lifetime import (
    make_descriptor, make_test_case, synthetic_environment,
)


class ModelCoverageLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(synthetic_environment(coverage="model_instructions"))
        self.directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="rvzr-cov-")))
        self.coverage = coverage.InstructionCoverage()
        self.coverage.start_test_case()

    def assert_report(self, expected: Dict[str, int]) -> None:
        state = deepcopy(vars(self.coverage))
        campaign, local = self.coverage._cov, self.coverage._local_cov
        finalized = self.coverage._finalized_signatures
        report = self.directory / "coverage.txt"
        self.coverage.report(str(report))
        self.assertEqual(vars(self.coverage), state)
        self.assertIs(self.coverage._cov, campaign)
        self.assertIs(self.coverage._local_cov, local)
        self.assertIs(self.coverage._finalized_signatures, finalized)
        lines = report.read_text(encoding="utf-8").splitlines()
        if not expected:
            self.assertEqual(lines, ["    No coverage data available"])
            return
        entries = [line.rsplit(maxsplit=1) for line in lines]
        self.assertEqual({name: int(count) for name, count in entries}, expected)
        self.assertEqual(len(entries), len(expected))
        self.assertEqual([int(count) for _, count in entries],
                         sorted(expected.values(), reverse=True))

    def test_signature_contains_mnemonic_and_explicit_operand_kinds_and_widths(self) -> None:
        inst = Instruction("shape")
        inst.add_op(RegisterOp("x0", 64, False, True))
        inst.add_op(MemoryOp("x20", 32, True, False))
        inst.add_op(ImmediateOp("7", 8))
        inst.add_op(LabelOp(".target"))
        inst.add_op(AgenOp("x1", 64))
        inst.add_op(FlagsOp(("",) * 9))
        inst.add_op(CondOp("eq"))
        inst.add_op(RegisterOp("x2", 32, True, False), implicit=True)
        self.assertEqual(coverage._get_instruction_signature(inst), "shape R64 M32 I8 L A64 F C")

    def test_signature_ignores_operand_values_register_names_and_memory_addresses(self) -> None:
        first, second = Instruction("ldr"), Instruction("ldr")
        first.add_op(RegisterOp("x0", 64, False, True))
        first.add_op(MemoryOp("x20 + 0x109000", 64, True, False))
        second.add_op(RegisterOp("x5", 64, False, True))
        second.add_op(MemoryOp("x21 + 0x309000", 64, True, False))
        self.assertEqual(coverage._get_instruction_signature(first), "ldr R64 M64")
        self.assertEqual(coverage._get_instruction_signature(second), "ldr R64 M64")

    def test_actor_sourced_instructions_with_identical_signatures_are_combined(self) -> None:
        test_case = make_test_case(self.directory, 2)
        instructions = test_case.get_obj().instruction_map()
        # Submit actual per-actor instruction objects to coverage; this does not
        # claim the tiny fixture executes both actors (it executes only main).
        self.coverage.add_instruction(instructions[0][4])
        self.coverage.add_instruction(instructions[1][4])
        self.assertEqual(self.coverage._local_cov, {"mov R64 R64": 2})
        self.coverage.finish_test_case()
        self.assertEqual(self.coverage._cov, {"mov R64 R64": 1})

    def test_local_executions_and_campaign_finalizations_have_different_units(self) -> None:
        inst = Instruction("nop")
        for _ in range(5):
            self.coverage.add_instruction(inst)
        self.assertEqual(self.coverage._local_cov, {"nop": 5})
        self.assertEqual(self.coverage._cov, {})
        self.coverage.finish_test_case()
        self.assertEqual(self.coverage._cov, {"nop": 1})
        self.coverage.start_test_case()
        self.assertEqual(self.coverage._local_cov, {})
        self.coverage.add_instruction(inst)
        self.coverage.finish_test_case()
        self.assertEqual(self.coverage._cov, {"nop": 2})

    def test_accumulates_real_model_inputs_and_finalizes_at_next_load(self) -> None:
        first_case = make_test_case(self.directory, 1)
        second_case = make_test_case(self.directory, 1)
        model = prepare_unicorn_model(first_case, make_descriptor(1),
                                      expected_payload_byte_order="little")
        input_ = InputData(1)
        input_.view(np.uint8).fill(0)
        model.trace_test_case([input_, input_], nesting=1)
        observed = model._dispatcher.coverage
        self.assertEqual(observed._local_cov, {"mov R64 R64": 2, "ldr R64 M64": 2})
        self.assertEqual(observed._cov, {})
        model.load_test_case(second_case)
        self.assertEqual(observed._cov, {"mov R64 R64": 1, "ldr R64 M64": 1})
        self.assertEqual(observed._local_cov, {})
        model.trace_test_case([input_], nesting=1)
        observed.finish_test_case()
        self.assertEqual(observed._cov, {"mov R64 R64": 2, "ldr R64 M64": 2})

    def test_relocation_does_not_change_signature_keys_for_controlled_fixture(self) -> None:
        test_case = make_test_case(self.directory, 1)
        input_ = InputData(1)
        input_.view(np.uint8).fill(0)
        observations = []
        for relocated in (False, True):
            model = prepare_unicorn_model(test_case, make_descriptor(1, relocated=relocated),
                                          expected_payload_byte_order="little")
            model.trace_test_case([input_], nesting=1)
            observations.append(dict(model._dispatcher.coverage._local_cov or {}))
        self.assertEqual(observations, [{"mov R64 R64": 1, "ldr R64 M64": 1}] * 2)

    def test_instrumentation_is_excluded_without_computing_signatures(self) -> None:
        inst = Instruction("nop", is_instrumentation=True)
        with patch.object(coverage, "_get_instruction_signature",
                          side_effect=AssertionError("Instrumentation signature requested")):
            self.coverage.add_instruction(inst)
        self.assertEqual(self.coverage._local_cov, {})

    def test_disabled_coverage_does_not_record_or_compute_signatures(self) -> None:
        with synthetic_environment(coverage="none"), \
                patch.object(coverage, "_get_instruction_signature",
                             side_effect=AssertionError("Disabled signature requested")):
            self.coverage.start_test_case()
            self.coverage.add_instruction(Instruction("nop"))
            self.coverage.finish_test_case()
        self.assertIsNone(self.coverage._local_cov)
        self.assertEqual(self.coverage._cov, {})

    def test_repeated_finish_commits_the_same_interval_only_once(self) -> None:
        self.coverage.add_instruction(Instruction("nop"))
        for _ in range(3):
            self.coverage.finish_test_case()
            self.assertEqual(self.coverage._cov, {"nop": 1})
            self.assertEqual(self.coverage._local_cov, {"nop": 1})
            self.assertEqual(self.coverage._finalized_signatures, {"nop"})

    def test_repeated_reports_include_pending_interval_without_committing_it(self) -> None:
        self.coverage.add_instruction(Instruction("nop"))
        for _ in range(2):
            self.assert_report({"nop": 1})
            self.assertEqual(self.coverage._cov, {})
            self.assertEqual(self.coverage._finalized_signatures, set())
        self.coverage.finish_test_case()
        self.assertEqual(self.coverage._cov, {"nop": 1})

    def test_repeated_reports_after_finalization_do_not_count_local_data_again(self) -> None:
        self.coverage.add_instruction(Instruction("nop"))
        self.coverage.finish_test_case()
        for _ in range(2):
            self.assert_report({"nop": 1})
        self.coverage.finish_test_case()
        self.assertEqual(self.coverage._cov, {"nop": 1})

    def test_reporting_empty_intervals_before_and_after_finish(self) -> None:
        self.assert_report({})
        self.coverage.finish_test_case()
        self.assert_report({})
        self.coverage.add_instruction(Instruction("nop"))
        self.coverage.finish_test_case()
        self.coverage.start_test_case()
        self.assert_report({"nop": 1})
        self.coverage.finish_test_case()
        self.assert_report({"nop": 1})

    def test_reporting_before_any_interval_is_a_no_op(self) -> None:
        self.coverage = coverage.InstructionCoverage()
        self.coverage.finish_test_case()
        self.assert_report({})
        self.assertIsNone(self.coverage._local_cov)

    def test_reporting_does_not_close_interval_or_change_subsequent_observations(self) -> None:
        nop, other = Instruction("nop"), Instruction("other")
        self.coverage.add_instruction(nop)
        self.assert_report({"nop": 1})
        self.coverage.add_instruction(nop)
        self.coverage.add_instruction(other)
        self.assert_report({"nop": 1, "other": 1})
        self.assertEqual(self.coverage._local_cov, {"nop": 2, "other": 1})
        self.coverage.finish_test_case()
        self.assertEqual(self.coverage._cov, {"nop": 1, "other": 1})

    def test_observations_after_finish_still_contribute_only_once_per_load_interval(self) -> None:
        nop, other = Instruction("nop"), Instruction("other")
        self.coverage.add_instruction(nop)
        self.coverage.finish_test_case()
        self.coverage.add_instruction(nop)
        self.coverage.add_instruction(other)
        for _ in range(2):
            self.assert_report({"nop": 1, "other": 1})
        self.assertEqual(self.coverage._cov, {"nop": 1})
        for _ in range(2):
            self.coverage.finish_test_case()
        self.assertEqual(self.coverage._local_cov, {"nop": 2, "other": 1})
        self.assertEqual(self.coverage._cov, {"nop": 1, "other": 1})

    def test_consecutive_intervals_with_overlapping_and_distinct_signatures(self) -> None:
        common, first, second = (Instruction(name) for name in ("common", "first", "second"))
        for inst in (common, common, first):
            self.coverage.add_instruction(inst)
        self.coverage.finish_test_case()
        self.coverage.start_test_case()
        for inst in (common, second, second):
            self.coverage.add_instruction(inst)
        self.assert_report({"common": 2, "first": 1, "second": 1})
        self.assertEqual(self.coverage._cov, {"common": 1, "first": 1})
        self.coverage.finish_test_case()
        self.coverage.finish_test_case()
        self.assert_report({"common": 2, "first": 1, "second": 1})
        self.assertEqual(self.coverage._local_cov, {"common": 1, "second": 2})

    def test_disabled_coverage_preserves_history_without_recording_or_finalizing(self) -> None:
        self.coverage.add_instruction(Instruction("nop"))
        self.coverage.finish_test_case()
        with synthetic_environment(coverage="none"):
            self.coverage.start_test_case()
            state = deepcopy(vars(self.coverage))
            self.coverage.add_instruction(Instruction("disabled"))
            self.coverage.finish_test_case()
            self.coverage.finish_test_case()
            self.assert_report({"nop": 1})
            self.assertEqual(vars(self.coverage), state)

    def test_report_write_failure_does_not_commit_pending_coverage(self) -> None:
        self.coverage.add_instruction(Instruction("nop"))
        state = deepcopy(vars(self.coverage))
        with self.assertRaises(FileNotFoundError):
            self.coverage.report(str(self.directory / "missing" / "coverage.txt"))
        self.assertEqual(vars(self.coverage), state)
        self.assert_report({"nop": 1})

    def test_real_model_load_after_explicit_finish_does_not_commit_interval_again(self) -> None:
        test_case = make_test_case(self.directory, 1)
        model = prepare_unicorn_model(test_case, make_descriptor(1),
                                      expected_payload_byte_order="little")
        input_ = InputData(1)
        input_.view(np.uint8).fill(0)
        model.trace_test_case([input_, input_], nesting=1)
        self.coverage = model._dispatcher.coverage
        self.coverage.finish_test_case()
        expected = {"mov R64 R64": 1, "ldr R64 M64": 1}
        self.assert_report(expected)
        model.load_test_case(test_case)
        self.assertEqual(self.coverage._cov, expected)
        self.assertEqual(self.coverage._local_cov, {})
        self.assertEqual(self.coverage._finalized_signatures, set())
        model.trace_test_case([input_, input_], nesting=1)
        self.assert_report({name: 2 for name in expected})
        self.assertEqual(self.coverage._cov, expected)
        self.coverage.finish_test_case()
        self.assertEqual(self.coverage._cov, {name: 2 for name in expected})

    def test_normal_and_architectural_model_coverage_remains_independent(self) -> None:
        test_case, allocation = make_test_case(self.directory, 1), make_descriptor(1)
        normal = prepare_unicorn_model(test_case, allocation,
                                       expected_payload_byte_order="little")
        architectural = prepare_unicorn_model(test_case, allocation,
                                              expected_payload_byte_order="little",
                                              enable_mismatch_check_mode=True)
        self.coverage = normal._dispatcher.coverage
        other = architectural._dispatcher.coverage
        self.assertIsNot(self.coverage, other)
        input_ = InputData(1)
        input_.view(np.uint8).fill(0)
        normal.trace_test_case([input_], nesting=1)
        self.coverage.finish_test_case()
        expected = {"mov R64 R64": 1, "ldr R64 M64": 1}
        self.assert_report(expected)
        self.assertEqual(other._cov, {})
        self.assertEqual(other._local_cov, {})
        self.assertEqual(other._finalized_signatures, set())
        architectural.trace_test_case([input_], nesting=1)
        other.finish_test_case()
        architectural.load_test_case(test_case)
        self.assertEqual(other._cov, expected)
        self.assert_report(expected)

    def test_signature_reflects_appended_operands(self) -> None:
        inst = Instruction("shape")
        inst.add_op(RegisterOp("x0", 64, False, True))
        self.assertEqual(coverage._get_instruction_signature(inst), "shape R64")
        inst.add_op(MemoryOp("x20", 64, True, False))
        self.assertEqual(coverage._get_instruction_signature(inst), "shape R64 M64")
        # A new, equivalent instruction has the same current shape.
        fresh = Instruction("shape")
        fresh.add_op(RegisterOp("x0", 64, False, True))
        fresh.add_op(MemoryOp("x20", 64, True, False))
        self.assertEqual(coverage._get_instruction_signature(fresh), "shape R64 M64")

    def test_signature_reads_current_mnemonic_on_each_call(self) -> None:
        inst = Instruction("before").add_op(RegisterOp("x0", 64, False, True))
        self.assertEqual(coverage._get_instruction_signature(inst), "before R64")
        # name is Final for typed callers, but Python does not freeze it at runtime.
        with patch.object(inst, "name", "after"):
            self.assertEqual(coverage._get_instruction_signature(inst), "after R64")
        self.assertEqual(coverage._get_instruction_signature(inst), "before R64")

    def test_coverage_reflects_operand_replacement_reordering_and_removal(self) -> None:
        inst = Instruction("shape")
        inst.add_op(RegisterOp("x0", 64, False, True))
        inst.add_op(MemoryOp("x20", 64, True, False))
        self.coverage.add_instruction(inst)
        inst.operands[0] = RegisterOp("w0", 32, False, True)
        inst.operands[1] = MemoryOp("x20", 128, True, False)
        self.coverage.add_instruction(inst)
        inst.operands.reverse()
        self.coverage.add_instruction(inst)
        inst.operands.pop()
        self.coverage.add_instruction(inst)
        inst.operands.clear()
        self.coverage.add_instruction(inst)
        expected = {"shape R64 M64": 1, "shape R32 M128": 1, "shape M128 R32": 1,
                    "shape M128": 1, "shape": 1}
        self.assertEqual(self.coverage._local_cov, expected)
        self.assert_report(expected)
        self.coverage.finish_test_case()
        self.coverage.finish_test_case()
        self.assertEqual(self.coverage._cov, expected)

    def test_signature_computation_does_not_retain_discarded_instruction_objects(self) -> None:
        references = []
        # Distinct shapes and widths exercise churn without requiring any ID collision.
        for index in range(128):
            inst = Instruction(f"shape{index}")
            inst.add_op(ImmediateOp(str(index), 8 if index % 2 == 0 else 64))
            expected = f"shape{index} I{8 if index % 2 == 0 else 64}"
            self.assertEqual(coverage._get_instruction_signature(inst), expected)
            self.coverage.add_instruction(inst)
            references.append(weakref.ref(inst))
            del inst
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertFalse(hasattr(coverage, "_SIGNATURE_CACHE"))
        self.assertEqual(len(self.coverage._local_cov or {}), 128)
        self.coverage.finish_test_case()
        self.assertEqual(len(self.coverage._cov), 128)
        # Coverage deliberately retains signature strings/counts, not instruction objects.


if __name__ == "__main__":
    unittest.main()
