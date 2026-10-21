"""Coverage lifecycle characterization, not a specification of desired defects.

Tests named legacy_risk pin non-idempotent finalization/reporting and stale
signature caching. Change those expectations when the corresponding defects
are fixed. No nondeterministic object-ID reuse is forced. The cache is isolated
per test and restored afterward; the production implementation is unchanged.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

from contextlib import ExitStack
import gc
from pathlib import Path
import tempfile
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
        stack.enter_context(patch.object(coverage, "_SIGNATURE_CACHE", {}))
        self.directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="rvzr-cov-")))
        self.coverage = coverage.InstructionCoverage()
        self.coverage.start_test_case()

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

    def test_instrumentation_is_excluded_without_populating_signature_cache(self) -> None:
        inst = Instruction("nop", is_instrumentation=True)
        self.coverage.add_instruction(inst)
        self.assertEqual(self.coverage._local_cov, {})
        self.assertEqual(coverage._SIGNATURE_CACHE, {})

    def test_disabled_coverage_does_not_record_or_cache_instructions(self) -> None:
        with synthetic_environment(coverage="none"):
            self.coverage.start_test_case()
            self.coverage.add_instruction(Instruction("nop"))
            self.coverage.finish_test_case()
        self.assertIsNone(self.coverage._local_cov)
        self.assertEqual(self.coverage._cov, {})
        self.assertEqual(coverage._SIGNATURE_CACHE, {})

    def test_legacy_risk_repeated_finish_counts_the_same_pending_interval_again(self) -> None:
        self.coverage.add_instruction(Instruction("nop"))
        for count in (1, 2, 3):
            self.coverage.finish_test_case()
            self.assertEqual(self.coverage._cov, {"nop": count})
            self.assertEqual(self.coverage._local_cov, {"nop": 1})

    def test_legacy_risk_report_mutates_counts_on_each_request(self) -> None:
        self.coverage.add_instruction(Instruction("nop"))
        report = self.directory / "coverage.txt"
        for count in (1, 2):
            self.coverage.report(str(report))
            self.assertEqual(self.coverage._cov, {"nop": count})
            self.assertEqual(report.read_text(encoding="utf-8").split(), ["nop", str(count)])

    def test_legacy_risk_operand_mutation_does_not_invalidate_cached_signature(self) -> None:
        inst = Instruction("shape")
        inst.add_op(RegisterOp("x0", 64, False, True))
        self.assertEqual(coverage._get_instruction_signature(inst), "shape R64")
        inst.add_op(MemoryOp("x20", 64, True, False))
        self.assertEqual(coverage._get_instruction_signature(inst), "shape R64")
        # A new, equivalent instruction demonstrates the expected uncached shape.
        fresh = Instruction("shape")
        fresh.add_op(RegisterOp("x0", 64, False, True))
        fresh.add_op(MemoryOp("x20", 64, True, False))
        self.assertEqual(coverage._get_instruction_signature(fresh), "shape R64 M64")

    def test_legacy_risk_cache_entry_survives_instruction_collection(self) -> None:
        inst = Instruction("nop")
        identifier, reference = id(inst), weakref.ref(inst)
        coverage._get_instruction_signature(inst)
        del inst
        gc.collect()
        self.assertIsNone(reference())
        self.assertEqual(coverage._SIGNATURE_CACHE, {identifier: "nop"})
        # This proves retained ID metadata, not actual ID reuse or a model/native leak.


if __name__ == "__main__":
    unittest.main()
