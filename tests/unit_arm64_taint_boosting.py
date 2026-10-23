"""Real one-actor ARM64 taints and boosting; no kernel execution.

Reuse B3.4b's GNU/ELF/Unicorn fixture and B3.4a's host adapter. Only CPU
identification/tool lookup and, in the RoundManager test, the hardware boundary
are adapted. Tracing, dependency tracking and boosted data generation are real.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access

from contextlib import ExitStack
from copy import deepcopy
from itertools import product
from pathlib import Path
import tempfile
from typing import List
import unittest
from unittest.mock import MagicMock, patch

import numpy as np

from rvzr import factory
from rvzr.config import CONF
from rvzr.fuzzer import Fuzzer, _RoundManager
from rvzr.isa_spec import InstructionSet
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputTaint
from tests.unit_arm64_contract_slice import software_environment
from tests.unit_arm64_conditional_contract import assemble_case, make_input, make_model


_ARM = Path(__file__).resolve().parent / "arm64"
_X0, _X4, _NZCV = 1024, 1028, 1030  # Fixed input word indices, not sandbox addresses.


class ARM64TaintBoostingTest(unittest.TestCase):
    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.directory = Path(stack.enter_context(tempfile.TemporaryDirectory(
            prefix="rvzr-arm64-taint-")))
        stack.enter_context(software_environment(self.directory))
        CONF.model_max_spec_window = 32
        CONF.data_generator_entropy_bits = 8
        CONF.input_gen_probability_of_special_value = 0.0
        CONF.inputs_per_class = 3
        self.case = assemble_case(self.directory)

    def assert_taint(self, taint: InputTaint, indices: List[int]) -> None:
        self.assertEqual(taint.shape, (1,))
        self.assertEqual(np.flatnonzero(taint.linear_view(0)).tolist(), sorted(indices))

    def memory_address_case(self) -> TestCaseProgram:
        """Derive a bounded load-value -> address dependency from the original fixture."""
        source = (_ARM / "asm/conditional_contract_slice.asm").read_text(encoding="ascii")
        self.assertEqual(source.count("add x4, x20, #128"), 1)
        source = source.replace("add x4, x20, #128", "ldr x4, [x20], #0\n"
                                "    and x4, x4, #128\n    add x4, x20, x4")
        template = self.directory / "taint-address.asm"
        template.write_text(source, encoding="ascii")
        isa = InstructionSet(str(_ARM / "min_arm64.json"))
        return factory.get_program_generator(1, isa).create_test_case_from_template(str(template))

    def test_branch_dependency_both_directions_and_value_only_loads(self) -> None:
        # CT observes addresses, not payload values. CMP -> ZF -> PC must preserve X0.
        # The shared tracker is conservative: initial NZCV and initial X4 (ADD dest)
        # remain dependencies even though this particular program overwrites them.
        for clause in ("seq", "cond"):
            model = make_model(clause, self.case)
            inputs = [make_input(selector) for selector in (0, 1, 0)]
            before = [input_.tobytes() for input_ in inputs]
            traces, taints = model.trace_test_case_with_taints(inputs, nesting=1)
            for index, selector in enumerate((0, 1, 0)):
                with self.subTest(clause=clause, selector=selector):
                    expected = [_X0, _NZCV]
                    if selector == 0 or clause == "cond":
                        expected.append(_X4)
                    self.assert_taint(taints[index], expected)
                    self.assertFalse(taints[index][0]["main"].any())
            self.assertNotEqual(traces[0], traces[1])
            self.assertEqual(traces[0], traces[2])
            self.assertEqual(model.trace_test_case(inputs, nesting=1), traces)
            self.assertEqual([input_.tobytes() for input_ in inputs], before)

    def test_loaded_value_taints_only_when_used_as_an_observed_address(self) -> None:
        case = self.memory_address_case()
        for clause in ("seq", "cond"):
            model = make_model(clause, case)
            inputs = [make_input(selector) for selector in (0, 1)]
            for input_ in inputs:
                input_[0]["main"][0] = 135  # AND #128 bounds the derived offset to 0 or 128.
            traces, taints = model.trace_test_case_with_taints(inputs, nesting=1)
            for index in range(2):
                expected = [_X0, _NZCV]
                if index == 0 or clause == "cond":
                    expected += [0, _X4]
                self.assert_taint(taints[index], expected)
            expected_memory = [[4096, 4224, 4224], [4096, 4096, 4096]] if clause == "seq" \
                else [[4096, 4096, 4096, 4224, 4224], [4096, 4224, 4224, 4096, 4096]]
            self.assertEqual([[entry.value for entry in trace.get_typed() if entry.type_ == "mem"]
                              for trace in traces], expected_memory)
            # A tainted load value really changes an observed address on the taken path.
            changed_taken = make_input(0)  # main[0]=7 instead of 135: offset 0 instead of 128.
            self.assertNotEqual(model.trace_test_case([changed_taken], nesting=1)[0], traces[0])
            # An unobserved loaded value can change without changing the sequential CT.
            if clause == "seq":
                changed = make_input(1)
                changed[0]["main"][0] = 7
                self.assertEqual(model.trace_test_case([changed], nesting=1)[0], traces[1])

    def test_checkpoint_rollback_restores_dependencies_keeps_transient_observations(self) -> None:
        model = make_model("cond", self.memory_address_case())
        tracker = model._taint_tracker
        rollback = tracker.rollback
        restored = []

        def observe_rollback() -> None:
            saved = deepcopy(tracker._checkpoints[-1])
            rollback()
            for kind in ("reg", "flag", "mem"):
                self.assertEqual(getattr(tracker._dependencies, kind), getattr(saved, kind))
            # Input main[0] controls only the wrong-path address for X0=1. Its
            # observation must survive rollback; architectural dependencies must not.
            self.assertIn("0x1000", tracker._tainted_labels)
            restored.append(True)

        with patch.object(tracker, "rollback", side_effect=observe_rollback):
            traces, taints = model.trace_test_case_with_taints([make_input(1)], nesting=1)
        self.assertEqual(restored, [True])
        self.assert_taint(taints[0], [0, _X0, _X4, _NZCV])
        self.assertEqual(tracker._checkpoints, [])
        self.assertFalse(tracker._tracking_in_progress)
        changed_wrong_path = make_input(1)
        changed_wrong_path[0]["main"][0] = 135
        self.assertNotEqual(model.trace_test_case([changed_wrong_path], nesting=1)[0], traces[0])

    def test_repetition_batch_reset_and_tracking_mode_switch(self) -> None:
        model = make_model("cond", self.memory_address_case())
        input_ = make_input(1)
        traces, taints = model.trace_test_case_with_taints([input_], nesting=1)
        original = taints[0].copy()
        self.assert_taint(taints[0], [0, _X0, _X4, _NZCV])
        # Same model/input, no speculative window: wrong-path address is unobserved.
        _, sequential_taints = model.trace_test_case_with_taints([input_], nesting=0)
        self.assert_taint(sequential_taints[0], [_X0, _NZCV])
        self.assertEqual(model.trace_test_case([input_], nesting=1), traces)
        repeated, repeated_taints = model.trace_test_case_with_taints([input_, input_], nesting=1)
        self.assertEqual(repeated, traces * 2)
        for taint in repeated_taints:
            np.testing.assert_array_equal(taint, original)
        np.testing.assert_array_equal(taints[0], original)
        self.assertEqual(model._taint_tracker._checkpoints, [])

    def test_production_booster_preserves_taints_varies_other_words_and_retraces(self) -> None:
        # Explicit random candidates/parents/masks keep the copy checks inspectable.
        # pylint: disable=too-many-locals
        case = self.memory_address_case()
        for clause, probability in product(("seq", "cond"), (0.0, 0.05)):
            CONF.input_gen_probability_of_special_value = probability
            model = make_model(clause, case)
            inputs = [make_input(0), make_input(1)]
            for input_ in inputs:
                input_[0]["main"][0] = 135
            traces, taints = model.trace_test_case_with_taints(inputs, nesting=1)
            originals = [input_.tobytes() for input_ in inputs]
            generator = factory.get_data_generator(123)
            boosted = generator.generate_boosted(inputs, taints, inputs_per_class=3)
            repeated = generator.generate_boosted(inputs, taints, inputs_per_class=3)
            self.assertEqual(len(boosted), 6)
            self.assertEqual([item.tobytes() for item in boosted],
                             [item.tobytes() for item in repeated])
            self.assertEqual(generator.get_state(), 123)
            # A second real generator supplies the random candidates, not a parallel
            # implementation of the boosting algorithm or hand-written random data.
            random_candidates = factory.get_data_generator(123).generate(4, n_actors=1)
            for index, item in enumerate(boosted[2:]):
                parent = index % 2
                mask = taints[parent].linear_view(0)
                old, new = inputs[parent].linear_view(0), item.linear_view(0)
                np.testing.assert_array_equal(new[mask], old[mask])
                np.testing.assert_array_equal(new[~mask],
                                              random_candidates[index].linear_view(0)[~mask])
                self.assertTrue(np.any(new[~mask] != old[~mask]))
                self.assertEqual(int(item[0]["gpr"][0]), parent)
            # Never assume fast-trace reuse proves equivalence: execute every boost.
            self.assertEqual(model.trace_test_case(boosted, nesting=1), traces * 3)
            self.assertEqual([input_.tobytes() for input_ in inputs], originals)

    def test_round_manager_uses_real_taints_boosting_and_full_retracing(self) -> None:
        model = make_model("cond", self.case)
        inputs = [make_input(0), make_input(1)]
        # Only the unavailable hardware executor/fuzzer container is mocked.
        # No _normal_stage()/hardware collection is invoked.
        fuzzer = MagicMock(spec=Fuzzer)
        fuzzer.model = model
        fuzzer.data_gen = factory.get_data_generator(123)
        fuzzer.executor = MagicMock()
        manager = _RoundManager(fuzzer, self.case, inputs)
        manager.conf.model_nesting = 1
        manager.conf.enable_fast_contract_tracing = False
        manager._boost_inputs()
        manager._collect_ctraces()
        self.assertEqual(len(manager.boosted_inputs), 6)
        self.assertEqual(manager.ctraces, manager._non_boosted_ctraces * 3)
        self.assertEqual([int(item[0]["gpr"][0]) for item in manager.boosted_inputs],
                         [0, 1, 0, 1, 0, 1])
        fuzzer.executor.load_test_case.assert_called_once_with(self.case)
        fuzzer.executor.trace_test_case.assert_not_called()
