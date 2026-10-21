"""Bounded Python lifetime checks, not proof of complete native Unicorn cleanup.

Observations contain only weakrefs and numbers. Helpers let model/exception
frames disappear before collection. No cleanup hooks or internal release calls
are invoked. Unsupported wrapper weakrefs are reported, not fabricated.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring

from contextlib import ExitStack
import gc
from pathlib import Path
import tempfile
from typing import Any
import unittest
from unittest.mock import patch
import warnings

from rvzr import factory
from rvzr.model_unicorn.interpreter import ARMExtraInterpreter
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.model_unicorn.preparation import prepare_unicorn_model
from rvzr.tc_components.test_case_binary import TestCaseBinary
from tools.probe_unicorn_model_lifetime import (
    ReferenceTracker, exercise_model, make_descriptor, make_test_case,
    reconstruct_once, synthetic_environment, watch_engines,
)


class ModelResourceLifetimeTest(unittest.TestCase):
    def setUp(self) -> None:
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="rvzr-life-")))

    def assert_collected(self, tracker: ReferenceTracker) -> None:
        gc.collect()
        gc.collect()  # Bounded second pass permits finalizer-created garbage to be collected.
        counts = tracker.counts()
        self.assertGreater(counts["model"]["supported"], 0)
        for kind, values in counts.items():
            with self.subTest(kind=kind):
                if values["unsupported"]:
                    warnings.warn(f"{kind} wrapper lacks weakref support: {values}", RuntimeWarning)
                self.assertEqual(values["alive"], 0)

    def test_prepared_and_discarded_model_and_both_engines_are_collectable(self) -> None:
        tracker = ReferenceTracker()
        with synthetic_environment(), watch_engines(tracker):
            reconstruct_once(make_test_case(self.directory, 1), make_descriptor(1),
                             tracker, "prepare")
            self.assert_collected(tracker)
        values = tracker.counts()["engine"]
        self.assertEqual(values["supported"] + values["unsupported"], 2)

    def test_bounded_relocation_actor_changes_and_speculative_construction(self) -> None:
        tracker = ReferenceTracker()
        with watch_engines(tracker):
            for clause in ("seq", "cond"):
                with synthetic_environment(clause):
                    for relocated in (False, True):
                        for actors in (1, 3, 1):
                            with self.subTest(clause=clause, relocated=relocated, actors=actors):
                                reconstruct_once(make_test_case(self.directory, actors),
                                                 make_descriptor(actors, relocated=relocated),
                                                 tracker, "prepare")
                                self.assert_collected(tracker)
        self.assertEqual(tracker.counts()["model"]["supported"], 12)

    def test_executed_model_and_previous_native_context_are_collectable(self) -> None:
        tracker = ReferenceTracker()
        with synthetic_environment(), watch_engines(tracker):
            reconstruct_once(make_test_case(self.directory, 1), make_descriptor(1),
                             tracker, "execute")
            self.assert_collected(tracker)
        context = tracker.counts()["context"]
        self.assertEqual(context["supported"] + context["unsupported"], 1)

    def test_speculative_model_with_real_saved_checkpoint_is_collectable(self) -> None:
        tracker = ReferenceTracker()
        with synthetic_environment("cond"), watch_engines(tracker):
            reconstruct_once(make_test_case(self.directory, 1), make_descriptor(1),
                             tracker, "checkpoint")
            self.assert_collected(tracker)
        context = tracker.counts()["checkpoint_context"]
        self.assertEqual(context["supported"] + context["unsupported"], 1)

    def test_retained_tracer_or_engine_keeps_model_alive_until_reference_is_released(self) -> None:
        for attribute in ("tracer", "emulator"):
            with self.subTest(attribute=attribute), synthetic_environment(), \
                    watch_engines(tracker := ReferenceTracker()):
                held = self.retain_one(tracker, attribute)
                gc.collect()
                self.assertEqual(tracker.counts()["model"]["alive"], 1)
                del held
                self.assert_collected(tracker)

    def retain_one(self, tracker: ReferenceTracker, attribute: str) -> Any:
        model = prepare_unicorn_model(make_test_case(self.directory, 1), make_descriptor(1),
                                      expected_payload_byte_order="little")
        exercise_model(model, 1, "execute")
        tracker.watch_model(model)
        return getattr(model, attribute)

    def test_partial_constructor_failure_does_not_retain_obsolete_graph(self) -> None:
        tracker = ReferenceTracker()
        original_init = ARMExtraInterpreter.__init__

        def fail_after_services(self_: ARMExtraInterpreter, target: Any,
                                model: ARM64UnicornModel) -> None:
            original_init(self_, target, model)
            tracker.watch_model(model)
            raise RuntimeError("synthetic constructor failure")

        def failed_scope() -> str:
            with patch.object(ARMExtraInterpreter, "__init__", new=fail_after_services):
                try:
                    prepare_unicorn_model(make_test_case(self.directory, 1), make_descriptor(1),
                                          expected_payload_byte_order="little")
                except RuntimeError as error:
                    return str(error)  # Exception/traceback never escapes this scope.
            raise AssertionError("Expected construction failure")

        with synthetic_environment(), watch_engines(tracker):
            self.assertEqual(failed_scope(), "synthetic constructor failure")
            self.assert_collected(tracker)

    def test_loading_failure_does_not_retain_candidate_or_either_engine(self) -> None:
        tracker = ReferenceTracker()
        constructor = factory.get_model

        def observe_factory(*args: Any, **kwargs: Any) -> Any:
            model = constructor(*args, **kwargs)
            assert isinstance(model, ARM64UnicornModel)
            tracker.watch_model(model)
            return model

        def fail_binary(*_: Any, **__: Any) -> bytes:
            raise ValueError("synthetic loading failure")

        def failed_scope() -> str:
            with patch.object(factory, "get_model", new=observe_factory), \
                    patch.object(TestCaseBinary, "to_bytes", new=fail_binary):
                try:
                    prepare_unicorn_model(make_test_case(self.directory, 1), make_descriptor(1),
                                          expected_payload_byte_order="little")
                except ValueError as error:
                    return str(error)
            raise AssertionError("Expected loading failure")

        with synthetic_environment(), watch_engines(tracker):
            self.assertEqual(failed_scope(), "synthetic loading failure")
            self.assert_collected(tracker)
        values = tracker.counts()["engine"]
        self.assertEqual(values["supported"] + values["unsupported"], 2)


if __name__ == "__main__":
    unittest.main()
