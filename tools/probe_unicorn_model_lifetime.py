"""Bounded host-only Unicorn reconstruction diagnostic, not a native leak detector.

Run from a checkout with Revizor dependencies: python -m tools.probe_unicorn_model_lifetime
All addresses, allocation generations and CPU identification below are synthetic.
Test-case instructions are emulated by Unicorn; no executor, sysfs or PMU is used.
These fixtures are also shared by host characterization tests.
"""

from contextlib import contextmanager, ExitStack
import argparse
import gc
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import tempfile
import tracemalloc
from typing import Any, Dict, Iterator, List, Optional
from unittest.mock import patch
import weakref

import numpy as np
import unicorn  # type: ignore[import-untyped]

from rvzr.arch.arm64.target_desc import ARM64TargetDesc
from rvzr.config import CONF
from rvzr.logs import update_logging_after_config_change
from rvzr.model_unicorn import model as model_module
from rvzr.model_unicorn.model import ARM64UnicornModel
from rvzr.model_unicorn.preparation import prepare_unicorn_model
from rvzr.sandbox_descriptor import SandboxDescriptor, parse_descriptor
from rvzr.target_desc import CPUDesc
from rvzr.tc_components.actor import Actor, ActorMode, ActorPL
from rvzr.tc_components.instruction import Instruction, LabelOp, MemoryOp, RegisterOp
from rvzr.tc_components.test_case_binary import SymbolTableEntry
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData


def _synthetic_cpu(_: ARM64TargetDesc) -> CPUDesc:
    return CPUDesc("ARM", 0, 8, 0)


@contextmanager
def synthetic_environment(clause: str = "seq", coverage: str = "none") -> Iterator[None]:
    """Select a software-only ARM64 fixture without native CPU discovery.

    No mock records model/engine calls or return values. Restores configuration
    and logging even on failure. This is not a hardware description of the host.
    """
    try:
        with ExitStack() as stack:
            for name, value in {
                    "instruction_set": "arm64", "model_backend": "unicorn",
                    "contract_execution_clause": [clause], "contract_observation_clause": "ct",
                    "_handled_faults": [], "model_max_spec_window": 8,
                    "coverage_type": coverage, "logging_modes": [],
            }.items():
                stack.enter_context(patch.object(CONF, name, value))
            stack.enter_context(patch.object(
                ARM64TargetDesc, "_build_cpu_desc", new=_synthetic_cpu))
            update_logging_after_config_change()
            yield
    finally:
        update_logging_after_config_change()


def make_descriptor(actors: int, *, relocated: bool = False,
                    generation: int = 1) -> SandboxDescriptor:
    """Parsed legacy fixture; never claims a kernel-published allocation."""
    data, code = (0x309000, 0x400000) if relocated else (0x109000, 0x200000)
    return parse_descriptor(json.dumps({
        "descriptor_version": 1, "input_format_version": 1, "architecture": "arm64",
        "payload_byte_order": "little", "layout_profile": "legacy-4k-v1",
        "kernel_page_size": 4096, "executor_instance": "0123456789abcdef0123456789abcdef",
        "generation": generation, "ready": True, "execution_enabled": True,
        "actor_count": actors, "utility_span": 36864,
        "bases": {"data": f"0x{data:016x}", "code": f"0x{code:016x}",
                  "entry": f"0x{code:016x}", "utility": f"0x{data - 36864:016x}"},
        "data": {"actor_stride": 16384, "macro_stack": [0, 64], "underflow_pad": [64, 4096],
                 "main": [4096, 8192], "faulty": [8192, 12288],
                 "register_init": [12288, 12608], "overflow_pad": [12608, 16384],
                 "local_stack_offset": 8184,
                 "permission_mappings": {"main": [4096, 8192], "faulty": [8192, 12288],
                                         "register_init": [12288, 16384]}},
        "code": {"actor_stride": 12288, "section": [0, 8192], "macros": [8192, 12288],
                 "permission_mapping": [0, 12288]},
    }))


def make_test_case(directory: Path, actors: int) -> TestCaseProgram:
    """Same tiny binary shape as B3.2b, using real actors, binary and interpreter.

    NOP measurement-start placeholder; MOV X0,X20; LDR X1,[X20]; NOP end
    placeholder. Only the main actor executes; extra actors exercise allocations.
    No assembler, ELF parser, test class or mock graph is needed by the probe.
    """
    code = bytes.fromhex("1f2003d5 e00314aa 810240f9 1f2003d5")
    binary = directory / f"actors-{actors}.bin"
    binary.write_bytes(code * actors)
    test_case = TestCaseProgram("synthetic-only.asm")
    symbols = []
    instructions: Dict[int, Dict[int, Instruction]] = {}
    for actor_id in range(actors):
        actor = Actor(ActorMode.HOST, ActorPL.KERNEL,
                      "main" if actor_id == 0 else f"actor{actor_id}", data_properties=1)
        test_case.add_actor_with_section(actor, allow_overwrite=actor_id == 0)
        actor.code_section().assign_elf_data(actor_id * len(code), len(code), actor_id)
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
        symbols.extend([SymbolTableEntry(actor_id, 0, 1, 0), SymbolTableEntry(actor_id, 12, 2, 0)])
    test_case.assign_obj(str(binary))
    test_case.get_obj().assign_elf_data(symbols, instructions)
    test_case.mark_as_assembled()
    return test_case


def exercise_model(model: ARM64UnicornModel, actors: int, workload: str) -> None:
    """Optionally emulate, then optionally retain a real saved checkpoint.

    The checkpoint is requested explicitly after emulation; this does not claim
    that the fixture's branch-free instructions caused a misprediction.
    """
    if workload == "prepare":
        return
    input_ = InputData(actors)
    input_.view(np.uint8).fill(0)
    input_[0]["main"][0] = 42
    model.trace_test_case([input_], nesting=1)
    if workload == "checkpoint":
        # pylint: disable-next=protected-access
        model.speculator._checkpoint(model.layout.code_start() + 8)


class ReferenceTracker:
    """Only weak references and scalar counters; never owns the observed graph."""

    def __init__(self) -> None:
        self.references: Dict[str, List[weakref.ReferenceType[Any]]] = {}
        self.supported: Dict[str, int] = {}
        self.unsupported: Dict[str, int] = {}

    def watch(self, kind: str, value: object) -> None:
        """Register a weakref, or explicitly count unsupported wrapper types."""
        try:
            reference = weakref.ref(value)
        except TypeError:
            self.unsupported[kind] = self.unsupported.get(kind, 0) + 1
        else:
            self.supported[kind] = self.supported.get(kind, 0) + 1
            self.references.setdefault(kind, []).append(reference)

    def watch_model(self, model: ARM64UnicornModel) -> None:
        """Observe service objects and available native-context wrappers."""
        for kind, value in (("model", model), ("tracer", model.tracer),
                            ("speculator", model.speculator)):
            self.watch(kind, value)
        context = getattr(getattr(model, "state", None), "previous_context", None)
        if context is not None:
            self.watch("context", context)
        for checkpoint in model.speculator._checkpoints:  # pylint: disable=protected-access
            self.watch("checkpoint_context", checkpoint[0])

    def counts(self) -> Dict[str, Dict[str, int]]:
        """Return scalar observations and prune already-dead references."""
        result = {}
        for kind in sorted(self.supported.keys() | self.unsupported.keys()):
            # Discard dead weakrefs so the instrumentation itself does not grow
            # with the number of already collected models.
            living = [reference for reference in self.references.get(kind, [])
                      if reference() is not None]
            self.references[kind] = living
            result[kind] = {"supported": self.supported.get(kind, 0),
                            "unsupported": self.unsupported.get(kind, 0), "alive": len(living)}
        return result


@contextmanager
def watch_engines(tracker: ReferenceTracker) -> Iterator[None]:
    """Observe both constructor and load engines without a mock call history."""
    constructor = getattr(model_module, "Uc")  # Observe the model module's constructor alias.

    def construct(*args: Any, **kwargs: Any) -> Any:
        engine = constructor(*args, **kwargs)
        tracker.watch("engine", engine)
        return engine

    with patch.object(model_module, "Uc", new=construct):
        yield


def reconstruct_once(test_case: TestCaseProgram, allocation: SandboxDescriptor,
                     tracker: ReferenceTracker, workload: str) -> None:
    """Short scope: no model, trace, bound method or traceback escapes."""
    model = prepare_unicorn_model(test_case, allocation, expected_payload_byte_order="little")
    exercise_model(model, test_case.n_actors(), workload)
    tracker.watch_model(model)


def _rss() -> Dict[str, Any]:
    for filename, field in (("/proc/self/smaps_rollup", "Rss:"), ("/proc/self/status", "VmRSS:")):
        try:
            for line in Path(filename).read_text(encoding="utf-8").splitlines():
                if line.startswith(field):
                    return {"rss_bytes": int(line.split()[1]) * 1024, "rss_source": filename}
        except (OSError, ValueError):
            continue
    return {"rss_bytes": None, "rss_source": None}


def _sample(phase: str, completed: int, tracker: ReferenceTracker,
            collected: Optional[int]) -> Dict[str, Any]:
    counts = tracker.counts()
    rss = _rss()
    current, peak = tracemalloc.get_traced_memory()
    return {"kind": "sample", "phase": phase, "measured_preparations": completed,
            "weakrefs": counts, "gc_collected": collected, "gc_counts": gc.get_count(),
            "python_traced_bytes": current, "python_traced_peak_bytes": peak, **rss}


def _bounded(text: str, minimum: int, maximum: int) -> int:
    try:
        number = int(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an integer") from error
    if not minimum <= number <= maximum:
        raise argparse.ArgumentTypeError(f"expected {minimum}..{maximum}")
    return number


def main() -> None:
    """Emit metadata, bounded batch samples and completion as JSON Lines."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=lambda text: _bounded(text, 1, 1000), default=50)
    parser.add_argument("--warmup", type=lambda text: _bounded(text, 0, 100), default=10)
    parser.add_argument("--batch-size", type=lambda text: _bounded(text, 1, 1000), default=10)
    parser.add_argument("--actors", type=int, choices=range(1, 9), default=1)
    parser.add_argument("--clause", choices=("seq", "cond"), default="seq")
    parser.add_argument("--workload", choices=("prepare", "execute", "checkpoint"),
                        default="prepare")
    parser.add_argument("--gc", choices=("default", "batch"), default="default", dest="gc_mode")
    parser.add_argument("--relocate", action="store_true",
                        help="Alternate synthetic data/code bases")
    args = parser.parse_args()
    if args.workload == "checkpoint" and args.clause != "cond":
        parser.error("checkpoint workload requires --clause cond")
    print(json.dumps({"kind": "metadata", "schema_version": 1, "synthetic_fixture": True,
                      "coverage_type": "none",
                      "python_version": platform.python_version(), "platform": platform.platform(),
                      "machine": platform.machine(), "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
                      "unicorn_package_version": version("unicorn"),
                      "unicorn_core_version": unicorn.uc_version(),
                      "unicorn_binding_path": unicorn.__file__, **vars(args),
                      "gc_enabled": gc.isenabled(), "gc_thresholds": gc.get_threshold(),
                      "baseline_and_final_full_gc": True}), flush=True)
    tracemalloc.start()
    tracker = ReferenceTracker()
    try:
        with tempfile.TemporaryDirectory(prefix="rvzr-model-probe-") as temporary, \
                synthetic_environment(args.clause), watch_engines(tracker):
            test_case = make_test_case(Path(temporary), args.actors)
            for index in range(args.warmup):
                reconstruct_once(test_case, make_descriptor(args.actors, generation=index + 1),
                                 tracker, args.workload)
            print(json.dumps(_sample("baseline", 0, tracker, gc.collect())), flush=True)
            for index in range(1, args.iterations + 1):
                allocation = make_descriptor(args.actors,
                                             relocated=args.relocate and index % 2 == 0,
                                             generation=args.warmup + index)
                reconstruct_once(test_case, allocation, tracker, args.workload)
                if index % args.batch_size == 0 or index == args.iterations:
                    collected = gc.collect() if args.gc_mode == "batch" else None
                    print(json.dumps(_sample("batch", index, tracker, collected)), flush=True)
            print(json.dumps(_sample("final", args.iterations, tracker, gc.collect())), flush=True)
            print(json.dumps({"kind": "complete", "status": "ok",
                              "measured_preparations": args.iterations,
                              "total_preparations": args.warmup + args.iterations}), flush=True)
    finally:
        tracemalloc.stop()


if __name__ == "__main__":
    main()
