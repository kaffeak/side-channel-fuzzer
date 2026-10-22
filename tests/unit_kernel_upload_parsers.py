"""Production parser/callback characterization, not kernel allocation or safety validation.

Run ordinary tests first: python -m unittest tests.unit_kernel_upload_parsers -v
Select a separate instrumented build with RVZR_PARSER_SANITIZER=address|undefined.
Use unittest -f to stop immediately on instrumented failures; never pad allocations.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring
# Keep parser/reset scenarios on the same native-build fixture.
# pylint: disable=too-many-lines

import errno
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Tuple
import unittest

import numpy as np

from rvzr.tc_components.actor import Actor, ActorMode, ActorPL
from rvzr.tc_components.test_case_binary import SymbolTableEntry
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData, save_input_sequence_as_rdbf


_ROOT = Path(__file__).resolve().parents[1]
_KERNEL = _ROOT / "rvzr" / "executor_km"
_HARNESS = Path(__file__).resolve().parent / "kernel_upload_parsers"


def _hash(payload: bytes) -> str:
    value = 14695981039346656037
    for byte in payload:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return f"{value:016x}"


def _rcbf_fixture(directory: Path, actor_count: int,
                  include_end: bool = True) -> Tuple[Path, bytes, int]:
    # Distinct section lengths exercise each next-section boundary and actor ordering.
    # Start/end placeholders occupy 12 bytes each; the intervening bytes are owned NOPs.
    # These bytes are serialized and parsed only; no assembler/emulator/executor runs.
    sections = [bytes.fromhex("1f2003d5") * (9 + actor_id) for actor_id in range(actor_count)]
    binary = directory / f"owned-{actor_count}.bin"
    binary.write_bytes(b"".join(sections))
    program = TestCaseProgram("owned-only.asm")
    symbols = []
    offset = 0
    for actor_id, code in enumerate(sections):
        actor = Actor(ActorMode.HOST, ActorPL.KERNEL,
                      "main" if actor_id == 0 else f"actor{actor_id}", data_properties=1)
        program.add_actor_with_section(actor, allow_overwrite=actor_id == 0)
        actor.code_section().assign_elf_data(offset, len(code), actor_id)
        symbols.extend([
            SymbolTableEntry(actor_id, 0, 0, actor_id),
            SymbolTableEntry(actor_id, 0, 1, 0),
        ])
        if include_end:
            symbols.append(SymbolTableEntry(actor_id, len(code) - 12, 2, 0))
        offset += len(code)
    program.assign_obj(str(binary))
    program.get_obj().assign_elf_data(symbols, {actor_id: {} for actor_id in range(actor_count)})
    program.mark_as_assembled()
    label = "valid" if include_end else "missing-end"
    rcbf = directory / f"{label}-{actor_count}.rcbf"
    program.get_obj().save_rcbf(str(rcbf))
    return rcbf, b"".join(sections), 16 + actor_count * (48 + 24) + len(symbols) * 32 + offset


def _fixtures(directory: Path) -> Dict[str, Tuple[Path, bytes, int]]:
    input_ = InputData(1)
    pattern = (np.arange(input_.nbytes, dtype=np.uint64) % 251).astype(np.uint8)
    input_.view(np.uint8).reshape(-1)[:] = pattern
    rdbf = directory / "valid.rdbf"
    save_input_sequence_as_rdbf([input_], str(rdbf))
    paged = directory / "paged.rdbf"
    save_input_sequence_as_rdbf([input_] * 33, str(paged))
    wrong_actor = directory / "wrong-actor.rdbf"
    wrong_input = InputData(2)
    wrong_input.view(np.uint8).reshape(-1)[:] = 0
    save_input_sequence_as_rdbf([wrong_input], str(wrong_actor))
    alternate = InputData(1)
    alternate.view(np.uint8).reshape(-1)[:] = np.bitwise_xor(pattern, 0x5A)
    alternate_path = directory / "attempt-alternate.rdbf"
    save_input_sequence_as_rdbf([alternate], str(alternate_path))
    (directory / "attempt-expected.bin").write_bytes(alternate.tobytes())
    return {"rcbf": _rcbf_fixture(directory, 1), "rcbf_multi": _rcbf_fixture(directory, 3),
            "rcbf_missing_end": _rcbf_fixture(directory, 1, include_end=False),
            "rdbf_paged": (paged, input_.tobytes() * 33, 405536),
            "rdbf_wrong_actor": (wrong_actor, wrong_input.tobytes(), 24624),
            "rdbf_alternate": (alternate_path, alternate.tobytes(), 12320),
            "rdbf": (rdbf, input_.tobytes(), 12320)}


def _unit_flags(filename: str) -> List[str]:
    if filename in ("test_case_parser.c", "input_parser.c"):
        return ["-Wno-error=sign-compare"]
    if filename == "upload_callback.c":
        return ["-Wno-error=unused-parameter"]
    if filename in ("harness.c", "attempt_upload.c", "preparation_state.c"):
        # Consistent kernel u64 spelling through the existing linux/types.h shim.
        return ["-D__KERNEL__"]
    return []


def _callback_unit() -> str:
    """Extract exact top-level definitions; fail closed if their shape changes.

    This is deliberately not a general C extractor. Only these current definitions
    have an opening/closing brace at column zero and no nested column-zero braces.
    No callback statements are generated, replaced or rewritten.
    """
    path = _KERNEL / "main.c"
    source = path.read_text(encoding="utf-8")
    parts = ['#include "compat.h"\n#include "test_case_parser.h"\n'
             '#include "input_parser.h"\n'
             '#include "sandbox_manager.h"\n#include "code_loader.h"\n'
             '#include "shortcuts.h"\nstruct kobject;\nstruct kobj_attribute;\n'
             'extern bool tc_ready, inputs_ready, unfinished_call;\n'
             'extern int next_measurement_id;\n']
    # Single-threaded boundary instrumentation, NOT an implementation of kernel mutexes.
    parts.append('struct mutex { bool held; size_t entries; };\n'
                 '#define DEFINE_MUTEX(name) struct mutex name = {false, 0}\n'
                 'static void mutex_lock(struct mutex *lock)\n'
                 '{ if (lock->held) abort(); lock->held = true; lock->entries++; }\n'
                 'static void mutex_unlock(struct mutex *lock)\n'
                 '{ if (!lock->held) abort(); lock->held = false; }\n')
    declaration = re.search(r"^static DEFINE_MUTEX\(executor_mutex\);$", source, re.MULTILINE)
    if declaration is None:
        raise RuntimeError("Cannot isolate production coordinator mutex")
    parts.append(declaration.group() + "\n")
    start = source.index("// RVZR_CALLBACK_WRAPPERS_BEGIN")
    end = source.index("// RVZR_CALLBACK_WRAPPERS_END", start)
    parts.append(source[start:end] + "\n")
    for name in ("check_test_case_compat", "test_case_store_unlocked", "inputs_store_unlocked",
                 "trace_show_unlocked"):
        matches = list(re.finditer(
            rf"^static (?:int|ssize_t) {name}\([^;{{}}]*\)\n\{{\n.*?^\}}$",
            source, re.MULTILINE | re.DOTALL))
        if len(matches) != 1:
            raise RuntimeError(f"Cannot isolate exactly one production {name} definition")
        match = matches[0]
        line = source.count("\n", 0, match.start()) + 1
        parts.append(f"#line {line} {json.dumps(str(path))}\n{match.group()}\n")
        if name.endswith("_unlocked"):
            callback = name.removesuffix("_unlocked")
            wrappers = re.findall(rf"^RVZR_LOCKED_(?:SHOW|STORE)\({callback}\)$",
                                  source, re.MULTILINE)
            if len(wrappers) != 1:
                raise RuntimeError(f"Cannot isolate production wrapper for {callback}")
            parts.append(wrappers[0] + "\n")
    parts.append('#line 1 "host_callback_adapter"\n'
                 'bool host_callback_lock_held(void) { return executor_mutex.held; }\n'
                 'static void check_callback_unlock(size_t before)\n'
                 '{ if (executor_mutex.held || executor_mutex.entries != before + 1) abort(); }\n'
                 'ssize_t host_test_case_store(const char *buf, size_t count)\n'
                 '{ size_t before = executor_mutex.entries;\n'
                 '  ssize_t ret = test_case_store(NULL, NULL, buf, count);\n'
                 '  check_callback_unlock(before); return ret; }\n'
                 'ssize_t host_inputs_store(const char *buf, size_t count)\n'
                 '{ size_t before = executor_mutex.entries;\n'
                 '  ssize_t ret = inputs_store(NULL, NULL, buf, count);\n'
                 '  check_callback_unlock(before); return ret; }\n'
                 'ssize_t host_trace_show(char *buf)\n'
                 '{ size_t before = executor_mutex.entries;\n'
                 '  ssize_t ret = trace_show(NULL, NULL, buf);\n'
                 '  check_callback_unlock(before); return ret; }\n')
    return "".join(parts)


# Keep related callback regressions on one shared native-build fixture.
class KernelUploadParserBaselineTest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    build_dir: Path
    binary: Path
    fixtures: Dict[str, Tuple[Path, bytes, int]]
    build_commands: List[List[str]]
    build_diagnostics: str
    _recovery_safety_records: List[Dict[str, Any]]

    def test_all_sysfs_callbacks_use_locked_wrappers(self) -> None:
        source = (_KERNEL / "main.c").read_text(encoding="utf-8")
        attributes = re.findall(r"__ATTR\(\w+,\s*\d+,\s*(\w+),\s*(\w+)\)", source)
        callbacks = {name for pair in attributes for name in pair if name != "NULL"}
        callbacks.update(name + "_read" for name in
                         re.findall(r"__BIN_ATTR_RO\((\w+),\s*\d+\)", source))
        wrappers = re.findall(r"^RVZR_LOCKED_(?:SHOW|STORE|BIN_READ)\((\w+)\)$",
                              source, re.MULTILINE)
        self.assertEqual(len(callbacks), 20)
        self.assertCountEqual(wrappers, callbacks)
        bodies = re.findall(r"^static ssize_t (\w+)_unlocked\(", source, re.MULTILINE)
        self.assertCountEqual(bodies, callbacks)

    def test_interface_removal_precedes_locked_destruction(self) -> None:
        source = (_KERNEL / "main.c").read_text(encoding="utf-8")
        exit_body = source.split("static void __exit executor_exit(void)\n{", 1)[1]
        exit_body = exit_body.split("\n}", 1)[0]
        operations = ["remove_executor_interfaces();", "mutex_lock(&executor_mutex);",
                      "free_measurements();", "free_sandbox_manager();",
                      "mutex_unlock(&executor_mutex);",
                      "kobject_put(kobj_interface);"]
        positions = [exit_body.index(operation) for operation in operations]
        self.assertEqual(positions, sorted(positions))
        removal = source.split("static void remove_executor_interfaces(void)\n{", 1)[1]
        removal = removal.split("\n}", 1)[0]
        self.assertNotRegex(removal, r"mutex_(?:lock|unlock)\(")
        self.assertIn("sysfs_remove_file(", removal)
        self.assertIn("sysfs_remove_bin_file(", removal)
        self.assertIn("goto out_unlock;", exit_body)
        self.assertNotRegex(exit_body, r"\breturn\s*;")
        initialization = source.split("static int __init executor_init(void)\n{", 1)[1]
        initialization = initialization.split("\n}", 1)[0]
        self.assertEqual(initialization.count("mutex_lock(&executor_mutex);"), 1)
        self.assertEqual(initialization.count("mutex_unlock(&executor_mutex);"), 1)
        self.assertLess(initialization.index("mutex_unlock(&executor_mutex);"),
                        initialization.index("remove_executor_interfaces();"))

    def setUp(self) -> None:
        if self._testMethodName == "test_recovery_interrupted_rdbf_safety_invariant":
            # setUp failures are NOT expected failures: never hide sanitizer/process/JSON errors.
            _, self._recovery_safety_records = self.recovery_records("rdbf-interrupted")

    @classmethod
    def setUpClass(cls) -> None:  # pylint: disable=too-many-locals
        if sys.byteorder != "little":
            raise RuntimeError("These native-word parser fixtures require a little-endian host")
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("Install a native C compiler or set CC; no kernel headers required")
        # pylint: disable-next=consider-using-with
        temporary = tempfile.TemporaryDirectory(prefix="rvzr-parser-baseline-")
        cls.addClassCleanup(temporary.cleanup)
        cls.build_dir = Path(temporary.name)
        # These includes supply dependencies only; all parser structs/macros remain production ones.
        for name in ("linux/types.h", "linux/slab.h", "linux/kernel.h", "linux/mm.h",
                     "linux/vmalloc.h", "linux/version.h", "linux/kallsyms.h",
                     "asm/io.h", "asm/cpu.h"):
            target = cls.build_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('#include "compat.h"\n', encoding="utf-8")
        units = []
        idle_checks = {
            "test_case_parser.c": """
bool host_tc_idle(void) {
    return !_is_receiving_test_case && _cursor == 0 && n_actors == 0 && n_symbols == 0 &&
        curr_section_id == 0 && curr_section_start == 0 && curr_section_end == 0 &&
        highest_n_actors == 0 && highest_n_symbols == 0 && actors == NULL &&
        _allocated_actor_table == NULL && _allocated_symbol_table == NULL &&
        _allocated_metadata == NULL && _allocated_data == NULL && test_case != NULL &&
        test_case->actor_table_size == 0 && test_case->symbol_table_size == 0 &&
        test_case->metadata_size == 0 && test_case->sections_size == 0 &&
        test_case->actor_table == NULL && test_case->symbol_table == NULL &&
        test_case->metadata == NULL && test_case->sections == NULL &&
        !test_case->features.includes_vm_actors && !test_case->features.includes_user_actors &&
        !test_case->features.has_explicit_fault_handler;
}
""",
            "input_parser.c": """
bool host_input_idle(void) {
    return !is_receiving_inputs && cursor == 0 && n_inputs == 0 &&
        highest_n_actors == 0 && highest_n_inputs == 0 && allocated_metadata == NULL &&
        allocated_data == NULL && inputs != NULL && inputs->metadata_size == 0 &&
        inputs->data_size == 0 && inputs->metadata == NULL && inputs->data == NULL;
}
""",
        }
        for filename, helper, cursor in (("test_case_parser.c", "host_tc_cursor", "_cursor"),
                                         ("input_parser.c", "host_input_cursor", "cursor")):
            unit = cls.build_dir / filename
            # Include actual sources, appending read-only observations of private reset state.
            unit.write_text(f"#include {json.dumps(str(_KERNEL / filename))}\n"
                            f"uint64_t {helper}(void) {{ return {cursor}; }}\n"
                            + idle_checks[filename], encoding="utf-8")
            units.append(str(unit))
        callback = cls.build_dir / "upload_callback.c"
        callback.write_text(_callback_unit(), encoding="utf-8")
        units.append(str(callback))
        cls.binary = cls.build_dir / "parser-baseline"
        flags = ["-std=gnu11", "-O0", "-g", "-Wall", "-Wextra", "-Werror",
                 "-DVENDOR_ID=3", "-DPHYSICAL_WIDTH=48", "-DL1D_ASSOCIATIVITY=8",
                 "-DL1D_SIZE_KB=32", "-I" + str(cls.build_dir), "-I" + str(_HARNESS),
                 "-I" + str(_KERNEL / "include")]
        sanitizer = os.environ.get("RVZR_PARSER_SANITIZER", "none")
        if sanitizer not in ("none", "address", "undefined"):
            raise RuntimeError("RVZR_PARSER_SANITIZER must be none, address or undefined")
        instrumentation = [] if sanitizer == "none" else [
            "-fsanitize=" + sanitizer, "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all", "-no-pie"]
        cls.build_commands, cls.build_diagnostics = [], ""
        objects = []
        adapter_units = [str(_HARNESS / "attempt_upload.c"), str(_KERNEL / "preparation_state.c")]
        for source in [str(_HARNESS / "harness.c")] + units + adapter_units:
            obj = cls.build_dir / (Path(source).stem + ".o")
            # Preserve existing parser signedness warnings; new harness warnings remain fatal.
            exceptions = _unit_flags(Path(source).name)
            cls.build_commands.append(compiler + flags + instrumentation + exceptions
                                      + ["-c", source, "-o", str(obj)])
            objects.append(str(obj))
        cls.build_commands.append(compiler + instrumentation + objects
                                  + ["-Wl,--wrap=parse_test_case_buffer",
                                     "-Wl,--wrap=parse_input_buffer", "-o", str(cls.binary)])
        for command in cls.build_commands:
            build = subprocess.run(command, capture_output=True, text=True,
                                   check=False, timeout=30)
            cls.build_diagnostics += build.stderr
            if build.returncode:
                raise RuntimeError(f"Build failed: {shlex.join(command)}\n"
                                   f"{build.stdout}{build.stderr}")
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"build_commands": cls.build_commands,
                              "build_diagnostics": cls.build_diagnostics}))
        cls.fixtures = _fixtures(cls.build_dir)
        for kind in ("rcbf", "rcbf_multi", "rdbf"):
            (cls.build_dir / f"reset-expected-{kind}.bin").write_bytes(cls.fixtures[kind][1])

    def invoke_fixture(self, kind: str, complete: bool, route: str = "direct",
                       step: int = 4096, *, replacement: str = ""
                       ) -> Tuple[subprocess.CompletedProcess[str], List[Dict[str, Any]]]:
        path, _, total = self.fixtures[kind]
        self.assertEqual(path.stat().st_size, total)
        limit = total if complete else total - 8
        environment = dict(os.environ)
        # LSan cannot run under ptrace on this host. ASan bounds checks remain enabled;
        # tracked allocations must independently be zero at teardown in every scenario.
        environment["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        parser = "rdbf" if kind == "rdbf" else "rcbf"
        result = subprocess.run(
            [str(self.binary), parser, route, str(path), str(limit), str(step)]
            + ([str(self.fixtures[replacement][0])] if replacement else []),
            capture_output=True, text=True, check=False, timeout=5, env=environment)
        records: List[Dict[str, Any]] = [json.loads(line) for line in result.stdout.splitlines()]
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"format": kind, "complete": complete, "route": route,
                              "replacement": replacement,
                              "exit": result.returncode, "stderr": result.stderr,
                              "records": records}))
        return result, records

    def run_fixture(self, kind: str, complete: bool, actor_count: int = 1,
                    step: int = 4096, *, route: str = "direct") -> List[Dict[str, Any]]:
        result, records = self.invoke_fixture(kind, complete, route, step)
        self.assertEqual(result.returncode, 0,
                         f"{kind} complete={complete}, exit={result.returncode}\n"
                         f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        self.assertEqual(result.stderr, "")
        self.assertEqual(records[0]["event"], "init")
        self.assertTrue(records[0]["not_receiving"])  # Idle, not a validated upload.
        self.assertFalse(records[0]["finished"])
        self.assertIsNone(records[0]["parser_ret"])
        self.assertEqual(records[0]["parser_calls"], 0)
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        feeds = records[1:-1]
        parser = "rdbf" if kind == "rdbf" else "rcbf"
        self.assertTrue(feeds)
        self.assertEqual([record["parser_calls"] for record in feeds],
                         list(range(1, len(feeds) + 1)))
        for record in feeds:
            self.assertEqual(record["event"], "feed")
            self.assertGreater(record["ret"], 0)
            self.assertEqual(record["consumed"], record["ret"])
            self.assertEqual(record["parser_ret"], record["ret"])
            self.assertEqual(record["callback_ret"], record["ret"] if route == "store" else None)
            self.assertLessEqual(record["ret"], record["requested"])
            self.assertLessEqual(record["requested"], step)
            self.assertEqual(record["receiving"], not record["not_receiving"])
            self.assertEqual(record["n_actors"], actor_count)
            if parser == "rcbf":
                # Exact metadata allocations put the nonexistent next entry into ASan's redzone.
                self.assertEqual(record["metadata_allocation_bytes"], actor_count * 24)
        self.assertTrue(any(record["ret"] < record["requested"] for record in feeds))
        limit = self.fixtures[kind][2] - (0 if complete else 8)
        self.assertEqual(sum(record["consumed"] for record in feeds), limit)
        self.assertEqual(feeds[-1]["cursor"], limit)
        self.assertEqual(feeds[-1]["finished"], complete)
        self.assertEqual(feeds[-1]["not_receiving"], complete)
        for record in feeds[:-1]:
            self.assertFalse(record["finished"])
        return feeds

    def trace_records(self, tc_ready: bool, inputs_ready: bool, unfinished: bool,
                      mode: str) -> Tuple[str, List[Dict[str, Any]]]:
        environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                           UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        result = subprocess.run(
            [str(self.binary), "trace", str(int(tc_ready)), str(int(inputs_ready)),
             str(int(unfinished)), mode], capture_output=True, text=True, check=False,
            timeout=5, env=environment)
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        records: List[Dict[str, Any]] = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        self.assertEqual(len(records), 3 if mode == "paginate" else 2)
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"trace_mode": mode, "records": records, "stderr": result.stderr}))
        return result.stderr, records[:-1]

    def check_rejected_trace(self, record: Dict[str, Any], trace_calls: int,
                             *, inputs_completed: bool = True, tc_completed: bool = True) -> None:
        self.assertEqual(record["ret"], -errno.EIO)
        self.assertEqual(record["trace_calls"], trace_calls)
        self.assertTrue(record["buffer_unchanged"])
        self.assertEqual(record["output_hex"], "")
        self.assertEqual(record["unfinished_before"], record["unfinished_after"])
        self.assertEqual(record["next_before"], record["next_after"])
        # Completion predicates are checked separately from validated readiness.
        self.assertEqual(record["tc_completed"], tc_completed)
        self.assertEqual(record["inputs_completed"], inputs_completed)

    def test_trace_rejects_unready_execution(self) -> None:
        for tc_ready, inputs_ready in ((False, True), (True, False), (False, False)):
            for unfinished in (False, True):
                with self.subTest(tc=tc_ready, inputs=inputs_ready, unfinished=unfinished):
                    stderr, records = self.trace_records(tc_ready, inputs_ready,
                                                         unfinished, "execute")
                    self.check_rejected_trace(records[0], trace_calls=0)
                    self.assertEqual(records[0]["next_before"], -1)
                    self.assertEqual(stderr, "[rvzr_executor:trace_show] Assertion failed: "
                                     "tc_ready && inputs_ready\n")

    def test_trace_rejects_unready_pending_results(self) -> None:
        for tc_ready, inputs_ready in ((False, True), (True, False), (False, False)):
            for unfinished in (False, True):
                with self.subTest(tc=tc_ready, inputs=inputs_ready, unfinished=unfinished):
                    stderr, records = self.trace_records(tc_ready, inputs_ready,
                                                         unfinished, "pending")
                    self.check_rejected_trace(records[0], trace_calls=0)
                    self.assertEqual(records[0]["next_before"], 1)
                    self.assertEqual(stderr, "[rvzr_executor:trace_show] Assertion failed: "
                                     "tc_ready && inputs_ready\n")

    def test_trace_ready_executes_and_formats_results(self) -> None:
        stderr, records = self.trace_records(True, True, False, "execute")
        self.assertEqual(stderr, "")
        record = records[0]
        self.assertEqual(record["trace_calls"], 1)
        self.assertEqual(record["next_before"], -1)
        self.assertEqual(record["next_after"], -1)
        self.assertFalse(record["unfinished_after"])
        expected = b"2,2,2,2,2,2\n1,1,1,1,1,1\ndone\n"
        self.assertEqual(bytes.fromhex(record["output_hex"]), expected)
        self.assertEqual(record["ret"], len(expected))

    def test_trace_error_unlocks_without_claiming_recovery(self) -> None:
        stderr, records = self.trace_records(True, True, False, "error")
        self.assertEqual(stderr, "")
        record = records[0]
        self.assertEqual(record["ret"], -errno.EIO)
        self.assertEqual(record["trace_calls"], 1)
        self.assertEqual(record["next_after"], -1)
        self.assertTrue(record["buffer_unchanged"])
        # Existing legacy state, not evidence of native recovery: the adapter separately
        # requires one acquisition and a released boundary even on this negative return.
        self.assertTrue(record["unfinished_after"])

    def test_trace_ready_pending_results_do_not_remeasure(self) -> None:
        stderr, records = self.trace_records(True, True, False, "pending")
        self.assertEqual(stderr, "")
        record = records[0]
        self.assertEqual(record["trace_calls"], 0)
        self.assertEqual(record["next_before"], 1)
        self.assertEqual(record["next_after"], -1)
        expected = b"2,2,2,2,2,2\n1,1,1,1,1,1\ndone\n"
        self.assertEqual(bytes.fromhex(record["output_hex"]), expected)
        self.assertEqual(record["ret"], len(expected))

    def test_trace_ready_pagination_preserves_format_and_cursor(self) -> None:
        stderr, records = self.trace_records(True, True, False, "paginate")
        self.assertEqual(stderr, "")
        first, second = records
        self.assertEqual(first["trace_calls"], 1)
        self.assertEqual(first["ret"], 4032)
        self.assertEqual(first["next_after"], 31)
        self.assertEqual(second["next_before"], 31)
        self.assertEqual(second["next_after"], -1)
        self.assertEqual(second["trace_calls"], 1)
        expected = b"".join((",".join([str((1 << 64) - 1 - index)] * 6) + "\n").encode()
                            for index in reversed(range(64))) + b"done\n"
        output = b"".join(bytes.fromhex(record["output_hex"]) for record in records)
        self.assertEqual(output, expected)
        self.assertEqual(sum(record["ret"] for record in records), len(expected))

    def test_trace_invalidated_pagination_does_not_emit_or_advance(self) -> None:
        for tc_ready, inputs_ready in ((False, True), (True, False), (False, False)):
            with self.subTest(tc=tc_ready, inputs=inputs_ready):
                stderr, records = self.trace_records(tc_ready, inputs_ready, False, "paginate")
                first, second = records
                self.assertEqual(first["trace_calls"], 1)
                self.assertEqual(first["ret"], 4032)
                self.assertEqual(first["next_after"], 31)
                self.assertTrue(first["tc_ready"])
                self.assertTrue(first["inputs_ready"])
                self.check_rejected_trace(second, trace_calls=1)
                self.assertEqual(second["next_before"], 31)
                self.assertEqual(second["tc_ready"], tc_ready)
                self.assertEqual(second["inputs_ready"], inputs_ready)
                self.assertEqual(stderr, "[rvzr_executor:trace_show] Assertion failed: "
                                 "tc_ready && inputs_ready\n")

    def preparation_records(self, scenario: str) -> Tuple[str, List[Dict[str, Any]]]:
        environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                           UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        paths = [self.fixtures[key][0] for key in
                 ("rcbf", "rdbf", "rdbf_paged", "rdbf_wrong_actor")]
        result = subprocess.run([str(self.binary), "prepare", scenario] + list(map(str, paths)),
                                capture_output=True, text=True, check=False,
                                timeout=5, env=environment)
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        records: List[Dict[str, Any]] = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(records[0]["event"], "init")
        self.assertFalse(records[0]["tc_ready"])
        self.assertFalse(records[0]["inputs_ready"])
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"prepare": scenario, "records": records, "stderr": result.stderr}))
        return result.stderr, records[1:-1]

    def check_input_upload(self, records: List[Dict[str, Any]], upload_id: int,
                           returns: List[int]) -> List[Dict[str, Any]]:
        feeds = [r for r in records if r["event"] == "feed" and r["upload_id"] == upload_id]
        self.assertTrue(feeds)
        self.assertEqual([r["ret"] for r in feeds], returns)
        for record in feeds:
            self.assertEqual(record["format"], "rdbf")
            self.assertEqual(record["parser_ret"], record["callback_ret"])
            self.assertFalse(record["ready_at_parser_entry"])
            self.assertFalse(record["inputs_at_parser_entry"])
            self.assertEqual(record["next_at_parser_entry"], -1)
            self.assertEqual(record["next_measurement_id"], -1)
            self.assertTrue(record["tc_ready"])
            self.assertEqual(record["consumed"], record["ret"] if record["ret"] > 0 else None)
        for record in feeds[:-1]:
            self.assertFalse(record["finished"])
            self.assertFalse(record["inputs_ready"])
        return feeds

    def check_fresh_single_trace(self, record: Dict[str, Any], calls: int) -> None:
        expected = b"1,1,1,1,1,1\ndone\n"
        self.assertEqual(record["ret"], len(expected))
        self.assertEqual(bytes.fromhex(record["output_hex"]), expected)
        self.assertEqual(record["trace_calls"], calls)
        self.assertEqual(record["next_before"], -1)
        self.assertEqual(record["next_after"], -1)
        self.assertTrue(record["tc_ready"])
        self.assertTrue(record["inputs_ready"])

    def test_prepare_valid_case_then_inputs_and_trace(self) -> None:
        stderr, records = self.preparation_records("normal")
        self.assertEqual(stderr, "")
        feeds = self.check_input_upload(records, 1, [16, 16, 4096, 4096, 4096])
        self.assertTrue(feeds[-1]["finished"])
        self.assertTrue(feeds[-1]["inputs_ready"])
        self.assertEqual(feeds[-1]["hash"], _hash(self.fixtures["rdbf"][1]))
        self.check_fresh_single_trace(records[-1], calls=1)

    def test_prepare_replacement_requires_input_reupload(self) -> None:
        stderr, records = self.preparation_records("test-replacement")
        self.assertEqual(stderr.count("Assertion failed: tc_ready && inputs_ready"), 1)
        feeds = [r for r in records if r["event"] == "feed" and r["upload_id"] == 2]
        self.assertEqual([r["ret"] for r in feeds], [16, 48, 96, 24, 36])
        self.assertTrue(feeds[-1]["tc_ready"])
        for record in feeds:
            self.assertFalse(record["inputs_at_parser_entry"])
            self.assertFalse(record["inputs_ready"])
            self.assertEqual(record["next_at_parser_entry"], -1)
        traces = [r for r in records if r["event"] == "trace"]
        self.check_rejected_trace(traces[0], trace_calls=0)
        self.assertEqual(traces[0]["next_before"], -1)
        self.assertFalse(traces[0]["inputs_ready"])
        restored = self.check_input_upload(records, 3, [16, 16, 4096, 4096, 4096])
        self.assertTrue(restored[-1]["inputs_ready"])
        self.check_fresh_single_trace(traces[1], calls=1)

    def test_prepare_incomplete_inputs_invalidate_pending_results(self) -> None:
        stderr, records = self.preparation_records("input-incomplete")
        self.assertIn("Assertion failed: tc_ready && inputs_ready", stderr)
        first = next(r for r in records if r["event"] == "trace")
        self.assertEqual(first["ret"], 4032)
        self.assertEqual(first["next_after"], 0)
        feeds = self.check_input_upload(records, 2, [16, 16, 4096, 4096, 4088])
        self.assertTrue(feeds[0]["ready_before_call"])
        self.assertFalse(feeds[-1]["finished"])
        self.assertFalse(feeds[-1]["inputs_ready"])
        self.check_rejected_trace(records[-1], trace_calls=1, inputs_completed=False)
        self.assertFalse(records[-1]["inputs_completed"])

    def test_prepare_actual_input_header_error_clears_readiness(self) -> None:
        stderr, records = self.preparation_records("input-error")
        self.assertIn("Mismatch in n_actors", stderr)
        self.assertIn("Assertion failed: tc_ready && inputs_ready", stderr)
        first = next(r for r in records if r["event"] == "trace")
        self.assertEqual(first["next_after"], 0)
        feeds = self.check_input_upload(records, 2, [-1])
        self.assertTrue(feeds[0]["ready_before_call"])
        self.assertFalse(feeds[0]["finished"])
        self.assertFalse(feeds[0]["inputs_ready"])
        self.assertIsNone(feeds[0]["hash"])
        self.check_rejected_trace(records[-1], trace_calls=1)

    def test_prepare_inputs_require_completed_test_case(self) -> None:
        stderr, records = self.preparation_records("input-before-test")
        self.assertIn("Assertion failed: tc_ready", stderr)
        feed = records[0]
        self.assertEqual(feed["callback_ret"], -errno.EIO)
        self.assertEqual(feed["parser_calls"], 0)
        self.assertIsNone(feed["parser_ret"])
        self.assertFalse(feed["inputs_ready"])
        self.assertFalse(feed["tc_ready"])
        self.check_rejected_trace(records[-1], trace_calls=0)

    def test_prepare_test_upload_discards_real_pending_page(self) -> None:
        stderr, records = self.preparation_records("test-pending")
        self.assertIn("Assertion failed: tc_ready && inputs_ready", stderr)
        traces = [r for r in records if r["event"] == "trace"]
        self.assertEqual(traces[0]["trace_calls"], 1)
        self.assertEqual(traces[0]["ret"], 4032)
        self.assertEqual(traces[0]["next_after"], 0)
        replacement = [r for r in records if r["event"] == "feed" and r["upload_id"] == 2]
        self.assertEqual(replacement[0]["ret"], 16)
        self.assertEqual(replacement[0]["next_at_parser_entry"], -1)
        self.assertFalse(replacement[0]["inputs_at_parser_entry"])
        self.check_rejected_trace(traces[1], trace_calls=1)
        self.assertEqual(traces[1]["next_before"], -1)
        self.check_fresh_single_trace(traces[2], calls=2)

    def test_prepare_input_upload_discards_real_pending_page(self) -> None:
        stderr, records = self.preparation_records("input-pending")
        self.assertEqual(stderr, "")
        traces = [r for r in records if r["event"] == "trace"]
        self.assertEqual(traces[0]["ret"], 4032)
        self.assertEqual(traces[0]["next_after"], 0)
        feeds = self.check_input_upload(records, 2, [16, 16, 4096, 4096, 4096])
        self.assertTrue(feeds[0]["ready_before_call"])
        self.assertTrue(feeds[-1]["inputs_ready"])
        self.check_fresh_single_trace(traces[1], calls=2)

    def recovery_records(self, scenario: str) -> Tuple[str, List[Dict[str, Any]]]:
        environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                           UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        paths = [self.fixtures[key][0] for key in ("rcbf", "rdbf", "rdbf_wrong_actor")]
        result = subprocess.run([str(self.binary), "recover", scenario] + list(map(str, paths)),
                                capture_output=True, text=True, check=False,
                                timeout=5, env=environment)
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        records: List[Dict[str, Any]] = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(records[0]["event"], "init")
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"recover": scenario, "records": records, "stderr": result.stderr}))
        return result.stderr, records[1:-1]

    def test_recovery_legacy_risk_interrupted_rdbf_header_completes_old_batch(self) -> None:
        # Evidence of a defect, not a specification that this retry or admission is safe.
        stderr, records = self.recovery_records("rdbf-interrupted")
        self.assertEqual(stderr.count("Assertion failed: tc_ready && inputs_ready"), 1)
        partial = self.check_input_upload(records, 1, [16, 16, 4096, 4096, 4088])
        self.assertEqual(partial[-1]["cursor"], 12312)
        self.assertTrue(partial[-1]["receiving"])
        self.assertFalse(partial[-1]["inputs_ready"])
        retry = self.check_input_upload(records, 2, [8])[0]
        self.assertEqual(retry["requested"], 16)
        self.assertEqual(retry["cursor"], 12320)
        self.assertTrue(retry["finished"])
        self.assertFalse(retry["receiving"])
        self.assertTrue(retry["inputs_ready"])
        # Independent bytes: the old payload's missing tail was replaced by a new actor-count word.
        mixed = self.fixtures["rdbf"][1][:-8] + self.fixtures["rdbf"][0].read_bytes()[:8]
        self.assertEqual(retry["hash"], _hash(mixed))
        self.assertNotEqual(retry["hash"], _hash(self.fixtures["rdbf"][1]))
        self.assertEqual(retry["allocation_attempts"], partial[-1]["allocation_attempts"])
        self.assertEqual(retry["sandbox_calls"], 1)
        self.assertEqual(retry["code_calls"], 1)
        self.assertEqual(retry["trace_calls"], 0)
        traces = [r for r in records if r["event"] == "trace"]
        self.check_rejected_trace(traces[0], trace_calls=0, inputs_completed=False)
        self.assertEqual(traces[1]["ret"], 17)  # The actual callback admits the mixed batch.
        self.assertEqual(traces[1]["trace_calls"], 1)

    @unittest.expectedFailure
    def test_recovery_interrupted_rdbf_safety_invariant(self) -> None:
        # Pending production correction: process/sanitizer validation ran in setUp, outside
        # expectedFailure. Only the known admission safety assertions may fail here.
        records = self._recovery_safety_records
        retry = [r for r in records if r["event"] == "feed" and r["upload_id"] == 2]
        self.assertFalse(retry[-1]["inputs_ready"], "Retry must not validate mixed old/new bytes")
        self.assertEqual(records[-1]["ret"], -errno.EIO)
        self.assertEqual(records[-1]["trace_calls"], 0)
        self.assertTrue(records[-1]["buffer_unchanged"])

    def test_recovery_valid_rdbf_after_actor_mismatch(self) -> None:
        stderr, records = self.recovery_records("rdbf-error")
        self.assertIn("Mismatch in n_actors", stderr)
        error = self.check_input_upload(records, 1, [-1])[0]
        self.assertEqual(error["requested"], 16)
        self.assertEqual(error["cursor"], (1 << 64) - errno.EIO)
        self.assertFalse(error["finished"])
        self.assertFalse(error["receiving"])
        self.assertFalse(error["inputs_ready"])
        self.assertIsNone(error["hash"])
        retry = self.check_input_upload(records, 2, [16, 16, 4096, 4096, 4096])
        self.assertEqual(retry[0]["cursor"], 16)
        self.assertTrue(retry[0]["receiving"])
        self.assertEqual(retry[-1]["cursor"], 12320)
        self.assertTrue(retry[-1]["finished"])
        self.assertTrue(retry[-1]["inputs_ready"])
        self.assertEqual(retry[-1]["hash"], _hash(self.fixtures["rdbf"][1]))
        for record in retry:
            self.assertEqual(record["sandbox_calls"], 1)
            self.assertEqual(record["code_calls"], 1)
            self.assertEqual(record["trace_calls"], 0)
        traces = [r for r in records if r["event"] == "trace"]
        self.check_rejected_trace(traces[0], trace_calls=0)
        self.check_fresh_single_trace(traces[1], calls=1)

    def test_recovery_interrupted_rcbf_retry_is_not_a_new_header(self) -> None:
        stderr, records = self.recovery_records("rcbf-interrupted")
        self.assertIn("consumed_bytes (8) != count (16)", stderr)
        feeds = [r for r in records if r["event"] == "feed"]
        self.assertEqual([r["parser_ret"] for r in feeds], [16, 48, 96, 24, 28, -errno.EIO])
        self.assertEqual([r["callback_ret"] for r in feeds], [r["parser_ret"] for r in feeds])
        partial, retry = feeds[-2:]
        self.assertEqual(partial["cursor"], 212)
        self.assertTrue(partial["receiving"])
        self.assertEqual(retry["requested"], 16)
        self.assertEqual(retry["cursor"], 220)
        self.assertTrue(retry["finished"])
        self.assertFalse(retry["receiving"])
        self.assertIsNone(retry["consumed"])
        self.assertIsNone(retry["hash"])
        self.assertEqual(retry["allocation_attempts"], partial["allocation_attempts"])
        for record in feeds:
            self.assertFalse(record["tc_ready"])
            self.assertFalse(record["inputs_ready"])
            self.assertEqual(record["sandbox_calls"], 0)
            self.assertEqual(record["code_calls"], 0)
            self.assertEqual(record["trace_calls"], 0)
        traces = [r for r in records if r["event"] == "trace"]
        self.check_rejected_trace(traces[0], trace_calls=0, tc_completed=False)
        self.check_rejected_trace(traces[1], trace_calls=0)

    def failure_records(self, stage: str, replacement: bool) -> Tuple[str, List[Dict[str, Any]]]:
        environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                           UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        paths = [self.fixtures[key][0] for key in ("rcbf", "rdbf", "rdbf_paged")]
        result = subprocess.run(
            [str(self.binary), "failure", stage, "replacement" if replacement else "first"]
            + list(map(str, paths)), capture_output=True, text=True, check=False,
            timeout=5, env=environment)
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        records: List[Dict[str, Any]] = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(records[0]["event"], "init")
        self.assertFalse(records[0]["tc_ready"])
        self.assertFalse(records[0]["inputs_ready"])
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"failure_stage": stage, "replacement": replacement,
                              "records": records, "stderr": result.stderr}))
        return result.stderr, records[1:-1]

    def check_preparation_failure(self, stage: str, replacement: bool) -> None:
        stderr, records = self.failure_records(stage, replacement)
        self.assertIn("Error [allocate_sandbox]" if stage == "allocation"
                      else "Error [load_sandbox_code]", stderr)
        self.assertEqual(stderr.count("Assertion failed: tc_ready && inputs_ready"), 2)
        base = int(replacement)
        failure_id = 2 * base
        failed = [r for r in records if r["event"] == "feed" and r["upload_id"] == failure_id]
        self.assertEqual([r["parser_ret"] for r in failed], [16, 48, 96, 24, 36])
        self.assertEqual([r["callback_ret"] for r in failed], [16, 48, 96, 24, -errno.EIO])
        self.assertEqual(failed[-1]["cursor"], 220)
        self.assertTrue(failed[-1]["finished"])
        self.assertFalse(failed[-1]["receiving"])
        self.assertIsNone(failed[-1]["consumed"])
        self.assertEqual(failed[-1]["hash"], _hash(self.fixtures["rcbf"][1]))
        for record in failed:
            self.assertFalse(record["tc_ready"])
            self.assertFalse(record["inputs_ready"])
            self.assertFalse(record["inputs_at_parser_entry"])
            self.assertEqual(record["next_at_parser_entry"], -1)
            self.assertEqual(record["next_measurement_id"], -1)
        for record in failed[:-1]:
            self.assertEqual(record["sandbox_calls"], base)
            self.assertEqual(record["code_calls"], base)
        self.assertEqual(failed[-1]["sandbox_calls"], base + 1)
        self.assertEqual(failed[-1]["code_calls"], base + int(stage == "code"))
        self.assertEqual(failed[-1]["sandbox_ret"], -errno.ENOMEM if stage == "allocation" else 0)
        self.assertEqual(failed[-1]["code_ret"], -errno.EINVAL if stage == "code"
                         else (0 if replacement else None))

        retry = [r for r in records if r["event"] == "feed" and r["upload_id"] == failure_id + 1]
        self.assertEqual([r["parser_ret"] for r in retry], [16, 48, 96, 24, 36])
        self.assertEqual([r["callback_ret"] for r in retry], [16, 48, 96, 24, 36])
        self.assertTrue(retry[-1]["tc_ready"])
        self.assertFalse(retry[-1]["inputs_ready"])
        self.assertEqual(retry[-1]["sandbox_calls"], base + 2)
        self.assertEqual(retry[-1]["code_calls"], base + int(stage == "code") + 1)
        self.assertEqual(retry[-1]["sandbox_ret"], 0)
        self.assertEqual(retry[-1]["code_ret"], 0)
        traces = [r for r in records if r["event"] == "trace"]
        if replacement:
            self.assertEqual(traces[0]["trace_calls"], 1)
            self.assertEqual(traces[0]["ret"], 4032)
            self.assertEqual(traces[0]["next_after"], 0)
        self.check_rejected_trace(traces[base], trace_calls=base)
        self.assertFalse(traces[base]["tc_ready"])
        self.assertFalse(traces[base]["inputs_ready"])
        self.assertEqual(traces[base]["next_before"], -1)
        self.check_rejected_trace(traces[base + 1], trace_calls=base)
        self.assertTrue(traces[base + 1]["tc_ready"])
        self.assertFalse(traces[base + 1]["inputs_ready"])
        restored = self.check_input_upload(records, failure_id + 2, [16, 16, 4096, 4096, 4096])
        self.assertTrue(restored[-1]["inputs_ready"])
        self.check_fresh_single_trace(traces[-1], calls=base + 1)

    def test_preparation_first_allocation_failure_and_retry(self) -> None:
        self.check_preparation_failure("allocation", replacement=False)

    def test_preparation_first_code_failure_and_retry(self) -> None:
        self.check_preparation_failure("code", replacement=False)

    def test_preparation_replacement_allocation_failure_and_retry(self) -> None:
        self.check_preparation_failure("allocation", replacement=True)

    def test_preparation_replacement_code_failure_and_retry(self) -> None:
        self.check_preparation_failure("code", replacement=True)

    def reset_records(self, kind: str, scenario: str, initial: str,
                      recovery: str) -> List[Dict[str, Any]]:
        environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                           UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        expected_payload = self.build_dir / f"reset-expected-{recovery}.bin"
        result = subprocess.run(
            [str(self.binary), "reset", kind, scenario, str(self.fixtures[initial][0]),
             str(self.fixtures[recovery][0]), str(expected_payload),
             str(self.fixtures["rcbf"][0])], capture_output=True, text=True,
            check=False, timeout=5, env=environment)
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        records: List[Dict[str, Any]] = [json.loads(line) for line in result.stdout.splitlines()]
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"reset_format": kind, "scenario": scenario, "initial": initial,
                              "recovery": recovery, "stderr": result.stderr, "records": records}))
        if scenario == "error":
            expected_error = "Symbol table does not contain measurement start/end" if \
                kind == "rcbf" else "Mismatch in n_actors"
            self.assertIn(expected_error, result.stderr)
            self.assertNotIn("Sanitizer", result.stderr)
        else:
            self.assertEqual(result.stderr, "")
        self.assertEqual(records[0]["event"], "init")
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        return records

    def check_reset_observations(self, records: List[Dict[str, Any]], kind: str,
                                 scenario: str, recovery: str) -> None:
        resets = [r for r in records if r["event"] == "reset"]
        self.assertEqual(len(resets), 3 if scenario == "cycles" else
                         2 if scenario == "repeated" else 1)
        for index, record in enumerate(records):
            if record["event"] not in ("reset", "final_reset"):
                continue
            self.assertEqual(record["ret"], 0)
            self.assertTrue(record["idle_valid"])  # Includes private counts, capacities, aliases.
            self.assertTrue(record["not_receiving"])
            self.assertEqual(record["cursor"], 0)
            self.assertFalse(record["finished"])  # Per-call harness value, not parser validity.
            self.assertIsNone(record["parser_ret"])
            self.assertIsNone(record["hash"])
            self.assertGreater(record["root_bytes"], 0)
            recreated = scenario == "released" and record is resets[0]
            self.assertEqual(record["root_preserved"], not recreated)
            previous = next(r for r in reversed(records[:index]) if "allocation_attempts" in r)
            self.assertEqual(record["allocation_attempts"],
                             previous["allocation_attempts"] + int(recreated))
            if record["format"] == "rcbf":
                self.assertEqual(record["n_actors"], 0)
            else:
                self.assertEqual(record["n_inputs"], 0)
                self.assertEqual(record["n_actors"], 1 if kind == "rdbf" else
                                 3 if recovery == "rcbf_multi" else 1)
        for record in records:
            if record["event"] in ("feed", "reset", "final_reset"):
                self.assertFalse(record["tc_ready"])
                self.assertFalse(record["inputs_ready"])
                self.assertEqual(record["sandbox_calls"], 0)
                self.assertEqual(record["code_calls"], 0)
                self.assertEqual(record["trace_calls"], 0)

    def check_reset_scenario(self, kind: str, scenario: str, *, initial: str = "",
                             recovery: str = "") -> None:
        initial = initial or kind
        recovery = recovery or kind
        records = self.reset_records(kind, scenario, initial, recovery)
        self.check_reset_observations(records, kind, scenario, recovery)
        feeds = [r for r in records if r["event"] == "feed" and r["format"] == kind]
        recovered = [r for r in feeds if r["upload_id"] == feeds[-1]["upload_id"]]
        expected_returns = {"rcbf": [16, 48, 96, 24, 36],
                            "rcbf_multi": [16, 144, 288, 72, 36, 40, 44],
                            "rdbf": [16, 16, 4096, 4096, 4096]}
        self.assertEqual([r["ret"] for r in recovered], expected_returns[recovery])
        for record in recovered:
            self.assertEqual(record["parser_ret"], record["ret"])
            self.assertEqual(record["consumed"], record["ret"])
            self.assertIsNone(record["callback_ret"])
            self.assertLessEqual(record["ret"], record["requested"])
        self.assertTrue(any(r["ret"] < r["requested"] for r in recovered))
        self.assertTrue(all(not r["finished"] and r["receiving"] for r in recovered[:-1]))
        self.assertTrue(recovered[-1]["finished"])
        self.assertFalse(recovered[-1]["receiving"])
        self.assertEqual(recovered[-1]["cursor"], self.fixtures[recovery][2])
        self.assertEqual(sum(r["consumed"] for r in recovered), self.fixtures[recovery][2])
        self.assertEqual(recovered[-1]["hash"], _hash(self.fixtures[recovery][1]))
        self.assertEqual([r for r in records if r["event"] == "payload_comparison"],
                         [{"event": "payload_comparison", "equal": True,
                           "bytes": len(self.fixtures[recovery][1])}])
        if scenario not in ("repeated", "released"):
            before_reset = [records[i - 1] for i, r in enumerate(records)
                            if r["event"] == "reset"]
            for record in before_reset:
                if scenario == "error":
                    self.assertLess(record["ret"], 0)
                    self.assertEqual(record["finished"], kind == "rcbf")
                else:
                    self.assertGreater(record["ret"], 0)
                    self.assertEqual(record["finished"], scenario == "complete")
                    limit = self.fixtures[initial][2] - (0 if scenario == "complete" else 8)
                    self.assertEqual(record["cursor"], limit)
        final_resets = [r for r in records if r["event"] == "final_reset"]
        self.assertEqual(len(final_resets), 2)
        self.assertEqual(final_resets[-1]["live_bytes"],
                         sum(r["root_bytes"] for r in final_resets))

    def test_reset_interrupted_rcbf(self) -> None:
        self.check_reset_scenario("rcbf", "interrupted")

    def test_reset_interrupted_rdbf(self) -> None:
        self.check_reset_scenario("rdbf", "interrupted")

    def test_reset_repeated_rcbf(self) -> None:
        self.check_reset_scenario("rcbf", "repeated")

    def test_reset_repeated_rdbf(self) -> None:
        self.check_reset_scenario("rdbf", "repeated")

    def test_reset_completed_rcbf(self) -> None:
        self.check_reset_scenario("rcbf", "complete", initial="rcbf_multi")

    def test_reset_completed_rdbf(self) -> None:
        self.check_reset_scenario("rdbf", "complete", initial="rdbf_paged")

    def test_reset_rcbf_semantic_failure(self) -> None:
        self.check_reset_scenario("rcbf", "error", initial="rcbf_missing_end")

    def test_reset_rdbf_actor_mismatch(self) -> None:
        self.check_reset_scenario("rdbf", "error", initial="rdbf_wrong_actor")

    def test_reset_consecutive_interrupted_rcbf(self) -> None:
        self.check_reset_scenario("rcbf", "cycles", initial="rcbf_multi")

    def test_reset_consecutive_interrupted_rdbf(self) -> None:
        self.check_reset_scenario("rdbf", "cycles", initial="rdbf_paged")

    def test_reset_recovery_to_multi_actor_rcbf(self) -> None:
        self.check_reset_scenario("rcbf", "interrupted", recovery="rcbf_multi")

    def test_reset_interrupted_later_rcbf_section(self) -> None:
        self.check_reset_scenario("rcbf", "interrupted", initial="rcbf_multi")

    def test_reset_recreates_released_rcbf_root(self) -> None:
        self.check_reset_scenario("rcbf", "released")

    def test_reset_recreates_released_rdbf_root(self) -> None:
        self.check_reset_scenario("rdbf", "released")

    def check_attempt_scenario(self, scenario: str, final_state: str = "READY") -> None:
        kinds = ("rcbf", "rdbf", "rdbf_alternate", "rcbf_missing_end", "rdbf_wrong_actor")
        command = [str(self.binary), "attempt", scenario]
        command += [str(self.fixtures[k][0]) for k in kinds]
        command += [str(self.build_dir / "attempt-expected.bin"),
                    str(self.build_dir / "reset-expected-rcbf.bin")]
        environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                           UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        result = subprocess.run(command, capture_output=True, text=True, check=False,
                                timeout=5, env=environment)
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        if scenario.startswith("parser-error"):
            self.assertIn("Symbol table does not contain measurement start/end" if
                          scenario.endswith("tc") else "Mismatch in n_actors", result.stderr)
        else:
            self.assertEqual(result.stderr, "")
        records: List[Dict[str, Any]] = [json.loads(line) for line in result.stdout.splitlines()]
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"attempt_scenario": scenario, "records": records,
                              "stderr": result.stderr}))
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        self.assertEqual(records[-2]["event"], "attempt_result")
        self.assertEqual(records[-2]["state"], final_state)
        feeds = [r for r in records if r["event"] == "attempt_feed"]
        self.assertTrue(feeds)
        for record in feeds:
            self.assertEqual(record["calls_after"], record["calls_before"] + 1)
            if record["ret"] > 0:
                self.assertEqual(record["position"], record["before"] + record["ret"])
                self.assertLessEqual(record["ret"], record["requested"])
        if scenario != "phase":  # This scenario deliberately stops at the 16-byte header.
            self.assertTrue(any(0 < r["ret"] < r["requested"] for r in feeds))
        rejections = [r for r in records if r["event"] == "rejection"]
        for record in rejections:
            self.assertLess(record["ret"], 0)
            self.assertEqual(record["calls_before"], record["calls_after"])
            self.assertTrue(record["unchanged"])
        if scenario.startswith("stale-"):
            self.assertEqual([r["operation"] for r in rejections], ["feed", "complete", "abort"])
            self.assertTrue(all(r["prefix_bytes"] == (4096 if scenario.endswith("input") else 16)
                                for r in rejections))
        comparisons = [r for r in records if r["event"] == "payload_comparison"]
        self.assertTrue(all(r["equal"] for r in comparisons))
        if final_state == "READY":
            self.assertIn({"event": "payload_comparison", "bytes": 12288, "equal": True},
                          comparisons)
        if final_state == "UNRECOVERABLE":
            self.assertEqual(records[-2]["fake_resources"], 3)

    def test_attempt_valid_preparation(self) -> None:
        self.check_attempt_scenario("valid")

    def test_attempt_stale_input_before_parser(self) -> None:
        self.check_attempt_scenario("stale-input")

    def test_attempt_stale_tc_before_parser(self) -> None:
        self.check_attempt_scenario("stale-tc")

    def test_attempt_wrong_instance_kind_and_parent(self) -> None:
        self.check_attempt_scenario("identity")

    def test_attempt_premature_complete_fails_closed(self) -> None:
        self.check_attempt_scenario("premature", "FAILED")

    def test_attempt_terminal_operations(self) -> None:
        self.check_attempt_scenario("terminal")

    def test_attempt_tc_parser_failure(self) -> None:
        self.check_attempt_scenario("parser-error-tc", "FAILED")

    def test_attempt_input_parser_failure(self) -> None:
        self.check_attempt_scenario("parser-error-input", "FAILED")

    def test_attempt_cleanup_failure_prevents_retry(self) -> None:
        self.check_attempt_scenario("cleanup-failure", "UNRECOVERABLE")

    def test_attempt_abort_retry_cycles(self) -> None:
        self.check_attempt_scenario("cycles")

    def test_attempt_length_and_header_checks(self) -> None:
        self.check_attempt_scenario("lengths", "FAILED")

    def test_attempt_receiving_phase_required(self) -> None:
        self.check_attempt_scenario("phase", "FAILED")

    def test_store_complete_rcbf(self) -> None:
        feeds = self.run_fixture("rcbf", True, route="store")
        self.assertEqual([record["ret"] for record in feeds], [16, 48, 96, 24, 36])
        self.assertEqual(feeds[-1]["hash"], _hash(self.fixtures["rcbf"][1]))
        self.assertTrue(feeds[-1]["tc_ready"])
        self.assertEqual(feeds[-1]["sandbox_calls"], 1)
        self.assertEqual(feeds[-1]["code_calls"], 1)
        self.assertEqual(feeds[-1]["next_measurement_id"], -1)
        self.assertTrue(all(not record["ready_at_parser_entry"] for record in feeds))
        for record in feeds[:-1]:
            self.assertFalse(record["tc_ready"])
            self.assertEqual(record["sandbox_calls"], 0)
            self.assertEqual(record["code_calls"], 0)

    def test_store_incomplete_rcbf(self) -> None:
        feeds = self.run_fixture("rcbf", False, route="store")
        self.assertEqual([record["ret"] for record in feeds], [16, 48, 96, 24, 28])
        for record in feeds:
            self.assertFalse(record["tc_ready"])
            self.assertEqual(record["sandbox_calls"], 0)
            self.assertEqual(record["code_calls"], 0)

    def check_final_validation_failure(self, route: str) -> Dict[str, Any]:
        # Main function and measurement start are present. Only measurement end is absent.
        # has_start is therefore initialized on this path; no uninitialized-value dependency.
        result, records = self.invoke_fixture("rcbf_missing_end", True, route)
        self.assertEqual(result.returncode, 65, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stderr, "[rvzr_executor:__batch_tc_parsing_end] "
                         "Symbol table does not contain measurement start/end\n")
        self.assertEqual(records[0]["event"], "init")
        self.assertFalse(records[0]["tc_ready"])
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        feeds = records[1:-1]
        self.assertEqual([record["ret"] for record in feeds], [16, 48, 64, 24, -1])
        self.assertEqual([record["parser_ret"] for record in feeds], [16, 48, 64, 24, -1])
        for record in feeds[:-1]:
            self.assertFalse(record["finished"])
            self.assertFalse(record["tc_ready"])
            self.assertEqual(record["sandbox_calls"], 0)
            self.assertEqual(record["code_calls"], 0)
            self.assertEqual(record["consumed"], record["ret"])
        final = feeds[-1]
        self.assertEqual(final["requested"], 36)
        self.assertEqual(final["cursor"], self.fixtures["rcbf_missing_end"][2])
        self.assertEqual(final["cursor"], 188)
        self.assertTrue(final["finished"])
        self.assertTrue(final["not_receiving"])  # Completion, not validated readiness.
        self.assertFalse(final["receiving"])
        self.assertIsNone(final["consumed"])  # A negative return is not a consumed-byte count.
        self.assertIsNone(final["hash"])  # Do not diagnose payload after failed validation.
        self.assertEqual(final["metadata_allocation_bytes"], 24)
        self.assertEqual(final["parser_calls"], 5)
        return final

    def test_direct_final_validation_failure(self) -> None:
        final = self.check_final_validation_failure("direct")
        self.assertIsNone(final["callback_ret"])
        self.assertFalse(final["tc_ready"])
        self.assertEqual(final["sandbox_calls"], 0)
        self.assertEqual(final["code_calls"], 0)

    def test_store_rejects_final_validation_failure(self) -> None:
        final = self.check_final_validation_failure("store")
        self.assertEqual(final["callback_ret"], -1)
        self.assertFalse(final["tc_ready"])
        self.assertEqual(final["sandbox_calls"], 0)
        self.assertEqual(final["code_calls"], 0)
        self.assertEqual(final["next_measurement_id"], -1)

    def test_store_valid_then_invalid_replacement(self) -> None:
        # Both uploads use actual callback/parser state in one process. Never set tc_ready
        # in the driver, and never reset the parser or counters between these uploads.
        result, records = self.invoke_fixture("rcbf", True, "store",
                                              replacement="rcbf_missing_end")
        self.assertEqual(result.returncode, 65, f"{result.stdout}\n{result.stderr}")
        self.assertEqual(result.stderr, "[rvzr_executor:__batch_tc_parsing_end] "
                         "Symbol table does not contain measurement start/end\n")
        self.assertEqual(records[0]["event"], "init")
        self.assertFalse(records[0]["tc_ready"])
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        feeds = records[1:-1]
        self.assertEqual([record["upload_id"] for record in feeds], [0] * 5 + [1] * 5)
        self.assertEqual([record["parser_calls"] for record in feeds], list(range(1, 11)))
        original, replacement = feeds[:5], feeds[5:]
        self.assertEqual([record["callback_ret"] for record in original], [16, 48, 96, 24, 36])
        self.assertTrue(original[-1]["tc_ready"])
        self.assertTrue(original[-1]["finished"])
        self.assertEqual(original[-1]["hash"], _hash(self.fixtures["rcbf"][1]))
        for record in original[:-1]:
            self.assertFalse(record["tc_ready"])
            self.assertEqual(record["sandbox_calls"], 0)
            self.assertEqual(record["code_calls"], 0)
        self.assertTrue(replacement[0]["ready_before_call"])
        self.assertEqual(replacement[0]["cursor"], 16)  # A real new-header parse occurred.
        self.assertEqual([record["callback_ret"] for record in replacement],
                         [16, 48, 64, 24, -1])
        for record in feeds:
            self.assertEqual(record["parser_ret"], record["callback_ret"])
            self.assertFalse(record["ready_at_parser_entry"])
        for record in replacement:
            self.assertFalse(record["tc_ready"])
            self.assertEqual(record["sandbox_calls"], 1)  # Only the original preparation.
            self.assertEqual(record["code_calls"], 1)
        for record in replacement[:-1]:
            self.assertFalse(record["finished"])
            self.assertTrue(record["receiving"])
            self.assertEqual(record["consumed"], record["ret"])
        self.assertTrue(replacement[-1]["finished"])
        self.assertFalse(replacement[-1]["receiving"])
        self.assertEqual(replacement[-1]["cursor"], 188)
        self.assertIsNone(replacement[-1]["consumed"])
        self.assertIsNone(replacement[-1]["hash"])

    def test_complete_rcbf(self) -> None:
        feeds = self.run_fixture("rcbf", True)
        self.assertEqual([record["ret"] for record in feeds], [16, 48, 96, 24, 36])
        self.assertEqual(feeds[-1]["hash"], _hash(self.fixtures["rcbf"][1]))

    def test_incomplete_rcbf(self) -> None:
        feeds = self.run_fixture("rcbf", False)
        self.assertEqual([record["ret"] for record in feeds], [16, 48, 96, 24, 28])
        self.assertIsNone(feeds[-1]["hash"])

    def test_complete_multi_actor_rcbf(self) -> None:
        feeds = self.run_fixture("rcbf_multi", True, actor_count=3)
        self.assertEqual([record["ret"] for record in feeds], [16, 144, 288, 72, 36, 40, 44])
        self.assertEqual(feeds[-1]["hash"], _hash(self.fixtures["rcbf_multi"][1]))

    def test_incomplete_multi_actor_rcbf(self) -> None:
        feeds = self.run_fixture("rcbf_multi", False, actor_count=3)
        self.assertEqual([record["ret"] for record in feeds], [16, 144, 288, 72, 36, 40, 36])
        self.assertIsNone(feeds[-1]["hash"])

    def test_multi_actor_rcbf_sections_split_across_calls(self) -> None:
        feeds = self.run_fixture("rcbf_multi", True, actor_count=3, step=32)
        # Payload starts after the 16-byte header, 144 actor, 288 symbol and 72 metadata bytes.
        self.assertEqual([(record["cursor"], record["ret"]) for record in feeds
                          if record["cursor"] > 520],
                         [(552, 32), (556, 4), (588, 32), (596, 8), (628, 32), (640, 12)])
        self.assertEqual(feeds[-1]["hash"], _hash(self.fixtures["rcbf_multi"][1]))

    def test_complete_rdbf(self) -> None:
        feeds = self.run_fixture("rdbf", True)
        self.assertEqual([record["ret"] for record in feeds], [16, 16, 4096, 4096, 4096])
        self.assertEqual(feeds[-1]["n_inputs"], 1)
        self.assertEqual(feeds[-1]["hash"], _hash(self.fixtures["rdbf"][1]))

    def test_incomplete_rdbf(self) -> None:
        feeds = self.run_fixture("rdbf", False)
        self.assertEqual([record["ret"] for record in feeds], [16, 16, 4096, 4096, 4088])
        self.assertEqual(feeds[-1]["n_inputs"], 1)
        self.assertIsNone(feeds[-1]["hash"])


if __name__ == "__main__":
    unittest.main()
