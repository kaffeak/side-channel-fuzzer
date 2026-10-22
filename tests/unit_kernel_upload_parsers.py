"""Production parser/callback characterization, not kernel allocation or safety validation.

Run ordinary tests first: python -m unittest tests.unit_kernel_upload_parsers -v
Select a separate instrumented build with RVZR_PARSER_SANITIZER=address|undefined.
Use unittest -f to stop immediately on instrumented failures; never pad allocations.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring

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
    return {"rcbf": _rcbf_fixture(directory, 1), "rcbf_multi": _rcbf_fixture(directory, 3),
            "rcbf_missing_end": _rcbf_fixture(directory, 1, include_end=False),
            "rdbf_paged": (paged, input_.tobytes() * 33, 405536),
            "rdbf_wrong_actor": (wrong_actor, wrong_input.tobytes(), 24624),
            "rdbf": (rdbf, input_.tobytes(), 12320)}


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
    for name in ("check_test_case_compat", "test_case_store", "inputs_store", "trace_show"):
        matches = list(re.finditer(
            rf"^static (?:int|ssize_t) {name}\([^;{{}}]*\)\n\{{\n.*?^\}}$",
            source, re.MULTILINE | re.DOTALL))
        if len(matches) != 1:
            raise RuntimeError(f"Cannot isolate exactly one production {name} definition")
        match = matches[0]
        line = source.count("\n", 0, match.start()) + 1
        parts.append(f"#line {line} {json.dumps(str(path))}\n{match.group()}\n")
    parts.append('#line 1 "host_callback_adapter"\n'
                 'ssize_t host_test_case_store(const char *buf, size_t count)\n'
                 '{ return test_case_store(NULL, NULL, buf, count); }\n'
                 'ssize_t host_inputs_store(const char *buf, size_t count)\n'
                 '{ return inputs_store(NULL, NULL, buf, count); }\n'
                 'ssize_t host_trace_show(char *buf)\n'
                 '{ return trace_show(NULL, NULL, buf); }\n')
    return "".join(parts)


# Keep related callback regressions on one shared native-build fixture.
class KernelUploadParserBaselineTest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    build_dir: Path
    binary: Path
    fixtures: Dict[str, Tuple[Path, bytes, int]]
    build_commands: List[List[str]]
    build_diagnostics: str

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
        for filename, helper, cursor in (("test_case_parser.c", "host_tc_cursor", "_cursor"),
                                         ("input_parser.c", "host_input_cursor", "cursor")):
            unit = cls.build_dir / filename
            # Including each unchanged .c in its own TU exposes only a read-only cursor accessor.
            unit.write_text(f"#include {json.dumps(str(_KERNEL / filename))}\n"
                            f"uint64_t {helper}(void) {{ return {cursor}; }}\n", encoding="utf-8")
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
        for source in [str(_HARNESS / "harness.c")] + units:
            obj = cls.build_dir / (Path(source).stem + ".o")
            # Preserve existing parser signedness warnings; new harness warnings remain fatal.
            exceptions = []
            if Path(source).name in ("test_case_parser.c", "input_parser.c"):
                exceptions = ["-Wno-error=sign-compare"]
            elif Path(source).name == "upload_callback.c":
                exceptions = ["-Wno-error=unused-parameter"]
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
                             *, inputs_completed: bool = True) -> None:
        self.assertEqual(record["ret"], -errno.EIO)
        self.assertEqual(record["trace_calls"], trace_calls)
        self.assertTrue(record["buffer_unchanged"])
        self.assertEqual(record["output_hex"], "")
        self.assertEqual(record["unfinished_before"], record["unfinished_after"])
        self.assertEqual(record["next_before"], record["next_after"])
        # Completion predicates are checked separately from validated readiness.
        self.assertTrue(record["tc_completed"])
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
