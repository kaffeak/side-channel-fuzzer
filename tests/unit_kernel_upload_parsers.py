"""Production parser/callback characterization, not kernel allocation or safety validation.

Run ordinary tests first: python -m unittest tests.unit_kernel_upload_parsers -v
Select a separate instrumented build with RVZR_PARSER_SANITIZER=address|undefined.
Use unittest -f to stop immediately on instrumented failures; never pad allocations.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring

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
    return {"rcbf": _rcbf_fixture(directory, 1), "rcbf_multi": _rcbf_fixture(directory, 3),
            "rcbf_missing_end": _rcbf_fixture(directory, 1, include_end=False),
            "rdbf": (rdbf, input_.tobytes(), 12320)}


def _callback_unit() -> str:
    """Extract two exact top-level definitions; fail closed if their shape changes.

    This is deliberately not a general C extractor. Only these current definitions
    have an opening/closing brace at column zero and no nested column-zero braces.
    No callback statements are generated, replaced or rewritten.
    """
    path = _KERNEL / "main.c"
    source = path.read_text(encoding="utf-8")
    parts = ['#include "compat.h"\n#include "test_case_parser.h"\n'
             '#include "sandbox_manager.h"\n#include "code_loader.h"\n'
             '#include "shortcuts.h"\nstruct kobject;\nstruct kobj_attribute;\n'
             'extern bool tc_ready;\nextern int next_measurement_id;\n']
    for name in ("check_test_case_compat", "test_case_store"):
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
                 '{ return test_case_store(NULL, NULL, buf, count); }\n')
    return "".join(parts)


class KernelUploadParserBaselineTest(unittest.TestCase):
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
                                  + ["-Wl,--wrap=parse_test_case_buffer", "-o", str(cls.binary)])
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
