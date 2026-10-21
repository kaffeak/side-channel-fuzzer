"""Direct production-parser baseline, not sysfs, allocation or kernel-safety validation.

Run ordinary tests first: python -m unittest tests.unit_kernel_upload_parsers -v
Select a separate instrumented build with RVZR_PARSER_SANITIZER=address|undefined.
Use unittest -f to stop immediately on instrumented failures; never pad allocations.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring

import json
import os
from pathlib import Path
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


def _rcbf_fixture(directory: Path, actor_count: int) -> Tuple[Path, bytes, int]:
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
            SymbolTableEntry(actor_id, len(code) - 12, 2, 0),
        ])
        offset += len(code)
    program.assign_obj(str(binary))
    program.get_obj().assign_elf_data(symbols, {actor_id: {} for actor_id in range(actor_count)})
    program.mark_as_assembled()
    rcbf = directory / f"valid-{actor_count}.rcbf"
    program.get_obj().save_rcbf(str(rcbf))
    return rcbf, b"".join(sections), 16 + actor_count * (48 + 3 * 32 + 24) + offset


def _fixtures(directory: Path) -> Dict[str, Tuple[Path, bytes, int]]:
    input_ = InputData(1)
    pattern = (np.arange(input_.nbytes, dtype=np.uint64) % 251).astype(np.uint8)
    input_.view(np.uint8).reshape(-1)[:] = pattern
    rdbf = directory / "valid.rdbf"
    save_input_sequence_as_rdbf([input_], str(rdbf))
    return {"rcbf": _rcbf_fixture(directory, 1), "rcbf_multi": _rcbf_fixture(directory, 3),
            "rdbf": (rdbf, input_.tobytes(), 12320)}


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
            exceptions = [] if Path(source).name == "harness.c" else ["-Wno-error=sign-compare"]
            cls.build_commands.append(compiler + flags + instrumentation + exceptions
                                      + ["-c", source, "-o", str(obj)])
            objects.append(str(obj))
        cls.build_commands.append(compiler + instrumentation + objects + ["-o", str(cls.binary)])
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

    def run_fixture(self, kind: str, complete: bool, actor_count: int = 1,
                    step: int = 4096) -> List[Dict[str, Any]]:
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
            [str(self.binary), parser, "direct", str(path), str(limit), str(step)],
            capture_output=True, text=True, check=False, timeout=5, env=environment)
        self.assertEqual(result.returncode, 0,
                         f"{kind} complete={complete}, exit={result.returncode}\n"
                         f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        self.assertEqual(result.stderr, "")
        records: List[Dict[str, Any]] = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(records[0]["event"], "init")
        self.assertTrue(records[0]["not_receiving"])  # Idle, not a validated upload.
        self.assertFalse(records[0]["finished"])
        self.assertEqual(records[-1], {"event": "teardown", "live_bytes": 0})
        feeds = records[1:-1]
        self.assertTrue(feeds)
        for record in feeds:
            self.assertEqual(record["event"], "feed")
            self.assertGreater(record["ret"], 0)
            self.assertEqual(record["consumed"], record["ret"])
            self.assertLessEqual(record["ret"], record["requested"])
            self.assertLessEqual(record["requested"], step)
            self.assertEqual(record["receiving"], not record["not_receiving"])
            self.assertEqual(record["n_actors"], actor_count)
            if parser == "rcbf":
                # Exact metadata allocations put the nonexistent next entry into ASan's redzone.
                self.assertEqual(record["metadata_allocation_bytes"], actor_count * 24)
        self.assertTrue(any(record["ret"] < record["requested"] for record in feeds))
        self.assertEqual(sum(record["consumed"] for record in feeds), limit)
        self.assertEqual(feeds[-1]["cursor"], limit)
        self.assertEqual(feeds[-1]["finished"], complete)
        self.assertEqual(feeds[-1]["not_receiving"], complete)
        for record in feeds[:-1]:
            self.assertFalse(record["finished"])
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"format": kind, "complete": complete, "records": records}))
        return feeds

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
