"""Synthetic offline output-verifier checks, never architectural execution evidence."""

# pylint: disable=missing-class-docstring,missing-function-docstring

import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from typing import Any
import unittest

from tools.verify_arm64_architectural_output import validate_output


def fixture(selector: int = 0, word: int = 7, page: int = 16384
            ) -> tuple[bytes, list[dict[str, Any]]]:
    """Explicit expected record fixtures; not captured or fabricated hardware results."""
    wire = bytearray(12288)
    struct.pack_into("<Q", wire, 0, word)
    struct.pack_into("<Q", wire, 8192, selector)
    # Independent literal outcomes for the small table exercised below.
    outcomes = {(0, 7): (22, 29, 0x60000000), (1, 7): (11, 18, 0x20000000),
                (0, (1 << 64) - 1): (22, 21, 0x60000000),
                ((1 << 64) - 1, 5): (11, 16, 0xa0000000)}
    marker, total, flags = outcomes[(selector, word)]
    metadata = {"kind": "metadata", "fixture": "b34a-fixed-body-v1",
                "input_format": "rvzr-inputdata-raw-v1", "program_source": "embedded-reference",
                "program_format": "rvzr-b34a-body-v1", "architecture": "aarch64",
                "page_size": page, "kernel": "synthetic-only"}
    state = {"kind": "architectural_state", "status": "ok", "input": 0,
             "selector": selector, "initial_word": word, "data_base": "0x100000",
             "code_base": "0x200000", "x0_x7": [selector, marker, word, total, 0, 0, 0, 0],
             "nzcv": flags, "sp_mod16": 0,
             "main_hex": (struct.pack("<Q", total) + bytes(4088)).hex()}
    return bytes(wire), [metadata, state, {"kind": "complete", "status": "ok", "cases": 1}]


def encoded(rows: list[dict[str, Any]]) -> bytes:
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()


class ArchitecturalOutputVerifierTest(unittest.TestCase):
    def test_expected_outcomes_and_page_sizes(self) -> None:
        for page in (4096, 16384):
            for selector, word in ((0, 7), (1, 7), (0, (1 << 64) - 1), ((1 << 64) - 1, 5)):
                wire, rows = fixture(selector, word, page)
                report = validate_output(encoded(rows), 0, wire,
                                         kernel_release="synthetic-only", page_size=page)
                self.assertEqual(report["status"], "validated")
        # Full-main comparison must preserve supported, nonzero bytes beyond the first word.
        wire, rows = fixture()
        nonzero_tail = bytearray(wire)
        nonzero_tail[4095] = 0x7a
        rows[1]["main_hex"] = rows[1]["main_hex"][:-2] + "7a"
        validate_output(encoded(rows), 0, bytes(nonzero_tail),
                        kernel_release="synthetic-only", page_size=16384)
        with self.assertRaises(ValueError):
            validate_output(encoded(rows), 0, wire,
                            kernel_release="synthetic-only", page_size=16384)

    def test_failed_and_partial_runs_never_validate(self) -> None:
        wire, rows = fixture()
        for code in (1, 2, 124, 137, -11, True):
            with self.subTest(exit=code), self.assertRaises(ValueError):
                validate_output(encoded(rows), code, wire,
                                kernel_release="synthetic-only", page_size=16384)
        for raw in (b"", encoded(rows[:-1]), encoded(rows + [rows[-1]]), encoded(rows)[::-1],
                    encoded(rows)[:-1], b"x" * 16385, b"[]\n[]\n[]\n", b"\xff\n"):
            with self.assertRaises((ValueError, KeyError, TypeError)):
                validate_output(raw, 0, wire, kernel_release="synthetic-only", page_size=16384)

    def test_corruption_and_wrong_context_rejected(self) -> None:
        wire, rows = fixture()
        for index, field, value in ((0, "kernel", "wrong"), (0, "page_size", True),
                                    (0, "program_source", "approved-generated"),
                                    (1, "input", True), (1, "x0_x7", [0] * 8),
                                    (1, "nzcv", 0), (1, "sp_mod16", 8),
                                    (1, "main_hex", "00" * 4096), (1, "selector", 1),
                                    (1, "data_base", "bad"), (1, "code_base", "0x100000"),
                                    (1, "code_base", "0x200001"),
                                    (1, "code_base", "0xffffffffffffffff"),
                                    (2, "cases", True)):
            changed = copy.deepcopy(rows)
            changed[index][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_output(encoded(changed), 0, wire,
                                kernel_release="synthetic-only", page_size=16384)
        for raw in (encoded(rows).replace(b'"kind": "metadata"', b'"kind":"metadata","kind":1'),
                    encoded(rows).replace(b'"input": 0', b'"input": NaN'),
                    encoded(rows).replace(b'"input": 0', b'"input": 0.0')):
            with self.assertRaises(ValueError):
                validate_output(raw, 0, wire, kernel_release="synthetic-only", page_size=16384)
        invalid = bytearray(wire)
        invalid[8200] = 1
        for fragment in (wire[:-1], wire + b"\0", bytes(invalid)):
            with self.assertRaises(ValueError):
                validate_output(encoded(rows), 0, fragment,
                                kernel_release="synthetic-only", page_size=16384)

    def test_cli_preserves_timeout_and_reports_validation_failure(self) -> None:
        tool = Path(__file__).resolve().parents[1] / "tools/verify_arm64_architectural_output.py"
        wire, rows = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "input").write_bytes(wire)
            (directory / "output").write_bytes(encoded(rows))
            for code in (0, 124, "0" * 17):
                (directory / "exit").write_text(str(code))
                run = subprocess.run([sys.executable, str(tool), str(directory / "output"),
                                      "--input", str(directory / "input"), "--exit-file",
                                      str(directory / "exit"), "--kernel", "synthetic-only",
                                      "--page-size", "16384"], capture_output=True, check=False,
                                     timeout=5)
                self.assertEqual(run.returncode, 0 if code == 0 else 1)
                self.assertEqual(json.loads(run.stdout)["status"],
                                 "validated" if code == 0 else "rejected")
