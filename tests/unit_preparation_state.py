"""Host tests for passive C logic, not actual parser reset or native cleanup.

CC selects a native compiler. RVZR_PREPARATION_SANITIZER=address or undefined
selects separate instrumentation. No kernel headers, module or host-page query.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,too-many-public-methods

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from typing import Dict
import unittest


_ROOT = Path(__file__).resolve().parents[1]


class PreparationStateTest(unittest.TestCase):
    binary: Path
    environment: Dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("Passive state tests require a native C11 compiler")
        sanitizer = os.environ.get("RVZR_PREPARATION_SANITIZER", "")
        if sanitizer not in ("", "address", "undefined"):
            raise ValueError("RVZR_PREPARATION_SANITIZER must be address or undefined")
        # pylint: disable-next=consider-using-with
        temporary = tempfile.TemporaryDirectory(prefix="rvzr-preparation-state-")
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "preparation-state"
        flags = ["-std=c11", "-pedantic-errors", "-O2", "-g", "-Wall", "-Wextra", "-Werror"]
        if sanitizer:
            flags += [f"-fsanitize={sanitizer}", "-fno-sanitize-recover=all",
                      "-fno-omit-frame-pointer", "-no-pie"]
        command = compiler + flags + [
            "-I", str(_ROOT / "rvzr/executor_km/include"),
            str(_ROOT / "rvzr/executor_km/preparation_state.c"),
            str(_ROOT / "tests/kernel_upload_parsers/preparation_state_test.c"),
            "-o", str(cls.binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
        if result.returncode or result.stderr:
            raise AssertionError(f"Build failed or emitted diagnostics: {shlex.join(command)}\n"
                                 f"{result.stdout}{result.stderr}")
        cls.environment = dict(os.environ)
        if sanitizer == "address":
            # Match the parser harness's documented WSL2 LeakSanitizer limitation.
            # This component allocates nothing; ASan bounds checks remain active.
            cls.environment["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
        elif sanitizer == "undefined":
            cls.environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"

    def run_case(self, name: str) -> None:
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True,
                                check=False, timeout=5, env=self.environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, f"PASS {name}\n")

    def test_progression(self) -> None:
        self.run_case("progression")

    def test_early_commit(self) -> None:
        self.run_case("early_commit")

    def test_failed_tc(self) -> None:
        self.run_case("failed_tc")

    def test_failed_input(self) -> None:
        self.run_case("failed_input")

    def test_abort_tc(self) -> None:
        self.run_case("abort_tc")

    def test_abort_input(self) -> None:
        self.run_case("abort_input")

    def test_stale_attempt(self) -> None:
        self.run_case("stale_attempt")

    def test_delayed_operation(self) -> None:
        self.run_case("delayed_operation")

    def test_clean_retry(self) -> None:
        self.run_case("clean_retry")

    def test_unsafe_cleanup(self) -> None:
        self.run_case("unsafe_cleanup")

    def test_fatal_rejection(self) -> None:
        self.run_case("fatal_rejection")

    def test_identifiers(self) -> None:
        self.run_case("identifiers")

    def test_overflow(self) -> None:
        self.run_case("overflow")

    def test_uncommitted_input(self) -> None:
        self.run_case("uncommitted_input")

    def test_newer_state(self) -> None:
        self.run_case("newer_state")

    def test_wrong_identity(self) -> None:
        self.run_case("wrong_identity")

    def test_wrong_instance(self) -> None:
        self.run_case("wrong_instance")

    def test_replace_tc(self) -> None:
        self.run_case("replace_tc")

    def test_replace_input(self) -> None:
        self.run_case("replace_input")

    def test_rejected_operations(self) -> None:
        self.run_case("rejected_operations")


if __name__ == "__main__":
    unittest.main()
