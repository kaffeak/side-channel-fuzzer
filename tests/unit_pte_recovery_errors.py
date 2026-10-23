"""Reported-error propagation through extracted production C, not PTE recovery validation.

CPU setup, PTE helpers and generated execution are replaced by bounded return/order
stubs. No physical PTE layout, mapping lifetime or successful restoration is modeled.
Use RVZR_PARSER_SANITIZER=address|undefined for separate instrumented builds.
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
import tempfile
from typing import Any, Dict
import unittest


_ROOT = Path(__file__).resolve().parents[1]
_KERNEL = _ROOT / "rvzr/executor_km"
_HARNESS = _ROOT / "tests/kernel_upload_parsers"


def _function(filename: str, name: str) -> str:
    path = _KERNEL / filename
    source = path.read_text(encoding="utf-8")
    # Current top-level definitions only; fail closed, no body rewriting.
    prefix = rf"^(?:static (?:inline )?)?(?:int|ssize_t) {name}\([^;{{}}]*\)"
    pattern = prefix + r"(?: \{[^\n{}]*\}$|\n\{\n.*?^\}$)"
    matches = list(re.finditer(pattern, source, re.MULTILINE | re.DOTALL))
    if len(matches) != 1:
        raise RuntimeError(f"Cannot isolate production {filename}:{name}")
    match = matches[0]
    line = source.count("\n", 0, match.start()) + 1
    return f"#line {line} {json.dumps(str(path))}\n{match.group()}\n"


def _unit() -> str:
    main = (_KERNEL / "main.c").read_text(encoding="utf-8")
    wrappers = main.split("// RVZR_CALLBACK_WRAPPERS_BEGIN\n", 1)[1]
    wrappers = wrappers.split("// RVZR_CALLBACK_WRAPPERS_END", 1)[0]
    if len(re.findall(r"^RVZR_LOCKED_SHOW\(trace_show\)$", main, re.MULTILINE)) != 1:
        raise RuntimeError("Cannot isolate trace wrapper binding")
    parts = ['#include "compat.h"\n',
             'struct kobject;\nstruct kobj_attribute;\n'
             'struct mutex { bool held; };\n'
             '#define DEFINE_MUTEX(name) struct mutex name = {false}\n'
             'static void mutex_lock(struct mutex *m)\n'
             '{ if (m->held) abort(); m->held = true; }\n'
             'static void mutex_unlock(struct mutex *m)\n'
             '{ if (!m->held) abort(); m->held = false; }\n'
             'static DEFINE_MUTEX(executor_mutex);\n', wrappers,
             f'#include {json.dumps(str(_HARNESS / "recovery_errors.c"))}\n',
             _function("sandbox_manager.c", "restore_orig_sandbox_page_tables")]
    # Keep the pre-existing uint8_t* -> char* warning visible without changing production.
    # Only the extracted measurement functions receive this exception, not the test stubs.
    parts.append('#pragma GCC diagnostic push\n'
                 '#pragma GCC diagnostic warning "-Wpointer-sign"\n')
    parts.extend(_function("measurement.c", name) for name in (
        "uarch_flush", "check_measurement_status", "set_execution_environment",
        "recover_orig_state", "run_experiment", "trace_test_case"))
    parts.extend(['#pragma GCC diagnostic pop\n', _function("main.c", "trace_show_unlocked"),
                  'RVZR_LOCKED_SHOW(trace_show)\n'
                  'ssize_t host_trace_entry(char *buf)\n'
                  '{ ssize_t ret = trace_show(NULL, NULL, buf);\n'
                  '  if (executor_mutex.held) abort(); return ret; }\n'])
    return "".join(parts)


class PteRecoveryErrorTest(unittest.TestCase):
    binary: Path
    environment: Dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("Recovery-flow tests require a native C compiler")
        sanitizer = os.environ.get("RVZR_PARSER_SANITIZER", "none")
        if sanitizer not in ("none", "address", "undefined"):
            raise ValueError("RVZR_PARSER_SANITIZER must be none, address or undefined")
        # pylint: disable-next=consider-using-with
        temporary = tempfile.TemporaryDirectory(prefix="rvzr-recovery-errors-")
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        for name in ("linux/types.h", "linux/slab.h", "linux/kernel.h", "linux/mm.h",
                     "linux/vmalloc.h", "linux/version.h", "linux/kallsyms.h",
                     "linux/interrupt.h", "asm/io.h", "asm/cpu.h"):
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('#include "compat.h"\n', encoding="utf-8")
        unit = directory / "recovery-flow.c"
        unit.write_text(_unit(), encoding="utf-8")
        cls.binary = directory / "recovery-flow"
        flags = ["-std=gnu11", "-O0", "-g", "-Wall", "-Wextra", "-Werror", "-D__KERNEL__",
                 "-Wno-error=unused-parameter", "-DVENDOR_ID=3", "-DPHYSICAL_WIDTH=48",
                 "-DL1D_ASSOCIATIVITY=8", "-DL1D_SIZE_KB=32"]
        if sanitizer != "none":
            flags += [f"-fsanitize={sanitizer}", "-fno-sanitize-recover=all",
                      "-fno-omit-frame-pointer", "-no-pie"]
        command = compiler + flags + ["-I" + str(directory), "-I" + str(_HARNESS),
                                      "-I" + str(_KERNEL / "include"), str(unit),
                                      "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
        if result.returncode:
            raise RuntimeError(f"Build failed: {shlex.join(command)}\n{result.stderr}")
        cls.environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:halt_on_error=1",
                               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        if os.environ.get("RVZR_PARSER_VERBOSE") == "1":
            print(json.dumps({"command": command, "build_diagnostics": result.stderr}))

    def records(self, stage: str, status: str, *, setup_error: bool = False) -> Dict[str, Any]:
        result = subprocess.run([str(self.binary), stage, status,
                                 "setup-error" if setup_error else "normal"],
                                capture_output=True, text=True, check=False, timeout=5,
                                env=self.environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # No stderr is silently discarded; only the production CHECK_ERR diagnostics are allowed.
        expected = ""
        if stage in ("run", "trace") and (status != "ok" or setup_error):
            expected = "[rvzr_executor]  Error [run_experiment:cleanup]\n"
            if stage == "trace":
                expected += "[rvzr_executor]  Error [trace_test_case:cleanup]\n"
        self.assertEqual(result.stderr, expected)
        record: Dict[str, Any] = json.loads(result.stdout)
        return record

    def test_wrapper_preserves_reported_restore_result(self) -> None:
        for status, expected in (("ok", 0), ("io", -errno.EIO), ("stale", -errno.ESTALE)):
            with self.subTest(status=status):
                record = self.records("wrapper", status)
                self.assertEqual(record["ret"], expected)
                self.assertEqual(record["events"], "H")

    def test_recovery_preserves_error_and_existing_cleanup_order(self) -> None:
        for status, expected in (("ok", 0), ("io", -errno.EIO), ("stale", -errno.ESTALE)):
            with self.subTest(status=status):
                record = self.records("recover", status)
                self.assertEqual(record["ret"], expected)
                self.assertEqual(record["events"], "FSH")

    def test_normal_loop_cannot_hide_reported_restore_error(self) -> None:
        for status in ("io", "stale"):
            with self.subTest(status=status):
                record = self.records("run", status)
                self.assertEqual(record["ret"], -errno.EIO)
                self.assertEqual(record["events"], "BCDAIEUFFSH")

    def test_restore_error_reaches_real_trace_admission_barrier(self) -> None:
        for status in ("io", "stale"):
            with self.subTest(status=status):
                record = self.records("trace", status)
                self.assertEqual(record["ret"], -errno.EIO)
                self.assertEqual(record["repeat"], -errno.EIO)
                self.assertEqual(record["events"], "MPOBCDAIEUFFSHQ")
                self.assertEqual(len(record["events"]), record["first_events"])
                self.assertTrue(record["unfinished"])
                self.assertFalse(record["tc_ready"])
                self.assertFalse(record["inputs_ready"])
                self.assertEqual(record["next"], -1)
                self.assertTrue(record["buffer_unchanged"])
                self.assertTrue(record["repeat_buffer_unchanged"])
                self.assertEqual(record["output_hex"], "")

    def test_success_keeps_existing_trace_format(self) -> None:
        record = self.records("trace", "ok")
        expected = f"{(1 << 63) | 17},0,1,2,3,4\ndone\n".encode()
        self.assertEqual(record["ret"], len(expected))
        self.assertEqual(bytes.fromhex(record["output_hex"]), expected)
        self.assertFalse(record["unfinished"])
        self.assertTrue(record["tc_ready"])
        self.assertTrue(record["inputs_ready"])
        self.assertEqual(record["events"], "MPOBCDAIEUFFSHQ")

    def test_setup_error_stays_negative_without_changing_legacy_cleanup(self) -> None:
        # Characterization of the remaining risk, NOT capture-qualified restoration:
        # faulty restore is still called before its setter. No PTE values are modeled.
        for status in ("ok", "io"):
            with self.subTest(status=status):
                record = self.records("trace", status, setup_error=True)
                self.assertEqual(record["ret"], -errno.EIO)
                self.assertEqual(record["repeat"], -errno.EIO)
                self.assertEqual(record["events"], "MPOBFSHQ")
                self.assertTrue(record["unfinished"])
