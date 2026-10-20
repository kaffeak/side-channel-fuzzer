"""Host-only timer protocol/control-flow checks, never timer measurements.

Retains the original 13 temporary synthetic checks. Only a temporary C copy has
its register reads/barrier replaced; the repository C source is never changed.
This tests actual argument parsing, fork/wait, failure reporting and formatting,
but cannot establish hardware access, instruction ordering or timing accuracy.
Run: python -m unittest tests.unit_arm64_timer_calibration -v
Requires Linux and a native C11 compiler; no ARM64 CPU or kernel module required.
"""

import copy
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.verify_arm64_timer import (CounterProbeTrapped, VerificationError,
                                      main, validate_output)


ROOT = Path(__file__).resolve().parents[1]
SERIES = ("adjacent_reads", "empty_window", "owned_buffer")


def encoded(records):
    return ("\n".join(json.dumps(record) for record in records) + "\n").encode("utf-8")


def valid_records():
    """Independent protocol fixture; tick magnitudes exceed binary64 precision."""
    records = [{
        "kind": "metadata", "schema_version": 1, "counter": "CNTVCT_EL0",
        "frequency_register": "CNTFRQ_EL0", "reported_frequency_hz": 24000000,
        "frequency_probe_exit": 0, "frequency_probe_signal": 0,
        "page_size_bytes": 16384, "selected_cpu": 2, "cpu_start": 2, "cpu_end": 2,
        "samples_per_series": 32, "loads_per_window": 2, "buffer_bytes": 512,
        "checksum": "2176", "kernel_release": "synthetic-only", "machine": "aarch64",
        "initial_allowed_cpus": [2, 5],
    }]
    tick = 2**60
    for series in SERIES:
        for index in range(32):
            delta = index % 3
            records.append({"kind": "sample", "series": series, "index": index,
                            "start_ticks": str(tick), "end_ticks": str(tick + delta),
                            "delta_ticks": str(delta)})
            tick += delta + (0 if series == "adjacent_reads" else 2)
        records.append({"kind": "summary", "series": series, "samples": 32,
                        "zero_deltas": 11, "min_delta_ticks": "0", "max_delta_ticks": "2",
                        "min_positive_observed_delta_ticks": "1"})
    records.append({"kind": "complete", "status": "ok", "samples_emitted": 96})
    return records


class TimerOutputVerificationTest(unittest.TestCase):
    def setUp(self):
        self.records = valid_records()

    def check_invalid(self, records=None, returncode=0):
        with self.assertRaises(VerificationError):
            validate_output(encoded(self.records if records is None else records), returncode)

    def test_exact_success_counts_order_and_wide_tick_values(self):
        self.assertEqual(len(self.records), 101)
        self.assertEqual(validate_output(encoded(self.records), 0), self.records[0])

    def test_null_frequency_after_failed_or_zero_frequency_probe(self):
        for exitcode, sig in ((128 + signal.SIGILL, signal.SIGILL), (10, 0), (0, 0)):
            with self.subTest(exitcode=exitcode):
                self.records[0].update(reported_frequency_hz=None,
                                       frequency_probe_exit=exitcode, frequency_probe_signal=sig)
                metadata = validate_output(encoded(self.records), 0)
                self.assertIsNone(metadata["reported_frequency_hz"])

    def test_rejects_malformed_duplicate_nonfinite_and_incomplete_jsonl(self):
        good = encoded(self.records)
        for data in (b"", b"not json\n", b"{}\n\n", good[:-1], b"[]\n", b"\xff\n",
                     good.replace(b'"kind": "metadata"', b'"kind":"metadata","kind":"metadata"'),
                     good.replace(b"24000000", b"NaN"), b"x" * (128 * 1024 + 1)):
            with self.subTest(data=data[:50]), self.assertRaises(VerificationError):
                validate_output(data, 0)

    def test_rejects_missing_extra_and_reordered_records(self):
        for records in (self.records[:-1], self.records + [self.records[-1]],
                        self.records[1:], list(reversed(self.records))):
            self.check_invalid(records)

    def test_rejects_wrong_series_indices_and_deltas(self):
        for key, value in (("series", "unknown"), ("index", 1), ("index", True),
                           ("start_ticks", "-1"), ("end_ticks", str(2**64)),
                           ("delta_ticks", "9"), ("delta_ticks", 0)):
            with self.subTest(key=key, value=value):
                records = copy.deepcopy(self.records)
                records[1][key] = value
                self.check_invalid(records)

    def test_rejects_wrong_summary_values_and_series(self):
        for key, value in (("series", "owned_buffer"), ("samples", 31), ("zero_deltas", 12),
                           ("min_delta_ticks", "1"), ("max_delta_ticks", "3"),
                           ("min_positive_observed_delta_ticks", None)):
            with self.subTest(key=key):
                records = copy.deepcopy(self.records)
                records[33][key] = value
                self.check_invalid(records)

    def test_accepts_one_zero_only_series_but_not_an_entire_nonadvancing_run(self):
        # Empty windows can quantize to zero even when the overall counter advances.
        for record in self.records:
            if record.get("series") == "empty_window":
                if record["kind"] == "sample":
                    record["end_ticks"] = record["start_ticks"]
                    record["delta_ticks"] = "0"
                else:
                    record.update(zero_deltas=32, min_delta_ticks="0", max_delta_ticks="0",
                                  min_positive_observed_delta_ticks=None)
        validate_output(encoded(self.records), 0)
        for record in self.records:
            if record["kind"] == "sample":
                record.update(start_ticks="7", end_ticks="7", delta_ticks="0")
            elif record["kind"] == "summary":
                record.update(zero_deltas=32, min_delta_ticks="0", max_delta_ticks="0",
                              min_positive_observed_delta_ticks=None)
        self.check_invalid()

    def test_rejects_invalid_metadata_and_completion(self):
        for key, value in (("schema_version", 2), ("schema_version", True),
                           ("counter", "alternate_clock"), ("samples_per_series", 31),
                           ("loads_per_window", 1), ("cpu_end", 5), ("checksum", "0"),
                           ("page_size_bytes", 0), ("reported_frequency_hz", 0),
                           ("initial_allowed_cpus", [5]), ("frequency_probe_signal", 4)):
            with self.subTest(key=key):
                records = copy.deepcopy(self.records)
                records[0][key] = value
                self.check_invalid(records)
        self.records[-1]["samples_emitted"] = 95
        self.check_invalid()

    def test_nonzero_exit_cannot_be_disguised_by_complete_output(self):
        self.check_invalid(returncode=1)

    def test_counter_probe_signal_is_explicit_unsuccessful_environment_candidate(self):
        for sig in (signal.SIGILL, signal.SIGSEGV):
            error = {"kind": "error", "status": "error", "stage": "counter_probe",
                     "errno": 0, "signal": sig, "worker_exit": 128 + sig}
            with self.subTest(sig=sig), self.assertRaises(CounterProbeTrapped):
                validate_output(encoded([error]), 1)
        # A signal elsewhere must not be excused as unavailable counter access.
        error["stage"] = "owned_buffer"
        with self.assertRaises(VerificationError) as caught:
            validate_output(encoded([error]), 1)
        self.assertNotIsInstance(caught.exception, CounterProbeTrapped)

    def test_driver_uses_bounded_workload_and_propagates_errors(self):
        with tempfile.TemporaryDirectory(prefix="rvzr-timer-driver-") as directory:
            output = Path(directory) / "raw.jsonl"
            error = encoded([{"kind": "error", "status": "error", "stage": "counter_probe",
                              "errno": 0, "signal": 4, "worker_exit": 132}])
            for code, stdout, expected in ((0, encoded(self.records), 0), (1, error, 3),
                                           (1, encoded(self.records), 1)):
                arguments = ["verify", "/unused/synthetic", "--output", str(output)]
                with self.subTest(expected=expected), \
                        patch("sys.argv", arguments), \
                        patch("tools.verify_arm64_timer.subprocess.run") as run, \
                        patch("sys.stdout", new_callable=io.StringIO), \
                        patch("sys.stderr", new_callable=io.StringIO):
                    run.return_value = subprocess.CompletedProcess(
                        [], code, stdout, b"diagnostic")
                    self.assertEqual(main(), expected)
                    self.assertEqual(run.call_args.args[0],
                                     ["/unused/synthetic", "--samples", "32", "--loads", "2"])
                    self.assertEqual(run.call_args.kwargs["timeout"], 15)
                    self.assertEqual(output.read_bytes(), stdout)
                    self.assertEqual(output.with_suffix(".stderr").read_bytes(), b"diagnostic")

    def test_driver_timeout_and_launch_failure_are_failures(self):
        for error in (subprocess.TimeoutExpired("synthetic", 15), OSError("launch failed")):
            with self.subTest(error=error), \
                    patch("sys.argv", ["verify", "/unused/synthetic", "--output", "/unused/raw"]), \
                    patch("tools.verify_arm64_timer.subprocess.run", side_effect=error), \
                    patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(main(), 1)


@unittest.skipUnless(sys.platform.startswith("linux"), "C control-flow fixture requires Linux")
class TimerSyntheticControlFlowTest(unittest.TestCase):
    """The original 13 checks, applied to real C control flow with fake reads only."""

    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("Timer host tests require a native C11 compiler (CC or cc)")
        temporary = tempfile.TemporaryDirectory(prefix="rvzr-timer-synthetic-")
        cls.addClassCleanup(temporary.cleanup)
        cls.source = ROOT / "tools" / "arm64_timer_calibration.c"
        cls.original = cls.source.read_bytes()
        text = cls.original.decode("utf-8")

        def replace_once(old, new):
            nonlocal text
            if text.count(old) != 1:
                raise RuntimeError(f"Fixture needs review: expected one occurrence of {old!r}")
            text = text.replace(old, new)

        replace_once('#if !defined(__linux__) || !defined(__aarch64__)',
                     '#if !defined(__linux__)')
        replace_once('#include <errno.h>', '#include <errno.h>\n#include <signal.h>')
        replacement = '''static inline uint64_t read_counter(void)
{
    static uint64_t tick;
    const char *mode = getenv("RVZR_TIMER_TEST_MODE");
    if (mode && strcmp(mode, "counter_signal") == 0) raise(SIGILL);
    if (mode && strcmp(mode, "constant") == 0) return 7;
    if (mode && strcmp(mode, "backwards") == 0) return 100 - ++tick;
    return ++tick;
}'''
        matches = re.findall(r'static inline uint64_t read_counter\(void\)\n\{.*?\n\}',
                             text, flags=re.DOTALL)
        if len(matches) != 1:
            raise RuntimeError("Fixture needs review: changed counter helper")
        replace_once(matches[0], replacement)
        replace_once('__asm__ volatile("dsb ish" : : : "memory");', '(void)0;')
        replace_once('''__asm__ volatile("isb\\n\\tmrs %0, cntfrq_el0\\n\\tisb"
                             : "=r"(result->frequency) : : "memory");''', '''
            const char *mode = getenv("RVZR_TIMER_TEST_MODE");
            if (mode && strcmp(mode, "frequency_signal") == 0) raise(SIGILL);
            result->frequency = mode && strcmp(mode, "zero_frequency") == 0 ? 0 : 24000000;''')
        if "__asm__" in text or "cntvct_el0" in text or "cntfrq_el0" in text:
            raise RuntimeError("Fixture must contain no architectural register instructions")
        fixture = Path(temporary.name) / "synthetic-only.c"
        fixture.write_text(text, encoding="utf-8")
        cls.binary = Path(temporary.name) / "synthetic-only"
        result = subprocess.run(compiler + ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                                            str(fixture), "-o", str(cls.binary)],
                                capture_output=True, text=True, check=False, timeout=30)
        if result.returncode:
            raise RuntimeError(f"Synthetic fixture compilation failed: {result.stderr}")

    @classmethod
    def tearDownClass(cls):
        if cls.source.read_bytes() != cls.original:
            raise RuntimeError("Tests must not change the repository timer source")

    def run_fixture(self, *arguments, mode=""):
        return subprocess.run([str(self.binary), *arguments], capture_output=True, check=False,
                              env={**os.environ, "RVZR_TIMER_TEST_MODE": mode}, timeout=10)

    def success(self, *, mode="", samples=4, loads=2):
        result = self.run_fixture("--samples", str(samples), "--loads", str(loads), mode=mode)
        metadata = validate_output(result.stdout, result.returncode, samples=samples, loads=loads)
        return result, metadata

    def invalid_arguments(self, *arguments):
        result = self.run_fixture(*arguments)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Usage:", result.stderr)

    def test_success_output_and_default_allowed_cpu(self):
        result, metadata = self.success()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(metadata["checksum"], "2092")
        self.assertEqual(metadata["selected_cpu"], min(os.sched_getaffinity(0)))

    def test_frequency_signal_does_not_fabricate_frequency(self):
        _, metadata = self.success(mode="frequency_signal")
        self.assertIsNone(metadata["reported_frequency_hz"])
        self.assertEqual(metadata["frequency_probe_signal"], signal.SIGILL)

    def test_zero_frequency_is_null(self):
        _, metadata = self.success(mode="zero_frequency")
        self.assertIsNone(metadata["reported_frequency_hz"])
        self.assertEqual(metadata["frequency_probe_exit"], 0)

    def test_counter_signal_emits_only_error_and_nonzero_exit(self):
        result = self.run_fixture("--samples", "4", "--loads", "2", mode="counter_signal")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {
            "kind": "error", "status": "error", "stage": "counter_probe",
            "errno": 0, "signal": signal.SIGILL, "worker_exit": 128 + signal.SIGILL})
        self.assertIn(b"Calibration failed", result.stderr)
        with self.assertRaises(CounterProbeTrapped):
            validate_output(result.stdout, result.returncode, samples=4, loads=2)

    def test_backwards_counter_fails(self):
        result = self.run_fixture("--samples", "4", mode="backwards")
        self.assertEqual(result.returncode, 1)
        error = json.loads(result.stdout)
        self.assertEqual((error["stage"], error["worker_exit"]), ("adjacent_reads", 11))
        with self.assertRaises(VerificationError):
            validate_output(result.stdout, result.returncode)

    def test_nonadvancing_counter_fails(self):
        result = self.run_fixture("--samples", "4", mode="constant")
        self.assertEqual(result.returncode, 1)
        error = json.loads(result.stdout)
        self.assertEqual((error["stage"], error["worker_exit"]), ("owned_buffer", 12))
        with self.assertRaises(VerificationError):
            validate_output(result.stdout, result.returncode)

    def test_rejects_zero_samples(self):
        self.invalid_arguments("--samples", "0")

    def test_rejects_excess_samples(self):
        self.invalid_arguments("--samples", "100001")

    def test_rejects_excess_loads(self):
        self.invalid_arguments("--loads", "257")

    def test_rejects_negative_cpu(self):
        self.invalid_arguments("--cpu", "-1")

    def test_rejects_extra_positional_argument(self):
        self.invalid_arguments("extra")

    def test_disallowed_cpu_fails_before_counter_access(self):
        disallowed = next((cpu for cpu in range(1024) if cpu not in os.sched_getaffinity(0)), None)
        if disallowed is None:
            self.skipTest("Every CPU representable by the fixture CPU mask is allowed")
        result = self.run_fixture("--cpu", str(disallowed))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["stage"], "cpu_not_allowed")

    def test_minimum_samples_maximum_loads(self):
        self.success(samples=1, loads=256)

    def test_additional_argument_syntax_and_overflow(self):
        for arguments in (("--samples",), ("--unknown",), ("--samples", "1.0"),
                          ("--samples", "+2"), ("--samples", "1e2"), ("--samples", ""),
                          ("--samples", "99999999999999999999999999999999"), ("--loads", "0")):
            with self.subTest(arguments=arguments):
                self.invalid_arguments(*arguments)

    def test_help_succeeds_without_measurement_records(self):
        result = self.run_fixture("--help", mode="counter_signal")
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"Usage:", result.stdout)
        self.assertEqual(result.stderr, b"")

    def test_output_write_failure_is_nonzero(self):
        # /dev/full deterministically fails writes; this exercises C's real
        # fflush/ferror path rather than substituting an output error handler.
        with open("/dev/full", "wb") as full:
            result = subprocess.run([str(self.binary), "--samples", "1", "--loads", "1"],
                                    env={**os.environ, "RVZR_TIMER_TEST_MODE": ""},
                                    stdout=full, stderr=subprocess.PIPE, check=False, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"write calibration output", result.stderr)


if __name__ == "__main__":
    unittest.main()
