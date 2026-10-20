"""Run a bounded native timer smoke test and validate its JSONL protocol.

This verifies output consistency, never cache behavior or timer accuracy. No
synthetic counter or alternate clock is used here. Exit 3 specifically reports
a trap during the initial counter probe; it is still a failed smoke test.
"""

import argparse
import json
from pathlib import Path
import re
import signal
import subprocess
import sys


SERIES = ("adjacent_reads", "empty_window", "owned_buffer")
MAX_OUTPUT_BYTES = 128 * 1024
UINT64_MAX = (1 << 64) - 1


class VerificationError(ValueError):
    """Malformed output, failed execution, or inconsistent measurements."""


class CounterProbeTrapped(VerificationError):
    """Initial counter access trapped: potentially an unsupported environment.

    A signal and stage are diagnostics, not proof that the program is defect-free.
    In particular, SIGSEGV may also indicate a memory bug and needs investigation.
    """


def _require(condition, message):
    if not condition:
        raise VerificationError(message)


def _integer(value):
    _require(type(value) is int and 0 <= value <= UINT64_MAX,
             f"Expected unsigned integer, got {value!r}")
    return value


def _ticks(value):
    _require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value),
             f"Expected decimal tick/checksum string, got {value!r}")
    return _integer(int(value))


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _nonfinite(value):
    raise VerificationError(f"Non-JSON number: {value}")

def _reject_float(value):
    raise VerificationError(
        f"Floating-point values are not permitted in the timer protocol: {value}"
    )


def validate_output(stdout, returncode, *, samples=32, loads=2):
    """Validate captured stdout and exit status, returning the metadata record.

    Parameters are expected workload dimensions, not values trusted from output.
    Host tests can pass output from an explicitly synthetic control-flow fixture.
    """
    try:
        _require(len(stdout) <= MAX_OUTPUT_BYTES, "Output exceeds smoke-test limit")
        text = stdout.decode("utf-8")
        _require(text.endswith("\n"), "Missing final JSONL newline")
        records = [
            json.loads(
                line,
                object_pairs_hook=_object,
                parse_float=_reject_float,
                parse_constant=_nonfinite,
            )
            for line in text.splitlines()
        ]
        _require(all(isinstance(record, dict) for record in records),
                 "Each JSONL record must be an object")
        if returncode != 0:
            _require(len(records) == 1, "Failed run must emit only one error record")
            error = records[0]
            _require(error["kind"] == "error" and error["status"] == "error",
                     "Failed run must explicitly report an error")
            for name in ("errno", "signal", "worker_exit"):
                _integer(error[name])
            _require(isinstance(error["stage"], str), "Missing error stage")
            if (returncode == 1 and error["stage"] == "counter_probe"
                    and error["errno"] == 0
                    and error["signal"] in (signal.SIGILL, signal.SIGSEGV)
                    and error["worker_exit"] == 128 + error["signal"]):
                raise CounterProbeTrapped(
                    f"Initial CNTVCT_EL0 probe trapped: {error}; "
                    "possibly unsupported timer access. No calibration succeeded. "
                    "Investigate the environment and signal before attributing the cause.")
            raise VerificationError(f"Calibration failed (exit={returncode}): {error}")

        _require(len(records) == 3 * samples + 5, "Incorrect total record count")
        metadata = records[0]
        for key, expected in (("kind", "metadata"), ("schema_version", 1),
                              ("counter", "CNTVCT_EL0"),
                              ("frequency_register", "CNTFRQ_EL0"),
                              ("samples_per_series", samples),
                              ("loads_per_window", loads), ("buffer_bytes", 512)):
            _require(metadata[key] == expected, f"Incorrect metadata {key}")
            if type(expected) is int:
                _integer(metadata[key])
        for name in ("frequency_probe_exit", "frequency_probe_signal", "page_size_bytes",
                     "selected_cpu", "cpu_start", "cpu_end"):
            _integer(metadata[name])
        _require(metadata["page_size_bytes"] > 0, "Invalid page size")
        for name in ("kernel_release", "machine"):
            _require(isinstance(metadata[name], str) and metadata[name],
                     f"Missing environment metadata: {name}")
        cpus = metadata["initial_allowed_cpus"]
        _require(isinstance(cpus, list) and cpus, "Missing allowed CPU mask")
        for cpu in cpus:
            _integer(cpu)
        _require(cpus == sorted(set(cpus)), "Invalid allowed CPU mask")
        _require(metadata["selected_cpu"] == min(cpus), "Default allowed CPU not selected")
        _require(metadata["cpu_start"] == metadata["selected_cpu"] == metadata["cpu_end"],
                 "CPU changed during calibration")
        frequency = metadata["reported_frequency_hz"]
        if frequency is not None:
            _require(_integer(frequency) > 0, "Non-null frequency must be positive")
            _require(metadata["frequency_probe_exit"] == metadata["frequency_probe_signal"] == 0,
                     "Frequency reported despite failed probe")
        probe_signal = metadata["frequency_probe_signal"]
        if probe_signal:
            _require(metadata["frequency_probe_exit"] == 128 + probe_signal,
                     "Inconsistent frequency-probe exit/signal")
        # The buffer initially contains 1..64; the loop restarts at word zero.
        expected_checksum = 2080 + samples * sum(j % 64 + 1 for j in range(loads))
        _require(_ticks(metadata["checksum"]) == expected_checksum, "Incorrect load checksum")

        cursor, previous_end, first_start = 1, None, None
        for series in SERIES:
            deltas = []
            for index in range(samples):
                record = records[cursor]
                cursor += 1
                _require(record["kind"] == "sample" and record["series"] == series,
                         "Incorrect sample kind or series order")
                _require(_integer(record["index"]) == index, "Noncontinuous sample indices")
                start, end, delta = (_ticks(record[name]) for name in
                                     ("start_ticks", "end_ticks", "delta_ticks"))
                _require(end >= start and delta == end - start, "Incorrect sample delta")
                if first_start is None:
                    first_start = start
                if previous_end is not None:
                    _require(start >= previous_end, "Counter moved backwards between windows")
                    if series == "adjacent_reads":
                        _require(start == previous_end, "Adjacent reads are not contiguous")
                previous_end = end
                deltas.append(delta)
            summary = records[cursor]
            cursor += 1
            _require(summary["kind"] == "summary" and summary["series"] == series,
                     "Incorrect summary kind or series")
            _require(_integer(summary["samples"]) == samples, "Incorrect summary sample count")
            _require(_integer(summary["zero_deltas"]) == deltas.count(0),
                     "Incorrect zero-delta count")
            _require(_ticks(summary["min_delta_ticks"]) == min(deltas)
                     and _ticks(summary["max_delta_ticks"]) == max(deltas),
                     "Incorrect summary extrema")
            positive = [delta for delta in deltas if delta > 0]
            minimum = summary["min_positive_observed_delta_ticks"]
            _require((_ticks(minimum) == min(positive)) if positive else minimum is None,
                     "Incorrect minimum positive observed delta")
        _require(previous_end > first_start, "Counter never advanced")
        complete = records[-1]
        _require(complete["kind"] == "complete" and complete["status"] == "ok"
                 and _integer(complete["samples_emitted"]) == 3 * samples,
                 "Missing or incorrect final completion record")
        return metadata
    except VerificationError:
        raise
    except (UnicodeError, ValueError, KeyError, TypeError, IndexError) as error:
        raise VerificationError(f"Invalid calibration output: {error}") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="Save the small raw stdout file")
    args = parser.parse_args()
    try:
        result = subprocess.run([str(args.binary.resolve()), "--samples", "32", "--loads", "2"],
                                capture_output=True, check=False, timeout=15)
        # Save failures as well as successes; do not replace partial or error output.
        args.output.write_bytes(result.stdout)
        args.output.with_suffix(".stderr").write_bytes(result.stderr)
        metadata = validate_output(result.stdout, result.returncode)
    except CounterProbeTrapped as error:
        print(f"UNSUPPORTED-ENVIRONMENT CANDIDATE: {error}", file=sys.stderr)
        return 3
    except (VerificationError, OSError, subprocess.TimeoutExpired) as error:
        print(f"Timer smoke test FAILED: {error}", file=sys.stderr)
        return 1
    print("Timer smoke test passed: 1 metadata, 96 samples, 3 summaries, 1 complete; "
          f"reported_frequency_hz={metadata['reported_frequency_hz']}. "
          "Timing values apply only to this environment, not Apple M3 compatibility.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
