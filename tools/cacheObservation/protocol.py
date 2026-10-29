"""Strict, bounded G3a artifact validation. Protocol validity never attests physical origin."""
# pylint: disable=missing-function-docstring

import hashlib
import json
from pathlib import Path
import re
from typing import Any

VERSION = "g3a-order-v1"
SERIES = ("ordered", "null", "repeat", "overhead")
MAX_BYTES = 4 * 1024 * 1024
U64 = (1 << 64) - 1
TARGET = 0x1122334455667788


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def integer(value: Any, low: int = 0, high: int = U64) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and low <= value <= high,
            "Invalid integer")
    return int(value)


def ticks(value: Any) -> int:
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None,
            "Invalid unsigned decimal string")
    return integer(int(value))


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def _number(value: str) -> None:
    raise ValueError(f"Floats/nonfinite values forbidden: {value}")


def decode(raw: bytes) -> Any:
    require(len(raw) <= MAX_BYTES, "Artifact exceeds 4 MiB")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                      parse_float=_number, parse_constant=_number)


def read_json(path: Path) -> Any:
    with path.open("rb") as file:
        return decode(file.read(MAX_BYTES + 1))


def schedule(seed: int, blocks: int) -> list[int]:
    state = integer(seed, 1, (1 << 32) - 1)
    integer(blocks, 1, 1024)
    result = []
    for _ in range(blocks):
        order = list(range(8))
        for i in range(7, 0, -1):
            state ^= (state << 13) & 0xffffffff
            state ^= state >> 17
            state ^= (state << 5) & 0xffffffff
            j = state % (i + 1)
            order[i], order[j] = order[j], order[i]
        result.extend(order)
    return result


def parameters(config: dict[str, Any]) -> None:
    for key, low, high in (("blocks", 1, 1024), ("seed", 1, 0xffffffff),
                           ("prep_bytes", 16384, 8388608), ("stride", 8, 4096)):
        integer(config[key], low, high)
    require(config["stride"] % 8 == 0 and config["prep_bytes"] % config["stride"] == 0,
            "Invalid preparation dimensions")
    require(6 * config["blocks"] * (config["prep_bytes"] // config["stride"]) <= 33554432,
            "Preparation work bound exceeded")
    require(config["platform"] in ("linux", "macos"), "Unsupported platform")
    require(isinstance(config["session"], str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", config["session"]) is not None,
            "Invalid session identity")
    for key, length in (("commit", 40), ("binary_sha256", 64), ("source_sha256", 64)):
        require(isinstance(config[key], str)
                and re.fullmatch(f"[0-9a-f]{{{length}}}", config[key]) is not None,
                "Invalid source/binary provenance")
    if config["selected_cpu"] is not None:
        integer(config["selected_cpu"], 0, 1023)
        require(config["platform"] == "linux", "macOS CPU pinning is unsupported")


def _frequency(meta: dict[str, Any]) -> None:
    require(isinstance(meta["frequency_timeout"], bool), "Invalid frequency status")
    integer(meta["frequency_exit"], -1, 255)
    integer(meta["frequency_signal"], 0, 127)
    require(meta["frequency_exit"] in (-1, 0, 10)
            or (meta["frequency_signal"] > 0
                and meta["frequency_exit"] == 128 + meta["frequency_signal"]),
            "Contradictory frequency exit")
    if meta["frequency_timeout"]:
        require(meta["frequency_signal"] == 9 and meta["frequency_exit"] == 137,
                "Contradictory frequency timeout")
    if meta["frequency_hz"] is not None:
        require(ticks(meta["frequency_hz"]) > 0 and meta["frequency_exit"] == 0
                and meta["frequency_signal"] == 0 and not meta["frequency_timeout"],
                "Contradictory frequency probe")
    elif meta["frequency_signal"]:
        require(meta["frequency_exit"] == 128 + meta["frequency_signal"],
                "Contradictory frequency signal")


def validate(raw: bytes, returncode: int, expected: dict[str, Any]) -> dict[str, Any]:
    """Use separately captured launch/build metadata, never producer-chosen workload dimensions.

    Failed/partial sessions remain on disk; this rejects them for statistical use.
    Nothing here executes a binary or synthesizes successful physical measurements.
    """
    # One pass keeps checks adjacent to their fields in this fixed schema.
    # pylint: disable=too-many-locals
    require(isinstance(returncode, int) and not isinstance(returncode, bool)
            and returncode == 0, "Nonzero exit/timeout: failed session")
    parameters(expected)
    require(len(raw) <= MAX_BYTES and raw.endswith(b"\n"), "Oversized/truncated JSONL")
    records = [decode(line) for line in raw.splitlines()]
    require(len(records) == expected["blocks"] * 8 + 2
            and all(isinstance(record, dict) for record in records), "Incorrect record count/type")
    meta, footer = records[0], records[-1]
    keys = {"kind", "version", "experiment", "session", "platform", "commit", "binary_sha256",
            "source_sha256", "compiler", "kernel", "machine", "page_size", "blocks", "seed",
            "prep_bytes", "stride", "access_bytes", "selected_cpu", "cpu_start", "cpu_end",
            "frequency_hz", "frequency_exit", "frequency_signal", "frequency_timeout",
            "target_address", "buffer_address"}
    require(set(meta) == keys, "Unknown/missing metadata fields")
    for key in ("session", "platform", "commit", "binary_sha256", "source_sha256", "blocks",
                "seed", "prep_bytes", "stride", "selected_cpu", "page_size", "kernel", "machine",
                "compiler"):
        require(meta[key] == expected[key], f"Metadata/provenance mismatch: {key}")
    require(meta["kind"] == "metadata" and integer(meta["version"]) == 1
            and meta["experiment"] == VERSION and integer(meta["access_bytes"]) == 8,
            "Unsupported experiment")
    parameters(meta)  # Reject booleans that compare equal to integer expectations.
    page = integer(meta["page_size"], 4096, 65536)
    require(page & (page - 1) == 0 and meta["prep_bytes"] % page == 0, "Page/size mismatch")
    for key in ("compiler", "kernel", "machine"):
        require(isinstance(meta[key], str) and 0 < len(meta[key]) <= 512, "Missing environment")
    require(meta["machine"] in (("arm64", "aarch64") if meta["platform"] == "macos"
                                else ("aarch64",)), "Not an AArch64 environment")
    addresses = []
    for key, extent in (("target_address", page), ("buffer_address", meta["prep_bytes"])):
        value = meta[key]
        require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-f]{1,16}", value) is not None,
                "Malformed address")
        address = integer(int(value, 16), page, U64 - extent)
        require(address % page == 0, "Unaligned allocation")
        addresses.append((address, address + extent))
    require(addresses[0][1] <= addresses[1][0] or addresses[1][1] <= addresses[0][0],
            "Overlapping owned regions")
    for key in ("cpu_start", "cpu_end"):
        if meta[key] is not None:
            integer(meta[key], 0, 1048575)
        if meta["platform"] == "macos":
            require(meta[key] is None, "macOS physical CPU identity must remain unknown")
        if meta["selected_cpu"] is not None:
            require(meta[key] == meta["selected_cpu"], "CPU mismatch")
    _frequency(meta)
    require(set(footer) == {"kind", "status", "samples", "stage", "errno", "worker_exit",
                            "signal", "timeout"}, "Unknown/missing completion fields")
    require(footer["kind"] == "complete" and footer["status"] == "ok"
            and integer(footer["samples"]) == expected["blocks"] * 8
            and footer["stage"] == "cleanup" and integer(footer["errno"]) == 0
            and integer(footer["worker_exit"]) == 0 and integer(footer["signal"]) == 0
            and footer["timeout"] is False, "Failed/incomplete session")
    previous = 0
    samples = records[1:-1]
    for index, (row, slot) in enumerate(zip(samples, schedule(meta["seed"], meta["blocks"]))):
        require(set(row) == {"kind", "index", "block", "series", "label", "condition", "status",
                             "start_ticks", "end_ticks", "delta_ticks", "value"},
                "Unknown/missing sample fields")
        condition = "none" if slot // 2 == 3 else (
            "target_before_sweep" if slot == 1 else "target_last")
        require(row["kind"] == "sample" and integer(row["index"]) == index
                and integer(row["block"]) == index // 8 and row["series"] == SERIES[slot // 2]
                and integer(row["label"]) == slot % 2 and row["condition"] == condition
                and row["status"] == "ok", "Incorrect schedule/condition/status")
        start, end, delta = (ticks(row[key]) for key in ("start_ticks", "end_ticks", "delta_ticks"))
        require(previous <= start <= end and end - start == delta, "Counter reversal/arithmetic")
        require(ticks(row["value"]) == (0 if slot // 2 == 3 else TARGET), "Unexpected probe value")
        previous = end
    require(previous > ticks(samples[0]["start_ticks"]), "Counter never advanced")
    return {"metadata": meta, "samples": samples, "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "protocol_valid": True, "physical_origin": "not_attested", "g3_accepted": False}


def load_session(path: Path) -> dict[str, Any]:
    require(not (path / "failure.json").exists(),
            "Session has a recorded capture/provenance failure")
    manifest = read_json(path / "launch.json")
    require(set(manifest) == {"expected", "command", "context", "status", "timeout", "returncode",
                              "raw_sha256", "started_ns", "ended_ns"}, "Unexpected launch fields")
    expected = manifest["expected"]
    require(isinstance(manifest["command"], list) and all(
        isinstance(arg, str) for arg in manifest["command"]), "Malformed launch command")
    require(integer(manifest["ended_ns"]) >= integer(manifest["started_ns"]),
            "Contradictory launch timestamps")
    require(manifest["status"] == "finished" and manifest["timeout"] is False,
            "Launch failed/timed out")
    with (path / "raw.jsonl").open("rb") as file:
        result = validate(file.read(MAX_BYTES + 1), manifest["returncode"], expected)
    require(result["raw_sha256"] == manifest["raw_sha256"], "Raw file changed after capture")
    result["host_label"] = manifest["context"]["host_label"]
    return result
