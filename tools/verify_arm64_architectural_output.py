"""Offline fixed-fixture G1 output verification; never launches native code.

Checks saved JSONL against a saved raw InputData fragment and independently
recorded kernel/page metadata. Successful file validation is not attestation that
the addresses were live or that physical execution occurred. Standard library only.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from typing import Any


_MAX = (1 << 64) - 1


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _integer(value: Any) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool)
             and 0 <= value <= _MAX, "Expected an unsigned 64-bit integer")
    return int(value)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise ValueError(f"Unsupported JSON number: {value}")


def _validate_addresses(state: dict[str, Any], page_size: int) -> None:
    addresses = []
    for name in ("data_base", "code_base"):
        address = state[name]
        _require(isinstance(address, str) and re.fullmatch(r"0x[0-9a-f]+", address) is not None,
                 "Malformed address")
        value = int(address, 16)
        _require(page_size <= value <= _MAX - 2 * page_size and value % page_size == 0,
                 "Invalid guarded allocation range")
        addresses.append(value)
    _require(abs(addresses[0] - addresses[1]) >= 3 * page_size, "Overlapping guarded allocations")


def validate_output(raw: bytes, returncode: int, input_bytes: bytes, *,
                    kernel_release: str, page_size: int) -> dict[str, Any]:
    """Validate exactly one complete embedded-reference execution, not a family run."""
    _require(isinstance(returncode, int) and not isinstance(returncode, bool)
             and returncode == 0, "Execution did not exit zero")
    _require(_integer(page_size) in (4096, 16384), "Unsupported expected page size")
    _require(bool(kernel_release), "Missing independently recorded kernel release")
    _require(len(input_bytes) == 12288, "Expected one raw 12288-byte input fragment")
    _require(not any(input_bytes[4096:8192] + input_bytes[8200:]),
             "Only main and X0 may be nonzero")
    _require(len(raw) <= 16384 and raw.endswith(b"\n"), "Oversized or incomplete JSONL")
    records = [json.loads(line, object_pairs_hook=_object, parse_float=_reject_number,
                          parse_constant=_reject_number)
               for line in raw.decode("utf-8").splitlines()]
    _require(len(records) == 3 and all(isinstance(row, dict) for row in records),
             "Expected exactly metadata, architectural_state and complete records")
    metadata, state, complete = records
    _require(_integer(metadata["page_size"]) == page_size, "Page metadata mismatch")
    _require(metadata == {
        "kind": "metadata", "fixture": "b34a-fixed-body-v1",
        "input_format": "rvzr-inputdata-raw-v1", "program_source": "embedded-reference",
        "program_format": "rvzr-b34a-body-v1", "architecture": "aarch64",
        "page_size": page_size, "kernel": kernel_release,
    }, "Unexpected metadata or program mode")
    _require(set(state) == {"kind", "status", "input", "selector", "initial_word", "data_base",
                            "code_base", "x0_x7", "nzcv", "sp_mod16", "main_hex"},
             "Unexpected architectural record fields")
    _require(state["kind"] == "architectural_state" and state["status"] == "ok"
             and _integer(state["input"]) == 0, "Invalid architectural record")
    selector, word = struct.unpack_from("<Q", input_bytes, 8192)[0], \
        struct.unpack_from("<Q", input_bytes)[0]
    marker = 22 if selector == 0 else 11
    registers = [selector, marker, word, (word + marker) & _MAX, 0, 0, 0, 0]
    _require((_integer(state["selector"]), _integer(state["initial_word"])) == (selector, word),
             "Input identity mismatch")
    _require(isinstance(state["x0_x7"], list)
             and [_integer(value) for value in state["x0_x7"]] == registers, "Register mismatch")
    flags = 0x60000000 if selector == 0 else (0xa0000000 if selector >> 63 else 0x20000000)
    _require(_integer(state["nzcv"]) == flags and _integer(state["sp_mod16"]) == 0,
             "NZCV or stack-alignment mismatch")
    expected_main = struct.pack("<Q", registers[3]) + input_bytes[8:4096]
    _require(state["main_hex"] == expected_main.hex(), "Full main-memory mismatch")
    _validate_addresses(state, page_size)
    _require(_integer(complete["cases"]) == 1
             and complete == {"kind": "complete", "status": "ok", "cases": 1},
             "Missing successful completion")
    return {"status": "validated", "kernel": kernel_release, "page_size": page_size,
            "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
            "output_sha256": hashlib.sha256(raw).hexdigest(), "x0_x7": registers,
            "nzcv": flags, "records": 3}


def main() -> int:
    """Read bounded saved artifacts; preserve nonzero/timeout exits as failures."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--exit-file", type=Path, required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--page-size", type=int, required=True)
    args = parser.parse_args()
    try:
        with args.output.open("rb") as output, args.input.open("rb") as input_file, \
                args.exit_file.open() as exit_file:
            exit_text = exit_file.read(17)
            _require(len(exit_text) <= 16, "Oversized exit-status file")
            report = validate_output(output.read(16385), int(exit_text),
                                     input_file.read(12289), kernel_release=args.kernel,
                                     page_size=args.page_size)
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        print(json.dumps({"status": "rejected", "reason": str(error)}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
