"""Passive M1-G3-P0 plans, schedules and saved-evidence checks. Never executes native code.

Validation establishes artifact consistency, not physical origin, cache state or G3 acceptance.
"""
# Small schema checks are documented together in README.m1-g3-p0.md.
# pylint: disable=missing-function-docstring
import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

PROTOCOL = "m1-g3-p0-exclusive-v1"
SCHEDULE = "xorshift32-fy6-v1"
EVIDENCE_ROOT = Path("/home/safelab/MasterThesis/output/G3/M1-G3-P0")
MAX_BYTES = 1024 * 1024
MAX_BLOCKS = 64
DEFAULT_BLOCKS = 32
PAGE = 16384
MAX_OWNED = 1024 * 1024
CPU_SECONDS = 2
WALL_SECONDS = 10
KILL_SECONDS = 2
OUTER_SECONDS = 20
U64 = (1 << 64) - 1
INITIAL = 0x1122334455667788
ATTEMPTED = 0x8877665544332211
CANARIES = (0x13579BDF2468ACE0, 0xFEDCBA9876543210)
CONDITIONS = ("adjacent_a", "adjacent_b", "clear_a", "clear_b", "sham_a", "sham_b")
MIDRS = {0: "0x00000000611f0221", 4: "0x00000000611f0231"}
SEEDS = {"calibration": (101, 102), "held_out": (201, 202)}
PLAN_FIELDS = ("schema_version protocol schedule_version run_id session_id cohort_id target_id "
               "evidence_kind phase "
               "cpu seed blocks kernel_release source_commit source_sha256 binary_sha256 "
               "disassembly_sha256 build_manifest_sha256 frozen_calibration_sha256").split()
META_FIELDS = ("kind plan architecture system byte_order page_size kernel_release os_id "
               "os_version os_id_like "
               "compatible midr allowed_cpus affinity_start cpu_start worker_pid target_page "
               "target_address results_base results_bytes owned_bytes").split()
SAMPLE_FIELDS = ("kind index block condition operation stxr_status store_succeeded memory_before "
                 "loaded_value attempted_value memory_after canaries_before canaries_after "
                 "cpu_before cpu_after").split()
COMPLETE_FIELDS = "kind status samples_emitted cpu_end affinity_end worker_pid canaries".split()
EXEC_FIELDS = "returncode timed_out signal worker_pid wall_ns".split()


class VerificationError(ValueError):
    """Keep the original artifacts; rejected evidence must never be silently replaced."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise VerificationError(message)


def integer(value: Any, low: int = 0, high: int = U64) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and low <= value <= high,
            "Invalid integer")
    return int(value)


def fields(value: Any, names: list[str]) -> None:
    require(isinstance(value, dict) and set(value) == set(names), "Unknown or missing fields")


def text(value: Any, maximum: int = 128) -> str:
    require(isinstance(value, str), "Invalid text")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError as error:
        raise VerificationError("Invalid Unicode text") from error
    require(0 < length <= maximum and value.isprintable(),
            "Invalid text")
    return str(value)


def digest(value: Any, size: int = 64) -> None:
    require(isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{size}}}", value) is not None,
            "Invalid provenance digest")


def word(value: Any) -> int:
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None,
            "Invalid uint64 decimal string")
    return integer(int(value))


def address(value: Any, size: int) -> int:
    require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-f]{16}", value) is not None,
            "Invalid address")
    result = int(value, 16)
    require(PAGE <= result <= U64 - size and result % PAGE == 0, "Invalid allocation range")
    return result


def cpus(value: Any) -> list[int]:
    require(isinstance(value, list) and 0 < len(value) <= 1024, "Invalid CPU list")
    result = [integer(cpu, 0, 1023) for cpu in value]
    require(result == sorted(set(result)), "Unordered or duplicate CPU list")
    return result


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise VerificationError(f"Floats/nonfinite numbers forbidden: {value[:32]}")


def decode(raw: bytes, limit: int = MAX_BYTES) -> Any:
    require(isinstance(raw, bytes) and len(raw) <= limit, "Oversized JSON")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                          parse_float=_reject_number, parse_constant=_reject_number)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise VerificationError(f"Invalid JSON: {error}") from error


def read_json(path: Path) -> Any:
    with path.open("rb") as stream:
        return decode(stream.read(4097), 4096)


def validate_plan(plan: dict[str, Any]) -> None:
    fields(plan, PLAN_FIELDS)
    require(integer(plan["schema_version"]) == 1 and plan["protocol"] == PROTOCOL
            and plan["schedule_version"] == SCHEDULE,
            "Unsupported schema/protocol")
    for key in ("run_id", "session_id", "cohort_id", "target_id"):
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", text(plan[key], 64)) is not None,
                "Invalid experiment identity")
    require(plan["evidence_kind"] in ("synthetic", "physical"), "Unknown evidence kind")
    require(isinstance(plan["phase"], str) and plan["phase"] in SEEDS,
            "Invalid calibration/held-out phase")
    require(integer(plan["cpu"]) in MIDRS, "Expected CPU 0 or 4")
    require(integer(plan["seed"]) in SEEDS[plan["phase"]], "Seed/phase mismatch")
    integer(plan["blocks"], 1, MAX_BLOCKS)
    text(plan["kernel_release"])
    digest(plan["source_commit"], 40)
    for key in ("source_sha256", "binary_sha256", "disassembly_sha256", "build_manifest_sha256"):
        digest(plan[key])
    if plan["phase"] == "calibration":
        require(plan["frozen_calibration_sha256"] is None, "Calibration cannot claim a frozen plan")
    else:
        digest(plan["frozen_calibration_sha256"])


def schedule(seed: int, blocks: int = DEFAULT_BLOCKS) -> list[str]:
    """Six labels once per block; versioned unsigned xorshift32 / Fisher-Yates shuffle."""
    state = integer(seed, 1, (1 << 32) - 1)
    integer(blocks, 1, MAX_BLOCKS)
    result = []
    for _ in range(blocks):
        order = list(CONDITIONS)
        for index in range(5, 0, -1):
            state ^= (state << 13) & 0xffffffff
            state ^= state >> 17
            state ^= (state << 5) & 0xffffffff
            swap = state % (index + 1)
            order[index], order[swap] = order[swap], order[index]
        result.extend(order)
    return result


def _canaries(value: Any) -> None:
    require(isinstance(value, list) and len(value) == 2
            and [word(item) for item in value] == list(CANARIES), "Canary mismatch")


def _metadata(meta: dict[str, Any], plan: dict[str, Any], pid: int) -> None:
    fields(meta, META_FIELDS)
    validate_plan(meta["plan"])
    require(meta["kind"] == "metadata" and meta["plan"] == plan, "Launch plan mismatch")
    require(meta["architecture"] == "aarch64" and meta["system"] == "Linux"
            and meta["byte_order"] == "little" and integer(meta["page_size"]) == PAGE,
            "Wrong architecture/platform/pages")
    require(meta["os_id"] == "fedora-asahi-remix" and meta["os_version"] == "45",
            "Wrong target OS")
    for key in ("os_id_like", "compatible"):
        require(isinstance(meta[key], list) and 0 < len(meta[key]) <= 16, "Invalid OS/device list")
        for item in meta[key]:
            text(item)
        require(len(set(meta[key])) == len(meta[key]), "Duplicate OS/device identity")
    require("fedora" in meta["os_id_like"] and "apple,t8103" in meta["compatible"],
            "M1/Fedora identity missing")
    require(text(meta["kernel_release"]) == plan["kernel_release"], "Kernel mismatch")
    cpu = plan["cpu"]
    require(meta["midr"] == MIDRS[cpu] and cpu in cpus(meta["allowed_cpus"]), "CPU/MIDR mismatch")
    require(cpus(meta["affinity_start"]) == [cpu] and integer(meta["cpu_start"]) == cpu,
            "Initial affinity mismatch")
    require(integer(meta["worker_pid"], 1, (1 << 31) - 1) == pid, "Worker identity mismatch")
    result_bytes = ((128 + 6 * plan["blocks"] * 128 + PAGE - 1) // PAGE) * PAGE
    require(integer(meta["results_bytes"]) == result_bytes, "Wrong result allocation")
    target = address(meta["target_page"], PAGE)
    results = address(meta["results_base"], result_bytes)
    require(meta["target_address"] == f"0x{target + PAGE // 2:016x}", "Wrong target address")
    require(target + PAGE <= results or results + result_bytes <= target, "Overlapping buffers")
    integer(meta["owned_bytes"], PAGE + result_bytes + 65536, MAX_OWNED)


def _sample(row: dict[str, Any], index: int, condition: str, cpu: int) -> int:
    fields(row, SAMPLE_FIELDS)
    require(row["kind"] == "sample" and integer(row["index"]) == index
            and integer(row["block"]) == index // 6, "Wrong sample index/block")
    operation = condition.split("_", 1)[0]
    require(row["condition"] == condition and row["operation"] == operation,
            "Wrong condition/operation/order")
    require(integer(row["cpu_before"]) == cpu == integer(row["cpu_after"]), "Sample CPU mismatch")
    status = integer(row["stxr_status"], 0, 1)
    require(isinstance(row["store_succeeded"], bool) and row["store_succeeded"] == (status == 0),
            "Contradictory store-success flag")
    require(word(row["memory_before"]) == INITIAL and word(row["loaded_value"]) == INITIAL
            and word(row["attempted_value"]) == ATTEMPTED, "Wrong public values")
    require(word(row["memory_after"]) == (INITIAL if status else ATTEMPTED),
            "Store status/memory mismatch")
    _canaries(row["canaries_before"])
    _canaries(row["canaries_after"])
    require(operation != "clear" or status == 1, "CLREX control unexpectedly stored")
    return status


def validate_output(raw: bytes, execution: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    """Use independently recorded plan/status. Reject failed evidence, never remove it."""
    # One pass keeps the fixed schema checks alongside their fields.
    # pylint: disable=too-many-locals
    validate_plan(plan)
    fields(execution, EXEC_FIELDS)
    require(isinstance(execution["timed_out"], bool), "Invalid timeout flag")
    require(execution["returncode"] is not None, "Unknown process exit")
    code = integer(execution["returncode"], -127, 255)
    sig = integer(execution["signal"], 0, 127)
    pid = integer(execution["worker_pid"], 1, (1 << 31) - 1)
    wall = integer(execution["wall_ns"], 0, OUTER_SECONDS * 1000000000)
    require(code == 0 and not execution["timed_out"] and sig == 0
            and wall <= WALL_SECONDS * 1000000000, "Failed/signal/timeout execution")
    require(isinstance(raw, bytes) and len(raw) <= MAX_BYTES and raw.endswith(b"\n"),
            "Oversized or truncated JSONL")
    lines = raw.splitlines()
    require(2 <= len(lines) <= 6 * MAX_BLOCKS + 2 and all(0 < len(line) <= 8192 for line in lines),
            "Invalid record count/line size")
    rows = [decode(line) for line in lines]
    require(all(isinstance(row, dict) for row in rows), "Records must be objects")
    _metadata(rows[0], plan, pid)
    if rows[-1].get("kind") == "error":
        error = rows[-1]
        fields(error, "kind stage message errno signal samples_emitted".split())
        text(error["stage"], 64)
        text(error["message"], 256)
        integer(error["errno"], 0, 4095)
        integer(error["signal"], 0, 127)
        require(integer(error["samples_emitted"]) == len(rows) - 2, "Wrong failed prefix count")
        raise VerificationError("Reported worker error; preserve the unsuccessful session")
    order = schedule(plan["seed"], plan["blocks"])
    require(len(rows) == len(order) + 2, "Incomplete or extra records")
    counts = {condition: {"successes": 0, "failures": 0} for condition in CONDITIONS}
    for index, (row, condition) in enumerate(zip(rows[1:-1], order)):
        status = _sample(row, index, condition, plan["cpu"])
        counts[condition]["failures" if status else "successes"] += 1
    end = rows[-1]
    fields(end, COMPLETE_FIELDS)
    require(end["kind"] == "complete" and end["status"] == "ok"
            and integer(end["samples_emitted"]) == len(order), "Missing complete record")
    require(integer(end["cpu_end"]) == plan["cpu"] and cpus(end["affinity_end"]) == [plan["cpu"]]
            and integer(end["worker_pid"]) == pid, "Final CPU/affinity/worker mismatch")
    _canaries(end["canaries"])
    baseline = sum(counts[c]["successes"] for c in CONDITIONS if c.startswith("adjacent"))
    sham = sum(counts[c]["successes"] for c in CONDITIONS if c.startswith("sham"))
    return {"plan": plan.copy(), "counts": counts,
            "architectural_assessment": "CONTROLS_OBSERVED_REVIEW_REQUIRED" if baseline and sham
            else "INCONCLUSIVE_NO_BASELINE_SUCCESS" if not baseline else "INCONCLUSIVE_SHAM",
            "environment": {key: rows[0][key]
                            for key in ("compatible", "midr", "os_id", "os_version")},
            "physical_execution_attested": False, "g3_accepted": False}


def validate_cohort(sessions: list[tuple[bytes, dict[str, Any], dict[str, Any]]], *,
                    phase: str, cpu: int) -> list[dict[str, Any]]:
    """Check two planned launch identities per phase/core; cannot attest independence."""
    require(isinstance(phase, str) and phase in SEEDS and integer(cpu) in MIDRS
            and isinstance(sessions, list) and len(sessions) == 2, "Wrong cohort")
    require(all(isinstance(item, (tuple, list)) and len(item) == 3 for item in sessions),
            "Invalid cohort records")
    reports = [validate_output(raw, execution, plan) for raw, execution, plan in sessions]
    plans = [report["plan"] for report in reports]
    require(all(plan["phase"] == phase and plan["cpu"] == cpu for plan in plans),
            "Mixed phase/core")
    for key in ("run_id", "session_id", "seed"):
        require(len({plan[key] for plan in plans}) == 2, "Duplicate launch/session/seed")
    shared = set(PLAN_FIELDS) - {"run_id", "session_id", "seed"}
    require(all(all(plan[key] == plans[0][key] for key in shared) for plan in plans),
            "Cohort provenance/frozen-plan mismatch")
    require(reports[0]["environment"] == reports[1]["environment"], "Cohort device mismatch")
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    scheduling = modes.add_parser("schedule",
                                  help="Print a deterministic plan; no native execution")
    scheduling.add_argument("--seed", type=int, required=True)
    scheduling.add_argument("--blocks", type=int, default=DEFAULT_BLOCKS)
    validating = modes.add_parser("validate", help="Validate saved files only")
    for name in ("raw", "execution", "plan"):
        validating.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.mode == "schedule":
            result = {"schedule_version": SCHEDULE, "seed": args.seed, "blocks": args.blocks,
                      "conditions": schedule(args.seed, args.blocks)}
        else:
            with args.raw.open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            result = validate_output(raw, read_json(args.execution), read_json(args.plan))
        print(json.dumps(result, allow_nan=False, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"NOT VALIDATED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
