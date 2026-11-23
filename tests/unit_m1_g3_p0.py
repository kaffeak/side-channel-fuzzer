"""Synthetic exclusive-reservation evidence only; no native instructions or counters execute."""
# pylint: disable=missing-function-docstring,missing-class-docstring,too-many-public-methods
import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import m1_g3_p0 as p

A, B = 0x1122334455667788, 0x8877665544332211
CANARIES = [str(0x13579BDF2468ACE0), str(0xFEDCBA9876543210)]


def fixture(cpu=0, phase="calibration", seed=None, session_id="session_a", blocks=2):
    """Numbers and hashes below are invented fixtures, never physical evidence."""
    plan = {"schema_version": 1, "protocol": "m1-g3-p0-exclusive-v1",
            "schedule_version": "xorshift32-fy6-v1", "run_id": "run_" + session_id,
            "session_id": session_id, "cohort_id": "synthetic_cohort", "target_id": "synthetic_m1",
            "evidence_kind": "synthetic", "phase": phase, "cpu": cpu,
            "seed": seed if seed is not None else 101 if phase == "calibration" else 201,
            "blocks": blocks, "kernel_release": "synthetic-kernel+16k", "source_commit": "a" * 40,
            "source_sha256": "b" * 64, "binary_sha256": "c" * 64,
            "disassembly_sha256": "d" * 64, "build_manifest_sha256": "e" * 64,
            "frozen_calibration_sha256": None if phase == "calibration" else "f" * 64}
    result_bytes = ((128 + 6 * blocks * 128 + 16383) // 16384) * 16384
    meta = {"kind": "metadata", "plan": deepcopy(plan), "architecture": "aarch64",
            "system": "Linux", "kernel_release": "synthetic-kernel+16k",
            "byte_order": "little", "page_size": 16384, "os_id": "fedora-asahi-remix",
            "os_version": "45", "os_id_like": ["fedora"],
            "compatible": ["apple,j293", "apple,t8103"],
            "midr": "0x00000000611f0221" if cpu == 0 else "0x00000000611f0231",
            "allowed_cpus": list(range(8)), "affinity_start": [cpu], "cpu_start": cpu,
            "worker_pid": 123, "target_page": "0x0000000000100000",
            "target_address": "0x0000000000102000", "results_base": "0x0000000000200000",
            "results_bytes": result_bytes, "owned_bytes": 16384 + result_bytes + 65536}
    rows = [meta]
    for index, condition in enumerate(p.schedule(plan["seed"], blocks)):
        operation = condition.split("_", 1)[0]
        status = int(operation == "clear")
        rows.append({"kind": "sample", "index": index, "block": index // 6,
                     "condition": condition, "operation": operation, "stxr_status": status,
                     "store_succeeded": status == 0, "memory_before": str(A),
                     "loaded_value": str(A),
                     "attempted_value": str(B), "memory_after": str(A if status else B),
                     "canaries_before": CANARIES.copy(), "canaries_after": CANARIES.copy(),
                     "cpu_before": cpu, "cpu_after": cpu})
    rows.append({"kind": "complete", "status": "ok", "samples_emitted": 6 * blocks,
                 "cpu_end": cpu, "affinity_end": [cpu], "worker_pid": 123,
                 "canaries": CANARIES.copy()})
    execution = {"returncode": 0, "timed_out": False, "signal": 0, "worker_pid": 123,
                 "wall_ns": 1000000}
    return rows, execution, plan


def encoded(rows):
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()


def session(**kwargs):
    rows, execution, plan = fixture(**kwargs)
    return encoded(rows), execution, plan


class ExclusiveReservationProtocolTest(unittest.TestCase):
    def test_fixed_public_values_and_versioned_schedule_fixture(self):
        self.assertEqual((p.INITIAL, p.ATTEMPTED), (A, B))
        self.assertEqual(p.schedule(1, 1),
                         ["adjacent_a", "sham_b", "clear_a", "adjacent_b", "sham_a", "clear_b"])
        for seed in (101, 102, 201, 202):
            one = p.schedule(seed)
            self.assertEqual(one, p.schedule(seed))
            self.assertEqual(len(one), 192)
            for block in range(32):
                self.assertEqual(sorted(one[6 * block:6 * block + 6]), sorted(p.CONDITIONS))
        self.assertNotEqual(p.schedule(101), p.schedule(102))
        for seed, blocks in ((0, 1), (True, 1), (1, False), (1, 65), (2 ** 32, 1)):
            with self.subTest(seed=seed, blocks=blocks), self.assertRaises(p.VerificationError):
                p.schedule(seed, blocks)

    def test_both_core_profiles_validate_with_exact_counts(self):
        for cpu in (0, 4):
            with self.subTest(cpu=cpu):
                raw, execution, plan = session(cpu=cpu)
                report = p.validate_output(raw, execution, plan)
                self.assertEqual(report["architectural_assessment"],
                                 "CONTROLS_OBSERVED_REVIEW_REQUIRED")
                for condition in p.CONDITIONS:
                    self.assertEqual(report["counts"][condition],
                                     {"successes": 0 if condition.startswith("clear") else 2,
                                      "failures": 2 if condition.startswith("clear") else 0})
                self.assertFalse(report["physical_execution_attested"])
                self.assertFalse(report["g3_accepted"])

    def test_spurious_adjacent_failure_is_retained_and_not_an_execution_error(self):
        rows, execution, plan = fixture()
        row = next(row for row in rows if row.get("condition") == "adjacent_a")
        row.update(stxr_status=1, store_succeeded=False, memory_after=str(A))
        report = p.validate_output(encoded(rows), execution, plan)
        self.assertEqual(report["counts"]["adjacent_a"], {"successes": 1, "failures": 1})
        self.assertFalse(report["g3_accepted"])

    def test_no_baseline_success_and_no_sham_success_are_inconclusive(self):
        for operation, outcome in (("adjacent", "INCONCLUSIVE_NO_BASELINE_SUCCESS"),
                                   ("sham", "INCONCLUSIVE_SHAM")):
            rows, execution, plan = fixture()
            for row in rows:
                if row.get("operation") == operation:
                    row.update(stxr_status=1, store_succeeded=False, memory_after=str(A))
            self.assertEqual(p.validate_output(encoded(rows), execution, plan)[
                "architectural_assessment"], outcome)

    def test_clear_success_is_rejected_even_when_its_reported_memory_agrees(self):
        rows, execution, plan = fixture()
        row = next(row for row in rows if row.get("operation") == "clear")
        row.update(stxr_status=0, store_succeeded=True, memory_after=str(B))
        with self.assertRaisesRegex(p.VerificationError, "CLREX"):
            p.validate_output(encoded(rows), execution, plan)

    def test_illegal_store_statuses_and_success_flag_types(self):
        for field, value in (("stxr_status", -1), ("stxr_status", 2), ("stxr_status", True),
                             ("stxr_status", "1"), ("stxr_status", 0.0),
                             ("store_succeeded", 1), ("store_succeeded", "true")):
            rows, execution, plan = fixture()
            rows[1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(p.VerificationError):
                p.validate_output(encoded(rows), execution, plan)

    def test_architectural_values_and_status_cannot_contradict(self):
        for field, value in (("memory_before", str(B)), ("loaded_value", str(A + 1)),
                             ("attempted_value", str(A)), ("memory_after", str(0)),
                             ("loaded_value", True), ("loaded_value", str(2 ** 64)),
                             ("loaded_value", "-1"), ("loaded_value", "01")):
            rows, execution, plan = fixture()
            rows[1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(p.VerificationError):
                p.validate_output(encoded(rows), execution, plan)
        rows, execution, plan = fixture()
        rows[1]["store_succeeded"] = not rows[1]["store_succeeded"]
        with self.assertRaisesRegex(p.VerificationError, "Contradictory"):
            p.validate_output(encoded(rows), execution, plan)

    def test_canary_corruption_is_rejected_before_and_after_trials_and_in_footer(self):
        for index, field in ((1, "canaries_before"), (1, "canaries_after"), (-1, "canaries")):
            rows, execution, plan = fixture()
            rows[index][field] = ["0", CANARIES[1]]
            with self.subTest(field=field), self.assertRaisesRegex(p.VerificationError, "Canary"):
                p.validate_output(encoded(rows), execution, plan)

    def test_cpu_affinity_midr_device_and_os_mismatches(self):
        changes = [(0, "midr", "0x00000000611f0231"), (0, "allowed_cpus", [4]),
                   (0, "affinity_start", [0, 4]), (0, "affinity_start", [0, 0]),
                   (0, "cpu_start", False), (0, "architecture", "x86_64"),
                   (0, "system", "Darwin"), (0, "page_size", 4096),
                   (0, "kernel_release", "wrong-kernel"),
                   (0, "os_id", "fedora"), (0, "os_version", "44"),
                   (0, "compatible", ["apple,t8103-other"]), (0, "os_id_like", []),
                   (1, "cpu_before", 4), (1, "cpu_after", 4),
                   (-1, "cpu_end", 4), (-1, "affinity_end", [0, 4])]
        for index, key, value in changes:
            rows, execution, plan = fixture()
            rows[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(p.VerificationError):
                p.validate_output(encoded(rows), execution, plan)

    def test_worker_identity_and_allocation_ranges(self):
        for index, key, value in ((0, "worker_pid", 124), (-1, "worker_pid", 124),
                                  (0, "target_page", "0x0000000000000000"),
                                  (0, "target_address", "0x0000000000102008"),
                                  (0, "results_base", "0x0000000000100000"),
                                  (0, "results_base", "0xffffffffffffc000"),
                                  (0, "results_bytes", True), (0, "results_bytes", 32768),
                                  (0, "owned_bytes", 2 ** 20 + 1)):
            rows, execution, plan = fixture()
            rows[index][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(p.VerificationError):
                p.validate_output(encoded(rows), execution, plan)

    def test_schedule_indices_blocks_labels_and_operations_are_exact(self):
        for key, value in (("index", 1), ("index", False), ("block", 1),
                           ("condition", "cache_hit"), ("operation", "sweep")):
            rows, execution, plan = fixture()
            rows[1][key] = value
            with self.subTest(key=key), self.assertRaises(p.VerificationError):
                p.validate_output(encoded(rows), execution, plan)
        rows, execution, plan = fixture()
        rows[1], rows[2] = rows[2], rows[1]
        with self.assertRaises(p.VerificationError):
            p.validate_output(encoded(rows), execution, plan)

    def test_duplicate_missing_extra_or_incomplete_records(self):
        original, execution, plan = fixture()
        cases = [original[:-1], original + [original[-1]],
                 [original[0], original[1], original[1], *original[3:]],
                 original[:1] + original[2:], original + [original[0]]]
        for rows in cases:
            with self.subTest(count=len(rows)), self.assertRaises(p.VerificationError):
                p.validate_output(encoded(rows), execution, plan)
        with self.assertRaises(p.VerificationError):
            p.validate_output(encoded(original).rstrip(), execution, plan)

    def test_duplicate_keys_unknown_fields_invalid_json_and_numbers(self):
        rows, execution, plan = fixture()
        raw = encoded(rows)
        candidates = [raw.replace(b'"kind": "metadata"', b'"kind":"metadata","kind":"metadata"'),
                      b'not-json\n', b'\xff\n', raw + b'\n', b'[]\n{}\n',
                      raw.replace(b'"stxr_status": 0', b'"stxr_status": NaN'),
                      raw.replace(b'"stxr_status": 0', b'"stxr_status": Infinity'),
                      b'[' * 1500 + b']' * 1500 + b'\n{}\n']
        for index, candidate in enumerate(candidates):
            with self.subTest(index=index), self.assertRaises(p.VerificationError):
                p.validate_output(candidate, execution, plan)
        for index in (0, 1, -1):
            changed = deepcopy(rows)
            changed[index]["extra"] = 1
            with self.assertRaisesRegex(p.VerificationError, "fields"):
                p.validate_output(encoded(changed), execution, plan)
        for index, key in ((0, "midr"), (1, "stxr_status"), (-1, "samples_emitted")):
            changed = deepcopy(rows)
            del changed[index][key]
            with self.assertRaises(p.VerificationError):
                p.validate_output(encoded(changed), execution, plan)

    def test_failed_unknown_signalled_and_timed_out_executions_never_validate(self):
        raw, execution, plan = session()
        for change in ({"returncode": 1}, {"returncode": None},
                       {"returncode": -4, "signal": 4}, {"timed_out": True},
                       {"wall_ns": 10000000001}, {"returncode": False},
                       {"timed_out": 0}, {"signal": True}, {"worker_pid": None}):
            with self.subTest(change=change), self.assertRaises(p.VerificationError):
                p.validate_output(raw, {**execution, **change}, plan)
        with self.assertRaises(p.VerificationError):
            p.validate_output(b'', {**execution, "returncode": 1}, plan)

    def test_reported_error_is_preserved_and_rejected(self):
        rows, execution, plan = fixture()
        rows = rows[:3] + [{"kind": "error", "stage": "setup", "message": "synthetic failure",
                           "errno": 12, "signal": 0, "samples_emitted": 2}]
        raw = encoded(rows)
        with self.assertRaisesRegex(p.VerificationError, "worker error"):
            p.validate_output(raw, execution, plan)
        self.assertEqual(raw, encoded(rows))

    def test_protocol_limits_and_fixed_profile(self):
        raw, execution, plan = session(blocks=64)
        self.assertLess(len(raw), p.MAX_BYTES)
        report = p.validate_output(raw, execution, plan)
        self.assertEqual(sum(sum(count.values()) for count in report["counts"].values()), 384)
        for key, value in (("schema_version", True), ("schema_version", 2), ("blocks", 65),
                           ("protocol", "unknown"), ("schedule_version", "unknown"),
                           ("source_sha256", "x" * 64), ("cpu", 1), ("run_id", "../escape"),
                           ("phase", []), ("seed", True), ("evidence_kind", "verified_cache"),
                           ("kernel_release", "\ud800"), ("kernel_release", "bad\nrelease")):
            with self.subTest(key=key), self.assertRaises(p.VerificationError):
                p.validate_plan({**plan, key: value})
        for candidate in (b'x' * (p.MAX_BYTES + 1), b' ' * 8193 + b'\n{}\n'):
            with self.assertRaises(p.VerificationError):
                p.validate_output(candidate, execution, plan)

    def test_producer_cannot_change_expected_identity_phase_or_evidence_kind(self):
        for key, value in (("run_id", "new_run"), ("source_sha256", "1" * 64),
                           ("evidence_kind", "physical")):
            rows, execution, plan = fixture()
            rows[0]["plan"][key] = value
            with self.subTest(key=key), self.assertRaises(p.VerificationError):
                p.validate_output(encoded(rows), execution, plan)
        rows, execution, plan = fixture()
        rows[0]["plan"].update(phase="held_out", seed=201, frozen_calibration_sha256="f" * 64)
        with self.assertRaises(p.VerificationError):
            p.validate_output(encoded(rows), execution, plan)

    def test_phase_seeds_and_frozen_calibration_reference(self):
        _, _, calibration = fixture()
        _, _, held = fixture(phase="held_out")
        p.validate_plan(held)
        for plan in ({**calibration, "frozen_calibration_sha256": "f" * 64},
                     {**held, "frozen_calibration_sha256": None}, {**held, "seed": 101},
                     {**calibration, "seed": 201}):
            with self.assertRaises(p.VerificationError):
                p.validate_plan(plan)

    def test_two_launch_cohort_validation_does_not_pool_phases_or_cores(self):
        for cpu in (0, 4):
            for phase, seeds in (("calibration", (101, 102)), ("held_out", (201, 202))):
                sessions = [session(cpu=cpu, phase=phase, seed=seed, session_id=f"launch_{seed}")
                            for seed in seeds]
                self.assertEqual(len(p.validate_cohort(sessions, phase=phase, cpu=cpu)), 2)
        calibration = session(seed=101, session_id="first")
        for other in (session(cpu=4, seed=102, session_id="second"),
                      session(phase="held_out", seed=201, session_id="second"), calibration):
            with self.assertRaises(p.VerificationError):
                p.validate_cohort([calibration, other], phase="calibration", cpu=0)

    def test_cohort_provenance_and_frozen_reference_must_match(self):
        first = session(phase="held_out", seed=201, session_id="first")
        for key in ("frozen_calibration_sha256", "binary_sha256", "cohort_id", "target_id"):
            rows, execution, plan = fixture(phase="held_out", seed=202, session_id="second")
            value = "2" * 64 if key.endswith("sha256") else "different"
            plan[key] = rows[0]["plan"][key] = value
            with self.subTest(key=key), self.assertRaises(p.VerificationError):
                p.validate_cohort([first, (encoded(rows), execution, plan)],
                                  phase="held_out", cpu=0)

    def test_physical_label_is_not_physical_attestation_or_g3_acceptance(self):
        rows, execution, plan = fixture()
        plan["evidence_kind"] = rows[0]["plan"]["evidence_kind"] = "physical"
        report = p.validate_output(encoded(rows), execution, plan)
        self.assertFalse(report["physical_execution_attested"])
        self.assertFalse(report["g3_accepted"])

    def test_saved_file_cli_never_changes_raw_evidence_and_rejects_large_plans(self):
        raw, execution, plan = session()
        with tempfile.TemporaryDirectory(prefix="g3-p0-synthetic-") as temporary:
            root = Path(temporary)
            (root / "raw.jsonl").write_bytes(raw)
            for name, value in (("plan", plan), ("execution", execution)):
                (root / (name + ".json")).write_text(json.dumps(value))
            args = ["p0", "validate", "--raw", str(root / "raw.jsonl"), "--execution",
                    str(root / "execution.json"), "--plan", str(root / "plan.json")]
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(p.main(), 0)
            self.assertFalse(json.loads(output.getvalue())["g3_accepted"])
            self.assertEqual((root / "raw.jsonl").read_bytes(), raw)
            (root / "plan.json").write_bytes(b'x' * 4097)
            with patch("sys.argv", args), contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(p.main(), 1)
            self.assertIn("NOT VALIDATED", error.getvalue())
            self.assertEqual((root / "raw.jsonl").read_bytes(), raw)

    def test_schedule_cli_only_emits_the_recorded_deterministic_order(self):
        with patch("sys.argv", ["p0", "schedule", "--seed", "101", "--blocks", "1"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(p.main(), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result, {"schedule_version": p.SCHEDULE, "seed": 101, "blocks": 1,
                                  "conditions": p.schedule(101, 1)})


if __name__ == "__main__":
    unittest.main()
