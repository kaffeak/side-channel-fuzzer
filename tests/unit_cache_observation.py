"""Synthetic G3a protocol/statistics and real C schedule/assembly checks. No timed execution."""
# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.cacheObservation import analyze, disassembly, manage, protocol

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "tools/cacheObservation"


def encoded(rows):
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()


def fixture(session="synthetic-1", seed=1, system="linux", separated=True):
    expected = {"session": session, "platform": system, "commit": "a" * 40,
                "binary_sha256": "b" * 64, "source_sha256": "c" * 64,
                "compiler": "synthetic compiler", "kernel": "synthetic kernel",
                "machine": "aarch64" if system == "linux" else "arm64", "page_size": 16384,
                "blocks": 4, "seed": seed, "prep_bytes": 1048576, "stride": 128,
                "selected_cpu": 2 if system == "linux" else None}
    meta = dict(expected, kind="metadata", version=1, experiment="g3a-order-v1", access_bytes=8,
                cpu_start=2 if system == "linux" else None,
                cpu_end=2 if system == "linux" else None,
                frequency_hz="1000000", frequency_exit=0, frequency_signal=0,
                frequency_timeout=False, target_address="0x100000", buffer_address="0x200000")
    rows = [meta]
    tick = 2 ** 60
    for index, slot in enumerate(protocol.schedule(seed, 4)):
        delta = 8 if separated and slot == 1 else 0
        rows.append({"kind": "sample", "index": index, "block": index // 8,
                     "series": ("ordered", "null", "repeat", "overhead")[slot // 2],
                     "label": slot % 2, "condition": "none" if slot // 2 == 3 else (
                         "target_before_sweep" if slot == 1 else "target_last"),
                     "status": "ok", "start_ticks": str(tick), "end_ticks": str(tick + delta),
                     "delta_ticks": str(delta),
                     "value": "0" if slot // 2 == 3 else "1234605616436508552"})
        tick += delta + 3
    rows.append({"kind": "complete", "status": "ok", "samples": 32, "stage": "cleanup",
                 "errno": 0, "worker_exit": 0, "signal": 0, "timeout": False})
    return expected, rows


def validated(session="synthetic-1", seed=1, separated=True):
    expected, rows = fixture(session, seed, separated=separated)
    result = protocol.validate(encoded(rows), 0, expected)
    result["host_label"] = "synthetic-host"
    return result


class CacheObservationProtocolTest(unittest.TestCase):
    def reject(self, rows, expected, code=0):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            protocol.validate(encoded(rows), code, expected)

    def test_complete_both_platforms_and_no_physical_acceptance(self):
        for system in ("linux", "macos"):
            expected, rows = fixture(system=system)
            result = protocol.validate(encoded(rows), 0, expected)
            self.assertTrue(result["protocol_valid"])
            self.assertFalse(result["g3_accepted"])
            self.assertEqual(result["physical_origin"], "not_attested")
            self.assertEqual(len(result["samples"]), 32)

    def test_zeros_are_retained_and_wide_ticks_are_exact(self):
        result = validated(separated=False)
        self.assertTrue(all(row["delta_ticks"] == "0" for row in result["samples"]))
        stats = analyze.distributions(result)
        self.assertEqual(stats["ordered"]["labels"]["0"]["zero_fraction"],
                         {"numerator": 4, "denominator": 4})
        self.assertEqual(stats["ordered"]["labels"]["0"]["p50"], 0)

    def test_reversal_overflow_and_contradictory_arithmetic(self):
        expected, rows = fixture()
        for key, value in (("start_ticks", "-1"), ("end_ticks", str(1 << 64)),
                           ("delta_ticks", "1"), ("start_ticks", str((1 << 64) - 1)),
                           ("start_ticks", 0), ("start_ticks", "00")):
            changed = copy.deepcopy(rows)
            changed[1][key] = value
            self.reject(changed, expected)

    def test_missing_duplicate_reordered_and_failed_records(self):
        expected, rows = fixture()
        for changed in (rows[:-1], rows[1:], rows + [rows[-1]], rows[:4] + rows[5:],
                        rows[:4] + [rows[3]] + rows[5:], list(reversed(rows))):
            self.reject(changed, expected)
        for code in (1, -4, 124, 137, True):
            self.reject(rows, expected, code)
        changed = copy.deepcopy(rows)
        changed[-1].update(kind="error", status="failed", worker_exit=11)
        self.reject(changed, expected)
        changed = copy.deepcopy(rows)
        changed[1]["status"] = "counter_reversal"
        self.reject(changed, expected)

    def test_malformed_duplicate_unknown_nonfinite_and_truncated_json(self):
        expected, rows = fixture()
        good = encoded(rows)
        for raw in (b"", good[:-1], b"\xff\n", b"[]\n", b"x" * (protocol.MAX_BYTES + 1),
                    good.replace(b'"version": 1', b'"version":1,"version":1'),
                    good.replace(b'"version": 1', b'"version":NaN'),
                    good.replace(b'"version": 1', b'"version":1.0')):
            with self.assertRaises((ValueError, KeyError, TypeError)):
                protocol.validate(raw, 0, expected)
        changed = copy.deepcopy(rows)
        changed[0]["unreviewed"] = True
        self.reject(changed, expected)

    def test_bad_preparation_labels_cpu_and_provenance(self):
        expected, rows = fixture()
        for field, value in (("prep_bytes", 2097152), ("stride", 64), ("seed", True),
                             ("access_bytes", 16), ("cpu_end", 3), ("commit", "d" * 40),
                             ("binary_sha256", "e" * 64), ("buffer_address", "0x100000"),
                             ("frequency_hz", "0"), ("frequency_signal", 4)):
            changed = copy.deepcopy(rows)
            changed[0][field] = value
            self.reject(changed, expected)
        for field, value in (("condition", "hit"), ("label", True), ("block", 1), ("index", 1),
                             ("value", "1"), ("series", "cache-hit")):
            changed = copy.deepcopy(rows)
            changed[1][field] = value
            self.reject(changed, expected)

    def test_independent_frequency_failure_is_explicit(self):
        expected, rows = fixture()
        rows[0].update(frequency_hz=None, frequency_signal=4, frequency_exit=132)
        self.assertIsNone(protocol.validate(encoded(rows), 0, expected)["metadata"]["frequency_hz"])

    def test_null_and_repeat_have_identical_actual_preparation(self):
        result = validated()
        for series in ("null", "repeat"):
            selected = [row for row in result["samples"] if row["series"] == series]
            self.assertEqual({row["label"] for row in selected}, {0, 1})
            self.assertEqual({row["condition"] for row in selected}, {"target_last"})
            self.assertEqual({row["delta_ticks"] for row in selected}, {"0"})

    def test_bounded_parameters(self):
        expected, _ = fixture()
        for field, value in (("blocks", 0), ("blocks", 1025), ("seed", 0),
                             ("prep_bytes", 1 << 30), ("stride", 7), ("stride", 4097)):
            config = dict(expected, **{field: value})
            with self.assertRaises(ValueError):
                protocol.parameters(config)

    def test_real_c_schedule_matches_python_without_timer_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, binary = Path(temporary) / "order.c", Path(temporary) / "order"
            source.write_text('#include <stdio.h>\n#include "schedule.h"\nint main(void) {\n'
                              'uint32_t seeds[] = {1,42,4294967295U};\n'
                              'for(unsigned s=0;s<3;s++){uint32_t state=seeds[s];\n'
                              'for(unsigned b=0;b<4;b++){unsigned order[8];\n'
                              'g3_order(order,&state);\n'
                              'for(unsigned i=0;i<8;i++)printf("%u ",order[i]);}puts("");}\n'
                              'return 0;}\n')
            subprocess.run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-I", str(PACKAGE), str(source), "-o", str(binary)],
                           check=True, timeout=15)
            lines = subprocess.run([str(binary)], capture_output=True, text=True,
                                   check=True, timeout=5).stdout.splitlines()
            for line, seed in zip(lines, (1, 42, 4294967295)):
                self.assertEqual([int(value) for value in line.split()], protocol.schedule(seed, 4))
        self.assertEqual(sorted(protocol.schedule(1, 1)), list(range(8)))
        self.assertNotEqual(protocol.schedule(1, 4), protocol.schedule(42, 4))

    def test_failed_launch_artifacts_are_retained(self):
        expected, rows = fixture()
        raw = encoded(rows)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            manifest = {"expected": expected, "command": [], "context": {"host_label": "synthetic"},
                        "status": "finished", "timeout": False, "returncode": 0,
                        "raw_sha256": hashlib.sha256(raw).hexdigest(),
                        "started_ns": 1, "ended_ns": 2}
            (path / "raw.jsonl").write_bytes(raw)
            (path / "launch.json").write_text(json.dumps(manifest))
            self.assertFalse(protocol.load_session(path)["g3_accepted"])
            manifest["timeout"] = True
            (path / "launch.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                protocol.load_session(path)
            self.assertEqual((path / "raw.jsonl").read_bytes(), raw)
            manifest["timeout"] = False
            (path / "launch.json").write_text(json.dumps(manifest))
            (path / "failure.json").write_text('{"status":"failed","reason":"provenance"}')
            with self.assertRaises(ValueError):
                protocol.load_session(path)

    def test_non_native_or_privileged_environment_is_never_success(self):
        with patch.object(platform, "machine", return_value="x86_64"), \
                patch.object(os, "geteuid", return_value=1000), self.assertRaises(ValueError):
            manage.native()
        with patch.object(os, "geteuid", return_value=0), self.assertRaises(ValueError):
            manage.native()


class CacheObservationAnalysisTest(unittest.TestCase):
    def test_frozen_calibration_does_not_tune_on_heldout(self):
        calibration = [validated(f"cal-{i}", i + 1) for i in range(3)]
        model = analyze.fit(calibration)
        frozen = copy.deepcopy(model)
        heldout = [validated(f"held-{i}", i + 10) for i in range(3)]
        report = analyze.evaluate(model, heldout)
        self.assertEqual(model, frozen)
        self.assertEqual(model["threshold_ticks"], 4)
        self.assertFalse(report["g3_accepted"])
        uncertainty = dict(report["uncertainty"] or {})
        self.assertEqual(uncertainty["unit"],
                         "independently launched session (assumed, not proven)")
        self.assertEqual(report["per_session_classification"][0]["ordered"]
                         ["matrix_actual_by_prediction"], [[4, 0], [0, 4]])
        self.assertEqual(report["per_session_classification"][0]["null"]
                         ["balanced_accuracy"], 0.5)
        self.assertEqual(protocol.decode(json.dumps(model).encode()), model)
        # A different held-out distribution may change scores, never the frozen threshold.
        changed = []
        for index in range(3):
            expected, rows = fixture(f"changed-held-{index}", index + 20)
            tick = 2 ** 60
            for row in rows[1:-1]:
                row.update(start_ticks=str(tick), end_ticks=str(tick + 100), delta_ticks="100")
                tick += 103
            session = protocol.validate(encoded(rows), 0, expected)
            session["host_label"] = "synthetic-host"
            changed.append(session)
        analyze.evaluate(model, changed)
        self.assertEqual(model, frozen)

    def test_calibration_validation_overlap_and_cross_platform_pooling_rejected(self):
        session = validated()
        model = analyze.fit([session])
        with self.assertRaises(ValueError):
            analyze.evaluate(model, [session])
        with self.assertRaises(ValueError):
            analyze.fit([session, session])
        other = validated("other", 8)
        other["metadata"]["platform"] = "macos"
        with self.assertRaises(ValueError):
            analyze.evaluate(model, [other])

    def test_quantized_equal_conditions_are_inconclusive(self):
        model = analyze.fit([validated("cal-zero", separated=False)])
        result = analyze.evaluate(model, [validated("held-zero", 4, separated=False)])
        self.assertIsNone(model["threshold_ticks"])
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertFalse(result["g3_accepted"])

    def test_few_sessions_have_no_independent_sample_interval(self):
        model = analyze.fit([validated("cal")])
        report = analyze.evaluate(model, [validated("held", 9)])
        self.assertIsNone(report["uncertainty"])
        self.assertEqual(report["outcome"], "inconclusive")

    def test_offline_cli_fit_then_heldout_evaluate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, seed in (("cal", 1), ("held", 2)):
                path = root / name
                path.mkdir()
                expected, rows = fixture(name, seed)
                raw = encoded(rows)
                (path / "raw.jsonl").write_bytes(raw)
                (path / "launch.json").write_text(json.dumps({
                    "expected": expected, "command": [], "context": {"host_label": "synthetic"},
                    "status": "finished", "timeout": False, "returncode": 0,
                    "raw_sha256": hashlib.sha256(raw).hexdigest(), "started_ns": 1, "ended_ns": 2}))
            model = root / "model.json"
            report = root / "report.json"
            subprocess.run([sys.executable, str(PACKAGE / "analyze.py"), "fit", str(root / "cal"),
                            "--output", str(model)], check=True, timeout=10)
            subprocess.run([sys.executable, str(PACKAGE / "analyze.py"), "evaluate",
                            str(root / "held"), "--model", str(model), "--output", str(report)],
                           check=True, timeout=10)
            self.assertEqual(json.loads(report.read_text())["outcome"], "inconclusive")
            self.assertFalse(protocol.read_json(model)["g3_accepted"])


class CacheObservationDisassemblyTest(unittest.TestCase):
    def test_actual_assembled_probe_without_execution(self):
        prefix = os.environ.get("RVZR_ARM64_BINUTILS_PREFIX", "" if platform.machine() == "aarch64"
                                else "aarch64-linux-gnu-")
        assembler, objdump = shutil.which(prefix + "as"), shutil.which(prefix + "objdump")
        linker = shutil.which(prefix + "ld")
        if not assembler or not objdump or not linker:
            self.skipTest("AArch64 GNU binutils unavailable; no substitute execution")
        with tempfile.TemporaryDirectory() as temporary:
            obj = Path(temporary) / "probe.o"
            source = Path(temporary) / "probe.s"
            # Preprocess for the Linux/ELF assembler; this never creates host timing code.
            preprocessed = subprocess.run(["gcc", "-E", "-P", "-x", "assembler-with-cpp",
                                           "-D__aarch64__", "-U__APPLE__",
                                           str(PACKAGE / "probe.S")], check=True,
                                          capture_output=True, timeout=10).stdout
            source.write_bytes(preprocessed)
            subprocess.run([assembler, str(source), "-o", str(obj)],
                           check=True, timeout=10)
            linked = Path(temporary) / "probe.elf"
            subprocess.run([linker, "--entry=g3_probe", str(obj), "-o", str(linked)],
                           check=True, timeout=10)
            dump = subprocess.run([objdump, "-d", str(linked)], check=True, capture_output=True,
                                  text=True, timeout=10).stdout
            disassembly.check(dump)
            changed = re.sub(r"ldr\s+x4,\s*\[x0\]", "ldr x4,[x1]", dump)
            self.assertNotEqual(changed, dump)
            with self.assertRaises(ValueError):
                disassembly.check(changed)

    @staticmethod
    def rendered(system="macho"):
        # Explicit rendering fixtures only, not native Mach-O build evidence.
        probe = ["dsb ish", "isb", "mrs x2, CNTVCT_EL0", "isb", "ldr x4, [x0]",
                 "dsb ish", "isb", "mrs x3, CNTVCT_EL0", "isb", "stp x2,x3,[x1]",
                 "str x4,[x1,#0x10]", "ret"]
        trial = ["cbz w5, 0x1068", "ldr x8,[x0]", "mov x6,#0x0", "ldr x7,[x1,x6]",
                 "add x6,x6,x3", "cmp x6,x2", "b.lo 0x106c", "cbnz w5, 0x1084",
                 "ldr x8,[x0]", "mov x1,x4", "b 0x1000"]
        text = ""
        for name, base, sequence in (
                ("g3_probe", 0x1000, probe),
                ("g3_empty", 0x1030, ["mov x4,xzr" if i == 4 else value
                                      for i, value in enumerate(probe)]),
                ("g3_trial", 0x1060, trial), ("g3_frequency", 0x108c, ["ret"])):
            if system == "elf":
                text += f"{base:016x} <{name}>:\n"
                for index, instruction in enumerate(sequence):
                    instruction = instruction.replace("0x1068", "1068 <g3_trial+0x8>")
                    instruction = instruction.replace("b.lo 0x106c", "b.cc 106c <g3_trial+0xc>")
                    instruction = instruction.replace("0x1084", "1084 <g3_trial+0x24>")
                    instruction = instruction.replace("b 0x1000", "b 1000 <g3_probe>")
                    text += f" {base + 4 * index:x}: 00000000 \t{instruction}\n"
            else:
                text += "_" + name + ":\n" + "\n".join(
                    f"{base + 4 * index:016x}\t{line}"
                    for index, line in enumerate(sequence)) + "\n"
        return text

    def test_macho_rendering_and_extra_access_rejected(self):
        text = self.rendered()
        disassembly.check(text)
        disassembly.check(text.replace("b 0x1000", "b _g3_probe"))
        for changed in (text.replace("ldr x4, [x0]", "ldr x4, [x1]"),
                        text.replace("\tisb\n", "\tldr x8,[x0]\n", 1)):
            with self.assertRaises(ValueError):
                disassembly.check(changed)

    def test_trial_operand_and_order_mutations_rejected(self):
        for system in ("elf", "macho"):
            text = self.rendered(system)
            for old, new in (("ldr x8,[x0]", "ldr x8,[x1]"),
                             ("mov x6,#0x0", "mov x6,#8"),
                             ("ldr x7,[x1,x6]", "ldr x7,[x0,x6]"),
                             ("add x6,x6,x3", "add x6,x6,#128"),
                             ("cmp x6,x2", "cmp x6,x3"),
                             ("mov x1,x4", "mov x1,x0"),
                             ("cbz w5,", "cbz x5,"), ("cbnz w5,", "cbz w5,")):
                with self.subTest(system=system, mutation=new), self.assertRaises(ValueError):
                    disassembly.check(text.replace(old, new, 1))
            # Remove only the second target load: target-last preparation must remain.
            changed = text.rsplit("ldr x8,[x0]", 1)
            with self.assertRaises(ValueError):
                disassembly.check("ldr x7,[x1,x6]".join(changed))

    def test_trial_branch_destinations_and_unsigned_loop_checked(self):
        changes: tuple[tuple[str, str], ...]
        for system in ("elf", "macho"):
            text = self.rendered(system)
            disassembly.check(text)
            if system == "elf":
                changes = (("1068 <", "106c <"), ("106c <", "1068 <"),
                           ("1084 <", "1080 <"), ("1000 <g3_probe>", "1030 <g3_empty>"),
                           ("b.cc", "b.lt"))
            else:
                changes = (("0x1068", "0x106c"), ("0x106c", "0x1068"),
                           ("0x1084", "0x1080"), ("b 0x1000", "b 0x1030"),
                           ("b.lo", "b.lt"), ("b 0x1000", "b _unknown"))
            for old, new in changes:
                with self.subTest(system=system, mutation=new), self.assertRaises(ValueError):
                    disassembly.check(text.replace(old, new, 1))

    def test_complete_bodies_reject_extras_gaps_duplicates_and_unknown_rendering(self):
        text = self.rendered()
        for changed in (text.replace("_g3_trial:", "000000000000105f\tldr x8,[x0]\n_g3_trial:"),
                        text.replace("_g3_frequency:",
                                     "000000000000108c\tldr x8,[x0]\n_g3_frequency:"),
                        text.replace("0000000000001064", "0000000000001068"),
                        text.replace("_g3_trial:", "_g3_trial:\n_g3_trial:"),
                        text.replace("_g3_trial:", "_unreviewed_trial:"),
                        text.replace("0000000000001060", "unknown-address")):
            with self.assertRaises(ValueError):
                disassembly.check(changed)


if __name__ == "__main__":
    unittest.main()
