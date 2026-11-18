"""Host-only G2 launcher tests. No original timer binary or architectural counter executes."""
import ast
import hashlib
import io
import json
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "tools/rvzr_m1_g2.sh"
CODE = LAUNCHER.read_text().split("<<'PY_G2'\n", 1)[1].rsplit("\nPY_G2", 1)[0]
FEDORA_ASAHI_RELEASE = (
    'NAME="Fedora Linux Asahi Remix"\nVERSION_ID=45\n'
    'ID=fedora-asahi-remix\nID_LIKE=fedora\n'
)


def load():
    module = types.ModuleType("synthetic_g2_launcher")
    with patch.object(sys, "argv", ["test", str(LAUNCHER)]):
        exec(compile(CODE, str(LAUNCHER), "exec"), module.__dict__)
    return module


def writable(directory):
    for path in [directory, *directory.rglob("*")]:
        path.chmod(0o700 if path.is_dir() else 0o600)


def synthetic_raw(cpu, loads):
    """Explicitly synthetic 128-sample fixture accepted by the unchanged validator."""
    from tests.unit_arm64_timer_calibration import valid_records
    meta = valid_records()[0]
    meta.update(samples_per_series=128, loads_per_window=loads, selected_cpu=cpu,
                cpu_start=cpu, cpu_end=cpu, initial_allowed_cpus=[cpu],
                kernel_release="synthetic-kernel", page_size_bytes=16384, machine="aarch64",
                checksum=str(2080 + 128 * sum(j % 64 + 1 for j in range(loads))))
    records, tick = [meta], 2 ** 60
    for series in ("adjacent_reads", "empty_window", "owned_buffer"):
        deltas = []
        for index in range(128):
            delta = (loads // 32 + 1) if series == "owned_buffer" else index % 3
            records.append({"kind": "sample", "series": series, "index": index,
                            "start_ticks": str(tick), "end_ticks": str(tick + delta),
                            "delta_ticks": str(delta)})
            tick += delta + (0 if series == "adjacent_reads" else 2)
            deltas.append(delta)
        records.append({"kind": "summary", "series": series, "samples": 128,
                        "zero_deltas": deltas.count(0), "min_delta_ticks": str(min(deltas)),
                        "max_delta_ticks": str(max(deltas)),
                        "min_positive_observed_delta_ticks": str(min(d for d in deltas if d > 0))})
    records.append({"kind": "complete", "status": "ok", "samples_emitted": 384})
    return ("\n".join(json.dumps(row) for row in records) + "\n").encode()


class LauncherTest(unittest.TestCase):
    def setUp(self):
        self.g = load()
        self.temp = tempfile.TemporaryDirectory(prefix="g2-software-only-")
        self.base = Path(self.temp.name)

    def tearDown(self):
        writable(self.base)
        self.temp.cleanup()

    def fixture_repo(self):
        repo = self.base / "repo with spaces"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        for name in self.g.FROZEN:
            path = repo / name
            path.parent.mkdir(exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        self.commit(repo, "synthetic frozen baseline")
        baseline = self.g.git(repo, "rev-parse", "HEAD").decode().strip()
        self.g.BASELINE = baseline  # Test fixture only; native CLI has no override.
        script = repo / "tools/rvzr_m1_g2.sh"
        shutil.copyfile(LAUNCHER, script)
        script.chmod(0o755)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        self.commit(repo, "synthetic later launcher commit")
        return repo, script

    @staticmethod
    def commit(repo, message):
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=G2 synthetic test",
                        "-c", "user.email=synthetic@example.invalid", "commit", "-qm", message],
                       check=True)

    def test_argument_handling_without_native_preflight(self):
        compile(CODE, "embedded", "exec", ast.PyCF_ONLY_AST)
        subprocess.run(["bash", "-n", str(LAUNCHER)], check=True, timeout=5)
        for args in ([], ["--session", "3"], ["--check", "--session", "1"],
                     ["--session", "1", "--note", "unrelated"]):
            result = subprocess.run([str(LAUNCHER), *args], cwd=self.base, capture_output=True,
                                    timeout=5, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"usage:", result.stderr)
        result = subprocess.run([str(LAUNCHER), "--help"], cwd=self.base,
                                capture_output=True, timeout=5, check=True)
        self.assertIn(b"--check", result.stdout)
        self.assertEqual(self.g.REPO, ROOT)

    def test_later_clean_commit_accepted_and_actual_revision_recorded(self):
        repo, script = self.fixture_repo()
        evidence = self.base / "evidence"
        evidence.mkdir()
        result = self.g.provenance(repo, script, evidence, "test")
        self.assertNotEqual(result["baseline_commit"], result["execution_commit"])
        self.assertEqual(result["launcher_revision"], result["execution_commit"])
        self.assertEqual(result["launcher_sha256"],
                         hashlib.sha256(script.read_bytes()).hexdigest())

    def test_dirty_staged_untracked_diagnostics_are_preserved(self):
        repo, script = self.fixture_repo()
        changed = repo / self.g.FROZEN[0]
        changed.write_text(changed.read_text() + "\n// staged synthetic drift\n")
        subprocess.run(["git", "-C", str(repo), "add", str(changed)], check=True)
        changed.write_text(changed.read_text() + "// unstaged synthetic drift\n")
        (repo / "untracked.txt").write_text("synthetic")
        with self.assertRaises(self.g.Blocked):
            self.g.provenance(repo, script, self.base, "dirty")
        self.assertIn("untracked.txt", (self.base / "git-dirty-status").read_text())
        self.assertIn("staged synthetic drift", (self.base / "git-dirty-staged.patch").read_text())
        self.assertIn("unstaged synthetic drift",
                      (self.base / "git-dirty-unstaged.patch").read_text())

    def test_committed_frozen_source_changes_are_rejected(self):
        repo, script = self.fixture_repo()
        changed = repo / self.g.FROZEN[0]
        changed.write_text(changed.read_text() + "\n// synthetic unauthorized change\n")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        self.commit(repo, "synthetic unauthorized source commit")
        with self.assertRaisesRegex(self.g.Blocked, "Frozen baseline changed"):
            self.g.provenance(repo, script, self.base, "changed")

    def test_post_measurement_revision_and_binary_drift_rejected(self):
        repo, script = self.fixture_repo()
        previous = self.g.provenance(repo, script, self.base, "before")
        binary = self.base / "synthetic-binary-never-executed"
        binary.write_bytes(b"synthetic")
        fingerprint = self.g.sha(binary)
        binary.write_bytes(b"changed")
        with self.assertRaisesRegex(self.g.Blocked, "Binary changed"):
            self.g.provenance(repo, script, self.base, "after", previous, (binary, fingerprint))
        (repo / "later.txt").write_text("unrelated but different execution revision")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        self.commit(repo, "synthetic revision drift")
        with self.assertRaisesRegex(self.g.Blocked, "revision drift"):
            self.g.provenance(repo, script, self.base, "revision", previous)

    def test_wrong_ancestry_is_rejected(self):
        repo, script = self.fixture_repo()
        self.g.BASELINE = "0" * 40
        with self.assertRaises(self.g.Blocked):
            self.g.provenance(repo, script, self.base, "ancestry")

    def target_context(self, *, midr0="0x00000000611f0221", midr4="0x00000000611f0231",
                       allowed=(0, 4), machine="aarch64", system="Linux", page=16384,
                       euid=1000, compatible="apple,t8103", release=FEDORA_ASAHI_RELEASE):
        def reading(path):
            name = str(path)
            if name == "/etc/os-release":
                return release
            if name.endswith("compatible"):
                return compatible
            if name.endswith("midr_el1"):
                return midr0 if "cpu0/" in name else midr4
            return "synthetic metadata"
        from contextlib import ExitStack
        stack = ExitStack()
        for target, value in (("optional", reading), ("platform.system", lambda: system),
                              ("platform.machine", lambda: machine), ("os.geteuid", lambda: euid),
                              ("os.sysconf", lambda _: page),
                              ("os.sched_getaffinity", lambda _: set(allowed))):
            parts = target.split(".")
            obj = getattr(self.g, parts[0]) if len(parts) == 2 else self.g
            stack.enter_context(patch.object(obj, parts[-1], value))
        return stack

    def test_target_identity_and_unavailable_core_are_blocked_before_measurement(self):
        with self.target_context():
            self.g.target(self.base)
        for settings in ({"midr0": "UNAVAILABLE"}, {"midr0": "0x123"},
                         {"midr4": "UNAVAILABLE"}, {"midr4": "0x123"},
                         {"allowed": (0,)}, {"allowed": (4,)}, {"machine": "x86_64"},
                         {"system": "Darwin"}, {"page": 4096}, {"euid": 0},
                         {"compatible": "apple,t8103-lookalike"}):
            with self.subTest(settings=settings), self.target_context(**settings), \
                    self.assertRaises(self.g.Blocked):
                self.g.target(self.base)
        self.assertTrue((self.base / "environment.json").is_file())

    def test_real_fedora_asahi_45_release_is_accepted(self):
        # Actual supplied os-release bytes; hardware/system calls remain synthetic fixtures.
        with self.target_context(release=FEDORA_ASAHI_RELEASE):
            evidence = self.g.target(self.base)
        self.assertEqual(evidence["os_release"], FEDORA_ASAHI_RELEASE)
        self.assertEqual(evidence["page_size"], 16384)
        self.assertEqual(evidence["cpus"]["0"]["core_type"], "Icestorm")
        self.assertEqual(evidence["cpus"]["4"]["core_type"], "Firestorm")

    def test_incompatible_or_ambiguous_os_release_is_blocked(self):
        for old, new in (("ID=fedora-asahi-remix", "ID=fedora"),
                         ("ID=fedora-asahi-remix", "ID=ubuntu"),
                         ("ID=fedora-asahi-remix\n", ""),
                         ("VERSION_ID=45", "VERSION_ID=44"),
                         ("VERSION_ID=45", "VERSION_ID=46"),
                         ("VERSION_ID=45", "VERSION_ID=450"),
                         ("ID_LIKE=fedora", "ID_LIKE=fedora-lookalike"),
                         ("ID_LIKE=fedora\n", ""),
                         ("VERSION_ID=45", "VERSION_ID=45\nVERSION_ID=44"),
                         ("ID=fedora-asahi-remix", "ID=fedora-asahi-remix\nID=fedora"),
                         ("ID=fedora-asahi-remix", 'ID="fedora-asahi-remix')):
            release = FEDORA_ASAHI_RELEASE.replace(old, new)
            with self.subTest(release=release), self.target_context(release=release), \
                    self.assertRaises(self.g.Blocked):
                self.g.target(self.base)

    def test_preflight_failure_is_sealed_and_never_collects(self):
        with patch.object(self.g, "OUTPUT", self.base), \
                patch.object(self.g.os, "geteuid", return_value=1000), \
                patch.object(self.g, "install_signals"), \
                patch.object(self.g, "provenance", side_effect=self.g.Blocked("synthetic dirty")), \
                patch.object(self.g, "collect") as collect:
            self.assertEqual(self.g.main(["--check"]), 1)
        collect.assert_not_called()
        directory = next(path for path in self.base.iterdir() if path.is_dir())
        self.g.verify_manifest(directory)
        self.assertIn("BLOCKED", (directory / "STATUS.txt").read_text())
        self.assertTrue(Path(str(directory) + ".tar.gz.sha256").is_file())

    def test_missing_tool_blocks_collect_without_build_or_measurement(self):
        software = self.base / "software"
        with patch.object(self.g, "provenance", return_value={}), \
                patch.object(self.g, "target", return_value={}), \
                patch.object(self.g.shutil, "which", return_value=None), \
                patch.object(self.g, "logged") as logged:
            with self.assertRaisesRegex(self.g.Blocked, "Missing prerequisite"):
                self.g.collect(self.base, 1)
        logged.assert_not_called()
        self.assertTrue(software.is_dir())

    def test_schedule_and_quantiles_match_frozen_protocol(self):
        for session, cpus in ((1, (4, 0)), (2, (0, 4))):
            expected = [(rep, cpu, (1, 8, 32, 128)[(rep - 1 + slot) % 4])
                        for rep in range(1, 6) for cpu in cpus for slot in range(4)]
            self.assertEqual(self.g.schedule(session), expected)
            self.assertEqual(len(expected), 40)
        self.assertEqual([self.g.quantile(list(range(128)), q) for q in (5, 50, 95, 99)],
                         [6, 63, 121, 126])
        self.assertIn('"--kill-after=2s", "15s", "taskset"', CODE)
        self.assertIn('"--samples", "128", "--loads"', CODE)

    def test_cross_session_criterion_is_strict_and_independent_per_cpu(self):
        rows = [{"cpu": cpu, "series": "owned_buffer", "loads": loads,
                 "p50_ticks": str(1 if loads == 1 else 2 if cpu == 4 else 1)}
                for cpu in (0, 4) for loads in (1, 128) for _ in range(10)]
        result = self.g.work_gate(rows)
        self.assertEqual(result["4"]["work_sensitivity"], "PASS")
        self.assertEqual(result["0"]["work_sensitivity"], "INCONCLUSIVE")
        with self.assertRaises(self.g.Blocked):
            self.g.work_gate(rows[:-1])

    def evidence(self):
        directory = self.base / "session"
        directory.mkdir()
        (directory / "STATUS.txt").write_text("synthetic incomplete evidence\n")
        (directory / "raw").mkdir()
        (directory / "raw/failure.stdout").write_text('partial synthetic JSONL\n')
        return directory

    def test_sealing_verifies_manifest_archive_and_has_no_self_reference(self):
        directory = self.evidence()
        archive = self.g.seal(directory)
        self.g.verify_archive(directory, archive)
        self.assertNotIn("SHA256SUMS", self.g.verify_manifest(directory))
        self.assertFalse(archive.is_relative_to(directory))
        with tarfile.open(archive) as packed:
            self.assertFalse(any(member.name.endswith(".tar.gz") for member in packed))
        checksum = Path(str(archive) + ".sha256").read_text().split()[0]
        self.assertEqual(checksum, self.g.sha(archive))
        self.assertEqual(directory.stat().st_mode & 0o222, 0)
        with self.assertRaises(FileExistsError):
            self.g.seal(directory)

    def test_checksum_tampering_is_detected(self):
        directory = self.evidence()
        archive = self.g.seal(directory)
        writable(directory)
        (directory / "STATUS.txt").write_text("tampered")
        with self.assertRaises(self.g.Blocked):
            self.g.verify_manifest(directory)
        with self.assertRaises(self.g.Blocked):
            self.g.verify_archive(directory, archive)

    def test_archive_failure_preserves_original_and_reports_outside_sealed_tree(self):
        def failed_collection(directory, _session):
            (directory / "raw.txt").write_text("synthetic retained raw")
            return "COMPLETE_RAW_SESSION; synthetic only"
        with patch.object(self.g, "OUTPUT", self.base), \
                patch.object(self.g.os, "geteuid", return_value=1000), \
                patch.object(self.g, "install_signals"), \
                patch.object(self.g, "collect", side_effect=failed_collection), \
                patch.object(self.g, "verify_archive",
                             side_effect=self.g.Blocked("synthetic archive error")):
            self.assertEqual(self.g.main(["--session", "1"]), 1)
        directory = next(path for path in self.base.iterdir() if path.is_dir())
        self.assertEqual((directory / "raw.txt").read_text(), "synthetic retained raw")
        self.g.verify_manifest(directory)
        self.assertTrue(Path(str(directory) + ".seal-failure.json").exists())
        receipt = json.loads(Path(str(directory) + ".receipt.json").read_text())
        self.assertEqual(receipt["actual_launcher_exit"], 1)

    def test_addendum_does_not_change_sealed_set(self):
        directory = self.evidence()
        archive = self.g.seal(directory)
        before = self.g.file_hashes(directory), self.g.sha(archive)
        extra = self.base / "addendum"
        extra.mkdir()
        self.g.addendum(directory, "synthetic late note", extra)
        self.g.seal(extra)
        self.assertEqual(before, (self.g.file_hashes(directory), self.g.sha(archive)))
        self.assertIn("synthetic late note", (extra / "addendum.json").read_text())

    def test_snapshot_drift_is_rejected(self):
        revision = {"sources_sha256": {}, "launcher_sha256": self.g.sha(LAUNCHER)}
        for name in self.g.FROZEN:
            shutil.copyfile(ROOT / name, self.base / Path(name).name)
            revision["sources_sha256"][name] = self.g.sha(ROOT / name)
        shutil.copyfile(LAUNCHER, self.base / "g2-driver.sh")
        self.g.verify_snapshots(self.base, revision)
        (self.base / "verify_arm64_timer.py").write_text("synthetic snapshot tampering")
        with self.assertRaisesRegex(self.g.Blocked, "Snapshot changed"):
            self.g.verify_snapshots(self.base, revision)

    def test_interrupted_session_and_late_seal_signal_cannot_claim_success(self):
        def interrupted(directory, _session):
            (directory / "raw-partial.txt").write_text("synthetic partial")
            self.g.on_signal(signal.SIGINT, None)
        with patch.object(self.g, "OUTPUT", self.base), \
                patch.object(self.g.os, "geteuid", return_value=1000), \
                patch.object(self.g, "install_signals"), \
                patch.object(self.g, "collect", side_effect=interrupted):
            self.assertEqual(self.g.main(["--session", "1"]), 130)
        directory = next(path for path in self.base.iterdir() if path.is_dir())
        self.assertIn("INTERRUPTED", (directory / "STATUS.txt").read_text())
        self.g.verify_manifest(directory)
        self.g.LAST_SIGNAL = None
        original = self.g.seal

        def seal_signal(path):
            archive = original(path)
            self.g.on_signal(signal.SIGTERM, None)  # Deferred; preserve the sealed tree.
            return archive
        with patch.object(self.g, "OUTPUT", self.base), \
                patch.object(self.g.os, "geteuid", return_value=1000), \
                patch.object(self.g, "install_signals"), \
                patch.object(self.g, "collect", return_value="COMPLETE_RAW_SESSION; synthetic"), \
                patch.object(self.g, "seal", side_effect=seal_signal):
            self.assertEqual(self.g.main(["--session", "2"]), 143)
        directory = next(path for path in self.base.iterdir()
                         if path.is_dir() and path != directory)
        receipt = json.loads(Path(str(directory) + ".receipt.json").read_text())
        self.assertEqual(receipt["state"], "INTERRUPTED_DURING_SEAL")
        self.assertEqual(receipt["actual_launcher_exit"], 143)
        self.g.verify_manifest(directory)

    def synthetic_collection(self, directory, session, fail_at=None):
        revision = {"baseline_commit": self.g.BASELINE, "execution_commit": "a" * 40,
                    "launcher_sha256": self.g.sha(LAUNCHER),
                    "sources_sha256": {name: self.g.sha(ROOT / name) for name in self.g.FROZEN}}
        env = {"uname": ["Linux", "synthetic-host", "synthetic-kernel"], "page_size": 16384,
               "cpus": {str(cpu): {"midr": str(value[0])} for cpu, value in self.g.MIDRS.items()}}
        measured = []

        def environment(folder):
            self.g.save(folder / "environment.json", env)
            return env

        def synthetic_command(command, stem, **_kwargs):
            # This mock never launches gcc, taskset or arm64-timer.
            if command[0] == "gcc":
                Path(command[-1]).write_bytes(b"SYNTHETIC NEVER EXECUTE")
            code = 0
            raw = b"synthetic diagnostic\n"
            if "--samples" in command:
                self.assertEqual(command[command.index("--samples") + 1], "128")
                cpu, loads = int(command[command.index("-c") + 1]), int(command[-1])
                measured.append((cpu, loads))
                raw = synthetic_raw(cpu, loads)
                if len(measured) == fail_at:
                    code, raw = 124, b"synthetic incomplete prefix\n"
            Path(str(stem) + ".stdout").write_bytes(raw)
            Path(str(stem) + ".stderr").write_text("synthetic only")
            Path(str(stem) + ".exit").write_text(str(code) + "\n")
            self.g.save(Path(str(stem) + ".execution.json"),
                        {"state": "RETURNED", "returncode": code})
            return code
        with patch.object(self.g, "provenance", return_value=revision), \
                patch.object(self.g, "target", side_effect=environment), \
                patch.object(self.g, "prerequisites"), \
                patch.object(self.g, "notes", return_value="SYNTHETIC fixture, no hardware"), \
                patch.object(self.g, "logged", side_effect=synthetic_command):
            state = self.g.collect(directory, session)
        self.g.save(directory / "session.json", {"state": state})
        return measured

    def test_full_synthetic_sessions_revalidate_and_compare_without_native_execution(self):
        paths = []
        for session in (1, 2):
            directory = self.base / f"synthetic-session-{session}"
            directory.mkdir()
            measured = self.synthetic_collection(directory, session)
            self.assertEqual(measured, [(cpu, loads) for _, cpu, loads in self.g.schedule(session)])
            self.assertEqual(len(list((directory / "raw").glob("*.stdout"))), 40)
            analysis = (directory / "analysis/analysis.jsonl").read_text().splitlines()
            self.assertEqual(len(analysis), 120)
            self.g.seal(directory)
            self.g.external_record(Path(str(directory) + ".receipt.json"),
                                   {"actual_launcher_exit": 0, "fixture": "synthetic only"})
            paths.append(directory)
        report = self.base / "comparison"
        report.mkdir()
        self.g.compare(paths, report)
        output = json.loads((report / "work-sensitivity.json").read_text())
        self.assertEqual(output["per_cpu"]["0"]["work_sensitivity"], "PASS")
        self.assertEqual(output["per_cpu"]["4"]["work_sensitivity"], "PASS")
        self.assertIn("PENDING", output["g2_verdict"])
        receipt = Path(str(paths[0]) + ".receipt.json")
        receipt.write_text('{"actual_launcher_exit":143}')
        with self.assertRaisesRegex(self.g.Blocked, "Receipt integrity"):
            self.g.compare(paths, report)

    def test_failed_synthetic_trial_stops_without_retry_and_retains_validation_error(self):
        directory = self.base / "failed-synthetic"
        directory.mkdir()
        with self.assertRaises(ValueError):
            self.synthetic_collection(directory, 1, fail_at=3)
        self.assertEqual(len(list((directory / "raw").glob("*.stdout"))), 3)
        self.assertEqual(len(list((directory / "raw").glob("*.validation.json"))), 3)
        last = directory / "raw/cpu-4-loads-32-rep-1.validation.json"
        self.assertEqual(json.loads(last.read_text())["state"], "NOT_ACCEPTED")
        self.assertFalse((directory / "analysis/analysis.jsonl").exists())

    def test_operator_notes_use_nonseeking_terminal_streams(self):
        modes = []

        def terminal(_path, mode):
            modes.append(mode)
            if mode == "r+":
                raise io.UnsupportedOperation("terminal is not seekable")
            return io.StringIO("AC power; synthetic operator response\n" if mode == "r" else "")

        with patch.object(self.g.sys.stdin, "isatty", return_value=False), \
                patch("builtins.open", side_effect=terminal):
            result = self.g.notes("Synthetic note prompt")
        self.assertEqual(modes, ["w", "r"])
        self.assertEqual(result, "AC power; synthetic operator response")
        with patch.object(self.g.sys.stdin, "isatty", return_value=False), \
                patch("builtins.open", side_effect=OSError("no tty")):
            self.assertIn("unknown", self.g.notes("Synthetic no-tty prompt"))

    def test_launch_failure_records_unknown_exit_and_validation_error(self):
        stem = self.base / "missing"
        with self.assertRaises(FileNotFoundError):
            self.g.run_trial(["/definitely-missing-g2-synthetic-command"], stem, 0, 1, None, {})
        self.assertEqual(Path(str(stem) + ".exit").read_text(), "UNKNOWN\n")
        self.assertEqual(json.loads(Path(str(stem) + ".validation.json").read_text())["state"],
                         "NOT_ACCEPTED")
        self.assertTrue(Path(str(stem) + ".stdout").exists())

    def test_nonzero_process_exit_is_factual_and_preserves_diagnostics(self):
        stem = self.base / "nonzero"
        code = self.g.logged([sys.executable, "-c",
                              "import sys; print('synthetic error',file=sys.stderr); sys.exit(7)"],
                             stem)
        self.assertEqual(code, 7)
        execution = json.loads(Path(str(stem) + ".execution.json").read_text())
        self.assertEqual(execution["state"], "FAILED")
        self.assertEqual(execution["returncode"], 7)
        self.assertEqual(Path(str(stem) + ".exit").read_text(), "7\n")
        self.assertIn("synthetic error", Path(str(stem) + ".stderr").read_text())

    def synchronized_timeout(self, stem, *, emit):
        # Only the test's first wait is gated on readiness. Production deadlines are unchanged.
        # The output case flushes before signalling; the empty case cannot print without release.
        child = """from pathlib import Path
import sys, time
ready, release = Path(sys.argv[1]), Path(sys.argv[2])
emit = sys.argv[3] == '1'
if emit:
    print('synthetic partial', flush=True)
    print('synthetic stderr', file=sys.stderr, flush=True)
ready.write_text('R')
deadline = time.monotonic() + 10
while not release.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
if not emit and release.exists():
    print('must not be released', flush=True)
time.sleep(30)
"""
        ready, release = self.base / "ready", self.base / "release"
        real_wait = subprocess.Popen.wait
        first_wait = True
        synchronized = False

        def wait_after_ready(process, timeout=None):
            nonlocal first_wait, synchronized
            if first_wait:
                first_wait = False  # Cleanup waits must still work if readiness setup fails.
                deadline = time.monotonic() + 10
                while not ready.exists() or ready.read_bytes() != b'R':
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise OSError("Synthetic child did not signal readiness")
                    time.sleep(0.01)
                if emit:
                    expected = b"synthetic partial\n"
                    if Path(str(stem) + ".stdout").read_bytes() != expected:
                        raise OSError("Readiness preceded the promised flushed output")
                    release.write_text('G')
                synchronized = True
            return real_wait(process, timeout=timeout)

        command = [sys.executable, "-c", child, str(ready), str(release), "1" if emit else "0"]
        with patch.object(self.g.subprocess.Popen, "wait", wait_after_ready), \
                self.assertRaises(subprocess.TimeoutExpired):
            self.g.logged(command, stem, limit=0.3)
        self.assertTrue(synchronized)
        result = json.loads(Path(str(stem) + ".execution.json").read_text())
        self.assertEqual(result["state"], "FAILED")
        self.assertTrue(result["outer_watchdog"])
        self.assertIsInstance(result["returncode"], int)
        self.assertNotEqual(result["returncode"], 0)
        self.assertEqual(Path(str(stem) + ".exit").read_text(), str(result["returncode"]) + "\n")

    def test_outer_timeout_preserves_partial_streams_and_non_success(self):
        stem = self.base / "timeout"
        self.synchronized_timeout(stem, emit=True)
        self.assertEqual(Path(str(stem) + ".stdout").read_bytes(), b"synthetic partial\n")
        self.assertEqual(Path(str(stem) + ".stderr").read_bytes(), b"synthetic stderr\n")

    def test_outer_timeout_before_output_has_empty_raw_streams(self):
        stem = self.base / "empty-timeout"
        self.synchronized_timeout(stem, emit=False)
        self.assertEqual(Path(str(stem) + ".stdout").read_bytes(), b"")
        self.assertEqual(Path(str(stem) + ".stderr").read_bytes(), b"")

    def test_signals_preserve_raw_status_and_stop_separate_owned_groups(self):
        # Real OS signals to benign Python children only, including timeout-like subgrouping.
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number):
                folder = self.base / str(number)
                folder.mkdir()
                stem = folder / "trial"
                pidfile = folder / "grandchild.pid"
                benign = ("import subprocess,os,time,sys; "
                          "child=subprocess.Popen([sys.executable,'-c',"
                          "'import time; time.sleep(30)'],"
                          "preexec_fn=os.setpgrp); "
                          f"open({str(pidfile)!r},'w').write(str(child.pid)); "
                          "print('synthetic raw prefix',flush=True); "
                          "print('synthetic stderr',file=sys.stderr,flush=True); time.sleep(30)")
                harness = (
                    "import sys,types; from pathlib import Path; "
                    "s=Path(sys.argv[1]).read_text().split(\"<<'PY_G2'\\n\",1)[1]; "
                    "s=s.rsplit('\\nPY_G2',1)[0]; "
                    "g=types.ModuleType('synthetic_child'); "
                    "exec(compile(s,sys.argv[1],'exec'),g.__dict__); g.install_signals(); "
                    "g.run_trial([sys.executable,'-c',sys.argv[3]],Path(sys.argv[2]),0,1,None,{})")
                invocation = [sys.executable, "-c", harness, str(LAUNCHER), str(stem), benign]
                with subprocess.Popen(invocation, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL) as process:
                    deadline = time.monotonic() + 5
                    while not pidfile.exists() or not Path(str(stem) + ".stdout").exists() or \
                            not Path(str(stem) + ".stdout").read_bytes():
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail("Benign fixture did not start")
                        time.sleep(0.01)
                    process.send_signal(number)
                    self.assertNotEqual(process.wait(timeout=8), 0)
                execution = json.loads(Path(str(stem) + ".execution.json").read_text())
                self.assertEqual(execution["state"], "INTERRUPTED")
                self.assertEqual(execution["requested_signal"], number)
                self.assertIsInstance(execution["returncode"], int)
                self.assertIn("synthetic raw prefix", Path(str(stem) + ".stdout").read_text())
                self.assertIn("synthetic stderr", Path(str(stem) + ".stderr").read_text())
                validation = json.loads(Path(str(stem) + ".validation.json").read_text())
                self.assertEqual(validation["state"], "NOT_ACCEPTED")
                status = Path(f"/proc/{pidfile.read_text()}/stat")
                if status.exists():
                    self.assertEqual(status.read_text().rsplit(")", 1)[1].split()[0], "Z")


if __name__ == "__main__":
    unittest.main()
