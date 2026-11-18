#!/usr/bin/env bash
# Frozen B3.5c G2 on M1 / Fedora Asahi. No timer runs in --check/--compare/--addendum.
# Usage: tools/rvzr_m1_g2.sh --check | --session 1 | --session 2
# Offline: --compare SESSION1 SESSION2 | --addendum SESSION --note 'dated observations'
# raw/*.stdout contains the untouched JSONL stream. Never edit sealed session files.
# Preserve archives, checksums and external receipt/seal-failure records together.
set -Eeuo pipefail
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1
umask 077
# Pass the script location explicitly; Python resolves it before changing directories.
exec python3 - "${BASH_SOURCE[0]}" "$@" <<'PY_G2'
"""Launcher supervision only; frozen C, validator and historical protocols stay unchanged."""
import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import uuid

BASELINE = "7a34feef80b64d31937c2d0bc7e1117e90e74b0d"
LAUNCHER = Path(sys.argv[1]).resolve()
REPO = LAUNCHER.parent.parent
OUTPUT = Path("/home/safelab/MasterThesis/output/G2")
FROZEN = ("tools/arm64_timer_calibration.c", "tools/verify_arm64_timer.py",
          "tools/README.m3-timer-protocol.md", "tools/README.m3-experiment-runbook.md")
SUPPORT = ("tools/experimental_environment.py",)
MIDRS = {0: (0x611f0221, "Icestorm"), 4: (0x611f0231, "Firestorm")}
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
LAST_SIGNAL = None
DEFER_SIGNALS = False


class Blocked(RuntimeError):
    """Missing prerequisites or inconsistent provenance; no further measurements."""


class Interrupted(RuntimeError):
    def __init__(self, number):
        super().__init__(f"Interrupted by signal {number}")
        self.number = number


def require(condition, message):
    if not condition:
        raise Blocked(message)


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    # Every record has a single writer. Terminal records replace only their own STARTED record.
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=10,
                            check=False)
    require(result.returncode == 0,
            f"Git {args} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def provenance(repo, launcher, directory, phase, previous=None, binary=None):
    # Save diagnostics BEFORE rejecting a dirty checkout, including staged changes.
    diagnostics = (
        ("status", ("status", "--porcelain=v1", "--untracked-files=all",
                    "--ignore-submodules=none")),
        ("unstaged.patch", ("diff", "--binary")),
        ("staged.patch", ("diff", "--cached", "--binary")),
    )
    for name, args in diagnostics:
        data = git(repo, *args)
        (directory / f"git-{phase}-{name}").write_bytes(data)
        if name == "status":
            status = data
    commit = git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    save(directory / f"revision-{phase}.json", {
        "baseline_commit": BASELINE, "execution_commit": commit})
    require(not status, "Clean committed checkout required; Git diagnostics retained")
    git(repo, "merge-base", "--is-ancestor", BASELINE, commit)
    hashes = {}
    for name in FROZEN:
        path = repo / name
        require(not path.is_symlink(), f"Frozen source must be a regular file: {name}")
        require(path.read_bytes() == git(repo, "show", f"{BASELINE}:{name}"),
                f"Frozen baseline changed: {name}")
        hashes[name] = sha(path)
    relative = launcher.relative_to(repo).as_posix()
    require(relative == "tools/rvzr_m1_g2.sh", "Use the committed tools/rvzr_m1_g2.sh")
    require(git(repo, "show", f"HEAD:{relative}") == launcher.read_bytes(),
            "Launcher differs from execution commit")
    require(git(repo, "ls-tree", "HEAD", relative).startswith(b"100755 "),
            "Commit the launcher with executable mode 100755")
    support = {}
    for name in SUPPORT:
        path = repo / name
        require(not path.is_symlink() and path.read_bytes() == git(repo, "show", f"HEAD:{name}"),
                f"Uncommitted environmental helper: {name}")
        support[name] = sha(path)
    result = {"support_sources_sha256": support,
              "baseline_commit": BASELINE, "execution_commit": commit,
              "branch": git(repo, "branch", "--show-current").decode().strip(),
              "launcher_revision": git(repo, "log", "-1", "--format=%H", "--", relative)
              .decode().strip(), "launcher_sha256": sha(launcher), "sources_sha256": hashes}
    if previous is not None:
        require(result == previous, "Source/revision drift during preparation or measurement")
    if binary is not None:
        require(sha(binary[0]) == binary[1], "Binary changed during measurement")
    save(directory / f"provenance-{phase}.json", result)
    return result


def optional(path):
    try:
        return Path(path).read_text().replace("\0", "\n").strip()
    except OSError as error:
        return f"UNAVAILABLE: {error}"


def target(directory):
    evidence = {"uname": list(platform.uname()), "page_size": os.sysconf("SC_PAGESIZE"),
                "os_release": optional("/etc/os-release"),
                "cpuinfo": optional("/proc/cpuinfo"),
                "clocksource": optional(
                    "/sys/devices/system/clocksource/clocksource0/current_clocksource"),
                "model": optional("/proc/device-tree/model"),
                "compatible": optional("/proc/device-tree/compatible"),
                "allowed_cpus": sorted(os.sched_getaffinity(0)), "cpus": {}}
    for cpu in (0, 4):
        base = Path(f"/sys/devices/system/cpu/cpu{cpu}")
        fields = {"core_type": "unknown", "midr": optional(base / "regs/identification/midr_el1"),
                  "capacity": optional(base / "cpu_capacity"),
                  "governor": optional(base / "cpufreq/scaling_governor")}
        fields["cache"] = {str(path): optional(path) for path in
                           sorted((base / "cache").glob("index*/*")) if path.name in
                           {"level", "type", "size", "coherency_line_size", "number_of_sets",
                            "ways_of_associativity", "shared_cpu_list"}}
        evidence["cpus"][str(cpu)] = fields
    save(directory / "environment.json", evidence)
    require(os.geteuid() != 0, "Ordinary user required")
    require(platform.system() == "Linux" and platform.machine() == "aarch64",
            "Native AArch64 Linux required; no alternate timer/emulation")
    require(evidence["page_size"] == 16384, "Expected 16 KiB runtime pages")
    require("apple,t8103" in evidence["compatible"].splitlines(), "M1/T8103 not established")
    require({0, 4}.issubset(evidence["allowed_cpus"]), "CPUs 0 and 4 must both be allowed")
    os_fields = {}
    for line in evidence["os_release"].splitlines():
        field, separator, value = line.partition("=")
        if separator and field in ("ID", "VERSION_ID", "ID_LIKE"):
            require(field not in os_fields, f"Duplicate OS identity field: {field}")
            try:
                words = shlex.split(value, comments=True)
            except ValueError as error:
                raise Blocked(f"Malformed OS identity field: {field}") from error
            require(len(words) == 1, f"Malformed OS identity field: {field}")
            os_fields[field] = words[0]
    require(os_fields.get("ID") == "fedora-asahi-remix"
            and os_fields.get("VERSION_ID") == "45"
            and "fedora" in os_fields.get("ID_LIKE", "").split(),
            "Expected Fedora Asahi Remix 45; inspect recorded OS evidence")
    for cpu, (expected, label) in MIDRS.items():
        text = evidence["cpus"][str(cpu)]["midr"]
        try:
            value = int(text, 16)
        except ValueError:
            raise Blocked(f"CPU {cpu} identity unavailable: {text}") from None
        require(value == expected, f"CPU {cpu} MIDR mismatch; expected {label}")
        evidence["cpus"][str(cpu)]["core_type"] = label
    save(directory / "environment.json", evidence)
    return evidence


def on_signal(number, _frame):
    global LAST_SIGNAL
    LAST_SIGNAL = number
    if not DEFER_SIGNALS:
        raise Interrupted(number)


@contextmanager
def defer_signals():
    global DEFER_SIGNALS
    previous = DEFER_SIGNALS
    DEFER_SIGNALS = True
    try:
        yield
    finally:
        DEFER_SIGNALS = previous


def install_signals():
    for number in STOP_SIGNALS:
        signal.signal(number, on_signal)


def stop_owned_session(process):
    """GNU time and timeout can have separate groups; stop only the new owned session.

    Linux /proc discovery is cleanup-only, outside every measurement. Descendants
    of these fixed tools do not create new sessions. SIGKILL/power loss cannot be trapped.
    """
    with defer_signals():
        for number, guard in ((signal.SIGTERM, 2), (signal.SIGKILL, 2)):
            groups = set()
            for entry in Path("/proc").glob("[0-9]*/stat"):
                try:
                    fields = entry.read_text().rsplit(")", 1)[1].split()
                    if int(fields[3]) == process.pid:
                        groups.add(int(fields[2]))
                except (OSError, ValueError, IndexError):
                    continue
            for group in groups:
                try:
                    os.killpg(group, number)
                except ProcessLookupError:
                    pass
            # Keep the KILL pass even if the direct parent exits before descendants.
            if number == signal.SIGTERM:
                time.sleep(guard)
            try:
                process.wait(timeout=guard)
            except subprocess.TimeoutExpired:
                pass
        return process.poll()


def logged(command, stem, *, cwd=None, limit=20):
    """Run once, retaining partial streams and actual status (or explicit UNKNOWN)."""
    before_signal = LAST_SIGNAL
    record = {"command": command, "started_utc": now(), "ended_utc": None,
              "state": "STARTED", "returncode": None, "requested_signal": None}
    save(Path(str(stem) + ".execution.json"), record)
    Path(str(stem) + ".command").write_text(shlex.join(command) + "\n")
    Path(str(stem) + ".exit").write_text("UNKNOWN\n")
    process, failure = None, None
    try:
        with Path(str(stem) + ".stdout").open("wb") as out, \
                Path(str(stem) + ".stderr").open("wb") as err:
            with defer_signals():
                process = subprocess.Popen(command, cwd=cwd, stdout=out, stderr=err,
                                           start_new_session=True)
            if LAST_SIGNAL != before_signal:
                raise Interrupted(LAST_SIGNAL)
            record["returncode"] = process.wait(timeout=limit)
            code = record["returncode"]
            record["state"] = ("RETURNED" if code == 0 else "TIMEOUT" if code == 124
                               else "FAILED")
    except (Interrupted, subprocess.TimeoutExpired, OSError) as error:
        failure = error
    finally:
        # Defer further signals while reaping and writing factual terminal records.
        with defer_signals():
            if failure is not None:
                record.update(state="INTERRUPTED" if isinstance(failure, Interrupted) else "FAILED",
                              reason=str(failure))
                if process is not None:
                    record["returncode"] = stop_owned_session(process)
                if isinstance(failure, subprocess.TimeoutExpired):
                    record["outer_watchdog"] = True
            if LAST_SIGNAL != before_signal:
                record.update(state="INTERRUPTED", requested_signal=LAST_SIGNAL)
                failure = Interrupted(LAST_SIGNAL)
            record["ended_utc"] = now()
            save(Path(str(stem) + ".execution.json"), record)
            Path(str(stem) + ".exit").write_text(
                "UNKNOWN\n" if record["returncode"] is None else str(record["returncode"]) + "\n")
    if failure is not None:
        raise failure
    return record["returncode"]


def schedule(session):
    cpus = (4, 0) if session == 1 else (0, 4)
    return [(rep, cpu, (1, 8, 32, 128)[(rep - 1 + slot) % 4])
            for rep in range(1, 6) for cpu in cpus for slot in range(4)]


def validator(path):
    module = types.ModuleType("frozen_g2_validator")
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    require(module.SERIES == ("adjacent_reads", "empty_window", "owned_buffer"),
            "Unexpected frozen series")
    return module


def quantile(values, percent):
    return sorted(values)[(percent * len(values) + 99) // 100 - 1]


def analyze_raw(raw, code, cpu, loads, verify, environment):
    metadata = verify.validate_output(raw, code, samples=128, loads=loads)
    require(metadata["selected_cpu"] == cpu and metadata["initial_allowed_cpus"] == [cpu],
            "Unexpected selected CPU/mask")
    require(metadata["machine"] == "aarch64" and metadata["page_size_bytes"] == 16384
            and metadata["kernel_release"] == environment["uname"][2], "Environment drift")
    records = [json.loads(line) for line in raw.splitlines()]
    result = []
    for series in verify.SERIES:
        values = [int(row["delta_ticks"]) for row in records
                  if row.get("kind") == "sample" and row["series"] == series]
        counts = Counter(values)
        result.append({"cpu": cpu, "loads": loads, "series": series,
                       "frequency_hz": metadata["reported_frequency_hz"], "samples": len(values),
                       "zero_count": counts[0], "min_ticks": str(min(values)),
                       **{f"p{q:02}_ticks": str(quantile(values, q)) for q in (5, 50, 95, 99)},
                       "max_ticks": str(max(values)),
                       "min_positive_observed_ticks": str(min(d for d in values if d > 0))
                       if any(values) else None,
                       "histogram_ticks": [[str(value), count]
                                           for value, count in sorted(counts.items())]})
    return result


def run_trial(command, stem, cpu, loads, verify, environment):
    try:
        code = logged(command, stem)
        raw_path = Path(str(stem) + ".stdout")
        # The on-disk stream is raw JSONL, including partial/error output.
        require(raw_path.stat().st_size <= verify.MAX_OUTPUT_BYTES, "Oversized raw output")
        rows = analyze_raw(raw_path.read_bytes(), code, cpu, loads, verify, environment)
    except (Exception, Interrupted) as error:
        save(Path(str(stem) + ".validation.json"), {"state": "NOT_ACCEPTED", "error": str(error)})
        raise
    save(Path(str(stem) + ".validation.json"), {"state": "VALIDATED", "analysis": rows})
    return rows


def file_hashes(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), "Symlink in evidence")
        if path.is_file() and path != directory / "SHA256SUMS":
            result[path.relative_to(directory).as_posix()] = sha(path)
    return result


def verify_manifest(directory):
    entries = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        require(name not in entries, "Duplicate manifest entry")
        entries[name] = checksum
    require(entries == file_hashes(directory), "Evidence checksum/inventory mismatch")
    return entries


def verify_archive(directory, archive):
    expected = {**verify_manifest(directory), "SHA256SUMS": sha(directory / "SHA256SUMS")}
    observed = {}
    with tarfile.open(archive, "r:gz") as packed:
        for member in packed:
            if member.isdir():
                continue
            require(member.isfile(), "Unexpected archive member type")
            prefix = directory.name + "/"
            require(member.name.startswith(prefix), "Unexpected archive prefix")
            name = member.name[len(prefix):]
            require(name not in observed, "Duplicate archive member")
            with packed.extractfile(member) as stream:
                observed[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    require(observed == expected, "Archive checksum/inventory mismatch")


def evidence_root(path):
    """Accept a new run container, its evidence child, or an untouched legacy directory."""
    path = Path(path).resolve()
    if (path / "evidence" / "metadata" / "layout.json").is_file():
        require(not (path / "session.json").exists(), "Ambiguous evidence container")
        return path / "evidence"
    return path


def artifacts(directory):
    """Only new evidence has a layout marker. Legacy sibling filenames remain unchanged."""
    marker = directory / "metadata" / "layout.json"
    if marker.is_file():
        layout = json.loads(marker.read_text())
        require(layout["layout_version"] == 1 and layout["experiment"] == "G2"
                and directory.name == "evidence" and layout["run_id"] == directory.parent.name,
                "Invalid evidence layout")
        return {"receipt": directory.parent / "receipt.json",
                "failure": directory.parent / "seal-failure.json",
                "archive": directory.parent / "evidence.tar.gz"}
    return {"receipt": Path(str(directory) + ".receipt.json"),
            "failure": Path(str(directory) + ".seal-failure.json"),
            "archive": Path(str(directory) + ".tar.gz")}


def new_run(label):
    parent = OUTPUT / label
    parent.mkdir(parents=True, exist_ok=True)
    container = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8] + "-", dir=parent))
    directory = container / "evidence"
    (directory / "metadata").mkdir(parents=True)
    save(directory / "metadata" / "layout.json", {
        "layout_version": 1, "experiment": "G2", "experiment_session": label,
        "run_id": container.name, "created_utc": now()})
    return directory


def seal(directory):
    hashes = file_hashes(directory)
    with (directory / "SHA256SUMS").open("x") as stream:
        stream.write("".join(f"{checksum}  {name}\n" for name, checksum in hashes.items()))
    verify_manifest(directory)
    # Discourage accidental edits. Owners can deliberately chmod; this is not tamper-proof.
    for path in directory.rglob("*"):
        path.chmod(0o500 if path.is_dir() else 0o400)
    directory.chmod(0o500)
    archive = artifacts(directory)["archive"]
    with tarfile.open(archive, "x:gz") as packed:
        packed.add(directory, arcname=directory.name)
    verify_archive(directory, archive)
    with Path(str(archive) + ".sha256").open("x") as stream:
        stream.write(sha(archive) + "  " + archive.name + "\n")
    require(Path(str(archive) + ".sha256").read_text().split()[0] == sha(archive),
            "Archive digest verification failed")
    return archive


def external_record(path, value):
    """Terminal receipts/addenda stay outside the immutable tree and get their own digest."""
    with path.open("x") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
    with Path(str(path) + ".sha256").open("x") as stream:
        stream.write(sha(path) + "  " + path.name + "\n")


def notes(prompt):
    if not sys.stdin.isatty():
        # Script source occupies stdin; operator prompts use the controlling terminal.
        try:
            # Separate streams avoid BufferedRandom requiring a seekable device.
            with open("/dev/tty", "w") as output, open("/dev/tty", "r") as source:
                output.write(prompt + "\n> ")
                output.flush()
                return source.readline().strip() or "unknown"
        except OSError:
            return "unknown (no controlling terminal)"
    return input(prompt + "\n> ").strip() or "unknown"


def prerequisites(directory):
    for tool in ("gcc", "timeout", "taskset", "lscpu", "readelf", "file"):
        require(shutil.which(tool), f"Missing prerequisite: {tool}")
    for name, command in (("lscpu", ["lscpu"]), ("gcc-version", ["gcc", "--version"]),
                          ("python-version", [sys.executable, "--version"])):
        require(logged(command, directory / name, limit=10) == 0, f"Failed {name}")
    for cpu in (0, 4):
        require(logged(["taskset", "-c", str(cpu), "true"], directory / f"affinity-{cpu}",
                       limit=10) == 0, f"CPU {cpu} affinity unavailable")


def verify_snapshots(directory, revision):
    for name in FROZEN:
        require(sha(directory / Path(name).name) == revision["sources_sha256"][name],
                f"Snapshot changed: {name}")
    for name, expected in revision.get("support_sources_sha256", {}).items():
        require(sha(directory / Path(name).name) == expected, f"Helper snapshot changed: {name}")
    require(sha(directory / "g2-driver.sh") == revision["launcher_sha256"],
            "Launcher snapshot changed")


def operator_note(directory, phase):
    text = notes("Record any unusual events, intentional background activity, "
                 "physical interruptions or changes in testing conditions. "
                 "Enter 'none observed' if appropriate, "
                 "or 'not monitored' for unknown conditions.")
    (directory / f"notes-{phase}.txt").write_text(text + "\n")
    metadata = directory / "metadata"
    metadata.mkdir(exist_ok=True)
    save(metadata / f"operator-{phase}.json", {
        "observed_utc": now(), "source": "manual operator report", "phase": phase,
        "status": "MANUAL", "observation": text})


def environment_snapshot(directory, phase):
    """One synchronous optional worker; return only after it exits or is reaped."""
    metadata = directory / "metadata"
    metadata.mkdir(exist_ok=True)
    stem = metadata / f"environment-{phase}"
    command = [sys.executable, str(directory / "software" / "experimental_environment.py")]
    report = {"schema_version": 1, "status": "UNAVAILABLE", "observed_utc": now(),
              "source": command, "phase": phase, "error": None}
    termination_known = True
    try:
        code = logged(command, stem, limit=5)
        require(code == 0, f"Environmental worker returned {code}")
        raw = Path(str(stem) + ".stdout")
        require(raw.stat().st_size <= 1024 * 1024, "Environmental report too large")
        report = json.loads(raw.read_bytes())
        require(report["schema_version"] == 1 and isinstance(report["records"], list),
                "Invalid environmental report")
    except Interrupted as error:
        report["error"] = str(error)
        raise
    except Exception as error:
        report = {"schema_version": 1, "status": "UNAVAILABLE", "observed_utc": now(),
                  "source": command, "phase": phase, "error": str(error)}
        execution = Path(str(stem) + ".execution.json")
        if execution.is_file():
            termination_known = json.loads(execution.read_text())["returncode"] is not None
    finally:
        save(metadata / f"environment-{phase}.json", report)
    require(termination_known,
            "Environmental worker termination unknown; cannot isolate measurement")


def collect(directory, session):
    software = directory / "software"
    software.mkdir()
    (directory / "raw").mkdir()
    (directory / "analysis").mkdir()
    revision = provenance(REPO, LAUNCHER, software, "before")
    environment = target(software)
    prerequisites(software)
    for name in (*FROZEN, *SUPPORT):
        dest = software / Path(name).name
        shutil.copyfile(REPO / name, dest)
        expected = {**revision["sources_sha256"], **revision["support_sources_sha256"]}
        require(sha(dest) == expected[name], "Snapshot hash mismatch")
    shutil.copyfile(LAUNCHER, software / "g2-driver.sh")
    require(sha(software / "g2-driver.sh") == revision["launcher_sha256"],
            "Launcher snapshot drift")
    verify = validator(software / "verify_arm64_timer.py")
    experiment_id = (directory.parent.name if
                     (directory / "metadata" / "layout.json").exists() else directory.name)
    save(directory / "methodology.json", {
        "session": session, "experiment_id": experiment_id, "revizor": revision,
        "program": "unchanged B3.5c arm64_timer_calibration.c", "inputs": "loads 1/8/32/128",
        "random_seed": "NOT APPLICABLE", "contract": "NOT APPLICABLE",
        "designation": "G2 characterization/replication; held-out cache evaluation NOT APPLICABLE",
        "method": "CNTVCT_EL0; CNTFRQ_EL0 independently probed",
        "units": "counter ticks, NOT cycles",
        "cpu_order": [4, 0] if session == 1 else [0, 4], "repetitions": 5,
        "samples_per_series": 128, "runs": 40, "raw_samples": 15360,
        "timeout_seconds": 15, "kill_guard_seconds": 2,
        "acceptance": "Per CPU across both sessions: "
                      "min(owned_buffer p50 loads=128) > max(p50 loads=1)"})
    operator_note(directory, "before")
    binary = directory / "arm64-timer"
    command = ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
               str(software / "arm64_timer_calibration.c"), "-o", str(binary)]
    require(logged(command, software / "build", limit=60) == 0, "Build failed")
    fingerprint = sha(binary)
    save(software / "binary.json", {"sha256": fingerprint})
    for name, command in (("file", ["file", str(binary)]), ("elf", ["readelf", "-h", str(binary)])):
        require(logged(command, software / name, limit=10) == 0, f"Failed {name}")
    verify_snapshots(software, revision)
    provenance(REPO, LAUNCHER, software, "prepared", revision, (binary, fingerprint))
    rows = []
    try:
        environment_snapshot(directory, "before")
        for rep, cpu, loads in schedule(session):
            stem = directory / "raw" / f"cpu-{cpu}-loads-{loads}-rep-{rep}"
            command = ["timeout", "--verbose", "--kill-after=2s", "15s", "taskset", "-c", str(cpu),
                       str(binary), "--samples", "128", "--loads", str(loads)]
            if Path("/usr/bin/time").is_file() and os.access("/usr/bin/time", os.X_OK):
                command = ["/usr/bin/time", "-v", "-o", str(stem) + ".rusage.txt", *command]
            else:
                Path(str(stem) + ".rusage.txt").write_text("GNU time unavailable\n")
            results = run_trial(command, stem, cpu, loads, verify, environment)
            rows.extend(dict(row, rep=rep) for row in results)
            print(f"Session {session}: {len(rows) // 3}/40 validated; cpu={cpu}, loads={loads}",
                  flush=True)
    finally:
        environment_snapshot(directory, "after")
    with (directory / "analysis" / "analysis.jsonl").open("x") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    operator_note(directory, "after")
    identity_after = directory / "metadata" / "identity-after"
    identity_after.mkdir()
    after = target(identity_after)
    require(after["uname"] == environment["uname"]
            and after["page_size"] == environment["page_size"],
            "Essential identity changed during measurement")
    verify_snapshots(software, revision)
    provenance(REPO, LAUNCHER, software, "after", revision, (binary, fingerprint))
    return "COMPLETE_RAW_SESSION; cross-session G2 decision PENDING"


def work_gate(rows):
    result = {}
    for cpu in (0, 4):
        groups = {loads: [int(row["p50_ticks"]) for row in rows if row["cpu"] == cpu
                          and row["series"] == "owned_buffer" and row["loads"] == loads]
                  for loads in (1, 128)}
        require(all(len(group) == 10 for group in groups.values()),
                "Need ten replicates/workload/CPU")
        result[str(cpu)] = {"min_p50_loads128": min(groups[128]), "max_p50_loads1": max(groups[1]),
                            "work_sensitivity": "PASS" if min(groups[128]) > max(groups[1])
                            else "INCONCLUSIVE"}
    return result


def compare(paths, output):
    paths = [evidence_root(path) for path in paths]
    require(paths[0] != paths[1], "Two separately launched sessions required")
    rows, commits, environments = [], [], []
    for session, path in enumerate(paths, 1):
        verify_manifest(path)
        related = artifacts(path)
        require(not related["failure"].exists(), "Session sealing failed")
        receipt_path = related["receipt"]
        require(Path(str(receipt_path) + ".sha256").read_text().split()[0] == sha(receipt_path),
                "Receipt integrity mismatch")
        require(json.loads(receipt_path.read_text())["actual_launcher_exit"] == 0,
                "Session launcher failed or was interrupted")
        archive = related["archive"]
        require(Path(str(archive) + ".sha256").read_text().split()[0] == sha(archive),
                "Archive integrity mismatch")
        verify_archive(path, archive)
        require(json.loads((path / "session.json").read_text())["state"].startswith(
            "COMPLETE_RAW_SESSION"), "Incomplete session")
        method = json.loads((path / "methodology.json").read_text())
        require(method["session"] == session, "Supply session 1 then session 2")
        commits.append(method["revizor"])
        snapshot = path / "software" / "verify_arm64_timer.py"
        baseline_validator = git(REPO, "show", f"{BASELINE}:tools/verify_arm64_timer.py")
        require(snapshot.read_bytes() == baseline_validator,
                "Unverified validator snapshot; refuse to execute it")
        verify = validator(snapshot)
        require(sha(path / "software" / "verify_arm64_timer.py")
                == method["revizor"]["sources_sha256"]["tools/verify_arm64_timer.py"],
                "Validator drift")
        environment = json.loads((path / "software" / "environment.json").read_text())
        environments.append(environment)
        require(len(list((path / "raw").glob("*.stdout"))) == 40, "Wrong raw run count")
        for rep, cpu, loads in schedule(session):
            stem = path / "raw" / f"cpu-{cpu}-loads-{loads}-rep-{rep}"
            execution = json.loads(Path(str(stem) + ".execution.json").read_text())
            require(execution["state"] == "RETURNED" and execution["returncode"] == 0,
                    "Interrupted/failed trial")
            rows.extend(analyze_raw(Path(str(stem) + ".stdout").read_bytes(),
                                    execution["returncode"], cpu, loads, verify, environment))
    require(commits[0] == commits[1], "Execution/source revisions differ between sessions")
    require(environments[0]["uname"] == environments[1]["uname"]
            and environments[0]["page_size"] == environments[1]["page_size"]
            and all(environments[0]["cpus"][str(cpu)]["midr"]
                    == environments[1]["cpus"][str(cpu)]["midr"] for cpu in (0, 4)),
            "Target/kernel/core identity differs between sessions")
    save(output / "work-sensitivity.json", {
        "sessions": [str(path) for path in paths], "per_cpu": work_gate(rows),
        "observed_frequencies_hz": {str(cpu): sorted(
            {str(row["frequency_hz"]) for row in rows if row["cpu"] == cpu}) for cpu in (0, 4)},
        "g2_verdict": "PENDING identity/frequency/distribution review; "
                      "this is only the frozen work gate",
        "scope": "Larger loop work sensitivity; "
                 "cache latency/HTrace/held-out cache classification NOT APPLICABLE"})


def addendum(path, text, output):
    path = evidence_root(path)
    verify_manifest(path)
    save(output / "addendum.json", {
        "session": str(path), "manifest_sha256": sha(path / "SHA256SUMS"),
        "recorded_utc": now(), "note": text})


def offline_provenance(directory):
    """Record the current analysis driver separately from the original session identity."""
    software = directory / "software"
    software.mkdir()
    revision = provenance(REPO, LAUNCHER, software, "offline")
    snapshot = software / "g2-driver.sh"
    shutil.copyfile(LAUNCHER, snapshot)
    require(sha(snapshot) == revision["launcher_sha256"], "Analysis driver snapshot drift")


def arguments(argv):
    parser = argparse.ArgumentParser(prog=LAUNCHER.name, description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Preflight only; preserves diagnostics")
    mode.add_argument("--session", type=int, choices=(1, 2))
    mode.add_argument("--compare", nargs=2, type=Path, metavar=("SESSION1", "SESSION2"))
    mode.add_argument("--addendum", type=Path)
    parser.add_argument("--note")
    args = parser.parse_args(argv)
    if bool(args.note) != bool(args.addendum):
        parser.error("--note is required only with --addendum")
    return args


def main(argv):
    args = arguments(argv)
    require(os.geteuid() != 0, "Use an ordinary user")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    label = (f"M1-G2-S{args.session}" if args.session else "preflight" if args.check
             else "comparison" if args.compare else "addenda")
    directory = new_run(label)
    print(f"Output: {directory.parent}", flush=True)
    state, code, started = "STARTED", 0, now()
    save(directory / "session.json", {"state": state, "started_utc": started})
    install_signals()
    try:
        require(sys.version_info >= (3, 11), "Python 3.11 or newer required")
        if args.check:
            software = directory / "software"
            software.mkdir()
            provenance(REPO, LAUNCHER, software, "preflight")
            target(software)
            validator(REPO / "tools/verify_arm64_timer.py")
            prerequisites(software)
            state = "PREFLIGHT_ONLY; no measurements"
        elif args.session:
            state = collect(directory, args.session)
        elif args.compare:
            offline_provenance(directory)
            compare([path.resolve() for path in args.compare], directory)
            state = "OFFLINE_COMPARISON_ONLY"
        else:
            offline_provenance(directory)
            addendum(args.addendum.resolve(), args.note, directory)
            state = "ADDENDUM_ONLY"
    except (Exception, Interrupted) as error:
        code = 128 + error.number if isinstance(error, Interrupted) else 1
        state = ("INTERRUPTED/INCOMPLETE" if isinstance(error, Interrupted) else
                 "BLOCKED/INCOMPLETE" if isinstance(error, Blocked) else "FAILED/INCOMPLETE")
        save(directory / "failure.json", {"state": state, "reason": str(error), "exit": code})
        if not (directory / "notes-after.txt").exists():
            (directory / "notes-after.txt").write_text(
                "Unavailable after interrupted/blocked execution. "
                "Use a separate hashed addendum.\n")
        print(f"G2 STOPPED: {error}", file=sys.stderr)
    # Once sealing starts, later signals are recorded outside the sealed tree.
    with defer_signals():
        if LAST_SIGNAL is not None:
            code, state = 128 + LAST_SIGNAL, "INTERRUPTED/INCOMPLETE"
        save(directory / "session.json", {"state": state, "started_utc": started,
                                          "ended_utc": now(), "exit_before_sealing": code,
                                          "launcher_pid": os.getpid()})
        (directory / "STATUS.txt").write_text(state + "\n")
        signal_at_seal = LAST_SIGNAL
        try:
            archive = seal(directory)
        except Exception as error:
            code = 1
            # Keep the original tree/archive untouched even after a sealing failure.
            external_record(artifacts(directory)["failure"], {
                "state": "SEAL_FAILED", "reason": str(error), "recorded_utc": now()})
            print(f"Sealing failed; preserve {directory}: {error}", file=sys.stderr)
        else:
            print(f"Evidence: {directory}\nArchive: {archive}\nChecksum: {archive}.sha256")
        if LAST_SIGNAL != signal_at_seal:
            code = 128 + LAST_SIGNAL
        # Receipt is outside the immutable evidence set and written only once.
        external_record(artifacts(directory)["receipt"], {
            "actual_launcher_exit": code, "requested_signal": LAST_SIGNAL,
            "state": "INTERRUPTED_DURING_SEAL" if LAST_SIGNAL != signal_at_seal else state,
            "recorded_utc": now()})

    return code


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[2:]))
    except (Blocked, OSError, subprocess.SubprocessError) as error:
        print(f"G2 BLOCKED: {error}; no acceptance claimed", file=sys.stderr)
        sys.exit(1)
PY_G2
