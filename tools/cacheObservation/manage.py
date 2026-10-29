"""Native build/capture only. Never runs on x86, substitutes clocks, retries, or creates HTraces."""
# pylint: disable=missing-function-docstring
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.cacheObservation import disassembly, protocol

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parents[1]


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def sources():
    return {path.name: digest(path) for path in sorted(PACKAGE.iterdir())
            if path.suffix in (".c", ".S", ".h", ".py", ".md")}


def source_hash(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def native():
    protocol.require(os.geteuid() != 0, "Ordinary user required")
    system, machine = platform.system(), platform.machine().lower()
    protocol.require((system == "Linux" and machine == "aarch64")
                     or (system == "Darwin" and machine == "arm64"),
                     "Native AArch64 Linux/macOS only; no emulation fallback")
    return "linux" if system == "Linux" else "macos"


def clean_commit(directory):
    def git(*args):
        return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                              check=True, timeout=10).stdout
    status = git("status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none")
    (directory / "git-status.txt").write_bytes(status)
    (directory / "unstaged.patch").write_bytes(git("diff", "--binary"))
    (directory / "staged.patch").write_bytes(git("diff", "--cached", "--binary"))
    commit = git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    protocol.require(not status, "Dirty checkout: blocked; Git diagnostics retained")
    return commit


def context(cpu):
    result: dict[str, Any] = {
        "uname": list(platform.uname()), "python": sys.version, "core_identity": "unknown",
        "migration": "unknown unless pinned Linux checks pass"}
    if platform.system() == "Linux":
        result["allowed_cpus"] = sorted(os.sched_getaffinity(0))
        fields = {}
        cpus = [cpu] if cpu is not None else result["allowed_cpus"][:32]
        result["inventory_cpus"] = cpus
        result["inventory_truncated"] = cpu is None and len(result["allowed_cpus"]) > 32
        for identifier in cpus:
            base = Path(f"/sys/devices/system/cpu/cpu{identifier}")
            paths = [base / "regs/identification/midr_el1", base / "cpu_capacity"]
            paths += sorted((base / "cache").glob("index*/*"))[:96]
            for path in paths:
                if path.name in {"midr_el1", "cpu_capacity", "level", "type", "size",
                                 "coherency_line_size", "number_of_sets", "ways_of_associativity",
                                 "shared_cpu_list"}:
                    try:
                        with path.open() as file:
                            fields[str(path)] = file.read(512)
                    except OSError as error:
                        fields[str(path)] = str(error)
        result["cpu_metadata"] = fields
        result["os_release"] = Path("/etc/os-release").read_text()
    else:
        result["sw_vers"] = subprocess.run(["sw_vers"], capture_output=True, text=True,
                                           check=True, timeout=5).stdout
        for key in ("hw.model", "machdep.cpu.brand_string", "hw.cachelinesize"):
            query = subprocess.run(["sysctl", "-n", key], capture_output=True,
                                   text=True, check=False, timeout=5)
            result[key] = {"exit": query.returncode, "stdout": query.stdout, "stderr": query.stderr}
        result["affinity_policy"] = "unknown/uncontrolled; no QoS or pinning"
    return result


def build(directory):
    system = native()
    commit = clean_commit(directory)
    files = sources()
    for name in files:
        shutil.copyfile(PACKAGE / name, directory / name)
    compiler = "gcc" if system == "linux" else "clang"
    version = subprocess.run([compiler, "--version"], capture_output=True, text=True,
                             check=True, timeout=10).stdout
    if system == "macos":
        protocol.require("Apple clang" in version, "Apple clang required for this macOS build")
    command = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fno-lto"]
    if system == "macos":
        command += ["-arch", "arm64"]
    command += [str(PACKAGE / "pilot.c"), str(PACKAGE / "probe.S"),
                str(PACKAGE / f"platform_{system}.c"), "-o", str(directory / "g3a")]
    save(directory / "build-command.json", command)
    with (directory / "build.stdout").open("wb") as out, \
            (directory / "build.stderr").open("wb") as err:
        subprocess.run(command, check=True, stdout=out, stderr=err, timeout=60)
    macros = subprocess.run([compiler, "-dM", "-E", "-x", "c", "/dev/null"],
                            capture_output=True, text=True, check=True, timeout=10).stdout
    compiled_version = re.search(r'^#define __VERSION__ (".*")$', macros, re.M)
    if compiled_version is None:
        raise ValueError("Missing compiler macro version")
    tool = ["objdump", "-d"] if system == "linux" else ["otool", "-tvV"]
    dump = subprocess.run([*tool, str(directory / "g3a")], capture_output=True,
                          text=True, check=True, timeout=15).stdout
    (directory / "disassembly.txt").write_text(dump)
    disassembly.check(dump)
    protocol.require(files == sources() and commit == clean_commit(directory),
                     "Source changed during build")
    save(directory / "build.json", {
        "version": 1, "platform": system, "commit": commit, "source_files": files,
        "source_sha256": source_hash(files), "binary_sha256": digest(directory / "g3a"),
        "compiler": json.loads(compiled_version[1]), "compiler_version": version,
        "command": command, "context": context(None),
        "disassembly_sha256": digest(directory / "disassembly.txt"), "disassembly_checked": True,
    })


def capture(directory, args):
    system = native()
    commit = clean_commit(directory)
    built = protocol.read_json(args.build / "build.json")
    binary = args.build / "g3a"
    protocol.require(built["version"] == 1 and built["platform"] == system
                     and built["commit"] == commit and built["source_files"] == sources()
                     and built["source_sha256"] == source_hash(sources())
                     and built["binary_sha256"] == digest(binary)
                     and built["disassembly_checked"] is True
                     and built["disassembly_sha256"] == digest(args.build / "disassembly.txt"),
                     "Build/source/disassembly provenance mismatch")
    disassembly.check((args.build / "disassembly.txt").read_text())
    expected = {key: built[key] for key in ("platform", "commit", "binary_sha256",
                                            "source_sha256", "compiler")}
    expected.update(session=args.session, blocks=args.blocks, seed=args.seed,
                    prep_bytes=args.prep_bytes, stride=args.stride, selected_cpu=args.cpu,
                    page_size=os.sysconf("SC_PAGESIZE"), kernel=platform.release(),
                    machine=platform.machine())
    protocol.parameters(expected)
    command = [str(binary)]
    for key in ("session", "commit", "binary_sha256", "source_sha256", "blocks", "seed",
                "prep_bytes", "stride"):
        command += ["--" + key.replace("_", "-"), str(expected[key])]
    if args.cpu is not None:
        command += ["--cpu", str(args.cpu)]
    launch = {"expected": expected, "command": command, "context": context(args.cpu),
              "status": "started", "timeout": False, "returncode": None,
              "raw_sha256": None, "started_ns": time.time_ns(), "ended_ns": None}
    launch["context"]["host_label"] = args.host_label
    save(directory / "launch.json", launch)
    shutil.copyfile(args.build / "build.json", directory / "build.json")
    interrupted = False
    with (directory / "raw.jsonl").open("wb") as out, (directory / "stderr.txt").open("wb") as err:
        with subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True) as process:
            try:
                process.wait(timeout=20)
            except KeyboardInterrupt:
                interrupted = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            except subprocess.TimeoutExpired:
                launch["timeout"] = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                except ProcessLookupError:
                    process.wait()
            launch["returncode"] = process.returncode
    launch.update(status="interrupted" if interrupted else "finished", ended_ns=time.time_ns(),
                  raw_sha256=digest(directory / "raw.jsonl"))
    save(directory / "launch.json", launch)
    protocol.require(not interrupted, "Interrupted; completed raw output retained, no retry")
    protocol.require(built["binary_sha256"] == digest(binary) and built["source_files"] == sources()
                     and commit == clean_commit(directory), "Provenance changed during capture")
    validated = protocol.load_session(directory)
    save(directory / "validation.json", {key: validated[key] for key in (
        "protocol_valid", "physical_origin", "g3_accepted", "raw_sha256")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    compile_parser = commands.add_parser("build")
    compile_parser.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("capture")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--build", type=Path, required=True)
    run.add_argument("--session", required=True)
    run.add_argument("--host-label", required=True,
                     help="Recorded machine identity; not attestation")
    run.add_argument("--blocks", type=int, default=64)
    run.add_argument("--seed", type=int, required=True)
    run.add_argument("--prep-bytes", type=int, default=1048576)
    run.add_argument("--stride", type=int, default=128)
    run.add_argument("--cpu", type=int)
    args = parser.parse_args()
    directory = args.output.resolve()
    protocol.require(not directory.is_relative_to(ROOT), "Output must be outside the checkout")
    directory.mkdir(parents=True, exist_ok=False)  # Never replace a failed session.
    try:
        if args.action == "build":
            build(directory)
        else:
            capture(directory, args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        save(directory / "failure.json", {"status": "failed", "reason": str(error),
                                          "g3_accepted": False})
        print(f"FAILED; preserve {directory}: {error}", file=sys.stderr)
        return 1
    print(f"Artifacts retained: {directory}; G3 acceptance not assessed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
