"""Passive P0 packet preparation and compile/disassembly evidence; never runs the worker."""
# pylint: disable=missing-function-docstring
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tools import m1_g3_p0 as protocol  # noqa: E402  # pylint: disable=wrong-import-position

STRINGS = ("run_id", "session_id", "cohort_id", "target_id", "kernel_release", "source_commit",
           "source_sha256", "binary_sha256", "disassembly_sha256", "build_manifest_sha256",
           "frozen_calibration_sha256")
FLAGS = ("-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong",
         "-D_FORTIFY_SOURCE=2", "-static", "-Wl,-z,noexecstack,-z,relro,-z,now")
FILES = ("tools/exclusiveReservation/worker.c", "tools/exclusiveReservation/worker.h",
         "tools/exclusiveReservation/linux.c", "tools/exclusiveReservation/probe.S",
         "tools/m1_g3_p0.py", "tools/m1_g3_p0_native.py", "tools/README.m1-g3-p0.md",
         "tools/README.m1-g3-p0-worker.md", "tests/m1_g3_p0/host.c",
         "tests/unit_m1_g3_p0_worker.py")
NAMES = ("p0_adjacent", "p0_clear", "p0_sham", "p0_clear_old")


def packet(plan: dict[str, Any]) -> bytes:
    """Canonical bounded transfer of an independently saved/validated flat plan, no JSON in C."""
    protocol.validate_plan(plan)
    protocol.require(len(json.dumps(plan, ensure_ascii=True).encode()) <= 4096, "Plan too large")
    result = b'M1G3P0\0\1' + struct.pack('<5I', plan['cpu'], plan['seed'], plan['blocks'],
                                         int(plan['phase'] == 'held_out'),
                                         int(plan['evidence_kind'] == 'synthetic'))
    for name in STRINGS:
        text = b'' if plan[name] is None else plan[name].encode('utf-8')
        result += struct.pack('<H', len(text)) + text
    protocol.require(len(result) <= 1024, "Packet size bound")
    return result


def _code(binary: bytes, address: int, size: int) -> bytes:
    """Map an ELF64 AArch64 executable's function range into its actual saved bytes."""
    protocol.require(len(binary) >= 64 and binary[:6] == b'\x7fELF\x02\x01'
                     and struct.unpack_from('<HH', binary, 16) == (2, 183),
                     "Not AArch64 ELF64 LE executable")
    offset = struct.unpack_from('<Q', binary, 32)[0]
    width, count = struct.unpack_from('<HH', binary, 54)
    protocol.require(width == 56 and 0 < count <= 256 and offset + width * count <= len(binary),
                     "Invalid ELF program headers")
    matches = []
    for index in range(count):
        kind, flags, start, base, _, length, _, _ = struct.unpack_from(
            '<II6Q', binary, offset + width * index)
        protocol.require(kind != 3, "Interpreter segment in purported static executable")
        if kind == 0x6474e551:
            protocol.require(not flags & 1, "Executable GNU stack")
        if kind == 1 and flags & 1 and base <= address and address + size <= base + length:
            position = start + address - base
            protocol.require(position + size <= len(binary), "Function outside file")
            matches.append(binary[position:position + size])
    protocol.require(len(matches) == 1, "Ambiguous/missing executable function mapping")
    return matches[0]


def verify(binary: bytes, disassembly: str, symbols: str) -> dict[str, list[str]]:
    # pylint: disable=too-many-locals
    """GNU ELF only, fixed complete bodies, checking instruction words against ELF bytes.

    No generic decoder or physical-origin guarantee. Other dialects fail closed.
    """
    result = {}
    for name in NAMES:
        matches = re.findall(rf'^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+GLOBAL\s+'
                             rf'\S+\s+\S+\s+{name}\s*$', symbols, re.M)
        protocol.require(len(matches) == 1, f"Missing/duplicate ELF function {name}")
        start, size = int(matches[0][0], 16), int(matches[0][1])
        protocol.require(size > 0 and size % 4 == 0, "Invalid symbol size")
        code = _code(binary, start, size)
        instructions, words, addresses = [], [], []
        for line in disassembly.splitlines():
            match = re.fullmatch(r'\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+(.+)', line)
            if match and start <= int(match[1], 16) < start + size:
                addresses.append(int(match[1], 16))
                words.append(int(match[2], 16))
                value = re.sub(r'\s+', '', match[3]).lower()
                value = value.replace('#0x10', '#16')
                aliases = {'retx30': 'ret', 'clrex#0xf': 'clrex', 'clrex#15': 'clrex'}
                value = aliases.get(value, value)
                instructions.append(value)
        middle = ['clrex'] if name == 'p0_clear' else ['nop'] if name == 'p0_sham' else []
        expected = ['clrex', 'ret'] if name == 'p0_clear_old' else [
            'dmbish', 'ldxrx3,[x0]', *middle,
            'stxrw4,x1,[x0]', 'dmbish', 'ldrx5,[x0]', 'stpx3,x5,[x2]', 'strw4,[x2,#16]', 'ret']
        protocol.require(instructions == expected and size == 4 * len(expected),
                         f"Full function mismatch {name}: {instructions}")
        protocol.require(addresses == list(range(start, start + size, 4)), "Noncontiguous body")
        protocol.require(words == list(struct.unpack('<' + 'I' * len(words), code)),
                         "Disassembly does not match saved ELF instruction bytes")
        result[name] = instructions
    return result


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(directory: Path, cc: str, objdump: str, readelf: str, sysroot: str | None = None) -> None:
    """Build source snapshots, retain failed builds too; never execute output."""
    # pylint: disable=too-many-locals
    directory.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(args: list[str], label: str) -> bytes:
        commands.append(args)
        (directory / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        with (directory / f'{label}.stdout').open('xb') as out, \
                (directory / f'{label}.stderr').open('xb') as err:
            result = subprocess.run(args, stdout=out, stderr=err, timeout=90, check=False)
        (directory / f'{label}.exit').write_text(str(result.returncode) + '\n')
        protocol.require(result.returncode == 0, f'{label} failed; preserve {directory}')
        return (directory / f'{label}.stdout').read_bytes()

    status = {'state': 'STARTED', 'physical_execution': False}
    try:
        manifest = []
        for name in FILES:
            source, target = ROOT / name, directory / name
            protocol.require(not source.is_symlink(), "Source symlink rejected")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            manifest.append(f'{sha(target)}  {name}\n')
        (directory / 'source-manifest.sha256').write_text(''.join(sorted(manifest)))
        version = run([cc, '--version'], 'compiler-version').decode()
        objdump_version = run([objdump, '--version'], 'objdump-version').decode()
        readelf_version = run([readelf, '--version'], 'readelf-version').decode()
        linker = run([cc, '-print-prog-name=ld'], 'linker-path').decode().strip()
        linker_version = run([linker, '--version'], 'linker-version').decode()
        sources = directory / 'tools/exclusiveReservation'
        command = [cc, *FLAGS]
        if sysroot:
            command += ['--sysroot=' + sysroot, '-isystem',
                        sysroot + '/usr/aarch64-linux-gnu/include']
        command += ['-I' + str(sources), str(sources / 'worker.c'), str(sources / 'linux.c'),
                    str(sources / 'probe.S'), '-o', str(directory / 'worker')]
        run(command, 'compile')
        dump = run([objdump, '-d', '-w', str(directory / 'worker')], 'full-disassembly').decode()
        symbols = run([readelf, '-sW', str(directory / 'worker')], 'symbols').decode()
        run([readelf, '-hW', '-lW', str(directory / 'worker')], 'elf-metadata')
        checked = verify((directory / 'worker').read_bytes(), dump, symbols)
        (directory / 'assembly-verification.json').write_text(
            json.dumps(checked, indent=2) + '\n')
        git = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], timeout=10,
                             capture_output=True, check=True).stdout.decode().strip()
        dirty = subprocess.run(
            ['git', '-C', str(ROOT), 'status', '--porcelain=v1', '--untracked-files=all'],
            timeout=10, capture_output=True, check=True).stdout
        status.update(state='BUILT_AND_DISASSEMBLED', compiler=version, git_head=git,
                      tool_versions={'compiler': version, 'linker': linker_version,
                                     'objdump': objdump_version, 'readelf': readelf_version},
                      flags=list(FLAGS), commands=commands,
                      dirty_checkout=bool(dirty),
                      source_sha256=sha(directory / 'source-manifest.sha256'),
                      binary_sha256=sha(directory / 'worker'),
                      disassembly_sha256=sha(directory / 'full-disassembly.stdout'))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        status.update(state='FAILED', error=str(error))
        raise
    finally:
        (directory / 'build.json').write_text(
            json.dumps(status, sort_keys=True, separators=(',', ':')) + '\n')
        with (directory / 'SHA256SUMS').open('x') as out:
            for path in sorted(directory.rglob('*')):
                if path.is_file() and path.name != 'SHA256SUMS':
                    out.write(f'{sha(path)}  {path.relative_to(directory).as_posix()}\n')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    preparing = modes.add_parser('prepare')
    preparing.add_argument('--plan', type=Path, required=True)
    preparing.add_argument('--output', type=Path, required=True)
    compiling = modes.add_parser('build')
    compiling.add_argument('--output', type=Path, required=True)
    compiling.add_argument('--cc', default='aarch64-linux-gnu-gcc')
    compiling.add_argument('--objdump', default='aarch64-linux-gnu-objdump')
    compiling.add_argument('--readelf', default='aarch64-linux-gnu-readelf')
    compiling.add_argument('--sysroot')
    args = parser.parse_args()
    try:
        if args.mode == 'prepare':
            data = packet(protocol.read_json(args.plan))
            with args.output.open('xb') as out:
                out.write(data)
        else:
            build(args.output.resolve(), args.cc, args.objdump, args.readelf, args.sysroot)
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'P0 preparation failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
