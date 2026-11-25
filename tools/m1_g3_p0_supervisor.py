"""Single-session P0 supervisor. Native execution requires explicit reviewed admission.

Self-test builds only the separate synthetic backend. No imports launch experiments.
"""
# pylint: disable=missing-function-docstring,too-many-locals
import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import platform
import resource
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
# pylint: disable=wrong-import-position
from tools import experimental_environment as environment  # noqa: E402
from tools import m1_g3_p0 as p, m1_g3_p0_native as native  # noqa: E402

REQUIRE = p.require
SUPPORT = ('tools/m1_g3_p0_supervisor.py', 'tools/experimental_environment.py',
           'tools/README.m1-g3-p0-supervisor.md', 'tests/unit_m1_g3_p0_supervisor.py')
HASH_FIELDS = ('source_commit', 'source_sha256', 'binary_sha256',
               'disassembly_sha256', 'build_manifest_sha256')
MAX_FILE = 8 * 1024 * 1024
MAX_TREE = 24 * 1024 * 1024
MAX_FILES = 256
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def utc():
    return datetime.now(timezone.utc).isoformat()


def stamp(text):
    REQUIRE(isinstance(text, str), 'UTC timestamp required')
    result = datetime.fromisoformat(text)
    offset = result.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise p.VerificationError('UTC timestamp required')
    return result


def canonical(value):
    return (json.dumps(value, allow_nan=False, sort_keys=True,
                       separators=(',', ':')) + '\n').encode()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as out:
        out.write(canonical(value))


def bounded(path, limit=MAX_FILE):
    REQUIRE(not path.is_symlink() and path.is_file(), f'Regular file required: {path}')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    REQUIRE(len(data) <= limit, f'Oversized artifact: {path}')
    return data


def read_json(path, limit=16384):
    return p.decode(bounded(path, limit), limit)


def sha(path):
    return hashlib.sha256(bounded(path, MAX_TREE)).hexdigest()


def inventory(directory):
    result, total = {}, 0
    REQUIRE(not directory.is_symlink(), 'Evidence directory symlink')
    paths = list(islice(directory.rglob('*'), MAX_FILES * 2 + 1))
    REQUIRE(len(paths) <= MAX_FILES * 2, 'Evidence directory-entry bound')
    for path in sorted(paths):
        REQUIRE(not path.is_symlink(), 'Symlink in evidence')
        if path.is_file():
            name = path.relative_to(directory).as_posix()
            REQUIRE('\n' not in name and '\r' not in name, 'Unsafe artifact name')
            data = bounded(path)
            result[name] = hashlib.sha256(data).hexdigest()
            total += len(data)
            REQUIRE(len(result) <= MAX_FILES and total <= MAX_TREE, 'Evidence tree bound')
    return result


def verify_manifest(directory):
    entries = {}
    for line in bounded(directory / 'SHA256SUMS', 65536).decode().splitlines():
        digest, name = line.split('  ', 1)
        p.digest(digest)
        REQUIRE(name not in entries, 'Duplicate manifest path')
        entries[name] = digest
    actual = inventory(directory)
    actual.pop('SHA256SUMS')
    REQUIRE(entries == actual, 'Manifest checksum/inventory mismatch')
    return entries


def verify_archive(directory, archive):
    REQUIRE(archive.stat().st_size <= MAX_TREE, 'Archive size bound')
    expected = inventory(directory)
    observed: dict[str, str] = {}
    seen = set()
    total = 0
    with tarfile.open(archive, 'r:gz') as packed:
        for member in packed:
            prefix = directory.name + '/'
            REQUIRE(member.name == directory.name or member.name.startswith(prefix),
                    'Wrong archive prefix')
            REQUIRE(not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
                    and member.name not in seen, 'Unsafe/duplicate archive path')
            seen.add(member.name)
            REQUIRE(len(seen) <= MAX_FILES * 2, 'Archive member bound')
            if member.isdir():
                continue
            REQUIRE(member.isfile() and member.size <= MAX_FILE, 'Unsafe archive member')
            REQUIRE(member.name.startswith(prefix), 'Wrong archive prefix')
            name = member.name[len(prefix):]
            REQUIRE(name in expected and name not in observed, 'Extra/duplicate archive path')
            total += member.size
            REQUIRE(total <= MAX_TREE and len(observed) < MAX_FILES, 'Archive expansion bound')
            stream = packed.extractfile(member)
            if stream is None:
                raise p.VerificationError('Missing archive data')
            with stream:
                observed[name] = hashlib.sha256(stream.read(MAX_FILE + 1)).hexdigest()
    REQUIRE(observed == expected, 'Archive contents differ from evidence')


def checked_git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, timeout=10,
                          capture_output=True).stdout


def provenance(repo, destination, plan):
    """Save diagnostics first; reject dirty, uncommitted or drifted source."""
    destination.mkdir(parents=True)
    diagnostics = [
        ('status', ('status', '--porcelain=v1', '--untracked-files=all',
                    '--ignore-submodules=none')),
        ('unstaged.patch', ('diff', '--binary')),
        ('staged.patch', ('diff', '--cached', '--binary'))]
    for label, command in diagnostics:
        (destination / ('git-' + label)).write_bytes(checked_git(repo, *command))
    head = checked_git(repo, 'rev-parse', 'HEAD').decode().strip()
    save(destination / 'revision.json', {'head': head})
    REQUIRE(not (destination / 'git-status').read_bytes(), 'Clean committed checkout required')
    REQUIRE(head == plan['source_commit'], 'Plan must identify current committed revision')
    names = sorted(set(native.FILES + SUPPORT))
    hashes = {}
    for name in names:
        data = bounded(repo / name)
        REQUIRE(data == checked_git(repo, 'show', f'HEAD:{name}'), 'Uncommitted source: ' + name)
        hashes[name] = hashlib.sha256(data).hexdigest()
        snapshot = destination / 'sources' / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(data)
    lines = sorted(f'{digest}  {name}\n' for name, digest in hashes.items())
    manifest = destination / 'supervisor-source-manifest.sha256'
    manifest.write_text(''.join(lines))
    return {'head': head, 'sources': hashes, 'supervisor_sources_sha256': sha(manifest)}


def verify_build(build, plan, approval, repo):
    """Verify saved artifacts without building or executing them."""
    p.validate_plan(plan)
    p.fields(approval, ['schema_version', 'protocol', *HASH_FIELDS])
    REQUIRE(p.integer(approval['schema_version']) == 1 and approval['protocol'] == p.PROTOCOL,
            'Unsupported independent approval')
    REQUIRE(all(approval[k] == plan[k] for k in HASH_FIELDS), 'Approval/plan mismatch')
    verify_manifest(build)
    record = read_json(build / 'build.json', 65536)
    REQUIRE(bounded(build / 'build.json', 65536) == canonical(record), 'Noncanonical build record')
    REQUIRE(record['state'] == 'BUILT_AND_DISASSEMBLED' and record['dirty_checkout'] is False
            and record['physical_execution'] is False, 'Clean compile-only build required')
    REQUIRE(record['git_head'] == plan['source_commit'], 'Build revision mismatch')
    for field, filename in (('source_sha256', 'source-manifest.sha256'),
                            ('binary_sha256', 'worker'),
                            ('disassembly_sha256', 'full-disassembly.stdout'),
                            ('build_manifest_sha256', 'build.json')):
        REQUIRE(sha(build / filename) == plan[field], 'Artifact hash mismatch: ' + filename)
        if field != 'build_manifest_sha256':
            REQUIRE(record[field] == plan[field], 'Build manifest provenance mismatch')
    raw_manifest = bounded(build / 'source-manifest.sha256', 65536)
    REQUIRE(raw_manifest == b''.join(sorted(raw_manifest.splitlines(keepends=True))),
            'Noncanonical source manifest')
    entries = {}
    for line in raw_manifest.decode().splitlines():
        digest, name = line.split('  ', 1)
        p.digest(digest)
        REQUIRE(name in native.FILES and name not in entries, 'Unknown/duplicate build source')
        REQUIRE(sha(build / name) == digest and sha(repo / name) == digest,
                'Source snapshot mismatch: ' + name)
        entries[name] = digest
    REQUIRE(set(entries) == set(native.FILES), 'Missing build source')
    REQUIRE(record['commands'] == read_json(build / 'commands.json', 65536), 'Command drift')
    REQUIRE(record['flags'] == list(native.FLAGS), 'Unexpected compiler flags')
    commands = record['commands']
    for label in ('compiler-version', 'linker-version', 'objdump-version', 'readelf-version',
                  'linker-path', 'compile', 'full-disassembly', 'symbols', 'elf-metadata'):
        REQUIRE(bounded(build / (label + '.exit'), 16) == b'0\n', 'Unsuccessful build command')
        bounded(build / (label + '.stdout'))
        bounded(build / (label + '.stderr'))
    for tool in ('compiler', 'linker', 'objdump', 'readelf'):
        REQUIRE(record['tool_versions'][tool] ==
                bounded(build / (tool + '-version.stdout')).decode(), 'Tool version drift')
    REQUIRE(record['compiler'] == record['tool_versions']['compiler'] and record['compiler'],
            'Missing compiler identity')
    REQUIRE(len(commands) == 9 and all(isinstance(cmd, list) and cmd for cmd in commands),
            'Unexpected build commands')
    verify_commands(commands, bounded(build / 'linker-path.stdout').decode().strip())
    actual = native.verify(bounded(build / 'worker'),
                           bounded(build / 'full-disassembly.stdout').decode(),
                           bounded(build / 'symbols.stdout').decode())
    REQUIRE(read_json(build / 'assembly-verification.json') == actual,
            'Assembly verification report mismatch')
    return record


def verify_commands(commands, linker):
    """Recognize only the existing passive builder's fixed compiler/disassembler recipe."""
    cc, objdump, readelf = commands[0][0], commands[1][0], commands[2][0]
    REQUIRE(commands[:5] == [[cc, '--version'], [objdump, '--version'], [readelf, '--version'],
                             [cc, '-print-prog-name=ld'], [linker, '--version']],
            'Unexpected compiler/tool identity commands')
    compile_command = commands[5]
    prefix = [cc, *native.FLAGS]
    REQUIRE(compile_command[:len(prefix)] == prefix, 'Compile recipe/flags mismatch')
    tail = compile_command[len(prefix):]
    if tail and tail[0].startswith('--sysroot='):
        sysroot = tail[0].split('=', 1)[1]
        REQUIRE(tail[:3] == ['--sysroot=' + sysroot, '-isystem',
                             sysroot + '/usr/aarch64-linux-gnu/include'], 'Unexpected sysroot')
        tail = tail[3:]
    REQUIRE(len(tail) == 6, 'Unexpected compile inputs')
    sources = Path(tail[1]).parent
    binary = str(sources.parent.parent / 'worker')
    REQUIRE(tail == ['-I' + str(sources), str(sources / 'worker.c'), str(sources / 'linux.c'),
                     str(sources / 'probe.S'), '-o', binary], 'Unexpected source/output paths')
    REQUIRE(commands[6:] == [[objdump, '-d', '-w', binary], [readelf, '-sW', binary],
                             [readelf, '-hW', '-lW', binary]], 'Unexpected verification commands')


def _os_release(root=Path('/')):
    """Read the fixed OS identity location, not an arbitrary artifact symlink.

    root is only for private filesystem fixtures; target() always uses '/'.
    Vendor symlink chains and unexpected directory links fail closed.
    """
    def signature(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns)

    directories = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    files = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with ExitStack() as cleanup:
        def opened(name, flags, parent=None):
            descriptor = os.open(name, flags, dir_fd=parent)
            cleanup.callback(os.close, descriptor)
            return descriptor

        anchor = opened(root, directories)
        etc = opened('etc', directories, anchor)
        before = os.stat('os-release', dir_fd=etc, follow_symlinks=False)
        link = None
        parent = etc
        selected = before
        if stat.S_ISLNK(before.st_mode):
            link = os.readlink('os-release', dir_fd=etc)
            REQUIRE(link in ('../usr/lib/os-release', '/usr/lib/os-release'),
                    'Unexpected /etc/os-release symlink target')
            usr = opened('usr', directories, anchor)
            parent = opened('lib', directories, usr)
            selected = os.stat('os-release', dir_fd=parent, follow_symlinks=False)
        REQUIRE(stat.S_ISREG(selected.st_mode), 'Regular OS release target required')
        descriptor = opened('os-release', files, parent)
        metadata = os.fstat(descriptor)
        REQUIRE(stat.S_ISREG(metadata.st_mode), 'Regular OS release target required')
        REQUIRE(signature(selected) == signature(metadata), 'OS release changed before open')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(4097)
        REQUIRE(len(data) <= 4096, 'Oversized OS release')
        REQUIRE(signature(metadata) == signature(os.fstat(descriptor)),
                'OS release changed during read')
        REQUIRE(signature(metadata) == signature(
            os.stat('os-release', dir_fd=parent, follow_symlinks=False)),
            'OS release target path changed')
        REQUIRE(signature(before) == signature(
            os.stat('os-release', dir_fd=etc, follow_symlinks=False)),
            '/etc/os-release changed during read')
        if link is not None:
            REQUIRE(os.readlink('os-release', dir_fd=etc) == link,
                    '/etc/os-release link changed during read')
        return data


def target(plan):
    """Non-measurement identity reads only. Does not execute the worker."""
    identity = {'system': platform.system(), 'architecture': platform.machine(),
                'page_size': os.sysconf('SC_PAGESIZE'), 'kernel_release': platform.release(),
                'allowed_cpus': sorted(os.sched_getaffinity(0)),
                'os_release': _os_release().decode(),
                'compatible': bounded(Path('/proc/device-tree/compatible'), 4096)
                .decode().rstrip('\0').split('\0'), 'cpus': {}}
    for cpu in (0, 4):
        base = Path(f'/sys/devices/system/cpu/cpu{cpu}')
        identity['cpus'][str(cpu)] = {
            'midr': bounded(base / 'regs/identification/midr_el1', 128).decode().strip(),
            'core_type': 'Icestorm' if cpu == 0 else 'Firestorm'}
    check_identity(identity, plan, os.geteuid())
    # Availability check only: no worker instructions and no timer/PMU accesses.
    os.close(os.pidfd_open(os.getpid()))
    resource.prlimit(os.getpid(), resource.RLIMIT_CPU)  # Availability read only.
    return identity


def check_identity(identity, plan, euid):
    REQUIRE(euid != 0 and identity['system'] == 'Linux' and
            identity['architecture'] == 'aarch64' and sys.byteorder == 'little',
            'Unprivileged native AArch64 Linux required')
    REQUIRE(identity['page_size'] == p.PAGE and 'apple,t8103' in identity['compatible'],
            'M1/T8103 16 KiB target required')
    REQUIRE(identity['kernel_release'] == plan['kernel_release'] and
            plan['cpu'] in identity['allowed_cpus'], 'Kernel/allowed CPU mismatch')
    release = {}
    for line in identity['os_release'].splitlines():
        key, sep, value = line.partition('=')
        if sep and key in ('ID', 'VERSION_ID', 'ID_LIKE'):
            REQUIRE(key not in release, 'Duplicate OS field')
            words = shlex.split(value)
            REQUIRE(len(words) == 1, 'Invalid OS field')
            release[key] = words[0]
    REQUIRE(release.get('ID') == 'fedora-asahi-remix' and release.get('VERSION_ID') == '45'
            and 'fedora' in release.get('ID_LIKE', '').split(), 'Fedora Asahi Remix 45 required')
    REQUIRE(all(int(identity['cpus'][str(cpu)]['midr'], 16) == int(midr, 16)
                for cpu, midr in p.MIDRS.items()), 'M1 MIDR mismatch')


class Interrupted(RuntimeError):
    """Record an interrupt/deadline and preserve evidence before returning failure."""


class Signals:
    """SIGALRM is an outer worker watchdog, independent of the pidfd deadline."""
    def __init__(self):
        self.number = 0
        self.timed_out = False
        self.received: list[int] = []
        self.deferred = False
        self.previous: dict[int, Any] = {}

    def handler(self, number, _frame):
        self.number = number
        self.received.append(number)
        if number == signal.SIGALRM:
            self.timed_out = True
        if not self.deferred:
            raise Interrupted(f'Supervisor signal {number}')

    def __enter__(self):
        REQUIRE(threading.active_count() == 1, 'Single-threaded supervisor required')
        REQUIRE(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
                'Supervisor must own child reaping; default SIGCHLD required')
        REQUIRE(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
                'Existing process timer would conflict with watchdog')
        for number in (*STOP_SIGNALS, signal.SIGALRM):
            self.previous[number] = signal.signal(number, self.handler)
        return self

    def __exit__(self, *_args):
        signal.setitimer(signal.ITIMER_REAL, 0)
        for number, previous in self.previous.items():
            signal.signal(number, previous)


def wait_exit(process, pidfd, seconds):
    """One blocking kernel exit notification; no stdout/telemetry polling."""
    if not select.select([pidfd], [], [], seconds)[0]:
        return False
    process.wait()
    return True


def terminate(process, pidfd, events=None):
    if events is None:
        events = []
    for number in (signal.SIGTERM, signal.SIGKILL):
        event = {'signal': number, 'requested_utc': utc(), 'sent': False,
                 'reaped': False, 'error': None}
        events.append(event)
        try:
            os.killpg(process.pid, number)
            event['sent'] = True
        except ProcessLookupError as error:
            # An interrupted constructor may not yet have established the new session.
            # The direct child PID remains owned/unreaped; never guess a group or PID.
            event['group_error'] = str(error)
            event['pid_fallback'] = True
            try:
                os.kill(process.pid, number)
                event['sent'] = True
            except OSError as direct_error:
                event['error'] = f'{type(direct_error).__name__}: {direct_error}'
        except OSError as error:
            event['error'] = f'{type(error).__name__}: {error}'
        try:
            if pidfd is not None:
                event['reaped'] = wait_exit(process, pidfd, p.KILL_SECONDS)
            else:
                # Cleanup-only fallback when pidfd acquisition failed. Never telemetry.
                process.wait(timeout=p.KILL_SECONDS)
                event['reaped'] = True
        except (OSError, subprocess.SubprocessError) as error:
            event['error'] = f'{type(error).__name__}: {error}'
        if event['reaped']:
            return True
    return False


class OwnedProcess(subprocess.Popen):
    """Register ownership before Popen initialization can create a child or be interrupted."""
    def __init__(self, owner, *args, **kwargs):
        owner.append(self)
        super().__init__(*args, **kwargs)


def configure_child(pid, cpu, record):
    """Parent-only policy changes while the reviewed worker is held before plan decoding."""
    record.update(verified=False, limits=[], affinity=None)
    for label, which, ceiling in (('cpu', resource.RLIMIT_CPU, p.CPU_SECONDS),
                                  ('file', resource.RLIMIT_FSIZE, p.MAX_BYTES),
                                  ('core', resource.RLIMIT_CORE, 0)):
        record['stage'] = 'prlimit-' + label
        soft, hard = resource.prlimit(pid, which)
        bounded_soft = ceiling if soft == resource.RLIM_INFINITY else min(soft, ceiling)
        bounded_hard = ceiling if hard == resource.RLIM_INFINITY else min(hard, ceiling)
        item = {'resource': label, 'before': [soft, hard],
                'requested': [bounded_soft, bounded_hard], 'after': None}
        record['limits'].append(item)
        resource.prlimit(pid, which, (bounded_soft, bounded_hard))
        after = resource.prlimit(pid, which)
        item['after'] = list(after)
        REQUIRE(after == (bounded_soft, bounded_hard), 'Child limit verification failed: ' + label)
    if cpu is not None:
        record['stage'] = 'affinity'
        os.sched_setaffinity(pid, {cpu})
        mask = sorted(os.sched_getaffinity(pid))
        record['affinity'] = mask
        REQUIRE(mask == [cpu], 'Child affinity verification failed')
    record.update(stage='configured', verified=True)


def supervise(binary, packet, plan, directory, signals, *, synthetic=False, fault=None,
              approved=False):
    """Exactly one direct child. Synthetic packets can never enable the native backend."""
    # Popen.__exit__ could wait without a bound on an unknown child: use explicit lifecycle.
    # pylint: disable=too-many-statements,too-many-branches,consider-using-with
    REQUIRE(threading.active_count() == 1, 'Single-threaded fork/exec required')
    REQUIRE(plan['evidence_kind'] == ('synthetic' if synthetic else 'physical'), 'Wrong backend')
    if not synthetic:
        native_gate(plan, approved)
    REQUIRE(packet == native.packet(plan), 'Packet differs from independent plan')
    directory.mkdir(parents=True)
    (directory / 'input.bin').write_bytes(packet)
    execution: dict[str, Any] = {
        'returncode': None, 'timed_out': False, 'signal': 0, 'worker_pid': None, 'wall_ns': 0}
    save(directory / 'execution-started.json', execution)
    process = pidfd = None
    owner: list[Any] = []
    detail = {'started_utc': utc(), 'finished_utc': None, 'reaped': False,
              'state': 'STARTED', 'requested_signal': None, 'error': None,
              'termination_attempts': [],
              'startup': {'spawn_attempted': False, 'constructor_returned': False,
                          'verified': False, 'packet_released': False,
                          'packet_release_state': 'not_attempted'},
              'command': ['/proc/self/fd/<verified-fd>'], 'binary_sha256': sha(binary)}
    started = time.monotonic_ns()
    read_fd = write_fd = -1
    command = ['/proc/self/fd/<verified-fd>']
    try:
        signals.deferred = False
        if signals.number:
            raise Interrupted(f'Signal before startup: {signals.number}')
        signal.setitimer(signal.ITIMER_REAL, p.OUTER_SECONDS)
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        with binary.open('rb') as executable, \
                (directory / 'stdout.jsonl').open('xb') as out, \
                (directory / 'stderr.txt').open('xb') as err:
            executable_bytes = executable.read(MAX_FILE + 1)
            REQUIRE(len(executable_bytes) <= MAX_FILE, 'Executable size bound')
            actual_hash = hashlib.sha256(executable_bytes).hexdigest()
            REQUIRE(actual_hash == plan['binary_sha256'], 'Opened executable hash mismatch')
            detail['binary_sha256'] = actual_hash
            executable.seek(0)
            env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
            if synthetic and fault:
                env['P0_HOST_FAULT'] = fault
            command = ['/proc/self/fd/' + str(executable.fileno())]
            detail['command'] = command.copy()
            detail['startup']['spawn_attempted'] = True
            process = OwnedProcess(
                owner, command, stdin=read_fd, stdout=out, stderr=err,
                start_new_session=True, pass_fds=(executable.fileno(),), env=env)
            detail['startup']['constructor_returned'] = True
            execution['worker_pid'] = process.pid
            pidfd = os.pidfd_open(process.pid)
            pipe_to_close, read_fd = read_fd, -1
            os.close(pipe_to_close)
            save(directory / 'spawn.json', {'worker_pid': process.pid,
                 'started_utc': detail['started_utc'], 'recorded_utc': utc(),
                 'command': command, 'binary_sha256': detail['binary_sha256'],
                 'trial_release': 'after parent configuration; packet pipe still empty'})
            if wait_exit(process, pidfd, 0):
                detail['reaped'] = True
                raise ChildProcessError('Child exited before initialization/packet release')
            configure_child(process.pid, None if synthetic else plan['cpu'], detail['startup'])
            if wait_exit(process, pidfd, 0):
                detail['reaped'] = True
                raise ChildProcessError('Child exited during initialization; packet not released')
            save(directory / 'initialized.json', {'worker_pid': process.pid, 'recorded_utc': utc(),
                 'configuration': detail['startup'].copy(), 'packet_released': False})
            if signals.number:
                raise Interrupted(f'Signal during startup: {signals.number}')
            remaining = p.WALL_SECONDS - (time.monotonic_ns() - started) / 1e9
            if remaining <= 0:
                execution['timed_out'] = True
                raise TimeoutError('Ten-second worker deadline before packet release')
            # A signal can arrive after the kernel write but before Python records its return.
            # Retain uncertainty rather than claiming that no trials could have started.
            detail['startup'].update(packet_released=None, packet_release_state='attempting')
            REQUIRE(os.write(write_fd, packet) == len(packet), 'Short packet-pipe write')
            detail['startup']['packet_released'] = True
            detail['startup']['packet_release_state'] = 'released'
            pipe_to_close, write_fd = write_fd, -1
            os.close(pipe_to_close)
            remaining = max(0, p.WALL_SECONDS - (time.monotonic_ns() - started) / 1e9)
            if not wait_exit(process, pidfd, remaining):
                execution['timed_out'] = True
                raise TimeoutError('Ten-second worker timeout')
            detail['reaped'] = True
            execution['returncode'] = process.returncode if detail['reaped'] else None
    except (OSError, ValueError, TimeoutError, Interrupted, subprocess.SubprocessError) as error:
        detail['error'] = f'{type(error).__name__}: {error}'
        if process is not None and detail['reaped']:
            execution['returncode'] = process.returncode
    finally:
        # Only cleanup/preservation defer exceptions. Startup always remains interruptible.
        signals.deferred = True
        if process is None and owner:
            process = owner[0]
        pid = getattr(process, 'pid', None)
        if isinstance(pid, int) and pid > 0:
            execution['worker_pid'] = pid
            if getattr(process, 'returncode', None) is not None:
                detail['reaped'] = True
            elif not detail['reaped']:
                try:
                    # Popen/wait may have reaped a failed child just before interruption.
                    # Confirm waitability without reaping before any PID-based signal.
                    os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    owned = True
                except OSError as error:
                    owned = False
                    detail['ownership_error'] = str(error)
                if owned and pidfd is None:
                    try:
                        pidfd = os.pidfd_open(pid)
                    except OSError as error:
                        detail['pidfd_error'] = str(error)
                if owned:
                    detail['reaped'] = terminate(process, pidfd, detail['termination_attempts'])
            if detail['reaped']:
                execution['returncode'] = getattr(process, 'returncode', None)
        elif not detail['startup']['spawn_attempted']:
            detail['reaped'] = True  # No constructor was called; no child can exist.
        signal.setitimer(signal.ITIMER_REAL, 0)
        if pidfd is not None:
            os.close(pidfd)
        if write_fd >= 0:
            os.close(write_fd)
        if read_fd >= 0:
            os.close(read_fd)
        execution['wall_ns'] = time.monotonic_ns() - started
        code = execution['returncode']
        execution['signal'] = -int(code) if isinstance(code, int) and code < 0 else 0
        if signals.timed_out:
            execution['timed_out'] = True
        detail.update(finished_utc=utc(), requested_signal=signals.number or None,
                      parent_signals=signals.received.copy(),
                      state='RETURNED' if detail['reaped'] else 'TERMINATION_UNKNOWN')
        if execution['worker_pid'] is None:
            detail['state'] = ('STARTUP_UNKNOWN' if detail['startup']['spawn_attempted']
                               else 'SPAWN_FAILED')
        if pid is not None and not (directory / 'spawn.json').exists():
            recovered = {'worker_pid': pid, 'recorded_utc': utc(), 'command': command,
                         'recorded_during_cleanup': True,
                         'binary_sha256': detail['binary_sha256'],
                         'packet_released': detail['startup']['packet_released']}
            save(directory / 'spawn.json', recovered)
        save(directory / 'execution.json', execution)
        save(directory / 'supervision.json', detail)
    return execution, detail


@contextmanager
def session_lock(root):
    root.mkdir(parents=True, exist_ok=True)
    with (root / '.supervisor.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        REQUIRE(not (root / '.active-worker.json').exists(),
                'Previous child termination not established; manual review required')
        yield


def claim(root, plan):
    """Enforce launch order without launching any predecessor or pooling observations."""
    p.validate_plan(plan)
    calibration = [('calibration', 4, 101), ('calibration', 0, 101),
                   ('calibration', 0, 102), ('calibration', 4, 102)]
    held_out = [('held_out', 4, 201), ('held_out', 0, 201),
                ('held_out', 0, 202), ('held_out', 4, 202)]
    order = calibration + held_out
    position = order.index((plan['phase'], plan['cpu'], plan['seed']))
    for phase, cpu, seed in order[:position]:
        key = f"slot-{plan['cohort_id']}-{phase}-{cpu}-{seed}"
        previous = p.read_json(root / '.claims' / key / 'launch.json')
        p.validate_plan(previous)
        REQUIRE((previous['phase'], previous['cpu'], previous['seed']) == (phase, cpu, seed),
                'Predecessor slot identity mismatch')
        _, _, checked, _ = verified_session(root / previous['run_id'])
        shared = (*HASH_FIELDS, 'kernel_release', 'blocks',
                  'cohort_id', 'target_id', 'evidence_kind')
        REQUIRE(checked == previous and all(previous[k] == plan[k] for k in shared),
                'Predecessor session failed or has incompatible provenance')
    for key in ('session-' + plan['session_id'],
                f"slot-{plan['cohort_id']}-{plan['phase']}-{plan['cpu']}-{plan['seed']}"):
        path = root / '.claims' / key
        path.parent.mkdir(exist_ok=True)
        path.mkdir()  # Permanent non-overwriting claim, even when a launch fails.
        save(path / 'launch.json', plan)


def environment_snapshot(directory, phase):
    started, before = utc(), time.monotonic_ns()
    try:
        value = environment.snapshot(seconds=2)
        REQUIRE(len(canonical(value)) <= p.MAX_BYTES, 'Oversized environment snapshot')
    except (OSError, ValueError) as error:
        value = {'status': 'UNAVAILABLE', 'error': str(error)}
    save(directory / ('environment-' + phase + '.json'), value)
    save(directory / ('environment-' + phase + '-timing.json'),
         {'started_utc': started, 'finished_utc': utc(),
          'wall_ns': time.monotonic_ns() - before, 'measurement_activity': False})


def seal(directory):
    entries = inventory(directory)
    REQUIRE('SHA256SUMS' not in entries, 'Already sealed')
    with (directory / 'SHA256SUMS').open('x') as out:
        out.write(''.join(f'{digest}  {name}\n' for name, digest in entries.items()))
    verify_manifest(directory)
    for path in directory.rglob('*'):
        path.chmod(0o500 if path.is_dir() else 0o400)
    directory.chmod(0o500)
    archive = directory.parent / 'evidence.tar.gz'
    with tarfile.open(archive, 'x:gz') as packed:
        packed.add(directory, arcname=directory.name)
    verify_archive(directory, archive)
    with Path(str(archive) + '.sha256').open('x') as out:
        out.write(sha(archive) + '  ' + archive.name + '\n')
    return archive


def verified_session(container):
    REQUIRE(not container.is_symlink(), 'Calibration container symlink')
    directory = container / 'evidence'
    verify_manifest(directory)
    receipt = read_json(container / 'receipt.json')
    REQUIRE(bounded(container / 'receipt.json.sha256', 256).decode() ==
            sha(container / 'receipt.json') + '  receipt.json\n', 'Receipt checksum mismatch')
    REQUIRE(p.integer(receipt['actual_launcher_exit']) == 0 and receipt['signal'] is None and
            receipt['state'] == 'VALIDATED', 'Unsuccessful/interrupted calibration')
    REQUIRE(not (container / 'seal-failure.json').exists(), 'Calibration sealing failed')
    archive = container / 'evidence.tar.gz'
    REQUIRE(receipt['archive_sha256'] == sha(archive) and
            bounded(Path(str(archive) + '.sha256'), 256).decode() ==
            sha(archive) + '  evidence.tar.gz\n', 'Calibration archive checksum mismatch')
    verify_archive(directory, archive)
    plan = p.read_json(directory / 'plan/launch.json')
    execution = p.read_json(directory / 'raw/execution.json')
    raw = bounded(directory / 'raw/stdout.jsonl', p.MAX_BYTES)
    report = p.validate_output(raw, execution, plan)
    REQUIRE(report == read_json(directory / 'analysis/validation.json'), 'Calibration report drift')
    return raw, execution, plan, receipt


def frozen_calibration(path, plan, root, supervisor_hash, approval_hash, launched_utc):
    """Supplementary freeze schema; never changes the established launch-plan schema."""
    raw = bounded(path, 16384)
    freeze = p.decode(raw, 16384)
    REQUIRE(raw == canonical(freeze), 'Frozen manifest must use canonical bytes')
    REQUIRE(hashlib.sha256(raw).hexdigest() == plan['frozen_calibration_sha256'],
            'Frozen calibration digest mismatch')
    freeze_fields = ['schema_version', 'protocol', 'phase', 'cpu', 'cohort_id', 'target_id',
                     'kernel_release', 'blocks', 'provenance', 'supervisor_sources_sha256',
                     'approval_sha256', 'frozen_utc', 'decision', 'calibration', 'held_out']
    p.fields(freeze, freeze_fields)
    REQUIRE(p.integer(freeze['schema_version']) == 1 and freeze['protocol'] == p.PROTOCOL
            and freeze['phase'] == 'calibration' and freeze['decision'] == 'REVIEWED_PROCEED',
            'Unreviewed/unsupported calibration freeze')
    for key in ('cpu', 'cohort_id', 'target_id', 'kernel_release', 'blocks'):
        REQUIRE(type(freeze[key]) is type(plan[key]) and freeze[key] == plan[key],
                'Frozen cohort/core/target/geometry mismatch')
    REQUIRE(freeze['provenance'] == {k: plan[k] for k in HASH_FIELDS}
            and freeze['supervisor_sources_sha256'] == supervisor_hash
            and freeze['approval_sha256'] == approval_hash, 'Frozen software provenance mismatch')
    REQUIRE(stamp(freeze['frozen_utc']) < stamp(launched_utc), 'Freeze must precede launch')
    REQUIRE(isinstance(freeze['held_out'], list) and len(freeze['held_out']) == 2,
            'Need two prospectively identified held-out sessions for this core')
    for item in freeze['held_out']:
        p.fields(item, ['run_id', 'session_id', 'seed'])
        probe = {**plan, **item}
        p.validate_plan(probe)
    REQUIRE({row['seed'] for row in freeze['held_out']} == set(p.SEEDS['held_out']) and
            all(len({row[key] for row in freeze['held_out']}) == 2
                for key in ('run_id', 'session_id')), 'Duplicate held-out identity')
    REQUIRE({k: plan[k] for k in ('run_id', 'session_id', 'seed')} in freeze['held_out'],
            'Held-out session not prospectively frozen')
    REQUIRE(isinstance(freeze['calibration'], list) and len(freeze['calibration']) == 2,
            'Need two calibration launches for this core')
    sessions = []
    for item in freeze['calibration']:
        p.fields(item, ['run_id', 'evidence_manifest_sha256',
                        'receipt_sha256', 'archive_sha256'])
        REQUIRE(re_token(item['run_id']), 'Invalid calibration run path')
        container = root / item['run_id']
        artifacts = (('evidence_manifest_sha256', 'evidence/SHA256SUMS'),
                     ('receipt_sha256', 'receipt.json'), ('archive_sha256', 'evidence.tar.gz'))
        for key, name in artifacts:
            p.digest(item[key])
            REQUIRE(sha(container / name) == item[key], 'Frozen calibration artifact drift')
        raw_session, execution, previous, receipt = verified_session(container)
        REQUIRE(previous['run_id'] == item['run_id'] and
                previous['evidence_kind'] == plan['evidence_kind'], 'Calibration identity mismatch')
        REQUIRE(stamp(receipt['started_utc']) <= stamp(receipt['finished_utc']) <
                stamp(freeze['frozen_utc']), 'Calibration/freeze chronology mismatch')
        REQUIRE(receipt['supervisor_sources_sha256'] == supervisor_hash and
                receipt['approval_sha256'] == approval_hash, 'Calibration supervisor drift')
        shared = (*HASH_FIELDS, 'blocks', 'cohort_id', 'target_id', 'kernel_release')
        REQUIRE(all(previous[key] == plan[key] for key in shared),
                'Calibration/held-out provenance mismatch')
        sessions.append((raw_session, execution, previous))
    reports = p.validate_cohort(sessions, phase='calibration', cpu=plan['cpu'])
    REQUIRE(all(r['architectural_assessment'] == 'CONTROLS_OBSERVED_REVIEW_REQUIRED'
                for r in reports), 'Calibration is inconclusive; no automatic continuation')
    return freeze


def re_token(value):
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'
    return isinstance(value, str) and 0 < len(value) <= 64 and all(
        char in alphabet for char in value)


def native_gate(plan, approved):
    REQUIRE(approved and os.environ.get('RVZR_SOFTWARE_TEST_ONLY') != '1',
            'Native execution disabled without explicit approval or during software tests')
    REQUIRE(plan['evidence_kind'] == 'physical', 'Native mode requires a physical plan')


def run_session(plan_path, build, approval_path, *, mode, note, frozen=None,
                repo=ROOT, root=p.EVIDENCE_ROOT, approved=False):
    """One preflight or one physical launch. No campaign loop, retries or build steps."""
    # Final preservation must also retain unexpected failures rather than dropping evidence.
    # pylint: disable=too-many-statements,broad-exception-caught
    REQUIRE(mode in ('preflight', 'execute'), 'Unknown session mode')
    plan = p.read_json(plan_path)
    p.validate_plan(plan)
    REQUIRE(plan['evidence_kind'] == 'physical', 'Use self-test for synthetic data')
    if mode == 'execute':
        native_gate(plan, approved)
    REQUIRE(isinstance(note, str) and len(note.encode()) <= 4096, 'Operator note too large')
    with session_lock(root), Signals() as signals:
        name = plan['run_id'] if mode == 'execute' else 'preflight-' + plan['run_id']
        container = root / name
        container.mkdir()
        directory = container / 'evidence'
        directory.mkdir()
        started = utc()
        status, error, archive, revision = 'FAILED', None, None, {}
        approval_hash = None
        known = True
        try:
            save(directory / 'plan/launch.json', plan)
            (directory / 'plan/launch.original.json').write_bytes(bounded(plan_path, 4096))
            save(directory / 'plan/schedule.json', {'version': p.SCHEDULE,
                 'conditions': p.schedule(plan['seed'], plan['blocks'])})
            save(directory / 'metadata/operator-before.json',
                 {'observed_utc': utc(), 'source': 'operator argument', 'observation': note})
            revision = provenance(repo, directory / 'software/supervisor', plan)
            try:
                identity = target(plan)
            except Exception as failure:
                save(directory / 'metadata/identity-before.json',
                     {'status': 'UNAVAILABLE', 'error': str(failure)})
                raise
            save(directory / 'metadata/identity-before.json', identity)
            approval = p.read_json(approval_path)
            REQUIRE(bounded(approval_path, 4096) == canonical(approval),
                    'Approval must use canonical JSON bytes')
            approval_hash = sha(approval_path)
            verify_build(build, plan, approval, repo)
            shutil.copytree(build, directory / 'software/build', symlinks=False)
            verify_build(directory / 'software/build', plan, approval, repo)
            save(directory / 'software/approval.json', approval)
            packet = native.packet(plan)
            (directory / 'plan/input.bin').write_bytes(packet)
            if plan['phase'] == 'held_out':
                REQUIRE(frozen is not None,
                        'Held-out launch requires a frozen calibration manifest')
                frozen_calibration(frozen, plan, root, revision['supervisor_sources_sha256'],
                                   approval_hash, started)
                (directory / 'plan/frozen-calibration-manifest.json').write_bytes(bounded(frozen))
            else:
                REQUIRE(frozen is None, 'Calibration cannot supply a held-out freeze')
            environment_snapshot(directory / 'metadata', 'before')
            REQUIRE(not signals.number, 'Interrupted preflight')
            if mode == 'execute':
                # Final source/identity checks precede claiming the one permitted launch.
                after = provenance(repo, directory / 'software/prepared', plan)
                REQUIRE(after == revision and target(plan) == identity, 'Preparation drift')
                verify_build(directory / 'software/build', plan, approval, repo)
                claim(root, plan)
                save(root / '.active-worker.json', {'run_id': plan['run_id'], 'started_utc': utc()})
                known = False
                binary = directory / 'software/build/worker'
                binary.chmod(0o500)
                signals.deferred = False
                execution, detail = supervise(
                    binary, packet, plan, directory / 'raw', signals, approved=approved)
                known = detail['reaped']
                if known:
                    (root / '.ownership-history').mkdir(exist_ok=True)
                    (root / '.active-worker.json').rename(root / '.ownership-history' / name)
                REQUIRE(known, 'Child termination unknown: subsequent sessions blocked')
                environment_snapshot(directory / 'metadata', 'after')
                REQUIRE(not signals.number and detail['error'] is None,
                        'Interrupted/failed supervision')
                validation = p.validate_output(bounded(directory / 'raw/stdout.jsonl', p.MAX_BYTES),
                                               execution, plan)
                save(directory / 'analysis/validation.json', validation)
                REQUIRE(sha(binary) == plan['binary_sha256'], 'Executed binary changed')
                final = provenance(repo, directory / 'software/after', plan)
                REQUIRE(final == revision and target(plan) == identity, 'Post-session drift')
                status = 'VALIDATED'
            else:
                environment_snapshot(directory / 'metadata', 'after')
                status = 'PREFLIGHT_ONLY_NO_EXECUTION'
        except (Exception, Interrupted) as failure:  # Preserve failed sessions, never retry.
            error = f'{type(failure).__name__}: {failure}'
            save(directory / 'analysis/failure.json',
                 {'state': 'NOT_VALIDATED', 'error': error, 'observed_utc': utc()})
        finally:
            signals.deferred = True
            save(directory / 'metadata/operator-after.json', {
                'observed_utc': utc(), 'status': 'UNAVAILABLE',
                'observation': 'Post-session operator input unavailable; use a hashed addendum.'})
            session = {'mode': mode, 'state': status, 'error': error,
                       'started_utc': started, 'finished_utc': utc(),
                       'termination_known': known, 'signal': signals.number or None}
            save(directory / 'session.json', session)
            if known:
                try:
                    archive = seal(directory)
                except Exception as failure:  # Sealing errors belong outside the sealed set.
                    status = 'SEAL_FAILED'
                    save(container / 'seal-failure.json',
                         {'error': str(failure), 'observed_utc': utc()})
            else:
                status = 'TERMINATION_UNKNOWN_UNSEALED'
            success = status in ('VALIDATED', 'PREFLIGHT_ONLY_NO_EXECUTION') and not signals.number
            code = 0 if success else 1
            receipt = {'schema_version': 1, 'protocol': p.PROTOCOL, 'mode': mode,
                       'run_id': plan['run_id'], 'state': status, 'actual_launcher_exit': code,
                       'started_utc': started, 'finished_utc': utc(),
                       'signal': signals.number or None,
                       'termination_known': known, 'physical_execution_attested': False,
                       'g3_accepted': False, 'approval_sha256': approval_hash,
                       'supervisor_sources_sha256': revision.get('supervisor_sources_sha256'),
                       'archive_sha256': sha(archive) if archive else None}
            save(container / 'receipt.json', receipt)
            (container / 'receipt.json.sha256').write_text(
                sha(container / 'receipt.json') + '  receipt.json\n')
        return container, code


def self_test(output):
    """Compile and run ONLY the fixed C synthetic backend, even on an ARM64 host."""
    output.mkdir(parents=True, exist_ok=False)
    from tests.unit_m1_g3_p0 import fixture  # pylint: disable=import-outside-toplevel
    _, _, plan = fixture(blocks=2)
    command = ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-I' + str(ROOT / 'tools/exclusiveReservation'),
               str(ROOT / 'tools/exclusiveReservation/worker.c'),
               str(ROOT / 'tests/m1_g3_p0/host.c'), '-o', str(output / 'synthetic-worker')]
    save(output / 'compile-command.json', command)
    with (output / 'compile.stdout').open('xb') as out, \
            (output / 'compile.stderr').open('xb') as err:
        result = subprocess.run(command, stdout=out, stderr=err, timeout=60, check=False)
    save(output / 'compile-status.json', {'returncode': result.returncode, 'synthetic_only': True})
    REQUIRE(result.returncode == 0, 'Synthetic compilation failed')
    plan['binary_sha256'] = sha(output / 'synthetic-worker')
    with Signals() as signals:
        execution, detail = supervise(output / 'synthetic-worker', native.packet(plan), plan,
                                      output / 'raw', signals, synthetic=True)
    REQUIRE(detail['reaped'] and not detail['error'], 'Synthetic supervision failed')
    save(output / 'plan.json', plan)
    save(output / 'validation.json', p.validate_output(
        bounded(output / 'raw/stdout.jsonl', p.MAX_BYTES), execution, plan))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    testing = modes.add_parser('self-test')
    testing.add_argument('--output', type=Path, required=True)
    for mode in ('preflight', 'execute'):
        command = modes.add_parser(mode)
        for name in ('plan', 'build', 'approval'):
            command.add_argument('--' + name, type=Path, required=True)
        command.add_argument('--frozen', type=Path)
        command.add_argument('--note', required=True)
        if mode == 'execute':
            command.add_argument('--approve-native-single-session', action='store_true')
    args = parser.parse_args()
    try:
        if args.mode == 'self-test':
            return self_test(args.output.resolve())
        container, code = run_session(
            args.plan, args.build, args.approval, mode=args.mode, note=args.note,
            frozen=args.frozen, approved=getattr(args, 'approve_native_single_session', False))
        print(f'Preserved session: {container}; launcher exit={code}')
        return code
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'P0 BLOCKED: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
