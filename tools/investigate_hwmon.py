"""One-shot hwmon inventory. No timer workload, monitoring loop or settings writes.

Default invocation preserves a unique evidence directory; --collect is its bounded
read-only worker. collect(root, emit) also supports synthetic desktop fixtures.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

OUTPUT = Path('/home/safelab/MasterThesis/output/G2/hwmon-investigation')
MAX_CONTROLLERS = 64
MAX_INPUTS = 64
MAX_ENTRIES = 512
MAX_FILE = 4096
MAX_OUTPUT = 16 * 1024 * 1024
SECONDS = 5
UNITS = {'temp': 'millidegrees Celsius (nominal ABI)', 'fan': 'RPM',
         'in': 'millivolts', 'curr': 'milliamps', 'power': 'microwatts'}
INPUT = re.compile(r'(temp|fan|in|curr|power)([0-9]+)_(?:input|average)')


def supported(name):
    match = INPUT.fullmatch(name)
    return bool(match and (name.endswith('_input') or match[1] == 'power'))


def utc():
    return datetime.now(timezone.utc).isoformat()


def collect(root, emit):
    """Bounded inventory, including raw enumeration order; never infer sensor-to-core mapping."""
    root = Path(root)
    started = time.monotonic()
    deadline = started + SECONDS
    partial = False

    def record(kind, source, **fields):
        nonlocal partial
        partial |= fields.get('status') == 'UNAVAILABLE' or bool(fields.get('truncated'))
        emit({'kind': kind, 'source': source, 'observed_utc': utc(), **fields})

    def check():
        if time.monotonic() >= deadline:
            raise TimeoutError('Cooperative inventory deadline exhausted')

    def read(source, unit, numeric=False, optional=False, link=False):
        reported_text = None
        try:
            check()
            path = root / source.lstrip('/')
            if link:
                value = '/' + path.resolve(strict=True).relative_to(root.resolve()).as_posix()
            else:
                with path.open('rb') as stream:
                    raw = stream.read(MAX_FILE + 1)
                if len(raw) > MAX_FILE:
                    raise ValueError('Interface exceeds size limit')
                value = raw.decode('utf-8').strip().replace('\0', '\n')
                if not value:
                    raise ValueError('Empty interface')
                if numeric:
                    reported_text = value
                    if not re.fullmatch(r'-?[0-9]{1,20}', value):
                        raise ValueError('Expected a bounded signed integer')
                    value = int(value)
            record('read', source, unit=unit, value=value, status='OS_REPORTED', optional=optional)
        except (OSError, ValueError, RuntimeError) as error:
            record('read', source, unit=unit, value=None, status='UNAVAILABLE', optional=optional,
                   error=f'{type(error).__name__}: {error}'[:512], reported_text=reported_text)

    def entries(source, pattern):
        check()
        names = []
        truncated = False
        try:
            with os.scandir(root / source.lstrip('/')) as listing:
                for index, entry in enumerate(listing):
                    check()
                    if index >= MAX_ENTRIES:
                        truncated = True
                        break
                    if pattern.fullmatch(entry.name):
                        names.append(entry.name)
            record('enumeration', source, status='OS_REPORTED' if names else 'UNAVAILABLE',
                   names_in_discovery_order=names, truncated=truncated,
                   enumeration_complete=not truncated, entries_examined_limit=MAX_ENTRIES,
                   error=None if names else 'No matching exposed interfaces')
        except OSError as error:
            record('enumeration', source, status='UNAVAILABLE', names_in_discovery_order=names,
                   enumeration_complete=False, error=f'{type(error).__name__}: {error}'[:512])
        return names

    def natural(name):
        return tuple(int(part) if part.isdigit() else part for part in re.split(r'([0-9]+)', name))

    emit({'kind': 'metadata', 'schema_version': 1, 'started_utc': utc(),
          'method': 'one-shot OS-reported hwmon inventory; no physical sensor mapping',
          'kernel': os.uname().release, 'architecture': os.uname().machine,
          'page_size': os.sysconf('SC_PAGESIZE'),
          'limits': {'controllers': MAX_CONTROLLERS, 'inputs_per_controller': MAX_INPUTS,
                     'entries_per_directory': MAX_ENTRIES, 'file_bytes': MAX_FILE,
                     'cooperative_seconds': SECONDS, 'output_bytes': MAX_OUTPUT}})
    try:
        base = '/sys/class/hwmon'
        controllers = entries(base, re.compile(r'hwmon.*'))
        selected = sorted(controllers, key=natural)[:MAX_CONTROLLERS]
        record('selection', base, selected=selected, truncated=len(controllers) > MAX_CONTROLLERS,
               legacy_first_eight=sorted(controllers[:8]),
               legacy_omitted_observed=sorted(controllers[8:], key=natural))
        for name in selected:
            path = base + '/' + name
            read(path, 'resolved sysfs path; not a serial number', link=True)
            read(path + '/name', 'driver-reported name; core mapping UNKNOWN')
            read(path + '/device/driver', 'resolved driver path', optional=True, link=True)
            inputs = entries(path, re.compile(r'.*_(?:input|average)'))
            available = sorted((name for name in inputs if supported(name)), key=natural)
            picked = available[:MAX_INPUTS]
            unsupported = [name for name in inputs if not supported(name)]
            legacy_prefix = [name for name in inputs if name.endswith('_input')][:16]
            record('selection', path, selected=picked, truncated=len(available) > MAX_INPUTS,
                   supported_observed=available, unsupported_observed=unsupported,
                   legacy_first_sixteen=sorted(legacy_prefix))
            for name in picked:
                unit = UNITS[INPUT.fullmatch(name)[1]]
                read(path + '/' + name, unit, numeric=True)
                read(path + '/' + name.rsplit('_', 1)[0] + '_label',
                     'optional driver label; mapping unverified', optional=True)
    except (OSError, ValueError) as error:
        record('error', '/sys/class/hwmon', status='UNAVAILABLE', error=str(error)[:512])
    emit({'kind': 'complete', 'finished_utc': utc(), 'status': 'PARTIAL' if partial else 'COMPLETE',
          'elapsed_seconds': time.monotonic() - started})


def worker():
    size = 0

    def emit(row):
        nonlocal size
        line = json.dumps(row, allow_nan=False) + '\n'
        size += len(line.encode())
        if size > MAX_OUTPUT:
            raise RuntimeError('Output limit reached; preserve incomplete JSONL')
        print(line, end='', flush=True)

    collect(Path('/'), emit)


def main():
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise RuntimeError('Use ordinary-user Linux; no sudo')
    os.umask(0o077)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-'),
                                      dir=OUTPUT))
    print(f'Output: {directory}', flush=True)
    status = {'state': 'STARTED', 'started_utc': utc(), 'returncode': None}
    child = None
    exit_code = 1
    launching = False
    pending_signal = None

    def interrupted(number, _frame):
        nonlocal pending_signal
        if launching:
            pending_signal = number
            return
        raise InterruptedError(f'Signal {number}')

    previous = {number: signal.signal(number, interrupted)
                for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        source = Path(__file__).resolve()
        for path in (source, source.with_name('experimental_environment.py')):
            (directory / path.name).write_bytes(path.read_bytes())
        revision = subprocess.run(['git', '-C', str(source.parent.parent), 'rev-parse', 'HEAD'],
                                  capture_output=True, timeout=3, check=False)
        (directory / 'provenance.json').write_text(json.dumps({
            'recorded_utc': utc(), 'git_returncode': revision.returncode,
            'git_head': revision.stdout.decode(errors='replace').strip(),
            'git_error': revision.stderr.decode(errors='replace')[:1024],
            'source_identity': 'Preserved actual source bytes; no clean-tree claim',
            'command': [sys.executable, str(source)], 'python_version': sys.version}, indent=2))
        command = [sys.executable, '-B', str(directory / source.name), '--collect']
        status['worker_command'] = command
        with (directory / 'raw.jsonl').open('xb') as out, \
                (directory / 'stderr.txt').open('xb') as err:
            launching = True
            try:
                child = subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
            finally:
                launching = False
            if pending_signal is not None:
                raise InterruptedError(f'Signal {pending_signal} during worker creation')
            status['returncode'] = child.wait(timeout=10)
        status['state'] = 'RETURNED' if status['returncode'] == 0 else 'FAILED'
        exit_code = 0 if status['returncode'] == 0 else 1
    except (Exception, KeyboardInterrupt) as error:
        exit_code = 1
        status.update(state='INCOMPLETE', error=f'{type(error).__name__}: {error}')
    finally:
        # Worker has no children. Defer repeat signals while stopping it and preserving evidence.
        for number in previous:
            signal.signal(number, signal.SIG_IGN)
        if child is not None:
            status['returncode'] = child.poll()
            if status['returncode'] is None:
                child.kill()
                try:
                    status['returncode'] = child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    status['termination'] = 'UNKNOWN; hashes are point-in-time only'
        status['finished_utc'] = utc()
        (directory / 'status.json').write_text(json.dumps(status, indent=2) + '\n')
        with (directory / 'SHA256SUMS').open('x') as manifest:
            for path in sorted(directory.iterdir()):
                if path.name != 'SHA256SUMS' and path.is_file():
                    with path.open('rb') as stream:
                        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                    manifest.write(digest + '  ' + path.name + '\n')
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(f'Preserve this whole directory, including unsuccessful output: {directory}', flush=True)
    return exit_code


if __name__ == '__main__':
    if sys.argv[1:] == ['--collect']:
        worker()
    elif not sys.argv[1:]:
        sys.exit(main())
    else:
        sys.exit('Usage: python3 tools/investigate_hwmon.py')
