"""Host-only supervision tests. No native worker is ever invoked, including on ARM CI."""
# pylint: disable=missing-function-docstring,missing-class-docstring,too-many-public-methods
from contextlib import ExitStack
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import tarfile
import time
import unittest
from unittest.mock import patch

from tools import m1_g3_p0 as p, m1_g3_p0_native as native
from tools import m1_g3_p0_supervisor as s
from tests.unit_m1_g3_p0 import fixture

ROOT = Path(__file__).resolve().parents[1]


def writable(root):
    for path in [root, *root.rglob('*')]:
        path.chmod(0o700 if path.is_dir() else 0o600)


class SupervisorTest(unittest.TestCase):
    shared: tempfile.TemporaryDirectory
    shared_root: Path
    binary: Path
    command: list[str]

    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
            prefix='p0-supervisor-synthetic-')
        cls.shared_root = Path(cls.shared.name)
        cls.binary = cls.shared_root / 'synthetic-worker'
        cls.command = ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                       '-I' + str(ROOT / 'tools/exclusiveReservation'),
                       str(ROOT / 'tools/exclusiveReservation/worker.c'),
                       str(ROOT / 'tests/m1_g3_p0/host.c'), '-o', str(cls.binary)]
        subprocess.run(cls.command, timeout=60, capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.shared.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
            prefix='p0-software-only-')
        self.base = Path(self.temp.name)
        self.env = patch.dict(os.environ, {'RVZR_SOFTWARE_TEST_ONLY': '1'})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        writable(self.base)
        self.temp.cleanup()

    def capture(self, plan=None, fault=None):
        if plan is None:
            _, _, plan = fixture()
        plan['binary_sha256'] = s.sha(self.binary)
        directory = self.base / ('raw-' + str(len(list(self.base.iterdir()))))
        with s.Signals() as signals:
            execution, detail = s.supervise(
                self.binary, native.packet(plan), plan, directory,
                signals, synthetic=True, fault=fault)
        return directory, execution, detail

    def test_real_synthetic_c_worker_pid_packet_and_schema(self):
        _, _, plan = fixture(blocks=32)
        directory, execution, detail = self.capture(plan)
        self.assertTrue(detail['reaped'])
        self.assertIsNone(detail['error'])
        self.assertEqual(execution['returncode'], 0)
        self.assertEqual((directory / 'input.bin').read_bytes(), native.packet(plan))
        report = p.validate_output((directory / 'stdout.jsonl').read_bytes(), execution, plan)
        self.assertFalse(report['physical_execution_attested'])
        self.assertFalse(report['g3_accepted'])
        rows = [json.loads(line) for line in (directory / 'stdout.jsonl').read_text().splitlines()]
        self.assertEqual(rows[0]['worker_pid'], execution['worker_pid'])
        self.assertEqual(len(rows), 194)

    def test_synthetic_faults_keep_partial_and_actual_signal(self):
        for fault, sig in (('trap', signal.SIGILL), ('hard_kill', signal.SIGKILL),
                           ('timeout', signal.SIGALRM)):
            directory, execution, detail = self.capture(fault=fault)
            with self.subTest(fault=fault):
                self.assertTrue(detail['reaped'])
                self.assertEqual(execution['returncode'], -sig)
                self.assertEqual(execution['signal'], sig)
                raw = (directory / 'stdout.jsonl').read_bytes()
                self.assertEqual(sum(json.loads(row)['kind'] == 'sample'
                                     for row in raw.splitlines()), 2)

    def script(self, source, *, barrier=True):
        path = self.base / ('fixture-' + str(len(list(self.base.iterdir()))))
        gate = 'import sys\nsys.stdin.buffer.read()\n' if barrier else ''
        path.write_text('#!' + sys.executable + '\n' + gate + source)
        path.chmod(0o700)
        return path

    def script_capture(self, binary, *, signals=None):
        _, _, plan = fixture()
        plan['binary_sha256'] = s.sha(binary)
        directory = self.base / ('raw-script-' + str(len(list(self.base.iterdir()))))
        if signals is not None:
            return s.supervise(binary, native.packet(plan), plan, directory, signals,
                               synthetic=True), directory
        with s.Signals() as state:
            result = s.supervise(
                binary, native.packet(plan), plan, directory, state, synthetic=True)
        return result, directory

    def test_timeout_uses_ready_child_preserves_streams_without_retry(self):
        binary = self.script('import os,time\nos.write(1,b"partial\\n")\n'
                             'os.write(2,b"diagnostic\\n")\ntime.sleep(30)\n')
        actual_wait = s.wait_exit
        ready_seen = []

        def deadline(process, fd, seconds):
            if seconds == 0:
                return actual_wait(process, fd, seconds)
            # Explicit readiness outside the worker code; no short-startup assumption.
            stdout = next(self.base.glob('raw-script-*/stdout.jsonl'))
            until = time.monotonic() + 3
            while not stdout.read_bytes() and time.monotonic() < until:
                time.sleep(0.01)
            self.assertEqual(stdout.read_bytes(), b'partial\n')
            ready_seen.append(True)
            return False if len(ready_seen) == 1 else actual_wait(process, fd, seconds)

        with patch.object(s, 'wait_exit', side_effect=deadline):
            (execution, detail), directory = self.script_capture(binary)
        self.assertTrue(execution['timed_out'])
        self.assertNotEqual(execution['returncode'], 0)
        self.assertTrue(detail['reaped'])
        self.assertEqual((directory / 'stdout.jsonl').read_bytes(), b'partial\n')
        self.assertEqual((directory / 'stderr.txt').read_bytes(), b'diagnostic\n')
        self.assertEqual(detail['termination_attempts'][0]['signal'], signal.SIGTERM)
        self.assertTrue(detail['termination_attempts'][0]['reaped'])

    def test_sigkill_escalation_for_term_ignoring_child(self):
        binary = self.script('import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                             'os.write(1,b"ready\\n")\ntime.sleep(30)\n')
        actual_wait = s.wait_exit
        count = 0

        def deadline(process, fd, seconds):
            nonlocal count
            if seconds == 0:
                return actual_wait(process, fd, seconds)
            count += 1
            if count == 1:
                path = next(self.base.glob('raw-script-*/stdout.jsonl'))
                until = time.monotonic() + 3
                while not path.read_bytes() and time.monotonic() < until:
                    time.sleep(0.01)
                self.assertEqual(path.read_bytes(), b'ready\n')
                return False
            return actual_wait(process, fd, min(seconds, 0.1))

        with patch.object(s, 'wait_exit', side_effect=deadline):
            (execution, detail), _ = self.script_capture(binary)
        self.assertEqual(execution['signal'], signal.SIGKILL)
        self.assertTrue(detail['reaped'])
        self.assertEqual([row['signal'] for row in detail['termination_attempts']],
                         [signal.SIGTERM, signal.SIGKILL])

    def test_interrupt_and_outer_watchdog_preserve_status(self):
        for number in (signal.SIGINT, signal.SIGALRM):
            binary = self.script('import time\ntime.sleep(30)\n')
            with s.Signals() as state:
                actual_wait = s.wait_exit
                count = 0

                def stop(process, fd, seconds, active=state, sig=number, waiter=actual_wait):
                    nonlocal count
                    if seconds == 0:
                        return waiter(process, fd, seconds)
                    count += 1
                    if count == 1:
                        active.handler(sig, None)
                    return waiter(process, fd, seconds)

                with patch.object(s, 'wait_exit', side_effect=stop):
                    (execution, detail), _ = self.script_capture(binary, signals=state)
            self.assertTrue(detail['reaped'])
            self.assertEqual(detail['requested_signal'], number)
            self.assertNotEqual(execution['returncode'], 0)
            self.assertEqual(execution['timed_out'], number == signal.SIGALRM)

    def test_nonzero_empty_and_malformed_output_are_not_observations(self):
        _, _, plan = fixture()
        for source in ('raise SystemExit(7)\n', '', 'print("not JSON")\n'):
            (execution, detail), directory = self.script_capture(self.script(source))
            self.assertTrue(detail['reaped'])
            with self.assertRaises(p.VerificationError):
                p.validate_output((directory / 'stdout.jsonl').read_bytes(), execution, plan)

    def test_unobservable_spawn_failure_does_not_claim_known_no_child(self):
        with patch.object(subprocess.Popen, '__init__',
                          side_effect=OSError('synthetic spawn failure')):
            directory, execution, detail = self.capture()
        self.assertFalse(detail['reaped'])
        self.assertEqual(detail['state'], 'STARTUP_UNKNOWN')
        self.assertIsNone(execution['worker_pid'])
        self.assertIsNone(execution['returncode'])
        self.assertEqual((directory/'stdout.jsonl').read_bytes(), b'')
        self.assertTrue((directory/'execution-started.json').exists())

    def test_stalled_constructor_watchdog_interrupts_before_normal_return(self):
        completed = []

        def stalled(_process, *_args, **_kwargs):
            time.sleep(0.4)
            completed.append(True)

        started = time.monotonic()
        with patch.object(p, 'OUTER_SECONDS', 0.1), \
                patch.object(subprocess.Popen, '__init__', new=stalled):
            directory, execution, detail = self.capture()
        elapsed = time.monotonic() - started
        self.assertFalse(completed, 'Watchdog must interrupt, not just record a flag')
        self.assertLess(elapsed, 0.35)
        self.assertTrue(execution['timed_out'])
        self.assertIsNone(execution['worker_pid'])
        self.assertFalse(detail['reaped'])
        self.assertEqual(detail['state'], 'STARTUP_UNKNOWN')
        self.assertFalse(detail['startup']['packet_released'])
        self.assertIn(signal.SIGALRM, detail['parent_signals'])
        self.assertNotIn('<verified-fd>', detail['command'][0])
        self.assertEqual((directory/'stdout.jsonl').read_bytes(), b'')

    def test_nondefault_child_reaper_is_rejected_before_spawning(self):
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            with self.assertRaisesRegex(p.VerificationError, 'child reaping'):
                with s.Signals():
                    self.fail('Auto-reaping could allow PID reuse before configuration')
        finally:
            signal.signal(signal.SIGCHLD, previous)

    def test_watchdog_expiry_remains_latched_during_later_cleanup_signal(self):
        with s.Signals() as state:
            state.deferred = True
            state.handler(signal.SIGALRM, None)
            state.handler(signal.SIGTERM, None)
            self.assertTrue(state.timed_out)
            self.assertEqual(state.number, signal.SIGTERM)
            self.assertEqual(state.received, [signal.SIGALRM, signal.SIGTERM])

    def test_interrupted_constructor_retains_created_child_pid_and_reaps_it(self):
        original = subprocess.Popen.__init__
        completed = []

        def stalled(process, *args, **kwargs):
            self.assertNotIn('preexec_fn', kwargs)
            original(process, *args, **kwargs)
            signal.setitimer(signal.ITIMER_REAL, 0.1)
            time.sleep(1.5)
            completed.append(True)

        started = time.monotonic()
        with patch.object(subprocess.Popen, '__init__', new=stalled):
            directory, execution, detail = self.capture()
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertFalse(completed)
        self.assertTrue(execution['timed_out'])
        self.assertTrue(detail['reaped'])
        self.assertGreater(execution['worker_pid'], 0)
        self.assertFalse(detail['startup']['constructor_returned'])
        self.assertFalse(detail['startup']['packet_released'])
        record = s.read_json(directory/'spawn.json')
        self.assertTrue(record['recorded_during_cleanup'])
        self.assertEqual(record['worker_pid'], execution['worker_pid'])

    def test_partial_startup_ignoring_term_is_killed_and_reaped_within_guards(self):
        binary = self.script('import os,signal,sys\n'
                             'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                             'os.write(1,b"ready-before-packet\\n")\n'
                             'sys.stdin.buffer.read()\n', barrier=False)
        original = subprocess.Popen.__init__
        deadline_started = []
        completed = []

        def stalled(process, *args, **kwargs):
            original(process, *args, **kwargs)
            raw = next(self.base.glob('raw-script-*/stdout.jsonl'))
            until = time.monotonic() + 3
            while not raw.read_bytes() and time.monotonic() < until:
                time.sleep(0.01)
            self.assertEqual(raw.read_bytes(), b'ready-before-packet\n')
            deadline_started.append(time.monotonic())
            signal.setitimer(signal.ITIMER_REAL, 0.1)
            time.sleep(1.5)
            completed.append(True)

        with patch.object(p, 'KILL_SECONDS', 0.1), \
                patch.object(subprocess.Popen, '__init__', new=stalled):
            (execution, detail), directory = self.script_capture(binary)
        self.assertLess(time.monotonic() - deadline_started[0], 1.0)
        self.assertFalse(completed)
        self.assertTrue(detail['reaped'])
        self.assertEqual(execution['signal'], signal.SIGKILL)
        self.assertEqual([row['signal'] for row in detail['termination_attempts']],
                         [signal.SIGTERM, signal.SIGKILL])
        self.assertFalse(detail['startup']['packet_released'])
        self.assertEqual((directory/'stdout.jsonl').read_bytes(), b'ready-before-packet\n')

    def test_partial_startup_without_process_group_signals_only_owned_pid(self):
        original = subprocess.Popen.__init__

        def stalled(process, *args, **kwargs):
            original(process, *args, **kwargs)
            signal.setitimer(signal.ITIMER_REAL, 0.1)
            time.sleep(1.5)

        original_kill = os.kill
        started = time.monotonic()
        with patch.object(subprocess.Popen, '__init__', new=stalled), \
                patch.object(s.os, 'killpg', side_effect=ProcessLookupError('no group yet')), \
                patch.object(s.os, 'kill', wraps=original_kill) as direct:
            _, execution, detail = self.capture()
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertTrue(detail['reaped'])
        self.assertTrue(detail['termination_attempts'][0]['pid_fallback'])
        self.assertEqual(direct.call_args.args, (execution['worker_pid'], signal.SIGTERM))

    def test_nonwaitable_pid_from_interrupted_constructor_is_never_signalled(self):
        def interrupted(process, *_args, **_kwargs):
            # Deliberately invalid ownership fixture; do not force actual PID reuse.
            process.pid = os.getpid()
            process.returncode = None
            signal.raise_signal(signal.SIGALRM)

        with patch.object(subprocess.Popen, '__init__', new=interrupted), \
                patch.object(s.os, 'killpg') as group, patch.object(s.os, 'kill') as direct:
            _, execution, detail = self.capture()
        group.assert_not_called()
        direct.assert_not_called()
        self.assertFalse(detail['reaped'])
        self.assertIsNone(execution['returncode'])
        self.assertIn('ownership_error', detail)
        self.assertFalse(detail['startup']['packet_released'])

    def test_startup_signals_interrupt_initialization_and_never_release_packet(self):
        for number in (signal.SIGTERM, signal.SIGALRM):
            def interrupted(_pid, _cpu, record, sig=number):
                record['stage'] = 'injected-initialization'
                signal.raise_signal(sig)

            started = time.monotonic()
            with patch.object(s, 'configure_child', side_effect=interrupted):
                directory, execution, detail = self.capture()
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertTrue(detail['reaped'])
            self.assertFalse(detail['startup']['packet_released'])
            self.assertIn(number, detail['parent_signals'])
            self.assertEqual(execution['timed_out'], number == signal.SIGALRM)
            self.assertFalse((directory/'initialized.json').exists())

    def test_limit_apply_and_verification_failures_keep_worker_behind_barrier(self):
        original = s.resource.prlimit

        def failing_policy(failure_mode):
            reads = 0

            def failed(pid, which, *limits):
                nonlocal reads
                if which == s.resource.RLIMIT_CPU:
                    if limits and failure_mode == 'apply-error':
                        raise PermissionError('synthetic prlimit failure')
                    if not limits:
                        reads += 1
                        if reads == 2 and failure_mode == 'readback-error':
                            return (-1, -1)
                return original(pid, which, *limits)

            return failed

        for mode in ('apply-error', 'readback-error'):
            with patch.object(s.resource, 'prlimit', side_effect=failing_policy(mode)):
                directory, execution, detail = self.capture()
            self.assertTrue(detail['reaped'])
            self.assertGreater(execution['worker_pid'], 0)
            self.assertFalse(detail['startup']['packet_released'])
            self.assertFalse(detail['startup']['verified'])
            self.assertEqual(detail['startup']['stage'], 'prlimit-cpu')
            self.assertIsNotNone(detail['error'])
            self.assertFalse((directory/'initialized.json').exists())

    def test_affinity_apply_and_verification_failures_prevent_release(self):
        selected = min(os.sched_getaffinity(0))
        original = s.configure_child

        def configure(pid, _cpu, record):
            original(pid, selected, record)

        for mode in ('apply-error', 'readback-error'):
            with patch.object(s, 'configure_child', side_effect=configure), ExitStack() as stack:
                if mode == 'apply-error':
                    stack.enter_context(patch.object(s.os, 'sched_setaffinity',
                                                     side_effect=PermissionError('synthetic')))
                else:
                    stack.enter_context(patch.object(s.os, 'sched_setaffinity', return_value=None))
                    stack.enter_context(patch.object(s.os, 'sched_getaffinity',
                                                     return_value={selected, selected + 1}))
                _, _, detail = self.capture()
            self.assertTrue(detail['reaped'])
            self.assertFalse(detail['startup']['verified'])
            self.assertFalse(detail['startup']['packet_released'])
            self.assertEqual(detail['startup']['stage'], 'affinity')

    def test_parent_sets_and_verifies_real_owned_child_affinity(self):
        selected = min(os.sched_getaffinity(0))
        original = s.configure_child
        binary = self.script('import json,os\nprint(json.dumps(sorted(os.sched_getaffinity(0))))\n')

        def configure(pid, _cpu, record):
            original(pid, selected, record)

        with patch.object(s, 'configure_child', side_effect=configure):
            (execution, detail), directory = self.script_capture(binary)
        self.assertEqual(execution['returncode'], 0)
        self.assertTrue(detail['startup']['verified'])
        self.assertEqual(detail['startup']['affinity'], [selected])
        self.assertEqual(json.loads((directory/'stdout.jsonl').read_bytes()), [selected])

    def test_child_exit_before_release_is_reaped_without_supplying_packet(self):
        binary = self.script('raise SystemExit(7)\n', barrier=False)

        def await_exit(pid, _cpu, _record):
            fd = os.pidfd_open(pid)
            try:
                self.assertTrue(s.select.select([fd], [], [], 3)[0])
            finally:
                os.close(fd)

        with patch.object(s, 'configure_child', side_effect=await_exit):
            (execution, detail), directory = self.script_capture(binary)
        self.assertEqual(execution['returncode'], 7)
        self.assertTrue(detail['reaped'])
        self.assertFalse(detail['startup']['packet_released'])
        self.assertFalse((directory/'initialized.json').exists())

    def test_pid_and_verified_policy_are_saved_before_release(self):
        original_write = os.write
        releases = []

        def inspect_release(fd, data):
            record = next(self.base.glob('raw-script-*/spawn.json'))
            initialized = s.read_json(record.parent/'initialized.json')
            spawn = s.read_json(record)
            self.assertEqual(initialized['worker_pid'], spawn['worker_pid'])
            self.assertTrue(initialized['configuration']['verified'])
            self.assertFalse(initialized['packet_released'])
            self.assertEqual((record.parent/'stdout.jsonl').read_bytes(), b'')
            releases.append(True)
            return original_write(fd, data)

        with patch.object(s.os, 'write', side_effect=inspect_release):
            (execution, detail), directory = self.script_capture(self.binary)
        self.assertEqual(releases, [True])
        self.assertEqual(execution['returncode'], 0)
        self.assertTrue(detail['startup']['packet_released'])
        plan = s.read_json(directory/'spawn.json')
        self.assertEqual(plan['worker_pid'], execution['worker_pid'])

    def test_signal_racing_successful_pipe_write_preserves_release_uncertainty(self):
        original_write = os.write

        def interrupted(fd, data):
            original_write(fd, data)
            signal.raise_signal(signal.SIGTERM)

        with patch.object(s.os, 'write', side_effect=interrupted):
            (_, detail), _ = self.script_capture(self.binary)
        self.assertTrue(detail['reaped'])
        self.assertIsNone(detail['startup']['packet_released'])
        self.assertEqual(detail['startup']['packet_release_state'], 'attempting')
        self.assertIn(signal.SIGTERM, detail['parent_signals'])

    def test_reaping_failure_does_not_invent_success(self):
        class UnknownProcess:
            pid = 99999999
        with patch.object(s.os, 'killpg') as kill, \
                patch.object(s, 'wait_exit', return_value=False) as wait:
            self.assertFalse(s.terminate(UnknownProcess(), 123))
        self.assertEqual([call.args[1] for call in kill.call_args_list],
                         [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual([call.args[2] for call in wait.call_args_list], [2, 2])

    def test_child_resource_limits_are_real_and_bounded(self):
        binary = self.script('import json,resource,os\nprint(json.dumps({\n'
                             '"cpu":resource.getrlimit(resource.RLIMIT_CPU),\n'
                             '"file":resource.getrlimit(resource.RLIMIT_FSIZE),\n'
                             '"core":resource.getrlimit(resource.RLIMIT_CORE)}))\n')
        (execution, _), directory = self.script_capture(binary)
        self.assertEqual(execution['returncode'], 0)
        limits = json.loads((directory/'stdout.jsonl').read_bytes())
        for name, bound in (('cpu', 2), ('file', 1048576), ('core', 0)):
            self.assertTrue(all(0 <= n <= bound for n in limits[name]))

    def test_invalid_external_plan_is_rejected_before_any_process(self):
        plan = self.base/'bad-plan.json'
        plan.write_bytes(b'{"schema_version":1,"schema_version":1}\n')
        with patch.object(s.subprocess, 'Popen') as spawn, self.assertRaises(p.VerificationError):
            s.run_session(plan, self.base/'build', self.base/'approval',
                          mode='execute', note='SYNTHETIC ONLY', root=self.base/'never-created')
        spawn.assert_not_called()
        self.assertFalse((self.base/'never-created').exists())

    def test_packet_mismatch_rejected_before_spawn(self):
        _, _, plan = fixture()
        with s.Signals() as signals, patch.object(s.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(p.VerificationError, 'Packet'):
                s.supervise(self.binary, native.packet(plan)+b'x', plan,
                            self.base/'raw', signals, synthetic=True)
        spawn.assert_not_called()

    def test_opened_executable_mismatch_rejected_before_spawn(self):
        _, _, plan = fixture()
        plan['binary_sha256'] = '0'*64
        with s.Signals() as state, patch.object(s.subprocess, 'Popen') as spawn:
            execution, detail = s.supervise(self.binary, native.packet(plan), plan,
                                            self.base/'raw-mismatch', state, synthetic=True)
        spawn.assert_not_called()
        self.assertIsNone(execution['worker_pid'])
        self.assertTrue(detail['reaped'])
        self.assertIn('Opened executable hash mismatch', detail['error'])

    def test_native_execution_disabled_in_all_software_test_entry_points(self):
        _, _, plan = fixture()
        plan['evidence_kind'] = 'physical'
        for approved in (False, True):
            with self.assertRaises(p.VerificationError):
                s.native_gate(plan, approved)
        with s.Signals() as signals, patch.object(s.subprocess, 'Popen') as spawn:
            with self.assertRaises(p.VerificationError):
                s.supervise(self.binary, native.packet(plan), plan, self.base/'raw', signals,
                            approved=True)
        spawn.assert_not_called()

    def test_self_test_cli_only_compiles_synthetic_backend(self):
        completed = subprocess.run(
            [sys.executable, '-B', str(ROOT/'tools/m1_g3_p0_supervisor.py'),
             'self-test', '--output', str(self.base/'self-test')],
            timeout=15, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        command = json.loads((self.base/'self-test/compile-command.json').read_bytes())
        self.assertIn(str(ROOT/'tests/m1_g3_p0/host.c'), command)
        self.assertNotIn(str(ROOT/'tools/exclusiveReservation/probe.S'), command)
        self.assertNotIn(str(ROOT/'tools/exclusiveReservation/linux.c'), command)
        report = json.loads((self.base/'self-test/validation.json').read_bytes())
        self.assertEqual(report['plan']['evidence_kind'], 'synthetic')
        self.assertFalse(report['g3_accepted'])

    def test_mutually_exclusive_sessions_and_permanent_claims(self):
        root = self.base/'runs'
        with s.session_lock(root):
            with self.assertRaises(BlockingIOError):
                with s.session_lock(root):
                    self.fail('Second lock admitted')
            _, _, plan = fixture(cpu=4)
            s.claim(root, plan)
            with self.assertRaises(FileExistsError):
                s.claim(root, plan)
            s.save(root/'.active-worker.json', {'state': 'UNKNOWN'})
        with self.assertRaisesRegex(p.VerificationError, 'termination'):
            with s.session_lock(root):
                self.fail('Unknown previous child admitted')

    def test_seal_inventory_archive_and_no_self_reference(self):
        directory = self.base/'run/evidence'
        s.save(directory/'status.json', {'synthetic': True})
        archive = s.seal(directory)
        s.verify_archive(directory, archive)
        self.assertNotIn('SHA256SUMS', s.verify_manifest(directory))
        self.assertNotIn(archive.name, s.verify_manifest(directory))
        self.assertEqual(archive.parent, directory.parent)
        with self.assertRaises(p.VerificationError):
            s.seal(directory)

    def test_archive_rejects_unrelated_directory_members(self):
        directory = self.base/'evidence'
        s.save(directory/'data.json', {'synthetic': True})
        bad = self.base/'wrong-prefix.tar.gz'
        with tarfile.open(bad, 'x:gz') as packed:
            member = tarfile.TarInfo('outside-evidence')
            member.type = tarfile.DIRTYPE
            packed.addfile(member)
        with self.assertRaisesRegex(p.VerificationError, 'prefix'):
            s.verify_archive(directory, bad)

    def identity(self):
        return {'system': 'Linux', 'architecture': 'aarch64', 'page_size': 16384,
                'kernel_release': 'synthetic-kernel+16k', 'allowed_cpus': [0, 4],
                'os_release': 'NAME="Fedora Linux Asahi Remix"\nID=fedora-asahi-remix\n'
                              'VERSION_ID=45\nID_LIKE=fedora\n',
                'compatible': ['apple,j293', 'apple,t8103'],
                'cpus': {str(k): {'midr': v} for k, v in p.MIDRS.items()}}

    def test_actual_fedora_identity_and_unavailable_or_incompatible_targets(self):
        _, _, plan = fixture()
        identity = self.identity()
        s.check_identity(identity, plan, 1000)
        for key, bad in (('architecture', 'x86_64'), ('system', 'Darwin'), ('page_size', 4096),
                         ('compatible', ['apple,t8112']), ('allowed_cpus', [4]),
                         ('kernel_release', 'other'), ('os_release', 'ID=fedora\nVERSION_ID=45')):
            with self.subTest(key=key), self.assertRaises(p.VerificationError):
                s.check_identity({**identity, key: bad}, plan, 1000)
        with self.assertRaises(p.VerificationError):
            s.check_identity(identity, plan, 0)
        identity['cpus']['0']['midr'] = p.MIDRS[4]
        with self.assertRaises(p.VerificationError):
            s.check_identity(identity, plan, 1000)
        with patch.object(s, 'bounded', side_effect=FileNotFoundError('unavailable')):
            with self.assertRaises(FileNotFoundError):
                s.target(plan)

    def repo_fixture(self):
        repo = self.base/'repo'
        repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        for name in sorted(set(native.FILES+s.SUPPORT)):
            path = repo/name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT/name, path)
        subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(repo), '-c', 'user.name=P0 synthetic test',
                        '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'],
                       check=True)
        _, _, plan = fixture()
        plan['source_commit'] = s.checked_git(repo, 'rev-parse', 'HEAD').decode().strip()
        return repo, plan

    def test_clean_committed_provenance_and_exact_revision(self):
        repo, plan = self.repo_fixture()
        result = s.provenance(repo, self.base/'proof', plan)
        self.assertEqual(result['head'], plan['source_commit'])
        self.assertEqual(len(result['sources']), len(set(native.FILES+s.SUPPORT)))
        plan['source_commit'] = '0'*40
        with self.assertRaisesRegex(p.VerificationError, 'revision'):
            s.provenance(repo, self.base/'wrong-head', plan)

    def test_dirty_staged_and_untracked_git_diagnostics_preserved(self):
        repo, plan = self.repo_fixture()
        source = repo/native.FILES[0]
        source.write_text(source.read_text()+'\n// STAGED\n')
        subprocess.run(['git', '-C', str(repo), 'add', native.FILES[0]], check=True)
        source.write_text(source.read_text()+'// UNSTAGED\n')
        (repo/'untracked.txt').write_text('preserve')
        with self.assertRaisesRegex(p.VerificationError, 'Clean committed'):
            s.provenance(repo, self.base/'proof', plan)
        self.assertIn('STAGED', (self.base/'proof/git-staged.patch').read_text())
        self.assertIn('UNSTAGED', (self.base/'proof/git-unstaged.patch').read_text())
        self.assertIn('untracked.txt', (self.base/'proof/git-status').read_text())

    def test_provenance_rejects_hidden_required_source_drift(self):
        repo, plan = self.repo_fixture()
        subprocess.run(['git', '-C', str(repo), 'update-index', '--assume-unchanged',
                        native.FILES[0]], check=True)
        source = repo/native.FILES[0]
        source.write_text(source.read_text()+'\n// concealed drift\n')
        with self.assertRaisesRegex(p.VerificationError, 'Uncommitted source'):
            s.provenance(repo, self.base/'proof', plan)

    def orchestration(self, *, mode='execute', fault=None):
        """Actual orchestration; measurement boundary is an explicitly synthetic fixture."""
        # pylint: disable=too-many-locals
        _, _, plan = fixture(cpu=4)
        plan['evidence_kind'] = 'physical'  # Schema fixture only, never passed to a real child.
        build = self.base/'fixture-build'
        build.mkdir()
        (build/'worker').write_bytes(b'NONEXECUTABLE SYNTHETIC ORCHESTRATION FIXTURE')
        plan['binary_sha256'] = s.sha(build/'worker')
        plan_path, approval_path = self.base/'plan.json', self.base/'approval.json'
        s.save(plan_path, plan)
        approval = {'schema_version': 1, 'protocol': p.PROTOCOL,
                    **{k: plan[k] for k in s.HASH_FIELDS}}
        s.save(approval_path, approval)
        events = []
        actual_supervise = s.supervise

        def proof(_repo, destination, _plan):
            s.save(destination/'fixture.json', {'synthetic': True})
            return {'supervisor_sources_sha256': 'f'*64}

        def snapshot(directory, phase):
            events.append(phase)
            s.save(directory/f'environment-{phase}.json', {'synthetic': True})

        def fake_child(_binary, packet, given, directory, _signals, **_kwargs):
            self.assertEqual(packet, native.packet(given))
            events.append('child')
            if fault == 'startup-unknown':
                synthetic = {**given, 'evidence_kind': 'synthetic',
                             'binary_sha256': s.sha(self.binary)}

                def stalled(_process, *_args, **_options):
                    time.sleep(0.4)

                with patch.object(p, 'OUTER_SECONDS', 0.1), \
                        patch.object(subprocess.Popen, '__init__', new=stalled):
                    return actual_supervise(self.binary, native.packet(synthetic), synthetic,
                                            directory, _signals, synthetic=True)
            directory.mkdir()
            if fault == 'unknown':
                execution = {'returncode': None, 'timed_out': True, 'signal': 0,
                             'worker_pid': 555, 'wall_ns': 10**10}
                s.save(directory/'execution.json', execution)
                return execution, {'reaped': False, 'error': 'MOCK UNREAPABLE; no child spawned'}
            rows, execution, _ = fixture(cpu=given['cpu'])
            rows[0]['plan'] = given
            execution['worker_pid'] = 555
            rows[0]['worker_pid'] = rows[-1]['worker_pid'] = 555
            if fault == 'incomplete':
                rows = rows[:-1]
            raw = b'not JSON\n' if fault == 'malformed' else b''.join(
                s.canonical(row) for row in rows)
            (directory/'stdout.jsonl').write_bytes(raw)
            (directory/'stderr.txt').write_bytes(b'SYNTHETIC ONLY: no process executed\n')
            s.save(directory/'execution.json', execution)
            return execution, {'reaped': True, 'error': None}

        with ExitStack() as stack:
            for name, side in (('provenance', proof), ('environment_snapshot', snapshot),
                               ('supervise', fake_child)):
                stack.enter_context(patch.object(s, name, side_effect=side))
            stack.enter_context(patch.object(s, 'native_gate'))
            stack.enter_context(patch.object(s, 'target', return_value=self.identity()))
            stack.enter_context(patch.object(s, 'verify_build', return_value={}))
            if fault == 'seal':
                stack.enter_context(patch.object(
                    s, 'verify_archive', side_effect=ValueError('seal')))
            if fault == 'late-signal':
                original = s.seal

                def late(directory):
                    archive = original(directory)
                    signal.raise_signal(signal.SIGTERM)
                    return archive

                stack.enter_context(patch.object(s, 'seal', side_effect=late))
            result = s.run_session(plan_path, build, approval_path, mode=mode,
                                   note='SYNTHETIC ORCHESTRATION FIXTURE; NO HARDWARE',
                                   root=self.base/'runs', approved=True)
        return result, events

    def test_preflight_never_calls_worker(self):
        (container, code), events = self.orchestration(mode='preflight')
        self.assertEqual(code, 0)
        self.assertEqual(events, ['before', 'after'])
        self.assertFalse((container/'evidence/raw').exists())
        receipt = s.read_json(container/'receipt.json')
        self.assertEqual(receipt['state'], 'PREFLIGHT_ONLY_NO_EXECUTION')

    def test_launch_order_requires_predecessor_without_automatically_starting_it(self):
        root = self.base/'ordered'
        root.mkdir()
        _, _, second = fixture(cpu=0, seed=101)
        with patch.object(s.subprocess, 'Popen') as spawn:
            with self.assertRaises(FileNotFoundError):
                s.claim(root, second)
        spawn.assert_not_called()
        self.assertFalse((root/'.claims').exists())

    def test_orchestration_snapshots_bracket_one_boundary_and_seals(self):
        (container, code), events = self.orchestration()
        self.assertEqual(code, 0)
        self.assertEqual(events, ['before', 'child', 'after'])
        self.assertFalse((container.parent/'.active-worker.json').exists())
        s.verify_archive(container/'evidence', container/'evidence.tar.gz')

    def test_invalid_output_is_failed_sealed_evidence(self):
        (container, code), events = self.orchestration(fault='malformed')
        self.assertEqual(code, 1)
        self.assertEqual(events, ['before', 'child', 'after'])
        self.assertEqual((container/'evidence/raw/stdout.jsonl').read_bytes(), b'not JSON\n')
        self.assertTrue((container/'evidence/analysis/failure.json').exists())
        self.assertTrue((container/'evidence.tar.gz').exists())

    def test_incomplete_zero_exit_output_still_fails(self):
        (container, code), events = self.orchestration(fault='incomplete')
        self.assertEqual(code, 1)
        self.assertEqual(events, ['before', 'child', 'after'])
        failure = s.read_json(container/'evidence/analysis/failure.json')
        self.assertIn('Incomplete', failure['error'])

    def test_signal_during_sealing_cannot_produce_success_receipt(self):
        (container, code), _ = self.orchestration(fault='late-signal')
        self.assertEqual(code, 1)
        receipt = s.read_json(container/'receipt.json')
        self.assertEqual(receipt['actual_launcher_exit'], 1)
        self.assertEqual(receipt['signal'], signal.SIGTERM)
        s.verify_archive(container/'evidence', container/'evidence.tar.gz')

    def test_unknown_reaping_blocks_followup_and_skips_after_snapshot_and_seal(self):
        (container, code), events = self.orchestration(fault='unknown')
        self.assertEqual(code, 1)
        self.assertEqual(events, ['before', 'child'])
        self.assertTrue((container.parent/'.active-worker.json').exists())
        self.assertFalse((container/'evidence.tar.gz').exists())
        with self.assertRaises(p.VerificationError):
            with s.session_lock(container.parent):
                self.fail('Unknown child admitted next measurement')

    def test_interrupted_unobservable_startup_preserves_ownership_and_blocks_next_session(self):
        started = time.monotonic()
        (container, code), events = self.orchestration(fault='startup-unknown')
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(code, 1)
        self.assertEqual(events, ['before', 'child'])
        self.assertTrue((container.parent/'.active-worker.json').exists())
        self.assertFalse((container/'evidence.tar.gz').exists())
        self.assertIsNone(p.read_json(container/'evidence/raw/execution.json')['worker_pid'])
        receipt = s.read_json(container/'receipt.json')
        self.assertFalse(receipt['termination_known'])
        self.assertEqual(receipt['signal'], signal.SIGALRM)
        with self.assertRaises(p.VerificationError):
            with s.session_lock(container.parent):
                self.fail('Unknown startup admitted subsequent session')

    def test_seal_failure_is_retained_outside_evidence(self):
        (container, code), _ = self.orchestration(fault='seal')
        self.assertEqual(code, 1)
        self.assertTrue((container/'seal-failure.json').exists())
        self.assertTrue((container/'evidence/SHA256SUMS').exists())
        self.assertTrue((container/'evidence.tar.gz').exists())
        s.verify_manifest(container/'evidence')

    def calibration_fixture(self, cpu=0):
        # pylint: disable=too-many-locals
        root = self.base/f'calibration-{cpu}'
        root.mkdir()
        supervisor_hash, approval_hash = '1'*64, '2'*64
        references, plans = [], []
        for seed, identity in ((101, 'first'), (102, 'second')):
            _, _, plan = fixture(cpu=cpu, seed=seed, session_id=identity)
            plan['binary_sha256'] = s.sha(self.binary)
            plans.append(plan)
            container = root/plan['run_id']
            directory = container/'evidence'
            s.save(directory/'plan/launch.json', plan)
            rawdir, execution, detail = self.capture(plan)
            self.assertTrue(detail['reaped'])
            shutil.copytree(rawdir, directory/'raw')
            raw = (rawdir/'stdout.jsonl').read_bytes()
            s.save(directory/'analysis/validation.json', p.validate_output(raw, execution, plan))
            archive = s.seal(directory)
            receipt = {'state': 'VALIDATED', 'actual_launcher_exit': 0, 'signal': None,
                       'archive_sha256': s.sha(archive),
                       'supervisor_sources_sha256': supervisor_hash,
                       'approval_sha256': approval_hash,
                       'started_utc': '2026-01-01T00:00:00+00:00',
                       'finished_utc': '2026-01-01T00:00:01+00:00'}
            s.save(container/'receipt.json', receipt)
            (container/'receipt.json.sha256').write_text(
                s.sha(container/'receipt.json') + '  receipt.json\n')
            references.append({'run_id': plan['run_id'],
                               'evidence_manifest_sha256': s.sha(directory/'SHA256SUMS'),
                               'archive_sha256': s.sha(archive),
                               'receipt_sha256': s.sha(container/'receipt.json')})
        _, _, held = fixture(cpu=cpu, phase='held_out', seed=201, session_id='held_first')
        held['binary_sha256'] = s.sha(self.binary)
        freeze = {'schema_version': 1, 'protocol': p.PROTOCOL, 'phase': 'calibration',
                  'cpu': held['cpu'], 'cohort_id': held['cohort_id'],
                  'target_id': held['target_id'],
                  'blocks': held['blocks'], 'kernel_release': held['kernel_release'],
                  'provenance': {k: held[k] for k in s.HASH_FIELDS},
                  'supervisor_sources_sha256': supervisor_hash, 'approval_sha256': approval_hash,
                  'frozen_utc': '2026-01-02T00:00:00+00:00', 'decision': 'REVIEWED_PROCEED',
                  'calibration': references,
                  'held_out': [
                      {'run_id': held['run_id'], 'session_id': held['session_id'], 'seed': 201},
                      {'run_id': 'run_held_second', 'session_id': 'held_second', 'seed': 202}]}
        return root, held, freeze, supervisor_hash, approval_hash

    def check_freeze(self, fixture_data, mutate=None):
        root, held, freeze, supervisor_hash, approval_hash = fixture_data
        changed = deepcopy(freeze)
        if mutate:
            mutate(changed)
        path = self.base/('freeze-'+str(len(list(self.base.iterdir())))+'.json')
        s.save(path, changed)
        held = {**held, 'frozen_calibration_sha256': s.sha(path)}
        return s.frozen_calibration(path, held, root, supervisor_hash, approval_hash,
                                    '2026-01-03T00:00:00+00:00')

    def test_frozen_calibration_revalidates_two_sealed_sessions_without_pooling(self):
        for cpu in (0, 4):
            data = self.calibration_fixture(cpu)
            result = self.check_freeze(data)
            self.assertEqual(result['cpu'], cpu)
            self.assertEqual(result['phase'], 'calibration')

    def test_launch_predecessor_is_a_revalidated_real_synthetic_session(self):
        root, _, freeze, _, _ = self.calibration_fixture(cpu=4)
        previous = p.read_json(root/freeze['calibration'][0]['run_id']/'evidence/plan/launch.json')
        s.claim(root, previous)
        _, _, second = fixture(cpu=0, seed=101, session_id='next_cpu0')
        second['binary_sha256'] = s.sha(self.binary)
        s.claim(root, second)
        self.assertTrue((root/'.claims'/('session-'+second['session_id'])).exists())
        wrong = p.read_json(root/freeze['calibration'][1]['run_id']/'evidence/plan/launch.json')
        slot = root/'.claims'/f"slot-{previous['cohort_id']}-calibration-4-101"/'launch.json'
        slot.write_bytes(s.canonical(wrong))
        with self.assertRaisesRegex(p.VerificationError, 'slot identity'):
            s.claim(root, {**second, 'seed': 102, 'session_id': 'next_seed'})

    def test_frozen_chronology_provenance_cpu_and_held_out_identity_fail_closed(self):
        data = self.calibration_fixture()
        changes = [('cpu', 4), ('blocks', 3), ('phase', 'held_out'), ('cohort_id', 'other'),
                   ('kernel_release', 'other-kernel'),
                   ('decision', 'UNREVIEWED'), ('supervisor_sources_sha256', '3'*64),
                   ('approval_sha256', '4'*64), ('frozen_utc', '2026-01-04T00:00:00+00:00'),
                   ('frozen_utc', '2025-01-01T00:00:00+00:00')]
        for key, value in changes:
            with self.subTest(key=key, value=value), self.assertRaises(p.VerificationError):
                self.check_freeze(data, lambda f, k=key, v=value: f.update({k: v}))
        with self.assertRaises(p.VerificationError):
            self.check_freeze(data, lambda f: f['held_out'][0].update(session_id='unplanned'))
        with self.assertRaises(p.VerificationError):
            self.check_freeze(data, lambda f: f['calibration'][1].update(**f['calibration'][0]))

    def test_frozen_digest_and_calibration_tampering_rejected(self):
        root, held, freeze, shash, ahash = data = self.calibration_fixture()
        path = self.base/'freeze.json'
        s.save(path, freeze)
        with self.assertRaisesRegex(p.VerificationError, 'digest'):
            s.frozen_calibration(path, held, root, shash, ahash, '2026-01-03T00:00:00+00:00')
        receipt = root/freeze['calibration'][0]['run_id']/'receipt.json'
        receipt.write_bytes(receipt.read_bytes()+b' ')
        with self.assertRaises(p.VerificationError):
            self.check_freeze(data)


class BuildAdmissionTest(unittest.TestCase):
    def test_saved_cross_build_and_mutations_are_checked_without_execution(self):
        """Optional retained artifact; the tests never spawn its AArch64 binary."""
        # pylint: disable=too-many-locals
        source = ROOT/'build/m1-g3-p0-phase2-final/evidence'
        if not source.is_dir():
            self.skipTest('No retained Phase 2 cross-build; no artifact verification claim')
        with tempfile.TemporaryDirectory(prefix='p0-build-admission-') as temporary:
            base = Path(temporary)
            build = base/'build'
            shutil.copytree(source, build)
            record = s.read_json(build/'build.json', 65536)
            _, _, plan = fixture()
            plan.update({key: record[key] for key in s.HASH_FIELDS if key in record})
            plan['source_commit'] = record['git_head']
            plan['build_manifest_sha256'] = s.sha(build/'build.json')
            approval = {'schema_version': 1, 'protocol': p.PROTOCOL,
                        **{key: plan[key] for key in s.HASH_FIELDS}}
            with self.assertRaisesRegex(p.VerificationError, 'Clean compile-only'):
                s.verify_build(build, plan, approval, ROOT)
            # Synthetic build-admission fixture only; original evidence is not edited.
            record['dirty_checkout'] = False
            (build/'build.json').unlink()
            s.save(build/'build.json', record)
            plan['build_manifest_sha256'] = s.sha(build/'build.json')
            approval['build_manifest_sha256'] = plan['build_manifest_sha256']
            (build/'SHA256SUMS').unlink()
            entries = s.inventory(build)
            (build/'SHA256SUMS').write_text(''.join(
                f'{digest}  {name}\n' for name, digest in entries.items()))
            with patch.object(s.subprocess, 'Popen', side_effect=AssertionError('No execution')):
                s.verify_build(build, plan, approval, ROOT)
                for field in s.HASH_FIELDS:
                    changed = {**approval, field: '0'*len(approval[field])}
                    with self.subTest(field=field), self.assertRaises(p.VerificationError):
                        s.verify_build(build, plan, changed, ROOT)
                    changed_plan = {**plan, field: changed[field]}
                    with self.subTest(artifact=field), self.assertRaises(p.VerificationError):
                        s.verify_build(build, changed_plan, changed, ROOT)
                worker = build/'worker'
                worker.write_bytes(worker.read_bytes()+b'tampered')
                with self.assertRaisesRegex(p.VerificationError, 'Manifest'):
                    s.verify_build(build, plan, approval, ROOT)


if __name__ == '__main__':
    unittest.main()
