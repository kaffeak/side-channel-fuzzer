"""Real C core with a synthetic backend; cross-built AArch64 code is never executed."""
# pylint: disable=missing-function-docstring,missing-class-docstring,too-many-public-methods
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from tools import m1_g3_p0 as p, m1_g3_p0_native as native
from tests.unit_m1_g3_p0 import fixture

ROOT = Path(__file__).resolve().parents[1]
C_DIR = ROOT / 'tools/exclusiveReservation'
GOLDEN = {
    101: ([0, 4, 3, 5, 2, 1], 'b10e73fbf1b21f3a2df8f7c3934181d0871bb2e85d0f9ccf23e1d03cbc25e621'),
    102: ([1, 3, 4, 5, 0, 2], '510f9cba1715e0c8e0c31129661f0d72e675801f61b9b7e29ae78540503a38c8'),
    201: ([2, 4, 3, 0, 1, 5], '1dfb6c3598ae9213f0a2c25ba30d018c3d53b36cad02575d83a4fc882945fc20'),
    202: ([1, 5, 0, 4, 3, 2], '7641aa621eb907cd8c5ccab7b7bcb8bd4116a4319e4a0ff91d6529695df89476'),
}


class WorkerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
            prefix='p0-host-only-')
        cls.directory = Path(cls.temporary.name)
        cls.cc = shutil.which('cc')
        if not cls.cc:
            raise RuntimeError('Host C compiler required; these are software-only tests')
        common = [cls.cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(C_DIR),
                  str(C_DIR / 'worker.c'), str(ROOT / 'tests/m1_g3_p0/host.c')]
        cls.binary = cls.directory / 'synthetic-worker'
        subprocess.run([*common, '-o', str(cls.binary)],
                       check=True, timeout=60, capture_output=True)
        cls.library = cls.directory / 'schedule.so'
        subprocess.run(
            [*common, '-fPIC', '-shared', '-Dmain=p0_unused_main', '-o', str(cls.library)],
            check=True, timeout=60, capture_output=True)
        cls.api = ctypes.CDLL(str(cls.library))
        cls.api.p0_order.argtypes = [
            ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint32)]
        cls.api.p0_results_bytes.argtypes = [ctypes.c_uint]
        cls.api.p0_results_bytes.restype = ctypes.c_size_t

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_worker(self, plan, *, fault=None, data=None, binary=None, environment_override=None):
        environment = {key: value for key, value in os.environ.items() if key != 'P0_HOST_FAULT'}
        if fault:
            environment['P0_HOST_FAULT'] = fault
        environment.update(environment_override or {})
        start = time.monotonic_ns()
        with subprocess.Popen([str(binary or self.binary)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=environment) as process:
            try:
                packet = native.packet(plan) if data is None else data
                raw, stderr = process.communicate(packet, timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=2)
                self.fail('Synthetic worker exceeded test bound; no retry')
        execution = {'returncode': process.returncode, 'timed_out': False,
                     'signal': -process.returncode if process.returncode < 0 else 0,
                     'worker_pid': process.pid, 'wall_ns': time.monotonic_ns() - start}
        return raw, stderr, execution

    def test_c_schedule_byte_for_byte_all_phase_seeds_and_frozen_hashes(self):
        for seed, (first, sha) in GOLDEN.items():
            state = ctypes.c_uint32(seed)
            data = bytearray()
            for _ in range(64):
                order = (ctypes.c_uint * 6)()
                self.api.p0_order(order, ctypes.byref(state))
                data.extend(list(order))
            expected = bytes(p.CONDITIONS.index(c) for c in p.schedule(seed, 64))
            with self.subTest(seed=seed):
                self.assertEqual(bytes(data), expected)
                self.assertEqual(list(data[:6]), first)
                self.assertEqual(hashlib.sha256(data[:192]).hexdigest(), sha)

    def test_result_geometry_all_block_counts_and_invalid_bounds(self):
        for blocks in range(1, 65):
            size = self.api.p0_results_bytes(blocks)
            self.assertEqual(size, ((128 + 6 * blocks * 128 + 16383) // 16384) * 16384)
            self.assertEqual(size % 16384, 0)
            self.assertLessEqual(size, 65536)
            self.assertLessEqual(3 * 16384 + size + 524288 + 65536 + 32768, 1048576)
        for blocks in (0, 65, 2 ** 32 - 1):
            self.assertEqual(self.api.p0_results_bytes(blocks), 0)

    def test_real_c_capture_and_serialization_match_frozen_validator(self):
        for cpu in (0, 4):
            for phase, seed in (('calibration', 101), ('calibration', 102),
                                ('held_out', 201), ('held_out', 202)):
                _, _, plan = fixture(cpu=cpu, phase=phase, seed=seed, blocks=32)
                raw, stderr, execution = self.run_worker(plan)
                with self.subTest(cpu=cpu, seed=seed):
                    self.assertEqual(execution['returncode'], 0, stderr)
                    result = p.validate_output(raw, execution, plan)
                    self.assertEqual(result['architectural_assessment'],
                                     'CONTROLS_OBSERVED_REVIEW_REQUIRED')
                    self.assertFalse(result['physical_execution_attested'])
                    self.assertFalse(result['g3_accepted'])
                    self.assertEqual(len(raw.splitlines()), 194)
                    records = [json.loads(line) for line in raw.splitlines()]
                    self.assertEqual(records[0]['plan'], plan)
                    self.assertLessEqual(records[0]['owned_bytes'], p.MAX_OWNED)
                    self.assertTrue(all(row['attempted_value'] == str(p.ATTEMPTED)
                                        for row in records if row['kind'] == 'sample'))

    def test_unicode_kernel_and_json_escaping_round_trip(self):
        _, _, plan = fixture()
        plan['kernel_release'] = 'synthetic-α-"quoted"'
        raw, stderr, execution = self.run_worker(plan)
        self.assertEqual(execution['returncode'], 0, stderr)
        p.validate_output(raw, execution, plan)

    def test_maximum_trial_and_output_ceiling(self):
        _, _, plan = fixture(blocks=64)
        raw, stderr, execution = self.run_worker(plan)
        self.assertEqual(execution['returncode'], 0, stderr)
        p.validate_output(raw, execution, plan)
        self.assertEqual(len(raw.splitlines()), 386)
        self.assertLess(len(raw), p.MAX_BYTES)
        self.assertTrue(all(len(line) <= 8192 for line in raw.splitlines()))

    def test_adjacent_failures_are_observations_without_retries(self):
        _, _, plan = fixture()
        raw, stderr, execution = self.run_worker(plan, fault='adjacent_fail')
        self.assertEqual(execution['returncode'], 0, stderr)
        result = p.validate_output(raw, execution, plan)
        self.assertEqual(result['architectural_assessment'], 'INCONCLUSIVE_NO_BASELINE_SUCCESS')
        self.assertEqual(sum(sum(value.values()) for value in result['counts'].values()), 12)

    def test_setup_affinity_and_allocation_failures_do_not_emit_success(self):
        _, _, plan = fixture()
        for fault in ('allocation', 'protection', 'platform', 'affinity', 'cpu_before'):
            raw, _, execution = self.run_worker(plan, fault=fault)
            with self.subTest(fault=fault):
                self.assertNotEqual(execution['returncode'], 0)
                rows = [json.loads(line) for line in raw.splitlines()]
                self.assertFalse(any(row['kind'] == 'sample' for row in rows))
                self.assertEqual(rows[-1]['kind'], 'error')
                with self.assertRaises(p.VerificationError):
                    p.validate_output(raw, execution, plan)

    def test_invalid_architectural_results_are_retained_before_error(self):
        _, _, plan = fixture()
        for fault in ('bad_status', 'bad_value', 'bad_canary', 'clear_success', 'cpu_after',
                      'mask_after', 'no_status'):
            raw, _, execution = self.run_worker(plan, fault=fault)
            with self.subTest(fault=fault):
                self.assertNotEqual(execution['returncode'], 0)
                rows = [json.loads(line) for line in raw.splitlines()]
                samples = [row for row in rows if row['kind'] == 'sample']
                self.assertGreater(len(samples), 0)
                self.assertEqual(rows[-1]['kind'], 'error')
                self.assertEqual(rows[-1]['samples_emitted'], len(samples))
                self.assertFalse(any(row['kind'] == 'complete' for row in rows))
                if fault == 'no_status':
                    self.assertEqual(samples[0]['stxr_status'], 2 ** 32 - 1)

    def test_trap_and_watchdog_signal_preserve_actual_prefix_and_signal_exit(self):
        _, _, plan = fixture()
        for fault, sig in (('trap', 4), ('timeout', 14)):
            raw, stderr, execution = self.run_worker(plan, fault=fault)
            with self.subTest(fault=fault):
                self.assertEqual(execution['returncode'], -sig)
                rows = [json.loads(line) for line in raw.splitlines()]
                self.assertEqual(sum(row['kind'] == 'sample' for row in rows), 2)
                self.assertEqual(rows[-1]['signal'], sig)
                self.assertEqual(rows[-1]['samples_emitted'], 2)
                self.assertIn(b'preserve partial evidence', stderr)
                with self.assertRaises(p.VerificationError):
                    p.validate_output(raw, execution, plan)

    def test_untrappable_kill_retains_flushed_prefix_without_a_success_footer(self):
        _, _, plan = fixture()
        raw, _, execution = self.run_worker(plan, fault='hard_kill')
        self.assertEqual(execution['returncode'], -9)
        rows = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(rows), 3)  # Metadata and two fully completed records.
        self.assertEqual([r['index'] for r in rows[1:]], [0, 1])
        with self.assertRaises(p.VerificationError):
            p.validate_output(raw, execution, plan)

    def test_actual_child_cpu_and_wall_limits_are_configured(self):
        _, _, plan = fixture()
        raw, stderr, execution = self.run_worker(plan, fault='limits')
        self.assertEqual(execution['returncode'], 0, stderr)
        p.validate_output(raw, execution, plan)
        _, soft, hard, wall = stderr.decode().strip().split(':')
        self.assertLessEqual(int(soft), 2)
        self.assertLessEqual(int(hard), 2)
        self.assertGreater(int(wall), 0)
        self.assertLessEqual(int(wall), 10)

    def test_native_physical_label_cannot_enable_host_backend(self):
        _, _, plan = fixture()
        plan['evidence_kind'] = 'physical'
        raw, _, execution = self.run_worker(plan)
        self.assertNotEqual(execution['returncode'], 0)
        self.assertFalse(any(json.loads(row)['kind'] == 'sample' for row in raw.splitlines()))

    def test_malformed_truncated_extra_packets_and_parameter_bounds_reject(self):
        _, _, plan = fixture()
        valid = native.packet(plan)
        cases = [b'', valid[:-1], valid + b'x', b'WRONG!!!' + valid[8:]]
        for offset, value in ((8, 1), (12, 0), (16, 0), (16, 65), (20, 2), (24, 2)):
            changed = bytearray(valid)
            struct.pack_into('<I', changed, offset, value)
            cases.append(bytes(changed))
        changed = bytearray(valid)
        struct.pack_into('<H', changed, 28, 129)
        cases.append(bytes(changed))
        for index, packet in enumerate(cases):
            raw, _, execution = self.run_worker(plan, data=packet)
            with self.subTest(index=index):
                self.assertNotEqual(execution['returncode'], 0)
                self.assertFalse(any(json.loads(row)['kind'] == 'sample'
                                     for row in raw.splitlines()))

    def test_address_and_undefined_sanitizers_valid_bounded_c_core(self):
        _, _, plan = fixture()
        for sanitizer in ('address', 'undefined'):
            binary = self.directory / ('synthetic-' + sanitizer)
            subprocess.run([self.cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fno-omit-frame-pointer', '-fsanitize=' + sanitizer,
                            '-I' + str(C_DIR), str(C_DIR / 'worker.c'),
                            str(ROOT / 'tests/m1_g3_p0/host.c'), '-o', str(binary)],
                           check=True, timeout=60, capture_output=True)
            # LSan is unsupported under this environment's ptrace. Bounds checks
            # stay enabled, matching existing host-harness tests; no leak-check claim.
            options = ({'ASAN_OPTIONS': 'detect_leaks=0:halt_on_error=1'}
                       if sanitizer == 'address' else
                       {'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'})
            raw, stderr, execution = self.run_worker(
                plan, binary=binary, environment_override=options)
            self.assertEqual(execution['returncode'], 0, stderr)
            self.assertNotIn(b'runtime error:', stderr)
            self.assertNotIn(b'ERROR: AddressSanitizer', stderr)
            p.validate_output(raw, execution, plan)


class CrossBuildTest(unittest.TestCase):
    def test_aarch64_compile_full_disassembly_and_fail_closed_mutations(self):
        # pylint: disable=too-many-locals
        cc = os.environ.get('P0_AARCH64_CC') or shutil.which('aarch64-linux-gnu-gcc')
        objdump = os.environ.get('P0_AARCH64_OBJDUMP') or shutil.which('aarch64-linux-gnu-objdump')
        readelf = os.environ.get('P0_AARCH64_READELF') or shutil.which('aarch64-linux-gnu-readelf')
        if not all((cc, objdump, readelf)):
            self.skipTest('No AArch64 compiler/disassembler; '
                          'cannot claim machine-code verification')
        with tempfile.TemporaryDirectory(prefix='p0-cross-build-only-') as temporary:
            root = Path(temporary) / 'evidence'
            native.build(root, cc, objdump, readelf,
                         os.environ.get('P0_AARCH64_SYSROOT'))
            binary = (root / 'worker').read_bytes()
            dump = (root / 'full-disassembly.stdout').read_text()
            symbols = (root / 'symbols.stdout').read_text()
            manifest = json.loads((root / 'build.json').read_text())
            self.assertEqual(manifest['flags'], list(native.FLAGS))
            self.assertEqual(manifest['commands'], json.loads((root / 'commands.json').read_text()))
            self.assertEqual(set(manifest['tool_versions']),
                             {'compiler', 'linker', 'objdump', 'readelf'})
            checked = native.verify(binary, dump, symbols)
            self.assertEqual(len(checked['p0_adjacent']), 8)
            self.assertEqual(len(checked['p0_clear']), 9)
            self.assertEqual(len(checked['p0_sham']), 9)
            self.assertEqual(checked['p0_clear_old'], ['clrex', 'ret'])
            for original, changed in (('ldxr\tx3, [x0]', 'ldxr\tw3, [x0]'),
                                      ('stxr\tw4, x1, [x0]', 'stxr\tw1, x1, [x0]'),
                                      ('dmb\tish', 'bl\t0'), ('clrex', 'nop'),
                                      ('str\tw4, [x2, #16]', 'str\tw4, [x2, #20]')):
                self.assertIn(original, dump)
                with self.subTest(mutation=changed), self.assertRaises(p.VerificationError):
                    native.verify(binary, dump.replace(original, changed), symbols)
            first = re.search(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+dmb\tish', dump)
            self.assertIsNotNone(first)
            bad = dump[:first.start(2)] + '00000000' + dump[first.end(2):]
            with self.assertRaisesRegex(p.VerificationError, 'ELF instruction bytes'):
                native.verify(binary, bad, symbols)
            with self.assertRaises(p.VerificationError):
                native.verify(binary, dump, symbols.replace('p0_clear_old', 'missing_clear_old'))
            with self.assertRaises(FileExistsError):
                native.build(root, cc, objdump, readelf)
            for line in (root / 'SHA256SUMS').read_text().splitlines():
                sha, name = line.split('  ', 1)
                self.assertEqual(sha, native.sha(root / name))

    def test_build_failure_preserves_sources_diagnostics_and_manifest(self):
        with tempfile.TemporaryDirectory(prefix='p0-build-failure-') as temporary:
            root = Path(temporary) / 'evidence'
            with self.assertRaises(OSError):
                native.build(root, '/definitely-not-a-compiler', 'objdump', 'readelf')
            self.assertEqual(json.loads((root / 'build.json').read_text())['state'], 'FAILED')
            self.assertTrue((root / 'tools/exclusiveReservation/probe.S').is_file())
            self.assertTrue((root / 'SHA256SUMS').is_file())


if __name__ == '__main__':
    unittest.main()
