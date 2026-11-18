"""One-shot inventory tests against synthetic sysfs, never the desktop's sensors."""
import contextlib
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import investigate_hwmon as diag


class HwmonInvestigationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hwmon-fixture-')
        self.root = Path(self.temp.name)
        self.hwmon = self.root / 'sys/class/hwmon'
        self.hwmon.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path, text):
        target = self.hwmon / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def capture(self):
        rows = []
        diag.collect(self.root, rows.append)
        return rows

    @staticmethod
    def reading(rows, suffix):
        return next(row for row in rows if row['kind'] == 'read'
                    and row['source'].endswith(suffix))

    def test_empty_and_unreadable_inventory_is_unavailable(self):
        rows = self.capture()
        listing = next(row for row in rows if row['kind'] == 'enumeration')
        self.assertEqual(listing['status'], 'UNAVAILABLE')
        self.assertEqual(listing['names_in_discovery_order'], [])
        with patch.object(diag.os, 'scandir', side_effect=PermissionError('fixture denied')):
            rows = self.capture()
        listing = next(row for row in rows if row['kind'] == 'enumeration')
        self.assertFalse(listing['enumeration_complete'])
        self.assertIn('PermissionError', listing['error'])
        self.assertEqual(rows[-1]['status'], 'PARTIAL')

    def test_more_than_eight_controllers_include_previously_omittable_values(self):
        for n in range(12):
            self.put(f'hwmon{n}/name', f'fixture{n}')
            self.put(f'hwmon{n}/temp1_input', '0' if n == 11 else '42000')
        rows = self.capture()
        self.assertEqual(len([r for r in rows if r.get('source', '').endswith('/name')]), 12)
        self.assertEqual(self.reading(rows, 'hwmon11/temp1_input')['value'], 0)
        selection = next(row for row in rows if row['kind'] == 'selection')
        self.assertEqual(selection['selected'], [f'hwmon{n}' for n in range(12)])
        self.assertFalse(selection['truncated'])
        self.assertEqual(len(selection['legacy_omitted_observed']), 4)

    def test_selection_deterministic_under_reversed_directory_order(self):
        for n in range(12):
            self.put(f'hwmon{n}/name', 'fixture')
        original = os.scandir

        @contextlib.contextmanager
        def reversed_scan(path):
            with original(path) as entries:
                yield iter(reversed(list(entries)))

        with patch.object(diag, 'MAX_CONTROLLERS', 8):
            one = next(row for row in self.capture() if row['kind'] == 'selection')
            with patch.object(diag.os, 'scandir', reversed_scan):
                two = next(row for row in self.capture() if row['kind'] == 'selection')
        self.assertEqual(one['selected'], two['selected'])
        self.assertEqual(one['selected'], [f'hwmon{n}' for n in range(8)])
        self.assertTrue(one['truncated'])

    def test_filtering_precedes_sensor_limit_and_power_average_is_explicit(self):
        for n in range(20):
            self.put(f'hwmon0/humidity{n}_input', 'PRIVATE_UNSUPPORTED')
        self.put('hwmon0/name', 'fixture')
        self.put('hwmon0/temp1_input', '-500')
        self.put('hwmon0/power1_average', '1000')
        self.put('hwmon0/power1_label', 'driver power label')
        rows = self.capture()
        self.assertEqual(self.reading(rows, 'temp1_input')['value'], -500)
        self.assertEqual(self.reading(rows, 'power1_average')['unit'], 'microwatts')
        self.assertEqual(self.reading(rows, 'power1_label')['value'], 'driver power label')
        self.assertNotIn('PRIVATE_UNSUPPORTED', json.dumps(rows))

    def test_missing_labels_unreadable_invalid_and_valid_zero_are_distinct(self):
        self.put('hwmon0/name', 'fixture')
        self.put('hwmon0/fan1_input', '0')
        self.put('hwmon0/temp1_input', 'unexpected')
        self.put('hwmon0/in1_input', '123')
        real_open = Path.open

        def reading(path, mode='r', *args, **kwargs):
            self.assertEqual(mode, 'rb')
            if path.name == 'in1_input':
                raise PermissionError('fixture unreadable')
            return real_open(path, mode, *args, **kwargs)

        with patch.object(Path, 'open', reading):
            rows = self.capture()
        self.assertEqual(self.reading(rows, 'fan1_input')['value'], 0)
        label = self.reading(rows, 'fan1_label')
        self.assertTrue(label['optional'])
        self.assertEqual(label['status'], 'UNAVAILABLE')
        self.assertIsNone(label['value'])
        invalid = self.reading(rows, 'temp1_input')
        self.assertEqual(invalid['reported_text'], 'unexpected')
        self.assertIsNone(invalid['value'])
        self.assertIn('PermissionError', self.reading(rows, 'in1_input')['error'])
        self.assertEqual(rows[-1]['status'], 'PARTIAL')

    def test_sysfs_symlinks_and_broken_links_are_preserved(self):
        device = self.root / 'devices/fixture'
        device.mkdir(parents=True)
        (device / 'name').write_text('fixture')
        (device / 'curr1_input').write_text('10')
        (self.hwmon / 'hwmon0').symlink_to(device, target_is_directory=True)
        (self.hwmon / 'hwmon1').symlink_to(self.root / 'absent', target_is_directory=True)
        (self.hwmon / 'hwmon2').symlink_to(self.hwmon / 'hwmon2', target_is_directory=True)
        rows = self.capture()
        self.assertEqual(self.reading(rows, 'hwmon2/name')['status'], 'UNAVAILABLE')
        link = self.reading(rows, '/hwmon0')
        self.assertEqual(link['value'], '/devices/fixture')
        self.assertEqual(self.reading(rows, 'curr1_input')['value'], 10)
        self.assertEqual(self.reading(rows, 'hwmon1/name')['status'], 'UNAVAILABLE')

    def test_discovery_input_and_deadline_caps_are_explicit(self):
        for n in range(5):
            self.put(f'hwmon0/temp{n}_input', '1')
        with patch.object(diag, 'MAX_INPUTS', 2):
            rows = self.capture()
        selection = [row for row in rows if row['kind'] == 'selection'][1]
        self.assertTrue(selection['truncated'])
        self.assertEqual(len(selection['supported_observed']), 5)
        self.assertEqual(len(selection['selected']), 2)
        with patch.object(diag, 'MAX_ENTRIES', 2):
            rows = self.capture()
        enumeration = [row for row in rows if row['kind'] == 'enumeration'][1]
        self.assertFalse(enumeration['enumeration_complete'])
        with patch.object(diag, 'SECONDS', 0):
            rows = self.capture()
        self.assertEqual(rows[-1]['status'], 'PARTIAL')
        self.assertTrue(any('deadline' in row.get('error', '') for row in rows))
        self.assertLess(len(json.dumps(rows)), diag.MAX_OUTPUT)

    def test_worker_output_cap_fails_without_fabricating_complete_record(self):
        with patch.object(diag, 'MAX_OUTPUT', 1), patch.object(diag, 'collect') as collect, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            collect.side_effect = lambda _root, emit: emit({'kind': 'metadata'})
            with self.assertRaisesRegex(RuntimeError, 'Output limit'):
                diag.worker()
        self.assertEqual(output.getvalue(), '')

    def test_creation_signal_is_deferred_until_owned_worker_can_be_stopped(self):
        worker = unittest.mock.Mock()
        worker.poll.return_value = None
        worker.wait.return_value = -9
        handlers = {}

        def installing(number, handler):
            handlers[number] = handler
            return None

        def launch(_command, **_kwargs):
            handlers[diag.signal.SIGINT](diag.signal.SIGINT, None)
            return worker

        with patch.object(diag, 'OUTPUT', self.root / 'output'), \
                patch.object(diag.os, 'geteuid', return_value=1000), \
                patch.object(diag.os, 'umask'), \
                patch.object(diag.signal, 'signal', side_effect=installing), \
                patch.object(diag.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, b'fixture\n', b'')), \
                patch.object(diag.subprocess, 'Popen', side_effect=launch), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(diag.main(), 1)
        worker.kill.assert_called_once()
        status = json.loads(next((self.root / 'output').glob('*/status.json')).read_text())
        self.assertEqual(status['state'], 'INCOMPLETE')
        self.assertIn('during worker creation', status['error'])
        self.assertEqual(status['returncode'], -9)

    def test_supervisor_timeout_preserves_raw_error_status_and_checksums(self):
        worker = unittest.mock.Mock()
        worker.wait.side_effect = [subprocess.TimeoutExpired(['fixture'], 10), -9]
        worker.poll.return_value = None
        provenance = subprocess.CompletedProcess([], 0, b'fixture-commit\n', b'')

        def launch(_command, **kwargs):
            kwargs['stdout'].write(b'{"kind":"metadata"}\n')
            kwargs['stdout'].flush()
            kwargs['stderr'].write(b'fixture diagnostic\n')
            kwargs['stderr'].flush()
            return worker

        with patch.object(diag, 'OUTPUT', self.root / 'output'), \
                patch.object(diag.os, 'geteuid', return_value=1000), \
                patch.object(diag.os, 'umask'), \
                patch.object(diag.signal, 'signal'), \
                patch.object(diag.subprocess, 'run', return_value=provenance), \
                patch.object(diag.subprocess, 'Popen', side_effect=launch), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(diag.main(), 1)
        worker.kill.assert_called_once()
        directory = next((self.root / 'output').iterdir())
        status = json.loads((directory / 'status.json').read_text())
        self.assertEqual(status['state'], 'INCOMPLETE')
        self.assertEqual(status['returncode'], -9)
        self.assertEqual((directory / 'raw.jsonl').read_bytes(), b'{"kind":"metadata"}\n')
        self.assertEqual((directory / 'stderr.txt').read_text(), 'fixture diagnostic\n')
        self.assertIn('  raw.jsonl', (directory / 'SHA256SUMS').read_text())
        self.assertNotIn('  SHA256SUMS', (directory / 'SHA256SUMS').read_text())
        for line in (directory / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ', 1)
            self.assertEqual(digest, hashlib.sha256((directory / name).read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
