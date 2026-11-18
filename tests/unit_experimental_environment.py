"""Synthetic Linux interface tests; no hardware measurement or live telemetry collection."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import experimental_environment as env


class EnvironmentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="environment-fixture-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path, text):
        dest = self.root / path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)

    def capture(self, **kwargs):
        # Runtime queries are deterministic fixtures too, not assertions about the desktop.
        with patch.object(env.os, "sysconf", side_effect=lambda name: {
                "SC_PAGESIZE": 16384, "SC_CLK_TCK": 100}[name]), \
                patch.object(env.os, "sched_getaffinity", return_value={0, 4}), \
                patch.object(env.os, "uname",
                             return_value=("Linux", "fixture", "kernel", "", "arm64")), \
                patch.object(env.os, "getpid", return_value=123), \
                patch.object(env.os, "getppid", return_value=124):
            return env.snapshot(self.root, **kwargs)

    @staticmethod
    def row(report, source):
        return next(row for row in report["records"] if row["source"] == source)

    def test_missing_sensors_explicitly_unavailable_not_zero(self):
        report = self.capture()
        self.assertEqual(report["status"], "PARTIAL")
        for category in ("power", "thermal", "hwmon", "frequency"):
            rows = [row for row in report["records"] if row["category"] == category]
            self.assertTrue(rows)
            self.assertTrue(all(row["status"] == "UNAVAILABLE" for row in rows))
            self.assertTrue(all(row["value"] is None and row["error"] for row in rows))
        self.assertEqual(self.row(report, "sysconf(SC_PAGESIZE)")["value"], 16384)

    def test_units_names_zero_and_negative_temperature_are_preserved(self):
        values = {"/sys/class/thermal/thermal_zone0/type": "unmapped_sensor",
                  "/sys/class/thermal/thermal_zone0/temp": "-500",
                  "/sys/class/hwmon/hwmon0/name": "fixture-controller",
                  "/sys/class/hwmon/hwmon0/temp1_input": "0",
                  "/sys/class/hwmon/hwmon0/temp1_label": "unverified board sensor",
                  "/sys/class/power_supply/BAT0/capacity": "73",
                  "/sys/class/power_supply/AC/online": "0",
                  "/sys/class/power_supply/BAT0/voltage_now": "12000000",
                  "/sys/class/power_supply/BAT0/current_now": "-10000",
                  "/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq": "2000000"}
        for path, value in values.items():
            self.put(path, value)
        report = self.capture()
        for path, value, unit in (("/sys/class/thermal/thermal_zone0/temp", -500,
                                   "millidegrees Celsius"),
                                  ("/sys/class/hwmon/hwmon0/temp1_input", 0,
                                   "millidegrees Celsius"),
                                  ("/sys/class/power_supply/AC/online", 0, "0=offline, 1=online"),
                                  ("/sys/class/power_supply/BAT0/capacity", 73, "percent"),
                                  ("/sys/class/power_supply/BAT0/voltage_now", 12000000,
                                   "microvolts"),
                                  ("/sys/class/power_supply/BAT0/current_now", -10000, "microamps"),
                                  ("/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq",
                                   2000000, "kHz")):
            with self.subTest(source=path):
                row = self.row(report, path)
                self.assertEqual((row["value"], row["unit"]), (value, unit))
                self.assertEqual(row["status"], "OS_REPORTED")
                self.assertTrue(row["observed_utc"].endswith("+00:00"))
        self.assertIn("mapping UNKNOWN", self.row(
            report, "/sys/class/thermal/thermal_zone0/type")["unit"])

    def test_unexpected_sensor_values_have_diagnostics_not_fabricated_values(self):
        for path, text in (("/sys/class/thermal/thermal_zone0/temp", "N/A"),
                           ("/sys/class/power_supply/BAT0/capacity", "101"),
                           ("/sys/class/power_supply/AC/online", "2")):
            self.put(path, text)
        report = self.capture()
        for path in ("/sys/class/thermal/thermal_zone0/temp",
                     "/sys/class/power_supply/BAT0/capacity", "/sys/class/power_supply/AC/online"):
            row = self.row(report, path)
            self.assertEqual(row["status"], "UNAVAILABLE")
            self.assertIsNone(row["value"])
            self.assertIn("ValueError", row["error"])
            self.assertIn("raw_diagnostic", row)

    def test_unreadable_interface_is_explicit(self):
        reader = env.Reader(self.root, 2)
        with patch.object(Path, "open", side_effect=PermissionError("fixture permission denied")):
            self.assertIsNone(reader.read("/sensor", "thermal", "millidegrees Celsius"))
        self.assertIn("PermissionError", reader.records[0]["error"])
        self.assertIsNone(reader.records[0]["value"])

    def test_collection_is_read_only_and_ignores_sensitive_process_files(self):
        self.put("/proc/123/cmdline", "PRIVATE_COMMAND")
        self.put("/proc/123/environ", "PRIVATE_ENV")
        self.put("/sys/class/power_supply/BAT0/serial_number", "PRIVATE_SERIAL")
        real_open, modes = Path.open, []

        def reading(path, mode="r", *args, **kwargs):
            modes.append(mode)
            self.assertNotIn(path.name, {"cmdline", "environ", "serial_number"})
            return real_open(path, mode, *args, **kwargs)

        with patch.object(Path, "open", reading):
            report = self.capture()
        self.assertTrue(modes)
        self.assertEqual(set(modes), {"rb"})
        self.assertNotIn("PRIVATE_", json.dumps(report))

    def test_process_fields_and_derived_utilization_are_contextualized(self):
        fields = ["0"] * 40
        fields[0], fields[11], fields[12] = "S", "100", "100"
        fields[19], fields[21], fields[36] = "1000", "2", "4"
        self.put("/proc/123/stat", "123 (fixture process) " + " ".join(fields))
        self.put("/proc/uptime", "20.00 10.00")
        self.put("/proc/meminfo", "MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
        self.put("/proc/stat", "cpu 1 2 3 4\ncpu0 1 2 3 4\nprocs_running 2")
        report = self.capture()
        proc = self.row(report, "/proc/123/stat")["value"]
        self.assertEqual(proc["name"], "fixture process")
        self.assertEqual(proc["last_cpu"], 4)
        derived = [row for row in report["records"]
                   if row["source"].startswith("/proc/123/stat +")]
        self.assertEqual([row["value"] for row in derived], [20.0, 3.125])
        self.assertTrue(all(row["status"] == "DERIVED" for row in derived))
        self.assertIn("since process start", derived[0]["unit"])
        self.assertEqual(self.row(report, "/proc/meminfo:SwapFree")["status"], "UNAVAILABLE")

    def test_midr_lookup_is_explicit_and_unknown_is_not_guessed(self):
        for cpu, midr in ((0, "0x611f0221"), (4, "0x611f0231"), (7, "unexpected")):
            self.put(f"/sys/devices/system/cpu/cpu{cpu}/regs/identification/midr_el1", midr)
        report = self.capture()
        labels = [row["value"] for row in report["records"] if row["unit"] == "core type"]
        self.assertEqual(labels, ["Icestorm", "Firestorm", "UNKNOWN"])

    def test_per_read_record_deadline_and_enumeration_limits(self):
        self.put("/big", "x" * (env.MAX_FILE + 1))
        reader = env.Reader(self.root, 2)
        self.assertIsNone(reader.read("/big", "test", "bytes"))
        self.assertIn("size limit", reader.records[-1]["error"])
        for index in range(5):
            self.put(f"/devices/{index}", "1")
        self.assertEqual(len(reader.glob("/devices/*", "test", 2)), 2)
        self.assertTrue(reader.limited)
        self.assertTrue(reader.records[-1]["truncated"])
        report = self.capture(seconds=0)
        self.assertTrue(any("deadline" in (row["error"] or "") for row in report["records"]))
        with patch.object(env, "MAX_RECORDS", 1):
            reader = env.Reader(self.root, 2)
            reader.record("test", "first", "unit", 1)
            reader.read("/absent", "test", "unit")
            self.assertEqual(len(reader.records), 1)
            self.assertEqual(reader.records[0]["source"], "first")
            self.assertNotIn("raw_diagnostic", reader.records[0])
            self.assertTrue(reader.limited)

    def test_nonfinite_uptime_is_unavailable_and_output_remains_json(self):
        self.put("/proc/uptime", "NaN 0")
        report = self.capture()
        self.assertEqual(self.row(report, "/proc/uptime")["status"], "UNAVAILABLE")
        self.assertLess(len(json.dumps(report, allow_nan=False).encode()), env.MAX_JSON)


if __name__ == "__main__":
    unittest.main()
