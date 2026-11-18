"""Synthetic Linux interface tests; no hardware measurement or live telemetry collection."""
import ast
import contextlib
import errno
import io
import json
import os
import random
import types
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

    def m1_inventory(self):
        # Controller identity/counts/order are supplied physical evidence. Attribute
        # names, labels and values below are synthetic representatives, not raw M1 data.
        for index, name in enumerate(("nvme", "macsmc_hwmon", "macsmc_battery", "fixture_empty",
                                      "fixture_empty", "tas2770", "tas2770", "tas2770",
                                      "tas2770", "fixture_empty")):
            self.put(f"/sys/class/hwmon/hwmon{index}/name", name)
        inputs = {0: ["temp1"],
                  1: ["fan1", "power1", "power2", "in0", "in1", "curr1", "curr2",
                      "temp1", "temp2", "temp3", "temp4", "temp5"],
                  2: ["temp1", "in0", "curr1", "power1"],
                  **{n: ["temp1"] for n in range(5, 9)}}
        for controller, names in inputs.items():
            for name in names:
                base = f"/sys/class/hwmon/hwmon{controller}/{name}"
                self.put(base + "_input", "0" if name == "fan1" else "42000")
                if controller == 1:
                    self.put(base + "_label", "synthetic component " + name)
        real_open = Path.open

        def reading(path, *args, **kwargs):
            if any(str(path).endswith(f"hwmon{n}/temp1_input") for n in range(5, 9)):
                raise OSError(errno.ENODATA, "synthetic unavailable amplifier reading")
            return real_open(path, *args, **kwargs)

        return patch.object(Path, "open", reading)

    def hwmon_order(self, order):
        real_scan = os.scandir

        @contextlib.contextmanager
        def scanning(path):
            with real_scan(path) as entries:
                entries = list(entries)
            if str(path).endswith("/sys/class/hwmon"):
                entries.sort(key=lambda entry: order.index(entry.name))
            else:
                entries.reverse()
            yield iter(entries)

        return patch.object(env.os, "scandir", scanning)

    def test_verified_m1_inventory_is_selected_under_original_reverse_and_shuffled_orders(self):
        observed = [f"hwmon{n}" for n in (8, 6, 4, 2, 0, 9, 7, 5, 3, 1)]
        shuffled = observed.copy()
        random.Random(37).shuffle(shuffled)
        with self.m1_inventory():
            for order in (observed, list(reversed(observed)), shuffled):
                with self.subTest(order=order), self.hwmon_order(order):
                    report = self.capture()
                enum = self.row(report, "/sys/class/hwmon/hwmon*")
                expected = [f"/sys/class/hwmon/hwmon{n}" for n in range(10)]
                self.assertEqual(enum["discovered"], expected)
                self.assertEqual(enum["selected"], expected)
                self.assertEqual(enum["value"], expected)  # Existing path-list interface.
                self.assertEqual(enum["omitted"], [])
                self.assertTrue(enum["discovery_complete"])
                self.assertFalse(enum["truncated"])
                self.assertEqual(enum["selection_limit"], 16)
                self.assertEqual(report["schema_version"], 1)
                self.assertFalse(report["limited"])
                sources = [row for row in report["records"] if row["category"] == "hwmon"
                           and row["source"].endswith("_input")
                           and row["unit"] != "interface paths"]
                self.assertEqual(sum(row["status"] == "OS_REPORTED" for row in sources), 17)
                self.assertEqual(sum(row["status"] == "UNAVAILABLE" for row in sources), 4)
                self.assertTrue(all(f"Errno {errno.ENODATA}" in row["error"] for row in sources
                                    if row["status"] == "UNAVAILABLE"))
                smc = self.row(report, "/sys/class/hwmon/hwmon1/temp1_label")
                self.assertEqual(smc["value"], "synthetic component temp1")
                self.assertTrue(smc["optional"])
                self.assertIn("mapping unverified", smc["unit"])
                self.assertFalse(any(row["status"] == "DERIVED" for row in report["records"]
                                     if row["category"] == "hwmon"))
                self.assertEqual(self.row(report, "/sys/class/hwmon/hwmon1/fan1_input")["value"], 0)
                empty = self.row(report, "/sys/class/hwmon/hwmon3/*_input")
                self.assertEqual(empty["value"], [])
                self.assertEqual(empty["status"], "OS_REPORTED")

    def test_controller_selection_limit_records_known_omissions_deterministically(self):
        for n in range(20):
            self.put(f"/sys/class/hwmon/hwmon{n}/name", "fixture")
        for order in (list(range(20)), list(reversed(range(20)))):
            with self.hwmon_order([f"hwmon{n}" for n in order]):
                report = self.capture()
            row = self.row(report, "/sys/class/hwmon/hwmon*")
            self.assertEqual(row["selected"], [f"/sys/class/hwmon/hwmon{n}" for n in range(16)])
            self.assertEqual(row["omitted"], [f"/sys/class/hwmon/hwmon{n}" for n in range(16, 20)])
            self.assertTrue(row["discovery_complete"])
            self.assertTrue(row["truncated"])
            self.assertTrue(report["limited"])
            self.assertFalse(any(r["source"].endswith("hwmon19/name") for r in report["records"]))

    def test_supported_filter_precedes_input_limit_and_records_omitted_sensors(self):
        for n in range(20):
            self.put(f"/sys/class/hwmon/hwmon0/humidity{n}_input", "must not be read")
        for n in range(1, 19):
            self.put(f"/sys/class/hwmon/hwmon0/temp{n}_input", "1")
        real_scan, real_open = os.scandir, Path.open

        @contextlib.contextmanager
        def scanning(path):
            with real_scan(path) as entries:
                entries = list(entries)
            entries.sort(key=lambda entry: (not entry.name.startswith("humidity"), entry.name))
            yield iter(entries)

        def reading(path, *args, **kwargs):
            self.assertFalse(path.name.startswith("humidity"))
            return real_open(path, *args, **kwargs)

        with patch.object(env.os, "scandir", scanning), patch.object(Path, "open", reading):
            report = self.capture()
        row = self.row(report, "/sys/class/hwmon/hwmon0/*_input")
        self.assertEqual(len(row["discovered"]), 18)
        self.assertEqual(row["selected"], [f"/sys/class/hwmon/hwmon0/temp{n}_input"
                                           for n in range(1, 17)])
        self.assertEqual(row["omitted"],
                         [f"/sys/class/hwmon/hwmon0/temp{n}_input" for n in (17, 18)])
        self.assertTrue(row["discovery_complete"])
        self.assertTrue(row["truncated"])

    def test_missing_optional_labels_preserve_raw_status_with_separate_completeness(self):
        self.put("/sys/class/hwmon/hwmon0/temp1_input", "42000")
        reader = env.Reader(self.root, 2)
        reader.read("/sys/class/hwmon/hwmon0/temp1_input", "hwmon",
                    "millidegrees Celsius", env.number)
        reader.read("/sys/class/hwmon/hwmon0/temp1_label", "hwmon", "optional label", optional=True)
        row = reader.records[-1]
        self.assertEqual(row["status"], "UNAVAILABLE")
        self.assertIsNone(row["value"])
        self.assertTrue(row["optional"] and row["missing"])
        summary = env._completeness(reader.records, reader.limited)
        self.assertEqual(summary["status_excluding_missing_optional_hwmon_labels"], "COMPLETE")
        self.assertEqual(summary["missing_optional_hwmon_labels"], 1)
        self.assertEqual(summary["other_unavailable_records"], 0)

    def test_optional_label_permission_error_still_counts_as_unavailable(self):
        reader = env.Reader(self.root, 2)
        with patch.object(Path, "open", side_effect=PermissionError("fixture denied")):
            reader.read("/sys/class/hwmon/hwmon0/temp1_label", "hwmon", "label", optional=True)
        self.assertTrue(reader.records[0]["optional"])
        self.assertFalse(reader.records[0]["missing"])
        summary = env._completeness(reader.records, reader.limited)
        self.assertEqual(summary["status_excluding_missing_optional_hwmon_labels"], "PARTIAL")
        self.assertEqual(summary["other_unavailable_records"], 1)

    def test_hwmon_symlinks_followed_and_broken_links_are_visible(self):
        self.put("/devices/controller/name", "fixture")
        self.put("/devices/controller/temp1_input", "1")
        base = self.root / "sys/class/hwmon"
        base.mkdir(parents=True)
        (base / "hwmon0").symlink_to(self.root / "devices/controller", target_is_directory=True)
        (base / "hwmon1").symlink_to(self.root / "absent", target_is_directory=True)
        report = self.capture()
        self.assertEqual(self.row(report, "/sys/class/hwmon/hwmon0/temp1_input")["value"], 1)
        missing = self.row(report, "/sys/class/hwmon/hwmon1/name")
        self.assertEqual(missing["status"], "UNAVAILABLE")
        enum = self.row(report, "/sys/class/hwmon/hwmon1/*_input")
        self.assertFalse(enum["discovery_complete"])
        self.assertIn("FileNotFoundError", enum["error"])

    def test_hwmon_discovery_cap_bounds_work_and_does_not_claim_complete_inventory(self):
        visited = []

        @contextlib.contextmanager
        def scanning(_path):
            def entries():
                for n in range(100):
                    visited.append(n)
                    yield types.SimpleNamespace(name=f"hwmon{n}")
            yield entries()

        reader = env.Reader(self.root, 2)
        with patch.object(env, "HWMON_DIRECTORY_ENTRIES", 5), \
                patch.object(env.os, "scandir", scanning):
            selected = reader.hwmon_paths("/sys/class/hwmon", "hwmon*",
                                          env.re.compile(r"hwmon[0-9]+"), 16)
        self.assertEqual(len(visited), 6)  # Five examined entries and one lookahead.
        self.assertEqual(len(selected), 5)
        row = reader.records[-1]
        self.assertEqual(row["entries_examined"], 5)
        self.assertFalse(row["discovery_complete"])
        self.assertTrue(row["truncated"])
        self.assertEqual(row["omitted"], [])  # Does not pretend this names unseen controllers.
        self.assertTrue(reader.limited)

    def test_hwmon_discovery_deadline_and_permission_errors_are_explicit(self):
        reader = env.Reader(self.root, 0)
        with patch.object(env.os, "scandir") as scanning:
            reader.hwmon_paths("/sys/class/hwmon", "hwmon*", env.re.compile(r"hwmon[0-9]+"), 16)
        scanning.assert_not_called()
        self.assertIn("deadline", reader.records[-1]["error"])
        reader = env.Reader(self.root, 2)
        with patch.object(env.os, "scandir", side_effect=PermissionError("fixture denied")):
            reader.hwmon_paths("/sys/class/hwmon", "hwmon*", env.re.compile(r"hwmon[0-9]+"), 16)
        self.assertEqual(reader.records[-1]["status"], "UNAVAILABLE")
        self.assertFalse(reader.records[-1]["discovery_complete"])
        self.assertIn("PermissionError", reader.records[-1]["error"])

    def test_hwmon_record_limit_retains_global_partial_status(self):
        with self.m1_inventory(), patch.object(env, "MAX_RECORDS", 25):
            report = self.capture()
        self.assertEqual(len(report["records"]), 25)
        self.assertTrue(report["limited"])
        self.assertEqual(report["status"], "PARTIAL")
        self.assertEqual(report["completeness"]["status_excluding_missing_optional_hwmon_labels"],
                         "PARTIAL")

    def busy_fixture(self):
        # Populate a synthetic eight-CPU / 64-process context to exercise the existing
        # global budget together with the supplied controller/sensor counts.
        for n in range(8):
            self.put(f"/sys/devices/system/cpu/cpu{n}/regs/identification/midr_el1", "0x611f0221")
            self.put(f"/sys/devices/system/cpu/cpu{n}/cpu_capacity", "512")
            self.put(f"/sys/class/thermal/thermal_zone{n}/type", "synthetic_component")
            self.put(f"/sys/class/thermal/thermal_zone{n}/temp", "42000")
        for n in (0, 4):
            for key, value in {"scaling_governor": "schedutil", "related_cpus": "0 1 2 3",
                               "affected_cpus": "0 1 2 3", "scaling_cur_freq": "800000",
                               "cpuinfo_cur_freq": "800000", "scaling_max_freq": "2000000",
                               "cpuinfo_max_freq": "2000000",
                               "scaling_available_frequencies": "800000 2000000"}.items():
                self.put(f"/sys/devices/system/cpu/cpufreq/policy{n}/{key}", value)
        for n in range(2):
            for key, value in {"type": "Battery", "online": "1", "status": "Charging",
                               "capacity": "50", "voltage_now": "12000000", "current_now": "10",
                               "charge_now": "100", "energy_now": "100", "power_now": "10"}.items():
                self.put(f"/sys/class/power_supply/fixture{n}/{key}", value)
        self.put("/proc/uptime", "10000.00 0")
        self.put("/proc/loadavg", "0.1 0.1 0.1 1/64 123")
        self.put("/proc/stat", "cpu 1 2 3 4\ncpu0 1 2 3 4\nprocs_running 1")
        self.put("/proc/meminfo", "MemTotal: 102400 kB\nMemAvailable: 51200 kB\n"
                 "SwapTotal: 0 kB\nSwapFree: 0 kB")
        for name in ("cpu", "memory"):
            self.put("/proc/pressure/" + name, "some avg10=0.00 avg60=0.00 avg300=0.00 total=0")
        fields = ["0"] * 40
        fields[0], fields[11], fields[19], fields[21] = "S", "100", "1000", "2"
        for n in [*range(2, 64), 123, 124]:
            self.put(f"/proc/{n}/stat", f"{n} (fixture) " + " ".join(fields))

    def test_m1_inventory_with_busy_context_fits_unchanged_record_and_json_budgets(self):
        self.busy_fixture()
        with self.m1_inventory():
            report = self.capture()
        self.assertLess(len(report["records"]), env.MAX_RECORDS)
        self.assertLess(len(json.dumps(report, allow_nan=False).encode()), env.MAX_JSON)
        self.assertFalse(report["limited"])
        self.assertEqual(len(self.row(report, "/sys/class/hwmon/hwmon*")["selected"]), 10)
        self.assertEqual(report["limits"]["cooperative_seconds"], 2)
        self.assertTrue(all("deadline" not in (row["error"] or "") for row in report["records"]))

    def test_sixteen_full_controllers_fit_budgets_with_busy_fixture(self):
        self.busy_fixture()
        for n in range(16):
            self.put(f"/sys/class/hwmon/hwmon{n}/name", "synthetic_full_controller")
            for channel in range(1, 17):
                base = f"/sys/class/hwmon/hwmon{n}/temp{channel}"
                self.put(base + "_input", "42000")
                self.put(base + "_label", "synthetic component")
        report = self.capture()
        self.assertLess(len(report["records"]), env.MAX_RECORDS)
        self.assertLess(len(json.dumps(report, allow_nan=False).encode()), env.MAX_JSON)
        self.assertFalse(report["limited"])
        self.assertEqual(len(self.row(report, "/sys/class/hwmon/hwmon*")["selected"]), 16)
        readings = [row for row in report["records"] if row["source"].endswith("_input")
                    and row["status"] == "OS_REPORTED" and row["unit"] != "interface paths"]
        self.assertEqual(len(readings), 256)

    def test_cli_output_guard_rejects_oversized_report_without_successful_output(self):
        tree = ast.parse(Path(env.__file__).read_text())
        cli = next(node for node in tree.body if isinstance(node, ast.If))
        body = compile(ast.Module(body=cli.body, type_ignores=[]), env.__file__, "exec")
        scope = {"snapshot": lambda: {"oversized_fixture": "x" * env.MAX_JSON},
                 "json": json, "MAX_JSON": env.MAX_JSON}
        with contextlib.redirect_stdout(io.StringIO()) as output, \
                self.assertRaisesRegex(ValueError, "JSON size cap"):
            exec(body, scope)
        self.assertEqual(output.getvalue(), "")

    def test_nonfinite_uptime_is_unavailable_and_output_remains_json(self):
        self.put("/proc/uptime", "NaN 0")
        report = self.capture()
        self.assertEqual(self.row(report, "/proc/uptime")["status"], "UNAVAILABLE")
        self.assertLess(len(json.dumps(report, allow_nan=False).encode()), env.MAX_JSON)


if __name__ == "__main__":
    unittest.main()
