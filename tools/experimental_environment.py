"""Bounded, read-only Linux environmental snapshots; no timer measurements, PMU or subprocesses.

Collection perturbs the system. Call synchronously outside measurement loops.
A snapshot records OS reports, not independently calibrated physical truth.
"""
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from itertools import islice
import json
import os
from pathlib import Path
import re
import time

MAX_FILE = 16384
MAX_RECORDS = 1024
MAX_JSON = 1024 * 1024
HWMON_DIRECTORY_ENTRIES = 256
HWMON_CONTROLLERS = 16
HWMON_INPUTS = 16
HWMON_INPUT_PATTERN = re.compile(r"(temp|fan|power|in|curr)[0-9]+_input")
M1_CORES = {0x611f0221: "Icestorm", 0x611f0231: "Firestorm"}


def utc():
    return datetime.now(timezone.utc).isoformat()


def number(text):
    if not re.fullmatch(r"-?[0-9]{1,20}", text):
        raise ValueError("Expected a bounded integer")
    return int(text)


def nonnegative(text):
    value = number(text)
    if value < 0:
        raise ValueError("Expected a nonnegative value")
    return value


def bounded(text, maximum):
    value = nonnegative(text)
    if value > maximum:
        raise ValueError("Reported value outside interface range")
    return value


class Reader:
    """Explicit whitelist reads, per-read sizes and a cooperative collection deadline."""
    def __init__(self, root, seconds):
        self.root = Path(root)
        self.deadline = time.monotonic() + seconds
        self.records = []
        self.limited = False

    def record(self, category, source, unit, value=None, *, error=None, status="OS_REPORTED"):
        if len(self.records) >= MAX_RECORDS:
            self.limited = True
            return
        self.records.append({"category": category, "source": source, "unit": unit,
                             "observed_utc": utc(), "status": "UNAVAILABLE" if error else status,
                             "value": None if error else value, "error": error})

    def read(self, source, category, unit, parser=str, *, optional=False):
        text = None
        previous = len(self.records)
        try:
            if time.monotonic() >= self.deadline:
                raise TimeoutError("Collection deadline exhausted")
            with (self.root / source.lstrip("/")).open("rb") as stream:
                data = stream.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise ValueError("Interface exceeds per-read size limit")
            text = data.decode("utf-8").replace("\0", "\n").strip()
            if not text:
                raise ValueError("Empty interface")
            value = parser(text)
        except (OSError, ValueError, IndexError, InvalidOperation) as error:
            self.record(category, source, unit, error=f"{type(error).__name__}: {error}")
            if text is not None and len(self.records) > previous:
                self.records[-1]["raw_diagnostic"] = text[:256]
            if optional and len(self.records) > previous:
                self.records[-1].update(optional=True, missing=isinstance(error, FileNotFoundError))
            return None
        self.record(category, source, unit, value)
        if optional and len(self.records) > previous:
            self.records[-1].update(optional=True, missing=False)
        return value

    def glob(self, pattern, category, limit):
        if time.monotonic() >= self.deadline:
            self.record(category, pattern, "interface paths", error="Collection deadline exhausted")
            return []
        try:
            paths = list(islice(self.root.glob(pattern.lstrip("/")), limit + 1))
        except OSError as error:
            self.record(category, pattern, "interface paths", error=str(error))
            return []
        truncated = len(paths) > limit
        self.limited |= truncated
        selected = sorted(paths[:limit])
        sources = ["/" + path.relative_to(self.root).as_posix() for path in selected]
        self.record(category, pattern, "interface paths", sources,
                    error=None if sources else "No exposed interfaces")
        if truncated and self.records and self.records[-1]["source"] == pattern:
            self.records[-1]["truncated"] = True
        return sources

    def hwmon_paths(self, directory, pattern, matcher, limit, *, empty_ok=False):
        """Select from a bounded inventory, retaining known omissions and discovery failures."""
        paths, examined, error = [], 0, None
        complete = False
        try:
            if time.monotonic() >= self.deadline:
                raise TimeoutError("Collection deadline exhausted")
            with os.scandir(self.root / directory.lstrip("/")) as entries:
                for entry in entries:
                    if time.monotonic() >= self.deadline:
                        raise TimeoutError("Collection deadline exhausted")
                    if examined >= HWMON_DIRECTORY_ENTRIES:
                        break  # One lookahead entry establishes incomplete discovery.
                    examined += 1
                    if matcher.fullmatch(entry.name):
                        paths.append(directory + "/" + entry.name)
                else:
                    complete = True
        except OSError as failure:
            error = f"{type(failure).__name__}: {failure}"
        paths.sort(key=lambda path: [int(part) if part.isdigit() else part
                                     for part in re.split(r"([0-9]+)", path)])
        selected, omitted = paths[:limit], paths[limit:]
        truncated = not complete or bool(omitted)
        self.limited |= truncated
        previous = len(self.records)
        self.record("hwmon", directory + "/" + pattern, "interface paths", selected,
                    error=error or (None if selected or empty_ok else "No exposed interfaces"))
        if len(self.records) > previous:
            self.records[-1].update(discovered=paths, selected=selected, omitted=omitted,
                                    discovery_complete=complete, entries_examined=examined,
                                    enumeration_limit=HWMON_DIRECTORY_ENTRIES,
                                    selection_limit=limit, truncated=truncated)
        return selected


def _completeness(records, limited):
    unavailable = [row for row in records if row["status"] == "UNAVAILABLE"]
    missing_labels = sum(row["category"] == "hwmon" and row.get("optional", False)
                         and row.get("missing", False) for row in unavailable)
    other = len(unavailable) - missing_labels
    return {"status_excluding_missing_optional_hwmon_labels":
            "PARTIAL" if other or limited else "COMPLETE",
            "missing_optional_hwmon_labels": missing_labels, "other_unavailable_records": other}


def runtime(reader, name, unit, query):
    try:
        reader.record("runtime", name, unit, query())
    except (OSError, ValueError, AttributeError) as error:
        reader.record("runtime", name, unit, error=str(error))


def cpu_stat(text):
    result = {}
    for line in text.splitlines():
        key, *values = line.split()
        if key.startswith("cpu") or key in {"ctxt", "processes", "procs_running", "procs_blocked"}:
            result[key] = [nonnegative(value) for value in values]
    if "cpu" not in result:
        raise ValueError("Missing aggregate CPU counters")
    return result


def process_stat(text):
    end = text.rfind(")")
    start = text.index("(")
    fields = text[end + 1:].split()
    return {"name": text[start + 1:end][:64], "state": fields[0],
            "user_ticks": nonnegative(fields[11]), "system_ticks": nonnegative(fields[12]),
            "start_ticks": nonnegative(fields[19]), "rss_pages": nonnegative(fields[21]),
            "last_cpu": nonnegative(fields[36])}


def processes(reader, page, hz, uptime, memtotal):
    paths = reader.glob("/proc/[0-9]*", "processes", 64)
    paths = sorted(set(paths + [f"/proc/{os.getpid()}", f"/proc/{os.getppid()}"]))
    for path in paths:
        data = reader.read(path + "/stat", "processes",
                           {"user/system/start": "USER_HZ ticks", "rss": "pages",
                            "last_cpu": "CPU ID"},
                           process_stat)
        if data is None:
            continue
        source = path + "/stat + /proc/uptime + sysconf(SC_CLK_TCK)"
        if hz and uptime is not None and uptime * hz > data["start_ticks"]:
            elapsed = uptime * hz - data["start_ticks"]
            percent = float(100 * Decimal(data["user_ticks"] + data["system_ticks"]) / elapsed)
            reader.record("processes", source, "percent of one CPU averaged since process start",
                          percent, status="DERIVED")
        else:
            reader.record("processes", source, "lifetime CPU percent",
                          error="Denominator unavailable")
        source = path + "/stat + sysconf(SC_PAGESIZE) + /proc/meminfo:MemTotal"
        if page and memtotal:
            percent = 100 * data["rss_pages"] * page / (memtotal * 1024)
            reader.record("processes", source, "percent RSS / physical MemTotal", percent,
                          status="DERIVED")
        else:
            reader.record("processes", source, "memory percent", error="Denominator unavailable")


def snapshot(root=Path("/"), *, seconds=2):
    """Return a single bounded report. root exists for synthetic filesystem fixtures."""
    started = utc()
    r = Reader(root, seconds)
    page = hz = None
    try:
        page, hz = os.sysconf("SC_PAGESIZE"), os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError):
        pass
    runtime(r, "os.uname()", "kernel/system fields", lambda: list(os.uname()))
    runtime(r, "sysconf(SC_PAGESIZE)", "bytes", lambda: os.sysconf("SC_PAGESIZE"))
    runtime(r, "sysconf(SC_CLK_TCK)", "USER_HZ ticks/second", lambda: os.sysconf("SC_CLK_TCK"))
    runtime(r, "sched_getaffinity(0), collector process", "allowed CPU IDs",
            lambda: sorted(os.sched_getaffinity(0)))
    for source in ("/proc/device-tree/model", "/proc/device-tree/compatible", "/etc/os-release",
                   "/sys/devices/system/cpu/online", "/sys/devices/system/cpu/present"):
        r.read(source, "identity", "reported text / CPU list")
    for base in r.glob("/sys/devices/system/cpu/cpu[0-9]*", "cpus", 32):
        midr = r.read(base + "/regs/identification/midr_el1", "cpus", "MIDR hex string")
        try:
            label = M1_CORES.get(int(midr, 16), "UNKNOWN") if midr else "UNKNOWN"
        except ValueError:
            label = "UNKNOWN"
        r.record("cpus", base + "/regs/identification/midr_el1 (M1-only lookup)", "core type",
                 label, status="DERIVED")
        r.read(base + "/cpu_capacity", "cpus", "kernel relative capacity", nonnegative)
    attributes = (("scaling_governor", "governor", str), ("related_cpus", "CPU list", str),
                  ("affected_cpus", "CPU list", str), ("scaling_cur_freq", "kHz", nonnegative),
                  ("cpuinfo_cur_freq", "kHz", nonnegative),
                  ("scaling_max_freq", "kHz", nonnegative),
                  ("cpuinfo_max_freq", "kHz", nonnegative),
                  ("scaling_available_frequencies", "kHz list", str))
    for base in r.glob("/sys/devices/system/cpu/cpufreq/policy*", "frequency", 16):
        for name, unit, parser in attributes:
            r.read(base + "/" + name, "frequency", unit, parser)
    attributes = (("type", "supply type", str),
                  ("online", "0=offline, 1=online", lambda text: bounded(text, 1)),
                  ("status", "charging state", str),
                  ("capacity", "percent", lambda text: bounded(text, 100)),
                  ("voltage_now", "microvolts", number), ("current_now", "microamps", number),
                  ("charge_now", "microamp-hours", nonnegative),
                  ("energy_now", "microwatt-hours", nonnegative),
                  ("power_now", "microwatts", number))
    for base in r.glob("/sys/class/power_supply/*", "power", 8):
        for name, unit, parser in attributes:
            r.read(base + "/" + name, "power", unit, parser)
    for base in r.glob("/sys/class/thermal/thermal_zone*", "thermal", 32):
        r.read(base + "/type", "thermal", "sensor name; core mapping UNKNOWN")
        r.read(base + "/temp", "thermal", "millidegrees Celsius", number)
    units = {"temp": "millidegrees Celsius", "fan": "RPM", "power": "microwatts",
             "in": "millivolts", "curr": "milliamps"}
    for base in r.hwmon_paths("/sys/class/hwmon", "hwmon*", re.compile(r"hwmon[0-9]+"),
                              HWMON_CONTROLLERS):
        r.read(base + "/name", "hwmon", "sensor controller name; core mapping UNKNOWN")
        for source in r.hwmon_paths(base, "*_input", HWMON_INPUT_PATTERN, HWMON_INPUTS,
                                    empty_ok=True):
            match = HWMON_INPUT_PATTERN.fullmatch(source.rsplit("/", 1)[1])
            r.read(source, "hwmon", units[match[1]], number)
            r.read(source[:-6] + "_label", "hwmon", "optional sensor label; mapping unverified",
                   optional=True)

    def uptime_parser(text):
        value = Decimal(text.split()[0])
        if not value.is_finite() or not 0 <= value <= 10 ** 12:
            raise ValueError("Invalid uptime")
        return str(value)
    uptime_text = r.read("/proc/uptime", "activity", "seconds since boot", uptime_parser)
    uptime = Decimal(uptime_text) if uptime_text is not None else None
    r.read("/proc/loadavg", "activity", "1/5/15-minute loads; runnable/total tasks; last PID")
    r.read("/proc/stat", "activity", "cpu rows: USER_HZ ticks; remaining fields: counters",
           cpu_stat)

    def memory_parser(text):
        fields = {}
        for line in text.splitlines():
            key, _, value = line.partition(":")
            if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                words = value.split()
                if len(words) != 2 or words[1] != "kB":
                    raise ValueError("Unexpected meminfo unit")
                fields[key] = nonnegative(words[0])
        return fields
    memory = r.read("/proc/meminfo", "activity", "KiB (kernel label kB)", memory_parser)
    for key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
        if memory is not None and key not in memory:
            r.record("activity", "/proc/meminfo:" + key, "KiB", error="Field not exposed")
    for resource in ("cpu", "memory"):
        r.read("/proc/pressure/" + resource, "pressure",
               "avg10/60/300: percent stalled time; total: microseconds")
    processes(r, page, hz, uptime, memory.get("MemTotal") if memory else None)
    return {"schema_version": 1, "started_utc": started, "finished_utc": utc(),
            "status": "PARTIAL" if any(row["status"] == "UNAVAILABLE" for row in r.records)
            or r.limited else "COMPLETE", "limited": r.limited, "records": r.records,
            "completeness": _completeness(r.records, r.limited),
            "limits": {"file_bytes": MAX_FILE, "records": MAX_RECORDS,
                       "cooperative_seconds": seconds, "process_candidates": 66,
                       "hwmon_directory_entries": HWMON_DIRECTORY_ENTRIES,
                       "hwmon_discovery_lookahead": 1, "hwmon_controllers": HWMON_CONTROLLERS,
                       "hwmon_inputs_per_controller": HWMON_INPUTS},
            "method": "OS reports/derived context only; "
                      "not window telemetry or cache-state evidence",
            "privacy": "No command lines, environments, usernames or device serial numbers"}


if __name__ == "__main__":
    result = snapshot()
    text = json.dumps(result, allow_nan=False)
    if len(text.encode()) > MAX_JSON:
        raise ValueError("Snapshot exceeds JSON size cap")
    print(text)
