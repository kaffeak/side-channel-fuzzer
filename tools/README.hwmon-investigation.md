# M1 hwmon truncation investigation — inventory required

The collector and G2 launcher are unchanged. No G1/G2 measurement is required or
permitted by this diagnostic. The reported M1 truncation establishes that the collector
saw at least nine matching hwmon entries at that time; it does not establish their
names, drivers, channels, or relevance. Supply the physical inventory before choosing
new production limits or hardware-specific selection rules. Completed evidence remains
unchanged; this is a new, separate diagnostic artifact.

## Verified current behavior

In `tools/experimental_environment.py`, `Reader.glob()` takes only `limit + 1` matches,
then sorts the first `limit`. The hwmon caller uses eight controllers and sixteen
`*_input` candidates per controller, then filters to temp/fan/in/curr/power inputs.

* Sorting **after truncation** stabilizes presentation, not selection. Different
  filesystem enumeration orders can yield different selected controller sets, even
  with the same interfaces. This is independently demonstrable using synthetic path
  iterators; no M1 observation is needed. The same weakness applies inside each
  controller. Sorting the nine collected paths before selecting eight would still
  fail to consider subsequent paths.
* Unsupported `*_input` names consume the sixteen-candidate allowance before the
  whitelist is applied. Relevant inputs outside that prefix can be skipped. This
  possibility is confirmed in the code, not demonstrated on the M1.
* The enumeration record identifies selected paths and `truncated=true`, but neither
  the total count nor omitted paths; even the extra path used to detect truncation is
  discarded. Counts of unavailable records do not explain which readings are missing.
* Missing labels and driver read errors are explicitly UNAVAILABLE, with null values.
  Valid integer zeroes and negative readings are preserved. Labels are optional:
  their absence can cause PARTIAL without invalidating the input reading.
* Standard class symlinks are followed for reads; broken/disappearing links become
  errors. Resolved device identity is not recorded, so duplicate names or aliases
  cannot be interpreted reliably across boots. `hwmonN` alone is not a durable sensor
  identity. Do not discard class symlinks as a proposed fix.
* Numeric input parsing is bounded and rejects unexpected text; errors retain a
  bounded diagnostic. The report's units are nominal ABI interpretations, not an
  independent check of calibration or sensor placement. Some driver-specific
  thermistor conventions require additional interpretation.
* `powerN_average` is a separate standard attribute, not matched by `*_input`.
  Whether this excludes useful M1 readings is unknown. The one-shot diagnostic also
  reads that explicitly whitelisted attribute and keeps its name distinct.
* `Path.glob()` may suppress directory-scanning errors, depending on Python version;
  the collector can conflate an inaccessible traversal with no exposed interfaces.
  The diagnostic uses explicit `scandir()` and preserves its errors.

The current 331-record result is below the 1,024-record cap. Its listed hwmon/process
truncations do not by themselves indicate record-budget exhaustion. `limited` combines
several kinds of limits. Process enumeration remains out of scope, and its separate
64-candidate cap can continue to produce `limited=true` after a future hwmon correction.

## What remains unknown

Linux exposes hwmon devices from multiple drivers; a controller is not necessarily a
CPU sensor. The Asahi SMC driver describes temperature, voltage, current, power and fan
channels, with platform-specific sensor descriptions. That source is context, **not a
verified match to the installed M1 kernel** and does not explain the reported controller
count. We need controller names, resolved sysfs/driver links, channel/label/value records,
errors and the kernel identity from the actual machine. Also preserve/share the hwmon
records from the original snapshot: the diagnostic's current order cannot reconstruct
selection in an earlier invocation or boot.

## Options after inventory

| Option | Benefit | Cost and limitation |
| --- | --- | --- |
| A: increase eight to a larger fixed limit | Smallest cap change if the inventory fits | Retains order bias whenever the new cap is exceeded; more reads and records. At sixteen input candidates, eight extra full controllers can add about 272 records, before other snapshot activity. The global record/deadline budgets still apply. |
| B: deterministic bounded discovery and selection | Reproducible selection for the same fully discovered interface set; explicit discovered/selected/omitted metadata | Discover up to a separate entry/time cap, filter before selection, sort by a documented key, then limit reads. If discovery itself is incomplete, mark that explicitly; no globally stable selection can be claimed. IDs may change across boots. |
| C: relevance-aware ranking | Could spend the read budget on controllers with readable supported channels | Adds discovery/name/probe reads and selection bias; unreadable interfaces may be transient. Sensor names cannot establish core temperature mapping. Defer unless inventory shows a need. |

Recommended direction is **B with a fixed read budget sized from the inventory**, not
Apple-specific sensor ranking. Keep this local to hwmon initially; do not change the
process-enumeration policy. Additive enumeration fields can preserve snapshot schema 1
and its current path-list value. Keep UNAVAILABLE semantics, source hashes and the
synchronous before/after placement. The smallest code-only correction to propose is
filter-before-capping plus selection after complete bounded discovery; simply sorting
the already truncated list is insufficient. No such collector change is made here.

## Single physical diagnostic command

After reviewing and transferring the new script, run from the checkout as an ordinary
user, while **no experimental measurement is running**:

```bash
python3 -B tools/investigate_hwmon.py
```

It creates and prints a new directory only under:

```text
/home/safelab/MasterThesis/output/G2/hwmon-investigation/<UTC-timestamp>-<unique-suffix>/
  investigate_hwmon.py
  experimental_environment.py
  provenance.json
  raw.jsonl
  stderr.txt
  status.json
  SHA256SUMS
```

Do not use sudo or run the internal `--collect` worker directly: the normal entry point
provides preservation and the outer timeout. No package installation, kernel module,
PMU access, timer workload, settings changes or background polling is involved. Reads
of hardware interfaces may themselves trigger driver queries; perform this separately
from G1/G2, not concurrently. There is no automatic retry and no deletion of failures.

Bounds: 512 directory entries examined per directory, 64 selected controllers, 64
supported reading attributes per controller, 4 KiB per file, 16 MiB JSONL, a cooperative
five-second inventory deadline, a ten-second parent wait and a two-second kill/reap
guard. These generous **diagnostic** caps are not proposed snapshot defaults. The
selection is naturally sorted only after discovery; incomplete enumeration and omitted
observed paths are explicit. A blocked kernel read cannot be given a hard real-time
termination guarantee; an UNKNOWN termination is a failed/incomplete diagnostic.

`raw.jsonl` contains metadata, enumeration, selection and read records, followed by
`complete` when collection returns normally. Read records preserve source, UTC time,
units, OS_REPORTED/UNAVAILABLE, optional-field status, values and errors. Numeric
failures preserve reported text. Zero is distinct from null. Unsupported attribute
names are inventoried where relevant, but their contents, serial-number files, uevents,
process data and environments are not read. Power-average values remain explicitly
average attributes. No driver labels are translated into Firestorm/Icestorm mappings.

`legacy_first_eight` and `legacy_first_sixteen` show what the old prefix rule would
select **for this diagnostic's observed order**, not proof of an earlier collector's
selection. Cap/deadline errors, optional missing labels and unreadable driver links
produce PARTIAL; inspect each reason. A zero process exit is successful diagnostic
execution, not proof of complete sensors or experimental acceptance. A timeout/error
preserves partial stdout, stderr, actual status where known, and checksums. Incomplete
JSONL or an absent final record is retained, never interpreted as success. Filesystem
failure, SIGKILL and power loss can prevent final status/checksum creation; preserve
such directories as incomplete too.

From the printed directory, verify and return the **whole directory**, including
failures, with:

```bash
sha256sum -c SHA256SUMS
```

The source snapshots and checksums identify executed bytes; Git HEAD is recorded where
available. The diagnostic does not claim that the checkout is clean or that the bytes
match that commit. Sysfs paths and labels disclose hardware context; review before
sharing, keeping the original unchanged. Wait for inventory review before changing
collector limits. No repeat of accepted G1/G2 is needed.

## Desktop checks and references

All diagnostic tests use synthetic directories or mocked subprocesses:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest \
  tests.unit_hwmon_investigation tests.unit_experimental_environment \
  tests.unit_m1_g2_launcher tests.unit_arm64_timer_calibration -v
git diff --check
```

Relevant primary references:

* [Linux hwmon ABI](https://docs.kernel.org/hwmon/sysfs-interface.html): class symlinks,
  optional fields, labels, units, power averages and driver-specific qualifications.
* [Python 3.12 pathlib](https://docs.python.org/3.12/library/pathlib.html#pathlib.Path.glob):
  directory ordering and glob error handling; check the target's recorded Python version.
* [Asahi SMC hwmon source](https://github.com/AsahiLinux/linux/blob/asahi/drivers/hwmon/macsmc-hwmon.c):
  platform-dependent channels and registration. Moving branch reference for background
  only; actual running-driver provenance remains to be established from the inventory.
