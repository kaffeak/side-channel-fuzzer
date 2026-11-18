# M1 experiment evidence management

This infrastructure update does not change the frozen G2 timer, validator, historical
M3-named protocols, schedule, quantiles or acceptance criterion. The completed physical
M1 G1/G2 evidence remains unchanged. The updated launcher and helper belong to a **new
execution commit** and require independent review and physical validation. Desktop
fixtures exercise packaging and orchestration, not architectural timer measurements.

## Directory layout

All launcher outputs remain below `/home/safelab/MasterThesis/output/G2/`:

```text
G2/
  M1-G2-S1/<unique-run-id>/             # independently launched session 1
    evidence/
      raw/                            # original stdout/stderr, status, validation
      analysis/
      software/                       # source snapshots, hashes, build, provenance
      metadata/                       # layout, before/after environment, operator notes
      session.json                    # complete, blocked, failed or interrupted
      SHA256SUMS
      ...                             # original methodology and diagnostic files
    evidence.tar.gz                   # outside the archived directory
    evidence.tar.gz.sha256
    receipt.json                      # actual launcher exit, including late signals
    receipt.json.sha256
    seal-failure.json                  # only if sealing fails; separately hashed
  M1-G2-S2/<unique-run-id>/...
  preflight/<unique-run-id>/...
  comparison/<unique-run-id>/...
  addenda/<unique-run-id>/...
```

UTC plus random identifiers and exclusive directory creation prevent rerun overwrite.
The actual container path is printed at startup and evidence/archive paths at sealing.
Partial stdout, stderr, exit status, validation failures and interrupted sessions are
retained. Nothing removes unsuccessful runs. SIGKILL, power loss and filesystem failure
can prevent completion/sealing: preserve the entire container and investigate rather
than assuming an absent receipt means success. Each archive is verified against the
internal manifest without extraction. Receipts are outside the immutable evidence set
and separately hashed. Read-only modes discourage accidental edits; owner-controlled
permissions and unauthenticated hashes are not tamper-proof signatures.

Old flat session directories, sibling archives/checksums and sibling receipts remain
supported by `--compare` and `--addendum`. Do not rename, move files within, reseal or
rewrite old sessions. New commands create their own output containers. For new sessions,
comparison accepts either the run container or its `evidence` child. Comparison still
requires matching execution/source identity across the two sessions; do not pool an old
execution commit and this updated implementation into one comparison.

## Bounded environmental snapshots

`tools/experimental_environment.py` is a standalone, read-only Linux helper. It uses
only Python standard-library interface reads and runtime queries; no subprocesses,
performance counters, timer measurement, settings writes or root access. The launcher
copies and hashes the committed helper together with the frozen source snapshots.
The reusable `snapshot()` API returns schema-version-1 JSON. Each record has category,
source, UTC observation time, units, status (`OS_REPORTED`, `DERIVED` or `UNAVAILABLE`),
value and error. Missing readings are null, never fabricated zeroes. Real zeroes and
negative temperatures/current readings remain distinguishable from missing data.

One synchronous worker runs immediately before the 40-run loop and one after it,
including ordinary failures inside the loop. There is **no monitoring subprocess or
telemetry polling during measurements**. Worker stdout/stderr, command, status and
start/end times are preserved under `metadata/environment-{before,after}.*`; the
`.json` file is the report or an explicit failure summary. The original essential
identity gate remains blocking, and is repeated after a successful measurement loop.

| Context | Interfaces and interpretation |
| --- | --- |
| Identity | `uname`, `sysconf(SC_PAGESIZE)`, affinity, device-tree model/compatible, `os-release`, online/present CPUs, MIDR and CPU capacity. Only exact known M1 MIDRs receive Icestorm/Firestorm labels; others are UNKNOWN. |
| Power | Whitelisted `/sys/class/power_supply` type, online, charging state, percent, voltage/current/charge/energy/power. Units follow the interface; unavailable AC/battery fields are explicit. |
| CPU frequency | cpufreq policy governor, related/affected CPUs, available and reported current/maximum frequencies in kHz. A reported requested P-state is not a calibrated instantaneous CPU frequency. |
| Thermal | Thermal-zone names and millidegree-C readings; hwmon controller, input and optional label. Whitelisted hwmon temperature/fan/power/voltage/current units are millidegree C/RPM/microwatt/millivolt/milliamp. No sensor-to-core mapping is inferred. |
| Activity | Uptime, load averages, `/proc/stat` CPU ticks and activity counters, selected `/proc/meminfo` fields (KiB), CPU/memory PSI text (percent averages; microsecond totals). These are snapshots/cumulative counters, not per-measurement utilization. |
| Processes | At most 64 enumerated PID candidates plus collector/parent: PID source path, bounded name, state, CPU ticks, start ticks, RSS pages, last CPU. Derived CPU percentage is averaged over process lifetime, **not** instantaneous; RSS percentage uses MemTotal. |

Enumeration is a bounded subset, **not a ranking of the busiest processes**; short-lived
processes may disappear before reading. Each file read is limited to 16 KiB, the report
to 1,024 records and 1 MiB JSON, with explicit enumeration caps (32 CPUs, 16 cpufreq
policies, eight power supplies and 32 thermal zones). Hwmon uses a separate discovery
bound and read allowance, described below. The helper has a cooperative two-second deadline. The launcher
supervises it with a five-second wait plus the existing bounded termination guards.
A blocked kernel interface cannot be given a hard real-time guarantee in userspace.
Optional failures or absent sensors are recorded as PARTIAL/UNAVAILABLE and do not
alone invalidate timer data. Unknown worker termination is blocking: measurements must
not start while a monitoring worker could remain alive. Interrupted workers propagate
interruption; no replacement readings or retries are invented.

### Hwmon selection and completeness

The supplied independently audited M1 inventory contains ten controllers. The reported
order placed `macsmc_hwmon` last, outside the former eight-controller prefix. The revised
collector discovers using explicit `scandir()` calls, then selects in numeric path order
(e.g. hwmon2 before hwmon10). It initially allows **16 controllers** and **16 supported
inputs per controller**. The original `temp/fan/power/in/currN_input` whitelist and source
paths remain unchanged. Unsupported attributes are filtered before the selection limit;
labels retain the driver's original text. This does not add `powerN_average` collection.

Each hwmon directory discovery examines at most **256 entries**, plus one lookahead
entry to detect that the inventory continues. This bound counts all directory entries,
including unsupported attributes. The shared cooperative deadline also applies inside
discovery. Only a fully discovered, unchanged set has order-independent selection;
if the discovery bound, deadline or an I/O error prevents completion, selection is from
the observed subset and **cannot** be assumed globally deterministic or exhaustive.
Standard sysfs class symlinks are followed; broken links remain explicit failures.

Schema version 1, existing `records`, `status`, `value`, `source` and unit fields remain.
Hwmon enumeration `value` is still a list of selected source paths. Additive metadata:

| Field | Meaning |
| --- | --- |
| `discovered` | Sorted supported paths actually discovered; not an assertion about unseen entries. |
| `selected` | Paths selected for attempted collection. Selection does not guarantee a successful reading. |
| `omitted` | Discovered paths excluded by the selection limit, including omitted sensor inputs. |
| `discovery_complete` | Whether directory enumeration reached its end within the bound and deadline. This is not an atomic inventory snapshot. |
| `entries_examined`, `enumeration_limit`, `selection_limit` | Work performed and the separate discovery/selection allowances. |
| `truncated` | Discovery was incomplete or known supported paths exceeded the selection allowance. |

Incomplete discovery or known omissions set `limited=true`. Budget exhaustion can
prevent later records from being retained; selected paths describe the intended read
set, not proof that every read is present. Directories successfully enumerated with no
supported inputs are reported as an empty OS_REPORTED path list. An absent/inaccessible
controller or hwmon class remains UNAVAILABLE. Process enumeration retains its original
64-candidate policy; its truncation can independently keep `limited=true`.

Optional hwmon label reads add `optional=true` and `missing`. Only `FileNotFoundError`
marks a label as missing. A missing label still has **UNAVAILABLE**, null value and its
original error. Permission errors, ENODATA, malformed values and deadlines are not
reclassified as benign absences. The existing top-level `status` remains conservative:
any unavailable record, even an optional missing label, still yields PARTIAL.

The additive `completeness` object reports `missing_optional_hwmon_labels`,
`other_unavailable_records`, and `status_excluding_missing_optional_hwmon_labels`.
That alternate status excludes only absent optional hwmon labels; it remains PARTIAL
for all other unavailable records or any `limited` condition. Neither status establishes
physical coverage or replaces validation. Available labels, OS_REPORTED input values,
DERIVED context and original UNAVAILABLE readings remain visible independently.

The supplied inventory includes readable NVMe/SMC/battery inputs, controllers without
supported inputs, and four tas2770 temperature reads returning ENODATA. Those errors
are preserved rather than retried or turned into zero. Names/labels for NAND, battery,
Wi-Fi, heatpipe or other components are **not** mapped to Firestorm/Icestorm temperatures.

Software regression fixtures reproduce controller identities/counts and enumeration
order; their channel names, labels and values are synthetic, not copied physical data.
An eight-CPU/64-process fixture verifies the original 1,024-record and 1 MiB limits with
the supplied ten-controller counts, and with sixteen fully populated controllers.
The extra enumeration and successful SMC reads add work outside measurement windows.
Fixture timings do not predict native sysfs/SMC latency: the **two-second deadline,
five-second launcher wait and termination guards are unchanged**, and pathological
inventories can still exhaust the record or JSON limits. Oversized JSON remains an
explicit worker failure, preserved by the launcher, rather than a fabricated success.
The revised collector requires separate physical M1 validation after deployment. No
completed G1/G2 evidence is changed and no repeat timer measurements are required.

No command lines, environments, usernames or device serial-number interfaces are read.
Process names/PIDs, hostname, OS and power/sensor labels still disclose context; review
before sharing, and retain the sealed original unchanged. Publish redactions separately.

Interface references: [power supply units](https://docs.kernel.org/power/power_supply_class.html),
[hwmon units and sensor interpretation](https://docs.kernel.org/hwmon/sysfs-interface.html),
[cpufreq reports](https://docs.kernel.org/admin-guide/pm/cpufreq.html),
[PSI](https://docs.kernel.org/accounting/psi.html).

Before/after reads themselves perturb caches and scheduling outside the loop. They
cannot establish constant conditions during sampling, exclude short interruptions,
measure cache residency, or identify physical frequency/temperature continuously.
No extra timer warmup is added. Any future G3 telemetry protocol needs separate review;
this helper creates no G3 observer, output runs or acceptance rule.

## Operator notes and provenance

Before/after prompts ask only about unusual events, intentional background activity,
physical interruptions or changed conditions. Use `none observed` or `not monitored`
as appropriate. `metadata/operator-{before,after}.json` records UTC, MANUAL source and
phase; compatible `notes-*.txt` files are retained. Missing after-notes on failure are
explicitly unavailable, not an assertion that nothing happened. Later observations use
`--addendum`, producing a new timestamped, hashed and sealed artifact referencing the
original manifest; never edit sealed notes.

The clean committed Git requirement remains. Status, staged and unstaged binary patches
are preserved before rejecting a dirty checkout. Baseline and execution revisions are
separate; the four frozen files must match `7a34feef80b64d31937c2d0bc7e1117e90e74b0d`
byte-for-byte. The helper must match the execution commit, and its captured copy is
rechecked before/after collection alongside launcher, frozen sources and timer binary.
New comparison/addendum containers also retain the current committed analysis driver,
its source hashes and Git diagnostics; their clean-tree check does not alter original
session provenance. The methodology retains parameters, units, program/input description
and NOT APPLICABLE
for seed, contract and held-out cache evaluation. This is G2 characterization only.

## Review and native verification commands

On the desktop (no native timer execution):

```bash
bash -n tools/rvzr_m1_g2.sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest \
  tests.unit_experimental_environment tests.unit_hwmon_investigation \
  tests.unit_m1_g2_launcher tests.unit_arm64_timer_calibration -v
git diff --check
```

Keep existing untracked `Zone.Identifier` files and unrelated G3b documents intact.
The clean-tree gate intentionally rejects them. Inspect them and preserve a copy/checksum
outside the checkout before **explicitly** moving incidental files, or review and commit
intended source/docs. Do not blanket-delete files, hide them with assume-unchanged, or
change ignore rules merely to bypass provenance. Record any cleanup separately. This
implementation does not move them, commit, push or run hardware experiments.

After review, user commit/push and pulling the exact new committed revision on the M1:

```bash
cd /home/safelab/MasterThesis/side-channel-fuzzer # use actual checkout location
./tools/rvzr_m1_g2.sh --check
```

Inspect the printed preflight container, STATUS, receipt and source diagnostics. Only
if independently approved for new physical replication, launch separate sessions:

```bash
./tools/rvzr_m1_g2.sh --session 1
./tools/rvzr_m1_g2.sh --session 2
./tools/rvzr_m1_g2.sh --compare \
  '/home/safelab/MasterThesis/output/G2/M1-G2-S1/<new-run-id>' \
  '/home/safelab/MasterThesis/output/G2/M1-G2-S2/<new-run-id>'
```

Legacy compatibility, without recollecting or modifying the completed experiment:

```bash
./tools/rvzr_m1_g2.sh --compare '/absolute/original/session1' '/absolute/original/session2'
./tools/rvzr_m1_g2.sh --addendum '/absolute/original/session1' \
  --note 'Timestamped later observation; original evidence unchanged.'
```

Run as an ordinary user, never sudo. Use actual printed paths, preserving spaces with
quotes. Save the whole run container (including failures, receipt and archive), not
just `evidence.tar.gz`. Verify `sha256sum -c evidence.tar.gz.sha256` and
`sha256sum -c receipt.json.sha256` from its container. Accepted prior G2 measurements
remain prior findings: this infrastructure still needs physical M1 validation and
cannot establish cache latency, HTraces or speculation-contract violations.

## Hwmon inventory follow-up

The physical inventory now justifies the correction documented above. See
[the historical audit and one-shot diagnostic](README.hwmon-investigation.md) for the
prior behavior and inventory procedure. That audit describes the pre-correction code;
the revised collector itself has not yet been validated on the physical M1.
