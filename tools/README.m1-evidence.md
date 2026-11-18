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
policies, eight power supplies, 32 thermal zones, eight hwmon controllers with 16 input
candidates each). The helper has a cooperative two-second deadline. The launcher
supervises it with a five-second wait plus the existing bounded termination guards.
A blocked kernel interface cannot be given a hard real-time guarantee in userspace.
Optional failures or absent sensors are recorded as PARTIAL/UNAVAILABLE and do not
alone invalidate timer data. Unknown worker termination is blocking: measurements must
not start while a monitoring worker could remain alive. Interrupted workers propagate
interruption; no replacement readings or retries are invented.

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
  tests.unit_experimental_environment tests.unit_m1_g2_launcher \
  tests.unit_arm64_timer_calibration -v
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
