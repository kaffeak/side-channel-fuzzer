# Unicorn model lifetime characterization

This diagnostic uses the isolated ARM64 `prepare_unicorn_model()` API with
synthetic legacy 4 KB descriptors. It neither prepares a kernel allocation nor
changes the fuzzer lifecycle. Run from a repository checkout with the Revizor
Python dependencies installed, for example using the existing virtual environment.
No root privileges, kernel module, ARM64 host, assembler or hardware interfaces
are needed. CPU identification is explicitly synthetic. Real Unicorn emulates
the small owned binary; these are not native M3 measurements.

## Tests

```sh
python -m unittest tests.unit_model_coverage_lifecycle tests.unit_model_resource_lifetime -v
```

The 24 coverage tests use the actual `InstructionCoverage` implementation and
real prepared models where useful. They establish instruction-shape signatures,
address independence for a controlled fixture, aggregation of actor-sourced
instructions, per-input/per-load accumulation, instrumentation exclusion and
disabled coverage. They also verify exactly-once signature contributions per load
interval, non-mutating reports including pending observations, and independent
normal/architectural model coverage. The actor aggregation test submits real
per-actor instruction objects to coverage; the fixture itself executes only main.

Local counters count instruction executions across all inputs within an interval.
Campaign counters count signature presence per interval, not executions. A new
model load finishes the previous interval and starts another, even when reloading
the same test case. Explicit finalization does not start a new interval: subsequent
observations can contribute newly seen signatures, but previously committed ones
are not counted again. Reports combine history and pending signatures in a
temporary view without committing anything, including when writing fails.

Instruction signatures are computed on demand without a global object-ID cache.
Mnemonic and explicit operand kinds/widths keep their existing representation;
operand values and implicit operands remain excluded. Regressions cover operand
append/replacement/reordering/removal, reading the current mnemonic, and collecting
128 discarded instructions while coverage retains their signature strings/counts.
No test depends on forcing Python object-ID reuse. Disabled coverage and
instrumentation return before signature computation. No invalidation or weakref
cache is needed, since signatures are derived from current instruction contents.

Changes to an instruction's shape affect subsequent observations only; previously
recorded observations retain their original string keys. Concurrent mutation during
an observation is not synchronized by this implementation. Typed callers treat
the mnemonic as `Final`, but signature generation reads its current runtime value.

### Signature-computation overhead

A bounded microbenchmark on x86-64 WSL2 / Python 3.12.3 compared the implementation
at commit `8b16757bfe1debd7051ae452b5185f8a1cd638b2` against cache removal:

| Operation | Legacy warm cache | No cache |
| --- | ---: | ---: |
| Signature generation | 0.181 microseconds | 0.635 microseconds |
| Enabled `add_instruction` | 0.347 microseconds | 0.798 microseconds |
| Disabled `add_instruction` | 0.077 microseconds | 0.079 microseconds |

The reproducible workload is a retained pool of 32 instructions alternating
`mov R64 R64` and `ldr R64 M64`: destination `x0`, source/address `x20`, no
instrumentation. Use actual old/new functions and coverage objects, start one
interval per object, and select `model_instructions` or `none` for enabled/disabled
cases. Each `timeit.Timer` executes `for inst in instructions: operation(inst)`
with those objects in its globals. Warm each variant for 100 loops, then measure
10,000 loops per repeat (320,000 observations), five paired repeats, alternating
old/new measurement order. Report median elapsed time divided by observations.
Keep the pool alive so the old implementation has cache hits, and run without
concurrent checks. `timeit` uses `perf_counter` and disables GC during timing.

This measured about 0.45 microseconds extra per enabled observation (2.30 times
the small `add_instruction` workload), not campaign slowdown. It excludes Unicorn
execution, other dispatch services, I/O, allocation churn and cold-cache misses.
Coverage is diagnostic and disabled by default; its disabled path is unchanged.
The simple uncached approach trades optional diagnostic cost for correctness;
actual campaign cost and native ARM64 performance remain unmeasured.

Seven lifetime tests cover unchanged/relocated addresses, actor growth/shrinkage,
sequential/conditional configurations, execution, saved contexts/checkpoints,
deliberately retained tracers/engines and constructor/loading failures. Both the
constructor and test-case-load engines are observed. Full collection is requested
twice after helper scopes return; exceptions and their tracebacks are not retained.
If a wrapper cannot be weak-referenced, the tests warn and the probe records an
`unsupported` count. Python model reachability is still checked. No internal
Unicorn cleanup function is called.

## Bounded memory observations

Run each policy in a fresh process; do not run competing measurements concurrently:

```sh
python -m tools.probe_unicorn_model_lifetime --iterations 40 --warmup 8 --batch-size 10 \
    --actors 2 --workload prepare --gc default --relocate > prepare-default.jsonl
python -m tools.probe_unicorn_model_lifetime --iterations 40 --warmup 8 --batch-size 10 \
    --actors 2 --workload prepare --gc batch --relocate > prepare-batch.jsonl
python -m tools.probe_unicorn_model_lifetime --iterations 40 --warmup 8 --batch-size 10 \
    --actors 2 --clause cond --workload checkpoint --gc default --relocate > checkpoint-default.jsonl
python -m tools.probe_unicorn_model_lifetime --iterations 40 --warmup 8 --batch-size 10 \
    --actors 2 --clause cond --workload checkpoint --gc batch --relocate > checkpoint-batch.jsonl
```

Defaults are 50 measured preparations, 10 warm-ups, batches of 10, one actor,
sequential configuration and preparation only. Bounds are 1..1000 measured
preparations, 0..100 warm-ups, 1..1000 batch size and 1..8 actors. The binary is
linear and tiny; emulation also uses the existing model's timeout. For unattended
runs an external timeout can additionally bound the entire process.

`execute` emulates MOV/LDR and measurement placeholders. `checkpoint` does that
and explicitly requests a real saved checkpoint through the conditional
speculator. It does **not** claim that the branch-free fixture induced a branch
misprediction. Extra actors vary allocation sizes; only main executes. `--relocate`
alternates between two synthetic data/code base pairs. Descriptors use increasing
synthetic generations, not kernel leases. Coverage remains disabled in the probe
to isolate engine lifetime from coverage bookkeeping.

JSON Lines output contains one environment/configuration record, a baseline,
fixed-boundary batch samples (including a partial last batch), a final sample,
then completion. `measured_preparations` excludes warm-up; `total_preparations`
includes it. There is one full collection after warm-up and one at the end in
**both** policies. `default` makes no explicit collection during measured batches;
`batch` requests collection before each batch sample. GC settings are reported,
not disabled or tuned. Failures propagate without a fabricated completion record.

Metadata includes Python/package/core versions, binding path, OS/architecture,
host page size, workload, clause, GC settings and actor count. The core version
tuple is reported as returned by Unicorn; it need not identify a patch release.
Samples distinguish:

| Observation | Meaning and limitation |
| --- | --- |
| Weak-reference `alive` | Python objects currently surviving; zero is not proof that every native allocation was freed. |
| `supported` / `unsupported` | Cumulative registrations and wrapper instrumentation limitations; constructor and load engines are counted separately. |
| `python_traced_bytes` | Current Python allocations visible to `tracemalloc`, including probe bookkeeping; not total Unicorn native memory. |
| `python_traced_peak_bytes` | Cumulative traced peak since tracing started, including warm-up; it does not decrease after collection. |
| `rss_bytes` | Current process RSS, preferably from Linux `smaps_rollup`, otherwise `status`; null if unavailable. Includes much more than model objects. |

Only selected surviving context wrappers are tracked, not every temporary native
allocation. Dead weakrefs are pruned at sample boundaries. Probes use replacement
functions without mock call histories that could retain engines. Creating a model
before discarding an old one can temporarily overlap native allocations; these
short-scope runs do not claim to measure the worst peak of future orchestration.

Reference cycles alone do not prove a leak: cyclic garbage can be collected and
the binding has its own finalizers. RSS can remain elevated after objects die
because of allocator caching, fragmentation, JIT/library state or delayed release.
Conversely, flat RSS does not prove correct native cleanup. A short increase or
one plateau is inconclusive. Do not introduce a universal RSS pass/fail threshold.
Compare repeated fresh-process runs, warm-up/batch trends and weakref observations;
use native allocation instrumentation if unexplained persistent growth remains.
`tracemalloc` by itself cannot establish native allocation release.

Exactly-once finalization, non-mutating reports and uncached current-shape
signatures are now regression-tested. Data-only coverage preservation remains
separate work. This evidence does not justify manually closing engines, prove
kernel allocation lifetime, enable 16 KB execution, or validate Apple M3 Pro compatibility.

Lint/type-check the new Python files with the repository's tools. Because `tools`
is a namespace package, pass `--explicit-package-bases` when checking its source
and importing tests together with mypy.
