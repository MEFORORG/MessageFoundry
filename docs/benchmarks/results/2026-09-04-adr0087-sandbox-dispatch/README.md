# ADR 0087 sandbox — what `mode="subprocess"` costs per message (2026-09-04)

**Why this exists.** ADR 0087 states a price for its own isolation mode and calls it *"the standing,
measured price of a non-executing wire"* (`docs/adr/0087-sandbox-subprocess-isolation.md:183-191`).
No artifact recorded that measurement. At `a2eef0f37`, before this directory existed:

```
git ls-files docs/benchmarks scripts/bench | xargs grep -ril sandbox   ->  0 files
git ls-files messagefoundry docs/adr tests | xargs grep -ril sandbox   -> 59 files   (control)
```

The control is the same command shape over trees where the term must appear, so the zero is an
absence and not a broken pipeline. BACKLOG **#1194** asks for the number the record leaves asserted.
This is it.

**Instrument:** [`scripts/bench/sandbox_dispatch.py`](../../../../scripts/bench/sandbox_dispatch.py).
Raw results: `A-default-adt.json` … `E-reference20k.json` in this directory.

**Box:** Intel Core Ultra 7 265KF (20 cores / 20 threads), 31.7 GiB RAM, Windows 11 Pro 10.0.26200,
CPython 3.14.6. A developer workstation, not the WIN2025 or Azure rigs the throughput ladders use —
so read the LEVELS here, and do not compose them with a msg/s figure measured elsewhere.

**Data:** synthetic HL7 only. A fabricated ADT^A01 with invented identifiers, optionally extended
with synthetic OBX result segments. No PHI, and nothing here was run against a feed.

---

## What was measured, and why it is the right quantity

The isolation seam is `run_sandboxed` (`messagefoundry/pipeline/sandbox.py:919-921`), reached from
`route_only` (router phase) and `transform_one` (transform phase). At `mode=off` it is `fn(payload)`;
at `mode=subprocess` it marshals the call to the persistent per-inbound worker child. Everything
else on those two paths — HL7 parse, registry lookup, `Send` validation — is identical in both modes,
so the **difference of the two end-to-end call walls is the isolation overhead and nothing else**.

One received message that routes to one handler costs **one router dispatch plus one transform
dispatch**, and the per-inbound worker serializes both. `router + transform` is therefore the
per-message figure.

Method rules, each because the opposite manufactures a number: levels in milliseconds and never a
derived msg/s; `off` and `subprocess` interleaved inside each repetition so drift moves both arms;
median and p90 rather than a mean, because a subprocess round-trip has a long right tail; warmup
discarded and the one-time child bootstrap reported on its own row.

---

## Results

Per-dispatch p50, milliseconds. `overhead` is the `subprocess` minus `off` delta.

| Case | payload | reference entries | router off | router sub | transform off | transform sub | **per-message overhead** |
|---|---:|---:|---:|---:|---:|---:|---:|
| **A** shipped default, bare ADT | 195 B | 0 | 0.0033 | 0.1822 | 0.0095 | 0.2223 | **0.392 ms** |
| **B** 50-OBX result | 3.4 KB | 0 | 0.0163 | 0.2422 | 0.0291 | 0.3070 | **0.504 ms** |
| **C** 400-OBX result | 26.7 KB | 0 | 0.1141 | 0.5038 | 0.1743 | 0.6230 | **0.838 ms** |
| **D** bare ADT, 1k reference table | 195 B | 1,000 | 0.0033 | 0.4955 | 0.0106 | 0.5384 | **1.020 ms** |
| **E** bare ADT, 20k reference table | 195 B | 20,000 | 0.0034 | 7.7641 | 0.0099 | 8.0136 | **15.76 ms** |

Sample sizes: A is 7 repetitions × 200 dispatches per leg (1,400 per leg); B is 5 × 150; C, D and E
are 5 × 100.

**Uncertainty.** Two bands, and both are reported because they answer different questions.

*Within a run*, the spread of the per-repetition medians says what the next repetition would land
on. For case A's `transform/subprocess` leg that is 0.2144 – 0.2312 ms, about ±4 percent.

*Across runs* is the wider and more honest figure. Case A was run five separate times at full sample
size over this session and returned a per-message overhead of 0.409, 0.406, 0.405, 0.404 and
0.392 ms. So **read case A as 0.40 ms, good to about ±3 percent** — not as 0.392. Case E across four
runs gave 15.20, 15.76, 16.07 and 16.26 ms, so read it as **16 ms, good to about ±4 percent**.

The p90 column in the tool's own output runs roughly 1.5× the p50 on every subprocess leg. That tail
is scheduler latency and garbage collection in one of the two processes, not a second regime.

**One-time costs, which belong in no per-message figure.**

| | measured | multiplied by |
|---|---|---|
| worker spawn + `load_config` + guard install | 1.8 – 2.7 s | once per inbound per engine start |
| worker process tree, resident (RSS) | 76.8 – 82.5 MiB | one tree per inbound |
| worker process tree, unique (USS) | 49.9 – 57.0 MiB | one tree per inbound |

The spawn row is a single observation per run (n=5 across the matrix, and n=13 counting every run of
the session), so treat it as *seconds*, not as a precise figure. The memory rows are stable to
±1 MiB across every case except E, where the 20k table the child holds adds about 7 MiB.

**A measured correction to the memory instrument, recorded so nobody repeats it.** Under a Windows
virtual environment, `.venv\Scripts\python.exe` is a launcher stub that re-execs the base
interpreter. `Popen`'s own pid is therefore a ~6 MiB shim and the real ~70 MiB interpreter is its
CHILD. The first version of this tool read only the direct pid and reported **6.0 MiB per worker** —
an order of magnitude low, and clean-looking. The control that caught it: read the parent's own RSS
in the same breath (72 MiB) and enumerate the child's descendants (`python.exe`, 70.5 MiB, cmdline
`-m messagefoundry.pipeline._sandbox_worker`). The tool now sums the tree.

---

## Findings

**1. On the shipped configuration the per-message cost is 0.40 ms, and it is not the reason the
default is off.** Case A is the default posture: no reference sets published, so `reference_view()`
returns an empty cache (`messagefoundry/store/store.py:4274-4282`) and the run context carries
nothing. 0.40 ms per message is roughly 2 percent of a 16.7 ms per-message budget at 60 msg/s. A
payload two orders of magnitude larger (case C, 27 KB) still costs under 1 ms.

**2. ADR 0087's `~0.19 ms with no reference view` is CONFIRMED, and its comparison sentence is
wrong on units.** The measured no-reference figure is 0.18 ms for a router dispatch and 0.22 ms for
a transform dispatch — the ADR's number, on different hardware, is right. But the ADR then calls its
20k-table figure *"well inside the ~60 msg/s per-interface end-to-end bound the pipeline already
has"*, comparing a **per-dispatch** cost against a **per-message** bound. A message pays the cost
twice, and the same persistent worker serializes both dispatches. Case E measures about 16 ms of
serialized child time per message, a sandbox-only per-lane ceiling of roughly **61 to 66 msg/s** —
the whole of that stated budget, not a slice of it. Whether it composes additively with the store
round-trip chain is not measured here and must not be assumed.

**3. The cost that actually blocks `subprocess` as a default is memory, and no record states it.**
One persistent child per inbound at ~50 MiB unique resident. At the committed enterprise target of
1,500 inbound connections that is roughly **74 GiB** of additional resident memory and 1,500 extra
OS processes (3,000 under a Windows virtual environment, counting launcher stubs). The bench graph
is one router and one handler; a real config loads more, so 50 MiB is a floor. This constraint
attaches to the **per-inbound worker cardinality**, not to the process boundary — a bounded shared
worker pool would decouple the bill from the connection count, and would preserve exactly the
property ADR 0087 claims (a boundary to the **engine**) while dropping one it already disclaims
(`messagefoundry/pipeline/sandbox.py:39-42`: the seam draws no line between admin functions).

**4. Isolating the ROUTER phase sacrifices no documented feature.** The live-enrichment carve-out is
the stated reason `subprocess` cannot be a default, and it is a **transform-phase** feature only.
`db_lookup` raises unless a runner is active (`messagefoundry/config/db_lookup.py:109-116`), and both
activation sites in the engine sit inside `run_contexts(..., phase="transform")`
(`messagefoundry/pipeline/wiring_runner.py:5623-5627` and `:5883-5887`). The engine's own comment at
`wiring_runner.py:5119` says it: *"db_lookup raises on a Router by design, so no lookup runner."*
`accepts=` predicates run at the router phase and are covered by the same fact
(`messagefoundry/pipeline/_sandbox_worker.py:159-167`). So router-phase isolation fails closed on
nothing, and case A prices it at **0.18 ms per message**.

## What this does not establish

The measurement is a single-lane microbenchmark on one developer workstation. It does not measure
the sandbox under concurrent lanes, on a server store backend, or against a saturated executor, and
it does not measure whether the serialized child time composes additively with the pipeline's store
round-trips. It also says nothing about whether any of this satisfies ASVS 15.2.5 — that is a
grading question and it belongs to the scorecard, not to this artifact.
