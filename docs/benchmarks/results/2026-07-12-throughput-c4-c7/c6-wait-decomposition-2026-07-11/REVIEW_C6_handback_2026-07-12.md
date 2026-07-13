# REVIEW — C6-LIVE handback (`HANDBACK_C6-LIVE_2026-07-12.md`)

**Date:** 2026-07-12 · **Reviewer:** coordinator · **Re:** the C6-LIVE convoy run (4 arms)
**Bottom line: VERDICT ACCEPTED — AMBIGUOUS-STRUCTURAL, fully verifiable against the shipped artifacts. This is the
best-disciplined handback of the arc. I attempted to refute it and failed; it refuted ME instead (see §2).**
**One NEW lead the run surfaced and nobody has yet looked at: `CXSYNC_PORT`. See §4 — flagged as a HYPOTHESIS, not a finding.**

---

## 1. The verdict is ACCEPTED — **AMBIGUOUS-STRUCTURAL**, both contrasts agree

Every load-bearing number reconciles against `c6_convoy_*.json`:

| arm | floor met | `convoy_present` | max group | max chain | tempdb-catalog VOIDs | runnable med (max) |
|---|---:|:--:|---:|---:|---:|---:|
| N=4@2 (floor) | **0/72** | `False` | 0 | 0 | 0 | 1 (3) |
| N=8@2 (PASS control) | **0/72** | `False` | 1 | 1 | 0 | 3 (9) |
| **N=8@3 (⭐ FAIL primary)** | **0/72** | `False` | 1 | 1 | 0 | 9 (20) |
| N=16@2 (target) | **0/72** | `False` | 2 | 1 | 0 | 17 (52) |

- **The convoy floor (≥5 suspended on one `resource_description`, or a chain ≥2 deep) was met in ZERO of 288 samples.**
  The largest suspended group ever observed, across the whole run, was **2**. Max chain depth **1**. There is no convoy.
  This is not a close call.
- **`n_sched = 8`** on every arm — the store box is genuinely unchanged (i4i.2xlarge), which is what the CPU% denominator
  and every C3/C4 comparison depend on. The engine-box change (m7i.4xlarge) is correctly recorded as a deviation and
  correctly argued to be irrelevant to a *within-run* contrast.
- **No VOID.** `void_tempdb_catalog_samples = 0` on all four arms; the only `PAGELATCH` hits were on **`mfbench`
  (db_id=5) USER pages** — and `storepage_soak.txt` confirms they are *scattered* (`5:1:310623`, `5:1:307604`,
  `5:1:306091` — one hit each, on the `queue` table, different pages). Not a hot page. The latch-free feature held.
- **The matched pair did its job.** N=8@3 (FAIL) vs N=8@2 (PASS), same shard count: **no convoy in either.** The arm
  I added to isolate a convoy from `N` found that there is nothing to isolate. That is a real answer, cheaply obtained.
- **The false-negative defence (§7) is sound.** The sampler *did* see waits (37/72 and 51/72 samples had ≥1 waiting
  task) — they were simply **scattered, never grouped**. And runnable tracked the collapse building (N=16: 0 early → 39
  late, max 52). The instrument was awake and looking; there was nothing there.
- **N=8@3 reproduced a third time** (50.1% delivered, slope +112.5 — against C5-b/b2's 50–52% and +108/+111). The C5
  collapse is now 3-for-3.

**The guardrails held under pressure.** The run had every temptation to name CPU-BOUND — store at 94%, runnable 52 on 8
schedulers, `SOS_SCHEDULER_YIELD` in the millions — and it correctly refused, per the §4 preclusion. That is the
discipline this programme exists to enforce.

---

## 2. ⚠️ The handback CORRECTS MY OWN C5 REVIEW — and it is right

My `REVIEW_C5_handback §2(c)` claimed `WRITELOG` was **absent** from C5's waits, and inferred "no write-path pressure."
**That was wrong.** C6's fenced, exclusion-set-filtered delta (`wait_delta_fenced_filtered_top`) shows:

| arm | `WRITELOG` `d_resource_ms` | rank |
|---|---:|:--:|
| N=4@2 (**100% delivered, healthy**) | **127,962** (≈128 s) | **#1** |
| N=8@2 | 191,348 (≈191 s) | **#1** |
| N=8@3 | 250,947 (≈251 s) | **#1** |
| N=16@2 | 577,773 (≈578 s) | **#1** |

`WRITELOG` was in C5's store all along — it simply sat **below the ~792,000 ms noise floor of C5's unfiltered top-14**,
crowded out by the idle-wait cluster. **I inferred absence from a truncated list: the mirror image of the very error I
was criticising.** Retracted in `REVIEW_C5_handback §2(c)`.

**The handback's numbers reconcile exactly** (its "128 s → 578 s" are the `d_resource_ms` column — I initially mis-checked
them against the raw *unfenced* `d_wait_ms` and wrongly suspected a discrepancy). **It is correct and I was not.**

**And its framing is better than mine was:** the reason §6's "write-path signature" names nothing is **not** that the
write wait is missing — it is that `WRITELOG` is **rank-1 even on the 100%-delivered N=4 floor.** A wait that is rank-1
when everything is healthy cannot name a wall when things collapse. That is the cleanest possible demonstration of why
rank never names a wall, and the handback found it. Credit where due.

---

## 3. Scoping note — what AMBIGUOUS-STRUCTURAL does NOT exclude (not a challenge to the verdict)

The verdict answers exactly the question asked — *"is the collapse blocked on a resource **convoy**?"* — and the answer
is a well-evidenced **no**. But it is worth stating plainly what that does and does not rule out, so the phrase does not
harden into "we looked and there is nothing there":

**The §3(a) convoy detector is, by construction, blind to any cost that is not a *shared* `resource_description`.** It
requires ≥5 sessions suspended on **one** resource. Costs that are **per-session** or **per-query** — parallelism
exchange, per-call CPU, allocator churn, scheduler queueing — **can never form a convoy** and will *always* return
"no convoy," no matter how dominant they are. So AMBIGUOUS-STRUCTURAL is consistent with:

- aggregate txn/event volume (the handback's reading — and the one C5 independently supports), **and**
- **self-inflicted per-query overhead** that the instrument cannot see (§4 below).

These have **different fixes**. The handback's consequence (→ txn/event levers) is well-supported and I endorse it as
the primary path — but it should not be read as "no other lever exists," because this instrument could not have found one.

---

## 4. 🔍 NEW LEAD — `CXSYNC_PORT` is the fastest-growing real wait in the run, by a wide margin (**HYPOTHESIS, NOT A FINDING**)

Nobody has looked at this. From the same fenced, filtered delta (`d_resource_ms`, 720 s window):

| wait | N=4@2 | N=8@2 | N=8@3 | N=16@2 | **growth N=4→16** |
|---|---:|---:|---:|---:|---:|
| `WRITELOG` | 127,962 | 191,348 | 250,947 | 577,773 | **4.5×** |
| **`CXSYNC_PORT`** | **10,782** | **50,020** | **130,588** | **366,796** | **⭐ 34.0×** |
| `MEMORY_ALLOCATION_EXT` | 35,351 | 84,196 | 101,192 | 109,221 | 3.1× |
| `IO_COMPLETION` | 11,437 | 23,027 | 21,971 | 22,933 | 2.0× |
| `LCK_M_X` | 29,023 | 7,752 | — | — | **shrinks** |

**`CXSYNC_PORT` is intra-query parallelism exchange.** It grows **34×** across the ladder — **7.5× faster than
`WRITELOG`** — and by N=16 it is the **#2 real wait** at 367 s of resource wait. It is also, per §3, **structurally
invisible to the convoy detector** (each query's exchange is its own resource, so parallelism can never meet the floor).

**The corroborating signal:** `WRITELOG`'s **signal fraction** (`d_signal_ms / d_wait_ms`) climbs **20% → 41% → 50% →
47%** across the ladder. Signal wait is time spent waiting for a **scheduler after the resource was already granted** —
i.e. rising signal fraction means tasks are increasingly **queueing for CPU, not for the log.** That is a
scheduler/CPU-pressure signature, and it is consistent with parallel plans oversubscribing 8 schedulers.

**The hypothesis:** a meaningful share of the store's CPU/scheduler pressure may be **self-inflicted parallelism
overhead** — store queries (plausibly the `list_fifo_lanes` `DISTINCT`/`ORDER BY` shape C4 fingered, which is exactly
the kind of plan the optimiser parallelises) going parallel across 8 schedulers and paying exchange + scheduler-queueing
cost. If so, a **`MAXDOP` / `OPTION (MAXDOP 1)` change on the dispatcher/claim queries could be an unusually cheap test.**

**⛔ Why this is a HYPOTHESIS and must NOT be written up as a finding:**
- `CXSYNC_PORT` is present on the **healthy N=4 arm** too (10.8 s). By this review's own standard, **a wait that appears
  when healthy cannot name a wall by its rank or its growth rate.** I am doing the *same* thing I just retracted C5 §6
  for — the only difference is that I am labelling it as such.
- The growth may be an **effect of collapse, not a cause**: deeper queue scans → bigger row estimates → parallel plans.
  This is *precisely* the "effect vs cause" trap that made C4's `list_fifo_lanes` result WITHHELD. **The one thing that
  weakly cuts against pure-effect:** `CXSYNC_PORT` already grows **4.6×** from N=4 to **N=8@2 — a 100%-delivered,
  pre-collapse arm** (10,782 → 50,020) at only 2× the shards. Suggestive. **Not conclusive.**
- Naming it now, off a rank and a growth rate, is exactly the inference class that got **C2 and C4 walked back.**

**Recommended disposition:** log it as an **open question**, not a result. It is **cheap** to settle (read the actual
query plans + `dm_exec_query_stats` DOP, or run one arm with `MAXDOP 1` on the store) — but it must be settled by a
**pre-registered test**, not by staring at this table. **It does not change C6's verdict, and it does not displace the
txn/event levers as the primary path.**

---

## 5. What C5 + C6 together settle (endorsed)

- **C5:** `R ∈ [2,3) < 3.62` → **N-sizing is insufficient on its own.**
- **C6:** the collapse is **not a nameable convoy** — not a lock, not a shared latch/page, not a memory-grant or spill.
- **Therefore:** neither *more shards* nor *a contention fix* nor *a single-query CPU rewrite* gets to 45M/day. The
  **`txn/event` levers** (Phase-3 `accepts=` — already merged; Phase-4 group-commit / batch-fusion) are the path, and
  they are **co-requisites, not follow-ons.**
- **Robustness note:** this consequence survives the one live dispute in the arc. Even if the §4 **CPU-BOUND preclusion**
  (resting on the offline 64.4% reconciliation) is wrong and the store *is* CPU-bound, the fix is *still* "fewer store
  round-trips per event" — which is *still* the txn/event levers. **The recommendation is robust to that disagreement**,
  which is a good reason to act on it now rather than re-litigate the preclusion.
- **Closed by C6:** the C4 WAIT-vs-CPU question (no convoy → not contention-bound) and the `list_fifo_lanes`
  intrinsic-vs-spill residual (no spill convoy → does **not** resolve to spill).

---

## 6. Sources
`HANDBACK_2026-07-12/c6-{n4x2,n8x2,n8x3,n16x2}/`: `c6_convoy_*.json` (floor, group, chain, runnable, and
`wait_delta_fenced_filtered_top` — the fenced, exclusion-set-filtered delta quoted throughout), `c6_samples_*.json`
(72 raw samples/arm), `c6-*.json` (throughput, `commit_sha`), `storepage_soak.txt`, `cpu_soak.csv`.
Read-only DMV / public catalog names only; no secrets, IPs, hostnames, ports, or PHI.
