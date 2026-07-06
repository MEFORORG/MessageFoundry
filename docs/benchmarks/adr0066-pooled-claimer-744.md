# ADR 0066 pooled claimer — at-scale evidence for the #744 default flip

**Status:** measured 2026-07-03 on a two-box AWS deployment (one engine box, one SQL Server 2022
store box, same VPC/subnet). Synthetic HL7 only; numbers/metadata only, no PHI.
**Code:** `feat/adr0066-pr5-bench` @ `85c7415` (PR4 pooled wiring + PR5 harness).
**Raw artifacts + provenance:** [`results/2026-07-03-adr0066-pooled-atscale/`](results/2026-07-03-adr0066-pooled-atscale/) (`environment.txt` there records the run matrix and the box gap).

---

## Bottom line

**Flip the default `claim_mode` to `pooled`.** At 1,500 concurrent inbound interfaces the current
default (`per_lane`, one claim worker per lane) does not merely regress — it **breaches the
zero-loss / at-least-once invariant** (systemic no-ACK, accepted-and-dropped), at every count
tested. `pooled` holds zero-loss with steady throughput. The failure is a **pool-independent**
claim-storm (an empty-claim `UPDLOCK` convoy on the shared queue's claim path); a 3× larger
connection pool does **not** rescue `per_lane`, and pooled claiming is precisely what removes it.

> Read the report, not the exit code or the automated verdict. The harness `/stats` poller **zeros
> the achieved-rate aggregate under overload**, so the comparison object's
> `throughput_non_regression=True` is a *vacuous* pass (pooled ≥ a zeroed baseline). The authority
> is the per-arm **zero-loss** table below, cross-checked against the independent sink counter.

> **CORRECTION (2026-07-03, post-commit-storm).** §2 below labels the ceiling "DB-write-bound." A
> driver-free commit-storm on the *same* store box subsequently measured its raw ceiling at
> **~27,000 commits/s** (sub-ms log, already group-committing ~19:1) against the pipeline's ~750
> commits/s — a **~36× store headroom**. So the ceiling is **not** durable-write capacity; it is the
> engine-side **claim-path feed** (the same `UPDLOCK` convoy noted above), a pipeline constraint.
> Read §2's "store-write-bound" as *feed-bound*, and its "faster DB tier" lever as *raise engine feed
> concurrency*. See [`results/2026-07-03-adr0066-pooled-atscale/commit_storm.txt`](results/2026-07-03-adr0066-pooled-atscale/commit_storm.txt)
> and [ADR 0069](../adr/0069-durable-write-throughput-lever.md).

---

## 1. The decision run — A/B at 1,500 interfaces (Run 1)

Profile `pooled_ab`: `per_lane` vs `pooled`, N = 500/1000/1500, offered **400 msg/s fixed
aggregate**, `pool_size=40`. Per-arm delivery and loss (from each record's `traffic`/`no_loss`):

| mode | N | sent | delivered (sink) | acked | send-timeouts | zero-loss | ACK p99 |
|---|---:|---:|---:|---:|---:|:--|---:|
| **per_lane** | 500  | 12000 | 11416 | 11156 | 844  | ❌ **lost 584** | 22.4 s |
| **per_lane** | 1000 | 12000 | 11180 | 10575 | 1425 | ❌ **no-ACK fault** | 25.2 s |
| **per_lane** | 1500 | 11998 | 10818 | 9426  | 2572 | ❌ **no-ACK fault** | 25.7 s |
| **pooled**   | 500  | 12000 | 12000 | 12000 | 0    | ✅ clean | 10.7 s |
| **pooled**   | 1000 | 12000 | 12000 | 12000 | 0    | ✅ clean | 12.3 s |
| **pooled**   | 1500 | 11999 | 11999 | 11999 | 0    | ✅ clean | 13.0 s |

`per_lane` breaches zero-loss at **all three** counts; `pooled` is loss-free at all three. The run's
overall exit code is `1`, tripped **only** by the aggregate `zero_loss` SLO — i.e. by the `per_lane`
arm.

**Mechanism, in one number — median pool-wait on the *same* 40-slot pool:**

| N | `per_lane` pool-wait p50 | `pooled` pool-wait p50 |
|---|---:|---:|
| 500  | 1000 ms | **0.05 ms** |
| 1000 | 2500 ms | **0.05 ms** |
| 1500 | 2500 ms | **0.05 ms** (max wait hit 105 s) |

`per_lane`'s ~4,500 claim workers thrash the pool so hard that the *median* claim waits 1–2.5
seconds for a connection, cascading into ACK timeouts and drops. `pooled`'s handful of claimers get
a slot in 0.05 ms and never drop. Idle-poll collapse at N=500: **269.6 → 2.6 /s (−99.0%)**;
throughput at N=500: **72.7 → 111.8 /s (+53.8%)**. (Idle-poll collapse reads INCONCLUSIVE at
N≥1000 only because the poller zeroed `per_lane`'s idle-poll — see the reading caveat.)

At N≥1000 this is a **resilience** result, not a throughput delta: `per_lane` did not sustain a
comparable baseline to measure a percentage against — it was drowning. "Pooled survives, per_lane
breaks."

---

## 2. The throughput ceiling is DB-write-bound and pool-independent (Runs 2 & 3)

Rate-walk at N=1500, `pooled`, offered load walked up until the store saturates.

| offered /s | `pool=40` deliv/s | `pool=128` deliv/s | backlog (peak in-pipeline) | ACK p99 | zero-loss |
|---:|---:|---:|---:|---:|:--|
| 80  | 78  | —   | 19    | 0.08 s | ✅ |
| 100 | **97**  | —   | 553   | 0.44 s | ✅ **max sustainable** |
| 120 | 104 | —   | 4027  | 2.6 s  | ✅ (draining) |
| 150 | —   | 102 | 14940 | 4.3 s  | ✅ (draining) |
| 160 | 107 | —   | 8782  | 4.6 s  | ✅ **peak (burst, drained)** |
| 250 | —   | 105 | 17051 | 7.2 s  | ✅ (draining) |
| 350 | —   | 106 | 28052 | 11.3 s | ✅ (draining) |
| 500 | —   | 108 | (drained to 3) | 39.9 s | ❌ **lost 2674** |

Peak delivery is **~107 msg/s at *both* `pool=40` and `pool=128`** — the 3× larger pool does not
move the ceiling. At `pool=128`, `pool_wait` p99 pegs at the 10 s cap once the store saturates
(offered ≥ 250/s; it is 5 s at 150/s) because connections queue on the **saturated store**, not on
the pool. Engine CPU sat at ~2 cores throughout.

- **Max sustainable, zero-loss, bounded backlog ≈ 97 msg/s** (~350 k/hr, ~8.4 M/day).
- **Peak (burst that still drained) ≈ 107 msg/s** (~385 k/hr, ~9.2 M/day).

Above ~100/s the pipeline still delivers ~104–108/s but with unbounded backlog growth and climbing
latency; at 500 offered it finally can't drain and breaches zero-loss. The store write tier is the
sole lever.

---

## 3. A bigger pool does NOT rescue `per_lane` (Run 4)

`per_lane`, N=1500, `pool_size=128`:

| offered /s | delivered (sink) | send-timeouts | zero-loss | ACK p99 |
|---:|---:|---:|:--|---:|
| 400 | 31686 / 36000 | 5962  | ❌ | 56.1 s |
| 800 | 27880 / 71999 | 31157 | ❌ | 75.8 s |

Tripling the pool leaves `per_lane` in full no-ACK collapse. **The bottleneck is not pool
starvation** — it is the empty-claim `UPDLOCK` convoy on the shared queue's claim path
(per-lane workers each contend to claim the head of their lane; at high fan-out they serialize on
the queue's claim index). More interfaces feed the storm. This is exactly the contention ADR 0066's
pooled per-stage claimer removes by batch-claiming head-prefixes across lanes with `K` claimers
instead of one-worker-per-lane.

---

## 4. Scope — what this does and does not establish

**Does establish:**
- The **#744 default flip to `pooled` is justified** — on the strongest possible grounds (the
  default drops messages at enterprise fan-out; pooled does not).
- Throughput at scale is **bounded by the DB write tier**, not the engine (CPU ~2 cores) or the
  connection pool (pool-independent). The lever is the DB tier (IOPS / instance size / sharding) or
  more engine+DB pairs.
- Pooled claim scheduling is **required** for high interface counts — an architectural property,
  not a tuning trick.

**Does NOT establish:**
- **Enterprise 45 M/day capacity.** The ~8.4 M/day sustained figure is *this modest store box's*
  write ceiling — roughly **5× short** of the committed 45 M/day target. Closing that gap is a DB-tier
  exercise (a larger/faster SQL instance, sharding, or multiple engine+DB pairs), **not** an engine
  or pool change, and needs a separately-provisioned run. Do not cite 8.4 M/day as a product ceiling.
- The store box's **instance type/IOPS were not recorded** (see `environment.txt`). Any external
  capacity citation must record it first.

---

## 5. Method, caveats, and harness follow-ups

- **Topology:** one engine box + one SQL Server 2022 store box, same VPC/subnet, engine→DB on the
  local network. The harness spawns the engine subprocess(es) and drives 1,500 inbound MLLP
  interfaces of synthetic HL7; each message is received+ACKed, routed, transformed, durably
  committed, and delivered. Every run enforces a zero-message-loss reconcile.
- **Poller-zero artifact:** the engine `/stats` poller zeros the achieved-rate aggregate under
  overload. Trust the sink counter + `no_loss`/`traffic` for failing arms. **Follow-up:** make
  `compare.py` loss-aware so a baseline that breaches `zero_loss` is flagged, not compared against a
  phantom 0 (the source of Run 1's vacuous automated PASS).
- **BOM papercut:** a profile written by PowerShell `Set-Content -Encoding utf8` carries a UTF-8 BOM
  that the TOML loader rejects (`Invalid statement (line 1, col 1)`). **Follow-up:** BOM-tolerant
  `tomllib` open (or a clearer error).
- Operational, experiment-neutral: `base_port` shifted 2600→20000 to clear RDP's 3389 at 1500
  lanes; `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE=1` for the bench clone dir; store TLS trust for the
  self-signed cert. A N=50/100 smoke passed before the full run; RCSI verified ON.

---

## 6. Recommendation

1. **Merge the #744 flip** (default `claim_mode=pooled`) once PR4's rider gate is green — this run
   is the decisive evidence, led by the §1 loss table and the §3 pool-independence.
2. Ship a recommended `pool_size` note: 40 was already past the point of diminishing returns here.
3. Track the **45 M/day capacity** question separately as a DB-tier / sharding exercise on
   recorded, enterprise-sized hardware.
4. Land the two harness follow-ups (loss-aware compare, BOM tolerance).
