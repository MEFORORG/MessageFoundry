# 0051 — Throughput parity with Corepoint — measure-first, durable-write levers, no engine rewrite

> ## ✅ THE MEASURE-FIRST PHASE IS COMPLETE (2026-07-12) — and it vindicated this ADR
> The measurements this ADR gated everything on **have been taken** (rig runs C1–C7). They **foreclose three of the
> candidate levers outright** and leave exactly one standing — the **durable-write / txn-per-event** lever this ADR
> named as its own #1.
>
> - **C5:** per-shard ceiling `R ∈ [2,3)`, below the **3.62/shard** a cleared N=16 would need → **N-sizing is
>   insufficient on its own.** (Decisive — the engine-box carve-out did not fire.)
> - **C6:** **no convoy** (0 of 288 samples met the floor) → **AMBIGUOUS-STRUCTURAL.** Not a lock, latch, grant, or
>   spill. **There is no single blocker to rewrite.**
> - **C7:** **parallelism exonerated and load-bearing** — `MAXDOP=1` made it worse *and* broke a healthy rung.
>
> **→ Store-side scaling is CLOSED** — recorded as **[ADR 0098](0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md) (Accepted)**.
> **→ The one surviving lever is transaction amortization** — **[ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md) (Proposed)**;
> its first piece, `accepts=`, is **merged** ([ADR 0084](0084-accepts-router-seam.md), #952/#213).
>
> **"Measure first" is why the wrong thing did not get built.** Everything below stands as written; the ceiling call
> it defers is now answered. Evidence: `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` §3, §8.

- **Status:** **Proposed (2026-06-28)** — the *direction* is agreed (measure first; incremental
  durable-write + lean-write levers on the existing Python engine; **no** language rewrite, **no**
  broker); the *build* of each lever is gated on the enterprise-hardware measurement and owner
  ratification. A strategy/decision ADR (no concrete build here — each buildable lever lands under its
  own ADR / backlog item), modeled on the shape of ADR 0040. **Adjusted 2026-06-29 (delayed enterprise
  hardware) — see the Update block: the no-regret levers build + proxy-measure NOW; only the
  absolute-ceiling call defers.**
- **Date:** 2026-06-28 (updated 2026-06-29)
- **Related:** ADR 0037 (L3 multi-process sharding — **built**, the multi-core path) · ADR 0039 (L5
  DBSHARD — design-approved, **shelved**) · ADR 0040 (L6 free-threading — declined-for-now) · ADR 0001
  (staged pipeline / ACK-on-receipt) · ADR 0019 (store DEK / KeyProvider) · ADR 0028 (base64 binary
  carriage) · [docs/THROUGHPUT-IMPROVEMENTS.md](../THROUGHPUT-IMPROVEMENTS.md) §5 (the engineering note) ·
  BACKLOG #64 (the tracked roadmap) · #28/#29 (load/throughput tests) · #40 (Win2025 + SQL2025 box CI) ·
  #34/#47/#62/#63 (the lean-writes/storage cluster) · #52 (capability-parity sibling) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (reliability + count-and-log invariants).

---

## Update (2026-06-29) — delayed-hardware adjustment: build the no-regret levers + proxy-measure now

The enterprise-hardware box (#40) is **not available for a while**, but build decisions are needed now. The
original "measure on enterprise hardware FIRST, build nothing before it" gate is **split in two**:

- **The ABSOLUTE ceiling stays deferred** — does *one* unified server-DB store hit 45M? sharding-vs-unified?
  the real `E_core` / IOPS? — these genuinely need enterprise hardware. **But the measurement is no longer
  blocked on the physical box**: it can be satisfied by the **local #40 box when available OR a spec-matched
  cloud setup** — an Azure VM / Azure SQL sized to the Corepoint shape (16 vCore + a **provisioned-IOPS**
  Premium SSD v2 / Ultra Disk at ~9,200 8 KB-random-write IOPS; Corepoint itself qualifies on the equivalent
  **Azure SQL 16-vCore** mapping). A correctly-provisioned cloud run is a *representative* absolute
  measurement (managed disks honour durability; no Docker/WSL2 storage virtualization) — the cloud is a
  measurement *vehicle*, not a change to the on-prem product target.
- **The RELATIVE, no-regret levers build NOW.** Group-commit ([ADR 0055](0055-group-commit-durable-write.md))
  and lean-writes / carriage (#62/#63/#47/#34) are **analysis-confirmed on the critical path regardless of
  where the absolute ceiling lands** ([[corepoint-45m-spec-parity-gap]], [[db-write-amplification-levers]]),
  and their **relative** effect is **proxy-measured on the 265KF** (consumer floor). A relative delta (does
  coalescing cut fsyncs/msg? does VARBINARY cut bytes/msg?) holds across hardware even though the absolute
  number does not.

**Proxy-measurement methodology (do NOT skip — durable-write deltas are storage-sensitive).** Carriage /
bytes-per-msg measurements are storage-*independent* and trustworthy on Docker as-is. But the **group-commit
/ fsync** measurement is skewed by Windows-Docker-Desktop storage virtualization (the WSL2 `vhdx`). For it,
either **(a)** run the DB **natively** (the real OS → NVMe fsync path), or **(b)** stay in Docker but use a
**named volume (ext4 on the NVMe `vhdx`), NEVER a Windows bind-mount**, and **verify**: run `fio --fsync=1`
(or `diskspd`) *inside the container* and compare its fsync latency to a native `diskspd` on the NVMe — if
they are in the same ballpark, the relative deltas are usable. (The earlier `gaming-pc-throughput-findings`
server-DB numbers carry this same Docker-storage caveat; the SQLite single-writer finding does not — that was
a native file on the NVMe.)

**Store-backend framing (always, per owner):** discuss SQLite alongside **Postgres + SQL Server** — the
server DBs *lift* SQLite's single-writer lock (concurrent commits), and the enterprise store is a server DB
on **one unified store**, not SQLite-sharding (which fragments the store). The group-commit lever's
*mechanism differs by backend* — see ADR 0055.

---

## Context

The forcing artifact is the **qualified Corepoint Integration Engine 45M-msg/day Server System
Requirements** (Interoperability Bidco dba Rhapsody, 05/2026): a 20-core .NET app server + a **16-core /
128 GB / 15 TB-RAID10-Tier-1** SQL Server qualified by Diskspd for **9,200 8 KB-random-write IOPS** (72
MB/s, 3.5 ms), with **multiple databases** (Queues/Logs 9 TB + Audit + PerfStats) under full **AlwaysOn
Availability Groups**, ~**11 KB/msg** durable. Corepoint's own document names *"the speed of the disk of
the database server's data drive"* as **the leading performance driver in message flow** — i.e. the
durable-write / DB tier is the battleground, by the incumbent's own account.

An earlier internal "we're at per-server parity" claim was **wrong**: it benchmarked against Rhapsody
*marketing* (~500 msg/s), not this qualified spec. The honest 2026-06-28 assessment:

- **Compute — unvalidated.** Only `E_core ≈ 42 msg/s` is *measured*, on a deliberately under-powered box
  (15 W APU + consumer SSD); the production estimates (×2 ≈ 84; a server-sizing ≈ 400) are **unvalidated**,
  so the whole sizing swings ~5×. Multi-process sharding (ADR 0037) is **built** and reaches the published
  competitor figure at the conservative `E_core`, but **per-connection** (not per-message) — a single hot
  feed is pinned to one core.
- **Durable-write — behind.** ~7 committed transactions/msg (`3 + 2H + 2N`) and **group-commit is not
  built**; the durable path is the named #1 lever.
- **Storage — runs higher, but mostly by construction, not inefficiency.** The "~2× vs Corepoint" figure
  was an unvalidated estimate vs a brochure number and is **retracted**. The real, code-confirmed drivers
  are **carriage** (`NVARCHAR(MAX)` 2 B/char + base64 of the `mfenc` ciphertext) and **encrypt-by-default**
  (AES-256-GCM at rest, key outside the DB — a stronger PHI posture Corepoint leaves to optional SQL TDE).
- **HA / multi-DB maturity — behind** (single shared DB + active-passive vs AlwaysOn AG across 4 DBs;
  DBSHARD shelved).
- **Cost / openness — ahead** (AGPL, no per-engine license, SQLite-default, code-first Python authoring).

The decision is bounded by the standing invariants, quoted verbatim ([CLAUDE.md](../../CLAUDE.md) §2):

> **Reliability invariant (do not break):** … At-least-once now relies on a re-run re-deriving identical
> output, so **routers and transforms must be pure** … outbound connections must still be **idempotent**.

> **Count-and-log invariant (do not break):** **every received message is persisted before the ACK** … so
> inbound counts still reflect the true received volume and nothing is accepted-and-dropped.

A full **language rewrite** would gut the load-bearing **code-first-Python** differentiator (Routers/
Handlers authored in Python) and re-prove the entire at-least-once / FIFO / finalizer / PHI / ASVS-L3 core
from zero — and it does not even raise the per-server ceiling (sharding does). A **broker** solves a
non-bottleneck on enterprise hardware and forfeits the single-system-of-record + exact FIFO + broker-less
on-prem identity. (Scope note: the owner's "rewrite the engine in another language" means the engine
**service runtime only**, with Python Routers/Handlers preserved — a **scoped native core** is more
defensible, but still re-proves the invariant-dense core *and* leaves the Python logic GIL-bound across the
boundary; it is a deferred contingency, not this decision.)

## Decision

**Pursue Corepoint-class throughput by validating on enterprise hardware FIRST, then applying incremental,
language-independent durable-write and lean-write levers on the existing Python engine plus multi-process
sharding — NOT a language rewrite and NOT a broker.** The ordered path, each step gated on the one before:

1. **Measure first (the gate).** Run an enterprise-hardware `E_core` + sustained durable-write IOPS test —
   the local **Windows Server 2025 + SQL Server 2025 box (#40)** via the load harness (#28/#29) — against
   the concrete Corepoint target: **sustain ~9,200 8 KB-random-write IOPS at the 20 + 16-core shape, ~11
   KB/msg**, and pin the real `E_core` (42 vs 84 vs 400). This single run collapses "unvalidated" to a
   number and tells us which axis binds. **Adjusted (2026-06-29, see Update):** this *absolute* run is
   deferred to the local box **or a spec-matched Azure setup** and gates only the absolute-ceiling decisions
   (one-store-vs-sharding, multi-DB split). It **no longer blocks** the no-regret levers below, whose
   *relative* deltas are proxy-measured on the 265KF.
2. **Group-commit** (durable-write, the #1 unbuilt lever) — **build now** (no-regret; analysis-confirmed as
   the #1 durable-write lever, [ADR 0055](0055-group-commit-durable-write.md)), with its relative fsync/msg
   delta proxy-measured per the methodology above. *Was: "iff the run shows durable-write-bound."* —
   coalesce stage commits to cut fsyncs/msg while preserving at-least-once, the per-stage **claim
   poison-guard**, and ACK-on-receipt. Designed; lands under **its own ADR** when built.
3. **Lean-writes / carriage** (storage): VARBINARY ciphertext (#62), the `message_events` verbosity knob
   (#63), embedded-doc pruning (#47, ADR 0042), per-connection retention (#34).
4. **Multi-DB log split** — **shared-server backend only** (isolate event/audit I/O from the queue's write
   path). The **atomic staged-queue transaction cannot be split** (cross-DB 2-phase commit is *more*
   expensive); only the non-transactional logs/audit can move.
5. **Contingencies, deferred behind the gate:** the **scoped native engine-service core**, **free-threading**
   (ADR 0040), and **DBSHARD** (ADR 0039) — revisited only if the measurement shows machinery-bound and/or
   the single-hot-feed case matters in practice.

Multi-process sharding (ADR 0037, built) stays the multi-core path. This decision changes **no** production
behaviour and breaks **no** invariant — it records a direction and a gate, not a build.

## Options considered

1. **Measure-first incremental Python levers + sharding (this).** **CHOSEN.** Closes the real durable-write
   and storage gaps at a fraction of the cost/risk, preserves the differentiator, and per-server parity is
   already reachable via sharding at the conservative `E_core`. Every step is gated on a real measurement
   with a concrete target.
2. **Full language rewrite (Go / Rust / C# / JVM).** **Rejected** — guts the code-first-Python
   differentiator + re-proves the whole correctness/PHI core from zero, and does not raise the per-server
   ceiling (sharding already does).
3. **Scoped native engine-service core (keep Python Routers/Handlers).** **Deferred** — more defensible
   (preserves the differentiator; the pure-transform contract makes the native↔Python boundary clean) and
   the most credible path to durable-write parity + escaping sharding sprawl + the single-hot-feed gap — but
   still re-proves the invariant-dense core in a new language *and* the Python logic stays GIL-bound across
   the boundary (the native core relocates, not eliminates, the per-core Python-parallelism problem).
   Revisit only post-measurement.
4. **External broker (Kafka / RabbitMQ).** **Rejected** — solves a non-bottleneck on enterprise hardware;
   forfeits the single-system-of-record + exact FIFO + broker-less on-prem identity.
5. **Claim parity / do nothing.** **Rejected** — the "at parity" claim rested on Rhapsody marketing, not the
   qualified spec; honesty requires the measure-first path.

## Consequences

**Positive** — closes the genuine gaps (durable-write, storage) with cheap, language-independent,
differentiator-preserving levers; every step gated on a real measurement against a concrete incumbent
target; reuses already-built machinery (sharding ADR 0037, store-once L2b); records the no-rewrite /
no-broker stance so a future "should we rewrite" restarts from a decision, not a blank page.

**Negative / risks** — every msg/s number swings ~5× on the **unvalidated** `E_core` until the box runs;
group-commit touches the most invariant-dense code (a real correctness risk — designed but unbuilt, and it
revisits the read-through-cache publish + cross-lane state visibility); storage will likely always run
somewhat higher than a plaintext-compressed competitor — the accepted cost of **encrypt-by-default**; and a
**single hot feed stays capped at one core** under per-connection sharding until a native core or
free-threading is adopted.

**Out of scope / deferred** — the actual **group-commit build** (its own ADR); the **scoped native-core
rewrite** + **free-threading** (ADR 0040) + **DBSHARD** (ADR 0039), all contingencies behind the
measurement; and the marketing/positioning of any parity claim (which must wait for the measured number).

## To resolve on acceptance

> The direction is decided; these gate the flip to `Accepted` (and the start of any lever build). Tracked so
> `adr-analyze` surfaces anything still open.

- [ ] Run the enterprise-hardware `E_core` + durable-write IOPS validation (#40 box / #28/#29 harness)
      against the 9,200-IOPS / ~11 KB-msg / 20 + 16-core target; record the real `E_core` and the binding axis.
- [ ] On that result, decide whether to build **group-commit** (its own ADR) — i.e. confirm durable-write-bound.
- [ ] Measure MEFOR's **real durable bytes/msg** and compare to a **real** Corepoint per-message footprint
      (the owner's live system, not the brochure) before sizing any storage-parity work.
- [ ] Owner ratify the **no-full-rewrite / no-broker** stance and the deferral of the scoped native core /
      free-threading / DBSHARD as post-measurement contingencies.
