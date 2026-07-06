# Throughput improvements

*Status: analysis / roadmap. Last refreshed 2026-06-28 — multi-process sharding (L3, ADR 0037) and
store-once (L2b) have **shipped**; the Corepoint-anchored path-to-parity is now **§5**, with the strategy
+ no-rewrite decision recorded in [ADR 0051](adr/0051-corepoint-throughput-parity-strategy.md) and tracked
as [BACKLOG #64](BACKLOG.md).*

How to make MessageFoundry faster, grounded in the current code and in our own
[throughput research](marketing/throughput-research-2026-06-13.md) (local/private) and
[load-testing harness](LOAD-TESTING.md). This is an engineering note, not a committed plan — the
0.2 work is one row in the [v0.1 plan's "deferred to 0.2+" table](releases/v0.1-PLAN.md).

---

## 1. Where the wall actually is

Two questions get conflated. Keep them separate:

1. **Durable-write throughput** — how fast can we commit a message (and each stage handoff) to the
   store? This is the *database* axis.
2. **Per-core compute throughput** — how fast can one CPU core decode → peek → route → transform →
   re-encode a message? This is the *Python core* axis.

Our research found that for an HL7 engine **both** matter, and that every incumbent (Mirth, Rhapsody,
Corepoint) hits the **same "durable commit gates throughput" wall** — the same class of constraint as
our single-writer SQLite WAL. But it also found **transformation cost is the dominant,
hardware-independent reducer** (a vendor self-benchmark showed ~1000 msg/s pass-through → ~400 msg/s
with transformation, −60%). So the core axis is often the binding one in practice.

**Rule: measure before optimizing.** The [load harness](LOAD-TESTING.md) has a deliberate CPU-spin
transform mode (`MEFOR_LOAD_TRANSFORM=slow`, a busy-loop not a sleep) specifically to find the
per-core transform ceiling. Run `cheap` vs `edit` vs `slow`, and SQLite vs Postgres, to learn whether
a given feed is parse-bound, transform-bound, or durable-write-bound *before* picking a lever below.

---

## 2. The database axis — why "pick a faster DB" is the wrong frame

The database engine is rarely the throughput lever; the **durable-write commit pattern** is. A faster
DB shaves the constant, it doesn't change the curve.

| Backend | What it's for | Throughput story |
|---|---|---|
| **SQLite (WAL)** | Single-node default | Fastest *per-write* (in-process, no network hop). The single-writer ceiling is the limit — and the lever is **group-commit**, not the engine. |
| **PostgreSQL** | Server-DB backend (built) | Usually *slower* per write (network + MVCC). The win is concurrency: `SKIP LOCKED` + row leases let many connections / lanes / delivery workers drain the shared store in parallel within one engine, so throughput scales with workers, not DB speed. (Engine HA is single-leader active-passive — the graph runs on the leader only; horizontal active-active multi-node draining was dropped and its code removed.) |
| **SQL Server** | Epic-shop requirement (promotion in progress) | Same class as Postgres — chosen for the customer ops stack, not for raw speed. |

### What about InterSystems Caché / IRIS?

Caché (now **InterSystems IRIS**) is genuinely fast for write-heavy workloads — but for an
*architectural* reason, not because it's a "faster SQL engine." It's a multidimensional "globals"
store with a **write-daemon + journal**: a commit lands in an in-memory journal buffer and the write
daemon asynchronously batches the physical disk writes. That is **group-commit done at the storage
tier** — exactly the lever we'd build in the app on SQLite/Postgres. So it would lower our
per-message durable-write cost, but:

- **It's proprietary/commercial.** There's no free embeddable Caché the way SQLite ships in-process;
  a Caché store backend conflicts with the project's open-source (AGPL) model.
- **If you're in the InterSystems ecosystem you'd use their *engine*, not their DB under ours.**
  IRIS for Health / HealthShare (ex-Ensemble) *is* a Mirth/Rhapsody competitor built on Caché.
  Bolting Caché under MessageFoundry takes on the licensing without the reason people pay for it.
- **It only helps if the DB is the bottleneck** — and the core axis (§3) may bind first.

**Conclusion:** Caché's win is the same group-commit lever we can build ourselves, minus the
open-source story and plus a licensing/ops bill. Not a backend we should chase.

### The database lever we *should* pull: group-commit

Coalesce many messages (and stage handoffs) into one durable commit. This is the single biggest
single-node durable-write win, it stays on the stores we already support, and it captures most of what
Caché's write daemon would give us — for free. Paired with **lean writes** (fewer rows/bytes per
message through the staged pipeline) and a **read/write split** (keep reads off the single writer).

---

## 3. The Python core / transform axis

**The key fact:** everything runs on one event loop in one process, so all Python work — decode,
peek, route, transform, re-encode — is bound to **one CPU core**, and the GIL means threads don't add
CPU parallelism for pure-Python work. Per inbound there's a listener + router worker + transform
worker; per outbound a delivery worker
([`wiring_runner.py`](../messagefoundry/pipeline/wiring_runner.py)) — all on that one loop.

Strict hl7apy validation is already pushed off-loop via `asyncio.to_thread`
([wiring_runner.py:740](../messagefoundry/pipeline/wiring_runner.py#L740)), but that only keeps the
loop *responsive*; the GIL means it does **not** run in parallel with other Python. `to_thread` buys
latency isolation, not throughput.

### 3a. Use more than one core *(highest leverage)*

| Approach | Fit | Verdict |
|---|---|---|
| **Multiple engine processes, sharded by inbound** | Each process = own loop + own core, owning a **disjoint** set of inbound connections — each shard with its own SQLite file + API port. | **BUILT** — ADR 0037 (`messagefoundry supervise` / `serve --shard`, PR #584): K subprocesses at ~0.85 linear efficiency. Sharding is **per-connection, not per-message** (per-message-key was rejected to preserve per-channel FIFO), so a *single hot feed* is pinned to one core — the one gap sharding can't close. |
| **`ProcessPoolExecutor` for heavy transforms** | Transforms are *required to be pure* (re-run-safe for at-least-once) → embarrassingly parallel → ideal pool candidates. | Workable, but per-message serialization cost + `db_lookup` (which bridges back to the loop) complicate it. Use only for genuinely heavy transforms. |
| **Free-threaded Python 3.14 (no-GIL, cp314t; PEP 703/779)** | Would make the worker threads *actually* parallel in one process — the only lever that lifts the single-hot-feed cap. | **Declined-for-now — [ADR 0040](adr/0040-free-threaded-engine-support.md)**: a weekly cp314t canary runs; the core compiled wheels (pydantic-core, cryptography, argon2/cffi) ship cp314t, but the single-thread tax + per-thread C-extension thread-safety are **unmeasured**. A deferred contingency, not a default. |

The purity invariant is the gift: because routers/transforms must be pure, parallelizing them across
processes is safe by construction.

### 3b. Stop parsing the same message multiple times *(cheap, high-impact)*

A message is parsed more than once: `Peek.parse` at ingress builds the **entire** python-hl7 tree
([peek.py:130](../messagefoundry/parsing/peek.py#L130)) just to read MSH-9/10/12 for routing; then
`route_only` re-parses the persisted raw in the router worker, and `transform_one` re-parses again in
the transform worker. The staged model persists raw text between stages (for durability/purity), so
some re-parse is the architecture's cost — but two concrete cuts:

- **Lazy / MSH-only peek.** Routing usually needs only MSH-9/10/12, yet `hl7.parse` walks the whole
  message. A fast MSH-only peek (split the first segment on the field separator from MSH-1) would slash
  hot-path parse cost on high-volume feeds; fall back to the full parse only when a filter touches a
  non-MSH path. **Cheapest high-impact change.**
- **Parse once within a stage.** Ensure a handler's transform parses once and reuses, rather than each
  field read/write re-walking.

### 3c. Make the transform itself cheap *(author-side, standing guidance)*

Since transformation cost dominates:

- **Precompile regex at module import** — the loader imports handler modules once; never `re.compile`
  per message.
- **Keep hl7apy out of the transform hot path** — it's the slow, full-structure parser; use the
  lightweight `Message` / peek API for field reads/writes + re-encode.
- **No synchronous network/DB inside transforms.** `db_lookup` (ADR 0010) is the one sanctioned
  exception and is already off-loop, but it blocks a worker thread up to 30s — use it sparingly.

### 3d. C-accelerate the parser *(bigger lift, biggest ceiling raise)*

python-hl7 is pure Python. If profiling shows parsing dominates, the heavy hammers are **PyPy**
(whole-process JIT — but PySide6/aiosqlite compat risk) or a **Cython/Rust extension** for the hot
peek. High payoff, but only after confirming parsing is the bottleneck.

---

## 4. Recommended order

1. **Measure** with the load harness (`cheap`/`edit`/`slow`; SQLite vs server DB) to confirm the binding
   axis per representative feed — now anchored to the **Corepoint target** (§5).
2. **Group-commit** (§2) — the single-node durable-write win; the **#1 unbuilt lever**; stays on existing
   backends. Lands under its **own ADR** when built (it touches the most invariant-dense code).
3. **Lean-writes / carriage** — VARBINARY ciphertext ([#62](BACKLOG.md)), the `message_events` verbosity
   knob ([#63](BACKLOG.md)), embedded-doc pruning ([#47](BACKLOG.md) / ADR 0042), retention
   ([#34](BACKLOG.md)).
4. **Multi-process sharding by inbound** (§3a) — **BUILT** (ADR 0037); the multi-core path. For the
   shared-server backend, a **multi-DB log split** (move event/audit churn off the queue's writer) is a
   further I/O-isolation step — but the **atomic staged-queue transaction cannot be split**.
5. **Lazy MSH-only peek** (§3b) + author-side transform discipline (§3c) — but the L2a parse-dedup pass
   found single-parse a **non-win** for HL7, so **confirm parse-bound** before investing.
6. Park **PyPy/Cython** (§3d), the **scoped native engine-service core**, and **free-threaded Python**
   ([ADR 0040](adr/0040-free-threaded-engine-support.md)) as contingencies, revisited only on the
   measurement.

Each lever is real work and gets its own plan + tests before building. The full Corepoint-anchored
ordering is **§5** / [ADR 0051](adr/0051-corepoint-throughput-parity-strategy.md) /
[BACKLOG #64](BACKLOG.md).

---

## 5. Path to Corepoint throughput parity (2026-06-28)

The forcing artifact is the **qualified Corepoint 45M-msg/day spec**: a 20-core app server + a **16-core /
128 GB / 15 TB-RAID10-Tier-1** SQL Server qualified for **9,200 8 KB-random-write IOPS**, multi-DB
(Queues/Logs 9 TB + Audit + PerfStats) under **AlwaysOn AG**, ~**11 KB/msg** durable — and Corepoint's own
doc names **DB durable-write I/O as the leading performance driver**. The decision + rationale are in
[ADR 0051](adr/0051-corepoint-throughput-parity-strategy.md); this is the engineering note.

**Honest verdict — NOT at demonstrated parity at 45M/day** (an earlier "at parity" claim was measured
against Rhapsody *marketing*, not this spec):

- **Compute** — *unvalidated*. Only `E_core ≈ 42 msg/s` is measured (under-powered box); 84/400 are
  estimates, so sizing swings ~5×. Sharding (ADR 0037) reaches the published figure at the conservative
  `E_core`, but per-connection — a single hot feed is one-core-bound.
- **Durable-write** — *behind*: ~7 commits/msg, **group-commit unbuilt**.
- **Storage** — runs higher, but mostly **by construction, not inefficiency**. The "~2× vs Corepoint" was
  estimate-vs-brochure and is **retracted**. The real, code-confirmed drivers are **carriage**
  (`NVARCHAR(MAX)` 2 B/char + base64 of the `mfenc` ciphertext → ~2.66·B on SQL Server; VARBINARY ciphertext
  ≈ B+28, ~Corepoint-class — [#62](BACKLOG.md)) and **encrypt-by-default** (AES-256-GCM at rest, key outside
  the DB — a stronger PHI posture than Corepoint's plaintext-+-optional-TDE; ciphertext also can't compress).
- **HA / multi-DB maturity** — *behind*. **Cost / openness** — *ahead*.

**The measure-first path (each step gated on the one before):**

1. **Measure (the gate).** An enterprise-hardware `E_core` + sustained durable-write IOPS run — the local
   **Windows Server 2025 + SQL Server 2025 box** ([#40](BACKLOG.md)) via the load harness
   ([#28](BACKLOG.md)/[#29](BACKLOG.md)) — against the **9,200-IOPS / ~11 KB-msg / 20 + 16-core** target.
   Pins `E_core` and the binding axis. **Nothing builds before it.**
2. **Group-commit** (§2) — *iff* durable-write-bound. Its own ADR.
3. **Lean-writes / carriage** — the [#62](BACKLOG.md)/[#63](BACKLOG.md)/[#47](BACKLOG.md)/[#34](BACKLOG.md)
   cluster.
4. **Multi-DB log split** — shared-server backend only.
5. **Deferred contingencies** — the scoped native engine-service core, free-threading
   ([ADR 0040](adr/0040-free-threaded-engine-support.md)), DBSHARD ([ADR 0039](adr/0039-database-tier-sharding-l5.md)) —
   revisited only if the measurement shows machinery-bound and/or the single-hot-feed case matters.

**Not on the path:** a full language rewrite (guts the code-first-Python differentiator + re-proves the
correctness/PHI core; doesn't raise the per-server ceiling) and an external broker (solves a non-bottleneck
on enterprise hw; forfeits single-system-of-record + exact FIFO + broker-less on-prem) — both declined in
[ADR 0051](adr/0051-corepoint-throughput-parity-strategy.md).
