# Throughput improvements

*Status: analysis / backlog (targeted for 0.2). Last updated 2026-06-15.*

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
| **PostgreSQL** | Track B scale-out (built) | Usually *slower* per write (network + MVCC). Wins by `SKIP LOCKED` letting **N nodes/processes** drain one shared store concurrently — throughput scales with workers, not DB speed. |
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
| **Multiple engine processes, sharded by inbound** | Each process = own loop + own core, all draining the shared store via `claim_next_fifo` / `SKIP LOCKED`; lane-owner gating (`coordinator.lane_owner()`) already preserves FIFO-per-lane across workers. The Track-B scale-out infra **already supports this** on Postgres/SQL Server. | **Best.** Lowest new risk; reuses built machinery. The scale-out model applied on one box. |
| **`ProcessPoolExecutor` for heavy transforms** | Transforms are *required to be pure* (re-run-safe for at-least-once) → embarrassingly parallel → ideal pool candidates. | Workable, but per-message serialization cost + `db_lookup` (which bridges back to the loop) complicate it. Use only for genuinely heavy transforms. |
| **Free-threaded Python 3.13+ (no-GIL, PEP 703)** | Would make the existing `to_thread` / thread-pool path *actually* parallel with minimal code change. | Promising; **dependency-compat risk** (hl7apy, python-hl7, pydantic, PySide6). Track it, don't bet a release on it. |

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

1. **Measure** with the load harness (`cheap`/`edit`/`slow`; SQLite vs Postgres) to confirm the
   binding axis per representative feed.
2. **Lazy MSH-only peek** (§3b) — cheap code change, immediate per-message win.
3. **Group-commit** (§2) — the single-node durable-write win; stays on existing backends.
4. **Multi-process sharding by inbound** (§3a) — the real core-axis ceiling-breaker; reuses the
   Track-B lane-owner / `SKIP LOCKED` machinery.
5. Author-side transform discipline (§3c) as standing guidance.
6. Park PyPy/Cython (§3d) and free-threaded Python (§3a) as "if parse-bound" / "when the ecosystem
   catches up."

Each of 2–4 is real work and gets its own plan + tests before building.
