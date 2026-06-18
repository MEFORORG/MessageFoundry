# MessageFoundry — System Requirements

These are the minimum and recommended requirements for running the MessageFoundry (MEFOR)
engine, its message store, and the administration clients. The engine is a headless
Python/asyncio service; the console is a separate desktop application.

> **On the throughput figures.** MEFOR does **not** ship a validated, published per-node
> throughput baseline. The sizing tiers in [Sizing by message volume](#sizing-by-message-volume)
> are **engineering estimates** derived from the architecture and from the synthetic load-test
> profiles in [`harness/load/`](../harness/load/) — they are starting points, not guarantees.
> Always establish your own baseline on production-like hardware before go-live
> (see [LOAD-TESTING.md](LOAD-TESTING.md) and [§ Capacity notes](#capacity-notes)).

---

## Hardware

| | Minimum (lab / low-volume pilot) | Recommended (single-node production) |
|---|---|---|
| **CPU** | 2 cores | 4+ cores (transform throughput is per-core; one worker set per connection) |
| **Memory** | 4 GB | 8–16 GB |
| **Disk** | 10 GB free, any disk | **SSD**, 50+ GB or sized to your retention window, on a low-latency local volume |
| **Store volume** | — | Put the message store on a fast local disk (not a network share). Budget for **store + WAL growth**: the staged pipeline writes ~3× per message on the embedded store (see [write-amplification benchmark](benchmarks/step-b-write-amplification.md)). |

> The engine and store may share a host for a low-volume pilot. For production, run a **server
> database** (PostgreSQL or SQL Server) on its own host, sized by your DBA, and keep the engine
> host dedicated. For volume beyond one CPU core, see [Sizing by message volume](#sizing-by-message-volume).

## Operating systems

| Platform | Status |
|---|---|
| **Windows Server 2022 / 2025** | ✅ Primary supported & serviced platform (Windows-service deployment via NSSM) |
| Windows Server 2019 | ✅ Supported |
| Windows 10 / 11 | ✅ Supported (development, pilot, console host) |
| **Linux** (modern x86-64 distributions) | ✅ Engine supported (cross-platform Python); no bundled service installer — run under systemd yourself |
| macOS | ⚠️ Development / console use only |

## Runtime

| Component | Requirement |
|---|---|
| **Python** | **3.11 or later**, 64-bit (3.11, 3.12, 3.13 supported; 3.11 and 3.13 are CI-validated) |
| Service manager (Windows) | **NSSM** (auto-provisioned, SHA-256-pinned, by the installer; or pre-staged). Requires administrator / elevation to register the service. |
| C compiler | Not required for the default install (runtime dependencies ship as wheels) |

## Databases (message store)

| Database | Status | Driver / prerequisite |
|---|---|---|
| **SQLite (WAL)** | ✅ Default, bundled — single-node | None (`aiosqlite`, in-process) |
| **PostgreSQL 13+** | ✅ Production | `messagefoundry[postgres]` extra (`asyncpg`, pure-Python — no OS dependency) |
| **Microsoft SQL Server 2019 / 2022** | ✅ Production | `messagefoundry[sqlserver]` extra (`aioodbc`) **plus the OS-level Microsoft ODBC Driver 18 for SQL Server**. Read-Committed Snapshot Isolation (RCSI) recommended. |
| MySQL / Oracle | ⛔ Not supported (roadmap) | — |

> The embedded SQLite store needs no setup and suits pilots and single-node deployments. A
> **server database is greenfield-only** — there is no in-place migration from a populated SQLite
> store; drain and cut over. The DB tier owns its own backup, HA, and (SQL Server) TDE / purge
> maintenance. A server database is also the **horizontal scale path** — see below.

## Administration clients

| Client | Requirement |
|---|---|
| **Desktop console** | PySide6 (Qt) desktop application — install with the `console` extra. Runs on Windows, Linux, or macOS as a separate process; connects to the engine over the localhost HTTP/WebSocket API. **Not browser-based.** |
| **VS Code extension** | Visual Studio Code (current stable) — route wizard, validate-on-save, test bench, stage→promote. |
| Web browser | Not required to operate the engine (no web admin UI; the API is HTTP/JSON for tooling). |

## Network & ports

| Purpose | Default | Notes |
|---|---|---|
| **Engine API** (HTTP + WebSocket) | `127.0.0.1:8765` | **Loopback by default**, authentication-required. No native transport TLS — to reach the API from another host, front it with a **TLS-terminating reverse proxy** or tunnel. |
| **Inbound MLLP / TCP listeners** | operator-defined (samples use e.g. `2575`, `2600`) | Open to sending systems via firewall. Keep MLLP on a **trusted network segment** (no MLLP-over-TLS). |
| **Outbound** | as configured | Reachability to downstream partners and, for server DBs, to the database host. |
| Installer egress | HTTPS | Outbound access for the service installer to fetch the pinned NSSM binary (or pre-stage it). |

---

## Sizing by message volume

> **Engineering estimate — not a validated benchmark.** These tiers project the architecture's
> behavior; they are not committed numbers. Throughput depends heavily on **transform cost per
> message** (the dominant factor), message size, fan-out, and strict-validation use. **Measure your
> own feeds** with the load harness before committing (see [Capacity notes](#capacity-notes)).

### How throughput is bounded (read this first)

A single engine process runs **all** message work — decode → peek → route → transform → re-encode —
on **one CPU core** (one asyncio event loop; the GIL prevents pure-Python parallelism across threads).
So per-process throughput is governed, in order, by:

1. **Transform cost per message** — usually the binding constraint. The project's own
   [throughput research](THROUGHPUT-IMPROVEMENTS.md) cites a comparable vendor benchmark where real
   transformation cut pass-through throughput by ~60% (≈1000 msg/s → ≈400 msg/s). A light/pass-through
   feed sits near the top of a tier; a heavy transform sits near the bottom.
2. **Durable-write cost** — every stage handoff (ingress → routed → outbound → delivered) is a
   committed transaction. In-process **SQLite is fastest per write**; a **server DB is slower per
   single write** (network + MVCC) but is the concurrency substrate (next point).

**To exceed one core**, the current architecture scales **horizontally**: run **multiple engine
processes sharded by inbound connection**, each on its own core, all draining **one shared server
database** (PostgreSQL or SQL Server) via `SELECT ... FOR UPDATE SKIP LOCKED` with per-lane FIFO
ownership preserved across processes. Throughput then scales with worker processes until the
**database's commit capacity** is the wall. (SQLite is single-writer and does **not** scale this way —
it is the single-process / single-node store.)

### Tiers

| Tier | Peak sustained (est.) | Indicative daily volume | Deployment shape | Store | Suggested hardware (engine host) |
|---|---|---|---|---|---|
| **Pilot / light** | up to ~50 msg/s | up to ~1–4 M/day | 1 process, single node | SQLite | 2 cores / 4 GB |
| **Standard single-node** | ~50–200 msg/s | ~4–15 M/day | 1 process, single node | SQLite, or PostgreSQL / SQL Server | 4 cores / 8 GB |
| **High single-node** | ~200–500 msg/s | ~15–40 M/day | 1 process, tuned (lean transforms; finite-retry on hot lanes) | Server DB recommended (PostgreSQL / SQL Server) | 4–8 cores / 16 GB |
| **Scale-out (single box, multi-process)** | ~500 – low-thousands msg/s | ~40 M+/day | **N processes sharded by inbound**, shared store via `SKIP LOCKED` | **PostgreSQL / SQL Server** (required — not SQLite) | 8+ cores / 32 GB + a dedicated DB host sized to the commit load |

**Reading the tiers**

- *Peak sustained* is a **per-second** capacity estimate. Healthcare feeds are bursty; real **average**
  rate (and therefore daily volume) is typically a fraction of peak, so the *indicative daily volume*
  columns assume a realistic duty cycle, not `peak × 86,400`.
- The **single-process ceiling** is roughly the "High single-node" row — a few hundred msg/s with real
  transforms, approaching ~1000 msg/s only for light/pass-through work. Past that you are over one
  core's budget and must scale out.
- The **estimated maximum as currently architected** is the **scale-out** row: multiply the per-core
  rate by the number of engine processes you can run, bounded by the shared database's commit ceiling.
  There is no fixed published cap — on a well-provisioned box with a tuned server DB this lands in the
  **low thousands of msg/s**, beyond which you are **database-bound** and scale the DB tier (and, if
  needed, add nodes behind it). Group-commit and a lazy MSH-only routing peek are identified 0.2
  levers to raise the per-core ceiling ([THROUGHPUT-IMPROVEMENTS.md](THROUGHPUT-IMPROVEMENTS.md)).

> **Single-stream server-DB caveat.** Because each staged handoff is a committed round-trip, a single
> delivery worker against a *remote* server DB drains far slower than in-process SQLite (the SQL Server
> CI smoke profile observes ~30 deliveries/s for one stream). High volume on a server DB comes from
> **concurrency** — many connections / lanes / processes draining in parallel — not single-stream speed.
> Size the DB host for that concurrent commit load.

### Capacity notes

- Validate with the load harness ([LOAD-TESTING.md](LOAD-TESTING.md)): run the `smoke` →
  `fanout-baseline` → `soak` ramp, exercise the `cheap` / `edit` / `slow` transform modes to find your
  per-core transform ceiling, and compare SQLite vs a server DB on identical traffic. Treat the
  **zero-loss reconciliation** as the headline gate — throughput is meaningless if messages were lost.
- The embedded store has ~3× write amplification and a single-writer ceiling; move to PostgreSQL or
  SQL Server when that becomes the bottleneck.
- Scale **intra-node first** (one delivery worker per outbound; keep retry policies finite where
  head-of-line blocking on a shared FIFO lane would otherwise stall a lane), then **multi-process /
  scale-out** on a server DB. Engine-native multi-node HA/failover is not a v0.1 capability — provide
  HA operationally at the DB tier + a load-balancer VIP if required.
