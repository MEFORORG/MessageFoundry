# MessageFoundry — Early-Adopter Installation & Rollout Guide

This guide is for teams piloting **MessageFoundry (MEFOR)** — a code-first, Python HL7 v2.x
integration engine — and taking it from a first install to full production use. It is an
**orchestration** document: it ties the existing docs together and adds the install-to-production
**rollout plan** that nothing else covers. Where a topic has a dedicated reference, this guide
links to it rather than repeating it.

> **Read this section first.** MessageFoundry is **pre-1.0** software. It does a small set of
> things well and production-grade today (see §2), and it has clearly-bounded areas that are
> **experimental or not yet built**. Any new integration engine — this one included — *will* have
> bugs you have not hit yet. The whole point of the staged rollout in §11 is to find them where
> they are cheap (a lab, a shadow feed) instead of where they are expensive (a production cut-over).
> If you adopt MEFOR, adopt the rollout discipline with it.

---

## Table of contents

1. [What MessageFoundry is, and who should pilot it](#1-what-messagefoundry-is-and-who-should-pilot-it)
2. [Maturity & honest limitations — read before you plan](#2-maturity--honest-limitations--read-before-you-plan)
3. [Prerequisites & environment checklist](#3-prerequisites--environment-checklist)
4. [Installation](#4-installation)
5. [Minimum viable configuration](#5-minimum-viable-configuration)
6. [Security & PHI hardening before real data](#6-security--phi-hardening-before-real-data)
7. [Reliability configuration — how nothing gets lost](#7-reliability-configuration--how-nothing-gets-lost)
8. [Pre-traffic validation](#8-pre-traffic-validation)
9. [Capacity & load testing on *your* hardware](#9-capacity--load-testing-on-your-hardware)
10. [Backup, restore & disaster recovery](#10-backup-restore--disaster-recovery)
11. [Staged rollout plan with go/no-go gates](#11-staged-rollout-plan-with-gono-go-gates)
12. [Day-2 operations & monitoring](#12-day-2-operations--monitoring)
13. [Upgrade & rollback](#13-upgrade--rollback)
14. [High availability & scale-out — setting expectations](#14-high-availability--scale-out--setting-expectations)
15. [Getting help & reporting bugs](#15-getting-help--reporting-bugs)
16. [Decommissioning a pilot](#16-decommissioning-a-pilot)

---

## 1. What MessageFoundry is, and who should pilot it

MessageFoundry routes, transforms, and validates HL7 v2.x messages between **Connections**, with
routing and handling expressed as **code-first Python**. The runtime model is a graph wired by name:

- **Connection** — an endpoint that receives (inbound) or sends (outbound) messages (MLLP, TCP,
  File today; REST/SOAP/Database destinations and a Database poll source also ship — see
  [CONNECTIONS.md](CONNECTIONS.md)).
- **Router** — a Python function bound to an inbound connection that decides which Handler(s) see
  each message.
- **Handler** — a Python function that filters → transforms a message and emits `Send`s to outbound
  connections.

The engine is a **headless asyncio service** (FastAPI/uvicorn) that owns a durable message store and
supervises one worker set per connection. A separate **PySide6 console** and a **VS Code extension**
operate it over a localhost HTTP API. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full model.

**Who should pilot it now.** Teams who want a code-first, Python-native alternative to Mirth/Corepoint,
who run **a single engine node** (see §2/§14 on HA), who can keep the engine on a trusted network or
behind their own TLS proxy, and who are comfortable validating a pre-1.0 tool against their own traffic
before trusting it. If you need turnkey multi-node failover, transport TLS out of the box, or SQL Server
as a production store **today**, MEFOR is not there yet — track those items (§2) and pilot the parts
that are ready.

---

## 2. Maturity & honest limitations — read before you plan

MessageFoundry is **single-node** in production today and genuinely solid within that envelope. The
authoritative built-vs-roadmap reference is [ARCHITECTURE.md](ARCHITECTURE.md); the README "Roadmap"
section is stale (it still lists PostgreSQL / REST destinations / the DB poller as "Later" although
they now ship). Use the table below and ARCHITECTURE.md, not the README, when planning.

### Built and production-ready (single-node)

| Capability | Status |
|---|---|
| Code-first Connection/Router/Handler graph | ✅ Built |
| **SQLite (WAL)** store backend | ✅ Production-ready — the default, single-node/dev |
| **PostgreSQL** store backend (single-node) | ✅ Production-ready — full staged pipeline, at-rest encryption, retention; single-node parity with SQLite |
| Transactional staged queue (ingress→routed→outbound), at-least-once, dead-letter, replay | ✅ Built — see [ADR 0001](adr/0001-staged-pipeline-architecture.md) |
| Auth + RBAC + hash-chained audit log | ✅ Built — see [SECURITY.md](SECURITY.md) |
| At-rest body encryption (AES-256-GCM, opt-in) + key rotation | ✅ Built — see [PHI.md](PHI.md) |
| MLLP / TCP / File connectors; REST / SOAP / Database destinations; Database poll source | ✅ Built — see [CONNECTIONS.md](CONNECTIONS.md) |
| Validation & load tooling (`generate`, `check`, `dryrun`, the test harness, the load harness) | ✅ Built — see §8/§9 and [LOAD-TESTING.md](LOAD-TESTING.md) |
| Windows-service deployment via NSSM | ✅ Built — see [SERVICE.md](SERVICE.md) |

### Experimental or not yet built — **do not depend on these for a production pilot**

| Capability | Status & implication |
|---|---|
| **High availability / failover** | ❌ **No shippable HA today.** The clustering machinery (`[cluster].enabled`) is **experimental active-active** and is **Postgres-only**; the active-passive (primary/standby) model the project is targeting is **not built** at its core (listeners still run on every node). It additionally has known distributed-correctness gaps (an unwired per-row lease heartbeat and a lease-blind startup sweep). **Run one node.** See §14. |
| **SQL Server** store backend | ❌ **Experimental / preview.** The staged pipeline is not implemented, so the engine **refuses to start** the staged runner against it. It also has known unfixed concurrency bugs. **Do not put PHI on it.** |
| **`Database` connector / DB poll source** | ⚠️ Experimental — exercised only in CI. Avoid for a first production flow. |
| **Native TLS** (API and MLLP) | ❌ Not built. Off-loopback exposure is cleartext. Front the engine with your own TLS-terminating reverse proxy (API) and keep MLLP on a trusted segment. See §6. |
| **`ack_after=delivered`** (defer the ACK until downstream delivery) | ❌ Not built — requesting it is rejected at config load. Only **ACK-on-receipt** exists, so a routing/transform/delivery failure happens **after** the sender was already told `AA` and will **not** NAK back. Operators rely on the message disposition + alerts, not the ACK. |
| **De-identification framework** | ❌ Not built. The AI assistant's `deidentified` scope falls back to `code_only`. |
| **In-place SQLite → server-DB migration** | ❌ Not built. Server-DB deployments are **greenfield only** — there is no automatic carry-over of SQLite history. Drain and cut over deliberately (§13). |
| Published throughput / tuning baseline | ❌ Not yet published. The load *tooling* ships ([LOAD-TESTING.md](LOAD-TESTING.md)), but committed per-node throughput numbers do not. **Measure on your own hardware** (§9). |

**The early-adopter bargain, stated plainly:** you get a robust single-node engine with strong
durability and a real validation toolchain, in exchange for providing HA/transport-TLS operationally
(at the DB tier and with a TLS proxy), running a single processing node, and validating capacity
yourself. If that trade is acceptable, the rest of this guide is your playbook.

---

## 3. Prerequisites & environment checklist

Consolidate these before you install anything:

- [ ] **Python 3.11+** on the engine host.
- [ ] **OS:** Windows is the primary supported/serviced platform (NSSM); the engine itself is
      cross-platform Python.
- [ ] **Administrator/elevation** on the host if you will install the Windows service.
- [ ] **Outbound network access** for the service installer to download the SHA-256-pinned NSSM
      binary (or pre-stage NSSM on the host / on `PATH`).
- [ ] **Firewall plan:** open your inbound MLLP listener port(s) (the samples use e.g. `2575`/`2600`)
      to senders, and decide who may reach the **API on `127.0.0.1:8765`** (default loopback —
      keep it that way; see §6).
- [ ] **A writable data directory** for the store + logs (service default: `C:\ProgramData\MessageFoundry`).
- [ ] **Backend decision (made here, not later):** **SQLite** (default, zero extra deps) for a
      single-node pilot, or **PostgreSQL** (`messagefoundry[postgres]`) if you want a server DB or a
      path toward DB-tier HA. **Avoid SQL Server** (experimental). See §2.
- [ ] If you will *ever* experiment with the (experimental) cluster path: **NTP time sync** across
      nodes is a hard prerequisite — its no-row-theft guarantee is wall-clock based. (Most adopters
      should skip this entirely; see §14.)
- [ ] A **PHI encryption key** plan (§6) and a **backup target + key-escrow** plan (§10) decided
      before any real data flows.

---

## 4. Installation

Full reference: **[SERVICE.md](SERVICE.md)**. The essentials:

### 4.1 Create a venv and install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .                 # core runtime only — this is what a headless engine needs
```

For a **reproducible pinned** deploy:

```powershell
pip install --require-hashes -r requirements.lock
pip install -e . --no-deps
```

> ⚠️ **`requirements.lock` is exported with `--all-extras`** — it pulls *every* optional dependency
> (PySide6, asyncpg, aioodbc, paramiko, dev tools) onto the host, not just the runtime deps. A plain
> `pip install -e .` is the minimal headless install. If you want pinned **and** minimal, regenerate a
> lock scoped to only the extras you run.

### 4.2 Optional extras

| Extra | Pulls in | When |
|---|---|---|
| `postgres` | `asyncpg` (pure-Python, no OS dep) | Using the PostgreSQL backend (recommended prod path) |
| `console` | PySide6 + keyring | Running the desktop admin console |
| `sftp` | paramiko | SFTP connectors |
| `sqlserver` | `aioodbc` **+ OS-level Microsoft ODBC Driver 18** | ⚠️ Experimental backend only — not for production |
| `dev` | pytest/ruff/mypy/httpx | Development & CI |

> ⚠️ There is **no friendly preflight** for the `postgres` extra: if you set `backend=postgres` but
> forgot `pip install 'messagefoundry[postgres]'`, you get a raw `ImportError` at startup instead of a
> clear message. Install the extra with the backend.

### 4.3 Run it (foreground, to learn the ropes)

```powershell
python -m messagefoundry serve --config samples/config --db ./messagefoundry.db --env dev
```

`serve` flags and their precedence (**CLI > `MEFOR_<SECTION>_<KEY>` env > `messagefoundry.toml` >
built-in default**): `--config` (default `samples/config`), `--service-config` (default
`./messagefoundry.toml` if present), `--db`, `--host`, `--port`, `--log-level`, `--env`
(`dev`/`staging`/`prod`), `--allow-insecure-bind`.

> ⚠️ **The active environment defaults to `prod`.** A quickstart that omits `--env` silently selects
> PROD `env()` values and the prod PHI posture. **Always pass `--env` explicitly** (or set
> `[ai].environment`). The active environment is logged at startup so you can confirm it.

### 4.4 Run it as a Windows service (the supported production run-mode)

Use the elevated installer; install under a **least-privilege virtual account** rather than the
default LocalSystem:

```powershell
# from an elevated shell
scripts\service\install-service.ps1 -ServiceAccount "NT SERVICE\MessageFoundry"
```

The installer is idempotent, auto-downloads a SHA-256-pinned NSSM, bakes absolute `serve` paths into
the service, and (with `-ServiceAccount`) auto-grants config-read + data-dir-read/write to the
account. Service defaults: name `MessageFoundry`, data dir `C:\ProgramData\MessageFoundry`, store
`<DataDir>\messagefoundry.db`, logs `<DataDir>\logs`, bind `127.0.0.1:8765`.

> ⚠️ **Editable-install operational model.** Because the documented install is `pip install -e .`,
> the running service loads **whatever branch is checked out** at process start. Picking up new code
> is just an NSSM restart — but a stray feature branch left checked out will be served on the next
> restart. Treat the deployed checkout as part of your release artifact (§13).

### 4.5 First-run admin bootstrap

Auth is **enabled by default**. On the first start against an empty store, MEFOR creates a one-time
bootstrap admin (`admin`) and writes its password to an **owner-only `bootstrap-admin.txt`** next to
the store (only the file *location* is logged — never the password). Then:

1. Log in as `admin`; you are **forced to change the password** on first use.
2. **Create a second real administrator** promptly.
3. **Delete `bootstrap-admin.txt`.**

The bootstrap account auto-retires once a second admin exists, or — while still unclaimed — 72h after
creation.

### 4.6 Verify it runs

```powershell
curl http://127.0.0.1:8765/health           # -> {"status":"ok"}
python samples/send_mllp.py samples/messages/adt_a01.hl7
# tail <DataDir>\logs\service.out.log for the "wiring started" banner
```

If start fails, check `service.err.log` first — the common causes are relative paths resolving to the
system dir under a service account, a busy MLLP/API port, or a data dir the account can't write.

---

## 5. Minimum viable configuration

Full reference: **[CONFIGURATION.md](CONFIGURATION.md)** (service settings) and
**[CONNECTIONS.md](CONNECTIONS.md)** (the graph).

There are two distinct configuration surfaces:

1. **The message graph (code-first Python)** in your `--config` directory. The minimum first flow is
   one module: an `inbound()` with a transport spec and a `router=` binding, a `@router` that returns
   handler name(s), and a `@handler` that returns `Send(...)` to a declared `outbound()`. Start by
   copying `samples/config/IB_ACME_ADT.py`. The loader globs `*.py` (non-recursive; skips `_*`-prefixed
   helper files), then merges an optional `connections.toml`.
2. **Service/operational settings** in `messagefoundry.toml` (+ `MEFOR_*` env + CLI). Keep **all
   secrets out of this file and out of source control** — supply them via `MEFOR_<SECTION>_<KEY>` env
   vars (the loader *warns* if it sees a known secret in the file).

Guidance for a clean first flow:

- **Use the MLLP/File pair** for an initial end-to-end test — both are fully built and need no extras.
  Avoid experimental connectors for a first production flow.
- **Never set a host on an inbound MLLP/TCP connection** (it is a config error). Set the listen
  interface once, service-side, via `[inbound].bind_host` (loopback for dev; a specific NIC behind a
  firewall for prod). Outbound MLLP/TCP *do* take the downstream host.
- **Author anything environment-specific as `env("key")`**, put non-secret values in
  `environments/dev.toml` / `environments/prod.toml` with identical keys, and inject secrets only via
  `MEFOR_VALUE_<KEY>`. A referenced-but-undefined key fails loud at load. Use `current_environment()`
  (not `env()`) inside a handler to branch on the deployment.
- **`connections.toml` (data) is optional** ([ADR 0007](adr/0007-gui-manageable-connections-toml.md)):
  move *transport config* there if you want hand/GUI editing; keep *logic* (routers/handlers) in `.py`.
  A name declared in both a module and `connections.toml` is a hard error (no silent shadowing).
- **The `--config` directory is a trust boundary.** `serve` and `POST /config/reload` **execute** the
  Python in it, in-process, as the service account. On POSIX the loader refuses a group/world-writable
  config dir; **on Windows this is your responsibility** — lock the directory's ACL to admins + the
  service account.

---

## 6. Security & PHI hardening before real data

Full references: **[SECURITY.md](SECURITY.md)** and **[PHI.md](PHI.md)**. MEFOR ships real auth,
RBAC, audit, and opt-in at-rest encryption; the decisive gap is **transport security**. Complete this
checklist **before any real PHI flows**:

- [ ] **Keep the API on `127.0.0.1`** (the default). There is **no native TLS**. To reach it from
      another host, front the loopback-bound engine with a **TLS-terminating reverse proxy** or an
      SSH/VPN tunnel. **Never use `--allow-insecure-bind` for real PHI** — it puts bearer tokens and
      PHI on the wire in cleartext. (With auth disabled, a non-loopback bind is refused unconditionally.)
- [ ] **Keep MLLP on a trusted network segment** — there is no MLLP-over-TLS yet.
- [ ] **Turn on at-rest encryption and make it mandatory:** mint a key with `messagefoundry gen-key`
      (or a Windows DPAPI-protected key file via `messagefoundry protect-key`), set
      `MEFOR_STORE_ENCRYPTION_KEY`, **and** set `[store].require_encryption = true` so the engine
      refuses to start unencrypted.
- [ ] **Enable volume encryption (BitLocker/LUKS).** App-level encryption protects message *bodies*;
      the `summary` / `control_id` / `message_type` columns and the `-wal`/`-shm`/temp files are **not**
      app-encrypted and rely on volume encryption.
- [ ] **Run under a least-privilege account** (the virtual account from §4.4) and lock down the store
      directory and any File-connector spill directories. **Treat backups as PHI.**
- [ ] **Finish the bootstrap-admin handoff** (§4.5): change the password, create a second admin,
      delete `bootstrap-admin.txt`.
- [ ] **For Active Directory:** use **LDAPS** with a trusted CA, never set `MEFOR_ALLOW_INSECURE_TLS`
      in production, and configure the directory's lockout/complexity policy (the engine's account
      lockout covers local accounts only). Note: MFA is not built.
- [ ] **Populate the fail-closed `[egress]` allowlist** (it defaults to unrestricted) for REST/Database
      destinations.
- [ ] **Keep logging at `INFO` or above** and `expose_docs` off in production. Full payloads are never
      logged at INFO+ by design, but PHI-log-redaction of chained-exception traceback text is not yet
      fully closed — **do not raise the service to DEBUG with real PHI**.
- [ ] **Author routers/handlers so they never interpolate raw HL7 into an exception message** (it can
      surface in `last_error`/`detail`).
- [ ] Run **`messagefoundry audit-verify`** periodically (the audit log is tamper-*evident*, not
      tamper-*proof*), and set `[retention]` windows — they are **off by default (kept forever)**.

---

## 7. Reliability configuration — how nothing gets lost

This is the heart of operating a new tool safely. The durability model is a **transactional staged
queue** (no external broker): each message flows ingress → routed → outbound, with every handoff a
single committed transaction, giving **at-least-once** delivery with crash-safe re-runs. Details in
[ADR 0001](adr/0001-staged-pipeline-architecture.md).

Key semantics to internalize:

- **ACK-on-receipt.** The sender is `AA`'d as soon as the raw message is durably committed (after
  synchronous decode/parse/optional strict-validate, which still NAK). **Any routing/transform/delivery
  failure happens *after* the ACK** and surfaces as an internal **disposition + alert**, never a NAK.
  Operators monitor disposition + alerts, **not** the ACK, for post-ingress failures.
- **Disposition lifecycle:** `RECEIVED` → `ROUTED`/`UNROUTED` → `PROCESSED`/`FILTERED`/`ERROR`. The
  store finalizer is the **sole authority** and never finalizes while any stage row is still in flight.
  Note: a single dead row at *any* stage flips the whole message to `ERROR` **even if a sibling handler
  delivered** — so read the **per-message event trail**, not just the headline status.
- **Failure classification & policy (per outbound):**
  - Permanent partner reject (`AR`/`CR`) → **dead-letter immediately** (still replayable).
  - Transient (`AE`/`CE`) or transport error → **retry per `RetryPolicy`**.
  - Internal/code error → either **STOP** the lane and raise a `connection_stopped` alert, or
    **CONTINUE** (auto-dead-letter the bad message and keep flowing).
  - **`RetryPolicy.max_attempts` unset = retry forever** (nothing silently lost) with exponential
    backoff. Under the default **FIFO** ordering, a permanently-failing head **blocks its lane** until
    it succeeds or is purged.

**Mandatory before go-live:**

- [ ] **Wire real alerts.** Configure the `[alerts]` **webhook and/or email** notifier — do **not**
      rely on the default logging-only sink. The conservative defaults (FIFO head-of-line blocking,
      retry-forever, STOP-on-internal-error) are only safe if a human gets paged when a lane stalls.
- [ ] **Set `[delivery]` buildup thresholds** (`max_oldest_seconds` defaults to 300s; set a `max_depth`
      sized to each connection's throughput) so `queue_buildup` fires before a stuck lane silently
      backs up. Buildup detection now covers the ingress and routed stages too, not just outbound.
- [ ] **Choose `RetryPolicy` per outbound deliberately:** retry-forever for partners that must never
      lose a message (accept head-of-line blocking + rely on buildup alerts), or a finite `max_attempts`
      where stale data is worse than a replayable dead-letter.
- [ ] **Choose `InternalErrorPolicy` intentionally:** `CONTINUE` (default) for high-volume feeds where
      uptime matters most; `STOP` for low-volume feeds where ordering/no-loss matters more than uptime.
- [ ] **Code routers/handlers as pure and idempotent.** At-least-once means a message can re-run after
      a crash or a replay. No side-effecting writes mid-transform; the **one** allowed exception is a
      **live, read-only DB lookup**. Downstream connectors/partners must **dedupe** (e.g. on MSH control id).

Recovery tools you should know cold: **`/dead-letters`** (triage) + **`/dead-letters/replay`** (bulk
*outbound* recovery), and per-message **`/messages/{id}/replay`** (for dead ingress/routed rows —
router/transform errors, undecryptable raw, a removed handler). Startup automatically returns stale
in-flight rows to pending (crash recovery) and dead-letters rows whose destination/handler left the
config.

---

## 8. Pre-traffic validation

Prove correctness **before** any network traffic. None of this should ever run against real PHI —
`generate`/`dryrun` can emit full message bodies; never redirect their output to a committed file or
CI log.

1. **Build a synthetic corpus:** `messagefoundry generate --type ADT --count 50 --out <fixtures>`
   (conformant HL7 v2.5.1, validated against hl7apy; 13 message types, 57 ADT triggers; PHI-free).
2. **Gate the config in CI / a pre-commit hook:**
   `messagefoundry check --config <dir> --messages <fixtures>`.
   - `validate` (every module loads; every inbound→router reference resolves; no port collisions) is
     **required and blocking**.
   - `dryrun` is **required only when you supply a fixtures dir containing `*.hl7`** — **without
     fixtures the dryrun is silently skipped** and the gate passes on `validate` alone, so a
     transform that errors at runtime is *not* caught. **Build and maintain the fixtures.**
   - `ruff`/`mypy` are advisory (never block).
3. **Inspect the wiring:** `messagefoundry validate --json` (all problems at once) and
   `messagefoundry graph --config <dir>` (confirm the wired graph matches intent).
4. **Confirm dispositions:** `messagefoundry dryrun` runs the same core the live engine runs (no I/O),
   so dry-run and live route identically. Then exercise the **test harness** (`harness/`): its 5
   headless `--scenario` runs (`processed`/`filtered`/`unrouted`/`error`/`dead_letter`) assert
   dispositions over the API for CI, and its GUI can inject delivery faults (delay-then-AA, close,
   fail-N-then-AA) to prove your **retry / dead-letter / replay** behavior before you trust it.

Note: `validate` only catches **literal** port collisions; `env()`-resolved ports are checked at bind
time. A `prod`-only missing `env()` value may not surface during a `dev`-context check — validate
against the target environment before promoting.

---

## 9. Capacity & load testing on *your* hardware

Full reference: **[LOAD-TESTING.md](LOAD-TESTING.md)**. There is **no published throughput baseline
yet**, so the SLO numbers in the built-in profiles are **synthetic targets on unspecified hardware,
not validated absolute numbers**. Establish your own baseline.

The headless load harness (`harness/load/`) drives an already-running engine over real MLLP and the
HTTP API (it never touches the store), so it is **store-agnostic** — swap the engine's `--db` to
compare SQLite vs Postgres ceilings on identical traffic.

Recommended ramp:

1. **`smoke`** — tiny zero-loss wiring check (no performance claim).
2. **`fanout-baseline`** — warmup → ramp → sustained → spike → recovery; SLOs are evaluated only on the
   measured sustained phases. Reference targets in the profile: ≥200 msg/s sustained, ACK p99 ≤50ms,
   e2e p99 ≤5s, error ≤0.001, drain ≤60s, zero-loss.
3. **`soak`** — ~1-hour steady state watching DB/WAL growth + dead-letter accumulation.

Treat the **zero-loss reconciliation** (`sent == engine_read`, `sink_received == engine_written`,
backlog drained to zero) as the **headline gate** — throughput numbers are meaningless if messages
were lost. Use a **closed-loop** phase (fixed concurrency) to find your true max sustainable
throughput, and the `slow` transform mode to find your per-core transform ceiling. Save the JSON/CSV
reports and use `--baseline` + `--tolerance` to catch regressions over time. Size `correlator_capacity`
above your peak in-flight (watch for correlation-miss notes), and remember a single Python sender
process is the offer ceiling — shard it across processes if it can't saturate your engine.

**Sizing reality:** the staged pipeline has ~**3× write-amplification** on SQLite (3 commits for a
common single-handler message; 2 + H for an H-way fan-out) — see
[the write-amplification benchmark](benchmarks/step-b-write-amplification.md). Plan disk headroom for
`.db` + `-wal`, plan retention/VACUUM (§10), and move to **Postgres** if a single-writer SQLite ceiling
becomes the bottleneck.

---

## 10. Backup, restore & disaster recovery

> **No existing repo doc covers this** — it is part of *your* operational responsibility. Rehearse a
> full restore before you carry real data.

**Back up the store.**

- **SQLite:** the WAL backend means three files must be captured **consistently** — `.db`, `.db-wal`,
  `.db-shm`. Use `sqlite3 <db> ".backup '<dest>'"` against the live DB, or take a **quiesced cold copy**
  (graceful stop → copy → restart). A naive copy of just the `.db` while the service runs can be
  inconsistent.
- **PostgreSQL:** use your standard DB backups — `pg_dump` for logical backups and/or WAL archiving /
  PITR for point-in-time recovery. The engine is greenfield-only on server DBs, so the DB tier owns
  store-level DR here.

**Escrow the encryption key SEPARATELY.** If you enabled at-rest encryption (§6), a restored store is
**unreadable without the same `MEFOR_STORE_ENCRYPTION_KEY` / DPAPI key file**. Back the key up in a
different location/system from the data, with its own access control.

**Restore-and-verify drill (do this in the lab, §11 Stage 0):** restore the store + key into a clean
host, start the engine, confirm `/health`, run `/status/integrity-check` (SQLite `PRAGMA quick_check`),
and spot-check `/messages` and dispositions.

**Keep the store bounded.** `[retention]` is **off by default (kept forever)**. Set `max_db_mb` (drives
a `storage_threshold` alert), `messages_days` / `dead_letter_days` (body purge), and the daily VACUUM
so the store doesn't grow unbounded and a full disk doesn't take you down mid-pilot.

---

## 11. Staged rollout plan with go/no-go gates

This is the recommended path from first install to full production. **Do not skip stages** — each one
exists to catch a different class of problem cheaply. Advance only when the stage's **exit criteria**
are met.

### Stage 0 — Lab / standalone

**Goal:** prove wiring, dispositions, and recovery on a throwaway box, with **synthetic data only**.

**Setup:** SQLite, loopback, auth on, a synthetic corpus from `messagefoundry generate`.

**Exit criteria (→ Stage 1):**
- [ ] `messagefoundry check --config <dir> --messages <fixtures>` exits 0 (validate **and** dryrun green).
- [ ] All 5 disposition `--scenario` runs pass (`processed`/`filtered`/`unrouted`/`error`/`dead_letter`).
- [ ] You have driven a retry → dead-letter → **replay** cycle via the harness fault injection and
      understand the recovery tools (§7).
- [ ] A **backup + restore** has been rehearsed once (§10).

### Stage 1 — Shadow / parallel run

**Goal:** run MEFOR alongside your **incumbent** engine on **real production traffic** without
affecting any downstream system.

**How:** tee/duplicate the production **inbound** feed to a MEFOR instance whose outbounds point at a
**throwaway/null sink** (the harness correlation sink works well), or use a router that `Send`s only to
a dedicated "shadow" outbound. Compare MEFOR's dispositions and transformed output against the
incumbent's outcomes for the same messages.

> ⚠️ **Do not dual-*write* to real partners in shadow.** At-least-once + non-idempotent downstreams
> make a true dual-write dangerous. Keep shadow outbounds pointed at a sink unless the partner dedupes.

**Exit criteria (→ Stage 2):**
- [ ] **Zero-loss reconciliation holds** over a sustained window (e.g. 1–2 weeks) at production volume.
- [ ] MEFOR dispositions/output **match the incumbent's** for the same messages (differences explained).
- [ ] **No unexplained dead-letters**; every `ERROR` understood.
- [ ] A load test on **production-like hardware** meets your own SLO targets (§9).

### Stage 2 — Limited production

**Goal:** MEFOR becomes the system of record for a **small, low-risk subset** of real feeds (one
partner / one low-volume interface).

**Prereqs:** switch to **Postgres (single-node)** if you need a server DB; **encryption on**
(`require_encryption=true`); **alerts wired** and **monitoring in place** (§12); **backups automated**;
**upgrade + rollback runbook validated on staging** (§13).

**Exit criteria (→ Stage 3):**
- [ ] e2e p99 within your SLO; **zero unexplained dead-letters** over the observation window.
- [ ] **Alert wiring proven by a deliberate fault-injection drill** — you triggered `queue_buildup` /
      `connection_stopped` and the on-call was actually paged.
- [ ] **Backup + restore rehearsed against the production store** (not just the lab copy).
- [ ] Rollback runbook exercised at least once.

### Stage 3 — Full production

**Goal:** migrate the remaining feeds **in waves** (never big-bang). Keep decommissioning the incumbent
as a **separate, later** step so you retain a fallback.

**Steady-state expectations:**
- [ ] Sustained-load SLO met on production hardware.
- [ ] DR (backup/restore) rehearsed and scheduled.
- [ ] On-call + the failure-drill runbook (§12) in place.
- [ ] HA provided operationally at the DB tier / via a VIP if you require it (§14) — the engine does
      not provide failover.

---

## 12. Day-2 operations & monitoring

**Verify-it-runs (after every start/restart):** `GET /health` → `{"status":"ok"}`, send a synthetic
message, and confirm the **"wiring started"** banner in `service.out.log`.

**Monitoring surfaces (poll the API + parse logs — there is no Prometheus exporter):**
- `/stats` — outbox counts by status.
- `/status` — DB size vs disk free, journal mode, counts. **Scrape db-size-vs-disk-free.**
- `/status/integrity-check` — on-demand store integrity.
- `/ws/stats` — ~1 Hz queue-depth WebSocket.
- `/messages` + `/messages/{id}` — per-message detail and the **event trail** (read this, not just the
  status — see §7).
- `/dead-letters` — **page on dead-letter accumulation.**
- **AlertSink events** to alert on: `connection_stopped`, `queue_buildup`, `storage_threshold` (wire
  these to webhook/email — §7).
- **`service.err.log`** — watch it.

> Note: the desktop console polls the API on its main thread, so it can freeze on a slow/remote call,
> and it has no Dead-Letters/Alerts GUI page yet. Use the **CLI/API** for dead-letter triage and alert
> management.

**Log management:** logs land under `<DataDir>\logs` via NSSM. Configure rotation, keep the level at
`INFO` or above (DEBUG can leak PHI — §6), treat `service.out/err.log` as **potential-PHI artifacts**
(ACL them; don't ship them off-box — off-box logging is deferred), and include them in your retention
policy.

**Graceful drain for maintenance:** stopping the service (Ctrl+C / NSSM stop) triggers the ASGI
lifespan to call `engine.stop()` for a clean drain. Always **drain → stop → back up → change → restart
→ verify**.

**Failure-drill runbook — rehearse these in the lab/staging before prod:**

| Symptom | First moves |
|---|---|
| **Stuck FIFO lane** (retry-forever head) | `queue_buildup` alert → inspect `/messages` for the head → fix-and-`replay`, or `dead_letter_now` to unblock the lane (the dead row stays replayable). |
| **Poison message** | It dead-letters under `CONTINUE` (or stops the lane under `STOP`) → triage via `/dead-letters` → fix the transform → replay. |
| **Full disk / `storage_threshold`** | Free space / tighten `[retention]` / VACUUM → confirm `/status` disk-free recovers. |
| **Crash / unexpected restart** | Startup auto-recovers in-flight rows → verify `/health`, the "wiring started" banner, and that backlog drains. |
| **Planned maintenance** | Drain-and-stop (graceful), perform the change, restart, verify. |

---

## 13. Upgrade & rollback

**Safe upgrade runbook (editable-install model):**
1. **Drain** inbound (quiesce senders or stop accepting new work) and confirm queues are draining.
2. **Stop** the service (graceful).
3. **Back up** the store **and** the encryption key (§10).
4. **Update code:** pull the target commit/tag and `pip install -e .` (or re-pin via
   `requirements.lock`). Treat the deployed checkout as a release artifact — don't leave a stray branch
   checked out (§4.4).
5. **Re-validate:** run `ruff`/`mypy`/`pytest` and `messagefoundry check` against your config.
6. **Restart** and **verify** (`/health`, "wiring started" banner, `/status`).

**Rollback:**
- **Config rollback** is the cheapest lever: the audited `POST /config/reload` does a quiesce-and-swap
  to a known-good `--config` directory (confined to the allow-listed reload roots). Keep your last
  known-good config dir available.
- **Code rollback:** `git checkout` the prior commit/tag → reinstall → restart (same runbook above).
- ⚠️ **Schema/store-level changes are not trivially reversible** against a populated store given the
  greenfield-only posture (no in-place migration). Plan code/config rollback as your primary path;
  use **dead-letter replay** to recover messages that a bad transform stranded before the rollback.

**Pre-1.0 cadence:** only the latest `main` is supported. Verify behavior against current `main` before
filing issues, and keep upgrades small and frequent rather than large and rare.

---

## 14. High availability & scale-out — setting expectations

**There is no shippable engine-level failover today.** Plan HA **operationally** and treat
engine-native failover as a future capability:

- **Provide HA at the DB tier** (PostgreSQL replication / managed-Postgres HA) and front the engine
  with a **floating VIP / load-balancer health check** if you need a standby to take over. Design this
  now if HA is a requirement; the engine does not orchestrate it.
- **Run a single processing node.** The durable staged queue (§7) — not clustering — is what gives you
  reliability on one node.

**If you are tempted to enable the experimental `[cluster]` path anyway — don't, for production.** It
is:
- **Experimental active-active**, **Postgres-only** (SQLite and SQL Server are rejected when
  `[cluster].enabled`), and requires `[store].pool_size` **≥ 2 (enforced)**, **≥ 3 recommended**
  (the leader holds one dedicated connection).
- Carrying known **distributed-correctness gaps** (an unwired per-row lease heartbeat → possible
  duplicate processing of slow work; a lease-blind startup sweep → a restart can dead-letter another
  node's in-flight rows).
- Operationally demanding even where it works: **NTP-synced clocks**, **byte-identical config across
  nodes**, and **coordinated (non-rolling) restarts** for any config change.

For throughput on a single node, scale **intra-node**: one independent delivery worker per outbound
connection (a slow/failing lane never blocks siblings), and keep retry policies finite where head-of-line
blocking on a shared FIFO lane would otherwise stall throughput.

---

## 15. Getting help & reporting bugs

- **Bugs & feature requests:** open a GitHub issue using the repository's issue templates
  (`bug_report.md` / `feature_request.md`).
- **Security vulnerabilities:** use the repository's **private security advisory** process per
  `.github/SECURITY.md` — do **not** open a public issue for a vulnerability.
- **Before filing:** verify against current `main` (pre-1.0, latest-main-only support), and include the
  engine version, config shape, and relevant **non-PHI** log excerpts.
- 🔒 **Never attach real PHI** to an issue, log excerpt, or reproduction. Reproduce with a synthetic
  corpus from `messagefoundry generate`.

---

## 16. Decommissioning a pilot

Ending a pilot is a **PHI-disposal** event. `uninstall-service.ps1` removes the service but
**deliberately leaves the store and logs on disk**. To tear down cleanly:

1. **Graceful drain + stop**, confirm no in-flight work remains.
2. **Uninstall the service** (`scripts\service\uninstall-service.ps1`).
3. **Securely dispose of all PHI-bearing artifacts:** the store (`.db` + `-wal` + `-shm`), any
   PostgreSQL database/backups, **File-connector spill directories**, the `logs` directory, every
   **backup copy**, and the **encryption key / DPAPI key file**.
4. **Revoke credentials** (service account, AD bind account, any API tokens).

Treat backups and the encryption key with the same disposal rigor as the live store — a forgotten
encrypted backup plus its escrowed key is still recoverable PHI.

---

## Appendix — where each topic is documented

| Topic | Reference |
|---|---|
| Install + Windows service | [SERVICE.md](SERVICE.md) |
| Service settings / environments | [CONFIGURATION.md](CONFIGURATION.md) |
| Connections / the graph / `connections.toml` | [CONNECTIONS.md](CONNECTIONS.md), [ADR 0007](adr/0007-gui-manageable-connections-toml.md) |
| Reliability / staged pipeline | [ADR 0001](adr/0001-staged-pipeline-architecture.md) |
| Security / auth / RBAC / audit | [SECURITY.md](SECURITY.md) |
| PHI handling / encryption | [PHI.md](PHI.md) |
| HL7 validation | [HL7-VALIDATION.md](HL7-VALIDATION.md) |
| Load testing | [LOAD-TESTING.md](LOAD-TESTING.md) |
| Write-amplification / sizing | [step-b-write-amplification.md](benchmarks/step-b-write-amplification.md) |
| Built-vs-roadmap (authoritative) | [ARCHITECTURE.md](ARCHITECTURE.md) |
