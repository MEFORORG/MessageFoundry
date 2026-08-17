# ADR 0031 — Startup connection fault isolation (a failed connection must not crash the engine)

- **Status:** **Accepted (2026-06-21, owner go).** Built in the same change. `0031` is the next free
  ADR number (0023/0027/0029 stay reserved; 0024/0025/0026/0028/0030 are taken — see
  [README.md](README.md)).
- **Built:** yes — [`RegistryRunner.start`](../../messagefoundry/pipeline/wiring_runner.py) now
  isolates a per-connection build/bind failure instead of aborting the whole startup; the failure is
  recorded, alerted, and surfaced on `GET /connections` + `/connections/{name}/metadata` and in the
  console connections table.
- **Decision in one line:** at **engine startup**, a single Connection that fails to build/bind
  (unresolvable `env()`/cert, an egress-allowlist refusal, a port already in use, a cleartext-exposure
  refusal, a capture/backend mismatch) is **isolated** — logged loudly, recorded as `failed` with its
  reason, and alerted — and the engine **brings up the rest of the graph and serves the API**; a
  failed *outbound* still gets its delivery worker (with no connector) so rows routed to it are
  **retried, never dropped**, and a reload/restart that builds it self-heals the lane; a failed
  *inbound* simply isn't listening. **Reload stays fail-fast** (its pre-quiesce `build_check` still
  rejects broken config before touching a healthy running graph) — only *startup* degrades.
- **Related:**
  - [ADR 0001](0001-staged-pipeline-architecture.md) (the staged pipeline + supervision model whose
    "a crash in one is isolated" principle this extends to the one remaining un-isolated path —
    startup wiring) and its **reliability** / **count-and-log** invariants ([CLAUDE.md](../../CLAUDE.md)
    §2) this change is careful to preserve;
  - [ADR 0013](0013-query-response-orchestration.md) §"fail closed at start" (the capturing-outbound /
    backend check — relaxed from *crash the engine* to *degrade this lane*, while still never silently
    dropping replies);
  - [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) §0 + [ADR 0025](0025-dicom-codec-store-connectors.md)
    §9 (the MLLP/DIMSE cleartext-exposure gate — a refused listener now degrades rather than crashing,
    and **never binds insecurely**);
  - [ADR 0014](0014-alerting-rules-engine.md) + the `AlertSink` protocol
    ([pipeline/alerts.py](../../messagefoundry/pipeline/alerts.py)) — a startup failure reuses the
    existing `connection_stopped` signal (its meaning, "this connection is down until an operator
    intervenes", fits exactly), so no new sink method is added;
  - the `messagefoundry check` / dry-run gate (`build_check_registry` in
    [pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py)) — the *pre-deploy*
    place to catch broken config; this ADR is the *runtime safety net* for failures that survive to
    start time (a cert missing on the box, a port conflict, an env not set), not a license to ship
    config that `check` would reject.

## Context

Before this change, [`RegistryRunner.start`](../../messagefoundry/pipeline/wiring_runner.py) built
every Connection inside one `try` block: it constructed all outbound connectors, built the live-lookup
executor, then bound every inbound listener. **Any** single failure — one outbound whose `env()` or
client cert couldn't resolve, one inbound whose port was taken — hit the `except`, tore down the
*partial* start, and re-raised. That exception propagated up through `Engine.start()` → the ASGI
lifespan → uvicorn's "Application startup failed. Exiting." So **one misconfigured or unreachable
connection took down the API and every healthy feed with it.**

That is the opposite of the engine's own design philosophy. The whole point of the staged pipeline
(ADR 0001) and the `RegistryRunner` supervisor is fault isolation: "one listener + a router worker + a
transform worker per inbound … supervised by the `RegistryRunner` so a crash in one is isolated"
([CLAUDE.md](../../CLAUDE.md) §2); "each outbound connection drains independently (a slow/failing one
never blocks siblings)". Every *runtime* failure path is already isolated — a bad message dead-letters,
a slow transform can't block routing, a failing delivery retries without stalling siblings. The single
remaining place where one component could take down the whole engine was **startup wiring**, and a
healthcare integration hub fronting many feeds should not refuse to start its other 20 feeds because
feed #21's downstream cert is missing this morning.

The real-world trigger: a sample graph included a WS-* SOAP outbound to an immunization registry whose
mutual-TLS client cert / WS-Security credentials come from `MEFOR_VALUE_REGISTRY_*` env vars
(deliberately not in the versioned env file). On a box where those aren't set, the SOAP connector's
constructor raises while loading the cert chain — and the entire engine refused to start, taking the
ADT, X12, eligibility, and FHIR feeds with it.

## Decision

### §1 Per-connection isolation at startup

`start()` builds each Connection independently. The outbound build + the inbound bind are each wrapped
so a failure of one is caught, **recorded** (`self._failed[name] = reason`), **logged** at ERROR with
the cause, and **alerted** (`AlertSink.connection_stopped(name, detail="failed to start: …")`) — then
startup **continues**. The outer `except` that unwinds + re-raises is retained as a backstop for
genuinely fatal, *graph-wide* startup errors (the store, the lookup executor) — those are not a single
connection and should still abort.

The end-of-start log distinguishes the two outcomes: a clean start logs `wiring started: N inbound, M
outbound`, a degraded start logs a WARNING `wiring started DEGRADED: … K failed to start … <names +
reasons>`.

### §2 A failed outbound retries; it never drops

A failed *outbound* is recorded in `_failed` **and still gets its delivery worker spawned — but with
no connector in `_destinations`.** The worker's existing "no connector for a claimed row" branch then
`mark_failed`s any row routed to that lane (with the connection's retry/backoff policy) and raises the
queue-buildup alert, exactly as it already does during a brief mid-reconcile window. Consequences:

- **The reliability + count-and-log invariants hold.** A message a router/handler sends to a failed
  outbound is enqueued, retried, and surfaced (disposition + `queue_buildup` alert + a growing
  backlog) — it is **never silently dropped or accepted-and-lost** ([CLAUDE.md](../../CLAUDE.md) §2).
  The ADR 0013 promise ("never silently drop replies") is preserved: a capturing outbound on an
  unsupported backend degrades its lane (rows retry) rather than dropping anything.
- **It self-heals.** Because the worker reads its connector live per item, a later reload/restart that
  builds the connector drains the accumulated backlog with no message loss.

### §3 A failed inbound simply isn't listening

A failed *inbound* is recorded in `_failed`; it is **not** in `_sources`, so `inbound_running()` is
False and it accepts nothing. Its router + transform workers are still spawned (they are
registry-tied, not source-tied), so any **crash-recovered** ingress/routed backlog from a prior run
still drains even though the listener is down. A cleartext-exposure refusal degrades the same way and
**never results in an insecure bind** — the gate still refused; the engine just doesn't also die.

### §4 Recovery is operator-driven; reload stays fail-fast

- **Engine restart** re-runs `start()`, which now isolates per connection and builds the previously
  failed one successfully once its cause is fixed. This is the primary recovery path.
- **An inbound** can also be recovered live with `POST /connections/{name}/start` (binds it; clears the
  failure marker on success).
- **A reload** recovers a failed *outbound* in place: `reload()`'s pre-quiesce `build_check` first
  re-validates the **whole** new registry — so it still **fail-fast rejects** a reload while a
  connection is *still* broken (you cannot push broken config onto a healthy running graph) — and once
  the cause is fixed, `_reconcile_outbounds` rebuilds the failed lane's connector in place and clears
  the marker.

The asymmetry is deliberate: **startup degrades** (a restart must never be held hostage by one
connection that's broken on the box right now), but **reload is fail-fast** (an operator editing a
running production engine gets the config validated before anything is quiesced).

### §5 Surfacing

`RegistryRunner` exposes `connection_failed(name) -> str | None` and `degraded_connections() ->
dict[str, str]`. `GET /connections` reports `status: "failed"` + an `error` reason on the affected
source/destination rows, and **emits a standalone row for a degraded outbound that has no traffic edge
yet** (so a failed-at-start outbound is never invisible just because nothing has been routed to it).
`GET /connections/{name}/metadata` carries the same `error`. The console connections table renders a
`failed` status in red with the reason on hover.

## Consequences

- **The engine starts in the presence of a broken connection** and serves the API, so operators can
  see the degraded state (log WARNING + `connection_stopped` alert + `failed` rows) and fix it without
  the all-or-nothing "the whole engine is down" failure mode.
- **A degraded outbound accrues a retrying backlog** rather than dropping traffic; the existing
  buildup alerting makes that visible. This is the intended trade (retry + alert > drop, and >
  crash-everything).
- **`messagefoundry check` is unchanged and still the right gate** for config errors pre-deploy — it
  builds every connector and fails on a bad one. This ADR does not weaken that; it adds resilience for
  failures that only manifest at runtime on a specific box.
- **No new dependency, no new AlertSink method, no schema change beyond an additive optional `error`
  field** on the two connection API models. The change is additive and the byte-for-byte behavior of a
  fully-valid graph is unchanged (no `_failed` entries → identical log line, identical rows).

## Options considered

1. **Crash the engine on any connection failure (status quo).** Simple, fail-loud — but a single
   misconfigured/unreachable feed denies service to every other feed. Rejected: contradicts the
   engine's own isolation philosophy and is the wrong posture for a multi-feed clinical hub.
2. **Isolate, retry failed-outbound rows, operator-driven recovery (chosen).** Preserves the
   reliability/count-and-log invariants, reuses existing retry/backoff/alert machinery (no new code
   paths for delivery), self-heals on reload/restart.
3. **Isolate, but immediately dead-letter messages routed to a failed outbound.** Rejected: a
   transient cause (a cert momentarily absent, an env not yet exported) would dead-letter live traffic
   that a simple retry would have delivered after a fix. Retry-and-alert is the safer default.
4. **Auto-retry the *build* of a failed connection on a background timer.** More machinery and timing
   semantics for marginal benefit; the reload/restart paths already rebuild. Deferred — can be added
   later without changing this contract.

## Amendment (2026-07-17, BACKLOG #114) — opt-in File/RemoteFile startup directory validation

**Status:** Accepted (owner go, DEMAND-GATE-BACKLOG Wave 3 / S3a). Built in the same change.

**Context.** As **BACKLOG #114** records, the File/RemoteFile **source** connectors do **not** validate
their directory at construction — `FileSource._run` logs-and-retries when the poll directory is
unreachable, and `FileDestination._write` `mkdir`s on write — so a *missing* directory never fails
startup. That run-time deferral is correct for an **intermittently-available** remote directory (the
feed must still come up and heal when the mount returns), but it gives no way to say "this directory
must exist at start, refuse to start otherwise" — Corepoint's perform-vs-defer directory-validation
toggle. (The observation that "File connectors don't validate the directory at construction" is
**#114's**, not a claim made by the original ADR 0031 above — this amendment adds the opt-in, it does
not correct the base decision.)

**Decision.** Add a per-connection **`validate_directory`** setting (default **`false`** —
byte-identical to today's deferral) to the File / SFTP / FTP(S) **inbound** connectors. When `true`,
the runner runs a new `SourceConnector.validate_startup()` hook **at bind** (in
`_start_inbound_unsafe`, right before `source.start()` — **not** at `build_check`, so an
intermittently-available directory can still BUILD/promote) and a missing/unusable directory raises
`SourceStartupError`, which the existing §1/§3 isolation catch records as **`failed`** (logged, alerted,
surfaced on `/connections`). Recovery is the same operator-driven path (fix the dir → restart, or `POST
/connections/{name}/start`).

Two deliberate details:

- **No-mkdir existence check (the semantic gap).** `validate_startup` must **not** reuse
  `_probe_dir_writable` verbatim: that probe's first line is `mkdir(parents=True, exist_ok=True)`, so it
  would silently **create** a merely-missing directory and PASS — the opposite of "missing dir fails
  startup". The new `_probe_dir_startup` therefore **creates nothing**: a missing path (or a
  non-directory) raises, so the connection is honestly reported `failed`.
- **Read-only-aware (composes with #142).** A `move`/`delete` source moves processed files into its
  subdirs, so it needs **write** (a temp-file probe). A `leave`-in-place source (BACKLOG #142) never
  writes to the poll directory, so its validation requires only **read/list** — a genuinely read-only
  share validates cleanly with `validate_directory=true` rather than being wrongly reported `failed`.

**Consequences.** Additive and default-off (a graph that never sets `validate_directory` is
byte-identical). No new schema, no new dependency; the failure rides the existing `_failed`/`failed`
surfacing and the `connection_stopped` alert. Reload stays fail-fast for the rest of config; the new
check only runs at bind, so a below-threshold / not-deployed / auto-start-off connection is unaffected.
The equivalent outbound (FileDestination) is out of scope here — it already `mkdir`s on write and has
the on-demand `POST /connections/{name}/test` probe.

**Follow-on (2026-08-03, BACKLOG #114) — the outbound rejects the option rather than ignoring it.**
**Superseded by the 2026-08-10 amendment below, which builds the hook and removes this `WiringError`;
kept for the reasoning, which still holds.** Because `File()`/`Sftp()`/`Ftp()` are single factories
serving both directions, the option above could be *written* onto an outbound, where nothing read it —
accepted and silently ignored. That was made a **`WiringError` at bind** in
`build_outbound_connection`, the one choke point both the code-first `outbound()` and the
`connections.toml` loader (ADR 0007) pass through. The outbound *validation hook* itself
(`DestinationConnector.validate_startup`) was out of scope here — note that the "on-demand test probe"
workaround cited above is **inbound-only in effect**: `FileDestination.test_connection` →
`_probe_dir_writable` and `RemoteFileDestination.test_connection` → `ensure_dir` both **create** the
target directory, so on an outbound no shipped mechanism could distinguish "the directory exists" from
"I just made it."

## Amendment (2026-08-10, BACKLOG #114) — the outbound half: `DestinationConnector.validate_startup`

**Status:** Accepted (owner go — build the remainder). Built in the same change.

**Context.** The 2026-07-17 amendment deferred the outbound hook on two grounds: the destination
"already `mkdir`s on write", and it "has the on-demand `POST /connections/{name}/test` probe". The
2026-08-03 follow-on already withdrew the second (both destinations' `test_connection` **create** the
directory — re-measured against the shipped code before this amendment was written, on a missing
directory, for both FILE and REMOTEFILE). This withdraws the first: `mkdir`-on-write is not a weaker
form of validation, it is the defect. A typo'd `directory`/`remote_dir` does not fail — it is
**created**, and every message delivered into it is counted and logged as delivered, because it was.
On a first deployment that is a feed landing in a path nobody is watching with no error anywhere.
(Nothing is misdelivering today; there are zero deployments — see CLAUDE.md §0.)

**Decision.** Three parts.

1. **`DestinationConnector.validate_startup()`**, defaulting to a **no-op** — the exact shape of the
   `SourceConnector` hook above, so the other eleven destination connectors are untouched and this is
   not a protocol change that ripples. `FileDestination` and `RemoteFileDestination` override it. The
   runner awaits it in `_start_outbound` immediately after the connector is built, **inside the
   existing ADR-0031 isolation `try`**: a `DestinationStartupError` therefore takes the same path as a
   build failure — the lane is recorded `failed` with **no live connector**, its delivery worker is
   **still spawned**, and rows routed to it are retried + buildup-alerted, never dropped. On an
   outbound, "invalid means not-started" *is* that degraded-lane state, so §1's reliability and
   count-and-log invariants are preserved rather than re-argued. The same call is made on the operator
   start path (`_ensure_destination_built`, which already isolates rather than raises). It is **not**
   made on the reload path, whose stated invariant is that a connector build there cannot fail (intake
   is quiesced at that point, so a raise would strand the swap).

2. **`validate_directory` becomes a both-directions option** on `File`/`Sftp`/`Ftp`, and the
   2026-08-03 outbound `WiringError` is **removed**. That guard existed for exactly one reason — no
   destination read the setting — and that reason is now gone; keeping it would mean shipping the hook
   behind a second, differently-named knob. Default stays `false`, so every outbound authored today
   builds and runs byte-identically.

3. **A created directory is loud.** Under the default (defer) arm the target is still created on
   write and the delivery still succeeds — but a create that actually happened now logs a `WARNING`
   naming the path. This is the half that applies to every existing outbound, because it is the
   default arm: the failure mode being closed is silence, not the creation itself.

Three deliberate details, each the mirror of a source-side one:

- **No-create at every asking point.** `validate_startup` uses `_probe_dir_startup` (FILE) or a
  `list_dir` (REMOTEFILE) — never `_probe_dir_writable`/`ensure_dir`, both of which create. Under
  `validate_directory=true` `test_connection` switches to the same no-create probes, because
  otherwise the operator's own `POST /connections/{name}/test` would silently repair the typo the
  toggle exists to catch and the next restart would then validate clean.
- **No-create at delivery time too, under the toggle.** "This directory must exist" has to keep
  meaning that after start, so `_write`/`_upload` do not create it either: a share that vanished
  mid-run fails the send **retryably** and the lane backs off and self-heals. The REMOTEFILE arm
  pre-checks with a `list_dir` specifically to reclassify — an SFTP/FTP no-such-dir is a **permanent**
  error, so letting the upload fail naturally would dead-letter live traffic over a merely-unmounted
  share. It costs one extra round trip per delivery, on the opt-in path only.
- **The default arm still serves the item's own trigger.** An intermittently-available directory must
  **not** fail startup — which is why the toggle is opt-in and defaults to defer in both directions.

**Consequences.** Additive; a graph that never sets `validate_directory` on an outbound behaves as
before apart from the create-on-write WARNING. The FILE default path's syscall count is unchanged
(`mkdir(parents=True, exist_ok=True)` already probed `is_dir()` on its `FileExistsError` branch, which
is the common one). `_RemoteClient.ensure_dir` now reports whether it created — a module-private
contract with two implementations. No new schema and no new dependency; a refusal rides the existing
`_failed`/`failed` surfacing and the `connection_stopped` alert.
