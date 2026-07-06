# ADR 0027 — Per-connection retention / pruning windows

- **Status:** Proposed  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-27
- **Related:** BACKLOG #34 · [ADR 0001](0001-staged-pipeline-architecture.md) (staged queue + the
  count-and-log / at-least-once invariants this purge must preserve) · [ADR 0007](0007-gui-manageable-connections-toml.md)
  (transport-config-as-data — the per-connection keys are also hand-/GUI-editable) ·
  [ADR 0021 §7](0021-inbound-ack-nak-capture-response-sent.md) (the `connection_event` log + the **#46
  per-connection diagnostics-override plumbing this reuses**) · [ADR 0005](0005-transform-accessible-state.md)
  (transform-state purge — stays global) · [ADR 0017](0017-consumer-deployment-model.md) (org-owned config
  repo across instances) · [CLAUDE.md](../../CLAUDE.md) §1 (no grouping unit; connections may be data),
  §2 (count-and-log + reliability), §9 ([PHI.md](../PHI.md) §8 retention) ·
  [`config/settings.py`](../../messagefoundry/config/settings.py) `RetentionSettings`/`DiagnosticsSettings` ·
  [`config/wiring.py`](../../messagefoundry/config/wiring.py) `InboundConnection`/`OutboundConnection` ·
  [`pipeline/retention.py`](../../messagefoundry/pipeline/retention.py) `RetentionRunner.run_once` ·
  [`store/store.py`](../../messagefoundry/store/store.py) `purge_message_bodies`/`purge_dead_letters`

---

## Context

Data retention today is a **single, store-wide policy**. The `[retention]` service-settings section
([`config/settings.py`](../../messagefoundry/config/settings.py) `RetentionSettings`) is enforced by
**one** global [`RetentionRunner`](../../messagefoundry/pipeline/retention.py) per process. Its windows
(`messages_days`, `dead_letter_days`) drive the store purge methods — `purge_message_bodies` nulls inbound
message bodies, `purge_dead_letters` nulls dead-lettered outbound bodies — and each takes a **single
`older_than` cutoff and purges store-wide by message age only**. The inbound `InboundConnection` and
outbound `OutboundConnection` ([`config/wiring.py`](../../messagefoundry/config/wiring.py)) carry no
retention field. So every feed shares one window: an operator cannot keep ADT for 90 days while pruning a
high-volume / low-value lab feed at 7, or null bodies sooner for one chatty connection to bound its PHI
footprint feed-by-feed. Mirth, by contrast, sets **message storage + pruning per channel** — the standard
operator lever for bounding PHI footprint feed-by-feed.

The mechanism to layer a per-connection override over a global default **already exists and was just
extended** for the #46 Corepoint-style event log ([ADR 0021 §7](0021-inbound-ack-nak-capture-response-sent.md),
PR #541): `InboundConnection.capture_ack` / `capture_connection_errors` are `bool | None` where
**`None` = inherit the matching `[diagnostics]` master switch** and an explicit value overrides it for one
connection — the same shape as `OutboundConnection.retry`/`ordering`/`buildup`
(`RetryPolicy`/`OrderingMode`/`BuildupThreshold`) and the inbound FIFO binding. The `inbound()`/`outbound()`
factories thread the field through `build_inbound_connection`/`build_outbound_connection`, and the ADR 0007
`connections.toml` loader desugars the same key through those same factories. Critically,
`retention.py run_once` **already interleaves** body-purge **and** the #46 `connection_event` purge in **one
pass** (the RETENTION hook). This ADR extends that **same** pass and **reuses that same override plumbing**
rather than inventing a parallel one.

Two [CLAUDE.md](../../CLAUDE.md) invariants bound the design and **must not** be relaxed:

- **Count-and-log** (§2): "**every received message is persisted before the ACK** … nothing is
  accepted-and-dropped." A purge therefore **NULLs the PHI *body* while keeping the metadata row** (counts,
  disposition, audit intact — the Mirth Data-Pruner pattern, `purge_message_bodies`' existing contract); it
  never deletes a `messages` row.
- **Reliability / at-least-once** (§2, ADR 0001): a body still in flight is never purged
  (`purge_message_bodies` already guards `NOT EXISTS (… queue.status IN pending/inflight)`); a per-connection
  cutoff only changes *which age* is eligible, never that guard.
- **No grouping unit / connections may be data** (§1): "*Routers/Handlers (logic) stay code-first*, but a
  Connection's *transport config* … may live in an optional **`connections.toml`**." Retention is transport
  *config* for a connection, so the override rides the connection spec + `connections.toml`, **not** a
  Router/Handler API and **not** a built "channel" object.

## Decision

**Add a per-connection retention override layered over the global `[retention]` default, authored on the
inbound/outbound connection (code-first **and** `connections.toml`), and thread a per-connection cutoff into
the existing purge SQL** — reusing the #46 override pattern, not a new one.

### D1 — Override field on the connection spec (= #46 / FIFO / RetryPolicy / BuildupThreshold)

Add `messages_days: int | None` to `InboundConnection` and `dead_letter_days: int | None` to
`OutboundConnection` (and their `inbound()` / `outbound()` factories + `build_inbound_connection` /
`build_outbound_connection` cores), where **`None` = inherit the global `[retention]` window** and an
explicit value overrides it for that one connection (`0` = keep-forever, `>0` = days). Authored code-first
(`inbound(..., messages_days=90)`) **and** as a `connections.toml` key (ADR 0007 desugars through the same
factory), so it stays hand- and GUI-editable. This is the **identical** override idiom #46 just shipped for
`capture_ack`/`capture_connection_errors` — no new settings section, no new resolver.

- `messages_days` rides the **inbound** because `purge_message_bodies` is keyed by the receiving connection
  (`messages.channel_id` = inbound name). `dead_letter_days` rides the **outbound** because
  `purge_dead_letters` is keyed by the connection that dead-lettered the row (`queue.destination_name` =
  outbound name).

### D2 — Thread a per-connection cutoff through the purge SQL on all three backends

The `RetentionRunner` resolves, per pass, a **`{connection_name → older_than}` map** (per-connection override
→ global `[retention]` default → keep-forever) and passes it to the purge methods alongside the global
cutoff. `purge_message_bodies` (keyed on `messages.channel_id`) / `purge_dead_letters` (keyed on
`queue.destination_name`) gain an **optional per-connection-cutoff argument** (default empty ⇒ byte-identical
to today's single global cutoff): a connection in the map is purged at its own cutoff; any connection absent
from the map falls back to the global window. The per-connection cutoff predicate is **AND-ed** with the
existing *never-purge-an-in-flight-body* predicate (`NOT EXISTS (pending/inflight)`), so a purge can never
evict a body still being routed/transformed/delivered. This must land on **all three** store backends
(**SQLite / Postgres / SQL Server**) with a purge-SQL parity test. Lane A is the **sole store-writer** —
coordinate land-order with the pool-prewarm store refactor so the purge-SQL change rebases cleanly onto the
shared read pool.

### D3 — One audit row per pass, recording per-connection cutoffs + counts

`RetentionRunner.run_once` still emits **exactly one** `retention_purge` `audit_log` entry per pass that did
work, now recording the **per-connection cutoffs + per-connection purged counts** (connection name + days +
count — **never** message content, no PHI) alongside the existing global fields. This is the same
count-and-log discipline the global runner already follows, and the same single pass that already interleaves
the #46 `connection_event` purge.

### What this must not break

- **Count-and-log / Mirth Data-Pruner.** Still null-body-keep-metadata — never delete a `messages` row;
  counts, disposition, and the audit trail stay intact. A per-connection cutoff changes *when* a body is
  nulled, never *that the row survives*.
- **At-least-once / reliability (ADR 0001).** The `NOT EXISTS (pending/inflight)` in-flight guard is
  AND-ed in unchanged — a message mid-pipeline is never purged regardless of its connection's window.
- **No grouping unit / code-first logic.** The override is connection transport-config (spec field +
  `connections.toml`); Router/Handler *logic* is untouched. No declarative "channel" element.
- **Global-only deployments.** Every new field defaults to `None` (inherit); a config with no per-connection
  override resolves to exactly one global cutoff and the purge SQL is byte-identical to today.
- **Stays global:** `audit_days` (keep-forever — tamper-evident hash chain, ~6-yr HIPAA expectation),
  `state_max_age_days` (per-*namespace*, not per-connection — a separate follow-up),
  `connection_event_retention_hours` (#46; already its own window), and `max_db_mb` / WAL / VACUUM (they
  govern the one store *file*, not a feed).

## Acceptance Criteria

> EARS form; each linked (`→`) to its test/fixture. `messagefoundry adr-analyze` checks each `→` resolves.

- **AC-1** — WHERE an inbound connection sets `messages_days`, WHEN `run_once` purges message bodies, THE
  SYSTEM SHALL apply that connection's cutoff to rows it received (`messages.channel_id`) and the global
  `[retention].messages_days` cutoff to every connection without an override.
  → `tests/test_per_connection_retention.py::test_override_applies_per_inbound`
- **AC-2** — WHERE an outbound connection sets `dead_letter_days`, WHEN `run_once` purges dead-letters, THE
  SYSTEM SHALL key the cutoff off the **outbound** that dead-lettered each row (`queue.destination_name`).
  → `tests/test_per_connection_retention.py::test_dead_letter_override_keys_off_outbound`
- **AC-3** — WHEN no per-connection override is configured, THE SYSTEM SHALL purge exactly as the global
  store-wide policy does today (a single global cutoff; byte-identical behaviour).
  → `tests/test_per_connection_retention.py::test_global_only_unchanged`
- **AC-4** — IF a message body is still pending/inflight, THEN THE SYSTEM SHALL NOT purge it even when its
  per-connection cutoff has elapsed (the cutoff AND-s with the in-flight guard).
  → `tests/test_per_connection_retention.py::test_in_flight_body_never_purged`
- **AC-5** — WHEN a per-connection override is set to `0`, THE SYSTEM SHALL keep that connection's bodies
  forever even while the global window prunes others (per-feed opt-out).
  → `tests/test_per_connection_retention.py::test_per_connection_zero_keeps_forever`
- **AC-6** — WHEN a pass purges across connections, THE SYSTEM SHALL write **exactly one** `retention_purge`
  audit row recording the per-connection cutoffs + counts and **no message content**.
  → `tests/test_per_connection_retention.py::test_audit_records_per_connection_cutoffs`
- **AC-7** — THE SYSTEM SHALL accept `messages_days` / `dead_letter_days` from both a code-first
  `inbound()`/`outbound()` and a `connections.toml` entry, resolving to identical `InboundConnection` /
  `OutboundConnection` overrides.
  → `tests/test_connections_file.py::test_retention_override_roundtrips_toml`
- **AC-8** — THE SYSTEM SHALL apply the per-connection cutoff identically on SQLite, Postgres, and SQL
  Server (purge-SQL parity).
  → `tests/test_per_connection_retention.py::test_three_backend_parity`

## Options considered

1. **Per-connection override field on the inbound/outbound spec, reusing the #46 override plumbing —
   CHOSEN.** Adds `messages_days`/`dead_letter_days` (`None` = inherit) to the connection spec exactly as
   `capture_ack`/`retry`/`buildup` already do, threaded through the same `build_*` factories + the same ADR
   0007 `connections.toml` desugaring, and threads a `{connection → cutoff}` map into the existing purge
   methods + the existing single-pass / single-audit `run_once`. Minimal new surface; one override idiom; the
   keys are already GUI/TOML-editable. Matches BACKLOG #34's stated scope.
2. **A new `[retention.connections.<name>]` settings overlay (a parallel resolver).** Rejected: invents a
   *second* override idiom parallel to FIFO/RetryPolicy/BuildupThreshold/#46-diagnostics, splits a
   connection's config across two surfaces, and re-derives a connection→cutoff resolver the #46 work already
   provides. The override belongs *on the connection*, where every other per-connection knob lives — the
   brief's explicit "reuse #46 plumbing, don't invent a parallel one."
3. **A `retention` field on the lower-level `Source`/`Destination` model** ([config/models.py](../../messagefoundry/config/models.py)).
   Rejected: those carry transport *type + settings*; the per-connection lifecycle knobs (router binding,
   FIFO, retry, #46 diagnostics) all live on the higher-level `InboundConnection`/`OutboundConnection` spec —
   retention rides there for consistency.
4. **A second `RetentionRunner` per connection.** Rejected: retention is a leader-only WRITE singleton
   (PHI-body nulling + audit) that must run on exactly one node and write **one** audit row per pass; N
   runners multiply the audit rows, the leader-election surface, and WAL/VACUUM contention. One runner with a
   per-connection cutoff map is strictly simpler.
5. **Status quo (store-wide only).** Rejected: forces a clinically-important feed onto a noisy feed's window
   and blocks feed-by-feed PHI minimization — the explicit owner ask and the Mirth per-channel gap.

## Consequences

**Positive** — Operators get the Mirth per-channel lever: keep ADT 90 days, prune a high-volume lab feed at
7, opt one feed out entirely — bounding PHI footprint feed-by-feed. It reuses one override idiom (no new
mental model, no new settings section, no new resolver), extends the existing single pass + single audit row,
and is purely additive (every default `None` ⇒ today's behaviour).

**Negative / risks** — The purge SQL gains a per-connection branch on three backends — a small parity surface
that must stay in lock-step (covered by AC-8 + the parity test). The per-connection cutoff map is resolved
each pass from the live registry, so a reload that changes an override takes effect on the next pass (not
retroactively un-purging already-nulled bodies — the intended one-way trade-off). Per-connection counts in
the audit detail grow the row with the number of connections that purged in a pass (still metadata-only).
Mis-keying inbound (`channel_id`) vs outbound (`destination_name`) would purge the wrong rows — the AC-1/AC-2
split pins it.

**Out of scope / stays global** — `audit_days` (keep-forever; tamper-evident chain, HIPAA ~6 yr),
`state_max_age_days` (per-*namespace* follow-up, not per-connection), `connection_event_retention_hours`
(#46; already its own window), `max_db_mb` / `wal_checkpoint_seconds` / `vacuum_at` (govern the one store
file, not a feed). Deleting metadata rows (vs nulling bodies) stays **declined** — count-and-log keeps the
row forever.

## To resolve on acceptance

- [ ] **Map vs join.** Resolve the per-connection cutoff as an in-Python `{connection → older_than}` map
  passed to the purge call, **or** push a `(connection, cutoff)` temp/VALUES join into the purge SQL? (Map is
  simpler and backend-uniform for a handful of overrides; a join scales to many connections. Decide before
  the Postgres / SQL Server parity build.)
- [ ] **Land-order with the store refactor.** Confirm the purge-SQL change rebases onto the pool-prewarm /
  shared-read-pool store refactor (Lane A is sole store-writer) — coordinate the merge order so neither
  clobbers the other's `store.py` purge methods.
- [ ] **Leader/audit semantics under sharding.** Confirm the leader-only `run_once` (one owner per process
  today; NullCoordinator single-node) stays correct for per-connection cutoffs under ADR 0037 multi-process
  sharding, where inbounds are partitioned across shards but outbound/logic are shared.
- [ ] **GUI surfacing.** Confirm the `connections.toml` GUI editor (ADR 0007) renders the two new keys
  (inbound `messages_days`, outbound `dead_letter_days`) — or defer to a follow-up GUI task.
