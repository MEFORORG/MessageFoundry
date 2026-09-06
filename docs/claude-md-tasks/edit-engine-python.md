# mefor-edit-engine-python

> Split out of [CLAUDE.md](../../CLAUDE.md) on 2026-09-05. Prohibitions that bind
> before this task starts stay in that file, which loads automatically. Read it first.


**Reliability invariant (do not break):** the transactional **staged queue on SQLite (WAL)** gives
at-least-once delivery, retries, replay, and dead-lettering *without* a separate broker. The inbound
connection is ACKed **only after** the raw message is durably committed to the **ingress** stage
(**ACK-on-receipt**; a per-connection `ack_after=delivered` to defer the ACK until delivery is
planned, not built). Every subsequent stage **handoff** (ingress→routed, routed→outbound) is a
**single committed transaction** (claim → produce-next-stage rows → complete-this-stage), so a message
is never lost or partially handed off: a crash before commit rolls the stage back and it re-runs; each
handoff is idempotent against a re-run (the consumed row is gone, so a re-run is a no-op).
`reset_stale_inflight` recovers in-flight rows of **every** stage on startup. Each outbound connection
drains independently (a slow/failing one never blocks siblings); routing and transform are themselves
queued stages, so a slow/hung router or transform can no longer stall intake — or each other. At-
least-once now relies on a re-run re-deriving identical output, so **routers and transforms must be
pure** (message in → message out, no external side effects); outbound connections must still be
**idempotent**. *Carve-out (ADRs 0010/0043):* a Handler may make a **live, read-only** lookup — a
database read via `db_lookup(connection, statement, params)` (gated by `[egress].allowed_db`) or a FHIR
read/search via `fhir_lookup(connection, query)` (ADR 0043; gated by `[egress].allowed_http`, reusing the
SMART bearer, GET-only) — the result may differ on a re-run, **accepted by design** (it reflects the source
at that pass). These are the sanctioned non-pure inputs: read-only, run **off the event loop**, and
unavailable on a Router or in dry-run (they raise).

**Count-and-log invariant (do not break):** **every received message is persisted before the ACK**
(status `RECEIVED` at the ingress stage), so inbound counts still reflect the true received volume and
nothing is accepted-and-dropped. The ACK now means **receipt-and-persistence, not a final
disposition**. Disposition is **recorded as the message flows**, and the store **finalizer is its
single authority** (it alone sees every stage's rows, so a delivered handler can't finalize a message
while a sibling handler's routed row is still in flight): `RECEIVED` at ingress → after the router
routes it, `ROUTED` (≥1 handler) or `UNROUTED` (no handler matched) → once every handler's transform +
delivery resolves, `PROCESSED` (all delivered), `FILTERED` (every handler ran but delivered nothing),
or `ERROR`/dead-letter at whichever stage failed. Decode/parse/strict-validate failures still **NAK
synchronously** at the listener and record `ERROR` *before* any ingress row; routing/transform
failures happen **after** the ACK, so they no longer NAK the sender — they are a logged `ERROR`/dead-
letter at the failing stage (operators rely on the disposition + AlertSink, not the ACK, for post-
ingress failures).

- **Connections are pluggable via a registry.** Implement the inbound/outbound connector in
  `transports/` and register it ([`transports/base.py`](../../messagefoundry/transports/base.py)); the
  pipeline resolves connections through the registry — never special-case a connection type
  inside `pipeline/`. (Today these are still `SourceConnector`/`DestinationConnector` +
  `register_source`/`register_destination`; the inbound/outbound vocabulary is being adopted.)
- **Routing/handling is code-first.** A **Router** (`@router`) returns handler name(s) — it decides
  forwarding (+ optional filtering); a **Handler** (`@handler`) filters → transforms (via
  [`Message`](../../messagefoundry/parsing/message.py)) → returns `Send`s to outbound connections. They
  are pure functions registered into the `Registry`; the `RegistryRunner` runs them in the inbound
  path and turns `Send`s into outbox rows. No declarative `Filter`/`TransformStep`.
- **Dependency direction is one-way:** `pipeline/ transports/ parsing/ store/ config/` never
  import `api/`. The API depends on the engine; the web console and the harness depend on the API
  (via the `apiclient/` HTTP client). **One carve-out:** `parsing/` is a **pure, side-effect-free HL7
  library** (no engine state, I/O, or DB) — a client (e.g. the harness's rehomed Parse Tree view) **may**
  import it for client-side rendering. That is not "reaching into the engine"; importing any other engine
  package (`pipeline/`, `store/`, `transports/`, `config/`) from a client is still forbidden.
- **Author config as modular Python.** Put shared helpers in `_`-prefixed files (the loader skips
  `_*`) and import them from siblings — don't copy-paste boilerplate. For a ported / non-trivial feed,
  split it by role — connections (`connections.toml`) / `@router` / `@handler` / `_<feed>_transforms.py`
  helper — rather than one monolithic module; see [`docs/CONNECTIONS.md`](../../docs/CONNECTIONS.md)
  §"Decomposing by role" and the `samples/config/IB_DEMO_ORU_*` worked example.

- Target **Python 3.14+** (the project requires `>=3.14`). Type-hint all public functions/attributes — **mypy runs in strict
  mode**.
- **asyncio core:** never block the event loop; use `aiosqlite` and async connectors. Long
  loops/workers must be **cooperatively cancellable** (respond to the connection's stop signal)
  and shut down cleanly (the ASGI lifespan calls `engine.stop()`).
- Error handling: catch **specifically**, never bare `except:`, never swallow silently — log
  it. Route bad *messages* to the error/dead-letter path rather than crashing a connection.
- Comments explain **why**, not what.

- **De-identification is built** ([ADR 0030](../../docs/adr/0030-anonymization-test-harness-tee.md)). The
  centralized framework lives in `messagefoundry/anon/` (vendored to `tee/anon/`): deterministic
  secret-per-dataset pseudonymization, **fail-closed**, HL7 v2 first. It builds PHI-free test datasets
  via the tee `anonymize-captures` subcommand + the test harness. **Centralize the rules — don't inline
  ad-hoc de-id logic**; use this framework, don't reimplement one beside it.
- Don't add Black. **Prefer TOML** for config (YAML isn't banned — use it only with a concrete case).
  Routing/handling *logic* is code-first Routers/Handlers (no declarative `Filter`/`TransformStep`) —
  but connection *transport config* may be data (`connections.toml`, ADR 0007); see §1.
