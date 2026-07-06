# ADR 0043 — Handler-callable live FHIR read lookup (`fhir_lookup`)

- **Status:** Accepted (2026-06-27, built — PR #618)  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-27
- **Related:** BACKLOG #58 ·
  [ADR 0010](0010-handler-callable-db-lookup.md) (the **read-only, off-loop, gated, Router-/dry-run-unavailable,
  re-run-divergent** `db_lookup` carve-out this **extends to FHIR**) ·
  [ADR 0022](0022-fhir-resource-codec-rest-client.md) (the pure `parsing/fhir/` codec + the **outbound**
  `FhirDestination` REST client + the `allowed_http` egress gate this reuses) ·
  [ADR 0024](0024-smart-backend-services-token-provider.md) (the **SMART Backend Services bearer** —
  `SmartBackendTokenProvider` / `with_smart_backend` — reused for read auth) ·
  [ADR 0009](0009-run-scoped-context-providers.md) (the run-scoped accessor + the re-run-stability rule this is the
  second sanctioned exception to) · [ADR 0006](0006-external-data-lookups.md) (the *synced-snapshot* `reference()`
  alternative the owner already rejected for live reads) · [ADR 0001](0001-staged-pipeline-architecture.md)
  (the staged-queue at-least-once / purity invariant this preserves exactly as `db_lookup` does) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (reliability invariant + the `db_lookup` carve-out it already records), §8/§9 ·
  [`config/db_lookup.py`](../../messagefoundry/config/db_lookup.py) `db_lookup`/`activated`/`LookupRunner`/`DbLookupError` ·
  [`transports/fhir.py`](../../messagefoundry/transports/fhir.py) `FhirDestination` (`_INTERACTIONS`, `_probe`) ·
  [`transports/smart.py`](../../messagefoundry/transports/smart.py) `SmartBackendTokenProvider`/`token_provider_from_destination` ·
  [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py)
  `_build_lookup_executor`/`_run_lookup`/`check_egress_allowed`/`_http_egress_allowed` ·
  [`config/settings.py`](../../messagefoundry/config/settings.py) `EgressSettings.allowed_http`

---

## Context

ADR 0010 shipped `db_lookup(connection, statement, params)`: a Handler may make a **live, read-only** database read
on each pass — provider NPI, eligibility, "is-this-an-EIHC-provider" — that **must reflect the source now**, not a
periodic snapshot (the owner explicitly **rejected** the synced-snapshot `reference()` alternative of
[ADR 0006](0006-external-data-lookups.md) for these). It is the **one sanctioned non-pure input** in the engine
([CLAUDE.md](../../CLAUDE.md) §2): read-only, run **off the event loop**, fail-closed-gated by `[egress].allowed_db`,
**unavailable on a Router and in dry-run / Test Bench** (it raises `DbLookupError` where no runner is published), and
its re-run divergence is **accepted by design** — a re-run may re-query and differ, which **does not** break the
at-least-once / purity invariant.

The same enrichment-and-gating need now exists against a **FHIR** source, not just SQL. A migration Handler often must
read a resource it does **not** have in the inbound message — resolve a `Patient` by id to fill a demographic, check a
`Coverage`/`Encounter` for eligibility gating, look up the practitioner behind an identifier — against an EHR's FHIR
API (Epic, Oracle Health) **as the data stands at that pass**. Today the engine has FHIR only on the **write** side:
[ADR 0022](0022-fhir-resource-codec-rest-client.md) shipped the pure `parsing/fhir/` codec and a `FhirDestination`
that POST/PUT/Bundle-delivers a resource, and its `_INTERACTIONS` tuple is **write-only** —
`("create", "update", "transaction", "batch")` ([transports/fhir.py:74](../../messagefoundry/transports/fhir.py)) —
with no GET/read/search path (ADR 0022 listed "A FHIR *read*/search client" explicitly **out of scope**). A Handler
cannot pull a FHIR resource mid-transform; it can only *push* one downstream.

This is the **FHIR mirror of the gap ADR 0010 filled for SQL** — and the right shape is to **extend the existing
`db_lookup` carve-out to FHIR**, not to invent a parallel mechanism:

- **The same re-run tension, already adjudicated.** A live FHIR read is a side input that can differ on a re-run —
  the *identical* purity concern ADR 0010 raised for a live DB read ([CLAUDE.md](../../CLAUDE.md) §2, "do not break").
  The owner already accepted that divergence for `db_lookup`; the FHIR read is the same trade, so it inherits the same
  ruling rather than reopening it.
- **The same off-loop concern, already solved.** Handlers run synchronously on the asyncio loop (`transform_one` is
  called inline by the transform worker). A blocking HTTP GET there would stall every listener, worker, and API call —
  exactly why `db_lookup` runs off the loop. The transform worker **already** runs the handler off the loop via
  `asyncio.to_thread` whenever the graph declares ≥1 lookup ([wiring_runner.py:1731-1740](../../messagefoundry/pipeline/wiring_runner.py)),
  and bridges the query back to the loop via `run_coroutine_threadsafe` (`_run_lookup`, [wiring_runner.py:451-465](../../messagefoundry/pipeline/wiring_runner.py)).
- **The substrate is already shipped.** The pure FHIR codec (`FhirPeek`/`FhirResource`/`FhirPeekError`), the hardened
  HTTP plumbing in `transports/rest.py` (the no-redirect, TLS-verifying `_NO_REDIRECT_OPENER`, `_redact_url`, the
  cleartext-credential refusal), the `[egress].allowed_http` host gate
  ([wiring_runner.py:2429](../../messagefoundry/pipeline/wiring_runner.py) `_http_egress_allowed`), and the **SMART
  Backend Services bearer** (`SmartBackendTokenProvider` / `with_smart_backend`,
  [transports/smart.py](../../messagefoundry/transports/smart.py)) all exist. A read lookup is a thin GET/search layer
  over them — it reuses, it does not re-implement.

Two [CLAUDE.md](../../CLAUDE.md) invariants bound the design and **must not** be relaxed (the same two `db_lookup`
honours):

- **Purity / at-least-once** (§2, ADR 0001): routers and transforms must be pure so a re-run re-derives identical
  output. `fhir_lookup` is the **second documented exception** — read-only, re-run-divergent, accepted — and is
  published **only** in the live transform path, so a call on a **Router** or **in dry-run** raises (no determinism is
  assumed there).
- **Never block the event loop** (§6): the FHIR GET is blocking `urllib` and runs **off the loop**, exactly as
  `db_lookup`'s query does.

## Decision

**Add a synchronous, handler-callable `fhir_lookup(connection, query)` that performs a live, read-only FHIR read —
a read-by-id GET or a search — against an operator-declared, allow-listed FHIR endpoint, by extending the ADR 0010
`db_lookup` carve-out to FHIR.** It reuses the SMART Backend bearer (ADR 0024) + `[egress].allowed_http`, runs **off
the event loop**, **raises on a Router / in dry-run**, and its result **may differ on a re-run** — accepted by design,
exactly like `db_lookup`. It does **not** break purity or at-least-once.

### D1 — A declared `FhirLookup` connection + the `fhir_lookup(connection, query)` accessor (the `db_lookup` idiom)

Mirror ADR 0010's split **exactly**: a declared, pooled, env()-resolvable **connection**; a per-call **query**:

- **`FhirLookup("epic", base_url=…, fhir_version="R4B", …)`** — a new declaration in
  [config/wiring.py](../../messagefoundry/config/wiring.py) registered into `Registry.lookups` alongside
  `DatabaseLookup` (the runner already builds *all* lookups from `registry.lookups` —
  [wiring_runner.py:442](../../messagefoundry/pipeline/wiring_runner.py)). It declares only the **connection**: the
  FHIR service base URL, the FHIR version, the timeout/TLS knobs, and the **same SMART auth seam** the outbound uses —
  authored either as flat `bearer_token=env(...)` or by composing `with_smart_backend(FhirLookup(...), token_url=…, …)`
  ([transports/smart.py:250](../../messagefoundry/transports/smart.py) accepts a `REST`/`FHIR` spec; `FhirLookup` is the
  read-side member of that family). Secrets ride `env()`/`_SECRET_SETTING_KEYS`, redacted from `/metadata` like every
  other connection.
- **`fhir_lookup(connection, query)`** — a synchronous accessor in a new
  [config/fhir_lookup.py](../../messagefoundry/config/fhir_lookup.py), a **near-clone of `config/db_lookup.py`**
  (the `_active` `ContextVar` runner holder, `set_active`/`reset`/`activated`, `FhirLookupError(RuntimeError)`,
  and the `LookupRunner` type). `query` is **one of two read shapes**, both read-only:
  - a **read-by-id**: `fhir_lookup("epic", "Patient/123")` (or a structured `("Patient", "123")`) → `GET {base}/Patient/123`;
  - a **search**: `fhir_lookup("epic", "Patient?identifier=MRN|123")` → `GET {base}/Patient?identifier=MRN|123`.
  It returns the parsed result as a **plain dict** (a single resource) or a **`Bundle` searchset dict** (a search),
  read on demand by the Handler via the pure `parsing/fhir/` codec (`FhirPeek`/`FhirResource`) — never a typed object
  pushed through the pipeline. `config/` stays import-clean: it owns **only** the accessor + the active-runner holder;
  the runner (HTTP pool + loop bridge + codec) is supplied by the `RegistryRunner`, exactly as `db_lookup`'s runner is
  ([db_lookup.py:18-23](../../messagefoundry/config/db_lookup.py)).

> **Read-only is structural, not a convention.** The accessor builds **only** a GET request — there is **no** verb
> parameter, no body, no POST/PUT/DELETE path — so a Handler **cannot** mutate the FHIR server through it (the
> `db_lookup` executor's "neither commits nor exposes a write path", ADR 0010, applied to HTTP). FHIR **writes** stay
> on the `FhirDestination` outbound, where they belong (past the staged-queue boundary, idempotent, retried).

### D2 — Reuse the off-loop runner machinery + the SMART bearer (no new mechanism)

The `RegistryRunner` **already** runs the handler off the loop and activates a lookup runner when the graph declares ≥1
lookup ([wiring_runner.py:1731-1749](../../messagefoundry/pipeline/wiring_runner.py)). `fhir_lookup` rides that same
seam:

- **A `FhirLookupExecutor`** (sibling of `DatabaseLookupExecutor`, [transports/database.py:660](../../messagefoundry/transports/database.py))
  built from the resolved `FhirLookup` specs at start/reload, reusing **rest.py's `_NO_REDIRECT_OPENER`** (TLS-verified,
  3xx-refusing — a redirect can't divert a PHI-bearing read to another host; ASVS 15.3.2), the SMART
  `SmartBackendTokenProvider.access_token()` for the `Authorization: Bearer …` header (the same provider, cache, and
  401-invalidate the outbound uses — [smart.py:135/150](../../messagefoundry/transports/smart.py)), and the pure
  `parsing/fhir/` codec to parse the reply. The query runs **off the event loop** in the handler's worker thread and
  bridges back via `run_coroutine_threadsafe` (the `_run_lookup` pattern), bounded by a result timeout like
  `_LOOKUP_RESULT_TIMEOUT_SECONDS`.
- **Activation is the existing `activated(...)` bracket.** The transform worker brackets the off-loop `transform_one`
  with the FHIR lookup runner published (alongside, or unified with, the db lookup runner), so a call-time
  `fhir_lookup(...)` resolves inside the worker thread and the prior runner is always restored — no leak across rows
  ([db_lookup.py:82-93](../../messagefoundry/config/db_lookup.py)). **When the graph declares no `FhirLookup`, the path
  is byte-identical** (no executor, no runner; a call raises `FhirLookupError`).

### D3 — Fail-closed egress gate: reuse `[egress].allowed_http` (a read is an egress host)

A FHIR read **dials out to an HTTP(S) host** — the same egress surface the `FhirDestination` outbound and the SMART
token endpoint already pass. The `FhirLookup`'s `base_url` (and, when SMART is composed, its `smart_token_url`) **must**
be checked against **`[egress].allowed_http`** at load/reload/start — the exact arm `FhirDestination`/SMART already use
([wiring_runner.py:2429](../../messagefoundry/pipeline/wiring_runner.py) `_http_egress_allowed`;
`check_egress_allowed` folds REST/SOAP/FHIR into the `allowed_http` branch — ADR 0022 §3.4). This adds a
`check_fhir_lookup_allowed(name, settings, egress)` modelled on `check_lookup_allowed`
([wiring_runner.py:2128](../../messagefoundry/pipeline/wiring_runner.py)) but reading `allowed_http` (HTTP host) rather
than `allowed_db` (SQL host:port). Under `[egress].deny_by_default` an empty `allowed_http` **refuses** the read
outright — an un-allowlisted FHIR read can never dial out. **This is the load-bearing security edit**: a read path that
skipped the gate would be a fail-open SSRF-shaped hole into a PHI system (the same reasoning ADR 0024 §5 gave for gating
`smart_token_url`).

### D4 — Re-run-divergence exception, made explicit (the second one after `db_lookup`)

`fhir_lookup` is the **second documented exception** to the re-run-stability rule (ADR 0009), with the **identical**
reasoning ADR 0010 recorded:

- It is published **only** in the live transform path. A call on a **Router** (`route_only`) or in the **dry-run /
  Test Bench** path (`pipeline/dryrun.py`) finds **no active runner** and **raises `FhirLookupError`** — a feed that
  uses it is previewed by **stubbing its wrapper**, exactly as a `db_lookup`-using feed is.
- A re-run may re-query and return a **different** resource/Bundle — **accepted by design**: the value used is whatever
  the FHIR server returns on that pass. Because the **outbound stays idempotent** and the divergence is read-side only,
  **at-least-once is not broken** — the [CLAUDE.md](../../CLAUDE.md) §2 carve-out that already names `db_lookup` is
  **widened to name `fhir_lookup` too** (a read-only `fhir_lookup` is permitted in a Handler; routers stay pure — no
  `fhir_lookup` on a Router).

### D5 — `CapabilityStatement` as the connection-test probe

`FhirLookup.test_connection()` reuses the **already-shipped** `FhirDestination._probe` shape
([transports/fhir.py:381-410](../../messagefoundry/transports/fhir.py)): a **GET of `{base}/metadata`** (the FHIR
`CapabilityStatement`) over the hardened opener — reachability without reading or writing a clinical resource. Any HTTP
response means the host answered; a **401/403** (with the SMART bearer acquired, if composed) means the configured
credentials would be rejected; DNS/conn/TLS/timeout fails. This makes a `FhirLookup` testable from `messagefoundry
check` / the console **without** issuing a PHI-bearing read — the natural FHIR analog of the DB lookup's connect test.

### What this must not break

- **Purity / at-least-once (ADR 0001).** `fhir_lookup` is read-only and re-run-divergent **by accepted design**; the
  outbound stays idempotent, routers stay pure. A re-run re-reads — it never re-writes.
- **Off the event loop (§6).** The blocking FHIR GET runs in the handler's worker thread (the existing
  `asyncio.to_thread` hop), bridged to the loop's pool — **never** on the loop.
- **Router / dry-run unavailability.** No runner is published on a Router or in dry-run, so a call **raises** there —
  identical to `db_lookup` (a determinism-assuming path never silently gets live data).
- **Fail-closed egress.** The read host (and any SMART token host) is gated by `[egress].allowed_http` at
  load/reload/start; `deny_by_default` + empty list refuses it.
- **PHI / secret safety (§9).** `FhirLookupError` and every log line carry only **routing-safe identifiers**
  (`resourceType`, resource `id`, an `OperationOutcome` `issue.code`/`severity`, a `_redact_url`'d host) — **never** the
  returned resource body, the query's parameter values, or the SMART token. The full resource goes only to the Handler
  in memory; nothing PHI-bearing is logged at INFO+ (ADR 0022 §1 PHI rule, applied to the read path).
- **No new mechanism.** It reuses `registry.lookups`, the `activated(...)` runner bracket, the off-loop transform hop,
  the SMART bearer, the hardened opener, and the `allowed_http` gate — it adds a read **executor + accessor**, not a
  parallel lookup framework.

## Acceptance Criteria

> EARS form; each linked (`→`) to its test/fixture. `messagefoundry adr-analyze` checks each `→` resolves.

- **AC-1** — WHEN a Handler calls `fhir_lookup(connection, "Patient/123")` against a declared `FhirLookup`, THE SYSTEM
  SHALL issue a read-only `GET {base}/Patient/123` over the hardened opener and return the parsed resource dict.
  → `tests/test_fhir_lookup.py::test_read_by_id_returns_resource`
- **AC-2** — WHEN a Handler calls `fhir_lookup(connection, "Patient?identifier=MRN|123")`, THE SYSTEM SHALL issue a
  read-only `GET {base}/Patient?identifier=MRN|123` and return the searchset `Bundle` dict.
  → `tests/test_fhir_lookup.py::test_search_returns_bundle`
- **AC-3** — WHEN `fhir_lookup` is called on a **Router** or in the **dry-run / Test Bench** path, THE SYSTEM SHALL
  raise `FhirLookupError` (no active runner), never return live data.
  → `tests/test_fhir_lookup.py::test_unavailable_on_router_and_dryrun`
- **AC-4** — WHERE `[egress].deny_by_default` is set and `[egress].allowed_http` does not list the `FhirLookup`
  `base_url` host, WHEN the graph loads/reloads/starts, THE SYSTEM SHALL refuse the connection with a `WiringError`.
  → `tests/test_fhir_lookup.py::test_egress_gate_refuses_unlisted_host`
- **AC-5** — WHEN a `FhirLookup` composes `with_smart_backend(...)`, WHEN a read runs, THE SYSTEM SHALL acquire a SMART
  bearer via `SmartBackendTokenProvider.access_token()` and send it as `Authorization: Bearer …` on the GET, and on a
  `401` SHALL invalidate the cached token.
  → `tests/test_fhir_lookup.py::test_smart_bearer_applied_and_reminted_on_401`
- **AC-6** — WHEN a read fails (unknown connection, non-2xx, unparseable body, timeout), THE SYSTEM SHALL raise
  `FhirLookupError` carrying only routing-safe identifiers — **no** resource body, query parameter values, or token —
  surfacing as that message's `ERROR` / dead-letter.
  → `tests/test_fhir_lookup.py::test_error_is_phi_and_secret_safe`
- **AC-7** — WHEN no `FhirLookup` is declared in the graph, THE SYSTEM SHALL behave byte-identically to today (no
  executor, no runner) and a `fhir_lookup` call SHALL raise.
  → `tests/test_fhir_lookup.py::test_no_lookup_declared_is_unchanged`
- **AC-8** — WHEN `FhirLookup.test_connection()` runs, THE SYSTEM SHALL `GET {base}/metadata` (the
  `CapabilityStatement`) and report reachability / a 401-403 credential failure without reading a clinical resource.
  → `tests/test_fhir_lookup.py::test_capability_statement_probe`
- **AC-9** — THE SYSTEM SHALL run the blocking FHIR GET off the event loop (the handler's worker thread), bridged to the
  engine loop, never on the loop.
  → `tests/test_fhir_lookup.py::test_read_runs_off_the_event_loop`

## Options considered

1. **Extend the `db_lookup` carve-out to FHIR — a declared `FhirLookup` + `fhir_lookup(connection, query)` accessor
   reusing the off-loop runner, SMART bearer, and `allowed_http` gate (CHOSEN).** Adds a read executor + accessor that
   mirror `DatabaseLookupExecutor` + `db_lookup` exactly, rides `registry.lookups` + the existing `activated(...)`
   bracket + the existing off-loop transform hop, and inherits the already-adjudicated re-run-divergence ruling.
   Minimal new surface; one mental model ("a live lookup is read-only, off-loop, gated, Router/dry-run-unavailable");
   read-only is structural (GET-only, no verb). **Adopted.**
2. **A FHIR *read*/search **transport** (a new inbound/poller or an `interaction="read"` on `FhirDestination`).**
   Rejected: a read mid-transform is **not** a transport stage — it is a Handler enrichment call, exactly as
   `db_lookup` is (not a DATABASE *source*). Adding `read` to `FhirDestination._INTERACTIONS` would put a
   *pull* on a *push* connector and route its result back through the pipeline, which the staged queue is not shaped
   for; the lookup accessor is the right home (ADR 0010's call, applied to FHIR).
3. **A synced-snapshot FHIR cache (the `reference()` / ADR 0006 model).** Rejected for the same reason ADR 0010
   rejected it for SQL: the value must reflect the FHIR server **now** (live eligibility / a just-created Patient),
   not a periodic snapshot. The owner already adjudicated this trade-off for live reads.
4. **A bespoke FHIR-read mechanism separate from `db_lookup` (its own runner holder, its own egress list, its own
   off-loop plumbing).** Rejected: it would invent a *second* live-lookup idiom parallel to `db_lookup`, re-derive the
   runner/activation/off-loop machinery the `RegistryRunner` already provides, and split a Handler's "live read"
   surface across two unrelated APIs. Reuse the one carve-out.
5. **A third-party FHIR client (`fhirpy`/`fhirclient`) for the read.** Rejected: the read is a GET over rest.py's
   already-hardened, stdlib-`urllib`, no-redirect, TLS-verifying, egress-gated opener — adding a networking dependency
   (its own TLS/redirect posture to vet, license, hash-lock, audit) buys nothing the existing opener + the pure
   `parsing/fhir/` codec don't already give. The *transport* half stays stdlib-only (the ADR 0022/0024 posture).

## Consequences

**Positive** — Handlers get the FHIR analog of `db_lookup`: resolve a `Patient`/`Coverage`/`Practitioner` against an
EHR FHIR API mid-transform, **as the data stands now**, to enrich or gate a message — unblocking SMART-secured Epic /
Oracle Health read enrichment that today has no path (FHIR is write-only). It **reuses one carve-out and one mental
model** (read-only, off-loop, gated, Router/dry-run-unavailable, re-run-divergent-by-design), **one** runner/activation
machine, the **shipped** SMART bearer + hardened opener + `allowed_http` gate, and the **pure** codec — adding only a
read executor + accessor. It is purely additive (no `FhirLookup` ⇒ byte-identical to today), and read-only is
**structural** (GET-only), so a Handler cannot mutate a FHIR server through it.

**Negative / risks** — It **widens the accepted-non-purity surface** from one input (`db_lookup`) to two
(`+fhir_lookup`); both are read-only and re-run-divergent-by-design, but the [CLAUDE.md](../../CLAUDE.md) §2 carve-out
must be **updated to name both**, and reviewers must hold the line that neither is ever called on a Router. A FHIR read
adds **network latency on the transform path** (an off-loop GET, plus the first SMART token round-trip) and occupies a
worker-thread for its duration — under heavy concurrent-lookup load this shares the same thread-pool-saturation concern
ADR 0010 flagged (a dedicated executor with a tuned size is the same deferred follow-up). The read host (and any SMART
token host) is **net-new egress** an operator must allowlist in `[egress].allowed_http`. **PHI/secret-leak risk** in
the error/log path is real (a careless implementation could embed a returned resource or the token in an exception) —
the routing-safe-identifiers-only rule (D-What-this-must-not-break, AC-6) is a **hard invariant** covered by review + a
test, mirroring `db_lookup`'s PHI-free errors and `_redact_url`.

**Out of scope / stays where it is** — **FHIR writes** stay on the `FhirDestination` outbound (idempotent, past the
queue boundary) — `fhir_lookup` is GET-only. **`fhir_lookup` on a Router** stays unavailable (Routers are pure). **The
inbound FHIR server facade** (ADR 0023, still unwritten) is unrelated — this is a *client read*, not a *served*
endpoint. **SMART App Launch** / human-user flows stay out (ADR 0024) — read auth reuses the Backend Services bearer.
**`$export` / Bulk Data** is a separate later read client (ADR 0024 noted it reuses the same Backend Services flow).
**Profile / terminology conformance validation** of the read resource stays out (ADR 0022) — the Handler reads it via
`FhirResource` if it wants structural validation.

## To resolve on acceptance

- [ ] **Confirm the ADR number is 0043** and add the `Proposed` row to [docs/adr/README.md](README.md) (coordinator
  owns the registry; it flips to `Accepted` on the owner's go).
- [ ] **Confirm the accessor name `fhir_lookup(connection, query)`** and the `FhirLookup(...)` declaration name, plus
  the `query` shape: a string (`"Patient/123"` / `"Patient?identifier=MRN|123"`) only, or also a structured
  `(resource_type, id)` / `(resource_type, search_params)` form. (A string mirrors `db_lookup`'s `statement`; a
  structured form lets the executor grammar-gate the path segments like `FhirDestination._validate_path_token` does —
  decide whether read paths need the same CWE-918 path-token gate before they hit the URL.)
- [ ] **Confirm the egress gate reuses `[egress].allowed_http`** (not a new list) via a `check_fhir_lookup_allowed`
  modelled on `check_lookup_allowed`, and that `deny_by_default` + empty `allowed_http` refuses a `FhirLookup`.
- [ ] **Confirm the SMART seam** — that `with_smart_backend(...)` accepts a `FhirLookup` spec (extend its REST/FHIR
  guard, or add the read spec to the family) and that the read executor reuses `SmartBackendTokenProvider`
  (`access_token`/`invalidate`) verbatim, with the token never logged/persisted (§9).
- [ ] **Confirm the runner unification** — whether `fhir_lookup` publishes a *second* runner alongside `db_lookup`'s,
  or both ride one activation bracket; and that the off-loop transform hop fires when **either** lookup kind is
  declared (today it keys on `registry.lookups`; confirm `FhirLookup` lands in the same map).
- [ ] **Confirm the result shape** — a plain `dict` for a read-by-id and a `Bundle` searchset `dict` for a search
  (Handler parses via `parsing/fhir/`), vs returning a `FhirResource`; and the empty/`404` semantics (a 404 read →
  empty/`None`, not an error, mirroring `db_lookup`'s empty-list-on-no-rows?).
- [ ] **Confirm the `[fhir]` extra dependency posture** — the executor reuses the pure `parsing/fhir/` codec, which
  needs the optional `[fhir]` extra for `FhirResource`; confirm a `FhirLookup`-declaring config fails loud with the
  same actionable "install messagefoundry[fhir]" message the outbound gives when the extra is absent.
- [ ] **Confirm the thread-pool posture** — `fhir_lookup` shares the default executor with `db_lookup`; decide whether
  the deferred dedicated-lookup-pool follow-up (ADR 0010) should be revisited now that two live-lookup kinds can
  contend.
