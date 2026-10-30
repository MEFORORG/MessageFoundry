# 0215 — The web console calls the JSON routes in-process through the ASGI app, so one gate family authorizes both planes

- **Status:** Proposed
- **Date:** 2026-10-29
- **Related:** vault BACKLOG #2603 (this ADR is its research step); #1197 (console grant rows),
  #2624 (a console action has no grant row to fall back on), #2709 (route-gate parity, which engine
  PR 2341 assigned to #2603), #2424 and #2450 (the seam snapshot's gaps), #2604 (the route guard,
  closed); [ADR 0065](0065-web-ops-dashboard.md) and
  [ADR 0088](0088-apiclient-service-cli-extraction.md) (both amended on acceptance, section 7),
  [ADR 0077](0077-action-bound-step-up.md), [ADR 0150](0150-client-address-on-audit-entries.md),
  [ADR 0151](0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md),
  [`docs/WEBCONSOLE-PACKAGE.md`](../WEBCONSOLE-PACKAGE.md) section 2; [CLAUDE.md](../../CLAUDE.md)
  sections 2, 4 and 6

---

## Context

Authorization on the JSON plane is a FastAPI dependency on each route, built by a gate factory in
[`api/security.py`](../../messagefoundry/api/security.py). The web console does not call those
routes. ADR 0065 mounted it in the engine's own app (section 1) and had its routes reuse the JSON
handlers (section 6 and the M2b addendum). `docs/WEBCONSOLE-PACKAGE.md` calls the `/ui` routes
clients of those handlers by reference. They now reach them through the `CoreHandlers` and `AdminHandlers`
bundles in [`api/_ui_seam.py`](../../messagefoundry/api/_ui_seam.py), injected as fields of
`UiDeps`. A direct call skips the handler's own `Depends` gate, so the console carries a second gate
family in [`messagefoundry_webconsole/_auth.py`](../../messagefoundry_webconsole/_auth.py) that
re-asserts each check by hand. `require_ui`'s docstring says so: the PHI views "call the JSON
handlers directly, which skips their own `Depends` gate".

Measured at engine `154fc13d99` with `create_app(serve_ui=True)`, by a read-only probe:

| What | Count |
|---|---|
| Route objects | 244: 242 HTTP routes, 1 WebSocket, 1 mount |
| HTTP method rows | 115 JSON, 127 `/ui` |
| JSON gates in use | `require` 41, `require_step_up` 22, `require_paced` 17, `require_step_up_action` 17, `require_phi_read` 8, `require_reauth_only_action` 4, `require_service_cert` 1, none 5 |
| `/ui` gates in use | `require_ui` 55, `require_ui_step_up` 34, `require_ui_step_up_action` 16, `require_ui_reauth_only_action` 5, `require_ui_step_up_when_own_sessions_end` 4, `require_ui_reauth_only` 2, none 11 |
| Gate factories | 10 on the JSON plane (with `optional_identity` and `authorize_ws`); 7 on the console plane (with `authorize_ui_ws`) |
| Seam call sites under `messagefoundry_webconsole/routes/` | 106: 69 `core.X(` and 37 `admin.X(`, naming 83 distinct handlers |
| Seam handler fields | 86: 55 on `CoreHandlers`, 31 on `AdminHandlers` |

The row's own figures (239 routes, 6 console factories, 100 calls) came from an earlier engine. The
tree has grown since, and every count above is the larger one, so the structure the row describes
holds.

The two families have drifted at least six times, each fixed alone (#287, #1227, #1738, #1739,
#1822, #1973). A by-call comparison in the 2026-10-01 review found no console route weaker than the
JSON gate on the handler it calls, so no privilege gap is known. One difference is real and open:
`require_ui` and `authorize_ui_ws` write no `auth.permission_granted` row (#1197), so a console
action would leave no grant row behind it (#2624). Engine PR 2341 added a parity test,
`test_each_console_gate_is_at_least_its_json_gate`. It pairs routes by a hand-kept table,
`_UI_JSON_COUNTERPARTS`, rather than by the handler a route calls, and it reads gates, not route
bodies. A second guard cannot remove the defect class. It can only narrow the window in which a new
console route picks a plausible but wrong gate. With zero deployments (CLAUDE.md section 0) that
would ship a missing step-up or PHI budget on the only operator surface on a first deployment.

The console wheel is versioned apart from the engine and checks a seam digest at startup
(`ENGINE_UI_SEAM`). #2709 records how that leaves the gate's strength to the console wheel: a wheel
built before an engine gate change passed the handshake and would have served two DR routes on the
session alone.

## Decision

**The console stops calling engine handlers. Every console route that needs engine data or an
engine action sends an in-process HTTP request to the JSON route through the engine's own ASGI app,
carrying the session token as a bearer credential. The JSON gate then authorizes it, as it does a
bearer client, and the console's own gate shrinks to session presence, same-origin, and turning a
refusal into a redirect.**

### 1. The sub-request

- The console builds each sub-request from the browser request it is serving. It sets a fresh
  `Authorization: Bearer <token>` header from the session cookie and copies no browser header. The
  JSON plane reads no other request header that matters here: at least `bearer_token`,
  `sole_authorization`, the body cap and the upload content type read headers, and the sub-request
  sets the last two itself.
- **The derived scope.** The sub-request's ASGI scope copies, from the browser request's scope, at
  least `client`, `server`, `scheme`, `http_version`, `root_path` and the TLS extension. `client`
  has already been through uvicorn's trusted-proxy rewrite, so `client_ip` reads the browser's real
  address and still parses no forwarding header. The new-address check, the audit `client` column
  (ADR 0150) and the network allow-list (ADR 0151) then see what they see for a bearer client from
  that host.
- **The console extension.** The scope carries one extension, `messagefoundry.console`, holding the
  browser request's id, its `/ui` path, and whether the route is a timer-driven poll. Only
  in-process code can set a scope extension: uvicorn builds the scope from the socket, so no
  network caller can supply or forge one. Section 3 says what each field is for, and none of them
  relaxes a gate.
- **The dispatch target is the full app** (`request.app`), not its router. Every middleware and
  exception handler then runs exactly as for a bearer client. Three effects are accepted. The
  request deadline nests, and the outer one fires first. The network gate judges the same copied
  address twice. The address-monoculture tripwire sees each address twice, which only brings forward
  a firing it would reach anyway.
- **The transport.** httpx's `ASGITransport` (0.28.1, read from source) cannot carry this. It sets
  `client` once per transport, with a loopback default `("127.0.0.1", 123)`. It builds the scope
  itself with no extension hook, and it buffers the whole response body. Measured: a route behind
  the default transport saw `('127.0.0.1', 123)`. Left that way, the new-address check and the audit
  `client` column would read loopback for every console action. The build adds a small in-process
  transport that derives the scope as above and streams both bodies, for the upload, the attachment
  download and the audit export.
- **The client.** `messagefoundry/apiclient`'s `EngineClient` is synchronous over `httpx.Client`.
  Calling it from an async console route would block the event loop (CLAUDE.md section 6). The
  build adds an async client to `apiclient` for the routes the console calls, over that transport.
  `apiclient` stays free of FastAPI and PySide6 (ADR 0088 AC-1): the transport needs only an ASGI
  callable and a scope mapping.

### 2. What the console's gate keeps

`require_ui` shrinks to three steps. Nothing else in the `require_ui*` family or the console's
step-up spend machinery survives the migration.

1. **Read the cookie and resolve the session read-only** (`activity=False`). No session sends a
   303 to the login page before any sub-request runs. This keeps the documented console ordering:
   an unauthenticated browser gets its login redirect, never a PHI hop refusal naming the instance's
   posture. The row's design said "read the cookie" only. This step is the smallest addition that
   keeps that ordering. The identity it returns is for display, at least which navigation links to
   draw. A hidden link is presentation, and the JSON gate decides access.
2. **Same-origin on every non-GET**, before the sub-request, as `assert_same_origin` runs today. The
   JSON plane has no CSRF check because a bearer header is not ambient. The console turns an ambient
   cookie into that header, so the check moves no further than the console.
3. **Turn the JSON refusal into a browser answer.** One table, one function:

   | JSON answer | Console answer |
   |---|---|
   | 401 | 303 to the login page, noting expiry when a cookie was sent |
   | 403 with `X-MFA-Required` | 303 to `/ui/mfa`; for a step-up route, to `/ui/reauth` carrying the action |
   | 403 with `X-Step-Up-Required` (with `X-Step-Up-Action` and the IdP marker when set) | 303 to `/ui/reauth` with a server-issued continuation, as today |
   | 403 with `X-Notify-Email-Required` | 303 to the notification-address page |
   | 403 for a must-change session | 303 to the change-password page, or `/ui/mfa` first when a factor is owed. The JSON refusal has no header for this today, only a detail string, so the build adds one |
   | Any other 403 | the console's forbidden page |
   | 429 with `Retry-After` | the console's throttled page, carrying the same `Retry-After` |
   | 503, auth not configured | 303 to the login page, as `require_ui` does now |

   For the new-address refusal, a 403 with `X-Step-Up-Required` from a PHI read or a paced write,
   the console keeps choosing the continuation (`_new_address_continuation`): a PHI page returns to
   itself and a write lands on `/ui`. That is a choice of landing page, not a gate.

ADR 0065 section 3's boundary holds unchanged. A browser request to a JSON route that carries only
the cookie still gets a 401. The tests named in AC-8 already pin that. Only the console's in-process
transport turns a cookie into a bearer header, and only after steps 1 and 2.

### 3. The four costs the row names, answered

1. **The browser's address.** Answered in section 1: the derived scope copies `client`. The
   new-address check asks once per PHI read or paced write. It is deduped and capped per session
   (`AuthService.flag_new_client_ip`), so a page that makes several sub-requests writes no extra
   rows.
2. **The PHI budget per handler call.** Charge per sub-request, with no exemption. The detail page
   with its body open calls `get_message` and `get_message_body`, so it costs two. A bearer client
   reading the same two resources pays two today, so the console moves to parity: today it
   under-charges. At the shipped `phi_read_rate_limit_per_actor = 120` per 60-second window, that
   still allows 60 body views a minute, above any human's pace, and the setting is per actor. A
   per-page exemption would be a mechanism that only lowers a control, so none is proposed.
3. **Polled routes: the idle clock and the grant row.** `/ui/nav-status` calls three to five
   handlers every 15 seconds per tab (`system_status`, `dr_status`, `cluster_status`, then
   `cluster_nodes` when clustered and `list_active_alerts` with `monitoring:diagnose`). That is
   720 to 1,200 sub-requests an hour per tab. Under `[diagnostics].audit_all_authz`, on by default,
   each would write a grant row, and each would touch the session's idle clock.
   - *Idle clock:* the extension's poll flag makes the JSON gate resolve the session with
     `activity=False`, as five `/ui` routes do today. It can only let a session age out sooner, so
     it relaxes nothing.
   - *Grant row:* the JSON gate writes at most one grant row per browser request. It keys that on the
     extension's request id, so the first authorized sub-request writes it and the rest of that
     browser request do not. That is the JSON plane's own ceiling, carried across the hop:
     `_grant_audit_permission` keeps "the grant to ONE audit row per request". A denial row is never
     deduplicated. The row records the JSON path that was authorized and names the console route
     beside it, so an investigator can tell a console action from a bearer call. For
     `/ui/nav-status` that is 240 rows an hour per tab, the same as a bearer client polling one
     route every 15 seconds today. Whether timer-driven reads should write grant rows at all is a
     question for both planes together. It is listed for the owner below, not decided here.
   - The extension cannot be forged from the network. A forged request id could only suppress grant
     rows, so it is the one field that must stay in-process. A poll flag sent as a request header
     would be safe, because it only ages a session faster. It stays in the extension anyway, so the
     console has one channel.
4. **One JSON encode and decode per call.** Measured on a stand-in FastAPI app, not the engine: a
   sub-request through an in-process transport plus decoding a 2,961-byte response took about
   0.44 ms (2,000 calls, Python 3.14.7, FastAPI 0.146.0, httpx 0.28.1). At five per nav poll that is
   about 2 ms every 15 seconds. The engine's middleware stack adds to it, and that is unmeasured. The
   first migration slice measures `/ui/nav-status` and one PHI page before and after, on the engine.

### 4. The JSON plane's policy table

Removing the second family does not stop a wrong but plausible choice among the ten JSON factories.
The route map in `docs/SECURITY.md` already pins each JSON route's permission and gate. A diff shows
a change, and nothing says whether the new gate is enough. The build adds one class per JSON route:
at least metadata read, PHI read, bulk PHI read, paced write, sensitive write and action-bound
write. Each class names its minimum factory, and a test fails when a route's gate is below its
class. A reviewer then judges one word per route rather than a factory name. This needs no part of
sections 1 to 3, so it can land at any point.

### 5. Why the proof-object design is not taken

The review's first proposal was a typed `Authorized[Op]` argument on every privileged handler, with
one `authorize()` that alone mints it. That guarantee cannot hold. At least the dual-control
executors (`api/app.py::_build_approval_gate` re-runs a captured operation at release), the cluster
config and state convergence workers (`pipeline/config_convergence.py`,
`pipeline/state_convergence.py`) and the DR re-apply run engine operations with no HTTP request and
no caller session. They would need a second mint path, and the guarantee would weaken to
"`authorize()` or a system mint", the weaker guarantee bought at the larger cost. It would also
re-sign about 110 handlers and the whole seam. The sub-request design gets the property that
matters for the console more simply: the handlers are closures nested in `create_app` and
`add_auth_routes`, and once `UiDeps` stops carrying them, no other module holds a reference.
AC-1 pins that.

### 6. What it must not break

No pipeline invariant is touched: no stage, handoff, ACK or disposition changes. Every PHI-access
audit row the handlers write today is still written, by the same handler. Channel scope still comes
from the identity the handler is given, now by the JSON gate. With zero deployments there is no
older console wheel to keep working. The seam digest moves and the startup handshake refuses the
skew, so no compatibility shim is built.

### 7. What this amends, once accepted

It supersedes no ADR whole. It amends two, and their text changes only when this one is accepted.

- **ADR 0065.** The handler reuse in section 6 and the M2b addendum: `/ui` routes stop calling
  handlers and stop re-applying gates (`require_ui_step_up` and its family). Section 1's in-process
  mount and section 3's cookie confinement stand, and section 2 of this ADR restates the latter.
- **ADR 0088.** `apiclient` gains an async client and the in-process transport beside
  `EngineClient`. Its acceptance criteria stand.

## Acceptance Criteria

The test files below do not exist yet. Each slice in the build order writes the ones its criteria
name.

- **AC-1** — WHEN the console is mounted, THE SYSTEM SHALL inject no engine handler into it:
  `UiDeps` SHALL carry no `CoreHandlers` or `AdminHandlers`, and no module under
  `messagefoundry_webconsole/` SHALL hold a reference to a `create_app` or `add_auth_routes`
  handler.
  → `packaging/messagefoundry-webconsole/tests/test_console_calls_json_routes.py`
- **AC-2** — WHEN a console route serves a browser request from address A, THE SYSTEM SHALL present
  A as the client of every sub-request it makes, so the new-address check and the audit `client`
  column read A.
  → `tests/test_inprocess_transport.py`
- **AC-3** — WHEN the console makes a sub-request, THE SYSTEM SHALL send exactly one
  `Authorization` header built from the session cookie, and no header the browser sent.
  → `tests/test_inprocess_transport.py`
- **AC-4** — WHEN one browser request makes several authorized sub-requests, THE SYSTEM SHALL write
  at most one `auth.permission_granted` row for it, and SHALL write every denial row.
  → `tests/test_auth_grant_audit.py`
- **AC-5** — WHEN a timer-driven console poll makes sub-requests, THE SYSTEM SHALL leave the
  session's idle clock where it was.
  → `packaging/messagefoundry-webconsole/tests/test_console_calls_json_routes.py`
- **AC-6** — IF a JSON route refuses a console sub-request, THEN THE SYSTEM SHALL answer the browser
  with the row of section 2's table that matches, and SHALL run no handler.
  → `packaging/messagefoundry-webconsole/tests/test_console_refusal_map.py`
- **AC-7** — WHEN a console write arrives without a same-origin proof, THE SYSTEM SHALL refuse it
  before any sub-request, and SHALL spend no budget and write no grant row.
  → `packaging/messagefoundry-webconsole/tests/test_console_refusal_map.py`
- **AC-8** — WHEN a browser request to a JSON route carries only the session cookie, THE SYSTEM
  SHALL answer 401, as ADR 0065 section 3 requires.
  → `packaging/messagefoundry-webconsole/tests/test_webui_core.py::test_cookie_not_accepted_on_json_api`
- **AC-9** — WHEN a JSON route's gate is below the minimum its policy class names, THE SYSTEM SHALL
  fail the policy-table test, with a planted weaker gate as its positive control.
  → `tests/test_security_doc_drift.py`
- **AC-10** — WHEN the console streams an upload, an attachment or the audit export, THE SYSTEM
  SHALL pass the body through the in-process transport without buffering it whole.
  → `tests/test_inprocess_transport.py`

## Build order

Each slice is one pull request, and each names what closes it.

1. **Inventory.** Classify all 86 seam fields. 66 are, by object identity, the endpoint of a JSON
   route. The other 20 are reached by a JSON route through a wrapper, or have no JSON route: at least
   the three presentation helpers `user_summary`, `current_user` and `federated_identity_view`, and
   the console's composite `search_messages`. For each without a route, add one or move the helper
   to the console. *Closes:* a test pins each field's class.
2. **Engine-side prerequisites, additive.** The extension reader in `api/security.py` (poll flag,
   one grant row per browser request), the must-change refusal header, and any JSON routes slice 1
   found missing. With no extension present, a bearer client sees no change. *Closes:* AC-4, and
   the JSON-plane half of AC-5.
3. **The transport and the async client.** The derived scope, streaming in both directions, fresh
   headers. *Closes:* AC-2, AC-3, AC-10, and ADR 0088 AC-1 still green.
4. **The shrunk gate and the refusal map.** *Closes:* AC-6, AC-7, and AC-8 still green.
5. **Migrate by page group, in this order:** monitoring and status reads (with the before and after
   measurement in section 3), PHI reads, connection and message writes, step-up and action-bound
   writes, then administration. Each group removes its fields from the bundles and deletes the
   `require_ui*` variants it no longer uses. *Closes per group:* its routes call no seam handler,
   and the seam digest moves.
6. **Remove the second family.** Delete `CoreHandlers` and `AdminHandlers` from `UiDeps`, the rest
   of the `require_ui*` factories and the console step-up spend machinery. Delete
   `test_each_console_gate_is_at_least_its_json_gate`, `_UI_JSON_COUNTERPARTS` and
   `test_ui_gate_divergences_are_exactly_the_reviewed_set`, which then guard nothing. Shrink
   `authorize_ui_ws` to cookie and origin, and hand the token to the checks `authorize_ws` runs,
   so the WebSocket writes its grant row too. Update `docs/SECURITY.md`'s `/ui` route map and
   `docs/WEBCONSOLE-PACKAGE.md` section 2. *Closes:* AC-1; #1197's console grant-row limb; the
   route-gate parity #2709 left to #2603; and the handler-signature half of #2424, which then has no
   handler signatures to cover.
7. **The policy table** (section 4). Independent of slices 1 to 6. *Closes:* AC-9.

## Options considered

1. **Sub-requests through the ASGI app, with a derived scope and one console extension.**
   **CHOSEN.** It deletes the second gate family rather than guarding it. It puts the gate in the
   engine wheel, so a console wheel cannot weaken it, and it closes the console limb of #1197 as a
   side effect.
2. **Keep both families and strengthen the parity guard** to pair by the handler a route calls.
   Rejected. It narrows the window and keeps the defect class. Every new console route still chooses
   a gate by hand, and #2709's version-skew case stays open, because the gate still ships in the
   console wheel.
3. **The proof-object design** (`Authorized[Op]`). Rejected for the reasons in section 5.
4. **Stock httpx `ASGITransport` with one transport per browser request.** Rejected. It can set the
   client address but not the console extension, so it cannot answer cost 3. It buffers whole
   bodies, so it cannot answer the streamed routes.
5. **Dispatch to the app's router, skipping the middleware a second time.** Rejected. A route
   reads its exception handlers from a scope key that Starlette's exception middleware sets
   (`starlette.exception_handlers`, read in `starlette/_exception_handler.py`). Without it, a gate's
   `HTTPException` escapes as an exception rather than becoming the 403 the refusal map reads.
   Copying that private key from the browser request would work, and would tie the console to a
   Starlette internal. Full-app dispatch makes the sub-request equal to a bearer client's request by
   construction rather than by argument, and running the middleware a second time costs less.

## Consequences

**Positive** — One gate family. The console cannot reach a handler without the JSON gate, and a
future in-process caller has no handler reference to reach for. The gate ships in the engine
wheel, so console and engine version skew cannot ship a weaker gate. Every console action gets a
grant row. Six drift rows' worth of hand-synchronised checks go away, with the two parity tests
that watched them. The seam shrinks from 86 handler signatures to the JSON routes and their DTOs,
which the route map and the API models already pin. A later step that moves the JSON plane into a
separate management process takes the console with it, and only the transport changes.

**Negative / risks** — More work per console page: a session resolution per sub-request where there
was one per page, and an encode and decode per call. The engine-side cost is unmeasured until slice
5 measures it. The PHI budget is spent faster on pages that read two resources. The derived scope
is security-relevant code: if it copied the wrong field, or failed to copy `client`, it would
silently weaken the new-address check and the audit trail. AC-2 and AC-3 are its guards. Grant
rows from the console add audit volume where there were none.

**Out of scope** — The console's own sign-in, sign-out, factor, re-authentication, OIDC and passkey
legs. They establish and step up the session rather than use a handler, and they keep calling
`AuthService`. Moving the JSON plane out of the data-plane process needs its own ADR. Channel-scope
enforcement is unchanged; it stays where the handlers apply it.

## To resolve on acceptance

- [ ] The owner accepts or rejects this design. Acceptance is the owner's, and this ADR stays
      Proposed until then.
- [ ] Timer-driven reads: should they write a grant row (240 an hour per tab for `/ui/nav-status`
      under this design, the same as a bearer poller today), or should both planes exempt them
      under `audit_all_authz`? A console-only exemption would re-open a plane difference, so this
      design does not take one.
- [ ] Is the grant row's form right: the authorized JSON path, with the console route named beside
      it?
- [ ] After slice 5's measurement, is one session resolution per sub-request acceptable, or should
      the gate memoise the session for the length of one browser request?
