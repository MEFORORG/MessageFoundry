# 0215 — The web console calls the JSON routes in-process through the ASGI app, so one gate family authorizes both planes

- **Status:** Proposed
- **Date:** 2026-10-29
- **Related:** vault BACKLOG #2603 (this ADR is its research step); #1197 (console grant rows),
  #2624 (a console action has no grant row to fall back on), #2709 (the console route-gate digest),
  #2424 and #2450 (the seam snapshot's gaps), #2604 (the route guard, closed);
  [ADR 0065](0065-web-ops-dashboard.md) and
  [ADR 0088](0088-apiclient-service-cli-extraction.md) (both amended on acceptance, section 7),
  [ADR 0077](0077-action-bound-step-up.md), [ADR 0083](0083-mtls-client-certificate-identity.md),
  [ADR 0150](0150-client-address-on-audit-entries.md),
  [ADR 0151](0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md),
  [`docs/WEBCONSOLE-PACKAGE.md`](../WEBCONSOLE-PACKAGE.md) sections 1 and 2;
  [CLAUDE.md](../../CLAUDE.md) sections 2, 4 and 6

---

## Context

Authorization on the JSON plane is a FastAPI dependency on each route, built by a gate factory in
[`api/security.py`](../../messagefoundry/api/security.py). The web console does not call those
routes. ADR 0065 mounted it in the engine's own app (section 1) and had its routes reuse the JSON
handlers (section 6 and the M2b addendum). `docs/WEBCONSOLE-PACKAGE.md` section 1 calls the `/ui`
routes clients of those handlers by reference. They reach them through the `CoreHandlers` and
`AdminHandlers` bundles in [`api/_ui_seam.py`](../../messagefoundry/api/_ui_seam.py), injected as
fields of `UiDeps` beside `get_engine` and `get_gate`. A direct call skips the handler's own
`Depends` gate, so the console carries a second gate family in
[`messagefoundry_webconsole/_auth.py`](../../messagefoundry_webconsole/_auth.py) that re-asserts each
check by hand. `require_ui`'s docstring says so: the PHI views "call the JSON handlers directly,
which skips their own `Depends` gate".

Measured at engine `154fc13d99` with `create_app(serve_ui=True)`, by a read-only probe:

| What | Count |
|---|---|
| Route objects | 244: 242 HTTP routes, 1 WebSocket, 1 mount |
| HTTP method rows | 115 JSON, 127 `/ui` |
| JSON gates in use | `require` 41, `require_step_up` 22, `require_paced` 17, `require_step_up_action` 17, `require_phi_read` 8, `require_reauth_only_action` 4, `require_service_cert` 1, none 5 |
| `/ui` gates in use | `require_ui` 55, `require_ui_step_up` 34, `require_ui_step_up_action` 16, `require_ui_reauth_only_action` 5, `require_ui_step_up_when_own_sessions_end` 4, `require_ui_reauth_only` 2, none 11 |
| Gate factories | 10 on the JSON plane (with `optional_identity` and `authorize_ws`); 7 on the console plane (with `authorize_ui_ws`) |
| Seam call sites under `messagefoundry_webconsole/routes/` | 106 matching `core.X(` (69) or `admin.X(` (37). A handler passed by reference, such as `core.start_connection` to `_ui_control`, is not counted |
| Seam handler fields | 86: 55 on `CoreHandlers`, 31 on `AdminHandlers` |

The row's own figures (239 routes, 6 console factories, 100 calls) came from an earlier engine. The
tree has grown since, and every count above is the larger one, so the structure the row describes
holds.

The two families have drifted at least six times, each fixed alone (#287, #1227, #1738, #1739,
#1822, #1973). A by-call comparison in the 2026-10-01 review found no console route missing a
step-up, an action binding, a PHI gate or pacing that the JSON gate on the same handler has. It
named one negligible residual: a custom role holding `files:delete` without `files:browse` would see
the names and sizes of its own uploads. It compared gates, not budget accounting. A console page
that reads two PHI resources charges the PHI budget once, where a bearer client reading the same
two pays twice (section 3, cost 2).

One difference is open: `require_ui` and `authorize_ui_ws` write no `auth.permission_granted` row
(#1197), so a console action would leave no grant row behind it (#2624). Two guards watch the
families today. `test_each_console_gate_is_at_least_its_json_gate` pairs routes by a hand-kept
table, `_UI_JSON_COUNTERPARTS`, rather than by the handler a route calls. Engine PR 2341 made the
seam digest cover each console route's gate, so a console wheel whose route gates differ from the
engine's is refused at mount (#2709). Neither covers a route body or an engine helper the console
calls, and neither removes the defect class: every new console route still picks one of seven
factories by hand. With zero deployments (CLAUDE.md section 0), a wrong pick would ship a missing
step-up or PHI budget on the only operator surface on a first deployment.

## Decision

**The console stops reaching into the engine. Every console route that needs engine data or an
engine action sends an in-process HTTP request to a JSON route through the engine's own ASGI app,
carrying the session token as a bearer credential. The JSON gate then authorizes it, as it does a
bearer client, and the console's own gate shrinks to a session check, same-origin, and turning a
refusal into a browser answer.**

### 1. The sub-request

- **Headers.** The console builds each sub-request with a fresh `Authorization: Bearer <token>`
  header from the session cookie and copies no browser header. One exception: a sub-request that
  passes a browser body through, which is the file upload, carries that body's `Content-Type`,
  because the multipart boundary is in it. The JSON plane's gates read no other request header:
  `bearer_token` and `sole_authorization` read `Authorization`, and the body cap reads the length
  headers the transport sets.
- **The derived scope.** The sub-request's ASGI scope copies exactly these keys from the browser
  request's scope: `client`, `server`, `scheme`, `http_version` and `root_path`. It never copies
  `state`, `transport` or `headers`. `client` has already been through uvicorn's trusted-proxy
  rewrite, so `client_ip` reads the browser's real address and still parses no forwarding header.
  The new-address check, the audit `client` column (ADR 0150) and the network allow-list (ADR 0151)
  then see what they see for a bearer client from that host. `state` is excluded because the mTLS
  identity shim (ADR 0083) stashes the verified peer certificate there. A copied `state` would
  carry the browser connection's certificate into a sub-request.
- **The console extension.** The scope carries one extension, `messagefoundry.console`, holding
  the browser request's `/ui` path and whether the route is a timer-driven poll. Only in-process
  code can set a scope extension: uvicorn builds the scope from the socket, so no network caller
  can supply one. Section 3 says what each field is for. Neither field relaxes a gate.
- **The dispatch target is the full app** (`request.app`), not its router. Every middleware and
  exception handler then runs as for a bearer client. Accepted effects, at least these: the request
  deadline nests, and the outer one fires first; the network gate judges the same copied address
  once per sub-request as well as once for the browser request; the address-monoculture tripwire
  counts each of those passes, which only brings forward a firing it would reach anyway.
- **The transport.** httpx's `ASGITransport` (0.28.1, read from source) cannot carry this. It sets
  `client` once per transport, with a loopback default `("127.0.0.1", 123)`, builds the scope itself
  with no extension hook, and buffers the whole response body. Measured: a route behind the default
  transport saw `('127.0.0.1', 123)`. Left that way, the new-address check and the audit `client`
  column would read loopback for every console action. The build adds a small in-process transport
  in `apiclient` that derives the scope as above and streams the response body, for the attachment
  download and the audit export. A handler exception reaches the console as a 500 response, never
  as a re-raised exception.
- **The client.** `messagefoundry/apiclient`'s `EngineClient` is synchronous over `httpx.Client`.
  Calling it from an async console route would block the event loop (CLAUDE.md section 6). The
  build adds an async client to `apiclient` for the routes the console calls, over that transport.
  `apiclient` stays free of FastAPI and PySide6 (ADR 0088 AC-1): the transport needs only an ASGI
  callable and a scope mapping.

### 2. What the console keeps

**Every console route, other than the reviewed public set, makes at least one sub-request before
it renders.** A route that shows no engine data of its own, such as the upload form or a
confirmation page, sub-requests a new gate-only JSON route, `GET /auth/check`, naming the
permissions of the action the page leads to. Its gate is `require` built from those permissions, so
it runs, in `require`'s order, the MFA access gate with its `auth.mfa_denied` row, must-change
confinement, the notification-address gate, the permission loop with its denial row, the idle-clock
touch and the grant row. `GET /auth/me` cannot serve here: it is exempt from the MFA access gate and
from must-change confinement, and it names no permission, so it writes no grant row. The check
route tells a caller nothing it cannot already read from its own `GET /auth/me`, which lists its
permissions, and it answers a pending session before the permission loop, as `require` does. A form
that would lose an upload to a re-authentication asks the read-only step-up status route (slice 2,
over `step_up_window_live`) first and sends the operator to `/ui/reauth` before showing the form.
That is presentation. The action's own JSON gate is the control.

`require_ui` shrinks to three steps:

1. **Read the cookie and resolve the session read-only** (`activity=False`). No session sends a
   303 to the login page before any sub-request runs. This keeps the documented console ordering:
   an unauthenticated browser gets its login redirect, never a PHI hop refusal naming the
   instance's posture. The row's design said "read the cookie" only. This step is the smallest
   addition that keeps that ordering. The identity it returns is for display, at least which
   navigation links to draw.
2. **Same-origin on every non-GET**, before the sub-request, as `assert_same_origin` runs today. The
   JSON plane has no CSRF check because a bearer header is not ambient. The console turns an
   ambient cookie into that header, so this check stays in the console. It is the one control left
   in the console wheel, and AC-7 pins it.
3. **Turn a JSON answer into a browser answer.** One table, one function:

   | JSON answer | Console answer |
   |---|---|
   | 401 | 303 to the login page, noting expiry when a cookie was sent |
   | 403 with `X-MFA-Required` | 303 to `/ui/reauth` with a server-issued continuation when the `/ui` route is a registered continuation; otherwise 303 to `/ui/mfa` |
   | 403 with `X-Step-Up-Required`, reason new address | 303 to `/ui/reauth`, continuing as `_new_address_continuation` decides today: a PHI page returns to itself, and a write lands on `/ui` |
   | 403 with `X-Step-Up-Required`, any other reason (with `X-Step-Up-Action` and the IdP marker when set) | 303 to `/ui/reauth`, with a server-issued continuation when the `/ui` route is a registered continuation |
   | 403 with `X-Notify-Email-Required` | 303 to the notification-address page |
   | 403 for a must-change session | 303 to the change-password page, or `/ui/mfa` first when a factor is owed |
   | Any other 403 | the console's forbidden page |
   | 429 with `Retry-After` | the console's throttled page, carrying the same `Retry-After` |
   | Any other status | the status and detail the console renders for an `HTTPException` today; `/ui/nav-status` keeps its own "engine down" reading of a failed read |

   Two rows need a header the JSON plane does not send today, and slice 2 adds both. The
   must-change refusal carries only a detail string. A new-address refusal and a stale step-up
   window are the same 403 from `_step_up_refusal`, so the refusal gains a reason header. The
   console's continuation registry (`register_ui_action`) says only which `/ui` routes may be
   resumed after a re-authentication. That is navigation, not gate knowledge, and it stays.

ADR 0065 section 3's boundary holds unchanged. A browser request to a JSON route that carries only
the cookie still gets a 401, which AC-8's existing test pins. Only the console's in-process transport
turns a cookie into a bearer header, and only after steps 1 and 2.

**What else leaves the console.** `UiDeps.get_engine`, `UiDeps.get_gate`, and every console read of
`AuthService` outside the sign-in legs, such as `admin.py`'s direct `service.store.get_user` read,
go too, each replaced by a JSON route. Otherwise a route could still read the engine behind a
session check alone.

**Two console behaviours survive as presentation.** The JSON action gates spend an action-bound
proof in the gate. Today `require_ui_step_up_action` can instead hold a proof unspent
(`spend=False`, used by unlock pages) and tolerate a double-click (`repeat=`, vault #2625). Both
become presentation over the JSON answer, never a way past it:

- A double-click's second POST gets the JSON 403 for an action proof already spent. When the same
  session's same `/ui` action succeeded within the window `repeat=` uses today, the console renders
  "already submitted" rather than sending the operator to re-authenticate. The action is refused
  either way.
- An unlock page asks the read-only step-up status route whether the session holds a live proof
  for an action, without spending it. Slice 2 adds that route, which also reports whether the
  session's step-up window is live.

**One write per POST.** A console write route makes one write sub-request and then redirects. Any
read it shows comes on the following GET, so a later refused read cannot report a completed write
as refused.

### 3. The four costs the row names, answered

1. **The browser's address.** Answered in section 1: the derived scope copies `client`. The
   new-address check asks once per PHI read or paced write. It is deduped and capped per session
   (`AuthService.flag_new_client_ip`), so a page that makes several sub-requests writes no extra
   rows.
2. **The PHI budget per handler call.** Charge per sub-request, with no exemption. The detail page
   with its body open calls `get_message` and `get_message_body`, so it costs two, as it costs a
   bearer client reading the same two resources. At the shipped
   `phi_read_rate_limit_per_actor = 120` per 60-second window, that still allows 60 body views a
   minute, above any human's pace, and the setting is per actor. A per-page exemption would be a
   mechanism that only lowers a control, so none is proposed. One effect follows: near the limit,
   the first read can succeed, with its `message_view` audit row, and the second can be refused.
   The row records a read the engine did serve, to the console process, and the operator sees the
   throttled page.
3. **Polled routes: the idle clock and the grant row.** `/ui/nav-status` calls three to five
   handlers every 15 seconds per tab (`system_status`, `dr_status`, `cluster_status`, then
   `cluster_nodes` when clustered and `list_active_alerts` with `monitoring:diagnose`). As separate
   sub-requests that is 720 to 1,200 an hour per tab. Under `[diagnostics].audit_all_authz`, on by
   default, each would write a grant row and touch the session's idle clock.
   - *Idle clock:* the extension's poll flag makes the JSON gate resolve the session with
     `activity=False`, as five `/ui` routes do today. It can only let a session age out sooner, so
     it relaxes nothing.
   - *Grant rows:* every sub-request writes its grant row, as a bearer request does. There is no
     deduplication: rows for different permissions or paths record different decisions, and
     dropping one would drop a decision. The volume is answered by composition instead. A polled
     page that needs several JSON reads gets one JSON route that composes them, so each poll is one
     sub-request. At least `/ui/nav-status` gets one, gated `monitoring:read`, with its alert count
     present only under `monitoring:diagnose`, as the console checks inline today. That is 240
     rows an hour per tab, and a bearer client gets the same one-call rollup. Each row records the
     JSON path that was authorized and names the console route from the extension, so an
     investigator can tell a console action from a bearer call.
   - Whether timer-driven reads should write grant rows at all is a question for both planes
     together. It is listed for the owner below, not decided here.
4. **One JSON encode and decode per call.** Measured on a stand-in FastAPI app, not the engine: a
   sub-request through an in-process transport plus decoding a 2,961-byte response took about
   0.44 ms (2,000 calls, Python 3.14.7, FastAPI 0.146.0, httpx 0.28.1). The engine's middleware
   stack adds to it, and that is unmeasured. The first migration group measures `/ui/nav-status` and
   one PHI page before and after, on the engine.

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
`add_auth_routes`, and once `UiDeps` stops carrying them and the engine accessors, no console module
holds a way in. AC-1 pins that.

### 6. What it must not break

No pipeline invariant is touched: no stage, handoff, ACK or disposition changes. Every PHI-access
audit row the handlers write today is still written, by the same handler, with one change the build
must make: `get_message_body` records `surface: console` only when the matched route starts with
`/ui/`, and a sub-request matches the JSON route. It reads the console extension instead, so a
console body view still records `console`. Channel scope still comes from the identity the handler
is given, now by the JSON gate. With zero deployments there is no older console wheel to keep
working. The seam digest moves and the startup handshake refuses the skew, so no compatibility shim
is built.

### 7. What this amends, once accepted

It supersedes no ADR whole. It amends two, and their text changes only when this one is accepted.

- **ADR 0065.** The handler reuse in section 6 and the M2b addendum: `/ui` routes stop calling
  handlers and stop re-applying gates (`require_ui_step_up` and its family). Section 1's in-process
  mount and section 3's cookie confinement stand, and section 2 of this ADR restates the latter.
- **ADR 0088.** `apiclient` gains an async client and the in-process transport beside
  `EngineClient`. Its acceptance criteria stand.

## Acceptance Criteria

The files for AC-8 and AC-9 exist today. Each slice in the build order writes the others' tests.

- **AC-1** — WHEN the console is mounted, THE SYSTEM SHALL inject no engine handler and no engine
  or approval-gate accessor into it: `UiDeps` SHALL carry no `CoreHandlers`, `AdminHandlers`,
  `get_engine` or `get_gate`, and the console's `AuthService` use SHALL be limited to a reviewed
  list of sign-in-leg methods.
  → `packaging/messagefoundry-webconsole/tests/test_console_calls_json_routes.py`
- **AC-2** — WHEN a console route serves a browser request from address A, THE SYSTEM SHALL present
  A as the client of every sub-request it makes, so the new-address check and the audit `client`
  column read A.
  → `tests/test_inprocess_transport.py`
- **AC-3** — WHEN the console makes a sub-request, THE SYSTEM SHALL send exactly one
  `Authorization` header built from the session cookie, no other browser header except a passed
  body's `Content-Type`, and a scope holding no copied `state`.
  → `tests/test_inprocess_transport.py`
- **AC-4** — WHEN a console route other than the reviewed public set serves a request, THE SYSTEM
  SHALL make at least one sub-request before it renders.
  → `packaging/messagefoundry-webconsole/tests/test_console_calls_json_routes.py`
- **AC-5** — WHEN a timer-driven console poll makes a sub-request, THE SYSTEM SHALL leave the
  session's idle clock where it was, and SHALL write the grant row a bearer request would.
  → `packaging/messagefoundry-webconsole/tests/test_console_calls_json_routes.py`
- **AC-6** — IF a JSON route refuses a console sub-request, THEN THE SYSTEM SHALL answer the browser
  with the row of section 2's table that matches, and SHALL run no handler for that sub-request.
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
- **AC-10** — WHEN the console serves an attachment or the audit export, THE SYSTEM SHALL stream
  the sub-response through the in-process transport without buffering it whole.
  → `tests/test_inprocess_transport.py`
- **AC-11** — WHEN the console views a message body, THE SYSTEM SHALL record the body view's
  surface as `console`.
  → `packaging/messagefoundry-webconsole/tests/test_console_calls_json_routes.py`

## Build order

Each slice is one pull request, and each names what closes it.

1. **Inventory.** Classify every `/ui` route by the JSON route that carries its authority, and
   every way the console reaches the engine: the 86 seam fields, `get_engine`, `get_gate`, and its
   `AuthService` reads. Of the 86 fields, 66 are, by object identity, the endpoint of a JSON route.
   The other 20 are reached by a JSON route through a wrapper or have no JSON route, at least the
   three presentation helpers `user_summary`, `current_user` and `federated_identity_view` and the
   console's composite `search_messages`. For each without a route, name the route to add or move
   the helper into the console. *Closes:* a test pins each route's and each field's class.
2. **Engine-side prerequisites, additive.** The extension reader in `api/security.py` (the poll
   flag; the console route on the grant row), the body-view surface read, the must-change refusal
   header, the step-up refusal's reason header, `GET /auth/check`, the read-only step-up status
   route, the composite poll routes (at least the nav rollup), and any JSON routes slice 1 found
   missing. Each new route gets its gate, its policy class and its route-map row. With no
   extension present, a bearer client sees no change beyond the new headers and routes. *Closes:*
   the JSON-plane halves of AC-5 and AC-11.
3. **The transport and the async client.** The derived scope, response streaming, fresh headers.
   *Closes:* AC-2, AC-3, AC-10, and ADR 0088 AC-1 still green.
4. **The shrunk gate and the refusal map.** *Closes:* AC-6, AC-7, and AC-8 still green.
5. **Migrate by page group, in this order:** monitoring and status reads (with the before and after
   measurement in section 3), PHI reads, connection and message writes, step-up and action-bound
   writes, then administration. Each group removes its fields from the bundles and deletes the
   `require_ui*` variants it no longer uses. *Closes per group:* its routes reach no seam handler,
   by call or by reference, and the seam digest moves.
6. **Remove the second family.** Delete at least: `CoreHandlers`, `AdminHandlers`, `get_engine` and
   `get_gate` from `UiDeps`; the rest of the `require_ui*` factories; the console step-up spend
   machinery other than the presentation in section 2; and every test and table that pairs console
   routes with JSON routes, among them `_UI_JSON_COUNTERPARTS` and the tests that read it,
   `test_ui_gate_divergences_are_exactly_the_reviewed_set`, and the parity planted-weakening
   control. Shrink `authorize_ui_ws` to cookie and origin, and hand the token to the checks
   `authorize_ws` runs, so the WebSocket writes its grant row too. Move the seam digest from
   handler signatures to the OpenAPI operations the console's client names, so a renamed query
   parameter or path moves it (FastAPI ignores an unknown query parameter, so a skewed console
   would otherwise lose a filter silently). Update `docs/SECURITY.md`'s `/ui` route map and
   `docs/WEBCONSOLE-PACKAGE.md` sections 1 and 2. *Closes:* AC-1, AC-4; #1197's console grant-row
   limb; and the handler-signature half of #2424.
7. **The policy table** (section 4). Independent of slices 1 to 6. *Closes:* AC-9.

## Options considered

1. **Sub-requests through the ASGI app, with a derived scope and one console extension.**
   **CHOSEN.** It deletes the second gate family rather than guarding it. Route gates then ship in
   the engine wheel, so no console wheel chooses one, and the console limb of #1197 closes as a
   side effect.
2. **Keep both families and strengthen the parity guard** to pair by the handler a route calls.
   Rejected. Since engine PR 2341 the handshake refuses a console wheel whose route gates differ,
   but the gate on each new console route is still chosen by hand, and route bodies and engine
   helpers stay outside every guard. A stronger guard narrows the window and keeps the defect class.
3. **The proof-object design** (`Authorized[Op]`). Rejected for the reasons in section 5.
4. **Stock httpx `ASGITransport` with one transport per browser request.** Rejected. It can set the
   client address but not the console extension, so it cannot carry the poll flag or the console
   route, and it buffers whole response bodies, so it cannot stream an attachment or the audit
   export.
5. **Dispatch to the app's router, skipping the middleware a second time.** Rejected. A route
   reads its exception handlers from a scope key that Starlette's exception middleware sets
   (`starlette.exception_handlers`, read in `starlette/_exception_handler.py`). Without it, a gate's
   `HTTPException` escapes as an exception rather than becoming the 403 the refusal map reads.
   Copying that private key from the browser request would work, and would tie the console to a
   Starlette internal. Full-app dispatch makes the sub-request equal to a bearer client's request by
   construction rather than by argument, and running the middleware a second time costs less.
6. **Deduplicate grant rows per browser request.** Rejected. Rows for different permissions record
   different decisions, and the JSON plane's one-row ceiling is per route, not per operator action.
   Composite poll routes cut the volume without dropping a decision.

## Consequences

**Positive** — One gate family. The console cannot reach a handler, the engine or the approval
gate without a JSON gate, and a future in-process caller has no handler reference to reach for.
Route gates ship in the engine wheel. Every console action gets a grant row. Six drift rows' worth
of hand-synchronised checks go away, with the parity tests that watched them. A later step that
moves the JSON plane into a separate management process takes the console with it, and only the
transport changes.

**Negative / risks** — More work per console page: a session resolution per sub-request where there
was one per page, and an encode and decode per call. The engine-side cost is unmeasured until slice
5 measures it. The PHI budget is spent faster on pages that read two resources. The derived scope
is security-relevant code: if it copied the wrong key, or failed to copy `client`, it would silently
weaken the new-address check, the audit trail or the mTLS identity. AC-2 and AC-3 are its guards.
The same-origin check stays in the console wheel. Grant rows from the console add audit volume
where there were none. New JSON routes are added, at least `GET /auth/check`, the step-up status
route, the composite poll routes and the ones slice 1 finds, each needing its own gate and route-map
row.

**Out of scope** — The console's own sign-in, sign-out, factor, re-authentication, OIDC and passkey
legs. They establish and step up the session rather than use a handler, and they keep calling
`AuthService`. Moving the JSON plane out of the data-plane process needs its own ADR. Channel-scope
enforcement is unchanged; it stays where the handlers apply it.

## To resolve on acceptance

- [ ] The owner accepts or rejects this design. Acceptance is the owner's, and this ADR stays
      Proposed until then.
- [ ] Timer-driven reads: should they write a grant row (240 an hour per tab for `/ui/nav-status`
      under this design, the same as a bearer client polling the rollup), or should both planes
      exempt them under `audit_all_authz`? A console-only exemption would re-open a plane
      difference, so this design does not take one.
- [ ] Is the grant row's form right: the authorized JSON path, with the console route named beside
      it?
- [ ] After slice 5's measurement, is one session resolution per sub-request acceptable, or should
      the gate memoise the session for the length of one browser request?
