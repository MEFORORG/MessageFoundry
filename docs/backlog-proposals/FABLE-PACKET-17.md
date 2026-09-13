# Proposed backlog items from Fable review packet 17 (API and web console parity)

**Disposable.** This file exists so the proposals travel with the engine PR; the Manager allocates
the numbers serially (owner instruction 2026-09-12: no packet runs `alloc.ps1`) and writes the items
into `docs/BACKLOG.md`. Delete this file in the same change. No number below is allocated or guessed;
where a finding already has a record, the record is cited.

Reproductions, measurements and the round-2 critic notes are in the vaulted
`docs/reviews/FABLE-PACKET-17-PARITY-2026-09-11-FINDINGS.md` (vault branch
`vault/fable-packet17-parity`). Reviewed ref: engine `fa7bc9e3e`, branch `review-p17`.

**Every impact claim is conditional.** There are zero deployments (`CLAUDE.md` section 0).

---

**B-1 (P17-01). the console's user-update route rides the shared step-up window while its JSON twin requires the action-bound single-use grant, so a login-seeded session can disable an account or change its notice address from the browser**
**Cluster:** auth / step-up parity across the console seam. **Priority:** P1. **Verdict:** build.
**Severity:** conditional (sec. 0). High. On a first deployment a session hijacked inside the login window could disable any account or redirect its security notices through the only shipped operator surface, while `PATCH /users/{id}` refuses the same request with `X-Step-Up-Action: admin_user_update`.
`routes/admin.py` `ui_user_update` is gated `require_ui_step_up`; `auth_routes.py` `update_user` is gated `require_step_up_action(STEP_UP_ACTION_ADMIN_USER_UPDATE, ...)`, and the constant appears nowhere in the console. Measured at `fa7bc9e3e`: JSON 403, console 303 with the display name changed and the account disabled. Fix: the console twin of what `routes/admin.py` already does for reset-password and reset-MFA (action-bound factory plus a tagged unlock continuation), and a stale-window test; the whole console suite stayed green with the gate removed. Reproduction: findings P17-01, part 6 control A.
**Duplicate search:** no match by `admin_user_update`, `users/{user_id}/update`, `require_ui_step_up_action` with `USERS` in either ledger. Related: #1148 (the reset lanes, since bound).

**B-2 (P17-02). the console's PHI reads skip the ADR 0092 serve-hop guard that require_phi_read folds in, so a refused hop would refuse PHI on the JSON API and serve the raw body from the console**
**Cluster:** PHI containment / console seam. **Priority:** P2. **Verdict:** build.
**Severity:** conditional (sec. 0). Medium. A production-PHI instance whose serve hop is not proven secure would emit the raw message body, parse tree and summaries from `/ui` while every JSON PHI read answers 403. Reachability is defence in depth: `serve` refuses the cleartext bind first and mints TLS, so the state is met by an embedder or a later posture change rather than on the default path.
`require_ui(phi=True)` re-applies the permission and throttle and never calls `enforce_phi_read_hop`; the console reaches `get_message`, `list_messages`, `list_dead_letters` and `download_attachment` by reference, skipping the dependency that carries the guard. Measured with the disposition set to REFUSE: four JSON routes 403, four console routes 200 (two with the body), the search route 403 because its handler guards in the body. Fix: one call in `require_ui` when `phi=True`, plus a test. Reproduction: findings P17-02.
**Duplicate search:** no match by `enforce_phi_read_hop`, `phi_read_hop`, `hop guard` with `console` or `/ui` in either ledger.

**B-3 (P17-03). the console upload route carries no step-up while POST /uploads requires one, so a stale-window session could place a PHI file at rest from the browser**
**Cluster:** PHI at rest / step-up parity across the console seam. **Priority:** P2. **Verdict:** build.
**Severity:** conditional (sec. 0). Medium. On a first deployment a session past its step-up window could import a PHI file through the browser where the engine's own gate design owes a fresh re-verification.
`routes/uploaded_logs.py` `ui_uploaded_logs_upload` is `require_ui(FILES_UPLOAD)`; `app.py` `upload_file` is `require_step_up(FILES_UPLOAD)`. The module docstring records the reason (a body-carrying POST cannot cross the re-auth redirect); the same file and `routes/admin.py` already solve that with a registered unlock GET, and `GET /ui/uploaded-logs/upload` is that form. Measured with a stale window: JSON 403, console 303 and the file listed with an `upload.create` row. Fix: `require_ui_step_up(FILES_UPLOAD, reauth_next=...)` plus `register_ui_action(..., unlock=True)` and a test; the uploaded-logs suite stayed green with the permission removed. Reproduction: findings P17-03, part 6 control B.
**Duplicate search:** no item carries it. #1227 (closed) notes "upload has no step-up either" in passing while fixing resend. Related: #1227, #1152.

**B-4 (P17-04). the console's own GET and control routes skip every path and query rule api/validation.py defines, and a rule-refused connection name lands in the tamper-evident audit chain from the browser (the console build remainder of BACKLOG #1108)**
**Cluster:** input validation / console seam. **Priority:** P2. **Verdict:** build.
**Severity:** conditional (sec. 0). Medium. On a first deployment any channel-scoped operator could write a forged or garbage channel name into `auth.channel_denied` rows, and any searcher into `message_search` rows, from the browser; the hash chain keeps them for the life of the store. The off-box tee escapes the value (measured) and the CSV export quotes it (measured), so this is chain integrity and a line-oriented consumer, not log forgery.
The JSON routes type `channel_id`, `destination_name`, `connection`, `{name}`, `status`, `message_type`, `control_id`, `kind` and every id with `api/validation.py` rules; the console routes into the same handlers (`ui_messages`, `ui_dead_letters`, `ui_message_search`, `ui_events`, the three per-name controls, bulk control and purge) declare length bounds only, and a direct handler call runs no parameter validation. Measured: 422 on four JSON routes, 200 or 403 on their console twins, the forged value stored byte for byte. The console's own `uploaded_logs.py` states the rule: the console must not be the looser of the two doors. Fix: import the `Annotated` rules the JSON routes use, convert the two datetime-local items then apply `EpochSeconds`, one 422 test per console route, and a golden-table drift guard. Reproduction: findings P17-04.
**Duplicate search:** the class is recorded in #1108's remainder paragraphs (a) and (b) as text inside an open research item whose closing act is a scorecard rescore; no build item exists and the consequence measured here is not recorded there. The Manager may fold this into #1108 rather than allocate it.

**B-5 (P17-05). the console health heart ignores connection state, reporting ok with no reason for an empty configuration and for an inbound that failed to bind, while GET /connections reports the row failed**
**Cluster:** status display / console. **Priority:** P2. **Verdict:** build.
**Severity:** conditional (sec. 0). Medium. On a first deployment the always-on heart would show green over an engine listening on nothing (packet 8's empty-configuration case) and after a port conflict on the only feed, with no alert; the dashboard row is right and the signal an operator watches is wrong.
`routes/status.py` `_derive_health` weighs store, disk, pool, DR and leadership and nothing about connections. Measured: empty engine, heart `ok`, status "0/0 running"; MLLP inbound on an occupied port, JSON `/connections` `failed`, heart `ok`, reason null, alerts 0. Fix: any deployed inbound in `failed` state is at least `warn` naming it; zero deployed inbounds on a started engine is `warn`. Whether a bind failure should also raise an alert instance is a pipeline question. Reproduction: findings P17-05.
**Duplicate search:** no match by `nav-status`, `_derive_health`, `health heart`, `empty config` with `console` or `health` in either ledger.

**B-6 (P17-06). the console step-up factories refuse an MFA-pending session without the auth.mfa_denied row the JSON twin writes, and run the permission loop first, so a password-only cookie learns which permissions it holds**
**Cluster:** audit completeness / MFA gate ordering / console seam. **Priority:** P2. **Verdict:** build.
**Severity:** conditional (sec. 0). Medium. On a first deployment a stolen password-only cookie could enumerate its victim's permissions over about thirty step-up console routes by status code (403 versus 303) and leave no MFA-denied row on any of them; the plain console routes were closed on 2026-09-03 under #1197 and the step-up family was not in that change.
`_auth.py` `require_ui_step_up` and its three siblings build on `require_ui(..., allow_mfa_pending=True)`, run the permission loop, then check `mfa_satisfied` and redirect with no audit call; `api/security.py` `require()` documents the opposite order as load-bearing. Measured with `require_mfa=True` and no factor: JSON replay 403 plus one row; console replay and edit 303 plus zero rows; console reload and users/new 403 with `permission_denied` rows before any factor was proven. Fix: factor check before the permission loop in the four factories, `audit_mfa_denied` before `_reauth_redirect`, two tests. Reproduction: findings P17-06.
**Duplicate search:** #1197 (open) recorded and closed the plain-route and WebSocket halves; its proposed-work list names neither the step-up factories nor the ordering. Related, not the same.

**B-7 (P17-07). the console bulk connection control writes the channel-denied row with a NULL client where the per-name and JSON controls carry the browser address**
**Cluster:** audit attribution / ADR 0150. **Priority:** P3. **Verdict:** build.
**Severity:** conditional (sec. 0). Low. ADR 0150 says NULL means no client was in scope; for this row the browser was.
`routes/connection_writes.py` `ui_bulk_control` calls `core.dual_role_control(...)` without the `client=` keyword the primitive takes. Measured: JSON stop and console per-name stop `127.0.0.1`, console bulk stop `None`. Fix: pass `client_ip(request)`. Reproduction: findings P17-07.
**Duplicate search:** no match by `bulk-control`, `dual_role_control`, `bulk control` in either ledger. Related: packet 7's P7-05 (a different site).

**B-8 (P17-08). the console reaches only the first page of every paginated API surface, presents the newest 200 audit rows as "the full trail", and derives its per-channel dead-letter replay controls from the rendered page**
**Cluster:** console pagination / status display. **Priority:** P3. **Verdict:** build.
**Severity:** conditional (sec. 0). Low. An operator would read the newest 200 audit rows as the trail and would not see a channel whose dead deliveries are older than the first page; the per-channel replay for it exists only on the JSON API.
Messages and dead letters render a count line with no navigation; audit, events and alerts render a first page with no count; only uploaded logs has a pager (#1152). `auth_routes.py` `_audit_ui_list` says "The UI shows the full trail". Measured: 50 of 120 messages with no next link, 200 of 269 audit rows under the full-trail heading, 100 of 130 events, and a dead-letter channel absent from the page and from the replay controls. Fix: one pager helper on the four lists, store-side distinct channels for the replay controls, and a corrected sentence. Reproduction: findings P17-08.
**Duplicate search:** no match by `_audit_ui_list`, `pager`, `paginat` with `console` or `/ui` in either ledger. #1152 (open) covers the uploaded-logs pager only.

**B-9 (P17-09). two console routes silently substitute a value where the JSON twin refuses the input: an out-of-range alert suspend becomes sixty minutes and audits as sixty, and a malformed received-date bound is dropped**
**Cluster:** input validation / console. **Priority:** P3. **Verdict:** build.
**Severity:** conditional (sec. 0). Low. An operator would be told a suspend or a filter succeeded when the engine did something else, and the audit row would record the substitute as the request.
Measured: JSON suspend with `minutes=999999` 422; console 303, suspended for 60.0 minutes, `alert_suspend` row `"minutes": 60.0`. The date branch was read, not measured. Fix: refuse with 400 and re-render with the error, as `routes/search.py` does. Reproduction: findings P17-09.
**Duplicate search:** no match by `suspend` with `fallback` or `60 minutes`, `datetime-local` with `drop`, in either ledger.

**B-10 (P17-10). no console test can see the step-up gate removed from the user-update route or the permission removed from the upload route**
**Cluster:** test quality / console gates. **Priority:** P3. **Verdict:** build.
**Severity:** no deployment axis for the tests themselves; the gates they should pin are shipped controls. Low.
Control A (user-update gate reduced to plain `require_ui`): the whole console suite 490 passed. Control B (upload permission removed): 21 passed. Control C (list-page permission removed): 1 failed, so the instrument sees the class. Fix: a parametrised stale-window test over the golden write-action and step-up sets, and a permission-denied test per console POST. Reproduction: findings part 6. May be folded into B-1 and B-3 if the Manager prefers the tests to land with the fixes.
**Duplicate search:** no match. Packet 7's P7-04 recorded the same shape for seven audit writes on the API side.

---

**Findings deliberately not filed.** The three dead `app.js` features and the JSON-only export, log-level and log-tail routes: already recorded under #124 and #171. The console's missing grant row: #1197, test-pinned. The console halves of packet 7's P7-02 and P7-03: confirmed by execution here, covered by packet 7's proposals. The deliberate asymmetries (edit-resend requiring `view_raw`, the user detail page requiring `users:manage`, the stepdown control hidden with a reason): not defects.
