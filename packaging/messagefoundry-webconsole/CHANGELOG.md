<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Changelog — messagefoundry-webconsole

All notable changes to the **web console** distribution (`messagefoundry-webconsole`) are documented
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is **separately versioned** from the engine and pins itself to the engine's
`api._ui_seam.ENGINE_UI_SEAM` via `SUPPORTED_ENGINE_SEAMS`; each entry records the supported engine
seam. Entries from before BACKLOG #1220 quote the integer that shipped at the time. A release since
then quotes the digest it shipped with. The Unreleased entry points at the constant instead, because
nobody picks that value and it can move until the release is cut. See
[`docs/WEBCONSOLE-PACKAGE.md`](../../docs/WEBCONSOLE-PACKAGE.md) for the seam handshake and the
engine compatibility range.

## [Unreleased]

**Supported engine UI seam: the single value in `SUPPORTED_ENGINE_SEAMS` -- read it from
[`messagefoundry_webconsole/__init__.py`](../../messagefoundry_webconsole/__init__.py), not from
this line.**

**Requires an engine newer than 0.4.0**, one whose `messagefoundry.api._ui_seam.ENGINE_UI_SEAM` is
that value. Console 0.3.0 does not work with that engine, so upgrade the two together. The entry
under Changed says why engine 0.4.0 does not work with this console.

### Added
- **An administrator can link, relink and unlink a user's federated (OIDC) identity** (`BACKLOG
  #1143`, `BACKLOG #295`, ADR 0184 slice B).
  - The user page gains a Federated sign-in card. It shows the issuer and `sub` the account is
    linked to, or says it is not linked.
  - `/ui/users/{user_id}/federated-identity` shows the link and offers Link, or Relink when one
    exists. `/ui/users/{user_id}/federated-identity/unlink-confirm` states what an unlink does
    before the one button that does it.
  - Both changes call the engine's own `PUT` and `DELETE /users/{user_id}/federated-identity`
    handlers. Each POST needs a fresh re-authentication for the action
    `admin_federated_identity`. A recent sign-in does not count, unless the site set
    `[auth].require_action_step_up = false`. A POST without one goes through `/ui/reauth` and
    comes back to the page, so the operator submits again.
  - Each attempt uses up its re-authentication, including one the engine refuses. The refusal
    page shows the reason in words and keeps the typed `sub`, and trying again asks for the
    password first.
  - Each form posts back the link it showed. If another administrator changed the link since
    the page opened, the POST is refused and the page shows the current link. The check runs
    before the engine's handler and does not serialise against a concurrent write. So a stale
    page can still replace or remove a link another administrator set at the same moment. A
    later slice would move the check into the service's bind and unbind.
  - An administrator's own account shows no form, and the engine refuses a POST on it. A local
    account, or an engine with no `[auth].oidc_issuer`, shows no Link form.
  - Needs the new engine seam: `AdminHandlers` gained the two handlers and the
    `federated_identity_view` projection, which returns the new `FederatedIdentityView`.
- **Pages that issue or enforce an admin-set temporary password now say when it stops working**
  (`BACKLOG #1141`, PR 1456). The engine refuses such a password once
  `[auth].initial_password_expiry_hours` have passed since it was set.
  - The create-user form states that window in hours. The account does not exist yet, so the form
    cannot state an instant.
  - A user's page states the instant while that user still owes a password change. The create form
    lands on the new account's page.
  - The forced change-password page, `/ui/account/password`, states the same instant. It adds that
    after that time an administrator has to reset the password. The page keeps the sentence when
    it re-renders after a rejected attempt.
  - Nothing is stated when no deadline applies. That includes a setting of `0` or less, a password
    the user chose, and the first-run bootstrap account while it is still unclaimed.
  - Each instant is the one the engine's sign-in check enforces, read from the stored stamp. It is
    shown in UTC.

### Changed
- **BREAKING — the engine UI seam moved again, so this console no longer pairs with engine 0.4.0**
  (`BACKLOG #1141`, PR 1456). `SUPPORTED_ENGINE_SEAMS` no longer holds `75c4117d21fd0b98`, the
  seam engine 0.4.0 ships. The line at the top of this section says where to read the value it
  holds now, which can move again before the release. The console now imports three helpers from
  `messagefoundry.api.security`: `pending_credential_deadline`, `pending_credential_deadline_for`
  and `initial_credential_window_hours`. Engine 0.4.0 has none of them. So with the console on,
  engine 0.4.0 fails while importing this console and reports it as not installed. It never reaches
  `UiSeamMismatch`. Same one-value `SUPPORTED_ENGINE_SEAMS` rule as 0.2.15 (`BACKLOG #279`).
  **Migration:** upgrade the engine and the console together. Or set
  `[security].serve_web_console = false` on the engine to run its JSON API alone.

### Fixed
- **The reset-password page no longer fails with a `500` when the temporary password's deadline is
  too far out to render** (`BACKLOG #1141`, PR 1456). Console 0.3.0 formatted the deadline with no
  guard. It raised past year 9999, or past year 3000 on Windows, which a large
  `[auth].initial_password_expiry_hours` can reach. By then the reset had already replaced the
  password, so the administrator never saw the new one. The page now drops the deadline sentence
  instead, and so do the new deadline sentences under Added.

### Security
- **The user page sets the notification address in its own field** (`BACKLOG #1139`, ADR 0182
  Amendment A). The page's Email field is pre-filled with the stored profile address and posted
  back on every save, and the engine copied it into the notification address. So saving a display
  name or a disable moved where security notices go, or filled a missing address from the
  directory. The engine no longer does that. The page now shows a Notification address field,
  pre-filled with the stored value, and a hidden copy of that value. The route sends the address
  only when the administrator changed it from what the page showed, so an unrelated save moves
  nothing, and a page left open cannot undo another administrator's change. Emptying the field is
  refused with an error, because the address cannot be cleared. A new value moves it and notifies
  the old address. **Requires an engine whose `UserUpdateRequest` carries `notify_email`**, which
  moved the engine UI seam. An older engine's model refuses the key, so every address change would
  fail as "invalid input". This console refuses that engine at startup with `UiSeamMismatch`
  instead.
- **The notification-address page suggests the address already on the account** (`BACKLOG #1139`).
  Engine PR 1522 added `/ui/account/notify-address`, where an account with no notification address
  is confined while the engine sends security notices. Its input now starts with the account's
  profile address, `users.email`, when that passes the same checks as a submitted address. On a
  directory account that is the last `mail` the directory supplied. A line under the input names
  the source and asks the holder to change it if it is not theirs. A pre-filled input is not
  focused on load. Opening the page writes nothing; the address is set only when the holder
  submits the form. Only a pure-ASCII address with no Punycode (`xn--`) domain label is suggested.
  So a directory writer cannot pre-fill a lookalike built from non-ASCII letters, such as a Cyrillic
  `a`. An all-ASCII lookalike such as `examp1e.org` is still offered, and the line under the input
  is what asks the holder to check it. The submit still accepts what it did.
  **Requires an engine with `AuthService.suggested_notify_email`**, which moved the engine UI seam
  again. An engine at PR 1522 lacks that method and ships the older seam, so this console refuses
  it at startup with `UiSeamMismatch` rather than failing on the page.
- **Ending a session or enrolling a factor from an MFA-pending session now needs the existing
  factor first, on an account that has one** (`BACKLOG #1951`, PR 1469).
  `require_ui_reauth_only_action` skips the MFA check, so that an account with no factor can still
  enrol one and end its own sessions. It guards `POST /ui/account/sessions/{session_id}/revoke`,
  `POST /ui/account/sessions/revoke-others`, `POST /ui/account/mfa/enroll`,
  `POST /ui/account/mfa/verify` and `POST /ui/account/webauthn/enroll`. For an account with a TOTP
  factor or a passkey, it now refuses a pending session itself. It writes an
  `auth.mfa_denied` audit row and redirects to `/ui/reauth`, which asks for the second factor as
  well as the password. Console 0.3.0's gate left this to its step-up check. That check covered
  the three enrol routes, wrote no audit row, and did not cover the two session routes. An account
  with no factor is unaffected. Other routes also skip the MFA gate, and this change does not
  cover them. At least `POST /ui/account/webauthn/verify`, `GET /ui/account/mfa/confirm` and
  `/ui/account/password` are among them. **The session-route half needs the engine side of the
  same PR.** That side adds `session_terminate` to the actions `AuthService` refuses to a pending
  session; engine 0.4.0 does not refuse it. The seam digest does not record that behaviour. On
  `main`, PR 1469 merged before the seam moved, so an engine released from `main` with this
  console's seam carries both halves.

### Notes
- **Not every `/ui` change needs a console change.** PR 1432 touched only a console test fixture,
  yet the console's OIDC sign-in now needs the IdP's `auth_time` claim (`BACKLOG #296`). That rule
  lives in the engine, and the engine's own `CHANGELOG.md` records it. Read that file too for
  engine changes that reach `/ui`.

## [0.3.0] — 2026-09-23 — Early Access

**Requires engine 0.4.0. Supported engine UI seam: `75c4117d21fd0b98`**, the value engine 0.4.0
ships as `messagefoundry.api._ui_seam.ENGINE_UI_SEAM`. With the console on, any other engine refuses
to start, and that includes every 0.3.x engine. A 0.3.x engine never reaches `UiSeamMismatch`: it
fails while importing this console and reports the console as not installed. Console 0.2.15 does
not work with engine 0.4.0 either, so upgrade the two together.

### Added
- **High Availability page** (BACKLOG #1495, ADR 0056). `/ui/cluster`, under Monitoring, renders
  cluster membership, each node's state and the leadership lease from whichever node serves it, and
  refreshes every 5 seconds. It carries one control: a planned stepdown of the node serving it, behind
  a step-up confirm page, plus a separate forced drain for the last promotable node. Each refusal the
  engine returns (400, 409, 412, 503) gets its own guidance. It renders no VIP owner, because the
  engine binds no address.

### Changed
- **The engine UI seam moved for the `/ui` PHI serve-hop refusal** (BACKLOG #1738): `_auth.py` now
  imports `api.security.enforce_phi_read_hop`, and seam discovery derives the console's security
  surface from those import statements, so the import alone moves the digest. Same one-value
  `SUPPORTED_ENGINE_SEAMS` rule as 0.2.15 (BACKLOG #279).
- **The engine UI seam moved for the High Availability page** (BACKLOG #1495): `CoreHandlers` gained
  `cluster_stepdown`, and the console now constructs `ClusterStepdownRequest`. Same one-value
  `SUPPORTED_ENGINE_SEAMS` rule as 0.2.15 (BACKLOG #279).

### Security
- **The console upload POST now carries the step-up its JSON twin has** (BACKLOG #1739).
  `POST /ui/uploaded-logs/upload` was plain `require_ui(files:upload)` while `POST /uploads` is
  `require_step_up`, so on a deployed instance a stolen cookie session past its step-up window could
  write PHI at rest through the console that the JSON API would have refused. It is now
  `require_ui_step_up(files:upload)` -- the shared session window, matching the twin, not a
  per-action grant. **Operator-visible change:** the upload **form** moved from
  `GET /ui/uploaded-logs/upload` to `GET /ui/uploaded-logs/upload-form` and is step-up-gated and
  registered as the POST's unlock continuation; the POST keeps its path. A stale window now answers
  the upload with `303` to `/ui/reauth`, and after re-authentication the operator lands back on the
  empty form and **re-picks the file** -- the multipart body does not survive the redirect, exactly
  as a typed password does not on `POST /ui/users`. The link on the uploaded-logs list page points
  at the new form path. **No engine UI seam change:** the route reuses `core.upload_file` and the
  existing `require_ui_step_up` gate.
- **The `/ui` PHI routes now take the ADR 0092 serve-hop refusal** (BACKLOG #1738).
  `enforce_phi_read_hop` is folded into the JSON plane's `require_phi_read`, but the console reaches
  `get_message` / `list_messages` / `list_dead_letters` / `download_attachment` **in-process**, which
  skips that `Depends` -- and `require_ui(..., phi=True)` re-applied the permission and the per-actor
  PHI-read budget without it. On a deployed production-PHI instance whose serve hop is neither
  loopback, nor in-process TLS, nor a declared TLS-terminating proxy, the JSON API would have refused
  a PHI read while `/ui` served the same body. **Operator-visible change:** on such an instance the
  six PHI browse routes (`GET /ui/messages`, `/ui/messages/{id}`, `/ui/messages/{id}/parse-tree`,
  `/ui/messages/{id}/attachments/{attachment_id}`, `/ui/dead-letters`, `/ui/messages/{id}/edit`) plus
  `POST /ui/messages/{id}/edit-resend` now return `403` with a PHI-free message naming the posture;
  every other console route is untouched. The refusal lands **below** the session check, so an
  unauthenticated visitor still gets the login redirect rather than a 403 disclosing the posture, and
  **above** the budget, so a read that will not be served spends no quota.
- **The message editor now requires `messages:view_raw` alongside `messages:edit`** (BACKLOG #324).
  `GET /ui/messages/{id}/edit` and `POST /ui/messages/{id}/edit-resend` gated on `messages:edit`
  alone, but the editor *displays* the body it edits (the textarea plus the pristine `data-original`
  copy behind Revert) and the POST's rejection arm re-renders that pristine copy — so a custom role
  holding `messages:edit` without `messages:view_raw` would have read raw PHI here on a deployed
  instance. Both verbs now fail closed on **either** permission. **Operator-visible change:** such a
  role gets `403` on the editor (it can still resubmit through the JSON API); no built-in role is
  affected, since `ADMINISTRATOR` and `OPERATOR` grant both. Both verbs additionally charge the
  per-actor PHI-read budget now, so either can return `429` + `Retry-After` under automation.
- **The two content-search step-up GET routes now charge the per-actor PHI-read budget on their
  short-circuit renders** (BACKLOG #1025). `GET /ui/messages/search` and `GET /ui/messages/search/layered`
  already charged the budget when they ran a real search — the reused engine handlers
  (`search_messages` / `layered_search`) pace it in their own body — but the bare-form and no-preset
  re-renders return *before* reaching those handlers, so on a deployed instance those render paths
  would have skipped the per-actor read budget. Each now charges `enforce_phi_read_pacing` **inline on
  its short-circuit branch only**, so the render spends a token and the route can return `429` +
  `Retry-After` under automation, **without** double-charging the real-search path (a gate-level
  `phi=`, which runs on every request, would have spent the bucket twice whenever a criterion was
  supplied). `GET /ui/uploaded-logs/file/{file_id}`, named alongside them in the original report, was
  found already paced by its own handler (`browse_uploaded_file`) on every call — it has no
  short-circuit — and is deliberately left unchanged; a charge there would double-count the same
  budget. **No engine UI seam change:** the charge reuses the existing `enforce_phi_read_pacing` helper
  the reused handlers already call.

### Notes
- **pip does not stop an unmatched pair.** The package still declares a bare `messagefoundry`
  dependency with no version range. So an install of console 0.3.0 beside any engine succeeds, and
  the seam check at engine startup is what refuses the pair. Pin both: `messagefoundry==0.4.0` with
  `messagefoundry-webconsole==0.3.0`.
- **This entry is not the full list of changes since 0.2.15.** It holds what was recorded here while
  0.3.0 was in development. The complete set is the git history of `messagefoundry_webconsole/` and
  `packaging/messagefoundry-webconsole/` between the `webconsole-v0.2.15` and `webconsole-v0.3.0`
  tags.

## [0.2.15] — 2026-07-06 — Early Access

Initial release of the web console as a standalone distribution. **Supported engine UI seam: `15`.**
This entry was written on 2026-07-06, but the wheel was built from the `webconsole-v0.2.15` tag and
published on 2026-07-29, from later code. That wheel accepts seam `15` only, and it carries the KPI
headline and the one-value seam rule below. Until 0.3.0 was cut, this line said seam `1`, and those
two items sat under Unreleased.

### Added
- **Extracted the `/ui` browser ops console into a separate, same-origin mounted package** (Option B,
  [ADR 0065](../../docs/adr/0065-web-ops-dashboard.md)). The console — page rendering (the autoescape
  HTML builder + nav registry), the confined `mf_session` cookie auth, the write-action registry, and
  every `/ui` route — moved out of the in-engine `messagefoundry/api/webui/` tree into this distribution
  (import `messagefoundry_webconsole`). The engine mounts it in-process via a single
  `mount_ui(app, deps)` call from `create_app`'s `serve_ui` tail; the `/ui` routes reach the reused JSON
  handlers through the typed `UiDeps` bundle the engine injects, so the single audited PHI path,
  per-channel RBAC, and summary redaction are reused verbatim.
- **`ENGINE_UI_SEAM` version handshake.** `SUPPORTED_ENGINE_SEAMS` + `assert_engine_seam` refuse an
  out-of-range engine at startup with a clear `UiSeamMismatch` (called before the engine builds the deps
  bundle, so a shape skew never surfaces as a raw `TypeError`). Backed by the engine-repo contract
  snapshot gate (`scripts/webconsole_seam_snapshot.py` + `tests/golden/webconsole_seam.snapshot`).
- **Independent version root.** Own `__version__`, changelog, and PyPI cadence (the departure from the
  lockstep `messagefoundry-harness`). It was meant to depend on the engine through a PEP 508 compat
  range. The published wheel declares a bare `messagefoundry` dependency instead; this line claimed
  the range until 0.3.0 was cut.
- **Own test suite + pytest config** (`packaging/messagefoundry-webconsole/tests/`) with
  `asyncio_mode = "auto"` + session loop scopes, so the relocated bare-`async def` ASGI/security tests
  actually run.
- **Engine-wide KPI headline on the status page** (BACKLOG #93). The status page now renders the
  top-line roll-up the engine surfaces on `/status` as `SystemStatus.kpis`: combined inbound+outbound
  endpoint count (running/stopped), total messages, and an engine-wide msg/s rate. Metadata only, no
  PHI.

### Changed
- **The engine UI seam moved** (`SystemStatus` gained the additive `kpis` field, so the contract
  surface changed). `SUPPORTED_ENGINE_SEAMS` holds the one new value, so this console build refuses
  any engine but the one it was built against -- including an engine one contract behind, whatever
  defaults its DTOs carry (BACKLOG #279).

### Unchanged (by design)
- A plain `pip install messagefoundry` stays **byte-identical**: with the console absent, the JSON API
  is unchanged; `serve_ui=true` without the console fails loud at startup. This line said `serve_ui`
  was default-off until 0.3.0 was cut; the engine at the `webconsole-v0.2.15` tag already had it on.
- The same-origin security model is **unchanged** — the `/ui`-confined `SameSite=Strict` cookie, the
  `Origin`/`Sec-Fetch-Site` CSRF check, step-up re-auth, the CSWSH `Origin == Host` WS check, and
  dual-control all moved verbatim.

### Notes
- This extraction decouples **development, test, and release** — **not deploy**: the package is
  co-installed in the engine venv and a new console build still requires an engine **restart**. See
  [`docs/WEBCONSOLE-PACKAGE.md` §5](../../docs/WEBCONSOLE-PACKAGE.md).
- Publishing this wheel to PyPI is a separate owner step (re-add the engine `[webconsole]` extra, set the
  compat ranges, re-lock, add the release job) — see [`RELEASE.md`](RELEASE.md). It was not wired
  when this entry was written; the `release-webconsole` job published this wheel on 2026-07-29.

[Unreleased]: https://github.com/MEFORORG/MessageFoundry/compare/webconsole-v0.3.0...HEAD
[0.3.0]: https://github.com/MEFORORG/MessageFoundry/releases/tag/webconsole-v0.3.0
[0.2.15]: https://github.com/MEFORORG/MessageFoundry/releases/tag/webconsole-v0.2.15
