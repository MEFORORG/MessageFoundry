<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Changelog — messagefoundry-webconsole

All notable changes to the **web console** distribution (`messagefoundry-webconsole`) are documented
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is **separately versioned** from the engine and pins itself to the engine's
`api._ui_seam.ENGINE_UI_SEAM` via `SUPPORTED_ENGINE_SEAMS`; each entry records the supported engine
seam. Entries from before BACKLOG #1220 quote the integer that shipped at the time; a current one
points at the constant instead, because nobody picks that value now. See
[`docs/WEBCONSOLE-PACKAGE.md`](../../docs/WEBCONSOLE-PACKAGE.md) for the seam handshake and the
engine compatibility range.

## [Unreleased]

**Supported engine UI seam: the single value in `SUPPORTED_ENGINE_SEAMS` -- read it from
[`messagefoundry_webconsole/__init__.py`](../../messagefoundry_webconsole/__init__.py), not from
this line.**

### Added
- **High Availability page** (BACKLOG #1495, ADR 0056). `/ui/cluster`, under Monitoring, renders
  cluster membership, each node's state and the leadership lease from whichever node serves it, and
  refreshes every 5 seconds. It carries one control: a planned stepdown of the node serving it, behind
  a step-up confirm page, plus a separate forced drain for the last promotable node. Each refusal the
  engine returns (400, 409, 412, 503) gets its own guidance. It renders no VIP owner, because the
  engine binds no address.
- **Engine-wide KPI headline on the status page** (BACKLOG #93). The status page now renders the
  top-line roll-up the engine surfaces on `/status` as `SystemStatus.kpis`: combined inbound+outbound
  endpoint count (running/stopped), total messages, and an engine-wide msg/s rate. Metadata only, no
  PHI.

### Changed
- **The engine UI seam moved for the `/ui` PHI serve-hop refusal** (BACKLOG #1738): `_auth.py` now
  imports `api.security.enforce_phi_read_hop`, and seam discovery derives the console's security
  surface from those import statements, so the import alone moves the digest. Same one-value
  `SUPPORTED_ENGINE_SEAMS` rule as the entries below.
- **The engine UI seam moved for the High Availability page** (BACKLOG #1495): `CoreHandlers` gained
  `cluster_stepdown`, and the console now constructs `ClusterStepdownRequest`. Same one-value
  `SUPPORTED_ENGINE_SEAMS` rule as the entry below.
- **The engine UI seam moved** (`SystemStatus` gained the additive `kpis` field, so the contract
  surface changed). `SUPPORTED_ENGINE_SEAMS` holds the one new value, so this console build refuses
  any engine but the one it was built against -- including an engine one contract behind, whatever
  defaults its DTOs carry (BACKLOG #279).

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

## [0.2.15] — 2026-07-06 — Early Access

Initial release of the web console as a standalone distribution. **Supported engine UI seam: `1`.**

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
  lockstep `messagefoundry-harness`); depends on the engine through a PEP 508 compat range.
- **Own test suite + pytest config** (`packaging/messagefoundry-webconsole/tests/`) with
  `asyncio_mode = "auto"` + session loop scopes, so the relocated bare-`async def` ASGI/security tests
  actually run.

### Unchanged (by design)
- A plain `pip install messagefoundry` stays **byte-identical**: with `serve_ui` default-off and the
  console absent, the JSON API is unchanged; `serve_ui=true` without the console fails loud at startup.
- The same-origin security model is **unchanged** — the `/ui`-confined `SameSite=Strict` cookie, the
  `Origin`/`Sec-Fetch-Site` CSRF check, step-up re-auth, the CSWSH `Origin == Host` WS check, and
  dual-control all moved verbatim.

### Notes
- This extraction decouples **development, test, and release** — **not deploy**: the package is
  co-installed in the engine venv and a new console build still requires an engine **restart**. See
  [`docs/WEBCONSOLE-PACKAGE.md` §5](../../docs/WEBCONSOLE-PACKAGE.md).
- Publishing this wheel to PyPI is a separate owner step (re-add the engine `[webconsole]` extra, set the
  compat ranges, re-lock, add the release job) — see [`RELEASE.md`](RELEASE.md). It is not wired yet.

[Unreleased]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.15...HEAD
[0.2.15]: https://github.com/MEFORORG/MessageFoundry/releases/tag/v0.2.15
