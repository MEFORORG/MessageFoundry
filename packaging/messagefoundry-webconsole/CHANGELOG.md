<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Changelog — messagefoundry-webconsole

All notable changes to the **web console** distribution (`messagefoundry-webconsole`) are documented
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is **separately versioned** from the engine and pins itself to the engine's
`api._ui_seam.ENGINE_UI_SEAM` via `SUPPORTED_ENGINE_SEAMS`; each entry notes the supported engine
seam(s). See [`docs/WEBCONSOLE-PACKAGE.md`](../../docs/WEBCONSOLE-PACKAGE.md) for the seam handshake and
the engine compatibility range.

## [Unreleased]

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
