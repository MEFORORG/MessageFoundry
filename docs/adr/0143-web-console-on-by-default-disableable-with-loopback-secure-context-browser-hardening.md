<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0143 — Web console on by default (disableable), with loopback secure-context browser hardening

- **Status:** Accepted (2026-07-21)
- **Date:** 2026-07-21
- **Related:** [ADR 0065](0065-web-ops-dashboard.md) (the web ops console — amended: default flipped on) · [ADR 0118](0118-secure-by-default-security-configuration-section.md) (the `[security]` secure-by-default section — `serve_web_console` default flipped; reframed as surface-reducing, not a loosening) · [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md) (the off-loopback exposure ladder — now runs for an explicitly-enabled console) · [docs/SECURITY-LOOSENING.md](../SECURITY-LOOSENING.md) · [docs/security/OFF-LOOPBACK-DEPLOYMENT.md](../security/OFF-LOOPBACK-DEPLOYMENT.md)

---

## Context

The browser **web console** (`messagefoundry_webconsole`, mounted same-origin at `/ui`, [ADR 0065](0065-web-ops-dashboard.md))
is the **sole operator console** — the PySide6 desktop console was retired (BACKLOG #103, ADR 0032 retired).
Yet it shipped **off by default** (`[api].serve_ui = False` / `[security].serve_web_console = False`): a stock
`serve` gave a JSON-only engine with **no operator UI at all** until the operator discovered and set the
switch. For the product's own operator surface — effectively core — an off-by-default that hides the primary
UI is the wrong default. The owner approved flipping it **on**.

Two obstacles made a naive flip unsafe:

1. **Browser security headers were off over cleartext loopback.** The `/ui` browser hardening bundle
   (per-response **nonce CSP** 3.4.7/3.4.8, **COOP**, **CORP**, **Reporting-Endpoints**;
   [ADR 0065 §hardening / BACKLOG #192](0065-web-ops-dashboard.md)) engaged **only in an effective-https
   context** (`effective_https` — real `https`/`wss`, or a declared `exposure_protected` proxy). Over the
   default cleartext-loopback bind it was a strict no-op. But `http://127.0.0.1` is a **W3C
   *potentially-trustworthy* origin** (a *secure context* in every modern browser), where a conformant browser
   **honours those headers** — so the local operator was needlessly running without them.

2. **Two coupled concerns keyed on one signal.** `effective_https` gated **both** (a) the session cookie's
   `Secure` flag + `__Host-` prefix **and** (b) the header hardening. A browser **rejects** a `Secure` /
   `__Host-` cookie over `http://`, so simply engaging the whole bundle on loopback would set a cookie the
   browser drops — **breaking login** on Chrome/Safari.

A full fix — terminate TLS on the loopback bind so `effective_https` is true and *everything* (headers +
secure cookie + HSTS) engages — is an **XL**: it means moving the whole API to https by default and migrating
every client (harness, `apiclient`, tray, IDE) in lockstep. Out of scope here.

## Decision

Ship the **owner-approved hybrid**: the console defaults **on** (still disableable), and the **http-safe**
subset of the browser hardening engages over the **loopback secure-context** — **without** auto-TLS.

### 1. Default-on, disableable

- `ApiSettings.serve_ui` and `SecuritySettings.serve_web_console` both default **`True`**. A stock `serve`
  now mounts `/ui`.
- The **one user lever** is `[security].serve_web_console = false` (the raw `[api].serve_ui` is a
  relocated key rejected in user TOML, [ADR 0118](0118-secure-by-default-security-configuration-section.md)).
  Setting it `false` desugars to `[api].serve_ui = False` → JSON-only. Because the `[security]` desugar is
  **presence-gated**, an absent `[security]` leaves the `ApiSettings` default (`True`) governing.

### 2. Security-header split — engage the http-safe headers on loopback, keep the cookie https-gated

A new **`security_headers_context(app_state, scheme)`** (in `messagefoundry_webconsole/_auth.py`) =
`effective_https(app_state, scheme) or bool(getattr(app_state, "loopback", False))`. The `/ui` header
middleware (`UiSecurityHeadersMiddleware`) now keys on **this** instead of `effective_https`. `effective_https`
and `session_cookie_name` are **unchanged**, so:

- **Headers** (nonce-CSP, COOP, CORP, Reporting-Endpoints, `frame-ancestors 'none'`) engage on the loopback
  secure-context (`http://127.0.0.1`, signalled by a new read-only `app.state.loopback`) as well as
  effective-https.
- The **session cookie** stays keyed on `effective_https`: over cleartext loopback it is the **plain
  `mf_session`** (`SameSite=Strict` + `HttpOnly`, **no** `Secure`, **no** `__Host-`), so **login is not
  broken**. `__Host-mf_session` + `Secure` still require real https (off-loopback TLS).
- **HSTS** stays **off** on loopback — the engine emits `Strict-Transport-Security` only over `https` or a
  declared `exposure_protected`, never on a cleartext loopback bind (verified; no change made).

The engine threads `app.state.loopback = loopback` in `create_app` / `create_managed_app`, and `__main__`
passes `loopback=settings.api.is_loopback`. The console reads it **read-only** with a graceful default (`getattr(..., "loopback", False)`),
so an older engine that predates the seam degrades gracefully — it is a soft seam addition, curated into the
webconsole seam snapshot **without** bumping `ENGINE_UI_SEAM` (parity with `exposure_protected`).

### 3. Soft-degrade — default-on must not turn a working config into a start failure

Default-on introduces two ways a previously-fine deployment would newly fail. Both **auto-degrade to
JSON-only** rather than refusing:

- **Optional package absent.** The console ships as a separate wheel (`messagefoundry-webconsole`). If it is
  **absent** and the console is **default-on** (not explicitly requested), `serve` serves **JSON-only + a
  warning** (exit 0). If `[security].serve_web_console=true` was **explicitly** set, the absent wheel keeps the
  **hard refuse** (exit 2) — the operator asked for the console by name. The default-vs-explicit signal is a
  new internal `ApiSettings.serve_ui_explicit` marker, set by `_desugar_security` when `serve_web_console` is
  provided.
- **Exposed bind.** The default-on is a **local-loopback** convenience. On an **exposed** instance (a
  non-loopback host, a declared TLS-terminating proxy `tls_terminated_upstream`, or a set `public_origin`) a
  **default-on** console **auto-degrades to JSON-only + a warning**, *before* the [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md)
  `/ui` exposure ladder — so a previously-working exposed JSON serve is never turned into a start failure. An
  **explicit** `serve_web_console=true` off-box is left on and still runs the full ladder **unchanged** (the
  off-loopback `/ui` refusals still fire for it). The console off-box remains a deliberate opt-in requiring TLS
  + `web_console_public_address`, exactly as before.

### 4. Not a loosening — a surface-reducing opt-out

`serve_web_console` is removed from the **loosening** framing: with default-on, **disabling** it *removes* the
`/ui` HTML/session-cookie attack surface (a *hardening*), so it does **not** appear in `security_loosenings()`.
`docs/SECURITY-LOOSENING.md` reframes its entry as a surface-reducing opt-out and flips the switch-table
default to `true`.

### Deferred (considered, not built): auto-TLS on loopback

Terminating TLS on the loopback bind so `effective_https` is true — which would let the **secure cookie +
HSTS** engage on loopback and move ASVS **3.3.1 / 3.3.3** from documented **Partial** to **Pass** — was
**considered and deferred** as an **XL**: it requires moving the whole API to https by default and a lockstep
client migration (harness, `apiclient`, tray, IDE). On loopback, 3.3.1/3.3.3 remain **documented Partials**
(the http-safe headers engage; the cookie's `Secure`/`__Host-` and HSTS are the only gap) — **not Fails**. The
Posture-A ASVS re-score is owner-gated and handled separately.

## Consequences

- **Positive** — a stock `serve` gives the operator console out of the box; the local operator gets the
  http-safe browser hardening (nonce-CSP/COOP/CORP/Reporting) over loopback; login is never broken (plain
  `mf_session` over cleartext); no previously-working config (package-absent or exposed JSON serve) is turned
  into a start failure.
- **Neutral / unchanged** — `effective_https`, `session_cookie_name`, the cookie's `Secure`/`__Host-` gating,
  HSTS emission, and the off-loopback `/ui` exposure ladder (for an explicitly-enabled console) are all
  **unchanged**. `checks.py` needs no `/ui` mirror (the default-on console auto-degrades off-box, so it never
  adds a serve-only refusal the parity net would miss).
- **Negative / risk** — a loopback deployment that was JSON-only-by-inertia now serves `/ui`; an operator who
  wants JSON-only must set `serve_web_console = false`. The two loopback ASVS cells (3.3.1/3.3.3) stay Partial
  until the deferred auto-TLS work lands.
- **Doc updates** — `docs/CONFIGURATION.md`, `docs/SECURITY.md`, `docs/PHI.md`,
  `docs/security/OFF-LOOPBACK-DEPLOYMENT.md`, `docs/SECURITY-LOOSENING.md`, and `ide/src/securityEditor.ts`
  flip the "off by default" statements and document the loopback secure-context hardening split.

## Acceptance Criteria

- **AC-1** — `SecuritySettings().serve_web_console` SHALL be `True`, and a bare load SHALL give
  `api.serve_ui == True`; `[security].serve_web_console = false` SHALL yield `api.serve_ui == False`. →
  `tests/test_security_config.py::test_web_console_on_by_default`,
  `test_secure_defaults_applied`.
- **AC-2** — A bare **loopback** `serve` SHALL mount `/ui` (`serve_ui=True`, `loopback=True` threaded) with no
  exposure-gate refusal. → `tests/test_cli.py::test_serve_ui_default_on_loopback_mounts_ui`.
- **AC-3** — Over a **loopback** (`app.state.loopback=True`) http `/ui` response the nonce-CSP + COOP + CORP +
  Reporting-Endpoints headers SHALL engage, AND the session cookie SHALL stay the plain `mf_session` (no
  `Secure`, no `__Host-`); over real https the `__Host-` cookie + headers both engage (unchanged). →
  `packaging/messagefoundry-webconsole/tests/test_ui_hardening.py::test_loopback_http_engages_headers_but_keeps_plain_cookie`,
  `test_https_uses_host_prefixed_secure_cookie`, `test_https_nonce_csp_coop_and_reporting`.
- **AC-4** — WHEN the console wheel is absent: a **default-on** serve SHALL degrade to JSON-only + a warning
  (exit 0); an **explicit** `serve_web_console=true` SHALL keep the hard refuse (exit 2). →
  `tests/test_webconsole_absent.py::test_serve_default_on_soft_degrades_to_json_only_when_absent`,
  `test_serve_explicit_console_refuses_when_absent`.
- **AC-5** — A **default-on** console on an **exposed** bind SHALL auto-degrade to JSON-only (exit 0), while an
  **explicit** console off-box SHALL still hit the exposure ladder (unchanged). →
  `tests/test_cli.py::test_serve_ui_default_on_offloopback_degrades_json_only`,
  `test_serve_ui_explicit_offloopback_still_refuses`.
- **AC-6** — HSTS SHALL NOT be emitted over cleartext loopback (verified; no change made). →
  covered by `packaging/messagefoundry-webconsole/tests/test_ui_hardening.py::test_loopback_http_engages_headers_but_keeps_plain_cookie`
  (asserts `strict-transport-security` absent).

## Options considered

1. **Hybrid: default-on + `security_headers_context` split (http-safe headers on loopback, cookie https-gated), soft-degrade both blockers.**
   **CHOSEN** — gives the operator UI + the browser hardening on loopback with zero broken logins and no
   config newly turned into a start failure.
2. **Auto-TLS on the loopback bind** (so `effective_https` is true and everything engages). — **Deferred**:
   an XL whole-API-https + lockstep client migration; tracked, not built.
3. **Default-on but keep headers off on loopback** (only flip the default). — **Rejected**: leaves the local
   operator without the browser hardening a trustworthy origin can carry, for no benefit.
4. **Default-on and refuse off-loopback default-on binds** (fail loud). — **Rejected**: turns every
   previously-working exposed JSON serve into a start failure and would require a `/ui` mirror in `checks.py`
   to keep the gate-parity net honest; the auto-degrade is the safer, parity-preserving choice.

## To resolve on acceptance

- [x] `ApiSettings.serve_ui` + `SecuritySettings.serve_web_console` default `True`; `serve_ui_explicit` marker set in `_desugar_security`.
- [x] `security_headers_context` added (`_auth.py`); `UiSecurityHeadersMiddleware` keyed on it; `effective_https` / `session_cookie_name` unchanged.
- [x] `app.state.loopback` threaded through `create_app` / `create_managed_app` / `__main__` (`is_loopback`); curated into the webconsole seam snapshot (no `ENGINE_UI_SEAM` bump).
- [x] Package-absent + exposed-bind soft-degrade (default → JSON-only + warn; explicit → refuse / ladder).
- [x] HSTS verified https-only (no change).
- [x] `security_loosenings()` untouched (the switch is not a loosening); `docs/SECURITY-LOOSENING.md` reframed + switch-table default flipped.
- [x] Docs (`CONFIGURATION.md`, `SECURITY.md`, `PHI.md`, `OFF-LOOPBACK-DEPLOYMENT.md`) + `ide/src/securityEditor.ts` flip "off by default" → on by default.
- [ ] Posture-A ASVS re-score (3.3.1/3.3.3 stay Partial on loopback; auto-TLS deferred) — **owner-gated, separate**.
