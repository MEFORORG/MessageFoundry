# Running the admin console on a remote PC

> **Retired UI (BACKLOG #103, 2026-07-13).** The **PySide6 desktop console is retired** — the operator
> UI is now the browser **web console** served same-origin by the engine at `/ui`
> ([ADR 0065](adr/0065-web-ops-dashboard.md)). To operate the engine from a remote PC today, **work
> §1 below end to end (bind off-loopback + TLS *and that branch's own fail-closed precondition* +
> `[security].serve_web_console = true`), then browse to `https://<engine-host>:8765/ui`** from the
> remote machine — no desktop client to install. Do not treat that parenthesis as the checklist: each
> TLS branch refuses to start until a further declaration is made, and §1 is where they are.
> The desktop-console `messagefoundry-console --url …` client **no longer ships**: there is no
> `messagefoundry.console` module and no console entry point, so those commands cannot be run. §3 has
> been rewritten for the browser; the retired flags survive only as a one-paragraph footnote.

The engine reaches its clients **only** over its localhost-or-network HTTP/WebSocket API
([`api/app.py`](../messagefoundry/api/app.py)) — a client never imports the engine or touches the store
directly. So the operator UI can run on a different machine from the engine.

Remote access is **supported but off by default**: out of the box the engine is bound to `127.0.0.1`
(loopback only), so nothing is exposed until an admin deliberately (1) binds the engine to a routable
address, (2) puts TLS in front of it **and satisfies that branch's second, fail-closed precondition**
(§1 — an attested revocation posture for in-process TLS, two proxy declarations for a terminator),
(3) sets `[security].serve_web_console = true` **explicitly** — the default-on console covers loopback
binds only, and silently degrades to JSON-only when exposed (§3) — and (4) browses to the `https://…/ui`
URL. Auth is already required.

---

## 1. Engine side — bind off-loopback, with TLS

By default the engine is loopback-only. To accept remote connections, turn
`[security].local_access_only` off, name the bind address in `[security].listen_address`, and
configure TLS. (`[api].host` was the old spelling; [ADR
0118](adr/0118-secure-by-default-security-configuration-section.md) moved the bind/console/origin
switches to `[security]` and setting them in `[api]` is now **refused at config load**.)

### How hard is the TLS requirement?

**For the browser console, absolute.** An off-loopback `/ui` bind without in-process TLS or a declared
TLS-terminating proxy is refused at startup, and `serve --allow-insecure-bind` explicitly does **not**
cover it — the flag was scoped to the JSON API's cleartext risk, never the browser surface. So the
deployment this page describes cannot be brought up in cleartext.

**For the JSON API alone, it is a ladder with an operator off-switch** — worth knowing, because a
reviewer who reads "refused at startup" as an architectural guarantee will be wrong about a
JSON-only instance:

| Posture (off-loopback bind) | Result |
|---|---|
| in-process TLS (`[api].tls_cert_file`) | **refused (exit 2) until `MEFOR_TLS_REVOCATION_ATTESTED=1` is also set** — the engine terminates TLS itself and performs no OCSP/CRL check, so revocation has to be attested ([ADR 0078](adr/0078-certificate-revocation-posture.md)). With the attestation: starts |
| proxy-terminated TLS (`[api].tls_terminated_upstream` + `trusted_proxies`) | starts on a synthetic instance — but on a **PHI** instance under `[security].enforcement = enforce` (the shipped default) it is **refused** until `[api].proxy_intra_service_auth` **and** `[api].proxy_tls_min_version` are declared as well. Option B's block below sets both |
| no TLS, plus `serve --allow-insecure-bind` **or** `[security].require_encryption_for_remote = false` | **starts**, with a stderr warning — bearer tokens cross the network in cleartext |
| …the same, on a **PHI-classified** instance under `[security].enforcement = enforce` (the default) | refused — the escape is clamped shut and cannot relax a PHI cleartext bind |
| no TLS, no escape | refused |

So cleartext is impossible for `/ui` and for a PHI instance at the default enforcement; on a
synthetic/non-PHI instance, or one dialled to `enforcement = warn`, the escape genuinely starts the
engine. The engine's own refusal message names the flag, so an operator will find it — treat it as a
lab tool and keep it out of any exposed deployment.

**Neither TLS row starts a stock instance on its own** — each carries a second, fail-closed
precondition, an `exit 2` before any listener binds, and `--allow-insecure-bind` covers neither. The
two are scoped differently, which matters when you reason about a lab box:

- the **in-process-TLS** revocation refusal reads **neither** the data label **nor** `enforcement`
  ([`config/tls_policy.py`](../messagefoundry/config/tls_policy.py),
  `in_process_tls_revocation_refused`), so a synthetic instance and one dialled to
  `enforcement = warn` are refused exactly like `prod`;
- the **terminator's** attestation refusal *is* posture-keyed — PHI **and** `enforcement = enforce`
  **and** an off-loopback bind. The recommended loopback-behind-a-proxy topology only warns.

Both options below carry their own precondition inline. The same ladder in checklist form is
[`DEPLOYMENT.md`](DEPLOYMENT.md) § *Before you expose off-loopback*.

### Option A — in-process TLS (simplest for a single engine host)

The engine (uvicorn) terminates TLS itself and serves `https`/`wss`. Configure in `messagefoundry.toml`:

```toml
[security]
local_access_only = false        # reachable from off this machine
listen_address = "0.0.0.0"       # or a specific NIC, e.g. "10.0.0.12"
# REQUIRED off-box, and it must be set EXPLICITLY: the default-on console (ADR 0143) covers loopback
# binds only — on an exposed instance a default-on console silently degrades to JSON-only (see §3).
serve_web_console = true
web_console_public_address = "https://engine-host:8765"   # the origin the browser uses

[api]
port = 8765
tls_cert_file = "C:/mefor/tls/engine-cert.pem"   # PEM cert (chain); PEM paths, not secrets
tls_key_file  = "C:/mefor/tls/engine-key.pem"    # may be omitted if the key is bundled in the cert PEM
# tls_min_version = "1.2"        # "1.2" (default) or "1.3"
# tls_key_password is a SECRET — supply via MEFOR_API_TLS_KEY_PASSWORD, never the file
```

**That block alone will not start the engine.** An off-loopback in-process-TLS bind is refused
(`exit 2`) until you also attest your revocation posture — and that is an **environment variable,
not a TOML key**; there is no `[api]` or `[security]` equivalent:

```
setx MEFOR_TLS_REVOCATION_ATTESTED 1        # per-session: PowerShell $env:MEFOR_TLS_REVOCATION_ATTESTED="1"
```

Under NSSM put it on the service, not in an interactive shell —
`nssm set MessageFoundry AppEnvironmentExtra MEFOR_TLS_REVOCATION_ATTESTED=1` (see
[`SERVICE.md`](SERVICE.md)). Setting it is **you taking responsibility for revocation**: the engine
performs no OCSP/CRL check of its own (stdlib `ssl` has no fetch), so the certificate this listener
presents must be backed by a revocation-checking PKI — short-lived / ACME-rotated certs, an
OCSP-must-staple issuer, or a trust store that consults CRLs. If you cannot make that claim
honestly, **use Option B instead**: terminating at a revocation-checking proxy satisfies the same
gate without an attestation. It is blanket and process-wide — it also clears the outbound
revocation refusals on this engine's verifying TLS connectors, so read
[`DEPLOYMENT.md`](DEPLOYMENT.md) § *Revocation-guard behavior* before setting it
([ADR 0078](adr/0078-certificate-revocation-posture.md)).

Use a cert whose SAN matches the hostname the console is browsed at — and make
`web_console_public_address` that same origin. Without it the `/ui` same-origin CSRF check falls back
to the client-forwardable `Host` header and **WebAuthn passkeys are unavailable** (fail-closed); the
engine warns at startup rather than refusing, so this is easy to miss. An internal/enterprise CA
(AD Certificate Services) or a public CA both work; on self-signed, see §3.

### Option B — TLS terminated upstream (reverse proxy / load balancer)

A proxy (nginx, IIS/ARR, HAProxy, a k8s ingress) terminates TLS and forwards plaintext to the engine.
Tell the engine a terminator is in front so the off-loopback gate is satisfied and the
audit/rate-limit source IP is the real client. The engine then terminates no TLS itself, so this
posture needs **no** `MEFOR_TLS_REVOCATION_ATTESTED` — revocation is delegated to the terminator,
which is why it is the better option when you cannot attest a revocation-checking PKI:

```toml
[security]
local_access_only = false        # or keep the engine on loopback if the proxy is on this same host
listen_address = "0.0.0.0"
serve_web_console = true         # REQUIRED off-box, and EXPLICITLY — see §3
# REQUIRED behind a declared proxy: the engine REFUSES TO START serving /ui without it, because the
# Host header is client-forwardable there and the CSRF check + WebAuthn origin binding need the exact
# external origin. Make it the origin the browser types.
web_console_public_address = "https://mefor.example.org"

[api]
tls_terminated_upstream = true
trusted_proxies = ["10.0.0.5"]   # the proxy's address(es) — REQUIRED; empty trusts nothing
# Posture-B attestations — BOTH REQUIRED, not optional. The engine terminates NO browser TLS here,
# so it can observe neither the proxy->engine hop nor the TLS floor the proxy offers browsers — both
# are operator DECLARATIONS. On a PHI instance (all three built-in env names) under the default
# [security].enforcement = enforce, an OFF-LOOPBACK bind REFUSES to start without them (exit 2); if
# you took the loopback-behind-the-proxy variant above it only WARNS — declare them anyway, they are
# the only record that the internal hop and the browser-facing floor were considered.
proxy_intra_service_auth = "network"   # "mtls" | "network" | "shared_secret"
# ASVS 12.1.1 — the browser-facing TLS floor. This line is an ATTESTATION worth exactly what your
# proxy config says: pin the floor in the PROXY (the reference fences linked below pin TLSv1.2 +
# TLSv1.3) and declare here the LOWEST version that fence still permits. Declaring "1.3" in front
# of a proxy that still accepts TLS 1.2 is a false attestation the engine cannot catch.
proxy_tls_min_version = "1.2"
```

**The `proxy_tls_min_version` line is not the control — your proxy configuration is.** Copy a
reference terminator config whole from
`security/OFF-LOOPBACK-DEPLOYMENT.md` § Reverse-proxy reference configs
(nginx, Caddy, or IIS + ARR — each pins an explicit protocol floor plus forward-secret ciphers and
key-exchange groups) and keep the fence and this declaration in step: narrow the proxy to TLS 1.3
only and you must raise `proxy_tls_min_version` to `"1.3"` in the same change. That page also
carries the recommended hardening for an exposed console (client-certificate device posture,
`web_console_public_address`, the full startup ladder). It is maintainer-internal —
[SECURITY-DOCS-POLICY.md](SECURITY-DOCS-POLICY.md) explains what is withheld and what you can request.

### Authentication at exposure

Auth is on by default; remote users sign in with local accounts (± TOTP MFA) or AD/LDAP. Note:

- With `[security].require_sign_in = false`, an off-loopback bind is **hard-refused** (loopback is the
  only no-auth posture).
- `[security].require_mfa` is **on by default**, and MFA is an access gate: an enrolled-pending session
  gets `403` + `X-MFA-Required: 1` on every authorized route. **Leave it on** — that default, not the
  startup gate below, is the control.
- The startup gate is narrower than it looks. On an exposed **PHI** instance — any of `dev`/`staging`/
  `prod`, since all three derive PHI ([ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)) —
  an explicit `[security].require_mfa = false` **refuses to start**, but only when
  `[security].enforcement = enforce` (the default) **and**
  `[security].allow_single_factor_admin_when_exposed` is not set
  ([`__main__.py`](../messagefoundry/__main__.py), the `admin_exposed` block). Either switch turns the
  refusal into a loud, audited warning that starts. A non-PHI instance is silent.
  **"Exposed" here is the bind-and-proxy posture, not the console**: an off-loopback bind, **or**
  `[api].tls_terminated_upstream` — whether or not `/ui` ends up mounted. So the recommended
  loopback-behind-a-terminator topology in §3 **does** trip it, including when the default-on console
  auto-degrades to JSON-only, and when `serve_web_console = false` disables the console outright: the
  single-factor surface being protected is the JSON operator API. (This is a correction —
  [BACKLOG #326](BACKLOG.md); the arm used to read the console flag, which the §3 auto-degrade clears
  first, and would have missed exactly that topology on first deployment.) An **undeclared** proxy —
  a set `[security].web_console_public_address` with no `tls_terminated_upstream` — is outside the
  predicate and does **not** refuse: nothing was declared, so exposure would be an inference. It gets
  its own **warning** instead, naming single-factor admin explicitly, on a PHI instance with
  `require_mfa` off. That is a distinct arm — **not** the ADR 0068 §8 undeclared-proxy warning, which
  is about the `/ui` cookie and HSTS and is suppressed by §3's auto-degrade in the same posture. See
  the `allow_single_factor_admin_when_exposed` row in [`CONFIGURATION.md`](CONFIGURATION.md) and
  [`SECURITY-LOOSENING.md`](SECURITY-LOOSENING.md).
- Under the shipped `require_mfa_scope = "every_local_account"`, a non-interactive **local**
  bearer-token service account becomes MFA-pending and cannot enrol unattended. Settle this **before**
  you turn exposure on, and note there are only **two** real destinations for such an account:
  **make it a directory (AD/Kerberos) principal** — those are out of MFA scope under either value,
  their factor being delegated to the directory — or set
  `[security].require_mfa_scope = "administrators"`, which is itself reported as a loosening on
  `GET /security/posture` and leaves *any* local Administrator still in scope.
  **Not** mTLS: `[api].tls_client_cert_identities` maps a verified client cert to a principal, but
  that plane is admitted on exactly one route (`GET /service/identity`) and carries no bearer/session
  access, so a service account moved there can read back its own identity and nothing else — it
  cannot replay, purge or poll. See [`CONFIGURATION.md`](CONFIGURATION.md) `[api]` and
  [`SECURITY.md`](SECURITY.md).
- Consider `[auth].admin_new_ip_step_up = true` to force a fresh step-up when an admin action arrives
  from a new client IP.

---

## 2. What the console can change

The web console is **not** a read-only viewer. It carries the operator write surface, and each `/ui`
write calls the same JSON handler, RBAC permission and audit path the API uses
([`api/app.py`](../messagefoundry/api/app.py)) — so exposing the console exposes these operations to
whoever holds the permission. Plan an exposure against this list, not against the dashboard's
read-only-looking front page.

Every row is a `POST`. **Step-up** means the operator is re-verified (password, plus MFA where
enrolled) before the action runs — a stale window is redirected to `/ui/reauth` rather than refused.
**Dual control** applies only where `[approvals]` is enabled (it is **off by default**): the action is
then held for a second, *distinct* approver holding `approvals:approve` instead of executing inline.

> **`[approvals].enabled = true` does not cover config reload.** `operations` defaults to
> `["connection_purge", "dead_letter_replay"]` only — `config_reload` is a valid but **deliberately
> excluded** value ([`config/settings.py`](../messagefoundry/config/settings.py),
> `_DEFAULT_APPROVABLE_OPERATIONS`), so turning dual control on leaves the one operation that
> **executes your config Python** on a single operator's authority. Add it explicitly:
> `operations = ["connection_purge", "dead_letter_replay", "config_reload"]`.

| Operation | Route | Permission | Extra gate |
|---|---|---|---|
| Start / stop / restart a connection, singly or over a selection | `/ui/connections/{name}/start`, `/stop`, `/restart`, `/ui/connections/bulk-control` | `connections:control` | — |
| Toggle a connection's flag annotation — the one console write that persists to `connections.toml` | `/ui/connections/{name}/flag` | `config:deploy` | — |
| Reload the graph from the engine's own startup config dir (executes your config Python) | `/ui/config/reload` | `config:deploy` | step-up; dual control **only if you add `config_reload` to `[approvals].operations`** — see the note above |
| Replay one message | `/ui/messages/{message_id}/replay` | `messages:replay` | step-up |
| Replay dead deliveries — for one channel, for one (channel, destination), or all of them | `/ui/dead-letters/{channel_id}/replay`, `/ui/dead-letters/{channel_id}/{destination_name}/replay`, `/ui/dead-letters/replay-all` | `messages:replay` | step-up + dual control |
| Edit a message body and resend it (re-route, or direct to a chosen outbound) | `/ui/messages/{message_id}/edit-resend` | `messages:edit` | step-up |
| Purge an outbound's queued deliveries, for one connection or a selection | `/ui/connections/{name}/purge/{scope}`, `/ui/connections/purge-bulk` | `messages:purge` | step-up + dual control |
| Acknowledge / resolve / suspend / resume an alert | `/ui/alerts/{alert_id}/ack`, `/resolve`, `/suspend`, `/resume` | `monitoring:diagnose` | — |
| Reset cumulative statistics — all of them, one connection, or a selection | `/ui/statistics/reset`, `/reset-one`, `/reset-many` | `monitoring:diagnose` | — |
| Run an on-demand store integrity check (`PRAGMA quick_check` — reads, changes nothing) | `/ui/status/integrity-check` | `monitoring:diagnose` | — |
| Activate / release a DR standby | `/ui/dr/activate`, `/ui/dr/release` | `dr:operate` | — |
| Upload a message file into the engine — **writes real PHI at rest** | `/ui/uploaded-logs/upload` | `files:upload` | — |
| Re-inject a message out of an uploaded file | `/ui/uploaded-logs/file/{file_id}/resend` | `files:browse` | — |
| Delete an uploaded file | `/ui/uploaded-logs/file/{file_id}/delete` | `files:delete` | step-up |
| Save / delete a message-search preset | `/ui/messages/search/presets`, `/presets/{preset_id}/delete` | `messages:read` | step-up on save |
| Create / update / delete a user; set roles or channel scope; reset password or MFA; revoke their sessions | `/ui/users`, `/ui/users/{user_id}/update`, `/roles`, `/channel-scope`, `/reset-password`, `/reset-mfa`, `/revoke-sessions`, `/delete` | `users:manage` | step-up |
| Create / update / delete a custom role | `/ui/roles/custom`, `/ui/roles/custom/{role_id}/update`, `/delete` | `users:manage` | step-up |
| Map AD groups to roles, and to channel scopes | `/ui/ad-groups/map`, `/ui/ad-groups/scope-map` | `users:manage` | step-up |
| The operator's **own** account: change password, enrol / confirm / disable TOTP, add or remove a passkey, revoke own sessions | `/ui/account/password`, `/ui/account/mfa/*`, `/ui/account/webauthn/*`, `/ui/account/sessions/*` | none — self-scoped, authorized by session ownership | password re-proof; full step-up to disable MFA or remove a passkey |
| Sign in, sign out, re-authenticate, verify a second factor | `/ui/login`, `/ui/logout`, `/ui/reauth`, `/ui/reauth/webauthn`, `/ui/mfa` | none | — |

Two things the console deliberately **cannot** do. It has no editor for Connection/Router/Handler
Python — the reload above always runs the engine's own startup config dir, never a browser-supplied
path — and it cannot write service settings: `[security]` and the rest of `messagefoundry.toml` are
read-only to it (`GET /security/posture`), so changing posture is a file/IDE operation. The
connection-flag row is the single exception to "no config writes".

The exhaustive per-route table — reads as well as writes, the exact gate on each, and the places a
`/ui` route is deliberately weaker than its JSON counterpart — lives in
[`SECURITY.md`](SECURITY.md).

---

## 3. Browser side — reach the console over TLS

**There is no client to install.** Open a browser on the remote PC at the origin you set in
`[security].web_console_public_address`, with `/ui` on the end:

```
https://engine-host:8765/ui
```

### Three engine-side preconditions, or that URL isn't there

| Precondition | What happens without it |
|---|---|
| `[security].serve_web_console = true`, set **explicitly** | The console's default-on posture ([ADR 0143](adr/0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md)) covers **local loopback binds only**. On an *exposed* instance — a non-loopback bind, a declared TLS terminator, **or** a set `web_console_public_address` — a *default-on* (not explicitly requested) console **auto-degrades to JSON-only** with a stderr warning, and `/ui` is simply not served ([`__main__.py`](../messagefoundry/__main__.py), the `console_exposed` block). Default-on must not turn a working exposed JSON serve into a start failure, so this degrades rather than refusing — which means an operator who never sets the switch gets **no console and no error**, only a warning line. |
| The **`messagefoundry-webconsole`** wheel installed | It is a separate optional package. With `serve_web_console` **explicitly** `true` and the wheel absent, `serve` **refuses to start** (exit 2). Left at the default it degrades to JSON-only with a warning instead. |
| TLS — Option A or Option B above, **including that option's own second precondition** | An off-loopback `/ui` bind without in-process TLS or a declared terminator is **refused at startup**, and `--allow-insecure-bind` does not cover it (§1). Configuring the TLS keys is not enough on its own: Option A additionally refuses without `MEFOR_TLS_REVOCATION_ATTESTED=1`, and Option B additionally refuses (PHI + `enforcement = enforce` + off-loopback) without `[api].proxy_intra_service_auth` and `[api].proxy_tls_min_version`. Both refusals land *before* the console gates, so the symptom is a dead engine, not a 404. |

### Certificate trust is the **browser's**, not the engine's

The retired desktop client carried its own trust flags. The browser does not: **no engine-side setting
makes a client trust a certificate.** Trust is arranged once on each client PC (or by your CA
estate), and the engine's only job is to present a cert whose SAN matches the host in
`web_console_public_address`.

| Engine cert | What the remote PC needs |
|---|---|
| Issued by your enterprise CA (AD CS), root already in the machine/domain trust store | nothing — it just works |
| Issued by a public CA (Let's Encrypt, etc.) | nothing — public roots ship with the OS/browser |
| **Self-signed**, or an internal CA **not** in this PC's trust store | install that cert / CA into the client's trust store (Windows: *Trusted Root Certification Authorities*, per-machine via GPO for a fleet) |

Clicking through the browser's interstitial is **not** a substitute: it leaves the origin flagged, it
is per-browser-profile, and it has to be repeated on every client. Install the anchor instead.

### Mutual TLS (optional) — a listener-wide requirement

**This is an Option A control only.** `[api].tls_client_ca_file` **requires `[api].tls_cert_file`**
(refused at config load without it), so it exists only where the engine terminates TLS itself. Under
Option B the engine sees no handshake — client certificates are the **proxy's** job there, and the
reference terminator configs in `security/OFF-LOOPBACK-DEPLOYMENT.md` are where that is configured.

Setting `[api].tls_client_ca_file` puts the whole listener in `ssl.CERT_REQUIRED`
([`api/tls.py`](../messagefoundry/api/tls.py)), so **every** client must present a cert the browser
picks from the OS certificate store — including the tray's `/health` poll and anything else on the
box. Roll it out to all clients in the same change, or they stop connecting.

mTLS here is **transport authentication only** unless you also populate
`[api].tls_client_cert_identities`, and even then a cert identity reaches exactly one route
(`GET /service/identity`) and is PHI-fenced — it is not a way to sign in to `/ui`. See
[`CONFIGURATION.md`](CONFIGURATION.md) `[api]`.

> **Footnote — the retired client's flags.** The desktop console's `--cacert`, `--client-cert` /
> `--client-key`, `--insecure` and `--poll` **do not exist**: there is no `messagefoundry.console`
> module and `[project.scripts]` ships only `messagefoundry` (plus the `messagefoundry-tray`
> gui-script). The trust model behind them survives as **library** keyword arguments on
> `EngineClient` — `cacert=`, `tls_client_cert=`, `tls_client_key=`, `allow_insecure=`
> ([`apiclient/client.py`](../messagefoundry/apiclient/client.py)) — used by the PySide6 test harness
> and any Python API client. They are not an operator surface, and none of them affects the browser.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Browser warns the certificate is not trusted | The engine cert's issuer isn't in this PC's trust store. Install the issuing CA (or the self-signed cert) into the client's trust store — there is no engine-side flag for this. |
| Hostname mismatch in the browser | The engine cert's SAN doesn't cover the host in `[security].web_console_public_address`. Reissue the cert with the right SAN, or point the origin at a name the cert covers. |
| `https://…/ui` returns 404, engine started fine | The console auto-degraded to JSON-only: `[security].serve_web_console` was left at its default on an exposed instance, or the `messagefoundry-webconsole` wheel is missing. Both print a stderr warning at startup — check the service log. |
| Engine won't start: `refusing to serve the browser ops dashboard … without TLS` | An off-loopback `/ui` bind with no TLS. Configure `tls_cert_file` (Option A) or `tls_terminated_upstream` + `trusted_proxies` (Option B). `--allow-insecure-bind` does **not** cover `/ui`. |
| Engine won't start: `…serve_web_console=true needs the web console package` | Install `messagefoundry-webconsole` (or set `serve_web_console = false` for a JSON-only engine). |
| Engine won't start: `refusing to serve … on non-loopback host` | An off-loopback `[security].listen_address` without TLS on the JSON API — same fix as above. |
| Engine won't start: `refusing to serve the API with in-process TLS on non-loopback host … performs NO certificate revocation check` | The [ADR 0078](adr/0078-certificate-revocation-posture.md) revocation gate on Option A. Set `MEFOR_TLS_REVOCATION_ATTESTED=1` in the **service environment** (not the TOML), or move to Option B and let the proxy do revocation. This gate reads neither the data label nor `[security].enforcement`, so a synthetic/lab box and a `warn`-dialled box hit it too. |
| Engine won't start: `refusing to serve on a … PHI instance … behind an upstream TLS terminator … without: [api].proxy_intra_service_auth …` | The Posture-B attestation gate on Option B. Declare **both** `[api].proxy_intra_service_auth` (`mtls`/`network`/`shared_secret`) and `[api].proxy_tls_min_version` (`1.2`/`1.3`) — see Option B's block. It fires on a PHI instance under `enforcement = enforce` with an off-loopback bind; the loopback-behind-a-proxy variant warns instead. |
| Signed in, but every route returns `403` with `X-MFA-Required: 1` | `[security].require_mfa` is on (the default) and this account hasn't enrolled a factor. Enrol TOTP or a passkey at `/ui/account`; the browser session is confined to `/ui/mfa` until then. |

The dashboard's live views take updates over the same-origin **`/ws/stats` WebSocket** and fall back
to a ~5s fragment poll whenever that socket is closed or unavailable
([`messagefoundry_webconsole/static/app.js`](../messagefoundry_webconsole/static/app.js)) — so a
proxy or firewall that blocks WebSocket upgrades degrades the refresh rate rather than breaking the
console. Under Option B, configure the proxy to forward the `Upgrade`/`Connection` headers.

See also: [`SECURITY.md`](SECURITY.md) (auth/TLS posture), [`CONFIGURATION.md`](CONFIGURATION.md)
(the full `[api]` settings), [`SERVICE.md`](SERVICE.md) (running the engine as a service).
