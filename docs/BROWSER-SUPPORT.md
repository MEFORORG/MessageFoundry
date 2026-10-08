# Browser support

**When a browser lacks a security feature the console relies on, the product warns you, refuses the
request, or leans on a control that does not need the browser.** Each row on this page says which of
the three applies:

- **Warns.** The page shows a message you can read.
- **Fails closed.** The server refuses the request, or the page does nothing.
- **Named control.** Something that does not depend on the browser does the same job, and the row
  names it.

Where a row has none of the three, the row says so in those words. At least one such case is left:
see [Two configurations turn the warnings off](#two-configurations-turn-the-warnings-off).

It covers the operator UI at `/ui`, the IDE extension's webviews, and at least these engine routes
outside `/ui` that a browser reaches:

- **The `/ws/stats` WebSocket.** The console's dashboard opens it with the session cookie. The server
  checks the handshake's `Origin` header before it accepts the socket.
- **The API documentation pages**, served only when you set `[api].expose_docs = true`. They are off
  by default. See [the engine's API pages](#the-engines-api-pages-load-third-party-scripts) below.
- **The client-network denial page**, served in place of any route when
  `[security].allowed_client_networks` refuses your address. See
  [the denial page](#the-client-network-denial-page-needs-no-browser-feature) below.

The engine's other routes serve programs, mostly with JSON. This page makes no claim about what a
browser does with them.

> **Where this comes from.** Every row below was read from the shipped code, or measured where the
> text says so. Two tests in the console package check parts of it on every run, and only those parts:
>
> - `test_ui_csp_canary.py` fails if the two tables under "What each absence does" stop naming a
>   response header, a `window.<Feature>` detect or a session-cookie attribute the code uses.
> - `test_browser_support_doc.py` fails if a `Sec-Fetch-*` or `Origin` header it finds read in the
>   console's code, or in the engine's WebSocket check, has no row, if a row's
>   **Allowed** or **Refused** verdict stops matching what the code does without that header, if
>   the opt-out cookie names or the HSTS conditions change, or if the list of IDE webviews or the
>   one with a host-side startup check changes. It also fails if an IDE panel stops carrying the two
>   banners quoted below, if their wording here drifts from the code, if the denial page's header
>   or policy changes, or if FastAPI's API pages gain or lose a no-JavaScript message.
>
> Nothing checks the middle column of the request-header table, the API pages' list of what they
> load, or the IDE table's description of each panel. Those were read or measured when written.

---

## One feature decides whether the console works: CSP nonce sources

The console serves a per-response Content-Security-Policy of the form
`script-src 'nonce-<random>' 'strict-dynamic'`. There is no host allowlist and no inline script. A
browser that enforces CSP but does not understand a `'nonce-...'` source therefore has no valid script
source, and blocks every script on the page.

That is the one case where you lose real function, so the console detects it without needing any
script to run. The banner is rendered by the server and is visible by default. A script removes it
from view, so it only stays up when scripts really are blocked:

> This browser is not running the console's scripts: Content-Security-Policy nonce sources are
> unsupported or JavaScript is disabled. Client-side protections [...] are NOT active. Server-side
> session expiry, permissions and auditing still apply. Use a current browser with JavaScript enabled.

The same banner covers a browser with JavaScript turned off.

**`'strict-dynamic'` is not part of the floor.** It is a CSP Level 3 keyword. A CSP Level 2 browser
does not recognise it, ignores it, and matches the nonce instead, so the console's scripts still run.
Only nonce-source support decides the outcome. The two cases look identical in a smoke test, which is
why the distinction is written down here rather than left to a tester.

### Minimum browser versions are deliberately not stated

**Unresolved.** MessageFoundry ships no pinned browser-compatibility dataset, so there is no version
table here that anyone could check against a source. Naming engine versions without one would mean
writing numbers chosen to match what already works, which tells you nothing about the feature the
console actually needs.

What would resolve it: pinning a versioned compatibility dataset into the repository and resolving
each feature in the table below to a per-engine minimum from it. That work is not funded yet.

Until then the floor is stated as a feature, and the console tells you at the moment of degradation.
Both statements are checkable. A version number would be neither.

---

## What each absence does

### Detected and warned

The console watches for these four and tells you in the page.

| Feature | What you see when it is missing |
|---|---|
| **HTTPS transport** (`window.isSecureContext`) | A banner: the console is not served over HTTPS, so secure cookies, COOP and CSP nonces are degraded. Correctly silent on `http://127.0.0.1`, which browsers already treat as a secure context. |
| **CSP enforcement** | A banner: this browser does not enforce Content-Security-Policy, so script-injection defenses are not being applied. The console proves this by loading one script that a conforming browser must refuse. |
| **CSP nonce sources / script execution** | The server-rendered banner quoted above. |
| **WebAuthn passkeys** (`window.PublicKeyCredential`) | The passkey button is disabled and the line beside it reads "This browser does not support passkeys." An account with no factor yet can still enroll TOTP here, and an account that also holds TOTP can still finish MFA with a TOTP code. Some accounts hold a passkey and no TOTP, at least a directory account and a local account outside `[security].require_mfa` ([the order](SECURITY.md#webauthn-passkeys-wp-14b-adr-0068)). If the engine asks such an account for its factor, it cannot answer in this browser. It cannot enroll TOTP until it does, so use a browser that supports passkeys, or ask an administrator to reset its MFA. |

### Degrades silently, with a control that still holds

No browser interface reports whether these took effect, so the console cannot warn you. Each one is
paired with a control that does not depend on the browser.

| Feature | What you lose | What still protects you |
|---|---|---|
| `Cross-Origin-Opener-Policy` | Process isolation for the console's browsing context. | `/ui` opens no cross-origin window and embeds no cross-origin content. The CSP's `frame-ancestors 'none'` still blocks framing. |
| `Cross-Origin-Resource-Policy` | A cross-origin read block on console resources. | `/ui` serves no resource meant to be embedded elsewhere. |
| `Reporting-Endpoints` | Delivery of CSP violation reports on the modern route. | Telemetry only, never a control. The legacy `report-uri` directive goes out alongside it, so most such browsers still deliver reports. |
| `Clear-Site-Data` | Storage clearing when a session ends. Safari does not support it. | The session is revoked on the server, the cookie is deleted, every `/ui` page is `Cache-Control: no-store`, and the idle-logoff script blanks the page before it navigates away. |
| `Cache-Control: no-store` | Cache and back-button suppression for console pages and PHI responses. | `Clear-Site-Data` on session end, the page blanking above, and the server refusing every request a restored page would make. |
| `X-Content-Type-Options` | MIME-sniffing suppression. | The `/ui` static mount serves only `.css` and `.js`, from one fixed directory, with correct types. The one `/ui` route that serves stored message content as a file, the attachment download, also carries `Content-Disposition: attachment` and a sandbox policy (see its row below). |
| `X-Frame-Options` | The legacy framing block. | Pure redundancy. `frame-ancestors 'none'` in the CSP is the modern control, and any browser that honours the nonce CSP honours it. |
| `Referrer-Policy` | Referrer suppression via the header. | The same policy is carried in the page itself by a `<meta name="referrer">` tag, and `/ui` URLs carry no operator-typed search term and link off-site nowhere. |
| `Strict-Transport-Security` | The browser's own downgrade protection. The engine sends it only when you supplied a certificate chain or declared a TLS terminator. It is absent on the engine's minted self-signed certificate, which is the shipped default, and on any IP-literal host such as `127.0.0.1`. RFC 6797 tells a browser to ignore it in both places anyway. | The engine's own listener speaks only TLS unless `[api].tls_terminated_upstream` declares a proxy in front of it. Behind such a proxy, redirecting cleartext to HTTPS is the proxy's job, and nothing in the engine checks that it does. The insecure-connection banner above makes a cleartext hop visible in the page. |
| Session cookie `__Host-` prefix (`__Secure-` under the opt-out below), `Secure`, `HttpOnly` | Prefix and transport binding on the session cookie. | `HttpOnly` is what makes these invisible to a page script in the first place. They are only ever set where a browser will honour them, session termination is server-side, and every state-changing `/ui` POST carries a server-side `Sec-Fetch-Site` / `Origin` check. |
| Session cookie `SameSite=Strict` | The browser's own cross-site request block. | That same server-side `Sec-Fetch-Site` / `Origin` check, on every state-changing `/ui` POST including login and logout. A browser that ignores `SameSite` still cannot be driven cross-site: a state-changing request that carries neither header **fails closed** with a 403, as the request-header table below says. |
| `sandbox` in the attachment download's `Content-Security-Policy` | On `/ui/messages/<id>/attachments/<id>`, the engine serves the file under `default-src 'none'; sandbox; frame-ancestors 'none'; base-uri 'none'`. A browser that ignores `sandbox` no longer puts the file in a unique, script-less origin of its own. | The response is always `Content-Disposition: attachment`, so the browser saves the file rather than showing it. Its declared type is an allow-listed inert type (PDF, image, plain text, CSV, JSON, DICOM) or `application/octet-stream`, and `nosniff` applies. The same policy's `default-src 'none'` still blocks every script in a browser that enforces CSP at all. Only a browser that ignored `sandbox`, `Content-Disposition` and `default-src` together would open the file in the console's origin, and nothing would warn you. |

### Request headers the browser sends

These are not features the console can detect. The server reads them on each request, and each row
says what the server does when the header is missing. "Allowed" means the request goes through
unchecked by that rule.

| Header | What the server does with it | When the browser does not send it |
|---|---|---|
| `Sec-Fetch-Site` | On every `/ui` request, static files included, a value of `cross-site` or `same-site` is refused with a 403. The one exception is a safe top-level navigation, defined by the next three rows. Every state-changing `/ui` POST refuses those two values again. On such a POST the header settles the request by itself only as exactly `same-origin` or `none`. The complete rule is the table in the `assert_same_origin` docstring (`messagefoundry_webconsole/_auth.py`), which a test drives row by row. | **Allowed** by the middleware, which passes the request. A page read then rests on the `SameSite=Strict` session cookie. A state-changing POST does not get through on this alone: the `Origin` check below takes over, and it refuses a POST that carries neither header. |
| `Sec-Fetch-Mode` | A `cross-site` or `same-site` request passes only as a `navigate` GET or HEAD. The Kerberos and OIDC sign-in routes also reject, and audit, any mode other than `navigate`. | **Refused** by the middleware, which reads it only after `Sec-Fetch-Site` said `cross-site` or `same-site`. The sign-in routes allow a request without it. |
| `Sec-Fetch-Dest` | That navigation must be for a `document`. This refuses cross-site framing before anything is served. | **Refused**, and read only after `Sec-Fetch-Site` said `cross-site` or `same-site`. |
| `Sec-Fetch-User` | A `same-site` navigation must carry `?1`, meaning the user started it with a click or a key. A `cross-site` one is not asked for it, so an identity provider's redirect back to the console still works. | **Refused**, and read only for a `same-site` navigation. |
| `Origin` on a form POST | Read only when `Sec-Fetch-Site` is missing or empty. It must equal `[security].web_console_public_address` when that is set, or else the request's `Host`. Behind a proxy in front of a loopback bind with no public address set, nothing matches and the POST is refused. | **Refused.** A state-changing `/ui` request that carries neither `Sec-Fetch-Site` nor `Origin` **fails closed** with a 403 that says so, and nothing is changed. That covers the sign-in POST, which has no session cookie yet for `SameSite=Strict` to withhold, and sign-out. A browser that sends neither header on its own form POST cannot sign in. **Three sign-in GETs are deliberately not blocked for missing fetch metadata**, under owner rulings R4 and R4b of 2026-09-28: `GET /ui/sso`, `GET /ui/oidc/callback`, and `GET /ui/oidc/start` when its "leaving this site" page is skipped. The first two never run this check. The third runs it as a GET, and a GET that carries neither header goes on to the identity provider; the GET rows of the docstring table named in the `Sec-Fetch-Site` row above say the rest. Not measured in a real browser: the console sends `Referrer-Policy: no-referrer`, and the Fetch standard then has a browser send `Origin: null` on a form POST, which this check refuses as a mismatch. Measured against the code, not a browser: a POST with no `Sec-Fetch-Site` and `Origin: null` was already refused before this rule existed, so nothing is new for a browser that sends `Origin` and no `Sec-Fetch-Site`. The rule is new only for a browser that sends neither header on its own form POST, and whether such a browser can run the console at all is unmeasured. If one exists and Kerberos or federated sign-in is on, one of those three GETs could still give it a session whose writes are refused, sign-out included; that session would end at least by expiry or by an administrator revoking it. At least one `/ui` POST is outside this rule, the CSP report sink `/ui/csp-report`: it reads `Sec-Fetch-Site` only, because a browser's reporting agent sends no fetch metadata, and it changes nothing. |
| `Origin` on the `/ws/stats` WebSocket handshake | The console's cookie handshake must come from the console's own origin, by the same rule as a form POST, or it is refused. The engine's own handshake path accepts a browser `Origin` only if `[api].ws_allowed_origins` lists it, and that list is empty by default. | **Allowed** by the `Origin` rule. A handshake with no `Origin` is treated as a program's, and the next check wants an `Authorization` header that a browser cannot set, so a browser still gets no socket. The dashboard then keeps its table current by polling over HTTP, and its queue-count line stays empty. Only an app built with authentication explicitly turned off, an embedding or development case, accepts the handshake. |

---

## Two configurations turn the warnings off

Three of the four detects are emitted only when the console binds a per-response CSP nonce: the
HTTPS banner, the CSP-enforcement banner and the scripts-blocked banner. In two cases it binds none,
and **those three banners disappear from the page**:

1. `MEFOR_WEBCONSOLE_DISABLE_BROWSER_HARDENING` is set. This is the deliberate escape hatch for a
   legacy proxy or browser that cannot tolerate a `__Host-` cookie or a nonce CSP.
2. The console is reached over cleartext on a non-loopback address with no declared TLS terminator.
   `messagefoundry serve` no longer produces this case, because the engine always serves TLS or runs
   behind a declared terminator. Only code that builds the engine's app directly can reach it.

In both cases the console falls back to the engine's static `script-src 'self'` policy, and drops
`Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` and `Reporting-Endpoints`. The passkey
line still appears, because it lives in the console's main script, which that policy still runs.

**In these two configurations those three absences have none of the three answers.** The page does
not warn, the server does not refuse, and no other control tells you that the browser ignores CSP or
runs no script. The server-side controls in the tables above still hold. The first configuration is a choice you
make by setting the variable. The second cannot be reached through `messagefoundry serve`, and
nothing else covers it.

The cookies differ between the two cases:

| Case | Session cookie | Federated sign-in flow cookie |
|---|---|---|
| The opt-out, over HTTPS (every `messagefoundry serve` posture) | `__Secure-mf_session` | `__Secure-mf_oidc_flow` |
| Any cleartext origin, including case 2 | `mf_session` | `mf_oidc_flow` |

Over HTTPS the opt-out withholds only the `__Host-` prefix. The cookies keep `Secure`, which is all the
`__Secure-` prefix requires. Nothing is left unprotected, but you also get no banner, so do not read a
clean page as evidence that the browser is conforming. If you set the variable, record why.

**The opt-out names can be planted; `__Host-mf_session` cannot (BACKLOG #2454).** A sibling host
could set a `__Secure-mf_session` or `mf_session` copy for the parent domain. Once the console had
set its own cookie, the browser would send two copies, and the console refuses a repeated session cookie with `400`, so every page
would answer `400` until the planted cookie is cleared. No mitigation is built; this is a known
gap, recorded in [SECURITY.md](SECURITY.md).

---

## The engine's API pages load third-party scripts

`[api].expose_docs = true` turns on the routes FastAPI provides for its API documentation: `/docs`
(Swagger UI), `/docs/oauth2-redirect`, `/redoc` (ReDoc) and the `/openapi.json` schema the pages
read. They are off by default and are not part of the console. Measured on 2026-09-28 against
FastAPI 0.141.1, the version this engine locked then, the pages load:

| Page | What it loads |
|---|---|
| `/docs` | Swagger UI's script and stylesheet from `cdn.jsdelivr.net` (`swagger-ui-dist@5`, a floating major version), a favicon from `fastapi.tiangolo.com`, and one inline script. |
| `/docs/oauth2-redirect` | One inline script and nothing from outside the engine. |
| `/redoc` | ReDoc's script from `cdn.jsdelivr.net` (`redoc@2`), a stylesheet from `fonts.googleapis.com`, and the same favicon. |

These URLs are FastAPI's defaults and can change when FastAPI is upgraded.

What that means for a browser:

- **Their only CSP is `frame-ancestors 'none'; base-uri 'none'`.** It blocks framing and `<base>`
  injection and nothing else, so no script source is restricted, and the files carry no integrity
  hash. What runs is whatever those hosts serve that day.
- **They need JavaScript and a route to those hosts, and they fail closed without either.** The
  page then shows no documentation and offers nothing to click. What it tells you differs:
  - `/redoc` with JavaScript off shows FastAPI's own line, "ReDoc requires Javascript to function."
    That is a warning.
  - `/docs` with JavaScript off is a blank page. It has no such line, so nothing tells you why.
  - Either page with JavaScript on and those hosts unreachable is blank too, with no message.

  A blank page here loses the page's own function. The `/openapi.json` schema the pages read is
  served the same way with or without JavaScript, so a blank page hides nothing that a direct
  request would not get. A blank page is still not a warning, and this page does not count it as
  one.
- The engine still sends `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: no-referrer` on them, as on every response.

Leave `[api].expose_docs` off unless you need these pages, and never turn it on for an engine that a
browser reaches off the host.

---

## The IDE extension's webviews

The VS Code extension draws its forms and views as webviews. A webview is a page that VS Code renders
with its own built-in browser engine, so the browser here is whichever one your VS Code release
ships. The extension declares `engines.vscode ^1.95.0` and states no separate browser floor.

**Every panel that runs a script warns you when that script has not started.** The panel's page
carries a plain-text banner that shows by itself one second after the page loads, and the panel's own script hides it as soon
as it has the VS Code API. The banner needs no script, no stylesheet and no message from the
extension, so it stays up whenever the script is blocked, fails to load, or stops at that first
step:

> MessageFoundry: this panel's script has not started, so its buttons and fields do nothing. Close
> the panel and open it again. If this message stays, VS Code is not running the panel's script.

Under the banner, the panel shows whatever the extension rendered into it, and every button and
field that talks to the extension does nothing. The table says what that is for each panel.

The banner does not cover a script that starts and fails later. **Only one webview also has a
host-side startup check**: the Steps view, in its row below.

| Webview | Source | What you see under the banner if its script does not run |
|---|---|---|
| Home, in the side bar | `home.ts` | The search box and the list of actions. Clicking one does nothing. |
| Route Wizard | `newRoute.ts` | The heading and the Back, Next and Cancel buttons. Every step's fields stay hidden, because the script is what shows them. |
| Connection form | `connectionEditor.ts` | The heading "New Connection", even for a connection that already exists, and a form with none of its saved values. The Transport and Router lists are empty, the Settings area has no rows, and the inbound and outbound options both show at once. Save does nothing. |
| Alert rules | `alertEditor.ts` | The headings and an empty rules table. The Event and Severity lists are empty. |
| Translation table | `codeSetEditor.ts` | The heading and an empty grid. The row and column buttons do nothing. |
| `connections.toml` and code-set editors | `configEditors.ts` | The connection form and the translation table above, with the same result. A file outside the config directory gets a one-line text notice instead, rendered with scripts turned off and no CSP, since it has no script to restrict. That notice runs no script, so it carries neither banner. |
| Security settings | `securityEditor.ts` | The heading and the Save and Close buttons. The form itself is blank, because the script builds it. |
| Config repo storage | `sourceControl.ts` | The options, with the current choice marked. Save does nothing. |
| Cookbook | `cookbook.ts` | Every recipe card. Search and Insert do nothing. |
| Engine setup | `engineSetup.ts` | Every section. Its buttons do nothing. |
| Wiring map | `wiringMap.ts` | The toolbar and the legend. The graph is blank, because the script draws it. |
| Test Bench | `testBench.ts` | The toolbar and any results already rendered. Its buttons do nothing. |
| Steps view | `stepsView.ts` | The rows. **If its script has not reported in within 3 seconds, VS Code shows an error** saying the view's script did not initialize and pointing you to the code view. When it falls back to text, it shows a one-line notice whose CSP allows no script at all, and which carries neither banner. |

**If VS Code's browser engine ignored CSP, each of those panels would warn you.** Each panel that
runs a script carries a `<meta>` CSP with `default-src 'none'` and a per-render `script-src` nonce.
The Steps view also allows scripts from the extension's own `media` folder. Each such panel also
carries one small script with no nonce. An engine that enforces the policy must refuse that script.
An engine that ignores the policy runs it, and it reveals a second banner:

> MessageFoundry: VS Code is not enforcing this panel's Content Security Policy, so the panel's
> defense against injected script is not active. Update VS Code, and treat what this panel shows
> with care until the message is gone.

This is the same idea as the console's CSP-enforcement banner above, with one difference. The
console loads its test script from a file. A webview has nowhere to report a blocked file and most
panels may load no files at all, so the webview's test script is inline.

What the second banner does not show:

- It proves that the engine blocks an inline script with no nonce. It says nothing about any other
  part of the policy.
- It warns, and it does not stop anything. With the policy ignored, script injection into a panel
  would no longer be blocked. The message checks in `ide/src/webviewMessaging.ts` would still reject
  a message from another origin, but they do not stop a script already running inside a panel.
- An enforcing engine logs one blocked-script line per panel in the webview's developer console.
  That line is the check working.

---

## The client-network denial page needs no browser feature

When `[security].allowed_client_networks` is set and your address is outside it, the engine refuses
the request before sign-in and before any route runs. This is a block, not a degraded page. At
least the `/health` probe is exempt from the rule.

The answer has two shapes, and both are a `403` that carries the header
`X-MessageFoundry-Denied: client-network`:

| Request | What comes back |
|---|---|
| A path at or under `/ui`, or any request whose `Accept` header names `text/html` | A plain HTML page: "Blocked: your network is not permitted". It names the address the engine saw and the setting an operator changes. |
| Anything else | A JSON body with the same message, a `denied` field of `client-network`, and the observed address. |

The page is built to work in a browser that supports nothing beyond HTML:

- It runs no script and loads nothing from outside itself. Its policy is `default-src 'none'` with
  inline styles allowed, plus `frame-ancestors 'none'` and `base-uri 'none'`. A browser that
  ignored the policy would have no script on the page to run.
- A browser that ignored its one inline style block would still show the same text, unstyled.
- The console's own banners do not appear on it, because the console never serves this response.

A WebSocket handshake from a refused address gets the same `403` where the server supports refusing
a handshake that way, and a plain close otherwise. The console's dashboard is then the page above,
since its own page request was refused first.

---

## Related

- [System requirements](SYSTEM-REQUIREMENTS.md) for the console's place in a deployment.
- [Security](SECURITY.md) for authentication, RBAC and the trust boundary.
- [Deployment](DEPLOYMENT.md) for the reverse-proxy and off-loopback preconditions.
