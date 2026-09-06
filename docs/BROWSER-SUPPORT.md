# Web console browser support

**The console warns, it never blocks.** Every browser security feature it relies on is
defense-in-depth. When a browser does not support one, the console keeps working and either shows you
a warning or falls back to a server-side control that does the same job. This page states which
features those are and what each absence costs you.

It covers the operator UI at `/ui` only. The engine's HTTP API needs no browser at all.

> **Where this comes from.** Every row below is derived from the shipped code: the headers the console
> and engine write onto a `/ui` response, the `window.<Feature>` reads in the console's own scripts,
> and the attributes on the session cookie. A test in the console package
> (`test_ui_csp_canary.py`) re-derives the same three sets on every run and fails if the in-code
> contract stops naming one of them.

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
| **WebAuthn passkeys** (`window.PublicKeyCredential`) | The passkey button is disabled and the line beside it reads "This browser does not support passkeys." A passkey is never the only factor, so you can still sign in and still enroll MFA with a password and a TOTP code. |

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
| `X-Content-Type-Options` | MIME-sniffing suppression. | The `/ui` static mount serves only `.css` and `.js`, from one fixed directory, with correct types. No operator-supplied file is ever served from the console's origin. |
| `X-Frame-Options` | The legacy framing block. | Pure redundancy. `frame-ancestors 'none'` in the CSP is the modern control, and any browser that honours the nonce CSP honours it. |
| `Referrer-Policy` | Referrer suppression via the header. | The same policy is carried in the page itself by a `<meta name="referrer">` tag, and `/ui` URLs carry no operator-typed search term and link off-site nowhere. |
| `Strict-Transport-Security` | The browser's own downgrade protection. Sent only over effective HTTPS. | Your reverse proxy terminates TLS and is configured to redirect cleartext, and the insecure-connection banner above makes a cleartext hop visible in the page. |
| Session cookie `__Host-` prefix, `Secure`, `HttpOnly` | Prefix and transport binding on the session cookie. | `HttpOnly` is what makes these invisible to a page script in the first place. They are only ever set where a browser will honour them, session termination is server-side, and every state-changing `/ui` POST carries a server-side `Sec-Fetch-Site` / `Origin` check. |
| Session cookie `SameSite=Strict` | The browser's own cross-site request block. | That same server-side `Sec-Fetch-Site` / `Origin` check, on every state-changing `/ui` POST including login and logout. A browser that ignores `SameSite` still cannot be driven cross-site. |

---

## Two configurations turn the warnings off

The four detects are emitted only when the console binds a per-response CSP nonce. In two cases it
binds none, and **all four warnings disappear from the page**:

1. `MEFOR_WEBCONSOLE_DISABLE_BROWSER_HARDENING` is set. This is the deliberate escape hatch for a
   legacy proxy or browser that cannot tolerate a `__Host-` cookie or a nonce CSP.
2. The console is reached over cleartext on a non-loopback address with no declared TLS terminator.

In both cases the console falls back to the engine's static `script-src 'self'` policy and the plain
session cookie. Nothing is left unprotected, but you also get no banner, so do not read a clean page
as evidence that the browser is conforming. If you set the variable, record why.

---

## Related

- [System requirements](SYSTEM-REQUIREMENTS.md) for the console's place in a deployment.
- [Security](SECURITY.md) for authentication, RBAC and the trust boundary.
- [Deployment](DEPLOYMENT.md) for the reverse-proxy and off-loopback preconditions.
