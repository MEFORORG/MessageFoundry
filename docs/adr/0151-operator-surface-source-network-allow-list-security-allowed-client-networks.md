<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0151 — Operator-surface source-network allow-list (`[security].allowed_client_networks`)

- **Status:** Accepted (2026-07-22) — built + green; default-off and byte-identical when unset. Owner accepted D-1 (evaluate `scope["client"]`, no second XFF trust path), D-3 (REFUSE a multi-address `trusted_proxies` alongside the allow-list), the unconditional middleware registration, and the `/health` `observed_client` echo — the last two because a control that can silently fail to install, or refuse undiagnosably, is the failure mode this ADR exists to remove.
- **Date:** 2026-07-22
- **Related:** [ADR 0118](0118-secure-by-default-security-configuration-section.md) (the `[security]` section this switch joins) · [ADR 0065](0065-web-ops-dashboard.md) (the `/ui` console this protects) · [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md) §8 (the off-loopback ladder + the XFP tripwire precedent) · [ADR 0113](0113-windows-tray-service-manager-stdlib-ctypes-tokenless.md) (the tokenless `/health` poll the loopback carve-out protects) · [ADR 0023](0023-inbound-http-listener.md) (the per-connection `source_ip_allowlist` this deliberately does **not** touch) · docs/security/OFF-LOOPBACK-DEPLOYMENT.md · [docs/SECURITY-LOOSENING.md](../SECURITY-LOOSENING.md)

---

## Context

When an operator opts the console off-box (`[security].local_access_only = false`, or a loopback bind
behind a declared reverse proxy), the requirement is that it be reachable **only from the hospital
network, never the internet**. Today that requirement is delegated **100% to firewall**. The engine
holds no expression of it: `GET /security/posture` cannot report it, `messagefoundry check` cannot
verify it, and an ASVS assessor reading the whole `[security]` section learns nothing about it.

The concrete failure this is aimed at is not a sophisticated attacker. It is
[`docs/REMOTE-CONSOLE-CUSTOMER-GUIDE.md`](../REMOTE-CONSOLE-CUSTOMER-GUIDE.md) instructing
`host = "0.0.0.0"`: an operator who means one clinical NIC and gets a second on a management or
backup VLAN is today contained by nothing inside the product.

## Decision

Add `[security].allowed_client_networks`: a list of CIDR networks / bare host addresses. **Empty (the
default) means no restriction and is byte-identical to today.** Non-empty means a request whose client
address falls outside every listed network is refused with 403 in ASGI middleware — before routing,
before any dependency, before auth.

It covers the **operator surface only** (the uvicorn-served FastAPI app: JSON API, `/ui`, `/ui/static`,
`/ws/stats`). It does **not** touch the MLLP/TCP/X12/DICOM/HTTP ingest listeners, which keep their own
per-connection `source_ip_allowlist`.

### D-1 — the address evaluated is `scope["client"]`, never a header we parse

This is the whole correctness argument and everything else hangs off it.

uvicorn's `ProxyHeadersMiddleware` is the **single** X-Forwarded-For trust point in the process. It
rewrites `scope["client"]` from XFF when, and only when, the socket peer matches
`forwarded_allow_ips` — which [`__main__.py`](../../messagefoundry/__main__.py) feeds verbatim from
`[api].trusted_proxies`. So the check is keyed on `trusted_proxies` **by construction**; there is
deliberately no `if trusted_proxies:` anywhere in our decision, and adding a second in-app XFF parse
would create a divergent trust path. Across the three exposure routes:

| Route | Topology | What the gate sees | Verdict |
|---|---|---|---|
| **R1** | Direct NIC bind, no proxy declared | the raw socket peer; `_TrustedHosts([])` matches nothing, so the XFF branch never runs | **Sound.** An attacker's XFF is ignored outright |
| **R2** | Loopback bind behind a **declared** proxy (the *recommended* topology) | the real client, already substituted by uvicorn before any app middleware | **Sound**, given D-3 |
| **R3** | Proxy in front, **nothing declared** | 127.0.0.1 for every request in the world → loopback carve-out admits it | **INERT.** Detected only, never fixed |

R3 is an honest limit with a regression test pinning it. The same holds for a bridge-networked
container and any SNAT'ing firewall. **This must never be documented as covered.**

### D-2 — loopback is allowed unconditionally

Not "loopback iff no `X-Forwarded-For`". That variant breaks the runbook's own recommended topology:
with nginx **on the engine box** proxying to `127.0.0.1`, an on-box operator's browser produces
`X-Forwarded-For: 127.0.0.1`, uvicorn finds every hop trusted and returns `127.0.0.1` *with XFF
present* — so the conditional rule locks the on-box operator out of the supported posture.

The credential-less on-box clients cannot be allow-listed at all: the tray's tokenless `/health` poll
(ADR 0113), a browser opening `/ui` on the engine host, `messagefoundry check`, the harness/apiclient,
a container HEALTHCHECK. Naming a ward subnet must never lock the box out of its own console. The
carve-out lives in the *operator* matcher only — the ingest `source_ip_allowlist` does not inherit it.

The forgery D-2 would otherwise re-open is closed by D-3 instead.

### D-3 — setting the allow-list REFUSES a multi-address `[api].trusted_proxies` entry

Any host inside a trusted range can set `X-Forwarded-For` to anything and uvicorn hands that value
back as `scope["client"]`. So `trusted_proxies = ["10.0.0.0/8"]` — which our own docs recommended —
makes **every workstation on a 10/8 LAN a trusted spoofer**, and silently reduces the allow-list to
decoration, from exactly the actor in the threat model (a phished workstation on the ward subnet).

**Refuse, not warn.** A warning on an off-box PHI console is a warning nobody reads, and the check can
only fire on the opt-in, so it cannot break an existing deployment. (The unconditional `"*"` and
unparseable-entry refusals on `trusted_proxies` are a separate, already-landed prerequisite.)

### D-4 — the "exposed with no allow-list" advisory keys on EXPOSURE, not the bind

`security_loosenings` gated on `not local_access_only` alone would never fire in **R2** — the
most-exposed supported posture, where the bind stays loopback. Gate on
`not local_access_only or bool(web_console_public_address)`. This entry is deliberately *conditional*,
unlike every other loosening: an empty list on a loopback bind is the **secure** position.

### D-5 — diagnosability is part of the control, not a nicety

An undiagnosable CIDR rejection is the most likely way this gets ripped back out the first week. So a
denial is: a distinct 403 carrying `X-MessageFoundry-Denied: client-network`; an HTML page for browsers
(self-contained — `/ui/static` is behind this same gate) naming the setting and echoing the observed
address, JSON otherwise; a rate-limited log line saying the same; and counters on
`GET /security/posture`. `/health` stays **exempt** and echoes `observed_client` when the allow-list is
in use, so a locked-out operator can `curl` it from the machine that cannot get in and read back
exactly which address the engine matches — which also immediately exposes an R2/R3/NAT misresolution.

Echoing the observed address discloses to a caller only what it already knows.

### D-6 — startup-only, and no startup gate

`[security]` is read at startup; `POST /config/reload` re-runs the graph, not `[security]`. A lockout
therefore costs a service restart from console/RDP — stated loudly in the runbook rather than papered
over. An exposed bind with an empty list **starts** (advisory only); the switch is opt-in.

## Consequences

**Mechanism.** A pure-ASGI middleware registered **last** in `create_app` (= outermost) and **outside**
the `serve_ui` guard, so it is above every route, dependency, body cap and auth check, and covers the
`/ui/static` mount and the `/ws/stats` WebSocket. Pure-ASGI is load-bearing: `BaseHTTPMiddleware` passes
every WebSocket scope straight through, so that form would have left `/ws/stats` reachable from any
address. It **returns** a response rather than raising `HTTPException`, which at this position would
surface as a 500. It must stay *inside* uvicorn's `ProxyHeadersMiddleware`, which it is automatically by
being part of the app uvicorn wraps — wrapping the app in `__main__` before `uvicorn.run` would break R2
completely.

The matcher is hoisted to a neutral, stdlib-only `messagefoundry/netaddr.py` so the operator surface and
the ingest listeners share **one** matcher and one CIDR syntax and can never disagree.

**What this does NOT protect against — state these, do not soften them:**

1. **It does not stop the stated threat actor in the common case.** Nobody maintains 40 `/32`s against
   DHCP; the realistic entry is the ward or site supernet, and a phished workstation *is in that
   supernet*. It excludes an attacker only when their foothold is on a segment operators do not use
   (guest wifi, biomed/IoT, vendor VLAN) **and** the hospital is actually segmented. On a flat /16 it
   excludes nobody.
2. **It is the weaker layer and the repo already ships the stronger one.** A Windows Firewall
   `-RemoteAddress` rule ([`docs/ANTIVIRUS-FIREWALL.md`](../ANTIVIRUS-FIREWALL.md)) is the identical
   control enforced at SYN — before TCP accept, before TLS. This middleware completes the handshake and
   TLS first. **Frame this as defence-in-depth and config-visibility, never as the primary network
   control.**
3. **It is silently inert in three shipped topologies** — R3, a bridge-networked container, any SNAT
   between VLANs. The monoculture tripwire *detects* the silent (loopback) case; it fixes nothing.
4. **It is not authentication and not authorization.** A denied address never reaches auth; an allowed
   address still faces the full RBAC/step-up/MFA stack. The allow-list grants nothing.
5. **It does not stop a confused deputy on an allowed subnet.** DNS rebinding, XSS or CSRF from a
   browser on a listed subnet produces requests whose source address is *genuinely* allowed. Write
   "reachable only from hospital-network source addresses", which any host on those subnets can be made
   to lend — never "reachable only from the hospital network".
6. **It cannot survive a broad `trusted_proxies`** (D-3 refuses that combination) **or request smuggling
   at the front proxy**, which delivers attacker-authored XFF on a trusted connection.
7. **It does not cover ingest.** An operator who sets this and believes the whole box is subnet-restricted
   is wrong.
8. **It has no remote recovery path** (D-6).

**Its genuine value, which should be the headline:** blast-radius containment for a fat-fingered bind;
exclusion of unlisted segments where segmentation exists; and an auditable, in-config posture assertion
an assessor can read in the same artifact as the rest of `[security]` — a firewall rule is invisible to
`GET /security/posture`.

**Deferred:** the VS Code `securityEditor.ts` field (owner-deferred — the CLI/TOML path works today); a
step-up `POST /security/client-networks` hot-reload that refuses a write excluding the calling request's
own address.

**#26-clean** — a config switch and a middleware; no visual/template-driven authoring, no channel element.
