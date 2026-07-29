# 0126 — Outbound forward/egress web proxy for the stdlib HTTP family

- **Status:** Accepted
- **Date:** 2026-07-17
- **Related:** [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) (stdlib-only HTTP transport) · [ADR 0024](0024-smart-backend-services-token-provider.md) (SMART token provider) · [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) (posture-keyed insecure-hop refusal) · CLAUDE.md §2 (one-way deps), §9 (PHI) · BACKLOG #112 (address / "Use Default Web Proxy") · #127 (credential types) · #128 (intranet bypass)

---

## Context

A site may mandate that **all outbound HTTP egress traverse a corporate forward/egress proxy**
(BACKLOG #112). The engine's HTTP family — REST, SOAP, FHIR (write + `fhir_lookup` read), DICOMweb
STOW-RS, and the OAuth2 / SMART Backend Services **token-endpoint** calls — all delivers through one
stdlib `urllib.request` opener built in [`transports/rest.py`](../../messagefoundry/transports/rest.py)
(`_NO_REDIRECT_OPENER`, reused by `soap.py`/`fhir.py`/`smart.py`/`dicomweb.py`/`http_auth.py`). Because
`build_opener` is called with no explicit `ProxyHandler`, urllib's *default* one picks up a proxy only
**incidentally** from the process-wide `HTTP_PROXY`/`HTTPS_PROXY` env vars — undocumented, all-or-nothing,
never per-connection, and unable to authenticate to the proxy. Every in-repo "proxy" setting today is the
opposite direction (an inbound reverse proxy that terminates TLS).

This is a **new network intermediary that sees PHI**: for an `http://` destination it sees the cleartext
request **body**; for an `https://` destination it sees the **`CONNECT host:port`** it tunnels. CLAUDE.md
§9 is in play verbatim: *"Never log full message bodies at INFO or above"* and *"no PHI leaves the local
environment without explicit, reviewed configuration."* A **proxy credential is a secret** (CLAUDE.md §9:
*"Secrets come from the environment (`MEFOR_*`), never source/tests/commit messages"*). The one-way
dependency rule (CLAUDE.md §2, *"`pipeline/ transports/ parsing/ store/ config/` never import `api/`"*)
and the reliability/purity invariants are unaffected — this is a per-connection transport-config knob, not
routing/handling logic.

Constraint that shaped the design (**#127 stdlib caveat**): urllib's `ProxyBasicAuthHandler` /
`ProxyDigestAuthHandler` are **reactive** — they answer a `407 Proxy Authentication Required` *on the
request*. For an **`https` destination** urllib reaches the proxy with a `CONNECT` tunnel, and the `407`
arrives **inside** the tunnel setup where those handlers never see it, so reactive proxy-auth **does not
work for https destinations**.

## Decision

Add a **per-connection forward-proxy** to the stdlib HTTP family, built into a **per-connection
`ProxyHandler`** threaded through **every** opener path — never mutating the shared `_NO_REDIRECT_OPENER`
— plus the OAuth2 and SMART **token-endpoint** openers (partial coverage that proxied data calls but not
token calls would be a bug). Off by default → byte-identical.

**#112 — address / "Use Default Web Proxy".** A per-connection `proxy` setting (`proxy_url`):
- unset → no per-connection proxy (byte-identical: the shared opener's incidental env behavior is
  untouched);
- `"default"` → **Use the OS/environment default web proxy** (`urllib.request.getproxies()`), made
  explicit and per-connection;
- an `http(s)://host:port` URL → an explicit forward-proxy address used for both http and https
  destinations.
An `[egress].proxy_url` (+ `[egress].proxy_no_proxy`) supplies a **site-wide default** the http-family
egress inherits unless the connection overrides it. Credentials stay per-connection.

**#127 — credential types (Basic shipped for all; Digest shipped for http destinations; NTLM/Windows
deferred).** `proxy_auth_type` ∈ `{basic, digest, ntlm, windows}`, with `proxy_user`/`proxy_password`
(secret → `env()`):
- **Basic (default)** — a **pre-emptive** `Proxy-Authorization: Basic …` header is added to the request.
  For an `http` destination it rides to the proxy as a normal header; for an `https` destination urllib's
  `do_open` **moves it into the `CONNECT` tunnel headers** (`http.client.set_tunnel(host, headers=…)`), so
  Basic works for **both** destination schemes. This is the pre-emptive tunnel-header path the reactive
  handler cannot provide.
- **Digest** — the reactive stdlib `ProxyDigestAuthHandler` (answers the proxy's `407` within one
  `opener.open()`), so it is supported **only for `http` destinations**. A `digest` proxy for an `https`
  destination is **refused loudly at construction** (the `407` is inside the `CONNECT` tunnel;
  digest-over-`CONNECT` is unsupported — use `basic`, or a local proxy).
- **NTLM / Windows** — **deferred, refused loudly at construction**. NTLM/Negotiate is
  **connection-bound** (type1/type2/type3 must ride one keep-alive TCP connection) which
  `urllib.request` — a new connection per `open()` — cannot satisfy; a correct build needs a keep-alive
  client driven by `pyspnego` (already locked, backing the AD/SSO path). The seam is shaped to admit it.

**#128 — intranet bypass.** A per-connection `proxy_no_proxy` host list (NO_PROXY-style: exact host,
`.suffix` / `*.suffix` domain match, `*` = all). Because a connection's destination host (and each token
endpoint host) is **fixed**, the bypass is evaluated **per target host at construction**: a bypassed host
gets **no proxy handler and no proxy credential at all** (byte-identical to no proxy) — so a bypassed
request can never leak the `Proxy-Authorization` credential to the origin. `"default"` mode additionally
honours the system `no_proxy` inside urllib.

**Cleartext-proxy-hop credential refusal (guard).** A proxy credential riding a **cleartext `http`
proxy hop** is refused **regardless of the destination scheme** (an `https` destination still sends the
`Proxy-Authorization` to the proxy in the clear during `CONNECT`). It reuses the ONE posture-keyed
authority (`refuse_cleartext_credential_hop`, ADR 0092): a production-PHI cleartext proxy hop is REFUSED
(the blunt global escape is inert for prod-PHI), a non-prod PHI hop is refused unless the clamped escape
downgrades it to a loud WARN, and an on-box loopback (a local `cntlm`), per-hop-attested, or synthetic
proxy hop is allowed. The message names only the proxy **host** — never the URL, scheme, or credential.

**`[egress].allowed_http` gate scope — the proxy host is OUT of scope.** The fail-closed allowlist gates
the **destination** host (where PHI is sent), which is unchanged. The forward proxy is an operator-chosen
transport intermediary, not a PHI destination; gating it against `allowed_http` would be wrong (one
corporate proxy fronts many hosts, and it would have to be co-listed with every destination). The
destination / token-endpoint host stays gated by `allowed_http` exactly as before.

**What it must not break.** No new dependency (stdlib `urllib`/`http.client`). No `api/` import from a
transport (one-way deps intact). Off by default → every existing connection is byte-identical (verify
path still returns the shared `_NO_REDIRECT_OPENER`). The proxy URL and credential are **never logged
unredacted** (reuse `_redact_url`, which drops userinfo + query). Router/transform purity, count-and-log,
ACK-on-receipt, and the no-"channel"-element rule are untouched.

## Acceptance Criteria

- **AC-1** — WHERE a connection sets `proxy="http://proxy:3128"`, THE SYSTEM SHALL deliver through a
  **per-connection** opener carrying a `ProxyHandler` for that address (never the shared
  `_NO_REDIRECT_OPENER`, never mutating it).
  → `tests/test_outbound_forward_proxy.py::test_explicit_proxy_builds_per_connection_opener`
- **AC-2** — WHERE `proxy="default"`, THE SYSTEM SHALL build a `ProxyHandler` from the OS/environment
  default web proxy (`getproxies()`).
  → `tests/test_outbound_forward_proxy.py::test_use_default_web_proxy`
- **AC-3** — WHILE no proxy is configured, THE SYSTEM SHALL be byte-identical (the verify path returns the
  shared `_NO_REDIRECT_OPENER` and adds no `Proxy-Authorization`).
  → `tests/test_outbound_forward_proxy.py::test_no_proxy_is_byte_identical`
- **AC-4** — WHERE `proxy_auth_type="basic"` with proxy credentials, THE SYSTEM SHALL add a pre-emptive
  `Proxy-Authorization: Basic …` header (so an https destination tunnels it via `CONNECT`).
  → `tests/test_outbound_forward_proxy.py::test_basic_proxy_auth_preemptive_header`
- **AC-5** — IF a proxy credential would ride a cleartext `http` proxy hop on a production-PHI instance,
  THEN THE SYSTEM SHALL refuse at construction **regardless of the destination scheme** (a loopback proxy
  is allowed).
  → `tests/test_outbound_forward_proxy.py::test_cleartext_proxy_hop_credential_refused`
- **AC-6** — IF `proxy_auth_type="digest"` targets an https destination, THEN THE SYSTEM SHALL refuse at
  construction (digest-over-`CONNECT` unsupported); IF `proxy_auth_type` ∈ {ntlm, windows}, THEN THE
  SYSTEM SHALL refuse at construction (deferred).
  → `tests/test_outbound_forward_proxy.py::test_digest_https_and_ntlm_windows_refused`
- **AC-7** — WHERE a target host matches `proxy_no_proxy`, THE SYSTEM SHALL bypass the proxy for that host
  (no proxy handler, no proxy credential).
  → `tests/test_outbound_forward_proxy.py::test_intranet_bypass`
- **AC-8** — WHEN a connection uses OAuth2 or SMART auth behind a proxy, THE SYSTEM SHALL route the
  **token-endpoint** call through the proxy too (opener + pre-emptive `Proxy-Authorization`).
  → `tests/test_outbound_forward_proxy.py::test_token_endpoint_is_proxied`
- **AC-9** — WHERE `[egress].proxy_url` is set and a connection sets no proxy, THE SYSTEM SHALL apply the
  site-wide default proxy to that connection.
  → `tests/test_outbound_forward_proxy.py::test_egress_default_proxy`

## Options considered

1. **Per-connection `ProxyHandler` threaded through every opener path + pre-emptive tunnel-header Basic.**
   **CHOSEN.** Stdlib-only, per-connection, covers https destinations (the reactive-handler gap), and
   composes with the existing insecure/expiry/mTLS/digest opener variants and the token-endpoint openers.
2. **Rely on process-wide `HTTP_PROXY`/`HTTPS_PROXY` only.** Rejected as the *sole* answer: undocumented,
   all-or-nothing, no per-connection control, no proxy authentication. (It remains the incidental
   byte-identical default when no per-connection proxy is set, and `proxy="default"` makes it explicit.)
3. **Reactive `ProxyBasicAuthHandler` / `ProxyDigestAuthHandler` for auth.** Rejected for Basic: it does
   **not** work for https destinations (the `407` is inside the `CONNECT` tunnel). Digest keeps the
   reactive handler but only for http destinations (documented limit).
4. **NTLM/Negotiate via `pyspnego` now.** Rejected/deferred: urllib is connection-per-`open()`; NTLM's
   handshake is connection-bound and needs a keep-alive client. Refused loudly; the seam admits it later.
5. **A Destination model field for proxy config.** Rejected as redundant: the connectors, the
   `FhirLookupExecutor`, and the token providers all read the **env-resolved settings mapping** (as they
   do for `bearer_token`/`basic_password`), and the `[egress]` default is merged into settings at the one
   choke point (`_dest_config` / the lookup-executor build). A typed model field would be unread cruft.

## Consequences

**Positive** — Corporate egress-proxy parity for the whole HTTP family in one seam; per-connection control
plus a site-wide `[egress]` default; Basic auth works for https destinations; every opener path (data +
token) is covered; no new dependency; off → byte-identical.

**Negative / risks** — Digest is http-destination-only and NTLM/Windows are deferred (documented, refused
loudly, not silent). The pre-emptive Basic path relies on urllib's documented `Proxy-Authorization` →
`set_tunnel` header movement for https. A new intermediary sees PHI bodies / `CONNECT` targets — mitigated
by the cleartext-proxy-hop refusal, redaction, and secret-in-`env()` handling.

**Out of scope** — NTLM/Windows/Negotiate proxy auth; a `FhirLookup()` **factory** proxy kwarg (the read
executor honours proxy settings from `connections`/`[egress]` but the factory adds no kwarg here); an
inbound/reverse-proxy change; per-scheme distinct proxies; SOCKS proxies.

## Deviations from the phase doc

- **Proxy-auth dispatch lives in `transports/rest.py`, not `transports/http_auth.py`.** `smart.py`'s token
  opener must also proxy, and `smart.py` imports `rest` (not `http_auth`, which imports `smart`); placing
  the shared proxy plumbing (`ProxyConfig`, `proxy_config_from_settings`, `_ForwardProxy*`, opener
  threading) in `rest.py` — the base HTTP-plumbing module every sibling already reuses — avoids a
  `smart → http_auth` import cycle. `http_auth.py` re-exports the helper name.
- **No `Destination` model proxy fields** (Options #5). Documented above.
