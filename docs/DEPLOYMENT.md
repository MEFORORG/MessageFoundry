# MessageFoundry — Deployment & Network Exposure Guide

This is the consolidated reference for **how every MessageFoundry network channel binds, whether it
supports TLS, and how it is authenticated and gated** — the artifact behind the v0.1 "native
off-loopback TLS" gate (Gate #4). If you are about to expose the engine beyond `127.0.0.1`, read the
[checklist](#before-you-expose-off-loopback) and the [channel matrix](#channel--tls-posture-matrix)
first.

Design rationale for the off-loopback posture is in
[`adr/0002-phase2-transport-security-and-strong-auth.md`](adr/0002-phase2-transport-security-and-strong-auth.md);
PHI-in-transit context is in [`PHI.md`](PHI.md) §4; clustering topology is in
[`CLUSTERING.md`](CLUSTERING.md). For the host-level antivirus exclusions and Windows Firewall rules
the engine needs, see [`ANTIVIRUS-FIREWALL.md`](ANTIVIRUS-FIREWALL.md).

---

## On-premises by default

MessageFoundry runs **on-premises** and binds **loopback (`127.0.0.1`) by default** — the engine API
(`[security].local_access_only = true`), and every inbound listener via `[inbound].bind_host`. In that
posture **no MessageFoundry listener is reachable off-host**.

**That is a claim about listeners only — it is not a claim that nothing PHI-bearing crosses a wire.**
Outbound delivery is **unaffected by the bind posture**: a loopback-bound engine still dials every
configured destination (MLLP, REST/SOAP, FHIR, DICOMweb, SFTP/FTPS, SMTP, Direct, a customer database),
still performs `db_lookup` / `fhir_lookup` reads, and still forwards syslog/SIEM logs and webhook
alerts — all off-box, and the delivery hops carry PHI. So the outbound controls
(§[Channel × TLS posture matrix](#channel--tls-posture-matrix), §[Egress allow-lists](#egress-allow-lists),
and the cleartext-hop authority) apply to a loopback-bound engine **exactly** as they do to an exposed
one. What follows about *binding* is what changes when you deliberately put a listener on a routable
address.

**Fail-closed rule (ADR 0002 §0):** a non-loopback **API** bind is *refused at startup* unless TLS is
configured (or an upstream TLS terminator is trusted), and every inbound **listen** type — MLLP, HTTP,
DICOM C-STORE SCP, raw TCP/X12 — is refused off-loopback without TLS at wiring time.

**The cleartext-bind escapes are clamped shut on the shipped posture** ([ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md),
ADR 0092 decision 2). `serve --allow-insecure-bind` — and its config twin
`[security].require_encryption_for_remote = false` — only warn-and-cross while the instance is **not**
enforcing-PHI. `[security].enforcement` defaults `enforce`, and all three built-in environment names
(`dev`, `staging`, `prod`) now derive `data_class = phi`, so a **stock instance refuses the cleartext
bind even with the flag**. Crossing it is a deliberate, recorded loosening: set
`[security].enforcement = warn`, or declare the box synthetic with
`[security].handles_real_patient_data = false`. Neither is a supported production setting.

---

## Container deployment (Docker / Kubernetes)

The **headless engine** ships as an OCI image (ADR 0017 "container fast-follow") — a complement to the
Windows-service/NSSM path ([`SERVICE.md`](SERVICE.md)), not a replacement. A container is just another
way to bind off-loopback, so it inherits the controls above unchanged. The operator console is the
**browser web console the engine serves in-process at `/ui`** (ADR 0065), but its optional
`messagefoundry-webconsole` wheel is **not in the image** — neither hash-locked profile installs it, so a
stock container soft-degrades to a **JSON-API-only serve** (with a warning) until you add the wheel to a
derived image. Full build/run/ops guide:
[`../docker/README.md`](../docker/README.md); the scoping analysis is in
[`CONTAINER-EXPOSURE-EVALUATION.md`](CONTAINER-EXPOSURE-EVALUATION.md).

Container-specific essentials (all detailed in [`../docker/README.md`](../docker/README.md)):

- **Two variants:** slim default (core + SQLite) and `-sqlserver` (adds the OS-level MS ODBC Driver 18
  for the SQL Server store / `db_lookup`). Non-root uid 10001; read-only root fs; per-profile hash-locked deps.
- **Config is executed code:** mount it owned by **uid 10001** and not group/world-writable, or — the
  robust path, and the only clean one on Kubernetes — **bake it into a derived image**
  (`FROM messagefoundry; COPY --chown=10001:10001 config /config`).
- **Store volume must persist** (named volume / PVC, never the ephemeral layer) or the at-least-once
  invariant is void across a restart; enable the at-rest cipher (`MEFOR_STORE_ENCRYPTION_KEY` +
  `MEFOR_STORE_REQUIRE_ENCRYPTION=true`).
- **Exposure:** Topology A (in-process TLS — the **recommended** of the two; TLS is **not** configured
  out of the box, `[api].tls_cert_file` defaults unset) or Topology B (reverse-proxy / same-pod sidecar).
  Reaching a published port means binding off-loopback in the container, so the bind guard requires TLS —
  exactly as on bare metal. Every listen type is guarded (MLLP, HTTP, the DICOM SCP, raw TCP/X12); raw
  TCP/X12 have no TLS to enable, so publishing those ports means firewalling/segmenting them instead.
- **Signals:** PID 1 is `tini`; `SIGTERM` → graceful `engine.stop()`. Allow a stop grace of ≥30s.

---

## Trust boundary — inside your organization's private network

**MessageFoundry's supported deployment is *inside a single healthcare organization's private, trusted
network* (on-prem or the org's private cloud), behind that org's perimeter controls — firewall, network
segmentation, VPN/NAC. It is *never* placed directly on the public internet.** This is the model every
clinical interface engine assumes; state it explicitly in your own runbook, because it is the
assumption every control here depends on and the first thing a security reviewer will ask for.

"Inside the network" is a statement about the **trust boundary**, *not* about which interface the
engine binds. Three planes sit at different exposure levels:

| Plane | What it is | Where it binds | Posture |
|---|---|---|---|
| **Management** | web console (`/ui`) / IDE → engine API | loopback by default (or a restricted management subnet) | auth + RBAC + full audit, **on by default** (`[security].require_sign_in`, default `true`) — disabling it is refused on a non-loopback bind **or a loopback bind behind a declared TLS terminator**, but on a bare **loopback** bind with no declared terminator it is permitted and drops the plane to a full-privilege no-RBAC identity; smallest surface — keep it off general-user VLANs |
| **Data** | inbound feeds you *receive* (MLLP, TCP/X12, DB-poll) | the **internal network interface** — feeds come from other systems on your LAN, not `127.0.0.1` | **TLS on the wire where the channel has it** (enable MLLP-over-TLS; **TCP/X12 have none** — segment them) + the `[egress]`/ingress allow-lists + your network segmentation. PHI must not cross the LAN in cleartext |
| **Inbound web service** | a partner *calls into* MEFOR (`Http()` source) | its own connector-owned socket | built (ADR 0023) — per-connection TLS + opt-in mTLS + IP allow-list, **no bearer/basic partner auth**. Both peer controls are **optional and unenforced** — a TLS-on listener with neither accepts any peer; see the caveat below |

The **management plane** is what you keep most contained; the **data plane is network-bound in any real
install** (an EHR's MLLP feed is not on localhost) — which is exactly why MLLP-over-TLS and the
fail-closed bind-guard exist. Enabling MLLP-over-TLS keeps **MLLP** feeds off the LAN in cleartext.

**"TLS on the data plane" is not a state every data-plane channel can reach**, so do not read that as a
whole-plane property: **TCP/X12 have no `tls` option at all** (`check_tcp_tls_exposure` refuses the
non-loopback bind and says so — they must be firewall-segmented or proxy-terminated); a
`dialect='generic'` DATABASE hop's TLS is the ODBC **driver's** own keyword, which the engine never
enforces or verifies; and a **Direct** destination with `use_tls=false` submits over cleartext SMTP.
Those three are the exceptions, and they are enumerated under
[No-TLS channels — hazards](#no-tls-channels--hazards) and the outbound matrix below.

### Off-loopback security controls — delegate to your environment (and write it down)

Because the trust boundary is your private network, the controls that only become material once the
engine leaves loopback are **satisfied by your organization's existing infrastructure** — *provided you
document the delegation* and turn on the engine-side floor. This is the delegation pattern **we
recommend** for the deployment-conditional OWASP ASVS items (tracked in the ASVS L3 remediation plan, an
internal security-posture document not published in this repository). ASVS accepts nothing: whether this
satisfies a given item is **your assessor's call**, deployment by deployment, and it is only defensible
if you document the delegation.

**Scoring caveat, before the table** (the table is what gets quoted): that plan's **per-cell** scoring
still reflects the pre-collapse posture columns —
[ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) collapsed
deployment scoring to `{loopback, off-loopback}`, but the per-cell re-score and the owner's re-signature
are an owner act and remain **pending**.

| Control (ASVS) | Delegate to your environment | Or build into the engine |
|---|---|---|
| **Transport encryption** (12.x) | — *enable* the shipped native API/WSS TLS + MLLP-over-TLS | already built (Gate #4) |
| **MFA / multi-layer admin** (6.3.3 / 8.4.2) | your **directory (AD / Entra)** — healthcare orgs are now *required* to enforce MFA there; MEFOR authenticates against it (see note below) | **native TOTP MFA is built and on by default** (ADR 0002 WP-14) — RFC 6238 for local accounts, `[security].require_mfa = true` with `require_mfa_scope = "every_local_account"` + the step-up gate; AD/Entra MFA stays delegated |
| **TLS client-cert / mTLS** (12.3.5) | your **PKI**; MF's API mTLS is built (`tls_client_ca_file`, opt-in) | enable mTLS + a console client cert |
| **Certificate revocation** (12.1.4) | your **proxy / PKI** (OCSP/CRL at the terminator) — **still the control for most hops**, and for a named few the engine also makes you say so | **ENFORCED on the API bind + seven outbound cells; delegated everywhere else.** An off-loopback in-process-TLS API bind is refused at `serve`, and **seven** verifying outbound TLS hops — MLLP-over-TLS, REST, SOAP, FHIR, DICOMweb https, SMTP/EMAIL, the **PostgreSQL** store hop — are refused at construction on an enforcing PHI instance, unless revocation is **proven in front** (an upstream TLS terminator — API gate only) or **attested** with `MEFOR_TLS_REVOCATION_ATTESTED=1` (the only lever that clears the outbound gate). **Other verifying hops are NOT gated and stay fully delegated** — the **SQL Server** store hop, DICOM C-STORE SCU over TLS, FTPS, the `dialect='sqlserver'` DATABASE destination, LDAPS, the syslog forwarder, the webhook + AI-broker endpoints. "Add OCSP/CRL to the TLS contexts" is **not** an available option anywhere: stdlib `ssl` exposes no OCSP/CRL fetch and the engine deliberately attempts none. See [Revocation-guard behavior](#revocation-guard-behavior) |
| **Off-box log shipping** (16.4.3) | forward the audit + operational logs to your **SIEM/syslog** | **built** — `[logging].forward_*` ships operational logs + PHI-redacted audit rows to a syslog/SIEM collector, over **native TLS** with `forward_protocol = "tls"` (RFC 5425, ADR 0080; port 6514) (residual: the transport **default** is UDP, so set TLS explicitly or front the collector with a local TLS-forwarding agent) |

**Write the delegation into your deployment runbook.** "We run MEFOR inside our network behind
\<perimeter / IdP / PKI / SIEM\>" is what turns these from open gaps into *addressed-by-environment* —
for your own risk posture and for any ASVS-scoped review.

**On MFA specifically.** Your **directory (AD / Entra) is the identity provider** and enforces MFA per
your policy — which healthcare organizations are now **required** to do — so MEFOR does not re-implement
it. One accuracy point for a security reviewer: a back-channel **LDAP simple-bind validates the password
but does not itself prompt the second factor**, so MFA applies through **Kerberos / Windows SSO** (the
workstation logon was already MFA'd), your **Conditional Access on a federated-SSO front**, or an
**MFA-terminating reverse proxy**. Local accounts now have a **native second factor** — RFC 6238 TOTP
(`[security].require_mfa`, WP-14) — **on by default for every local account**, so leave it on; AD / SSO
remains preferable where your IdP already enforces and manages MFA centrally.

### Caveat — accepting inbound web-service calls

If you intend to use MEFOR to **accept** web-service calls (a partner POSTs *into* the engine), the
inbound listener **is built** — `Http(port=...)`, a connector-owned HTTP/1.1 receiver (ADR 0023) that
answers `202 Accepted` once the raw body is durably committed to the ingress stage. It is a **distinct
network surface even inside your LAN**, with its own bind/port in the connector layer, **separate** from
the management API, and it does not inherit the API's auth: harden it deliberately.

- **Built:** per-connection TLS (`tls = true` + `tls_cert_file`/`tls_key_file`), opt-in **mTLS** via
  `tls_ca_file`, a per-connection `source_ip_allowlist`, DoS caps (`max_connections`, `receive_timeout`,
  `max_body_bytes`, `max_header_bytes`), and the off-loopback exposed-gate (`check_http_tls_exposure`).
- **Not built:** any *application*-layer partner authentication — there is no bearer/basic credential
  check on the listener, so **mTLS or the IP allow-list is the partner authentication**, or you front it
  with an authenticating reverse proxy. The synchronous downstream-reply (SOAP-envelope) path is also a
  defined ADR 0013 follow-on, not built: the first slice is respond-with-receipt only.
- **Neither peer control is enforced — treat configuring one as mandatory, not optional.** The
  off-loopback gate (`check_http_tls_exposure`) checks only that **TLS is on**; it never checks that a
  peer control exists. So an off-loopback `Http()` with `tls = true`, no `tls_ca_file` and no
  `source_ip_allowlist` **starts cleanly and accepts POSTs from anyone on the LAN** (`source_ip_allowlist`
  defaults to *no restriction*). Do not infer the DICOM SCP's floor here: the SCP **does** refuse a
  non-loopback bind with no peer control at construction, and the matrix below advertises that refusal —
  the HTTP listener has no equivalent.

---

## High availability — clients reach the engine through a floating VIP / L4 LB

MessageFoundry's HA model is **active-passive clustering** (N engine processes against one shared
server DB; one leader runs the graph, the rest are warm standbys) — full setup in
[CLUSTERING.md](CLUSTERING.md). It changes the network picture in one way that belongs in your
deployment plan:

- **Only the primary binds the inbound listener ports.** So senders must reach "the engine" through an
  operator-provided **floating VIP / L4 load balancer**, not a fixed node. Use **one VIP per inbound
  port with a TCP-connect health check on that port** — the check passes only on the primary, so the VIP
  lands inbound traffic on it and follows the primary across a failover. MLLP/TCP senders see a
  connection drop and reconnect through the VIP (make partners reconnect-on-drop).
- **The engine API is up on every node** (it's a control/read plane over the shared DB), so an API VIP
  can health-check the unauthenticated **`GET /health`** for liveness, or pin operations to the primary
  via **`GET /cluster/status`** (`role`) / **`GET /cluster/nodes`** (`leader_node_id`).
- **DB-tier HA is delegated to the database** (PostgreSQL streaming replication / SQL Server Always On)
  — MEFOR does not replicate the store itself.

MEFOR designs for the VIP and exposes the health-check/role endpoints, but **does not ship a load
balancer** — you stand it up (keepalived, HAProxy, F5, a cloud NLB, …). Single-node deployments need
none of this.

**Cloud / Kubernetes HA:** for a multi-replica, Postgres-backed HA deployment on k8s — the copyable
`replicas: 3` manifest, the L4-NLB-per-MLLP-port recipe (primary-only health check, no L7/HPA for MLLP),
and the hybrid edge-relay topology — see [`CLOUD-DEPLOYMENT.md`](CLOUD-DEPLOYMENT.md); for the cloud PHI /
HIPAA posture (BAA, KMS, PrivateLink, region pinning), see [`CLOUD-PHI-HIPAA.md`](CLOUD-PHI-HIPAA.md)
(both per [ADR 0047](adr/0047-cloud-kubernetes-ha-deployment-packaging.md)).

---

## Before you expose off-loopback

1. **API** — set `[security].local_access_only = false` + `[security].listen_address`, then either
   `[api].tls_cert_file` + `[api].tls_key_file` (in-process TLS) *or* `[api].tls_terminated_upstream = true`
   + `[api].trusted_proxies` (front it with a TLS terminator). Keep `[security].require_sign_in = true`
   (a non-loopback bind with sign-in disabled is refused, and no flag covers it). The legacy `[api].host`
   / `[auth].enabled` keys are **rejected at load** — they moved to `[security]` (ADR 0118).

   **Neither branch alone starts a stock instance.** On the shipped default (PHI +
   `[security].enforcement = enforce`) each carries a second, *fail-closed* precondition — a refusal
   (exit 2), not an advisory, and not covered by `--allow-insecure-bind`:
   - **In-process TLS** also needs `MEFOR_TLS_REVOCATION_ATTESTED=1` — your attestation that the PKI
     behind the cert enforces revocation, because the engine performs no OCSP/CRL
     ([ADR 0078](adr/0078-certificate-revocation-posture.md)). The alternative is to terminate at a
     revocation-checking proxy instead (which is branch B).
   - **The terminator branch** also needs `[api].proxy_intra_service_auth`
     (`mtls` / `network` / `shared_secret`) **and** `[api].proxy_tls_min_version` (`1.2` / `1.3`) — the
     engine can verify neither the proxy→engine internal hop nor the proxy's negotiated TLS floor, so it
     requires you to declare both before an off-loopback PHI bind may start.
2. **Web console (`/ui`)** — an off-loopback `/ui` **requires** in-process TLS or a declared terminator;
   `--allow-insecure-bind` does **not** cover the browser surface. The console is also on-by-default for
   *loopback* binds only: an exposed instance serves the JSON API alone unless you ask for it explicitly
   with `[security].serve_web_console = true`, and behind a declared terminator it additionally requires
   `[security].web_console_public_address` (the external https origin) or the serve refuses.
3. **MLLP inbound** — set `tls = true` + `tls_cert_file`/`tls_key_file` per connection. A non-loopback
   MLLP bind without `tls` is refused (`check_mllp_tls_exposure`). The DICOM SCP and inbound HTTP
   listeners have the same shape (`check_dimse_tls_exposure` / `check_http_tls_exposure`).
4. **Raw TCP / X12 inbound** — **no transport TLS exists** (these connectors are plaintext-only). They
   are, however, **exposed-gated** (since PR #558): a non-loopback raw-TCP/X12 bind is **refused at
   startup** (`check_tcp_tls_exposure`), parity with the MLLP/DICOM/HTTP guards. Because there is no TLS
   to enable, the only ways past the gate are a loopback bind or OS-level firewall/segmentation — on the
   shipped enforcing-PHI posture `serve --allow-insecure-bind` is clamped inert and the bind still
   refuses. See [no-TLS hazards](#no-tls-channels--hazards).
5. **Outbound connectors** — **defaults split by family, and the split matters.** The HTTP family
   (REST / SOAP / FHIR / DICOMweb) defaults to verified HTTPS (`verify_tls = true`), SMTP/Direct default
   to STARTTLS, and the SQL Server DB hop to `Encrypt=yes` — but **MLLP, raw TCP, X12 and DICOM
   C-STORE SCU default to plaintext** and need `tls = true` per connection (raw TCP and X12 have no
   `tls` to set at all), and RemoteFile `protocol=ftp` is cleartext. Either way, a
   **cleartext off-loopback hop is refused** on any `enforcement = enforce` instance — the hop authority
   no longer reads the instance's data label, so a *synthetic* box is refused too. Per-connection, the only
   honest way across is `cleartext_accepted = true` + `cleartext_reason` (ADR 0153: warn + audit at every
   construction, listed by `messagefoundry check` and `GET /security/posture`). Do **not** set
   `MEFOR_ALLOW_INSECURE_TLS` in production — it no longer influences a cleartext hop at all, and where it
   still applies it only weakens verification (see [the escape hatch](#the-mefor_allow_insecure_tls-escape-hatch)).
   **Two outbounds are outside that refusal** and need a deliberate decision from you: a
   `dialect='generic'` DATABASE hop (driver-owned TLS, never engine-enforced) and a Direct destination
   with `use_tls=false` — see the exceptions under the [matrix](#channel--tls-posture-matrix).
   Separately, **seven** verifying TLS outbounds have a revocation gate of their own — and the rest do
   **not**, including the SQL Server store hop and the TLS DICOM SCU: see
   [Revocation-guard behavior](#revocation-guard-behavior). And check every connection for
   [`tls_allow_expired`](#tls_allow_expired--the-weakening-with-no-posture-gate-at-all), which no posture
   gate, escape variable or loosening register covers.
6. **Lock down egress** — populate the relevant `[egress].allowed_*` allow-lists so **the engine's own
   outbound connectors** (and the sanctioned read-only `db_lookup` / `fhir_lookup`) can only reach
   approved destinations — **all eight**, plus the separate `[alerts]` allow-lists for the
   webhook / SMTP alert sinks, which `[egress]` does **not** cover (see
   [egress allow-lists](#egress-allow-lists)). A PHI instance with *nothing* declared and
   deny-by-default off **refuses to start**. **`[egress]` is not a boundary around Handler code** — see
   the limit stated under [egress allow-lists](#egress-allow-lists).
7. **Off-box logs + MFA** — **both are built** and pair with off-loopback exposure: enable
   `[logging].forward_*` to ship logs + (PHI-redacted) audit to your SIEM (set
   `forward_protocol = "tls"` for the native RFC 5425 hop — the default is UDP — or front it with a
   local TLS agent), and leave `[security].require_mfa` on (it defaults on for every local account;
   AD/Entra MFA stays delegated to the IdP).

---

## Channel × TLS posture matrix

Legend: **Bind** = default bind/connect posture · **TLS** = transport encryption support · **Auth** =
authentication on the channel · **Egress gate** = the `[egress]` allow-list that confines it ·
**Off-loopback guarded?** = whether a non-loopback bind is refused without TLS.

### Inbound (listeners — the engine binds a socket)

| Channel | Bind default | TLS support | Auth | Ingress/egress gate | Off-loopback guarded? |
|---|---|---|---|---|---|
| **Engine API** (FastAPI/uvicorn) | `[security].local_access_only` = true → `127.0.0.1` | **Yes** — in-process via `tls_cert_file`/`tls_key_file`, *or* upstream via `tls_terminated_upstream` + `trusted_proxies`; `tls_min_version` (≥1.2); opt-in mTLS via `tls_client_ca_file`; HSTS over https | Bearer token + session RBAC — **required by default** (`[security].require_sign_in`, default `true`); `false` is refused on a non-loopback bind or a loopback bind behind a declared TLS terminator, and on a bare loopback bind with no declared terminator yields a full-privilege *system* identity with no RBAC | — (auth-gated) | **Yes** — refused without TLS or a trusted terminator, and `--allow-insecure-bind` is clamped inert on an enforcing PHI instance (the default); also refused if sign-in is disabled on a non-loopback bind or a loopback bind behind a declared terminator |
| **MLLP source** | `[inbound].bind_host` = `127.0.0.1` | **Yes** — per-connection opt-in `tls=true` + `tls_cert_file`/`tls_key_file`; opt-in mTLS via `tls_ca_file`; ≥TLS 1.2. **Plaintext by default** | None (MLLP has no app auth) | — | **Yes** — non-loopback plaintext refused (`check_mllp_tls_exposure`) |
| **HTTP source** (`Http()`, ADR 0023) | `[inbound].bind_host` = `127.0.0.1` | **Yes** — per-connection opt-in `tls=true` + `tls_cert_file`/`tls_key_file`; opt-in mTLS via `tls_ca_file`. **Plaintext by default** | mTLS client cert only — **no bearer/basic partner auth**, and **neither mTLS nor the IP allow-list is required**: with TLS on and both unset the listener accepts any peer | per-connection `source_ip_allowlist` — **optional, defaults to no restriction** | **Yes** — non-loopback plaintext refused (`check_http_tls_exposure`) — but the gate checks **only** that TLS is on, **never** that a peer control exists (unlike the DICOM SCP row below) |
| **DICOM C-STORE SCP** (`DICOM()`, ADR 0025) | `[inbound].bind_host` = `127.0.0.1` | **Yes** — per-connection opt-in `tls=true` + cert/key; opt-in mTLS via `tls_ca_file`. **Plaintext by default** | `calling_ae_allowlist` / `require_called_ae_title` / mTLS (DIMSE has no transport auth of its own) | per-connection `source_ip_allowlist` | **Yes** — non-loopback plaintext refused (`check_dimse_tls_exposure`), **and** a non-loopback SCP with *no* peer control (calling-AE allow-list, IP allow-list, or mTLS) is refused at construction |
| **Raw TCP source** | `[inbound].bind_host` = `127.0.0.1` | **No** — plaintext only | None | — | **Yes** — non-loopback plaintext refused (`check_tcp_tls_exposure`, PR #558); no TLS to enable, so keep loopback / firewall-segment / proxy-terminate |
| **X12 source** (ISA/IEA framed) | `[inbound].bind_host` = `127.0.0.1` | **No** — plaintext only (same socket plumbing as raw TCP) | None | — | **Yes** — non-loopback plaintext refused (`check_tcp_tls_exposure`, PR #558); keep loopback / firewall-segment / proxy-terminate |
| **File source** | local filesystem | n/a (no network) | n/a | — | n/a |
| **Database poll source** | dials an **operator-configured DB host** — its own `server`/`port`, **not** the `[store]` database and **not** `[store]` TLS | **Yes, per connection** — on the default `sqlserver` dialect its own `encrypt` (default true) / `trust_server_certificate` (default false), weakened only via the escape. On `dialect='generic'` TLS is the ODBC **driver's** own keyword (`SSLmode=verify-full`, …) and is **NOT engine-enforced** — a missing one logs a WARNING, never a refusal | ODBC `sql` / `integrated` / `entra`, per connection | `[egress].allowed_db` | n/a (outbound DB connection) |

### Outbound (the engine dials a destination)

| Channel | Connect | TLS support | Auth | Egress gate |
|---|---|---|---|---|
| **MLLP destination** | dials host:port | **Yes** — per-connection `tls=true`; `tls_verify=true` **default**; client-cert mTLS via `tls_cert_file`/`tls_key_file` + `tls_ca_file`; ≥TLS 1.2 | peer HL7 ACK | `[egress].allowed_mllp` |
| **Raw TCP destination** | dials host:port | **No** — plaintext only | None | `[egress].allowed_tcp` |
| **X12 destination** | dials host:port | **No** — plaintext only | None (optional TA1) | `[egress].allowed_tcp` |
| **REST destination** | dials URL | **HTTPS by default** — `verify_tls=true` default (downgrade refused without the escape); cleartext-credential `http` refused; 3xx redirects refused | optional `Authorization` (Basic/Bearer), refused over plaintext | `[egress].allowed_http` |
| **SOAP destination** | dials URL | **HTTPS by default** — reuses the REST client + no-redirect opener; per-connection client-cert mTLS; ≥TLS 1.2 in the mTLS context | optional WS-Security `UsernameToken` (Nonce + Timestamp) | `[egress].allowed_http` |
| **FHIR destination** (ADR 0024/0043) | dials URL | **HTTPS by default** — `verify_tls=true` default (downgrade refused without the escape); reuses the REST client | SMART Backend Services bearer (signed `client_assertion`), or static bearer / basic — refused over plaintext | `[egress].allowed_http` — **and the SMART token endpoint host is checked against the same list** |
| **DICOMweb destination** (STOW-RS, ADR 0025) | dials URL | **HTTPS by default** — `verify_tls=true` default (downgrade refused without the escape); reuses the REST client | optional bearer / basic, refused over plaintext | `[egress].allowed_http` |
| **DICOM C-STORE SCU** (`DICOM()`, ADR 0025) | dials host:port (default `104`) | **Yes** — per-connection opt-in `tls=true`; **chain and hostname are always verified** (there is no `tls_verify=false` on this connector), but **expiry checking is relaxable per connection** via `tls_allow_expired` — see the note below; opt-in client-cert mTLS. **Plaintext by default** | calling / called AE title (DIMSE has no transport auth of its own) | `[egress].allowed_tcp` (a raw socket) |
| **EMAIL destination** (SMTP, ADR 0029) | dials host:port (default `587`) | **STARTTLS by default** (`use_tls=true`; implicit TLS on `465`). `use_tls=false` routes through the cleartext-hop authority; SMTP AUTH credentials are refused over cleartext **either way** | optional SMTP AUTH | `[egress].allowed_smtp` |
| **Direct destination** (S/MIME HISP relay, ADR 0085) | dials HISP relay host:port (default `587`) | **STARTTLS by default** (`use_tls=true`); the body is S/MIME signed + encrypted regardless. ⚠️ `use_tls=false` is gated by the **raw** `MEFOR_ALLOW_INSECURE_TLS` — it does **not** route through the cleartext-hop authority and is **not clamped** by `enforcement` (AUTH credentials stay refused) | S/MIME cert trust + optional SMTP AUTH | `[egress].allowed_direct` |
| **DATABASE destination** | dials server:port | **Dialect-dependent** — `dialect='sqlserver'` (default): `Encrypt=yes` **default**, `TrustServerCertificate=false` default (weakened only via the escape). ⚠️ `dialect='generic'` (ODBC to Postgres/Oracle/MySQL): TLS is the **driver's** own keyword in `odbc_params` and is **never engine-enforced or verified** — a hop with no TLS keyword logs a WARNING at construction and connects anyway, on any posture | ODBC `sql` / `integrated` / `entra` | `[egress].allowed_db` |
| **File destination** | local filesystem | n/a (no network) | n/a | `[egress].allowed_file_dirs` |
| **RemoteFile destination + source** (SFTP / FTPS / FTP) | dials remote host | **Protocol-dependent** — **SFTP** encrypted (SSH host-key verify on by default); **FTPS** explicit TLS; **FTP** plaintext (credentials refused without the escape) | username/password or SSH key | `[egress].allowed_remote` |

Above and beyond each row: an **off-loopback cleartext outbound hop is decided by one authority** for
every connector **that routes through `InsecureHopGuard`** (ADR 0092, amended by ADR 0153) — loopback
ALLOW, then a per-connection `cleartext_accepted` + `cleartext_reason` WARN (logged + audited at every
construction), then WARN while `[security].enforcement` is not `enforce`, else **REFUSE**. It no longer
reads the instance's data label, and `MEFOR_ALLOW_INSECURE_TLS` no longer reaches it at all. MLLP, raw
TCP, X12, the DICOM SCU, the HTTP family and EMAIL all decide there.

**Two outbound channels do not — and they are the two that reach furthest.** Confirming that MLLP and
REST obey the authority does not settle these:

- **`dialect='generic'` DATABASE** — the connector cannot introspect an arbitrary ODBC driver's TLS, so
  it reports the hop as **non-weakened by construction** and it never reaches the authority. A plaintext
  PHI hop to a Postgres / Oracle / MySQL ODBC target crosses with a **log WARNING and no refusal, on any
  posture**. TLS here is operator-owned: set the driver's keyword in `odbc_params`
  (`SSLmode=verify-full`, `SSLMODE=VERIFY_IDENTITY`, …) and treat it as a deployment requirement.
- **Direct (S/MIME) cleartext SMTP** — `use_tls=false` consults the **raw** `MEFOR_ALLOW_INSECURE_TLS`
  directly rather than the authority, which is why the escape-hatch list below marks it *Not clamped*.
  `[security].enforcement` does not reach it. (SMTP AUTH credentials are refused over cleartext either
  way, and the Direct body is S/MIME-encrypted — but the SMTP envelope metadata is not.)

### `tls_allow_expired` — the weakening with no posture gate at all

The `verify_tls` / `use_tls` columns above, the cleartext-hop authority, and the escape-hatch list
below are all about **turning verification off**. There is a **third, narrower weakening** that none of
them covers, and it is the only TLS relaxation in the product with **no posture gate whatsoever** — so
an audit built from those columns alone has a hole:

**`tls_allow_expired = true`** is a **per-connection** setting on **six** outbound connectors — **MLLP,
REST, SOAP, FHIR, DICOM C-STORE SCU, and RemoteFile FTPS** (a factory parameter, and therefore also a
`connections.toml` `[settings]` key and a GUI field — the connection schema is derived from the factory
signatures). It relaxes **only** the certificate validity-period check: an **expired** server
certificate is accepted **indefinitely**, while the **chain, hostname and key usage are still fully
verified** (ADR 0094). It is genuinely narrower than `tls_verify=false` — that is the point of it — but:

- it needs **no** `MEFOR_ALLOW_INSECURE_TLS`;
- it is **not clamped** by `[security].enforcement` — `enforce` does not touch it;
- it does **not** route through `InsecureHopGuard`, because verification stays on, so **no
  cleartext/verify-off refusal keys on it**;
- it is **absent from `security_loosenings()`**, and therefore from `GET /security/posture` and the
  serve-time loosening warning. **Nothing reports that a connection has it set** except the WARNING it
  logs at each construction.

Two consequences worth stating plainly. **(1)** Combined with the ungated revocation hops in
[Revocation-guard behavior](#revocation-guard-behavior), a PHI hop can be pinned to a certificate that
is **both long-expired and revoked** with nothing refusing it, warning at posture level, or reporting
it. **(2)** A two-week bridge set when a partner's certificate lapses has **nothing that expires it or
surfaces it** — it survives in config until someone reads the connection. If you use it, put the
connection name and a removal date in your own risk register; the engine will not keep that list for
you. **DICOMweb is deliberately not in the list above** — it reuses the REST client but does *not* honour
`tls_allow_expired`, so a DICOMweb hop always enforces expiry.

### Internal

| Channel | Transport | TLS |
|---|---|---|
| **Inter-node cluster coordination** (active-passive HA / Track B) | **Rides the shared `[store]` DB connection — no separate node-to-node socket.** Leadership lease, heartbeat (`last_seen`), and config-version bumps are reads/writes against cluster tables on the same pool. | **= the store DB connection's TLS** (`DbCoordinator` on the asyncpg pool for PostgreSQL, `SqlServerCoordinator` on the aioodbc pool for SQL Server). Encrypt the store connection and the cluster traffic is encrypted with it. |
| **Store DB connection** (PostgreSQL / SQL Server) | asyncpg / aioodbc pool | **Yes** — `[store].encrypt` (default true) + `[store].trust_server_certificate` (default false); weakened only via the escape |

---

## No-TLS channels — hazards

These channels have **no transport encryption at all** — there is no per-connection `tls` option as
there is for MLLP:

- **Raw TCP source/destination** — plaintext, arbitrary framing.
- **X12 source/destination** — plaintext ISA/IEA-framed EDI interchanges.
- **Plain FTP** (RemoteFile `protocol=ftp`, as opposed to SFTP/FTPS) — cleartext protocol; credentials
  and file contents cross the wire in the clear (the connector refuses credentials over plain FTP unless
  the escape is set).

**Two more channels can carry PHI in cleartext even though they are not "no-TLS" by protocol** — list
them in the same risk register, because the engine will not refuse either one for you:

- **`dialect='generic'` DATABASE** (source *or* destination) — TLS is the ODBC driver's own keyword in
  `odbc_params`, which MessageFoundry cannot introspect. It is **never engine-enforced**: with no TLS
  keyword the connection logs a construction WARNING and proceeds, on any posture. Set
  `SSLmode=verify-full` (psqlODBC) / `SSLMODE=VERIFY_IDENTITY` (MySQL) / the equivalent, and treat it as
  a deployment requirement rather than a default.
- **Direct (S/MIME) with `use_tls = false`** — the message body is S/MIME signed and encrypted, but the
  SMTP session (envelope metadata, recipients) is cleartext. This path is gated by the raw
  `MEFOR_ALLOW_INSECURE_TLS` escape only; `[security].enforcement` does not clamp it.

**Deployment requirement:** run these on **loopback only**, or behind a **TLS-terminating proxy / on a
trusted, isolated network segment**. If PHI flows over one of them off-host without that protection, it
is exposed in cleartext. A non-loopback raw-TCP/X12 **bind** is refused at startup (`check_tcp_tls_exposure`,
PR #558) — but because these connectors have no TLS to enable, the gate's only passes are a loopback bind
or OS-level firewall/segmentation (`serve --allow-insecure-bind` is clamped inert on the default
enforcing-PHI posture); choosing one (and keeping PHI off the cleartext wire) is the **operator
responsibility**. On the **outbound** side these are cleartext *hops*, so they are governed by the hop
authority instead: off-loopback they **refuse** on an enforcing instance unless the connection declares
`cleartext_accepted` + `cleartext_reason`. For raw TCP and X12 that declaration is **permanent, not
transitional** — there is no `tls = true` for them to migrate to ([ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md)
decision 4; TLS support for them is BACKLOG #311). Credentialed plain FTP is refused outright on an
enforcing PHI instance (it puts the credential itself on the wire).

---

## The `MEFOR_ALLOW_INSECURE_TLS` escape hatch

Several connectors **fail closed** on a weakened-TLS or cleartext-credential configuration unless the
environment variable `MEFOR_ALLOW_INSECURE_TLS` is set. It exists for **dev / trusted-lab** use only.
With it set, these otherwise-refused settings become permitted (each logs a loud warning):

- REST/SOAP `verify_tls = false`. *(Clamped.)*
- MLLP outbound `tls_verify = false`; FTPS `tls_verify = false`. *(Clamped.)*
- DATABASE destination / store: `Encrypt=false` or `TrustServerCertificate=true` (SQL Server),
  `[store].trust_server_certificate=true` / `[store].encrypt=false`. *(Clamped.)*
- Plain-FTP credentials. *(Clamped.)*
- RemoteFile SFTP: accepting an unknown host key. *(Not clamped — the raw escape still applies.)*
- Cleartext SMTP submission on a **Direct** (S/MIME) destination. *(Not clamped; AUTH credentials over
  cleartext stay refused outright either way.)*
- The non-connection cells that have nowhere to carry a per-hop declaration: the `[logging]` syslog/SIEM
  forwarder and the API PHI-read serve hop *(both clamped)*, plus LDAPS, the webhook alert sink and the
  AI-broker endpoint *(raw escape)*.

**Two limits worth stating plainly.** *(a)* Since [ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md)
this variable has been **unhooked from the cleartext-hop authority** — that decision no longer reads it,
nor the instance's data label — so cleartext credentials over `http`, cleartext MLLP/DICOM/DICOMweb and the
cleartext HTTP family are now governed only by a per-connection `cleartext_accepted` + `cleartext_reason`
(warn + audit) or a loopback hop. (The engine also honours a `tls_hop_attested` hop — the opposite claim,
"secure by other means", a silent ALLOW — but that field has **no authoring surface on a connection**: no
factory parameter and no `connections.toml` key, so it is unreachable from config today. Refusal messages
that suggest it are ahead of the code.) *(b)* Where it does still apply it is mostly
**clamped** (ADR 0092 decision 2 / ADR 0148): it cannot relax a hop while `[security].enforcement =
enforce`, and for the MLLP/FTPS/plain-FTP and store-TLS cells the clamp additionally requires the instance
to be PHI — which is also the default. Either way, on the shipped posture those cells are inert; the
bullets marked *not clamped* are the exceptions that still honour the raw variable.

**Never set `MEFOR_ALLOW_INSECURE_TLS` in production.** Its presence is the single **environment-variable**
switch that turns the remaining fail-closed verification checks into best-effort.

**It is not the only way to weaken TLS, so do not audit for it alone.** Three further families of lever
sit outside this variable entirely, and a config review that greps for `MEFOR_ALLOW_INSECURE_TLS` will
miss all of them: per-connection **`cleartext_accepted` + `cleartext_reason`** (the sanctioned cleartext-hop
declaration — warned, audited and reported); **`[security].enforcement = warn`** or
**`handles_real_patient_data = false`** (instance-wide, and they downgrade or silence the gates
themselves); and per-connection
**[`tls_allow_expired`](#tls_allow_expired--the-weakening-with-no-posture-gate-at-all)**, which no
environment variable, posture clamp or loosening register covers at all.

---

## Egress allow-lists

Outbound destinations are confined by per-protocol allow-lists in `[egress]`
([`config/settings.py`](../messagefoundry/config/settings.py)). An **empty** list means unrestricted only
while deny-by-default is off — which, on a PHI instance, it is not (see below). Once a list is
**populated, it is fail-closed**: a destination of that type that
does not resolve to a listed `host:port` makes the config **fail at load / reload / start** (validated
*after* `env()` substitution, so dynamic addresses are checked against the resolved value).

| Setting | Confines |
|---|---|
| `[egress].allowed_mllp` | MLLP destinations |
| `[egress].allowed_tcp` | raw TCP, X12 **and** DICOM C-STORE SCU destinations |
| `[egress].allowed_http` | REST, SOAP, **FHIR**, **DICOMweb (STOW-RS)** destinations, the **SMART token endpoint**, and the read-only `fhir_lookup` |
| `[egress].allowed_db` | DATABASE destination + the DB poll source |
| `[egress].allowed_remote` | RemoteFile SFTP/FTPS/FTP (source + destination) |
| `[egress].allowed_smtp` | **EMAIL (SMTP) destinations** |
| `[egress].allowed_direct` | **Direct S/MIME HISP relay destinations** (deliberately separate from `allowed_smtp` — a distinct trust relationship) |
| `[egress].allowed_file_dirs` | File destination directories |

**The alert sinks are *not* on this table and are not covered by `[egress]`.** The webhook and SMTP
*alert* sinks carry no PHI bodies and keep their **own** host allow-lists —
`[alerts].webhook_allowed_hosts` and `[alerts].smtp_allowed_hosts`. Populate those separately; an
`[egress].allowed_http` entry does nothing for a webhook alert.

**What `[egress]` does and does not bound — read this before you book it as the exfiltration control.**
The check validates **declared connector settings** at config load / reload / start. It bounds the
**engine's own outbound connectors** and the two sanctioned Handler helpers (`db_lookup` against
`allowed_db`, `fhir_lookup` and the SMART token endpoint against `allowed_http`). It does **not** bound
arbitrary Handler code. **Config is executed code** (see above): a Handler is Python running in the
engine process, so nothing in `[egress]` stops Handler code from opening its own socket or HTTP client
and reaching any address the host can route to — with every list correctly populated and
`block_unlisted_outbound` on. The engine's own wording for the control is precise and worth borrowing:
it exists so a *fat-fingered or hostile **destination*** cannot exfiltrate PHI — a destination, not a
transform.

**The controls that do apply to Handler code**, none of which is an egress boundary:

- **Code review of Handler / Router modules** — the primary control, and the one to keep in your control
  set. `[egress]` does not replace it.
- **The `messagefoundry check` security lint** (ADR 0144) — a static scan for risky patterns in
  config-dir Router/Handler modules. It is **advisory: it prints and never blocks**, and static analysis
  catches a fraction of insecure code. A filter, not a boundary.
- **The opt-in `[sandbox]` subprocess isolation** (ADR 0087) — `mode` defaults to **`off`**. Set to
  `subprocess` it gives an address-space boundary plus a forbidden-import guard, which is real
  blast-radius reduction, but it is **not a network-egress deny**: a worker can still connect sockets
  from inside the child. It also **fails `db_lookup` / `fhir_lookup` closed**, so a feed needing live
  enrichment cannot use it. A deny-by-default brokered sandbox is **proposed, not built** (ADR 0147).

For an off-loopback deployment, populate the lists you use so a **misconfigured or hostile destination**
cannot deliver to an unapproved address — **all eight of them**, not just the transports you happen to
remember. An operator who takes the `block_unlisted_outbound = false` opt-out and then populates only
the rows they recall leaves the rest of the estate's declared egress unrestricted while believing
exfiltration is confined. The **global deny-by-default toggle is built** — `[security].block_unlisted_outbound`
— and on a **PHI instance the serve gate turns it on for you** unless you set it explicitly, so a
transport whose `allowed_*` list is empty then refuses *every* destination of that type. Related refusal:
a PHI instance with **no** allow-list populated *and* deny-by-default off has fully unrestricted egress
and **refuses to start** under `[security].enforcement = enforce` (it warns at `warn`).

---

## Bind-guard behavior (summary)

- **API** ([`__main__.py`](../messagefoundry/__main__.py)): a non-loopback bind is refused unless
  in-process TLS is configured, or `tls_terminated_upstream` + `trusted_proxies` are set; also refused if
  `[security].require_sign_in = false`, which no flag covers. Override (dev only):
  `serve --allow-insecure-bind` — **clamped inert on an enforcing PHI instance**, i.e. on the shipped
  default.
  **This is not the whole API gate.** Two further `return 2` refusals layer on top of that ladder, and
  **neither is covered by `--allow-insecure-bind`**: an in-process-TLS off-loopback bind also needs
  `MEFOR_TLS_REVOCATION_ATTESTED=1` ([ADR 0078](adr/0078-certificate-revocation-posture.md) — see
  [Revocation-guard behavior](#revocation-guard-behavior)), and a PHI instance behind a **declared**
  terminator also needs `[api].proxy_intra_service_auth` + `[api].proxy_tls_min_version` (off-loopback:
  refuse; loopback-behind-proxy: warn).
- **MLLP inbound** ([`pipeline/wiring_runner.py`](../messagefoundry/pipeline/wiring_runner.py),
  `check_mllp_tls_exposure`): a non-loopback MLLP source without `tls=true` raises a `WiringError` at
  wiring time (before the engine starts). Override (dev only): `serve --allow-insecure-bind`, under the
  same clamp.
- **DICOM C-STORE SCP / HTTP / raw-TCP / X12 inbound** (same module): siblings of the MLLP guard —
  `check_dimse_tls_exposure`, `check_http_tls_exposure`, and `check_tcp_tls_exposure` (raw-TCP **and** X12,
  shipped in PR #558) — each refuses a non-loopback bind without TLS at wiring time. raw-TCP/X12 are
  plaintext-only, so for them the only passes are loopback or OS firewall/segmentation. So every inbound
  listen type is now exposed-gated.
- **The clamp, precisely** ([ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md),
  ADR 0092 decision 2): all four inbound gates and the API gate honour `--allow-insecure-bind` only while
  the instance is **not** (`enforcement = enforce` **and** PHI). Both halves are the default, so on a stock
  instance the flag changes nothing — the recorded loosening is `[security].enforcement = warn` or
  `[security].handles_real_patient_data = false`. These refusals also name `tls_hop_attested`, which the
  gates do read, but that field has no authoring surface on a connection today (see
  [the escape hatch](#the-mefor_allow_insecure_tls-escape-hatch)).
- **Browser console (`/ui`)**: an off-loopback `/ui` additionally requires in-process TLS or a declared
  terminator and is refused without one — `--allow-insecure-bind` does not cover it.

---

## Revocation-guard behavior

**The engine performs no certificate revocation checking, and it will not.** Stdlib `ssl` exposes no
OCSP/CRL fetch, and the engine is offline-by-default on-premises, so it attempts none. A chain is
validated (including strict RFC 5280 path validation), but a **revoked-but-unexpired** certificate is
still accepted. [ADR 0078](adr/0078-certificate-revocation-posture.md) (and its #201 outbound amendment)
turns that from a documented delegation into **two fail-closed refusals**, both layered *after* the
bind-guard ladder above:

- **Listener** — `serve` **refuses (exit 2)** an off-loopback bind that terminates TLS **in-process**
  (`[api].tls_cert_file`). Loopback binds and proxy-terminated binds never reach this and start
  unchanged.
- **Outbound** — **seven** verifying outbound TLS hops are **refused at construction** (`messagefoundry
  check` / dry-run / reload / the serve pre-flight) on an instance that is **PHI *and*
  `enforcement = enforce`**, when the hop is off-loopback. That list is the **whole gated set, not a
  sample**: **MLLP-over-TLS, REST, SOAP, FHIR, DICOMweb (https), SMTP/EMAIL, and the PostgreSQL store
  hop** — the only cells that construct a `RevocationHopGuard`. A non-enforcing PHI instance **warns**
  instead; a synthetic instance is unaffected (see *The ways across*, below).

**Every other verifying TLS hop the engine dials is ungated.** It validates the chain — and nothing
asks it for an attestation, warns, or refuses. **Do not book revocation as an estate-wide engine
control**: confirming the refusal on MLLP and REST tells you nothing about these, which cross silently
on the shipped posture.

| Ungated verifying TLS hop | Why it is a verifying hop |
|---|---|
| **SQL Server store hop** | `[store].encrypt` defaults **true** and `[store].trust_server_certificate` defaults **false** — and SQL Server is a documented production store. The PostgreSQL store hop *is* gated; its SQL Server twin is not |
| **DICOM C-STORE SCU** with `tls = true` | the SCU client context always verifies chain + hostname |
| **RemoteFile FTPS** | explicit TLS, verifying by default |
| **`dialect='sqlserver'` DATABASE destination** | `Encrypt=yes` / `TrustServerCertificate=false` defaults |
| **LDAPS** (`[auth].ad_tls_verify`, default true) | verifying directory bind |
| **`[logging]` TLS syslog forwarder** (`forward_tls_verify`, default true) | CA-anchored RFC 5425 hop |
| **Webhook alert sink** and the **AI-broker endpoint** | verifying https openers |
| **`[alerts]` SMTP sink** and the **per-user security-event notifier** | `email_tls_verify` defaults **true** ([#323](BACKLOG.md)) — one verifying context, two call sites. Deliberately carries **no** `RevocationHopGuard`: it is constructed outside the `active_hop_posture` scope those guards read, so a guard here could not see the instance posture. Its verify-off / cleartext deviations are gated by `[security].allow_unverified_alert_smtp_tls` at the serve gate instead |

For every hop in that table, revocation is exactly what the ASVS row above calls *delegated* — **your
PKI's or your egress proxy's job, written into your runbook**. The engine will not make you say so, and
`MEFOR_TLS_REVOCATION_ATTESTED=1` is not consulted for them either. A deployment that runs the SQL
Server store and a TLS C-STORE SCU to the PACS has **no** engine-enforced revocation on either hop.

The two gates compose with — never duplicate — the cleartext gates: a cleartext or `verify_tls=false`
hop is already refused by the [hop authority](#channel--tls-posture-matrix), so revocation only ever
decides a hop that is *already* verifying.

**The ways across.** There is no `--allow-insecure-bind` for either gate and `MEFOR_ALLOW_INSECURE_TLS`
does not reach them — but there are **five** crossings, not three. Items 1–3 are the only ones available
**at the shipped PHI + `enforce` default**. Items 4–5 are what a *changed* posture does, they apply to
the **outbound gate only** (the listener gate reads neither the data label nor `enforcement`, so it
refuses regardless), and they are the realistic failure mode — a mislabelled box, not a missing
attestation:

1. **Prove revocation in front — API gate only.** Terminate at a revocation-checking reverse proxy:
   `[api].tls_terminated_upstream` + `[api].trusted_proxies`, after which the engine terminates no TLS
   itself and the listener gate never fires. **There is no outbound equivalent you can configure.** The
   authority has a "declared revocation-checking egress terminator" input, but no call site ever sets it
   — routing your egress through such a proxy is good practice and does not change the engine's
   decision, so an outbound hop still needs option 2 or 3.
2. **Attest it** — set the environment variable `MEFOR_TLS_REVOCATION_ATTESTED=1`. It is **blanket**:
   it clears both gates for the whole process, for every hop. This is you taking responsibility for
   revocation, not the engine acquiring it; an attestation that suppresses a would-be refusal is
   **logged at WARNING at every construction**, so it stays visible.
   (A per-connection `tls_revocation_attested` field exists on the outbound model and the connectors do
   read it — but like `tls_hop_attested` it has **no authoring surface**: no connector-factory parameter
   and no `connections.toml` key, so it is unreachable from config today. The blanket env var is the
   only attestation you can actually set. Do not plan a per-hop revocation posture around it.)
3. **Stay on loopback**, which neither gate reaches.
4. **Declare the box synthetic** — `[security].handles_real_patient_data = false` **silences the
   outbound gate entirely**: the disposition returns ALLOW before it ever reaches the refuse arm, on
   every hop, with no per-hop record. This is the widest crossing on the list and the easiest to reach
   for by accident (it is also a plausible way to quieten startup output), so treat a synthetic
   declaration on a box that carries real feeds as a **revocation-control failure**, not a labelling nit.
   It is named in `security_loosenings()` / `GET /security/posture` — audit it there.
5. **`[security].enforcement = warn`** — downgrades every outbound revocation refusal to a **warning**
   and lets the hop proceed. Also a named loosening in the posture read-out.

Items 4 and 5 are **not supported production settings** and neither is a per-hop decision: both are
instance-wide, and both leave the refusal-shaped evidence a reviewer looks for **absent rather than
recorded**. If you are auditing revocation, check those two switches *before* counting attestations.

---

*Maintenance: keep this matrix in sync with `transports/`, `config/settings.py` (`[security]`/`[egress]`/
`[api]`/`[store]`/`[alerts]`), `config/tls_policy.py` (the cleartext-hop authority **and** the revocation
guards), and the bind-guards in `__main__.py` / `pipeline/wiring_runner.py`. Four standing traps:
a connector that does **not** route through `InsecureHopGuard` must be named as an exception rather than
covered by the "one authority" paragraph; **the same discipline applies to `RevocationHopGuard`** — the
gated set is enumerable (grep the constructions) and every *other* verifying TLS hop must be named as
ungated, never covered by an "every verifying hop" sentence; a weakening with no posture gate
(`tls_allow_expired`) must be listed even though no refusal keys on it and
`security_loosenings()` never reports it; and a field with no factory parameter and no `connections.toml`
key (`tls_hop_attested`, `tls_revocation_attested`) must never be offered as an operator lever.
Two more rules of thumb: state a control **with its default and its off-switch** (`require_sign_in`,
`enforcement`, `handles_real_patient_data`), and never describe `[egress]` as bounding a *transform* —
it bounds declared **destinations**.
Cross-referenced from `PHI.md` §4, `CLUSTERING.md`, and ADRs 0002 / 0078 / 0148 / 0153.*
