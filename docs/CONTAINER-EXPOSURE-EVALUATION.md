# Off-Loopback Exposure Evaluation — Containerized MessageFoundry Engine

**Status:** Evaluation / recommendation (no code, no Dockerfile). Scopes the ADR 0017
"container fast-follow" — shipping the **headless engine** as an OCI image. The PySide6 console
stays a host-side GUI client; only the engine containerizes.

**Audience:** the owner deciding whether/how to build the container image, and the security
reviewer who will ask "what changes when this leaves loopback."

**Bottom line:** the engine is **already safely exposable off-loopback** — the four work packages
that the loopback assumption depended on (WP-13a API/WSS TLS, WP-13b MLLP-over-TLS, WP-14 TOTP MFA,
WP-15 reverse-proxy trust) are **built and live**, and the fail-closed bind guards refuse an unsafe
exposure at startup. A container is just another way to bind off-loopback, so it inherits those
controls unchanged. The build task is **packaging + ops wiring**, not new security logic. The
residuals below are small and already documented design choices, plus a few container-specific
operational notes.

> **Doc-staleness flags:**
> 1. Earlier *project memory* describing ADR 0002 WP-13a/13b/15 as "deferred until off-loopback" is
>    **stale** — they are built (ADR 0002 is Accepted; code cited throughout below). Memory was left
>    untouched (shared across sessions; the owner should confirm before any memory write).
> 2. **Corrected in this change:** several current-state docs (DEPLOYMENT.md, CONFIGURATION.md,
>    FEATURE-MAP.md, EARLY-ADOPTER-GUIDE.md, THREAT-MODEL.md, and the `console/client.py`
>    `_assert_safe_transport` docstring) had called **WP-14 native MFA**, **mTLS**, and **off-box log
>    forwarding** "0.2 / not built." All three are built (MFA WP-14 2026-06-17; mTLS via
>    `tls_client_ca_file`/`tls_ca_file`; off-box logs via `[logging].forward_*`), and those docs were
>    updated. **Left as-is** (point-in-time records, not current-state claims): the ASVS scorecard docs
>    (owned by a parallel session) and the dated v0.1 release-plan / review snapshots.

---

## 0. What is actually built (verification, not re-derivation)

| Control | Where | Confirmed behavior |
|---|---|---|
| API/WSS in-process TLS (WP-13a) | [`api/tls.py`](../messagefoundry/api/tls.py) `build_api_ssl_context`; [`config/settings.py`](../messagefoundry/config/settings.py) `ApiSettings.tls_*` | `PROTOCOL_TLS_SERVER`, `minimum_version` from `tls_min_version` (1.2/1.3 floor), `load_cert_chain(cert, key, password)`, optional ciphers, hardened KEX groups + strict X.509; opt-in mTLS via `tls_client_ca_file` → `CERT_REQUIRED`. Wired into the single `uvicorn.run(...)` via `ssl_context_factory` ([`__main__.py`](../messagefoundry/__main__.py) ~538-545). |
| API bind guard ("exposed" gate) | [`__main__.py`](../messagefoundry/__main__.py) ~419-451 | Non-loopback `[api].host` → **allow** if `tls_enabled`, **allow** if `tls_terminated_upstream` (+`trusted_proxies`), **warn** if `--allow-insecure-bind`, else **refuse (exit 2)**. Auth-disabled non-loopback is refused by a separate earlier gate **regardless of** `--allow-insecure-bind`. |
| MFA-at-exposure gate | [`__main__.py`](../messagefoundry/__main__.py) ~462-481 | Non-loopback + `auth.enabled` + **not** `require_mfa`: **refuse** on a production PHI instance, **warn** on a non-production PHI instance, quiet on synthetic. Gates **local** Administrator accounts only (AD MFA delegated). |
| MLLP-over-TLS (WP-13b) | [`transports/mllp.py`](../messagefoundry/transports/mllp.py) `_mllp_ssl_context`; `MLLP(...)` in [`config/wiring.py`](../messagefoundry/config/wiring.py) ~540-610 | Per-connection `tls=true`. Inbound presents `tls_cert_file`/`tls_key_file`; `tls_ca_file` opts into mTLS (`CERT_REQUIRED`). Outbound verifies the peer (`tls_verify=true` default; `false` refused unless `MEFOR_ALLOW_INSECURE_TLS`), optional client cert. `start_server(ssl=)` / `open_connection(ssl=, server_hostname=)`. TLS 1.2+. |
| MLLP exposed gate | [`pipeline/wiring_runner.py`](../messagefoundry/pipeline/wiring_runner.py) `check_mllp_tls_exposure` ~1655-1678 | A non-loopback MLLP listener **without** `tls=true` raises `WiringError` at wiring time (before start); `--allow-insecure-bind` downgrades to a warning; loopback or `tls=true` pass. Sibling `check_dimse_tls_exposure` covers DICOM SCP. |
| Reverse-proxy trust (WP-15) | `ApiSettings.tls_terminated_upstream` / `trusted_proxies`; `forwarded_allow_ips` in `uvicorn.run` ([`__main__.py`](../messagefoundry/__main__.py) ~531-533) | `tls_terminated_upstream` satisfies the gate **without** in-process TLS, but the model validator **requires** `trusted_proxies` to be set with it. `forwarded_allow_ips` trusts XFF/XFP only from the named proxies (empty = trust nothing). |
| TOTP MFA (WP-14) | ADR 0002 §3; `[auth].require_mfa`; console flow in [`console/client.py`](../messagefoundry/console/client.py) | Native RFC 6238 TOTP for local accounts; step-up boundary; admin reset; recovery codes. Built 2026-06-17. |
| Cert-expiry monitor | [`pipeline/cert_expiry.py`](../messagefoundry/pipeline/cert_expiry.py); `[cert_monitor]` in [`config/settings.py`](../messagefoundry/config/settings.py) | Engine-owned asyncio task (started in `Engine.start`). `certs_from_registry` watches the `[api]` cert + every connection `tls_cert_file`; reads `notAfter` only (never the key); `warn_days` default 30, 12 h cadence; raises a `cert_expiry` AlertSink event. |
| Console transport guard | [`console/client.py`](../messagefoundry/console/client.py) `_assert_safe_transport` | `https` always allowed; loopback host allowed; non-loopback `http` **refused** unless `--insecure` (then warned). `httpx.Client(cert=...)` carries a client cert for mTLS via `--client-cert`/`--client-key`. |
| At-rest PHI cipher | `[store].encryption_key` (`MEFOR_STORE_ENCRYPTION_KEY`), `require_encryption` | AES-256-GCM on PHI columns; `require_encryption=true` refuses start without a key; rotation via `messagefoundry rotate-key` + `encryption_keys_retired`. |

**No Dockerfile / compose exists in the repo** (confirmed via glob). ADR 0017 decision 7 lists the
container image as a **fast-follow**, "byte-identical multi-instance rollout… after the env-name
Blocker; not on the critical path." So this is greenfield packaging.

---

## 1. Recommended container exposure topology

Docker port publishing (`-p host:container`) forwards traffic to the **container's network
interface** (e.g. `eth0` on the bridge), *not* the container's loopback. So an engine that must be
reachable through a published port has to bind **off-loopback inside the container** — which engages
the gate. The right topology depends on the orchestrator.

### Recommendation, by orchestration

| Orchestration | API plane | MLLP data plane | Why |
|---|---|---|---|
| **Plain Docker, single host** | **(a) in-process TLS** — engine binds `0.0.0.0:8443`, mount PEM cert/key, `-p 8443:8443` | in-container **MLLP-over-TLS** (`tls=true` per connection), `-p 2575:2575` | Self-contained, matches the single-binary / broker-free ethos; no extra moving parts. |
| **Kubernetes / same-pod sidecar / `--network host`** | **(c→b) loopback + TLS-terminating sidecar** — engine binds `127.0.0.1`, sidecar terminates TLS, forwards to `127.0.0.1`; set `trusted_proxies=[127.0.0.1]` | a **TLS-terminating TCP sidecar** for MLLP, engine MLLP binds loopback (gate passes) — *or* in-container MLLP-over-TLS | A shared network namespace makes the engine genuinely loopback-bound, so the gate passes **trivially** and only the hardened proxy is exposed. Cleanest from the engine's view. |
| **Separate proxy container on a Docker network** (not shared netns) | **(b) upstream TLS** — engine binds `0.0.0.0:8765` on the internal network, `tls_terminated_upstream=true` + `trusted_proxies=[<proxy IP/subnet>]`; do **not** publish the engine port to the host | in-container **MLLP-over-TLS** (no MLLP proxy primitive in the design unless you add a TCP/TLS sidecar) | Fits shops standardizing on nginx/Caddy/IIS or an ingress controller; the proxy is also the right place for OCSP-must-staple revocation and client-cert mTLS. |

### The three options, justified

- **(a) In-process TLS (WP-13a) — default for the shipped image.** Bind `[api].host = 0.0.0.0`,
  mount `tls_cert_file`/`tls_key_file`, publish `8443`. The bind guard sees `tls_enabled` → allows;
  HSTS engages on `https`, `/ws/stats` is `wss`. One image, no second process. Best for "docker run
  it and go" and for the byte-identical multi-instance rollout ADR 0017 wants.

- **(b) Sidecar / ingress reverse proxy (WP-15) — first-class alternative.** Keep the engine `http`
  on the container network behind a TLS terminator. Two sub-cases:
  - **Same pod / shared netns (recommended for k8s):** the sidecar reaches the engine on `127.0.0.1`,
    so the engine stays **loopback-bound** and the gate never even trips. Still set
    `trusted_proxies=[127.0.0.1]` so the audit/rate-limit source IP is the real client from
    `X-Forwarded-For`, not the proxy.
  - **Separate container, different netns:** the engine binds the internal interface (off-loopback),
    so you **must** set `tls_terminated_upstream=true` + `trusted_proxies` to pass the gate without
    in-process TLS. Do not publish the engine's plaintext port to the host.

- **(c) "Loopback-only publish" — does the guard still trip? Yes (mostly).** Publishing to
  `-p 127.0.0.1:8765:8765` only narrows *who on the host* can reach the port; the engine inside the
  container must still listen on the container interface, because Docker's NAT forwards to the
  container's IP, not its loopback. If the engine binds `127.0.0.1` *inside the container*, the
  forwarded packets arrive at `eth0` and find nothing → connection refused. So **(c) is not a way to
  avoid TLS** — the bind guard fires exactly as for any off-loopback bind. The **only** true-loopback
  escape is a **shared network namespace** (`--network host` on Linux, or a same-pod sidecar), where
  binding `127.0.0.1` in the container *is* the host/pod loopback. `--network host` is Linux-only and
  not portable to Docker Desktop on Windows; treat it as the k8s/Linux pattern in (b), not a Windows
  story.

**Recommendation:** ship the image defaulting to **(a)** for self-contained installs, document **(b)
same-pod sidecar** as the k8s-preferred pattern (cleanest gate story + the place to do mTLS and
revocation), and explicitly debunk **(c)** as a TLS bypass.

---

## 2. Bind-guard behavior inside a container

The guards are network-posture checks, blind to whether they run in a container — so the in-container
bind host is all that matters.

| Topology | `[api].host` in container | API gate outcome | Required config |
|---|---|---|---|
| (a) in-process TLS | `0.0.0.0` (off-loopback) | **allow** — `tls_enabled` branch | `tls_cert_file` (+ `tls_key_file`); `auth.enabled=true` |
| (b) same-pod sidecar | `127.0.0.1` (loopback) | **gate not triggered** (`is_loopback`) | `trusted_proxies=[127.0.0.1]` (for correct client IP); no in-process cert needed |
| (b) separate proxy container | `0.0.0.0` (off-loopback) | **allow** — upstream branch | `tls_terminated_upstream=true` **and** `trusted_proxies=[<proxy>]` (validator enforces the pairing) |
| (c) loopback publish, no shared netns | `0.0.0.0` (forced — see §1) | same as (a)/(b-separate); `127.0.0.1` bind would be unreachable | same as (a) or (b-separate) |

MLLP gate (`check_mllp_tls_exposure`), per inbound's resolved host (`[inbound].bind_host`, typically
`0.0.0.0` in a container to receive published traffic):

| MLLP bind | `tls` | Outcome |
|---|---|---|
| loopback (incl. same-pod sidecar terminating MLLP-TLS) | any | **pass** |
| `0.0.0.0` (off-loopback) | `tls=true` (+ cert) | **pass** |
| `0.0.0.0` | unset | **`WiringError` at wiring time** (engine won't start) |

**Is `--allow-insecure-bind` ever right for a container?** Only for a **dev/test compose on a
trusted, isolated segment** — e.g. a local integration rig where partners and console are on the same
host and no real PHI flows. It downgrades both the API refuse-path and the MLLP `WiringError` to loud
warnings. It is **never** a production setting and must not be baked into the shipped image's default
command. (It also does **not** override the auth-disabled refusal or the production-PHI MFA refusal —
those stay fail-closed.)

**Exact required config per topology:**

```toml
# (a) in-process TLS — the default shipped posture
[api]
host = "0.0.0.0"
port = 8443
tls_cert_file = "/etc/mefor/tls/api.crt"
tls_key_file  = "/etc/mefor/tls/api.key"     # tls_key_password via MEFOR_API_TLS_KEY_PASSWORD if encrypted
# tls_client_ca_file = "/etc/mefor/tls/console-ca.crt"  # opt-in mTLS for the console
[auth]
enabled = true
require_mfa = true                            # required on a production PHI instance with local admins

# (b) separate proxy container terminates TLS
[api]
host = "0.0.0.0"
port = 8765
tls_terminated_upstream = true
trusted_proxies = ["10.0.0.0/8"]              # the proxy/ingress addresses ONLY

# (b) same-pod sidecar (shared netns) — engine stays loopback
[api]
host = "127.0.0.1"
port = 8765
trusted_proxies = ["127.0.0.1"]               # so XFF from the sidecar gives the real client IP
```

```python
# MLLP inbound in a container (data plane) — required when bind_host is off-loopback
inbound("IB_ACME_ADT", MLLP(
    port=2575,
    tls=True,
    tls_cert_file="/etc/mefor/tls/mllp.crt",
    tls_key_file="/etc/mefor/tls/mllp.key",   # unencrypted, OR encrypted + tls_key_password=env("mllp_key_pw")
    # tls_ca_file="/etc/mefor/tls/partner-ca.crt",  # opt-in partner mTLS
), router="route_adt")
```

---

## 3. The data plane, not just the console

Partners send HL7 to the **inbound MLLP listener** — in any real install this is on the LAN, not
localhost (an EHR's feed is not on `127.0.0.1`). It is the **primary off-loopback surface**, more so
than the admin API. DEPLOYMENT.md's three-plane model makes this explicit: the **management plane**
stays most contained; the **data plane is network-bound by nature**.

**MLLP-over-TLS for a containerized listener is effectively mandatory.** With `[inbound].bind_host =
0.0.0.0` (the container norm), `check_mllp_tls_exposure` raises a `WiringError` at start unless each
MLLP connection sets `tls=true` (+ server cert). There is **no MLLP-terminating reverse-proxy
primitive** in the engine the way there is for the API (WP-15) — the gate's only no-TLS pass is a
*loopback* bind. So two valid container patterns:

1. **In-container MLLP-over-TLS** (the direct path): `tls=true` per connection, key/cert mounted.
2. **TLS-terminating TCP sidecar** (the MLLP analogue of WP-15): a same-pod sidecar terminates
   MLLP-over-TLS (and any partner mTLS) and forwards plaintext to the engine on `127.0.0.1`, where
   the MLLP gate passes on loopback. The engine never sees the partner cert in this pattern.

**mTLS for partners — opt-in, not default.** Keep it opt-in (`tls_ca_file` on the connection), which
is what's built and what ADR 0002's "to resolve on acceptance" item 1 leaned toward (mTLS opt-in;
expiry alert yes). Rationale:
- A healthcare partner estate is a mixed bag — forcing client certs on every sending system is an
  integration blocker, and many partners terminate at *their* edge.
- Server-auth TLS already gets PHI off the wire encrypted (the 12.3.1 win); partner *identity* is
  often established by network segmentation + the `source_ip_allowlist` (already per-connection) + the
  `[egress]` allow-lists.
- Where a partner *can* present a cert (or for a high-value feed), turn mTLS on per connection. Make
  it a documented, easy per-connection switch — not a global default that breaks day-one onboarding.

So: **server TLS required** (the gate enforces it), **mTLS opt-in per partner**, with
`source_ip_allowlist` as the lighter-weight identity control for partners that can't do certs.

---

## 4. Cert + secret provisioning into a container

| Item | Type | How into the container | Notes |
|---|---|---|---|
| `tls_cert_file`, `tls_key_file` (API + MLLP) | PEM **files** (the *key* is sensitive) | **mount** as read-only files (bind mount, Docker config/secret-as-file, or k8s Secret mounted as a volume) | The settings treat these as *paths, not secrets*, but the **key file is sensitive** — mount read-only, restrict perms, never bake into an image layer. |
| `tls_key_password` (API + MLLP) | secret | API: env `MEFOR_API_TLS_KEY_PASSWORD`. MLLP: per-connection `tls_key_password=env(...)` | Decrypts an encrypted private key. The API key uses the env var; an encrypted **MLLP** key uses the per-connection `tls_key_password` (env-sourced) — see §7. |
| Store cipher key | secret | container env / secret → `MEFOR_STORE_ENCRYPTION_KEY` (base64 32-byte) | Set `[store].require_encryption = true` so the engine **fails closed** if the key is absent. Mint with `messagefoundry gen-key`. |
| DB password / `tls_client_ca_file` etc. | secret / file | env (`MEFOR_STORE_PASSWORD`) / mounted file | Prefer the orchestrator's secret store over plain `-e` where possible. |

**Prefer secret stores over plain env** for the passwords/keys (Docker/K8s secrets surface as files
or scoped env; plain `-e` leaks into `docker inspect` and image history). PEM **certs** can be plain
mounts; the **private keys** should be treated like secrets (read-only, tight perms).

**Rotation.**
- **MLLP cert/key:** rebuilt in the connector `__init__`, so a **config reload** (`POST
  /config/reload`) re-instantiates the connector and picks up a swapped PEM — no restart.
- **API cert/key:** the uvicorn TLS context is built **once** at `uvicorn.run` (a fixed
  `ssl_context_factory`); a config reload does **not** rebuild it. **API cert rotation requires a
  process/container restart.** With the byte-identical multi-instance + active-passive HA model, do a
  **rolling restart** (drain one instance, swap its mounted cert, restart). Worth stating in the
  runbook; consider an `ssl_context_factory` that re-reads on each handshake as a future enhancement.

**Cert-expiry monitor inside a container — works.** `CertExpiryRunner` is an engine-owned asyncio
task; it reads the mounted PEM files (`notAfter` only) on a 12 h cadence and raises a `cert_expiry`
AlertSink event (default `LoggingAlertSink` if no notifier is configured). To get a real notification
out of a container, wire an `[alerts]` transport (webhook/email) — otherwise it only logs, and a
container's stdout may be the only sink. **Caveat:** `certs_from_registry` **skips a cert path
supplied as a deferred `env()` reference** (it isn't a literal path at scan time). If MLLP cert paths
are provided via `env()`, those certs go **unmonitored** — use literal paths for monitored certs, or
accept that only the `[api]` cert (always a literal setting) is alarmed. (See §7.)

---

## 5. Console reach

The console stays a **host-side process**; only its target URL changes.

- **Same-host (recommended for an operator on the container host):** publish the API to
  `-p 127.0.0.1:8443:8443` and point the console at `https://localhost:8443`.
  `_assert_safe_transport` allows `https` unconditionally, so this is clean. **Friction to document:**
  `httpx` verifies the server cert by default, so the cert's SAN must include `localhost` (or the host
  name used) and the console host must trust the issuing CA — a self-signed cert needs the CA in the
  trust store. Provide a CA bundle or a properly-SAN'd cert in the runbook.
- **Remote (operator elsewhere on the trusted network):** `https://<engine-host>:8443`. For mTLS, the
  API sets `tls_client_ca_file` (→ `CERT_REQUIRED`) and the console presents a client cert via
  `--client-cert`/`--client-key` (threaded into `httpx.Client(cert=…)`).
- **Plaintext-refuse holds (confirmed):** `_assert_safe_transport` refuses `http` to a non-loopback
  host unless `--insecure` (which then warns). So a remote console **cannot** silently send the bearer
  token + PHI in cleartext — it must be `https`, or the operator must consciously opt into the
  trusted-network dev escape. The background-poll client (`for_polling`) inherits the same guard
  (same constructor). *(Minor: the `_assert_safe_transport` docstring still says "there is no transport
  TLS yet" — stale wording; the `https`/mTLS paths are implemented. Cosmetic, fold into the doc
  sweep.)*

---

## 6. PHI / volume considerations

- **SQLite store volume holds PHI.** Mount a named volume (or bind mount) for `messagefoundry.db` +
  WAL/SHM files. Enable the at-rest cipher: `MEFOR_STORE_ENCRYPTION_KEY` set, and
  `[store].require_encryption = true` so a PHI instance **refuses to start** without it (fail-closed,
  matching the keyless-store posture). Back up and restrict the volume like any PHI-at-rest store.
- **External SQL Server / Postgres store.** The store connection is TLS by default
  (`[store].encrypt = true`, `[store].trust_server_certificate = false`). **`MEFOR_ALLOW_INSECURE_TLS`
  must NOT be set in a real deployment** — it is the single switch that downgrades store TLS (and
  MLLP-outbound verify, REST/SOAP verify, SFTP host-key, plain-FTP creds) to best-effort. Note CI sets
  it deliberately for the self-signed SQL Server container; that is a **CI-only** posture and must
  never leak into a production image/compose. Give the production DB a CA-trusted cert instead.
- **Logs.** Keep the service at INFO (never raise to DEBUG in a PHI container — full-body logging risk
  per the PHI rules). **Off-box log + audit forwarding is built** (`[logging].forward_*` → syslog/SIEM);
  enable it so a container's logs + PHI-redacted audit rows reach the org pipeline. Residual: the syslog
  transport is plaintext — front it with a local TLS-forwarding agent (or rely on the container
  runtime's log driver to a TLS collector).

---

## 7. Gaps / residuals to flag

1. **In-engine TLS revocation is delegated (ADR 0002, accepted).** The in-process API-TLS and direct
   MLLP-over-TLS paths do **not** do live OCSP/CRL — a revoked-but-unexpired cert is not rejected by
   the engine itself (`harden_verify_flags` does strict RFC 5280 *path* validation, not revocation).
   For **enforced revocation**, use topology (b) with an **OCSP-must-staple** terminator + the org PKI.
   Document this for any topology-(a) deployment that has a revocation requirement.

2. **MLLP TLS private keys may be passphrase-encrypted (BUILT in the container work).** `_mllp_ssl_context`
   now plumbs `password=` into `load_cert_chain` on both the inbound and outbound paths, fed by a
   per-connection `MLLP(... tls_key_password=...)` (supply it via `env()` so the secret stays out of
   config — parity with the API's `MEFOR_API_TLS_KEY_PASSWORD`). An unencrypted MLLP key is still fine
   (omit `tls_key_password`); protect it via the secret store + file perms regardless. *(An encrypted key
   with no passphrase fails deterministically at build — no TTY prompt — in both the MLLP and API paths.)*

3. **Cert-expiry monitor skips `env()`-referenced cert paths** (`certs_from_registry`). MLLP certs
   wired via `env()` are **unmonitored**. Use literal paths for any cert you want alarmed, or accept
   that only the `[api]` cert is covered. Worth a one-line note in the container runbook.

4. **API cert rotation needs a container restart** (§4) — the uvicorn TLS context is built once. Plan a
   rolling restart; MLLP certs rotate on config reload, the API cert does not.

5. **Raw TCP / X12 inbound have *no* transport guard.** Unlike MLLP/DICOM, a non-loopback raw-TCP or
   X12 listener is **not refused** — it would publish plaintext PHI with no startup error (operator
   responsibility, per DEPLOYMENT.md "No-TLS channels — hazards"). A container that exposes those must
   keep them loopback-bound or front them with a TLS-terminating TCP proxy. The shipped image should
   **not** publish raw-TCP/X12 ports by default.
   **[CORRECTION 2026-06-28 — ADR 0047]:** the raw-TCP/X12 startup TLS guard has since **shipped**
   (`check_tcp_tls_exposure`, PR #558, 2026-06-26): a non-loopback raw-TCP/X12 bind without TLS and without
   `--allow-insecure-bind` is now **refused at startup**, at parity with the MLLP/DICOM/HTTP guards. The
   "operator responsibility / not refused" framing above is the point-in-time (pre-PR-558) record; keep the
   loopback-or-TLS-proxy guidance, but the engine now enforces it rather than leaving it unchecked.

6. **No Dockerfile/compose exists — the build task owns the container-runtime hardening**, none of
   which is security-logic the engine lacks, but all of which must be designed:
   - non-root UID, read-only root filesystem, dropped capabilities, minimal base image;
   - a `HEALTHCHECK` (the API exposes `GET /health`);
   - **signal handling** — `SIGTERM` → uvicorn graceful shutdown → the ASGI lifespan calls
     `engine.stop()` (which drains MLLP clients with the `_CLIENT_SHUTDOWN_GRACE` bound). Verify the
     container init/entrypoint forwards signals (PID 1 / `--init` / `tini`) so shutdown is clean and
     at-least-once holds.
   - The engine is **Windows-service-first** (NSSM) today; a **Linux** container is a new runtime
     target. The asyncio/uvicorn/SQLite stack is OS-portable and the console stays on the host, so this
     is low-risk — but it is the first non-Windows runtime and deserves a CI leg.

7. **Production-PHI + local accounts must enable MFA to even start.** The MFA-at-exposure gate
   *refuses* a non-loopback bind on a production PHI instance with local accounts unless
   `[auth].require_mfa = true` (or all accounts are AD, where MFA is delegated). The container's
   default config and docs must make `require_mfa = true` the production default, or the operator hits
   a hard startup refusal — which is correct, but should be expected, not surprising.

8. **Doc/memory staleness.** The current-state doc staleness (MFA / mTLS / off-box logs described as
   "0.2 / not built") **was corrected in this change** (see header flag 2). The **project memory**
   calling WP-13a/b/15 "deferred" is still stale — WP-13a/13b/14/15 are built — but memory was left
   untouched (the owner should confirm before any memory write, per the shared-memory rule).

---

## Appendix — quick decision summary

- **Ship the image defaulting to in-process TLS (a):** `host=0.0.0.0:8443`, mount cert/key, MLLP
  `tls=true`. Self-contained, fewest moving parts, fits the byte-identical multi-instance model.
- **Document same-pod sidecar (b) as the k8s-preferred pattern:** engine stays loopback-bound, gate
  passes trivially, the hardened proxy is the only exposed surface and the home for mTLS + revocation.
- **The bind guards do the right thing in a container already** — there is no container-specific
  security hole; the work is packaging + ops (cert mounting, secrets, signal handling, a Linux CI leg)
  plus the small residuals in §7.
- **Evaluation only.** If the owner says "go," the build (Dockerfile, compose/k8s manifests, the
  signal/healthcheck wiring, the §7 MLLP-key-password enhancement, the doc sweep) is a separate task.
