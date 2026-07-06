# Running the admin console on a remote PC

The PySide6 admin **console** is a separate process that reaches the engine **only** over its
localhost-or-network HTTP/WebSocket API ([`api/app.py`](../messagefoundry/api/app.py)) — it never
imports the engine or touches the store directly. So it can run on a different machine from the engine.

This is **supported but off by default**: out of the box both ends are bound to `127.0.0.1` (loopback
only), so nothing is exposed until an admin deliberately (1) binds the engine to a routable address,
(2) puts TLS in front of it, and (3) points the console at the `https://` URL. Auth is already required.

---

## 1. Engine side — bind off-loopback, with TLS

By default `[api].host = 127.0.0.1`. To accept remote connections, set it to a specific NIC address
or `0.0.0.0`, and configure TLS — an off-loopback bind without TLS is **refused at startup** (the
bearer token and PHI would cross the network in cleartext).

### Option A — in-process TLS (simplest for a single engine host)

The engine (uvicorn) terminates TLS itself and serves `https`/`wss`. Configure in `messagefoundry.toml`:

```toml
[api]
host = "0.0.0.0"                 # or a specific NIC, e.g. "10.0.0.12"
port = 8765
tls_cert_file = "C:/mefor/tls/engine-cert.pem"   # PEM cert (chain); PEM paths, not secrets
tls_key_file  = "C:/mefor/tls/engine-key.pem"    # may be omitted if the key is bundled in the cert PEM
# tls_min_version = "1.2"        # "1.2" (default) or "1.3"
# tls_key_password is a SECRET — supply via MEFOR_API_TLS_KEY_PASSWORD, never the file
```

Use a cert whose SAN matches the hostname/IP the console will dial. An internal/enterprise CA
(AD Certificate Services) or a public CA both work; a self-signed cert works too (see `--cacert` below).

### Option B — TLS terminated upstream (reverse proxy / load balancer)

A proxy (nginx, IIS/ARR, HAProxy, a k8s ingress) terminates TLS and forwards plaintext to the engine
on loopback. Tell the engine a terminator is in front so the off-loopback gate is satisfied and the
audit/rate-limit source IP is the real client:

```toml
[api]
host = "0.0.0.0"
tls_terminated_upstream = true
trusted_proxies = ["10.0.0.5"]   # the proxy's address(es) — REQUIRED; empty trusts nothing
```

### Authentication at exposure

Auth is on by default; remote users sign in with local accounts (± TOTP MFA) or AD/LDAP. Note:

- With `[auth].enabled = false`, an off-loopback bind is **hard-refused** (loopback is the only
  no-auth posture).
- On an exposed **production PHI** instance, `[auth].require_mfa = false` **refuses to start** — turn
  MFA on (it's a warning on non-production). See [`SECURITY.md`](SECURITY.md).
- Consider `[auth].admin_new_ip_step_up = true` to force a fresh step-up when an admin action arrives
  from a new client IP.

---

## 2. Console side — point it at the engine

```
python -m messagefoundry.console --url https://engine-host:8765
```

(or launch the windowed `messagefoundry-console` executable and it will use the same flags).

### Certificate trust — usually nothing to configure

The console verifies the engine's TLS certificate against the **operating-system trust store**
(via `truststore`). On a domain-joined Windows PC the enterprise/AD-CS root is already trusted by
Windows, and public-CA certs are trusted everywhere — so in the common case **no extra flag is needed**.

| Engine cert | What the console needs |
|---|---|
| Issued by your enterprise CA (AD CS), root already in the OS store | nothing — it just works |
| Issued by a public CA (Let's Encrypt, etc.) | nothing — public roots are in the OS store |
| **Self-signed**, or an internal CA **not** in this PC's OS store | `--cacert` (below) |

### `--cacert` — trust a self-signed or not-yet-trusted CA

Point `--cacert` at a PEM containing the engine's self-signed cert, or your internal CA bundle:

```
python -m messagefoundry.console --url https://engine-host:8765 --cacert C:/mefor/tls/engine-cert.pem
```

This pins trust to exactly that PEM. (Alternatively, install your internal CA into the PC's OS trust
store once and skip the flag entirely.)

### `--client-cert` / `--client-key` — mutual TLS (optional)

If the engine requires a client certificate (`[api].tls_client_ca_file` is set → `CERT_REQUIRED`),
present one so the console authenticates by certificate as well as the bearer token:

```
... --client-cert C:/mefor/tls/console.pem --client-key C:/mefor/tls/console-key.pem
```

(`--client-key` is optional when the key is bundled in the cert PEM.)

### `--insecure` is **not** a TLS-trust bypass

`--insecure` only permits plaintext `http://` to a non-loopback host on a trusted dev network — it does
**not** disable certificate verification for `https://`. To trust a self-signed `https` engine, use
`--cacert`, not `--insecure`.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `CERTIFICATE_VERIFY_FAILED` / "not trusted by the trust provider" | The engine cert isn't trusted by this PC. Use `--cacert <pem>`, or install the issuing CA into the OS trust store. |
| `refusing to use plaintext http to non-loopback host …` | You used an `http://` URL to a remote host. Use `https://` (configure engine TLS), or `--insecure` only for a trusted dev network. |
| Engine won't start: `refusing to serve … on non-loopback host` | An off-loopback `[api].host` without TLS. Configure `tls_cert_file` (Option A) or `tls_terminated_upstream` + `trusted_proxies` (Option B). |
| Hostname mismatch on connect | The engine cert's SAN doesn't include the host/IP in `--url`. Reissue the cert with the right SAN. |

The console reads over HTTP polling (no WebSocket client), so "live" views refresh at the poll
interval (`--poll`, default 2s) — the same as a local console, just over the network.

See also: [`SECURITY.md`](SECURITY.md) (auth/TLS posture), [`CONFIGURATION.md`](CONFIGURATION.md)
(the full `[api]` settings), [`SERVICE.md`](SERVICE.md) (running the engine as a service).
