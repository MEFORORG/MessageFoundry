<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# Containerizing the MessageFoundry engine

The **headless engine** runs cleanly as an OCI container (ADR 0017 "container fast-follow"). This
directory holds the image, a Topology-A `compose.yaml`, minimal Kubernetes manifests, and a CI smoke.

The PySide6 **console is never in the image** — it is a host-side GUI client that reaches the engine
over the HTTP API. Only the headless engine (asyncio/uvicorn/SQLite, no GUI dependency) containerizes.

Read [`docs/CONTAINER-EXPOSURE-EVALUATION.md`](../docs/CONTAINER-EXPOSURE-EVALUATION.md) first — it
establishes that the off-loopback security controls are already built; this is packaging + ops wiring.

## Image variants

| Image | Build | Use |
|---|---|---|
| **slim (default)** | `docker build -f docker/Dockerfile -t messagefoundry .` | Core engine + SQLite store. The default for most adopters. |
| **`-sqlserver`** | `docker build -f docker/Dockerfile --target runtime-sqlserver -t messagefoundry:sqlserver .` | Adds the OS-level Microsoft ODBC Driver 18 + `[sqlserver]` extra — needed **only** for the SQL Server store or the DATABASE / `db_lookup` connectors. |

Both are multi-stage, run as **non-root uid 10001**, install from per-profile **hash-locked**
requirements (`docker/locks/*.lock`, kept in sync with `uv.lock` by the DEP-1 step in
`.github/workflows/security.yml`), and are based on `python:3.11-slim-bookworm`. The slim default omits
PySide6, dev tools, and ODBC; the SQL Server layer (a Microsoft-EULA apt repo) is only in the variant.

## Configuration — bake it in (recommended) or mount it carefully

The engine **executes your config `*.py` as its service account**, so `_assert_safe_config_source`
refuses a config dir that is **group/world-writable** *or* **owned by a different uid** than the engine
(uid 10001). Two ways to satisfy it:

**1. Bake config into a derived image (recommended; immutable, matches ADR 0017).**
```dockerfile
FROM messagefoundry:<version>
COPY --chown=10001:10001 config /config
```
Deploy that image. This is the only clean path on Kubernetes — a ConfigMap/projected volume mounts
**root-owned**, which the guard rejects.

**2. Mount config read-only (Docker single-host).** The mount must be owned by uid 10001 and not
group/world-writable:
```sh
chown -R 10001:10001 ./config && chmod -R go-w ./config
docker run ... -v "$PWD/config:/config:ro" ...
```
A **Docker-Desktop-on-Windows** bind mount surfaces as `0o777` and **will be refused** — bake instead.

`env()` value files resolve under `/config/environments/<env>.toml` (the image sets
`MEFOR_ENVIRONMENTS_BASE_DIR=/config`), so mount/bake your whole config repo at `/config`.

## Run

- **Docker single host:** [`compose.yaml`](compose.yaml) — Topology A (in-process TLS). Copy
  `secrets.env.example` → `secrets.env`, drop a cert/key under `./tls`, point `./config` at your repo.
- **Kubernetes:** [`k8s/statefulset.yaml`](k8s/statefulset.yaml) + [`k8s/secret.example.yaml`](k8s/secret.example.yaml)
  — in-process TLS, a PVC for the store, secrets via `secretKeyRef`. Set `image:` to your config-baked image.

## Exposure topologies (see the evaluation §1)

- **(A) In-process TLS — default shipped posture.** Engine binds `0.0.0.0:8443` with `tls_cert_file`/
  `tls_key_file`; MLLP runs `tls=True`. Self-contained, fewest moving parts.
- **(B) Reverse-proxy / same-pod sidecar — k8s-preferred.** Engine stays loopback (or behind a trusted
  terminator with `tls_terminated_upstream=true` + `trusted_proxies=[…]`); the sidecar does TLS + mTLS +
  OCSP-must-staple revocation. The engine bound to `127.0.0.1` never trips the exposure gate.

Reaching the engine through a published port requires binding **off-loopback inside the container**
(Docker NAT forwards to the container interface, not its loopback). The startup bind guard then requires
TLS (A) or a declared upstream terminator (B), or it **refuses to start** — by design.

## Volumes & secrets

- **Store (PHI at rest):** a **named volume / PVC**, never the ephemeral layer — the at-least-once
  invariant only holds if the store survives a restart. Mount the writable **directory** holding
  `messagefoundry.db` (WAL writes `-wal`/`-shm` siblings beside it). The image defaults
  `MEFOR_STORE_PATH=/var/lib/mefor/messagefoundry.db`. Set `MEFOR_STORE_ENCRYPTION_KEY` (base64 32 bytes,
  `messagefoundry gen-key`) and `MEFOR_STORE_REQUIRE_ENCRYPTION=true` so a PHI instance fails closed
  without a key.
- **Secrets** (`MEFOR_STORE_ENCRYPTION_KEY`, `MEFOR_API_TLS_KEY_PASSWORD`, `MEFOR_STORE_PASSWORD`, …):
  the engine reads these from **env vars**. On k8s inject via `secretKeyRef` (clean). On Docker use
  `env_file` (gitignored) — note plain env is visible in `docker inspect`; prefer a secrets manager for
  production.
- **TLS cert/key:** mount **read-only**; never bake into an image layer. The API key may be
  passphrase-encrypted (`MEFOR_API_TLS_KEY_PASSWORD`).

## Healthcheck, signals, rotation

- **Healthcheck:** `GET /health` is tokenless and always 200 — a **liveness** signal (it answers before
  the engine finishes starting; there is no unauthenticated readiness endpoint). The image probe uses
  `curl -k https://127.0.0.1:8443/health` (the container presents its own, often self-signed, cert on
  loopback, so `-k`/`--cacert` is **mandatory**) then falls back to `http://127.0.0.1:8765/health`.
- **Graceful shutdown:** PID 1 is `tini`, which forwards `SIGTERM` → uvicorn lifespan → `engine.stop()`
  (drains MLLP clients within the `_CLIENT_SHUTDOWN_GRACE` bound). Give the orchestrator a stop grace of
  **≥30s** (`stop_grace_period` / `terminationGracePeriodSeconds`) to cover the ordered teardown — the
  budget grows with the graph (≈10s graph-quiesce + ~5s per MLLP listener + store-close margin, drained
  serially), so raise it for many-listener graphs. A fully graceful shutdown exits **0**; **143**
  (128+SIGTERM) is also fine; **137** means it was SIGKILLed (grace exceeded = ungraceful).
- **Cert rotation:** the **API** TLS context is built once at startup, so an API-cert renewal needs a
  **container restart** (rolling restart across instances). **MLLP** certs reload on `POST /config/reload`.

## Residuals / gotchas

- **MLLP-over-TLS is effectively mandatory.** A non-loopback MLLP listener without `tls=True` is refused
  at wiring time. Set `tls=True` + cert/key on each `MLLP()`. The MLLP key must be **unencrypted** unless
  the connection sets **`tls_key_password`** (env-sourced — added with this work, parity with the API key).
- **Do not publish raw-TCP / X12 ports without TLS.** Those two listeners have **no** startup transport
  guard — a non-loopback bind would carry plaintext PHI with no startup error. Keep them loopback-bound or
  front them with a TLS-terminating TCP proxy. (MLLP **and** the DICOM C-STORE SCP *are* guarded —
  `check_mllp_tls_exposure` / `check_dimse_tls_exposure` refuse a non-loopback bind without `tls=True`.)
- **`require_mfa=true` for production + local accounts.** A production-PHI off-loopback bind with local
  accounts and `require_mfa=false` is **refused at startup** (AD-only shops delegate MFA). Set it true.
- **Never bake `MEFOR_ALLOW_INSECURE_TLS`** — it disables outbound/peer TLS verification across **all**
  transports (store incl. Postgres/SQL Server, MLLP-outbound, REST/SOAP/FHIR/SMART/DATABASE, SFTP host-key,
  LDAP, alert webhooks). It is a CI-only switch for self-signed test containers.
- **Cert-expiry monitor skips `env()`-referenced cert paths.** Use literal paths for any cert you want the
  built-in expiry alert to watch (the `[api]` cert is always literal and covered).
- **In-engine TLS revocation is delegated** (ADR 0002). For enforced revocation use Topology B with an
  OCSP-must-staple terminator.

## CI

The `docker-smoke` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) builds the slim image
and a baked test image ([`smoke/`](smoke/)), serves it loopback + auth-off, sends one synthetic ADT^A01
over MLLP, asserts it finalizes to **PROCESSED** (not merely RECEIVED), and verifies a graceful
`docker stop`. It is the engine's first non-Windows runtime gate.
