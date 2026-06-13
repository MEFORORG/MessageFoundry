# Service configuration & settings

> **Status: first cut implemented; the rest is the target.** The `ServiceSettings` model + loader
> ([config/settings.py](../messagefoundry/config/settings.py)) and the **CLI > env > file > default**
> precedence are built and wired into `serve`. Implemented sections: **`[store]`** (`backend`, `path`,
> `synchronous`), **`[api]`** (`host`, `port`), **`[inbound]`** (`bind_host`), **`[delivery]`**
> (`retry_*` + `ordering` — the default retry policy and queue ordering an outbound inherits when it
> declares none), **`[environments]`**
> (`dir`; active env = `[ai].environment`), **`[logging]`** (`level`), **`[auth]`** (authentication +
> RBAC), and **`[ai]`** (AI-assistance policy) — plus `--service-config`.
> **`[retention]`** is now enforced (retention/purge + SQLite maintenance), except its `audit_days`
> key, which is **reserved/keep-forever by design**. Other catalog entries
> (`[delivery].outbox_workers`/`dead_letter`, some server-DB `[store]` keys, structured `[logging]`)
> are **accepted-but-ignored** in a config file today so a forward-looking file still loads; build
> them incrementally.

## Principle — two kinds of configuration

MessageFoundry deliberately separates them:

1. **The message graph is code-first.** Connections / Routers / Handlers are authored as Python
   ([config/wiring.py](../messagefoundry/config/wiring.py)) and loaded from `--config`. This never
   becomes a settings file — no YAML, no declarative channel config.
2. **Service/operational settings are deployment config**, not code: where the store lives and its
   credentials, the API bind address, logging, retention, retry defaults, etc. These are what this
   document covers. They're set by whoever *operates* the service (ops/admin), not by the interface
   author, and must keep **secrets out of source control**.

## Mechanism (proposed)

A single **`messagefoundry.toml`** (TOML — consistent with `pyproject.toml`; **not** YAML, and not
channel config) with one section per group, plus **environment-variable overrides** for secrets, plus
**CLI flags** for the common knobs. Precedence (highest first):

```
CLI flag  >  environment variable  >  messagefoundry.toml  >  built-in default
```

- File location: `./messagefoundry.toml` by default, or `--service-config <path>`.
- **Secrets** (e.g. a DB password) should come from **env** (or a secret reference), never plaintext
  in the file — env wins over the file so a deployment can inject them.
- Env naming: `MEFOR_<SECTION>_<KEY>` (e.g. `MEFOR_STORE_PASSWORD`, `MEFOR_API_PORT`).
- Loaded once at startup into a typed `ServiceSettings` (pydantic) model; the engine + store read from
  it. `serve` keeps its existing flags as the CLI layer.

## Settings catalog

### `[store]` — message store / DB
The keys are **implemented in `StoreSettings`**; the SQLite backend is wired, and the SQL Server
backend that consumes the server-DB keys lands incrementally (the settings + validation exist now).
| Key | Type | Default | Notes |
|---|---|---|---|
| `backend` | enum | `sqlite` | `sqlite` · `sqlserver` · (later `postgres`/`mysql`/`oracle`) |
| `path` | str | `./messagefoundry.db` | SQLite only |
| `synchronous` | enum | `normal` | SQLite: `normal`/`full` |
| `encryption_key` | secret | — | **env only** (`MEFOR_STORE_ENCRYPTION_KEY`); base64 32-byte **active** key — when set, PHI columns (`raw`/`payload` + `error`/`last_error`/`detail`) are AES-256-GCM-encrypted at rest. Mint one with `messagefoundry gen-key`. Empty = off. See [PHI.md §3](PHI.md#3-encryption-at-rest). |
| `encryption_keys_retired` | secret | — | **env only** (`MEFOR_STORE_ENCRYPTION_KEYS_RETIRED`); comma-separated base64 **decrypt-only** keys kept available during a rotation until `messagefoundry rotate-key` finishes re-encrypting under the active key (ASVS 11.2.2). |
| `require_encryption` | bool | `false` | when `true`, `serve` **refuses to start** without an encryption key (any environment). Off by default; with it off, a `prod` environment still gets a loud startup warning. |
| `server`, `port` | str/int | — / 1433 | server DBs (required for `sqlserver`) |
| `database` | str | — | server DBs (required for `sqlserver`) |
| `auth` | enum | `sql` | `sql` · `integrated` · `entra` (SQL Server) |
| `username` | str | — | server DBs (required when `auth = sql`) |
| `password` | secret | — | **env only** (`MEFOR_STORE_PASSWORD`) |
| `encrypt`, `trust_server_certificate` | bool | `true`/`false` | TLS to the DB |
| `pool_size` | int | 5 | server DBs |
| `connect_timeout`, `command_timeout` | int (s) | 15 / 30 | server DBs |
| `db_schema`, `application_name` | str | — / `messagefoundry` | optional (`db_schema` ⇒ env `MEFOR_STORE_DB_SCHEMA`) |

> Selecting `backend = "sqlserver"` validates that `server`/`database` (and `username` when
> `auth = "sql"`) are present. The backend is **EXPERIMENTAL**: it needs the `sqlserver` extra
> (`pip install 'messagefoundry[sqlserver]'`) plus the Microsoft ODBC Driver 18, and is exercised
> against a real SQL Server only by the CI service-container job. `serve` warns when it's selected;
> SQLite remains the supported default.

### `[api]`
| Key | Type | Default | Notes |
|---|---|---|---|
| `host` | str | `127.0.0.1` | localhost by default. A **non-loopback** bind is **refused** unless `serve --allow-insecure-bind` is passed (Phase 1 has no API TLS, so bearer tokens + PHI would cross the network in cleartext — front it with TLS for real remote access). With `[auth] enabled = false` a non-loopback bind is refused **unconditionally** (the flag does not relax it). |
| `port` | int | 8765 | |
| `expose_docs` | bool | `false` | serve `/docs`, `/redoc`, `/openapi.json` (off by default — widens surface) |
| `config_reload_roots` | list[str] | `[]` | extra directories `POST /config/reload` may load from, besides the startup `--config` dir. The loader **executes Python** from these, so list only admin-owned, trusted roots (e.g. an IDE staging dir). Any reload path outside the startup dir + these roots is rejected (403). |
| `tls_cert_file`, `tls_key_file`, `tls_min_version`, … | — | off | **Phase 2 (designed, not built)** — in-process API/WS TLS via uvicorn `ssl_*`; encrypted-key password via env `MEFOR_API_TLS_KEY_PASSWORD`. Or terminate TLS upstream: `trusted_proxies` + `tls_terminated_upstream` (reverse-proxy path). Full design: [ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md); see [PHI.md](PHI.md#4-data-in-transit). |

### `[inbound]` — inbound listener defaults
| Key | Type | Default | Notes |
|---|---|---|---|
| `bind_host` | str | `127.0.0.1` | the network interface **every** inbound MLLP/TCP listener binds to. Authors never set a host on an inbound connection (a wiring error if they do) — it's a per-environment operator decision here. Binding `0.0.0.0` exposes unauthenticated MLLP to the network, so it's deliberate (DEV typically loopback, PROD a specific NIC behind a firewall). See [CONNECTIONS.md](CONNECTIONS.md). |

### `[environments]` — per-environment graph values (DEV/PROD)
The **same** code-first graph runs in every environment; only the values it references via
[`env("key")`](../messagefoundry/config/wiring.py) differ. The **active** environment is the single
cross-cutting selector **`[ai].environment`** (`dev`/`staging`/`prod`, or `serve --env <name>`); this
section only locates the value files.

| Key | Type | Default | Notes |
|---|---|---|---|
| `dir` | str | `environments` | directory (relative to the working dir) holding `<env>.toml` flat key→value tables for non-secret values, **versioned** in the repo. |

- A graph value that differs by environment is authored as `env("acme_adt_host")`; the running
  instance resolves it from `<dir>/<active-env>.toml` overlaid by **`MEFOR_VALUE_<KEY>`** env vars
  (secrets — never the file; env wins). Keys are `lower_snake_case`.
- A referenced key that is **undefined for the target environment** makes the engine refuse to load
  or promote that graph (fail loud) — never a silent blank host. See the env files under
  [`environments/`](../environments/) and `samples/config/IB_ACME_ADT.py` for a worked example.

### `[auth]` — authentication & RBAC
Implemented (see [SECURITY.md](SECURITY.md)). Authentication is **required** by default; the AD bind
password is a **secret** supplied via env (`MEFOR_AUTH_AD_BIND_PASSWORD`), never the file.
| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | required by default; off only for embedding/tests |
| `session_idle_timeout_minutes` | int | 30 | idle auto-logoff (inactivity window; background re-checks don't reset it) |
| `session_absolute_hours` | int | 12 | absolute session lifetime |
| `max_sessions_per_user` | int | 5 | cap concurrent sessions per user (ASVS 7.1.2; `0` = unlimited); a login beyond the cap revokes the user's oldest active session |
| `password_min_length` | int | 15 | local-password policy — ASVS 5.0-aligned, length-first |
| `password_require_uppercase`/`_lowercase`/`_digit`/`_symbol` | bool | `false` | character classes — **opt-in** (ASVS 5.0 forbids mandatory composition); on only for a legacy standard that still mandates them |
| `password_check_breached` | bool | `true` | reject known common/breached passwords against a bundled offline top-10k list (no live HIBP call) |
| `password_check_context` | bool | `true` | reject passwords containing app/vendor/HL7 terms (e.g. `messagefoundry`, `mefor`, `hl7`, `corepoint`) |
| `lockout_threshold` | int | 5 | failed logins before lock (per account) |
| `lockout_minutes` | int | 15 | lockout duration |
| `bootstrap_expiry_hours` | int | 72 | the first-run bootstrap admin is auto-disabled once a second administrator exists, and — while still unclaimed (never password-changed) — this many hours after creation. `0` = no time expiry |
| `login_rate_limit_enabled` | bool | `true` | in-process sliding-window limiter on `/auth/login`, `/auth/negotiate`, `/me/password` (in front of the per-account lockout) |
| `login_rate_limit_per_ip` | int | 10 | max attempts per client IP per window (`0` disables) |
| `login_rate_limit_global` | int | 60 | max attempts across all clients per window (`0` disables) |
| `login_rate_limit_window_seconds` | float | 60 | sliding-window length |
| `phi_read_rate_limit_enabled` | bool | `true` | per-actor anti-automation throttle on the PHI-read endpoints `/messages`, `/messages/{id}`, `/dead-letters` (ASVS 2.4.1) — bounds scripted PHI harvesting on top of pagination + access auditing |
| `phi_read_rate_limit_per_actor` | int | 120 | max PHI reads per user per window (generous — clears console/human use; `0` disables this dimension) |
| `phi_read_rate_limit_global` | int | 0 | max PHI reads across all users per window (`0` = off) |
| `phi_read_rate_limit_window_seconds` | float | 60 | sliding-window length |
| `ad_enabled` | bool | `false` | turn on Active Directory login |
| `ad_server` | str | — | e.g. `ldaps://dc1.example.com:636` (required when `ad_enabled`) |
| `ad_domain` | str | — | UPN suffix, e.g. `example.com` |
| `ad_user_search_base` | str | — | required when `ad_enabled` |
| `ad_group_search_base` | str | — | base for nested-group resolution |
| `ad_bind_dn` | str | — | service-account DN used for lookups |
| `ad_bind_password` | secret | — | **env only** (`MEFOR_AUTH_AD_BIND_PASSWORD`) |
| `ad_use_nested_groups` | bool | `true` | resolve nested groups (`LDAP_MATCHING_RULE_IN_CHAIN`) |
| `ad_tls_verify` | bool | `true` | validate the LDAPS certificate |
| `ad_tls_ca_cert_file` | str | — | trust an internal CA for LDAPS without disabling verification |
| `ad_allow_insecure_ldap` | bool | `false` | explicit opt-in to a non-`ldaps://` bind (trusted-network dev only) |
| `kerberos_enabled` | bool | `false` | Windows SSO (experimental; needs `ad_enabled`) |
| `kerberos_spn` | str | — | service principal, e.g. `HTTP/host.example.com` |

> AD-group→role mappings live in the DB and are managed by an admin (`PUT /ad-group-map` or the
> console Users page), not in this file.

### `[ai]` — AI coding assistance policy
Implemented (see [AI.md](AI.md)). Controls the IDE AI assistant across the **OFF→PHI-safe** range;
the policy is centrally governed and **environment-clamped**. `mode`/`data_scope`/`environment` are
the only keys that act in the MVP — the rest are forward-compat placeholders for the future engine
broker (accepted-but-ignored today).
| Key | Type | Default | Notes |
|---|---|---|---|
| `mode` | enum | `byo` | `off` · `byo` · `managed_claude` · `managed_claude_baa` (the last two are **future** — not serviceable by the current IDE) |
| `data_scope` | enum | `code_only` | `code_only` · `synthetic` · `deidentified` · `phi`, least→most sensitive; capped by `environment` and by `mode` (only `managed_claude_baa` reaches `phi`) |
| `environment` | enum | `prod` | `dev` · `staging` · `prod`; sets the `data_scope` ceiling (`dev`/`staging` ⇒ `synthetic`; `prod` ⇒ `phi` only under `managed_claude_baa`, else `code_only`). Unset resolves to the safest ceiling |
| `provider` | str | `claude` | **forward-compat, unused in MVP** (P1 broker) |
| `model` | str | `claude-opus-4-8` | **forward-compat, unused in MVP** |
| `baa_attested` | bool | `false` | **forward-compat, unused in MVP** |
| `endpoint` | str | — | **forward-compat, unused in MVP** |

> Only `code_only` context is ever sent in the MVP (graph names + active editor code) — **never
> message bodies**. The full resolution/clamping algorithm, the `GET /ai/policy` endpoint, the
> `messagefoundry ai-policy` CLI, and the `ai:assist` RBAC permission are documented in
> [AI.md](AI.md). Env keys: `MEFOR_AI_MODE`, `MEFOR_AI_DATA_SCOPE`, `MEFOR_AI_ENVIRONMENT`, etc.

### `[logging]`
| Key | Type | Default | Notes |
|---|---|---|---|
| `level` | enum | `info` | never run prod at `debug` (PHI) |
| `file`, `max_bytes`, `backups` | str/int | — | rotation (NSSM captures stdout today) |
| `format` | enum | `text` | `text`/`json` once structlog lands |
| `phi_redaction` | bool | `true` | **planned** (with structlog) — see [PHI.md](PHI.md#7-logging--phi-redaction) |

### `[retention]`
Enforced by the engine's retention/purge task ([pipeline/retention.py](../messagefoundry/pipeline/retention.py)).
A purge **NULLs the PHI *body*** past its window while **keeping the metadata row** (counts,
disposition, and the audit trail stay intact — the Mirth Data-Pruner pattern); it never deletes a
`messages` row and never touches a body still in flight. Everything defaults to `0`/`""` = keep/off,
so retention is opt-in.
| Key | Type | Default | Notes |
|---|---|---|---|
| `messages_days` | int | `0` | past N days, null inbound bodies (`raw`/`summary`/`error`) of **fully-resolved** messages (no `pending`/`inflight` delivery), keeping metadata. `0` = keep |
| `dead_letter_days` | int | `0` | past N days, null the bodies of **dead-lettered** outbound rows (their own window — a dead row stays replayable until purged). `0` = keep |
| `audit_days` | int | `0` | **reserved / not enforced.** The `audit_log` is a tamper-evident hash chain and HIPAA expects ~6-year retention, so audit is **keep-forever by design**; archive-first pruning is a tracked follow-up. Accepted so a forward-looking file still loads |
| `max_db_mb` | int | `0` | advisory only: warn (WARNING log + an `AlertSink` `storage_threshold` event) when the DB (+ `-wal`/`-shm`) exceeds this. Never auto-deletes. `0` = off |
| `purge_interval_seconds` | float | `3600` | how often the purge/maintenance loop runs a pass |
| `wal_checkpoint_seconds` | float | `0` | `PRAGMA wal_checkpoint(TRUNCATE)` cadence (SQLite). `0` = off (rely on auto-checkpoint). Evaluated once per pass, so a value below `purge_interval_seconds` is effectively rounded up to it |
| `vacuum_at` | str | `""` | daily local `"HH:MM"` to run `VACUUM` (SQLite; reclaims space freed by purges). `""` = off. A daily off-peak time, **not** a cron expression (no new dependency); VACUUM holds a write lock on the whole DB while it runs |

> **SQLite-only.** Retention/maintenance runs on the SQLite backend. On the experimental SQL Server
> backend it is a DBA concern (TDE + a SQL Agent purge/shrink job). Each pass that does real work
> writes one `retention_purge` `audit_log` entry (cutoffs + counts, **no** message content). Design:
> [PHI.md §8](PHI.md#8-retention--purge).

### `[delivery]`
| Key | Type | Default | Notes |
|---|---|---|---|
| `retry_max_attempts` | int | _unset_ | attempts before a delivery dead-letters. **Unset = retry forever** (the conservative default — a transient failure/`AE` NAK is never silently lost; under FIFO the head blocks its lane until it succeeds or is purged). Set a finite value to opt back into retry-then-dead-letter. A permanent `AR` reject fails fast regardless. |
| `retry_backoff_seconds`, `retry_backoff_multiplier`, `retry_max_backoff_seconds` | num | 5 / 2 / 300 | exponential backoff between attempts (per-outbound `retry=` overrides) |
| `ordering` | enum | `fifo` | default queue ordering per outbound: `fifo` (strict in-order, head-of-line on failure) or `unordered` (batch + rotate-past-failures). Per-outbound `ordering=` overrides. |
| `internal_error` | enum | `continue` | what a delivery worker does on an **internal/code error** (a non-`DeliveryError` exception from `send` — our bug, not the partner's): `continue` (dead-letter the row + advance) or `stop` (halt the connection's worker, preserve the message for replay, raise a `connection_stopped` alert). Per-outbound `internal_error=` overrides. Partner NAKs / transport failures are unaffected. |
| `buildup_max_depth` | int | _unset_ | raise a `queue_buildup` alert when an outbound lane's pending depth reaches this. Unset = depth dimension off (a healthy ceiling is throughput-specific, so there's no safe default). Per-outbound `buildup=BuildupThreshold(...)` overrides. |
| `buildup_max_oldest_seconds` | num | 300 | raise `queue_buildup` when the lane's **oldest** pending message has waited this long (a stuck/retry-forever head is the classic cause). On by default — a head stuck >5 min is a problem in any environment. Set to unset/`0`-disable via a per-outbound override. |
| `outbox_workers` | int | per-outbound | delivery concurrency (planned) |
| `dead_letter` | enum | `keep` | `keep`/`drop`-after-N (planned) |

### `[egress]`
Fail-closed **outbound destination allowlist** (WP-11c; ASVS 13.2.4/13.2.5/14.2.3) — bounds where the
engine may **send** PHI, so a fat-fingered or hostile destination can't exfiltrate it. Each list is
**opt-in**: empty = unrestricted (today's behavior); once a transport's list is set, an outbound of
that transport not on it is **refused at config load/reload** (a `WiringError` → 422 / refused reload),
checked against the resolved (`env()`-substituted) destination.

| Key | Type | Default | Notes |
|---|---|---|---|
| `allowed_mllp` | list | `[]` | allowed MLLP destinations; each entry is `host` (any port) or `host:port`. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_MLLP` |
| `allowed_file_dirs` | list | `[]` | allowed File output directories; a destination's directory must resolve at/under one of these |
| `allowed_http` | list | `[]` | allowed REST/SOAP (HTTP) destination hosts; each entry is `host` (any port) or `host:port` (ADR 0003). Via env: comma-separated `MEFOR_EGRESS_ALLOWED_HTTP` |
| `allowed_db` | list | `[]` | allowed DATABASE destination servers; each entry is `host` (any port) or `host:port` (ADR 0003). Via env: comma-separated `MEFOR_EGRESS_ALLOWED_DB` |

> The webhook/SMTP **alert** sinks carry no message bodies (no PHI) and keep their own host allowlists
> in `[alerts]` (`webhook_allowed_hosts` / `smtp_allowed_hosts`).

### `[alerts]`
Where the delivery pipeline's operational alerts (`connection_stopped`, `queue_buildup`) are
delivered. **Both transports are off by default** — with neither configured, events are logged at
`WARNING` (the `LoggingAlertSink`). A transport turns on when its essentials are present. Payloads
carry the connection name + queue shape only — **never a message body** (no PHI). Delivery is
best-effort and runs on a background task, so it never blocks or hangs a delivery lane.

| Key | Type | Default | Notes |
|---|---|---|---|
| `webhook_url` | str | _unset_ | enable the **webhook** transport: HTTP `POST` the event as JSON here (fronts Slack/Teams/PagerDuty/custom inbound webhooks). |
| `webhook_timeout` | num | 10 | seconds per POST |
| `webhook_allowed_hosts` | list | `[]` | egress allowlist for the webhook host (`[]` = any); SSRF defense (ASVS 15.3.2/1.3.6) |
| `email_smtp_host` | str | _unset_ | SMTP server; with `email_from` + `email_to` set, enables the **email** transport |
| `email_smtp_port` | int | 587 | SMTP port |
| `email_from` | str | _unset_ | sender address (required for email) |
| `email_to` | list | _unset_ | recipient(s) (required for email). Via env: comma-separated `MEFOR_ALERTS_EMAIL_TO` |
| `email_use_tls` | bool | `true` | issue STARTTLS before sending |
| `email_username` | str | _unset_ | SMTP login user (omit for unauthenticated relays) |
| `email_password` | str | _unset_ | **secret** — supply via `MEFOR_ALERTS_EMAIL_PASSWORD`, never the file |
| `email_timeout` | num | 30 | seconds per send |
| `smtp_allowed_hosts` | list | `[]` | egress allowlist for the SMTP host (`[]` = any); parity with `webhook_allowed_hosts` (WP-11c) |
| `realert_seconds` | num | 300 | suppress re-notifying the same (event, connection) more often than this (anti-spam for a flapping lane) |

> Routing these events to a richer destination, templating, and send-retry are future work; this is
> the first real notifier behind the `AlertSink` seam.

### `[engine]`
| Key | Type | Default | Notes |
|---|---|---|---|
| `shutdown_timeout_seconds` | int | 30 | graceful stop |
| `data_dir` | str | `.` | base for relative paths |

### `[service]` (NSSM / Windows)
Mostly lives in `scripts/service/` today: service name, auto-restart, stdout/stderr log paths.

### `[security]`
Authentication & RBAC are configured in **`[auth]`** above (see [SECURITY.md](SECURITY.md)).
`encryption_at_rest` — **future**. The planned approach (AES-GCM through the store's
`_encode`/`_decode` seam for SQLite, plus required volume encryption; SQL Server TDE on that backend)
is documented in [PHI.md](PHI.md#3-encryption-at-rest).

## Example

```toml
# messagefoundry.toml
[store]
backend = "sqlserver"
server = "sql01.hospital.local"
database = "MessageFoundry"
auth = "sql"
username = "mefor_service"
encrypt = true

[api]
host = "127.0.0.1"
port = 8765

[logging]
level = "info"

[retention]
messages_days = 30      # null inbound bodies after 30 days, keep metadata
dead_letter_days = 90   # null dead-letter bodies after 90 days
vacuum_at = "03:30"     # daily off-peak VACUUM to reclaim space
```
```bash
# secret via env (never in the file)
set MEFOR_STORE_PASSWORD=...
```

## Build order (incremental)

1. ✅ **Done** — `ServiceSettings` model + loader (file + env + CLI precedence); `[api]`/`[logging]`
   and `[store] backend=sqlite|path|synchronous` wired into `serve` (`--service-config` + the
   `--db`/`--host`/`--port`/`--log-level` overrides).
2. `[delivery]` defaults → feed the default `RetryPolicy`.
3. `[store]` server-DB keys land **with** the SQL Server backend.
4. ✅ **Done** — `[retention]` purge/maintenance job (body-null + WAL/VACUUM, audited; `audit_days`
   reserved). `[logging]` structlog + redaction still lands with the logging epic.

## Open decisions (to confirm)

- **TOML file + env + CLI** as above — or env-only / all-CLI? (TOML chosen for consistency with
  `pyproject.toml` and ops-friendliness; secrets via env.)
- Where settings are **edited from** — Console (operational) and/or a read-only view in the IDE.
- Whether per-connection overrides (e.g. a connection's own retry) stay in code (today) or also move
  into settings. Recommendation: **keep per-connection logic in code**, service settings are defaults.
