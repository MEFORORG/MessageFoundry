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
- **Per-face logic inside a transform:** `env()` is a *deferred reference* resolved only when a
  **connection** spec is built — using it in a handler is an always-truthy object (a bug). To branch a
  Router/Handler on the deployment, read the active environment **name** with
  [`current_environment()`](../messagefoundry/config/active_environment.py) (`"dev"`/`"staging"`/
  `"prod"`, or `None` in a dry-run):
  ```python
  from messagefoundry import current_environment
  # Corepoint: If ActiveFace="Test" Then MSH-11.1 = "T"
  if current_environment() in ("staging", "dev"):
      msg.set("MSH-11.1", "T")
  ```
  The active environment is a deployment constant, so the read is pure + re-run-safe.

### Code sets — reference lookup tables (`codesets/`)
A code-first Router/Handler often needs a **reference table** — an Epic diet code → a food-service
system value, a facility code → a downstream mnemonic. Rather than a hand-maintained Python dict, drop the table in a
**code set** and look it up with [`code_set("name")`](../messagefoundry/config/code_sets.py).

- **Where.** Files live in `codesets/` **relative to the `--config` dir** — a config bundle carries
  its own reference tables and they **reload with the graph** (POST `/config/reload`). This is distinct
  from `environments/` (cwd-level endpoint values for `env()`). A missing `codesets/` dir is fine
  (no code sets). The code-set **name** is the file's stem (`codesets/epic_diets.csv` → `"epic_diets"`).
- **CSV** (`<name>.csv`) — a header row; the **first column is the lookup key**. One other column →
  the value is that scalar (`str`); several other columns → the value is a `dict` `{header: cell}`. A
  duplicate key is a **load error** (fail loud).
- **TOML** (`<name>.toml`) — a flat table `key = value` → `{key: scalar}`; a nested `[key]` table →
  `{key: {…}}` (mirrors the `environments/<env>.toml` shape).
- **Usage.** Capture once at a module's top level (preferred) or look it up at call time inside a
  handler — both resolve:
  ```python
  from messagefoundry import code_set, handler, Send

  DIET = code_set("epic_diets")          # frozen, read-only mapping; captured at import

  @handler("to_cbord")
  def handle(msg):
      msg["ODS-3"] = DIET.get(msg["ODS-3"], "")     # .get(key, default) — blank on a miss
      fac = code_set("facility_mnemonics").get(msg["MSH-4"])  # call-time lookup also works
      ...
      return Send("OB_CBORD_DIET", msg)
  ```
  A `CodeSet` is a read-only `Mapping`: `cs[key]` (raises `KeyError` naming the set on a miss),
  `cs.get(key, default)`, `key in cs`, `len(cs)`, iteration. It is **frozen** — one instance is shared
  across transforms, so a handler must never mutate the reference data.
- **Fail loud.** `code_set("missing")` (no such file) or a malformed/duplicate-key CSV/TOML raises a
  `WiringError`, surfaced by `validate` / `messagefoundry check` / reload exactly like a missing
  `env()` value — never a silent empty table.
- **Purity caveat.** The lookup is pure (key in → value out), so it's compatible with the staged
  pipeline's **pure-re-run** invariant ([ADR 0001](adr/0001-staged-pipeline-architecture.md) /
  CLAUDE.md §2). The one caveat: a hot-reload that **changes** a table between a run and a
  crash-re-run can make the re-run derive a different output. That's acceptable for reference data (a
  code set is deliberately operator-editable, and a reload is an explicit, audited act), but it is the
  one way a transform's re-run can legitimately differ — note it where you document the transform.

### Transform state — cross-message correlation ([ADR 0005](adr/0005-transform-accessible-state.md))

Where code sets are **read-only** reference data, **transform state** is **read/write** correlation
data a Handler accumulates across messages: an anonymous-patient mapping (persist a real MRN → a stable
anonymized id and reuse it on later messages), order↔result correlation, running aggregates. It is
authored against two surfaces from `messagefoundry`:

```python
from messagefoundry import handler, Send, SetState, state_get

@handler("anonymize")
def anonymize(msg):
    mrn = msg["PID-3.1"]
    anon = state_get("patient_anon", mrn)          # synchronous read; None on a miss
    ops = []
    if anon is None:
        anon = derive_anon_id(mrn)                  # deterministic derivation preferred (see below)
        ops.append(SetState("patient_anon", mrn, anon))
    msg["PID-3.1"] = anon
    return [Send("OB_DOWNSTREAM", msg), *ops]       # Sends and SetStates, mixed in one list
```

- **Write contract — declared, never imperative.** A Handler returns
  `Send | SetState | list[Send | SetState] | None`; it does **not** mutate state directly. Each
  `SetState(namespace, key, value)` (the `value` must be JSON-serializable — validated at construction)
  is an **upsert by `(namespace, key)`** the engine applies **inside the routed→outbound handoff
  transaction**. `Send`-only Handlers are unchanged — fully **backward compatible**.
- **Exactly-once / re-run safety.** Because the write commits in the **same transaction** as the
  outbound rows, a crash before commit leaves **no** state (atomic with the handoff) and the attempt
  that commits applies the write **exactly once per message** — this preserves the staged pipeline's
  **pure-re-run** invariant ([ADR 0001](adr/0001-staged-pipeline-architecture.md) / CLAUDE.md §2). A
  non-deterministic value (a random anon id) is still safe because only the committed attempt persists,
  but **prefer a deterministic derivation** where cross-run identity matters.
- **Read — synchronous, read-through cache.** Handlers are pure synchronous functions and a DB read is
  async, so `state_get(namespace, key, default=None)` reads an in-memory **read-through cache** the
  engine maintains (loaded at startup, updated as writes commit) and publishes around each
  router/transform run — exactly how `code_set()` resolves against an active set. A missing key returns
  `default` (state is sparse, not a referenced table). **Non-linearization caveat:** a read reflects
  committed state as of its invocation, but is **not** linearized with a concurrent sibling handler's
  write — fine for read-mostly correlation; a race-sensitive read-modify-write within one namespace
  needs author care.
- **Encryption at rest.** State values may carry PHI (MRN↔id), so they are AES-256-GCM-encrypted with
  the store cipher just like `messages.raw`, and covered by key rotation (`messagefoundry rotate-key`).
- **Retention (TTL).** Set `[retention].state_max_age_days` to age out stale entries (a global age
  purge; per-namespace policy is a follow-up). Off by default = keep forever. The whole-table cache
  assumes **bounded** state — unbounded estates (every MRN ever seen) are a documented follow-up
  ([ADR 0005](adr/0005-transform-accessible-state.md)).
- **SQL Server.** State writes ride the staged `transform_handoff`, which is SQLite-only today, so the
  `state` table on the experimental SQL Server backend is **inert** (parity schema only) until its
  staged pipeline lands.

`state_get` also resolves in **dry-run** / the IDE Test Bench / `messagefoundry check`: each simulated
message gets a fresh in-memory view that accumulates that run's own declared writes (so a later handler
sees an earlier one's `SetState`), and `dryrun` output lists the declared state ops — **PHI-gated**
behind `--show-phi` like a message body.

### Reference sets — external-data enrichment ([ADR 0006](adr/0006-external-data-lookups.md))

Where a **code set** is a static lookup table shipped in the bundle and **transform state** is
read/write correlation, a **reference set** is **external data materialized off the message path**: a
provider directory, a DB-backed translation table (the Corepoint Data Point / DB Association pattern).
The engine syncs the source into a **versioned, encrypted store snapshot** on a cadence; a Handler
reads it **purely** at run time. Because the read carries no external call, the staged pipeline's
pure-re-run invariant holds (the only non-determinism is a snapshot flip landing between a run and a
crash-re-run — the same accepted caveat as a code-set hot-reload).

- **Declare** a set in a wiring module (registers it into the graph, like `inbound`):
  ```python
  from messagefoundry import Reference, FileRef, env, handler, Send, reference

  Reference("provider_npi", source=FileRef(path=env("provider_npi_csv")), refresh_seconds=3600)

  @handler("enrich")
  def enrich(msg):
      npi = reference("provider_npi").get(msg["PV1-7.1"])   # pure dict lookup, no I/O
      if npi:
          msg.set("PV1-7.13", npi)
      return Send("OB_DOWNSTREAM", msg)
  ```
- **`reference(name)`** returns a frozen, read-only `ReferenceSet` (`rs[k]` / `rs.get(k, d)` / `k in rs`).
  A missing **key** returns the default (external data is sparse); a missing/unsynced **set** raises
  (fail loud) at run time → that message's `ERROR` disposition. Call it **inside a Handler/Router**, not
  at module top level (the snapshot exists only once the store is open + synced — unlike `code_set`).
- **Sources:** `FileRef(path=…, encoding=…)` — a local CSV/TOML in the **code-set format**, re-read on
  the refresh cadence (the path for an externally-produced export; `path` may be `env()`).
  `DatabaseRef(server=…, database=…, statement=…, key_column=…, value_column=…)` — the engine runs a
  read-only SQL query on the cadence (SQL Server via the `[sqlserver]` extra, **experimental**; secrets
  via `env()`; the dial-out is gated by the fail-closed `[egress].allowed_db` allowlist). `key_column`
  is the lookup key; `value_column` (if set) is the value, else the value is a dict of the other columns.
- **Sync.** The engine's `ReferenceSyncRunner` materializes each set once at startup (before listeners
  serve, so `reference(...)` resolves on the first message) and every `refresh_seconds`. A source
  failure is **isolated**: it's logged + alerted and the **last-good snapshot is kept** (the write
  isn't attempted), so one bad source never blocks the others or the message path.
- **At rest:** snapshot values are AES-GCM-encrypted (they may carry PHI) and covered by key rotation,
  exactly like `state`/message bodies; the `[egress].allowed_db` gate will govern the (increment-2) DB
  source. **SQLite-only** (the SQL Server store has an inert stub).
- **`[reference]` settings:** `refresh_interval_seconds` (loop tick, default 3600), `sync_on_startup`
  (default true), `max_staleness_seconds` (reserved, 0 = off).
- **Dry-run / `check`** resolve file-backed sets best-effort (literal paths) so a reference-using
  transform validates; DB-backed or `env()`-path sets are absent in a pure dry-run.

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
| `kerberos_enabled` | bool | `false` | Windows SSO (experimental, **0.2 target — not supported in v0.1**; needs `ad_enabled`) |
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
| `state_max_age_days` | int | `0` | past N days, **delete** transform-state entries (ADR 0005) last written before the cutoff — keeps the in-memory state cache + table bounded. A simple global age purge (by `set_at`); per-namespace policy is a follow-up. `0` = keep |
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
| `allowed_tcp` | list | `[]` | allowed raw-TCP (`Tcp(...)`) destinations; each entry is `host` (any port) or `host:port`. An inbound `Tcp(...)` is a local listener and is not gated. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_TCP` |
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

### `[cluster]` — horizontal scale-out coordination (Track B)
**Experimental / Postgres-only.** Introduces the multi-node coordination seam — a `nodes` table, a
per-node heartbeat, (Track B Step 4) **leader election**, (Step 5) **per-lane FIFO ownership**, and
(Step 6) **cross-node reference + config-reload convergence** — *without changing single-node behavior*.
With `enabled = false` (the default) the engine uses a no-op coordinator and runs **byte-identically**
to before. Enabling it requires `[store].backend = "postgres"` (SQLite is single-node; SQL Server is
experimental) **and** `[store].pool_size >= 2` — the leader holds **one dedicated pooled connection**
for the lifetime of its leadership advisory lock, so a pool of 1 would starve the store. A
cross-section validator refuses either violation at config load.

With `[cluster].enabled` on Postgres, **leader election is built**: exactly one node across the cluster
holds a session-level Postgres advisory lock and is the **leader**. The leader-only **WRITE singletons**
run on that one node while followers **no-op** them (reactive-by-polling, so failover is automatic on
the next tick):
- **`[retention]` purge/VACUUM/audit** — runs on the leader only.
- **the lease-reclaim sweep** — the leader periodically calls `reclaim_expired_leases` (cadence
  `reclaim_interval_seconds`) to recover **crashed** nodes' in-flight rows (only rows whose lease has
  *expired*, never a live sibling's). In clustered mode the engine therefore **skips** the
  single-node unconditional `reset_stale_inflight` startup recovery, which would steal a live
  sibling's in-flight rows.

**Poll-source intake is leader-gated (Track B Step 4b).** A **poll** source — `file` (a watched
directory), `database` (a polled table), `remote-file` (an SFTP/FTP directory) — reads a **shared
external resource**: if more than one node polled it, the same file/row would be ingested twice. So
only the **leader** polls a poll source; a follower's poll loop keeps ticking but **skips** the
scan/select (it neither reads nor moves files / marks rows), and resumes on the tick after it becomes
leader (reactive-by-polling, no restart). **Listen** sources — `mllp`, `tcp` — are **not** gated: each
node binds its own endpoint (distribute inbound connections with a load balancer or per-node ports),
so they run on every node, as do all the **staged-queue workers** (router / transform / delivery),
which share the queue via `FOR UPDATE SKIP LOCKED` + row leases. The brief overlap during a leadership
transition (the old leader's last in-flight poll vs. the new leader's first) is bounded by the same
at-least-once guarantees that cover a crash mid-poll — the file-rename / row-claim atomicity and the
downstream queue's idempotent handoff make a re-read a tolerated duplicate, never data loss. The
worst-case transition window scales with `heartbeat_seconds`: a leader whose lock connection silently
drops keeps polling until its next maintenance tick detects the drop and demotes (up to one
`heartbeat_seconds`), so keep `heartbeat_seconds` modest if duplicate-intake cost is high. For a
`database` source the row-claim atomicity is the operator's `poll_statement`/`mark_statement` (claim
with a status flag or `UPDATE ... RETURNING`); the engine owns the atomic rename only for file sources.

If the leader stops or its connection drops, its advisory lock is released and a follower acquires
leadership on its next heartbeat tick. **Single-node operation is unchanged** (the no-op coordinator
is always leader, so every poll source always scans, runs the unconditional startup reset, and spawns
no leader sweep).

**Per-lane FIFO ownership preserves order across nodes (Track B Step 5).** The staged-queue workers
(router / transform / delivery) run on **every** node, so without coordination two nodes draining the
**same** FIFO lane would interleave it: node A's `FOR UPDATE SKIP LOCKED` locks the head (row 1) and
node B's `SKIP LOCKED` skips the locked head and claims row 2 — so row 2 could deliver before row 1.
To prevent that, a FIFO lane is **owned by exactly one node at a time** via a `lane_leases` table, and
ownership is enforced **atomically at claim time**: each FIFO claim, in one transaction, first
acquires-or-renews the lane lease (`INSERT ... ON CONFLICT ... WHERE owner = me OR lease expired`) and
only then claims the head — so only the lane's owner ever claims its rows, head-of-line blocking is
restored, and strict per-lane FIFO holds across nodes with a **zero reorder window** (the claim itself
is the authority, not a cached gate). An idle lane's lease simply expires and the next node with work
for it re-acquires it (one node at a time). **Crash mid-delivery stays ordered, too**: a node that dies
holding the head leaves it `inflight` under an expired row lease, so the next node taking over the lane
reclaims that lane's expired-lease inflight rows back to pending **in the same claim transaction, before
the head select** — the stranded head is recovered and blocks the lane rather than being skipped, so a
later row can never deliver ahead of it (the recovery does not wait on the leader's periodic sweep). The
wall-clock lease shares the row-lease NTP assumption:
keep `[store].lease_ttl_seconds` comfortably above clock skew + the claim cadence. **UNORDERED**
lanes are intentionally **not** lane-owned — concurrent draining across nodes is fine there.
**Single-node is byte-identical**: the no-op coordinator's lane owner is `None`, so the claim takes its
unchanged no-owner path (no `lane_leases` touch). SQLite and SQL Server (single-node) accept and ignore
the owner.

**Cross-node convergence is built (Track B Step 6).** Two shared-state concerns now converge across
nodes automatically:
- **Reference sets** — materialize-from-source is **leader-gated** (only the leader re-reads the
  external file/DB source and writes the shared, versioned snapshot), and **every** node then
  **read-throughs** that snapshot into its own in-process read cache via the store's
  `converge_reference_cache` (matching on the per-set version). So the external source is read **once**
  per cluster and no follower is left on a stale cache — replacing the prior "every node re-syncs" model.
  Single-node is byte-identical: the no-op coordinator is always leader (materializes every pass) and
  the convergence call is a no-op on SQLite (the sole writer's cache is always current).
- **Config reload** — an operator `POST /config/reload` on **one** node bumps a single-row
  `cluster_config` **version token**; every **other** node's config-convergence loop observes the higher
  version and reloads **its own** (identically-deployed) config dir to converge. The initiating node
  advances its applied version when it bumps, so it does **not** re-reload (no feedback loop). A
  `dry_run` never bumps; single-node never spawns the loop. This assumes **homogeneous config** across
  nodes (the token coordinates *when* to reload; each node reloads its own dir) — the same assumption as
  the dead-letter-missing-destinations/handlers startup sweeps.

> Still **experimental**: the remaining gap is **transform-STATE cross-node read-through (Step 6b)** — a
> transform's write-state is still per-node — and the absence of a **cluster ops API (Step 7)**. Leader
> election, leader-gated singletons + poll-source intake, per-lane FIFO order across nodes, and
> cross-node reference + config convergence are all built (a one-time startup `WARNING` summarizes the
> state), so order- and shared-state-sensitive flows are now safe under multi-node — but treat
> `[cluster].enabled` as experimental until transform-state convergence and the ops API land.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | turn on the coordination seam; requires `[store].backend = "postgres"` and `[store].pool_size >= 2` |
| `node_id` | str | _unset_ | override the auto id (`host:pid:hex`); pin for a stable identity / tests. Unset → reuses the store's lease owner-id, so node-id == owner-id |
| `heartbeat_seconds` | num | 10 | how often a node refreshes its `last_seen` heartbeat **and** maintains its leader lock (no separate leader-check knob). Must be > 0 |
| `node_timeout_seconds` | num | 30 | a node is considered dead when its `last_seen` is older than this (election diagnostics / future stale-member sweep). The advisory lock — not this timeout — is what transfers leadership today. Must be > 0, and must exceed `heartbeat_seconds` |
| `reclaim_interval_seconds` | num | 30 | how often the **leader** runs the lease-reclaim sweep that recovers crashed nodes' in-flight rows (followers no-op). Must be > 0 |

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
