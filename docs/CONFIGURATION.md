# Service configuration & settings

> **Status: the catalog is built.** The `ServiceSettings` model + loader
> ([config/settings.py](../messagefoundry/config/settings.py)) and the **CLI > env > file > default**
> precedence are built and wired into `serve`, along with `--service-config`. Every bracketed `[section]`
> catalogued below is a real, validated section on the `ServiceSettings` model — **`[store]`** (SQLite
> **and** the server-DB keys), **`[api]`**, **`[inbound]`**, **`[delivery]`** (the retry policy, queue
> ordering and alert thresholds an outbound inherits when it declares none), **`[environments]`** (`dir`;
> active env = `[ai].environment`), **`[logging]`**, **`[auth]`**, **`[ai]`**, **`[retention]`** (enforced
> by the retention/purge + SQLite-maintenance pass), and the rest. **`[engine]` is not one of them**: it
> has no model, so it is refused at load like any other unknown section ([`[engine]`](#engine)). The four sections that used to be built-but-uncatalogued now have their own entries:
> **`[tls]`** (client trust anchors, [ADR 0093](adr/0093-pinned-internal-ca-trust-anchor.md)),
> **`[reference]`**, **`[backup]`** ([ADR 0049](adr/0049-turnkey-dr-backup-restore-verify.md)) and
> **`[dr]`** ([ADR 0048](adr/0048-third-tier-disaster-recovery-standby.md)).
>
> **An unrecognized KEY in `messagefoundry.toml` is REFUSED at load** — a key its section does not
> define fails the start, naming the section, the key and the nearest real field name. It used to be
> accepted silently, which left the setting it was meant to apply un-applied with nothing anywhere
> reporting a problem. **An unknown top-level SECTION, or a key written above the first `[section]`
> header, is refused the same way**, naming it and, when one fits, the section it was probably meant
> for. So is a top-level section written as anything but one table (`[[integrity]]`). A misspelt section
> used to drop every key under it at once: `[integrty]` with `fail_closed_on_drift = true` loaded clean
> and left the tripwire alert-only. So a file that adds a section from newer docs no longer loads on an
> engine that does not model it. The refusal never repeats the offending value, because this file can
> carry secrets.
>
> **The refusal covers the FILE, and the CLI refuses an unknown flag too. Env mostly does not — check
> `MEFOR_*` spellings yourself.** An unknown `serve` flag stops the command: argparse prints
> `unrecognized arguments` and exits 2. Its default prefix matching still applies, so an unambiguous
> prefix of a real flag (`--service-conf`) is read as that flag. A misspelled `MEFOR_*` variable is
> dropped with no warning, whether the typo is in its section part or its key part. Some env input is
> refused anyway: at least an unrecognized `[security]` key and the renamed `[logging]` keys, both
> described below. The env layer is where
> secrets belong, and it already drops a var aimed at one of the four sections that have no env layer
> ([Mechanism](#mechanism)). The loader also cannot tell such a typo from one of the documented
> `MEFOR_*` variables its consuming module reads straight from the environment rather than declaring as
> a field (`MEFOR_STORE_VAULT_ADDR`, `MEFOR_TLS_REVOCATION_ATTESTED` and siblings). **One exception:**
> an unrecognized `[security]` posture switch is refused from **env as well as the file**, because every
> shipped `MEFOR_SECURITY_*` name maps to a real field, so there is no out-of-band variable to collide
> with — and believing a posture control is on when it is not is the worst case of the class.
>
> A handful of keys are **declared but not yet read** — they load, they just do nothing yet:
> `[retention].audit_days` (**reserved/keep-forever by design**), `[reference].max_staleness_seconds`,
> `[ai].baa_attested`, and `[update_check].index_url`/`index_allowed_hosts`. The former
> "accepted-but-ignored" keys that were never fields at all — `[delivery].outbox_workers`/`dead_letter`
> and `[logging].max_bytes`/`backups` — now **refuse**. **`[logging].file` is no longer one of them:**
> #122 / ADR 0162 made it a real, engine-owned field, and the two legacy spellings beside it refuse.
> **They refuse on BOTH layers, and only one of those is the general rule.** In the file they hit the
> unknown-key refusal above (`max_bytes` is even suggested onward as `file_max_bytes`; `backups` is
> refused naming nothing). From **env** — where a misspelled `MEFOR_*` is otherwise dropped in
> silence — they hit a dedicated `[logging]` validator that names the replacement for both.

## Principle — two kinds of configuration

MessageFoundry deliberately separates them:

1. **The message graph's logic is code-first.** Routers and Handlers are authored as Python
   ([config/wiring.py](../messagefoundry/config/wiring.py)) and loaded from `--config`. Connections are
   Python by default too. A Connection's transport config (its type and settings, an inbound's
   router binding, and delivery knobs) may instead live in an optional `connections.toml` in the same
   directory ([ADR 0007](adr/0007-gui-manageable-connections-toml.md)). Not every transport can be
   declared there: an unsupported one is refused at load, and the error lists those it accepts. The loader builds each entry
   through the same transport factories into the same registry entries `inbound()`/`outbound()`
   produce, so the file is a flat list of endpoints, not a channel. None of this is a service setting —
   no YAML, no declarative channel config.
2. **Service/operational settings are deployment config**, not code: where the store lives and its
   credentials, the API bind address, logging, retention, retry defaults, etc. These are what this
   document covers. They're set by whoever *operates* the service (ops/admin), not by the interface
   author, and must keep **secrets out of source control**.

## Mechanism

A single **`messagefoundry.toml`** (TOML — consistent with `pyproject.toml`; **not** YAML, and not
channel config) with one section per group, plus **environment-variable overrides** for secrets, plus
**CLI flags** for the common knobs. Precedence (highest first):

```
CLI flag  >  environment variable  >  messagefoundry.toml  >  built-in default
```

- File location: `./messagefoundry.toml` by default, or `--service-config <path>`.
- **Secrets** (e.g. a DB password) should come from **env** (or a secret reference), never plaintext
  in the file — env wins over the file so a deployment can inject them.
- Env naming: `MEFOR_<SECTION>_<KEY>` (e.g. `MEFOR_STORE_PASSWORD`, `MEFOR_API_PORT`). The parser splits
  the name at the **first** `_` after the prefix and matches that against a known-section list, so four
  built sections have **no env layer** and a `MEFOR_*` var aimed at one is dropped without a warning:
  `[service]`, and the underscored `[cert_monitor]`, `[secret_rotation]`, `[update_check]`. The reasons
  differ. `[service]` would work if the known-section list named it, but it just isn't listed. The other
  three fail a different way: that same first-underscore split turns `MEFOR_CERT_MONITOR_ENABLED` into
  section `cert`, not `cert_monitor`, so no list entry can rescue it. Set those four in the file.
- Loaded once at startup into a typed `ServiceSettings` (pydantic) model; the engine + store read from
  it. `serve` keeps its existing flags as the CLI layer.

## Settings catalog

### `[store]` — message store / DB
The keys are **implemented in `StoreSettings`**. **All three backends are built and selectable:**
SQLite is the zero-dependency default; **Postgres** and **SQL Server** are production server-DB
backends behind their extras. What each one supports is the
[capability matrix](#per-backend-capability-matrix) below — read it before assuming a feature is
backend-limited.
| Key | Type | Default | Notes |
|---|---|---|---|
| `backend` | enum | `sqlite` | `sqlite` · `postgres` · `sqlserver` · (later `mysql`/`oracle`) — all three implemented; see the [capability matrix](#per-backend-capability-matrix) |
| `path` | str | `./messagefoundry.db` | SQLite only |
| `synchronous` | enum | `normal` | SQLite: `normal`/`full` |
| `group_commit_window_ms` | float (ms) | `0.0` | **SQLite only** ([ADR 0055](adr/0055-group-commit-durable-write.md)). When `> 0` a dedicated committer coroutine **coalesces** the grouped stage-handoff mutations (`enqueue_ingress`, `route_handoff`, `transform_handoff`, `mark_done`, `complete_with_response`, `dead_letter_now`, `mark_failed`) into **one** durable commit, amortizing the per-commit fsync (a large win under `synchronous = full`, muted under the default `normal`). A member waits up to this window for siblings to join before the batch commits; the claim / reference-snapshot / audit writes stay **standalone** (never grouped — the hash chain must not batch). `0` (the default) = **off**, byte-identical to the inline-commit path. Ignored by the server-DB backends, which coalesce through their connection pool instead. |
| `group_commit_max_batch` | int | `64` | **SQLite only.** Flush threshold for the group-commit committer: once this many members are enrolled in the open batch it commits immediately rather than waiting out the rest of `group_commit_window_ms`, bounding batch size + latency under load. Ignored when group-commit is off (`group_commit_window_ms = 0`). |
| `fifo_claim_batch` | int | `1` | all backends (ADR 0058). Max rows the **INGRESS/ROUTED** FIFO claim takes per commit. `1` = **OFF** (the workers claim one row per commit — byte-identical to before). `> 1` (clamped `1..64`) claims the **contiguous due head-prefix** in one commit and then processes each row in strict FIFO order with its own off-loop route/transform + separate handoff, amortizing the standalone claim commit toward 1/N. A not-due or producer-locked head still blocks the lane (strict per-lane FIFO, #285). The **outbound/delivery** claim is never batched. Opt-in throughput tuning (recommend `8`–`16`); size against worst-case message size, since N decrypted bodies are resident per lane between the claim and the N handoffs. |
| `fifo_claim_fold_reset` | bool | `false` | **SQL Server only** ([ADR 0114](adr/0114-phase-4-claim-path-call-complexity-reduction-driver-interface-redesign-ingress-routed-reset-fold.md) sub-lever C). Folds the pooled claim's session `LOCK_TIMEOUT` reset into the claim batch on the **clean success path at INGRESS/ROUTED** (the write-less commit#2 disappears; the shielded finally-guard still runs on every non-clean exit — 1222, kept≠claimed, cancellation, any error). OUTBOUND/RESPONSE are never folded. `false` = **byte-identical** shipped batch + guard. Flip only after its own ADR 0114 §8 bench gate (AC-14). |
| `fifo_claim_proc` | bool | `false` | **SQL Server only** (ADR 0114 sub-lever A). Executes the pooled claim via the two lane-family versioned procs `dbo.mefor_claim_fifo_heads_cid_v2` / `_dst_v2` (fixed-arity `{CALL}`, one JSON lanes parameter) instead of the ~3 KB ad-hoc batch. Needs database `COMPATIBILITY_LEVEL >= 130` (SQL Server 2016); **fails safe to the batch, loudly**, whenever the startup gate cannot verify both deployed bodies against this build — at least: a missing proc, a body matching no form this build deploys (hand edit, hand deploy, or a body changed without bumping the proc version), a definition this principal cannot read (no `VIEW DEFINITION`, or `WITH ENCRYPTION`), or compat < 130 — never a lane outage. A hardened split-principal deployment must `GRANT EXECUTE` on both called procs to the runtime principal (again for each new proc version) (the bootstrap principal owns them), and `GRANT VIEW DEFINITION` so the gate can read the bodies it verifies. `false` = byte-identical. Flip only after its own §8 gate (AC-14). |
| `fifo_claim_prepared` | bool | `false` | **SQL Server only** (ADR 0114 sub-lever B). Stabilizes the pooled claim's statement text (one JSON lanes parameter) and retains a prepared claim cursor on store-owned dedicated connections (INGRESS/ROUTED; the non-DDL fallback lane to `fifo_claim_proc`). **Logs + no-ops unless `fifo_claim_fold_reset` is on** (without the fold the finally-guard's reset would evict the one-slot prepare cache every call). `false` = byte-identical. Flip only after its own §8 gate (AC-14). |
| `encryption_key` | secret | — | **env only** (`MEFOR_STORE_ENCRYPTION_KEY`); base64 32-byte **active** key — when set, PHI columns (`raw`/`payload` + `error`/`last_error`/`detail`) are AES-256-GCM-encrypted at rest. Mint one with `messagefoundry gen-key`. Empty = off. See [PHI.md §3](PHI.md#3-encryption-at-rest). |
| `encryption_keys_retired` | secret | — | **env only** (`MEFOR_STORE_ENCRYPTION_KEYS_RETIRED`); comma-separated base64 **decrypt-only** keys kept available during a rotation until `messagefoundry rotate-key` finishes re-encrypting under the active key (ASVS 11.2.2). Keep them through the engine's first start after the rotation as well. That start re-keys the secret-rotation fingerprints, and needs the old key to spot a secret changed in the same window (BACKLOG #2242; [PHI.md §3](PHI.md#3-encryption-at-rest)). |
| `encryption_key_file` | path | — | Windows **DPAPI-protected** key file (WP-11d, ASVS 13.3.1) — a path produced by `messagefoundry protect-key`. When `encryption_key` is unset and this is set, the active key is `CryptUnprotectData`'d from this file at store open, so the plaintext key never sits in the service environment. Windows-only, and the **env key takes precedence** when both are present. A **path, not a secret** — it may live in the file. Unset = use `encryption_key` (the cross-platform default). `protect-key` creates the file restricted and refuses to replace an existing one. When the provider reads this file, `serve` first checks that no broad account can read it, and refuses to start under `[security].enforcement = "enforce"` if one can ([PHI.md](PHI.md), "Key files"). |
| `aad_bind` | bool | `true` | **not a secret** (`MEFOR_STORE_AAD_BIND`); cell binding (ASVS 11.3.3, [ADR 0019](adr/0019-pluggable-keyprovider-hsm-kms-vault.md)). New at-rest AES-256-GCM writes use the cell-bound writer, `mfenc:v4` (`mfenc:v2` before [ADR 0196](adr/0196-a-fresh-or-rewound-store-must-not-restart-a-store-key-s-aes-gcm-invocation-count.md), which seals each store under its own HKDF data sub-key) — each value is bound to its `(table, column, row)` cell via GCM Associated Data, so a ciphertext cut-and-pasted into another cell **fails the auth tag** (dead-lettered `CipherError`) instead of silently decrypting. **On by default** (ADR 0148 GIVEN 1: the shipped configuration runs the hardened path). Setting it `false` selects the frozen `mfenc:v1` writer (byte-identical at rest) and is a **loosening** — `security_loosenings()` names it, so the opt-out is never silent. No effect without an `encryption_key` (the identity cipher has nothing to bind). Legacy `v1` rows still decrypt (dual-read); `messagefoundry rotate-key` upgrades them `v1` to `v4`, so the default is safe and reversible on an existing store. |
| `allow_unmarked_ciphertext` | bool | `false` | **not a secret** (`MEFOR_STORE_ALLOW_UNMARKED_CIPHERTEXT`); refuse unmarked values (ASVS 11.3.3, BACKLOG #1169). On a keyed store, a non-blank value with no `mfenc:` marker in an encrypted column is **refused** (`CipherError`, plus an `integrity_drift` alert with subject `store-cipher` naming only the table and column) instead of being read back as plaintext: it is a stripped marker or a planted row. A purged `''` is never refused. The keyed open seals legacy plaintext only on a `(table, column)` that holds no ciphertext yet, one transaction per column. Setting it `true` restores the old behaviour (plaintext passthrough, and the open seals every unmarked value) and is a **loosening** — `security_loosenings()` names it. No effect without an `encryption_key`. **It covers the uploaded-file store too** (owner ruling 2026-09-23): on a keyed store a plaintext upload under `uploads_dir` is refused on read until `messagefoundry rotate-key` seals it, alerting under its own subject `upload-cipher`, and `serve` logs the count of such uploads at startup. Setting this `true` restores the upload passthrough as well. Under `cipher_provider = "vault_transit"` uploads keep the passthrough either way; [PHI.md](PHI.md) §3 says why. |
| `key_provider` | enum | `auto` | selects **how** the active/retired DEK bytes are *sourced* — never how they are used (the cipher, keyring, and `mfenc:v1` format are unchanged; ADR 0019, ASVS 13.3.3). `auto` (default) is the env-then-DPAPI ladder, **byte-identical** to the pre-seam behavior; `env` pins `MEFOR_STORE_ENCRYPTION_KEY` and `dpapi` pins `encryption_key_file`, and each ignores the other source. A key set only in the source the pinned provider ignores is **refused, not used as keyless** (BACKLOG #2077): `serve`, `supervise` and `provision-admin` refuse before opening, whatever the audited opt-out says, and `open_store` refuses for every other command. Set `auto` or the source the provider reads. Under `cipher_provider = "vault_transit"` the gate still counts any local key, because the store never resolves `key_provider` there; DR backups and `rotate-key` do, and refuse the ignored key. `vault` **is built** ([store/keyprovider_vault.py](../messagefoundry/store/keyprovider_vault.py)): it envelope-decrypts a wrapped DEK through HashiCorp Vault **Transit** and needs the optional `[vault]` extra. Its wiring comes from the environment. `MEFOR_STORE_VAULT_TRANSIT_KEY` (the KEK name; not the next row's `MEFOR_STORE_TRANSIT_KEY`) and `MEFOR_STORE_VAULT_WRAPPED_DEK` are required. `MEFOR_STORE_VAULT_ADDR`, `MEFOR_STORE_VAULT_TOKEN` and `MEFOR_STORE_VAULT_CA_FILE` are optional, and an unset address or token is **not refused**: hvac falls back to its own `VAULT_ADDR`/`VAULT_TOKEN` handling and built-in defaults, so set both. The unwrap runs wherever the key is resolved, at least at every store open and every DR backup pass. It reads the KEK's metadata to check its type before decrypting, so the token needs both. A missing required variable or extra, a KEK of an unsuitable type, or a failed unwrap **fails closed**: the store does not open, or that backup pass fails. Only the **active** key comes from Vault; retired keys still come from `encryption_keys_retired`, in plaintext. The unwrapped DEK feeds the in-process cipher, so unlike `cipher_provider = "vault_transit"` it does enter engine heap. **The keyless-PHI gate counts it as a key** (BACKLOG #1998). `_store_key_configured` in [`__main__.py`](../messagefoundry/__main__.py) treats every external provider as a configured key without resolving it, because the gate runs before the store opens and must not need the network. So a PHI instance set to `vault` with no local key passes the gate, and a provider that cannot resolve fails closed when the store opens. Under `cipher_provider = "vault_transit"` the store never resolves `key_provider`; DR backups and `rotate-key` still do, and fail closed there. `aws_kms`·`azure_kv`·`gcp_kms`·`pkcs11` are **not built yet**; selecting one **fails closed** the same way, never a silent downgrade. Names a *provider*, not key material, so it is **not** a secret. |
| `cipher_provider` | enum | `aesgcm` | selects the at-rest **cipher itself** — distinct from `key_provider`, which only *sources* DEK bytes for the in-process cipher ([ADR 0138](adr/0138-transit-bulk-crypto-provider-dek-out-of-engine-heap-for-asvs-13-3-3-demand-gated.md), ASVS 13.3.3). `aesgcm` (the default) is that in-process AES-256-GCM cipher, byte-identical to today. `vault_transit` performs the bulk encrypt/decrypt **inside** Vault/OpenBao Transit, so the plaintext DEK never enters engine heap; at-rest values then carry the `mfenc:v3:` marker, the local `encryption_key`/`key_provider` go unused (Transit holds the key), and the audit chain is keyed by Transit's `generate_hmac` — computed inside the vault, so no HMAC key enters heap either. Threaded through **all three** backends. Vault address / token / data-key name come from `MEFOR_STORE_VAULT_ADDR`, `MEFOR_STORE_VAULT_TOKEN` and `MEFOR_STORE_TRANSIT_KEY` (optionally `MEFOR_STORE_TRANSIT_AUDIT_KEY`). Names a *provider*, not key material, so it is **not** a secret. Any other value **fails closed** at `open_store` — never a silent downgrade to plaintext. **Needs the optional `[vault]` extra** (`pip install 'messagefoundry[vault]'` — hvac); lazy-imported, so a base install pulls no Vault SDK and an absent extra fails closed at `open_store` rather than degrading. **Two preconditions before you plan a deployment on this — read both.** (1) *The keyless-PHI serve gate does not treat this setting as a key.* [`__main__.py`](../messagefoundry/__main__.py)'s gate tests `encryption_key` / `encryption_key_file` and an external `key_provider` (previous row). It consults `cipher_provider` only to count a local key that a pinned `key_provider` ignores (BACKLOG #2077). All three built-in environment names derive PHI, so a PHI instance configured for `vault_transit` **with no local key and no external `key_provider` still refuses to start (exit 2)** and points you at `messagefoundry gen-key`. Forcing past it with `[security].allow_unencrypted_phi` (+ `…_under_strict_enforcement`) makes `security_loosenings()` and `GET /security/posture` publish the instance as *PHI stored UNENCRYPTED at rest* while it is in fact encrypted inside Transit — a false read-out, not a real posture. Until the gate learns `cipher_provider`, **also configure a local `encryption_key`**, with a `key_provider` that reads it (`auto` or `env`): the Transit cipher never reads it, but it satisfies the gate, and it remains the key `.mfbak` DR archives actually use (`resolve_active_key` never consults `cipher_provider`, so Transit does **not** cover backups). (2) *Greenfield stores only.* The Transit cipher **fails closed** (`CipherError`) on any pre-existing `mfenc:v1`/`v2` value, and `rotate-key` both refuses to run without an active *local* key and would itself have to decrypt those values through the Transit cipher — so there is **no in-place migration** off an already-encrypted store today. Flipping this on a populated store makes its historical PHI unreadable. |
| `require_encryption` | bool | `false` | when `true`, `serve` **refuses to start** without an encryption key in **any** environment, even a synthetic one. Off by default. |
| `allow_unencrypted_phi` | | | **→ moved to `[security].allow_unencrypted_phi`** (ADR 0118) — set it there; no longer accepted in `[store]`. |
| `server`, `port` | str/int | — / 1433 | server DBs (required for `sqlserver`) |
| `database` | str | — | server DBs (required for `sqlserver`) |
| `auth` | enum | `sql` | `sql` · `integrated` · `entra` (SQL Server). `integrated` connects `Trusted_Connection=yes` — the **service account's** Windows identity authenticates (no SQL password); the turnkey **gMSA** walkthrough (grant the gMSA a SQL login + run the service under it) is [`DEPLOY-SERVER-DB.md` §1.1](DEPLOY-SERVER-DB.md). |
| `username` | str | — | server DBs (required when `auth = sql`) |
| `password` | secret | — | **env only** (`MEFOR_STORE_PASSWORD`) |
| `require_managed_identity` | bool | `false` | delegated-identity precondition (#203, ASVS 13.2.1/13.3.2): when `true`, `serve` **refuses to start (exit 2)** unless the store authenticates via a managed identity — SQL Server `auth = integrated`/`entra`. SQLite is exempt; Postgres cannot satisfy it. Off by default. **The refuse/warn split is `[security].enforcement`, not the production tier** — the gate reads `enforcing` ([`__main__.py`](../messagefoundry/__main__.py), the `managed_identity_precondition` block), and `enforce` is the shipped default on `dev` and `staging` as much as on `prod`, so a staging box that turns this on and leaves `auth = "sql"` is **refused**, not warned. It downgrades to a warning only under `enforcement = warn`. **It covers the STORE hop and nothing else** — the check is a `StoreSettings` method, so the graph's own `Database` / `DatabasePoll` / `DatabaseLookup` / `DatabaseRef` hops are outside its reach by construction and each defaults to a static SQL login; `messagefoundry check`'s advisory `static-credentials` line names that set, and the opt-in `[security].require_nonstatic_credentials` refuses it (BACKLOG #1182, [`CONNECTIONS.md`](CONNECTIONS.md) §*Static database credentials*) |
| `require_least_privilege` | bool | `false` | least-**privilege** precondition on the store principal (#1008, ASVS 13.2.2) — the privilege sibling of `require_managed_identity` above, which constrains the credential's *kind* and never what it may do (a `sysadmin` gMSA satisfies that one clean; never grant one — [`DEPLOY-SERVER-DB.md` §1.1](DEPLOY-SERVER-DB.md)). **The probe itself is NOT gated by this setting:** it runs at every start regardless, logs what it observed, writes a `store_privilege_preflight` audit row, and reports any excess grant in `security_loosenings()` / `GET /security/posture`. **With it left `false`, an OBSERVED over-grant already refuses** under `[security].enforcement = enforce` ([ADR 0199](adr/0199-an-over-granted-store-login-refuses-start-under-enforce-with-an-audited-opt-out.md), owner ruling 2026-09-27), unless `[security].allow_over_granted_store_principal = true` accepts it (audited); an **unobservable** probe only warns. Setting this flag `true` is the stricter declaration: `serve` also refuses when **the probe could not run at all**, since a declared refusal that passed an unobservable principal would be the fail-open shape it exists to prevent, and it outranks the opt-out, so with both set an over-grant still refuses. Refuse/warn splits on `[security].enforcement` exactly like `require_managed_identity`: under `warn` every arm here only warns. SQLite is exempt (a local file has no server principal). |
| `schema_management` | enum | `external` on `sqlserver`/`postgres`; always `auto` on `sqlite` | who runs the store's schema DDL (BACKLOG #305, ASVS 13.2.2). **`external`** (the server-DB default): `serve` runs **no** DDL. It reads the `schema_meta` marker and **refuses to start** when it does not match this build, naming the fix: a DBA runs `messagefoundry store provision-schema` as a DDL-capable principal before the first start and before the first start of any upgrade whose schema moved. The runtime login then needs row access only, and the startup privilege probe counts `db_ddladmin` (SQL Server) or `CREATE` on the store schema (Postgres) as excess. **`auto`**: the engine builds and upgrades its own schema at open, so its runtime login needs standing DDL rights; on a server DB this is reported by `security_loosenings()` as `schema_management`. An explicit `external` on `sqlite` is refused at load. [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) §2 |
| `encrypt`, `trust_server_certificate` | bool | `true`/`false` | TLS to the DB |
| `ssl_root_cert` | path | — | server DBs — pin the DB server's certificate by **file** so a private/self-signed DB CA verifies **without** a machine-wide trust import, on the **secure** posture only (`encrypt = true`, `trust_server_certificate = false`) — it never disables verification. **Postgres:** an asyncpg `SSLContext` CA-bundle (chain + hostname still checked). **SQL Server:** the ODBC Driver **18.1+** `ServerCertificate` keyword (a leaf/exact-cert match; needs driver ≥ 18.1). Rejected for SQLite (no TLS); a missing file fails loud at load. A path, not a secret — may live in the file. See [`DEPLOY-SERVER-DB.md` §5](DEPLOY-SERVER-DB.md). |
| `ssl_crl_file` | path | — | **Postgres only** — a PEM file of CRLs checked against the **DB server's** certificate (BACKLOG #299). The store builds its own context and resolves no trust anchor, so `[tls].crl_file` never reaches it; this is its own knob rather than a silent inheritance. It loads on **both verifying branches**: with `ssl_root_cert` (the pinned CA) and without it (the system trust store). The engine builds the `SSLContext` asyncpg uses on both, so both narrow to the approved suites and both can carry a CRL (BACKLOG #300; before that, the default path handed asyncpg `ssl=True` and this setting required `ssl_root_cert`). It is also what crosses the #201 revocation refusal on a production-PHI remote store hop: a blanket `MEFOR_TLS_REVOCATION_ATTESTED` no longer suffices there ([`DEPLOYMENT.md` §Revocation-guard behavior](DEPLOYMENT.md#revocation-guard-behavior)). Setting it on SQL Server or SQLite, or on a hop that verifies nothing (`encrypt = false` or `trust_server_certificate = true`), is **refused at load** rather than silently ignored — it could not be checked on any of them. A missing path is refused at load; one that is unloadable or past `nextUpdate` is refused at store open, not at the first DB handshake. So is one carrying a certificate the store did not already hold (BACKLOG #1890), so give it a bare CRL. The engine re-reads the file for every new pool connection, so a refreshed CRL applies to each new connection. Connections already open keep the CRL they were made with until the pool replaces them, so restart the engine to apply a revocation at once. If the file goes missing or expires while the engine runs, the next new connection fails with an error naming this setting. Refresh it by writing a new file and renaming it into place: a connection opened while the file is half-written fails. |
| `multi_subnet_failover` | bool | `false` | **SQL Server only** — emit the ODBC `MultiSubnetFailover=Yes` keyword so a client connecting to an Always On Availability Group **listener** reaches the current primary promptly across subnets, instead of serially waiting out each replica subnet's DNS/TCP timeout on failover. A no-op for Postgres/SQLite (they never see the ODBC string). Off by default — only a multi-subnet AOAG needs it. |
| `pool_size` | int | 40 | server DBs — **server-DB only** (no-op on SQLite). The inverted-U optimum (raised from 5; do **not** set higher — over-provisioning is catastrophic, [ADR 0062](adr/0062-default-store-pool-size.md)). **Per engine:** `engines × pool_size` share one `max_connections` — see [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) §3 |
| `connect_timeout`, `command_timeout` | int (s) | 15 / 30 | server DBs — the **login** and **statement** bounds respectively; neither bounds the wait for a free pooled connection (that is `acquire_timeout`) |
| `acquire_timeout` | num (s) | 30 | server DBs — upper bound on **one pooled-connection borrow**, and on the throwaway pool a `DatabaseRef` reference sync opens. Must be `> 0`; there is no "0 disables" value. At the limit the borrow raises `StoreAcquireTimeout`, an ordinary `Exception` the stage worker handles like any other transient store failure (the row stays claimable, the handoff re-runs idempotently) — and a connection the pool hands over after the borrower gave up is released back rather than stranded. 30 s sits far above a healthy wait; read p95/p99 from the `pool_status()` acquire-wait histogram before lowering it. No-op on SQLite. **The two backends reach this differently** — read the scope note in [`CONNECTIONS.md`](CONNECTIONS.md) ("Behaviour at the store-pool acquire limit") rather than assuming it is uniform. |
| `warm_pool` | bool | `true` | server DBs — pre-open pooled connections in the background on graph start/promotion so a connection burst (the post-promotion delivery workers, or a cold start) finds them warm instead of paying cold connects (TCP+TLS+login). Best-effort, self-releasing, **no-op on SQLite**. On by default (it touches no commit/correctness seam); set `false` to opt out on a connection-constrained/licensed site. |
| `warm_pool_timeout` | num (s) | 15 | server DBs — upper bound on the background warm-up; on expiry it logs and continues with a partially warm pool. Must be `> 0`. A **clustered** server-DB node also rejects an **explicit** value `>= [cluster].leader_fence_timeout_seconds` (a warm should finish within the leadership term that started it); the default (15 < the 20 fence) never trips this. |
| `warm_pool_target` | int | — | server DBs — how many connections to pre-open. Unset (default) = a safe fraction of the pool (`min(pool_size-1, pool_size//2)`), so the warm never pins more than half the pool; an explicit value is clamped to `pool_size-1`. A pool of 1 is never warmed. At the default `pool_size = 40` this is `min(39, 20) = 20` pre-opened per server-DB engine at startup. |
| `db_schema` | str | — | **Postgres only** (env `MEFOR_STORE_DB_SCHEMA`). Postgres points the pool's `search_path` at it, so each schema gets its own tables and its own cluster election. **Refused at load on `sqlserver` and `sqlite`**, because neither store reads it. The SQL Server store resolves every table against the login's default schema, so two installs on one SQL Server database share all their tables whatever this says. Give each SQL Server install its own database. |
| `application_name` | str | `messagefoundry` | optional |
| `lease_ttl_seconds` | num (s) | 60 | server DBs — the **in-flight row-lease TTL**. A worker that claims a row stamps owner + `lease_expires_at = now + this`; a renew timer extends it while processing, and the `[cluster]` leader's reclaim sweep recovers only rows whose lease has **expired**, so a crashed node's work comes back without stealing a live sibling's in-flight rows. The lease is **wall-clock across nodes**, so set it comfortably above expected clock skew + the renew interval. A shared server-DB field: SQL Server and SQLite don't lease and ignore it. |
| `uploads_dir` | path | — | **Off unless set.** Enables the opt-in **uploaded-logs** surface (POST `/uploads` + the `/ui/uploaded-logs/upload` delegate, [ADR 0134](adr/0134-offline-uploaded-logs-viewer-connection-decoupled-upload-browse-resend-deletion-phi-at-rest-posture-stdlib-multipart.md)); a filesystem dir for operator-uploaded diagnostic logs. A storage **path**, not a secret. Unset = no PHI-at-rest upload surface exists. See [CONNECTIONS.md §"Uploaded-logs file policy"](CONNECTIONS.md#uploaded-logs-file-policy-asvs-511). |
| `max_upload_bytes` | int (bytes) | `26214400` (25 MiB) | Hard cap on a single uploaded file (`ge=1`, `le=512 MiB`). Bounds the multipart upload buffer and the offline whole-file split; the global 1 MiB HTTP body cap is raised to this value **only** on the two upload routes. |
| `max_upload_files_per_user` | int | `100` | Max number of uploaded diagnostic files one uploader may retain at once (ASVS 5.2.4, `ge=1`). A would-be 101st upload is refused **HTTP 409** (`upload.reject_quota`). **Default-on** once `uploads_dir` is set — the control cannot ship disabled. |
| `max_upload_total_bytes_per_user` | int (bytes) | `262144000` (250 MiB) | Max aggregate bytes of uploaded files one uploader may retain (ASVS 5.2.4, `ge=1`). An upload pushing the uploader's total over the cap is refused **HTTP 409**. Default-on. |
| `uploads_retention_days` | int (days) | `30` | Age after which an uploaded file (blob+meta pair) is pruned (ASVS 5.2.4, `ge=1`) — swept opportunistically at save time and by a periodic task; every prune audited (`upload.prune`, id + uploader only). Default-on. |

> Selecting `backend = "sqlserver"` validates that `server`/`database` (and `username` when
> `auth = "sql"`) are present. The backend is **production** (full staged pipeline, response capture,
> at-rest encryption): it needs the `sqlserver` extra (`pip install 'messagefoundry[sqlserver]'`) plus
> the Microsoft ODBC Driver 18, and is exercised against a real SQL Server by the CI service-container
> job. SQLite remains the zero-dependency default.

#### Per-backend capability matrix

Each row is a `supports_*` capability flag on the `QueueStore` protocol
([`store/base.py`](../messagefoundry/store/base.py)); each cell is the value the backend's store class
actually declares. The engine reads these flags to **fail closed at startup** — an unsupported feature is
refused before any message is accepted, never a silent degrade and never a post-ACK surprise.

| Capability flag | SQLite | Postgres | SQL Server |
|---|---|---|---|
| `supports_ingest_stage` | yes | yes | yes |
| `supports_response_capture` | yes | yes | yes |
| `supports_pt_reingress` | yes | yes | yes |
| `supports_streaming_attachments` | yes | yes | yes |
| `supports_fused_sync_handoff` | no | no | **yes** |
| `supports_reference_sets` | yes | yes | yes |

**Request/response capture ([ADR 0013](adr/0013-query-response-orchestration.md)), PT/`Loopback()`
re-ingress, and [ADR 0006](adr/0006-external-data-lookups.md) reference sets work on ALL THREE
backends** — including SQL Server, which has shipped `capture_response` + `reingress_to` at full parity
since #249 and the reference-snapshot store since [BACKLOG #235](BACKLOG.md) (2026-07-16, CI-proven
against real SQL Server 2022 + 2025). Do not read a backend limitation into any of those rows. (The
reference-set gate itself stays: a graph declaring a `Reference(...)` on a *future* backend that leaves
the allow-list default `False` is still refused at `messagefoundry check`, at engine start, and on
reload/promote.)

The one row that *does* vary:

- **`supports_fused_sync_handoff` — SQL Server only.** The fused synchronous handoff twins
  ([ADR 0071](adr/0071-cut-executor-round-trips-b5.md) B5) collapse a multi-statement handoff into one executor
  completion. The profiled wall is aioodbc's per-statement thread crossing, which only SQL Server pays:
  asyncpg is loop-native and SQLite's handoff lock is loop-affine, so neither has anything to fuse. SQL
  Server is the *most* capable backend here.

> **This table is pinned by `tests/test_store_capability_matrix.py`,** which parses it and asserts every
> cell against the live store-class attributes. Flip a flag or add a new one and you must update this
> table **in the same commit**, or the test fails. That is deliberate: the stale "backend X doesn't
> support Y" prose this table replaced once sent a team off to build a feature that already existed.

### `[api]`
| Key | Type | Default | Notes |
|---|---|---|---|
| `host` | | | **→ moved to `[security].local_access_only` / `listen_address`** (ADR 0118) — set it there; no longer accepted in `[api]`. |
| `port` | int | 8765 | |
| `expose_docs` | bool | `false` | serve `/docs`, `/redoc`, `/openapi.json` (off by default — widens surface) |
| `config_reload_roots` | list[str] | `[]` | extra directories `POST /config/reload` may load from, besides the startup `--config` dir. The loader **executes Python** from these, so list only admin-owned, trusted roots (e.g. an IDE staging dir). Any reload path outside the startup dir + these roots is rejected (403). The path is compared with the roots **as text first**, before any filesystem call on it, then resolved and compared again. A subdirectory of a root is allowed. A network share or a device-namespace path is refused unless it lies under a root that is itself spelled that way. Name the path the way the root is written here, or the way it resolves: another spelling of the same directory (a link to it, an 8.3 short name) is refused. |
| `tls_cert_file` | str | _unset_ | **`[BUILT]` (WP-13a, ADR 0002):** PEM server-certificate path. **Setting it serves your certificate in place of the generated self-signed placeholder** ([ADR 0172](adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md)) — the API serves `https`/`wss`, HSTS engages, and a non-loopback bind is allowed without `--allow-insecure-bind`. |
| `tls_key_file` | str | _unset_ | PEM private-key path (omit if the key is in the cert PEM). Requires `tls_cert_file`. |
| `tls_key_password` | secret | _unset_ | passphrase for an encrypted key — **env only** (`MEFOR_API_TLS_KEY_PASSWORD`), never the file. |
| `tls_min_version` | str | `1.2` | minimum negotiated TLS version floor (NIST SP 800-52r2): `1.2` or `1.3`. |
| `tls_ciphers` | str | _unset_ | optional OpenSSL cipher string (unset = the approved AEAD suites, the default on every hop the engine builds, BACKLOG #300). **Validated against a strict positive allow-list at config load** ([BACKLOG #1317](BACKLOG.md), ASVS 12.1.2): every suite the string resolves to must be forward-secret, must actually encrypt, must authenticate the peer, **and** must be named in `_APPROVED_TLS_SUITES`. The list is AEAD-only, so it excludes the six CBC-SHA2 suites the interpreter default enables, and since BACKLOG #300 so does the unset default. Since BACKLOG #2042 (owner ruling of 2026-09-26) it also excludes the three AES-128-GCM TLS 1.2 suites, so `ECDHE+AESGCM` refuses and `ECDHE+AESGCM+AES256:ECDHE+CHACHA20` passes. TLS 1.3's `TLS_AES_128_GCM_SHA256` stays on Python 3.14, a recorded gap, and goes on a Python that has `SSLContext.set_ciphersuites` (expected in 3.15). The three property checks exist because forward secrecy alone admitted `ECDHE-RSA-NULL-SHA` (plaintext) and `ADH-AES256-GCM-SHA384` (authenticates nobody). Needing a suite that is not listed is a change to that set, not a configuration override. |
| `tls_client_ca_file` | str | _unset_ | CA bundle to **require + verify client certs** (opt-in mTLS, e.g. the console). Requires `tls_cert_file`. **The engine reads the file once, checks those bytes, and loads the same bytes** (BACKLOG #1142), so a file swapped after the check is not trusted. It loads plain `CERTIFICATE` PEM blocks. A file the TLS library will not load refuses at start and at reload. That includes at least a `TRUSTED CERTIFICATE` block, a file with no PEM block, a file holding only a CRL, and a damaged block anywhere in the file. The engine also refuses a block of any kind that carries a `Proc-Type:` or `DEK-Info:` encryption header, such as an encrypted private key, before the TLS library reads it (BACKLOG #2270). A well-formed CRL beside a certificate is ignored: put it in `tls_client_crl_file`. The same rules hold for `[auth].oidc_tls_ca_cert_file`, `[auth].ad_tls_ca_cert_file` and an inbound connection's `tls_ca_file`. An outbound connection's `tls_ca_file` takes the pin, permission and change checks too, but not these PEM rules, since its hop still loads the file by path ([CONNECTIONS.md](CONNECTIONS.md#the-engine-checks-the-file-at-every-start-and-reload-tls_ca_pin), vault BACKLOG #2371). **For this file, `[auth].oidc_tls_ca_cert_file` and `[auth].ad_tls_ca_cert_file`, a changed file takes effect at the next restart, not at a reload** (BACKLOG #2185). A reload re-checks each of the three and refuses one that breaks the rules above. It does not load the new bytes. While a file differs from the bytes in use, each reload that passes this check logs a WARNING. It also writes an `auth.trust_anchor` audit row with `event` set to `restart_required`. The reload's own response does not say so. A file nothing loaded gets no warning, since a restart would apply nothing. AD over plain `ldap://` is one such case. **A path that is set is still checked when nothing loads it** (BACKLOG #2269). So `[auth].ad_tls_ca_cert_file` with AD off or on plain `ldap://`, or `[auth].oidc_tls_ca_cert_file` with OIDC off, still refuses the start, and every reload that is not a dry run, if the file breaks the rules above or cannot be read. Unset a path nothing uses. The pins are read at start too. So after you rotate a pinned file and change its pin, each reload that is not a dry run is refused until you restart. |
| `tls_client_crl_file` | str | _unset_ | **Opt-in revocation checking for mTLS client certificates** (BACKLOG #1005). A PEM file holding the CRL for the client CA. Read only when the engine terminates TLS itself and `tls_client_ca_file` is set. Otherwise nothing applies this key, including under `tls_terminated_upstream` with no `tls_cert_file`. A missing or blank path is still refused at load in every configuration, naming this setting (BACKLOG #1997). **Unset, a revoked but chain-valid client certificate is accepted**, because `tls_client_ca_file` checks the chain and RFC 5280 conformance only. Set, a revoked client certificate fails the TLS handshake. It checks the client's own certificate, not the rest of its chain, and there is no OCSP. **The engine reads the file at start, and again when you replace it.** It refuses to start on a bad file: at least a missing file, a file with no CRL, and an expired CRL. **An expired CRL would refuse every client, not only revoked ones.** So replace the file before its `nextUpdate`. When the new file passes the start rules and supersedes the old one, new handshakes check it within about a minute, without a restart. The [`[cert_monitor]`](#cert_monitor) section says what that takes, and what it does not reach (BACKLOG #299). The scan warns before that date. The engine refuses to start if the file carries a certificate the client trust store does not already hold (BACKLOG #1890). Loading one would make it a trusted client CA, outside the pin. Give this setting a bare CRL, and put the client CA in `tls_client_ca_file`. The CRL file itself has no pin or permission check: whoever can write it can change what is revoked, not what is trusted. Source of record: `harden_crl_check` in [`config/tls_policy.py`](../messagefoundry/config/tls_policy.py). |
| `tls_client_ca_pin` | str | _unset_ | optional lowercase-hex SHA-256 pin over the corresponding CA anchor PEM (`tls_client_ca_file`); a mismatch refuses at load + reload (ASVS 6.7.1); unset = no pin (dormant); set but empty or whitespace refuses at load. |
| `tls_client_cert_identities` | map issuer DN → (map str→str) | `{}` | **(#200, ADR 0002; activated by [ADR 0083](adr/0083-mtls-client-certificate-identity.md)):** mTLS client-cert → MessageFoundry principal map. Meaningful only with in-process mTLS (`tls_client_ca_file` set, so uvicorn `CERT_REQUIRED`-verifies the peer): a **verified** peer cert's issuer and subject CN / SAN are resolved to an existing account through this **allow-list** — a service-to-service identity that carries no bearer token. **The map is nested by issuer (BACKLOG #2237).** The outer key is the subject DN of the CA certificate, loaded from `tls_client_ca_file`, that signed the client's certificate. The inner keys are the qualified cert name `CN:<commonName>` or `SAN:<type>:<value>` (e.g. `SAN:DNS:svc.internal`). **Each value is the target account's id, not its username (BACKLOG #2238)**: the 32 lowercase hex characters in the `id` field of `GET /users`. A rename can hand a username to another account, and a map keyed by name would then follow it; the id never moves. A value that is not an id is refused at load. Write the issuer as a TOML literal (single-quoted) key, so any backslash in it stays as written: `[api.tls_client_cert_identities.'CN=Acme Service CA,O=Acme,C=US']` followed by `"CN:svc.internal" = "<the account's id>"`. A subject maps only under the CA named for it, so when `tls_client_ca_file` holds several CAs, the same subject from another of them reaches nothing. **The engine finds the issuer by signature, not by the client certificate's issuer field**: a loaded CA counts only when its subject equals that field exactly and its key verifies the certificate's signature. **An intermediate the client sends never counts**, since any trusted CA could mint one carrying another CA's name. If an intermediate signs your client certificates, load it in `tls_client_ca_file` with its root, and name the intermediate. A client certificate loaded in `tls_client_ca_file` itself is named by its own subject. **Two loaded CA certificates with the same subject DN and different keys name no issuer at all**, because the map cannot tell them apart; a CA re-issued under the same key counts as one issuer. Mid-rollover to a new key, the old and new CA name no issuer until the old one is removed. `serve` logs a WARNING at start for any issuer key that names no loaded CA, or names two. **Write the issuer DN in RFC 4514 form**, most specific attribute first, exactly as `cryptography` prints the CA certificate's subject: `python -c "import sys; from cryptography import x509; print(x509.load_pem_x509_certificate(open(sys.argv[1], 'rb').read()).subject.rfc4514_string())" ca.pem`. `openssl x509 -noout -subject -nameopt RFC2253` prints the same string after its `subject=` prefix when the name is plain ASCII and uses only CN, OU, O, DC, L, ST and C. **Refused at load:** a flat entry with no issuer, an issuer key that `cryptography` cannot parse unless it has the exact shape `cryptography` renders (its parser refuses some names its renderer prints, such as a three-letter `C=`), a name `cryptography` reads but writes differently (the error names the form to write), an issuer with no names, a name no certificate can carry (`CN:` or `SAN:<type>:<value>` with every part filled in), and a value that is not an account id. The loader cannot check attribute ORDER: a DN written in certificate order parses and never matches, and the start warning names it. **Deny-by-default:** an unmapped verified cert, a spoofed CN, or a listed subject from an unlisted, unloaded or ambiguous CA, or an unknown or disabled account, resolves to no identity and is denied. A structured map, so **TOML-only** (no env-string form). Empty (the default) disables cert-identity. **LIVE, not inert (ADR 0083).** Stock uvicorn does not surface the peer cert to the ASGI scope — so `serve` swaps in a scope-populating uvicorn HTTP-protocol subclass ([`api/tls_client_cert.py`](../messagefoundry/api/tls_client_cert.py)) **whenever `tls_client_ca_file` and this map are both set** ([`__main__.py`](../messagefoundry/__main__.py), the `ssl_context_factory` block), and that shim is why a `CERT_REQUIRED`-verified peer cert reaches the resolver. Both conditions are required: a mutual-auth-only bind (client CA, empty map) keeps the stock protocol. **What a cert identity can reach — narrower than "the request".** It is admitted **only** on routes declared with `require_service_cert` — today exactly one, `GET /service/identity` (`monitoring:read`). That plane is cert-**only** and never crosses the bearer/session plane (a cert-only caller gets 401 on every bearer route, a bearer-only caller gets 401 here); it carries **no session, no second factor and no step-up**; and it is **PHI-fenced** — `require_service_cert` raises at app construction if asked to gate a PHI-view permission. So mapping a cert to a privileged principal does **not** confer general API access, and can never reach the interactive or patient-data surface. |
| `tls_client_cert_files` | list[str] | `[]` | **(ASVS 6.4.5):** PEM paths of **inbound service callers'** client certs you hold a copy of. Folded into the [`[cert_monitor]`](#cert_monitor) scan, so a caller's cert expiry is caught **even while that caller has stopped connecting** — the handshake-time check can only see a cert still being presented. These are certs the engine *verifies*, not ones it *presents*, so the served-cert scan cannot see them. Public certificates only (never a key); empty = off. |
| `trusted_proxies` | list[str] | `[]` | **`[BUILT]` (WP-15):** reverse-proxy IP(s) whose `X-Forwarded-For`/`-Proto` are trusted (uvicorn `forwarded_allow_ips`), so the audit/rate-limit source IP is the **real client**, not the proxy. **Empty = trust nothing** (the direct TCP peer is used). Set ONLY to the proxy's address(es), or XFF spoofing returns — every host inside an entry may declare its own source address, so a broad range (e.g. `10.0.0.0/8` on a LAN numbered out of 10/8) makes every workstation a trusted spoofer. `"*"` and unparseable entries are **refused at load** (uvicorn would silently treat the latter as a never-matching literal, collapsing every client to the proxy). So is a CIDR with host bits set, such as `10.0.0.1/24`: uvicorn parses it strictly and it would match no peer. The error names the single address (`10.0.0.1`), then the network the entry spans (`10.0.0.0/24`) (BACKLOG #2488). **A non-empty list also needs `tls_terminated_upstream = true` or your own `tls_cert_file`, or it is refused at load (BACKLOG #2055).** A trusted proxy's `X-Forwarded-Proto` sets the request scheme. Without either key, a proxy that forwards `http` would make the web console issue its session cookie without `Secure`. Either key forces `Secure`, whatever the proxy forwards. Use `tls_cert_file` when the proxy re-encrypts to the engine; the generated placeholder does not count. |
| `tls_terminated_upstream` | bool | `false` | **`[BUILT]` (WP-15):** declare that a reverse proxy / load balancer terminates TLS in front of the engine. Lets a non-loopback bind satisfy the TLS gate **without** in-process TLS — but only when `trusted_proxies` is set (else refused at load). The pairing runs both ways: `trusted_proxies` without this key is refused too, unless you set `tls_cert_file` (previous row). **Without `tls_cert_file`, `serve` also refuses to start it until you set `plaintext_upstream_hop_acknowledged`** (next row). |
| `plaintext_upstream_hop_acknowledged` | bool | `false` | **Required with `tls_terminated_upstream` when `tls_cert_file` is unset (BACKLOG #1179).** In that topology the proxy terminates TLS and the engine mints no certificate ([ADR 0172](adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md) decision 3), so the proxy-to-engine hop is **plaintext by design**. The engine does nothing to protect that hop. Securing it is your site's job: a same-host loopback hop, an isolated network segment, or a host firewall. Setting this to `true` says you have taken that on. It records a decision and secures nothing. It is a listed loosening ([SECURITY-LOOSENING.md](SECURITY-LOOSENING.md)). Without it, `serve` **refuses** (exit 2) in **every** mode: `enforce` or `warn`, loopback bind or not. With your own `tls_cert_file` the engine serves that hop over TLS, so the acknowledgement is not required there, and setting it anyway is harmless. The proxy must then speak https to the engine and trust that certificate, or every request through it fails. Setting it **without** `tls_terminated_upstream` is **refused at load**, since there is no such hop to acknowledge. |
| `proxy_intra_service_auth` | enum | `none` | **Posture-B operator attestation (#200, ADR 0002)** — *how* the proxy→engine hop is authenticated, so a rogue peer on the internal segment cannot impersonate the proxy. `none` (the default) is **undeclared**; declare `mtls` (the proxy presents a client cert), `network` (an isolated proxy↔engine segment / host firewall allow-list) or `shared_secret` (a pre-shared header the proxy injects). **Attestation only — the engine enforces nothing at run time**; it is the record that the hop was considered. Left undeclared under `tls_terminated_upstream` on a PHI instance, `serve` **refuses** when `[security].enforcement = enforce` **and** the bind is non-loopback, and **warns** otherwise (including the recommended loopback-behind-proxy topology). **One coherence check (BACKLOG #1181, ASVS 12.3.5):** declaring `mtls` on a PHI instance while `[api].tls_client_ca_file` is unset **warns**. The engine is the far end of that hop and verifies a client certificate only with a client CA configured, so with none its own configuration contradicts the declaration. It stays a warning because a sidecar in front of the engine can legitimately terminate the proxy's mTLS, and it changes nothing on the wire — the setting is still an attestation. To have the engine itself require and verify the proxy's certificate, set `tls_cert_file` **and** `tls_client_ca_file`; both are valid alongside `tls_terminated_upstream`, because an operator-supplied certificate wins ahead of the no-mint branch. |
| `proxy_tls_min_version` | str | _unset_ | the operator-**declared** TLS version floor the reverse proxy negotiates with browsers: `1.2` or `1.3` (NIST SP 800-52r2) — any other value is refused at load. The engine terminates no browser TLS in Posture-B, so it cannot inspect the proxy's negotiated version (ASVS 11.6.2); this is the attested floor, validated only for coherence. Unset = undeclared, gated exactly like `proxy_intra_service_auth` above. |
| `proxy_tls_ciphers` | str | _unset_ | an **optional** declared OpenSSL cipher list for that proxy floor. When set it must resolve to suites that are forward-secret (ASVS 11.6.2), that encrypt, and that authenticate the peer — so a declared floor can't itself name a non-forward-secret key exchange, a NULL cipher, or an anonymous one. It uses the same validator as `tls_ciphers` but **deliberately without the approved-suite allow-list** ([BACKLOG #1317](BACKLOG.md)): this field *declares* what a proxy the engine does not operate already speaks, and refusing an unlisted-but-sound suite would not harden anything — it would stop an operator describing their proxy accurately. Unset = no cipher declaration; it is **not** required to satisfy the Posture-B gate (only `proxy_intra_service_auth` + `proxy_tls_min_version` are). |
| `serve_ui` | | | **→ moved to `[security].serve_web_console`** (ADR 0118) — set it there; no longer accepted in `[api]`. |
| `serve_ui_explicit` | | | **Removed, and refused at load** in the file or as `MEFOR_API_SERVE_UI_EXPLICIT` (BACKLOG #2000). It was an internal marker, never an operator setting. `serve` now checks whether you set `[security].serve_web_console` yourself, at either value. With the console wheel absent, an explicit `true` refuses to start. The default-on posture serves JSON only, with a warning. To request the console explicitly, set `[security].serve_web_console`. |
| `public_origin` | | | **→ moved to `[security].web_console_public_address`** (ADR 0118) — set it there; no longer accepted in `[api]`. |
| `ws_allowed_origins` | list[str] | `[]` | browser `Origin` allowlist for the **native/bearer** `/ws/stats` path only — NOT the `/ui` browser WebSocket (that authorizes via the cookie + a match against `[security].web_console_public_address`, falling back to the `Host` header when unset). Don't conflate the two knobs. |

> **An OpenSSL `@` directive is refused in `tls_ciphers` and `proxy_tls_ciphers`** ([BACKLOG #2106](BACKLOG.md)). That covers `@SECLEVEL`, `@STRENGTH` and any other `@` token. A directive names no suite, so the suite checks cannot see it. `@SECLEVEL=0` dropped the security level below the build's default (2 on OpenSSL 3.5), so a peer could present an RSA-1024 certificate. List suite names only. The per-connection MLLP and DICOM `tls_ciphers` follow the same rule. Each of those contexts, and the API listener's, is also checked once built, and refused if it runs below the build's default security level.

> **MLLP-over-TLS** is built too (WP-13b — per-connection `tls`/`tls_*` on the `MLLP(...)` connector,
> see [CONNECTIONS.md](CONNECTIONS.md)), and the §0 **exposed-gate is enforced**: a non-loopback
> *plaintext* MLLP listener is refused (a `WiringError`, before the engine starts). **Do not plan on
> `serve --allow-insecure-bind` here** — it is clamped inert whenever the hop is enforcing PHI
> (`[security].enforcement = enforce` **and** a PHI data label, which is every one of `dev`/`staging`/
> `prod` on shipped defaults), so on a stock instance passing it changes nothing and the bind still
> refuses. The fix is `tls = true` (+ `tls_cert_file`/`tls_key_file`) on the connection. Gate #4's
> transport-TLS subset is complete, and **native TOTP MFA (WP-14) is also built**
> (`[security].require_mfa`, every account under the default scope, directory ones included since
> BACKLOG #1144 — `[auth].require_mfa` is a relocated key and is **rejected
> at config load**). See [ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md).

> **WebAuthn passkeys (WP-14b, [ADR 0068](adr/0068-browser-webauthn-passkeys-offloopback.md)).**
> Browser passkeys need the optional **`[webauthn]` extra**
> (`pip install messagefoundry[webauthn]`) — no new `[auth]` setting: installing the extra + a user
> enrolling on `/ui/account` is the opt-in (extra-less installs show a legible notice, never an
> error). The WebAuthn RP identity rides the external origin — set it as
> **`[security].web_console_public_address`** (the internal field is still `api.public_origin`, but
> `[api].public_origin` is a relocated key and is **rejected at config load**, row above). A plain
> loopback deployment derives the RP from the request URL, but only with `[api].trusted_proxies`
> empty. A set `trusted_proxies` with no declared terminator (an operator `tls_cert_file` behind a
> re-encrypting proxy) starts, and passkey ceremonies fail closed there until
> `web_console_public_address` is set (BACKLOG #2116). On a loopback bind the `/ui` same-origin
> checks fail closed there too: no `Origin` matches the Host the proxy forwards, so the console's
> WebSocket feed is refused (pages fall back to polling), and a browser that sends no
> `Sec-Fetch-Site` cannot submit a form (BACKLOG #2217). **Behind a declared reverse proxy
> (`tls_terminated_upstream`) an unset origin is a startup REFUSAL, not a degraded ceremony**: with
> the console served, `serve` exits 2 until `web_console_public_address` is set, because the `Host`
> header is client-forwardable there and both the `/ui` CSRF check and the passkey origin binding
> need the exact external origin.
>
> **IT IS NO LONGER A CONSOLE SETTING ON A PHI INSTANCE, and that is a SECOND, INDEPENDENT
> refusal** (BACKLOG #1026). A **PHI** instance behind a declared terminator under `enforce` exits 2
> with the origin unset **even with the console off**. The reason has nothing to do with `/ui`: the
> ASVS 12.1.1 startup probe dials that origin to measure the terminator's TLS floor, so leaving it
> unset *silently disabled the check* rather than failing it — and a control that degrades to a
> no-op reports success forever afterwards. So on a PHI instance, read this as a property of the
> **deployment posture**, not of whether you serve the console. It is only in the **in-process-TLS off-loopback** case that the
> engine warns and starts — and *there* the ceremonies do fail closed (no passkeys) until you set it.
> Either way, **changing its host later invalidates every enrolled passkey** (they pin their
> mint-time RP; the account page marks them "unusable (origin changed)").

> **Off-loopback browser-console walkthrough (L5b, ADR 0068 §8).**
>
> **Step 0, and it is not optional: set `[security].serve_web_console = true` explicitly.** Every
> posture below — a non-loopback bind, a declared terminator, a set `[api].trusted_proxies`
> (BACKLOG #2218), **or** merely setting `web_console_public_address` — makes the instance
> *exposed*, and an exposed instance
> **auto-degrades a default-on console to JSON-only** (ADR 0143; [`__main__.py`](../messagefoundry/__main__.py)
> flips `serve_ui` off in place). That degrade is the **one precondition on this page whose absence
> produces no error**: the engine starts clean, prints a single stderr warning, and `/ui` 404s. It is
> the *explicitness* that saves you, not the value — `serve` treats the console as explicit only when
> you wrote the key yourself, so inheriting the `true` default is exactly what trips it. Verified by
> loading the terminator recipe below through `load_settings()`. Without the key,
> `security.serve_web_console_explicit` is `False` and the exposure predicate is true, so the console
> is dropped. With it, that property is `True` and the console is served, and then has to satisfy the
> ladder. Setting it also arms the refusals below — which is the point: an explicit `true` converts
> every silent degrade on this page into a loud `exit 2`.
>
> With that set, the two supported postures:
> **in-process TLS** (`tls_cert_file` [+`tls_key_file`]) — the browser connects directly to the
> engine — or a **declared upstream terminator** (`tls_terminated_upstream = true` +
> `plaintext_upstream_hop_acknowledged = true` +
> `trusted_proxies = ["<proxy egress IP or CIDR>"]` + **`[security].web_console_public_address`**,
> which the L5b ladder now requires — set it under `[security]`, not as the rejected
> `[api].public_origin`). `trusted_proxies` entries match the proxy's **direct TCP peer address exactly** (CIDR
> supported, but scope it to the proxy pool — every host inside an entry may forge its own source
> address; watch the `::1`-vs-`127.0.0.1` mismatch) — a *syntactically valid but wrong* entry silently
> disables the forwarded-header rewrite, collapsing audit/rate-limit source IPs to the proxy. An
> **unparseable** entry, a CIDR with host bits set (such as `10.0.0.1/24`), or `"*"`, is refused at
> config load rather than degrading silently. With either
> posture declared (`exposure_protected`), the `/ui` session cookie ships `Secure` and HSTS is
> emitted regardless of the per-request scheme.
>
> The two postures, written out — each is the **console** half only; a PHI instance still has to
> satisfy the encryption / egress / retention / security-notification gates catalogued below before
> `serve` will start at all:
>
> ```toml
> # A — declared upstream terminator (loopback bind behind a reverse proxy)
> [security]
> serve_web_console = true                                 # step 0 — without this /ui silently 404s
> web_console_public_address = "https://mefor.example.org"  # required under a declared terminator
> [api]
> tls_terminated_upstream = true
> plaintext_upstream_hop_acknowledged = true  # required: the proxy->engine hop is plaintext, and yours to secure
> trusted_proxies = ["10.20.0.5"]        # the proxy's DIRECT TCP peer address, not a broad range
> # On THIS (loopback-bind) topology the two Posture-B attestations only WARN if you omit them; they
> # become an exit 2 once the bind itself is off-loopback. Declare them anyway — the warning is the
> # record that the proxy->engine hop was considered.
> proxy_intra_service_auth = "mtls"      # how the proxy->engine hop is authenticated (attestation only)
> proxy_tls_min_version = "1.3"          # the TLS floor the proxy negotiates with browsers
> ```
>
> ```toml
> # B — in-process TLS (the browser connects straight to the engine)
> [security]
> serve_web_console = true               # step 0 — same silent degrade applies to this posture
> local_access_only = false
> listen_address = "10.20.4.7"
> web_console_public_address = "https://mefor.example.org"  # optional here, but WebAuthn fails closed without it
> [api]
> tls_cert_file = "C:/mefor/tls/server.pem"
> tls_key_file  = "C:/mefor/tls/server.key"
> ```
> Posture **B** additionally needs `MEFOR_TLS_REVOCATION_ATTESTED=1` in the service environment — see
> the next paragraph.
>
> **Neither posture starts a stock instance from the keys above alone** — beyond step 0, each has a
> second, fail-closed precondition outside the `[api]` section:
> in-process TLS off-loopback additionally needs the environment variable
> **`MEFOR_TLS_REVOCATION_ATTESTED=1`** ([ADR 0078](adr/0078-certificate-revocation-posture.md); that
> gate reads neither the data label nor `[security].enforcement`, so a synthetic lab box hits it
> too), and the terminator additionally needs **`[api].proxy_intra_service_auth`** *and*
> **`[api].proxy_tls_min_version`** on a PHI instance under `enforcement = enforce` with an
> off-loopback bind (the rows above). Both are `exit 2`, both land before the console gates, and
> `--allow-insecure-bind` covers neither. The worked recipes are
> [REMOTE-CONSOLE.md](REMOTE-CONSOLE.md) §1 Options A/B and [DEPLOYMENT.md](DEPLOYMENT.md) § *Before
> you expose off-loopback*. Full runbook + reverse-proxy-mTLS reference
> configs: security/OFF-LOOPBACK-DEPLOYMENT.md — a maintainer-internal document; see
> [SECURITY-DOCS-POLICY.md](SECURITY-DOCS-POLICY.md) for what is withheld and what you can request.

### `[tls]` — outbound client trust anchors
Instance-wide **client trust-anchor policy** (#190, [ADR 0093](adr/0093-pinned-internal-ca-trust-anchor.md)) —
a small shared fallback for the outbound connectors that verify a downstream *server* certificate (MLLP,
DICOM, FTPS today). The inbound FTPS poller dials out and verifies its server too, so it reads this block
as well (vault BACKLOG #2370): a `pinned` mode or a `crl_file` must suit its partner. By default the OS trust store roots verify the peer; a hospital estate whose internal
endpoints present a private/internal-CA certificate can pin that CA **once** here instead of installing it
box-globally or repeating a per-connection `tls_ca_file`. This selects **which** roots verify the peer — it
**never disables verification** — so it composes with (never weakens) the connectors' fail-closed no-CA /
`tls_verify=false` / cleartext-hop refusals. A connection naming its **own** `tls_ca_file` always wins
verbatim, and a loopback hop is exempt. The default is a no-op: a config with no `[tls]` block builds a
byte-identical SSL context.

| Key | Type | Default | Notes |
|---|---|---|---|
| `internal_ca_file` | path | — | PEM path to the org's internal CA. **Not a secret** — a path, like `tls_cert_file` / `forward_tls_ca_file`. Unset (default) = no internal anchor; every hop uses the OS trust store. |
| `trust_anchor_mode` | enum | `system` | how `internal_ca_file` composes with the OS default roots on a non-loopback internal hop. `system` (default) = **OS trust store only**, `internal_ca_file` ignored (byte-identical). `augment` = OS roots **and** the internal CA (a mixed public + private estate). `pinned` = **only** the internal CA, not the public bundle (a fully-private estate; strictest). `pinned` **without** `internal_ca_file` is **refused at load** — with nothing to pin it would silently fall back to the full OS trust store, i.e. the operator excludes public roots and gets all of them. |

### `[inbound]` — inbound listener defaults
| Key | Type | Default | Notes |
|---|---|---|---|
| `bind_host` | str | `127.0.0.1` | the **default** network interface every inbound MLLP/TCP listener binds to. Authors never set a `host` on an inbound connection (a wiring error if they do) — it's a per-environment operator decision here. Binding `0.0.0.0` exposes unauthenticated MLLP to the network, so it's deliberate (DEV typically loopback, PROD a specific NIC behind a firewall). A non-loopback bind **requires `tls=true`** on each MLLP connection: the §0 exposed-gate (`check_mllp_tls_exposure`) raises a `WiringError` for a plaintext off-loopback listener at wiring time, before the engine starts. `serve --allow-insecure-bind` downgrades that to a warning **only on a non-enforcing instance** — it is clamped inert whenever the hop is enforcing, which is the shipped default on all three built-in env names, so on a stock instance the flag buys nothing. Declaring the instance synthetic was the other way past the clamp and it is gone ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)); the `[security].enforcement` dial is the only one left. A single connection may override the interface with a per-connection `bind_address` (and restrict peers with a per-connection `source_ip_allowlist`) — MLLP/TCP only; see [CONNECTIONS.md](CONNECTIONS.md). |
| `ack_after` | enum | `ingest` | the **default** ACK timing every inbound inherits (staged pipeline, [ADR 0001](adr/0001-staged-pipeline-architecture.md)). `ingest` = ACK-on-receipt, once the raw message is durably committed to the ingress stage and **before** routing/transform/delivery. `delivered` (defer the ACK until delivery succeeds) is **not built** — wiring it raises a `WiringError`, so it fails loud rather than silently ACKing early. A connection's own `ack_after=` overrides this. |
| `stream_inflight_budget_bytes` | int (bytes) | `0` | aggregate cap on the **total** bytes of over-threshold message bodies concurrently mid-detach across **all** inbounds (#149, [ADR 0105](adr/0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md)). A detach that would push the running total over it is refused with backpressure (the message is NAK'd/`ERROR`'d, never accepted-and-dropped), so a burst of very large documents can't exhaust memory. `0` (default) = unlimited — a *single* body is still bounded by the per-connection `max_message_bytes`. Only over-threshold streaming detaches count against it. **Unlimited is opt-out, and it now says so at start** ([BACKLOG #1729](BACKLOG.md)): binding an inbound that sets `stream_threshold_bytes` while this is `0` logs a **WARNING** naming that connection, its threshold and its effective single-body cap. It does **not** refuse. A refusal here would fire on every streaming graph that is valid today with no new opt-in gating it, which is the scoping rule stated on `[security].require_memory_encryption_declaration` below; the warning is the rung below it, and it fires on start, on reload, and on a runtime connection start. A stock graph sets no `stream_threshold_bytes`, never reaches the detach path, and is silent. |
| `max_staged_depth` | int (rows) | `0` | the **staged-backlog depth bound** ([BACKLOG #290](BACKLOG.md)). **Opt-in**: `0` (default) = off. When positive, the engine **pauses intake** while the not-done rows at the **ingress + routed** stages of the store exceed it, and resumes once they drain to 90% of it, so the pause does not flap. It counts the **one** store, so engine shards sharing a store share one budget. The outbound stage is not counted, so one down destination does not stop every feed. **A shared budget has a cost**: one feed whose router or transform stalls, or the leftover rows of a dead engine shard, count against every feed and can hold all intake paused until an operator acts, so size it well above a normal backlog. The pause is **backpressure only**: `mllp`, `tcp`, `x12` and `http` inbounds stop reading (nothing more is parsed or committed; the socket buffers asyncio already filled, up to about 128 KiB a connection, sit unACKed in memory; an HTTP partner waits for its answer; and a paused `http` listener does not answer a health probe either). A `dimse` (DICOM SCP) inbound refuses each **new** association as busy, before any object is sent. The refusal is an A-ASSOCIATE-RJ of *rejected-transient, temporary congestion*, which is DICOM's "retry later". A peer the association checks would refuse anyway, such as an unlisted calling AE, gets that refusal instead. A C-ECHO-only association is refused as busy too, so a monitor that echoes the SCP sees it as down during a pause. An association accepted before the pause finishes normally, and each C-STORE on it is still committed before its Success. `file`, `remotefile`, `database` and `timer` inbounds skip their tick. A skipped tick is not made up at resume: the next one comes on the usual cadence, and a skipped cron slot is not fired late. Nothing already read is NAKed, dropped or left uncommitted, and the ACK still follows the durable commit. A sender that gives up during a pause and resends may be recorded more than once, which at-least-once delivery already allows; a plaintext connection it abandoned with a request already sent keeps its slot until the pause ends. A **WARNING** marks each pause and an **INFO** its end. The same pause fires on low disk, keyed on `[retention].min_free_disk_mb`. The engine measures once before its listeners start and then about once a second, and a poll tick already under way finishes its batch (`poll_max_files` / `poll_max_rows`, and every message split out of a batch file in it), so intake can overrun the bound by about a second of traffic plus one poll tick's worth. A listener checks the pause before it starts a read, so a connection already waiting in a read when the pause begins still takes in its next chunk, up to 4 KiB, whenever that arrives. A DICOM association accepted before the pause is not bounded by it at all. A modality that holds one open keeps sending until it releases it. |

**A pause raises an alert** (BACKLOG #290). On either bound, the depth or the low-disk floor, the
engine raises `intake_paused` while a pause holds and `intake_resumed` when it ends. The `[alerts]`
section below says how often, and what the payload holds.

**`serve` notes when the depth bound is unset.** Under `[security].enforcement = "enforce"`, the
shipped default, a start with `max_staged_depth = 0` logs one INFO line to the service log. It names
this key and says the staged backlog is unbounded. It is not a warning and never refuses a start,
because the bound is opt-in by owner ruling. With the key set, or under `enforcement = "warn"`, it
says nothing.

### `[environments]` — per-environment graph values (DEV/PROD)
The **same** code-first graph runs in every environment; only the values it references via
[`env("key")`](../messagefoundry/config/wiring.py) differ. The **active** environment is the single
cross-cutting selector **`[ai].environment`** — a **free-form name** (ADR 0017), set in the TOML or via
`serve --env <name>`, and **required** (no default); this section only locates the value files.

| Key | Type | Default | Notes |
|---|---|---|---|
| `dir` | str | `environments` | directory holding `<env>.toml` flat key→value tables for non-secret values, **versioned** in the repo. Resolved against `base_dir` (below). |
| `base_dir` | str | `""` (= the working dir) | **Anchor** `dir` resolves against. Empty keeps the original behavior (relative to the process working directory). Set it to the **config-repo root** so env-value resolution no longer depends on where `serve` was launched. A relative value is taken against the working dir; an absolute value is used as-is — **on Windows it must be drive-qualified** (`C:/repo`); a leading-slash `/repo` is drive-relative and still inherits the launch drive (logged as a warning). Overridable per run with `serve --project-root`. |

- A graph value that differs by environment is authored as `env("acme_adt_host")`; the running
  instance resolves it from `<base_dir>/<dir>/<active-env>.toml` overlaid by **`MEFOR_VALUE_<KEY>`**
  env vars (secrets — never the file; env wins). Keys are `lower_snake_case`.
- **Anchoring the value files (`base_dir` / `--project-root`).** A standalone **config repo** (ADR
  0017) keeps `environments/` at its root — a *sibling* of the `--config` dir. With the default
  (empty) `base_dir`, the files resolve relative to the **process working directory**, so a `serve`
  launched from anywhere but the repo root reads **no** env values (a silent empty table, not an
  error — the missing values then fail loud only when a connector is built). This bites most under
  **NSSM**, whose working directory is rarely the repo. Pin the anchor so resolution is
  launch-independent — in the instance's `messagefoundry.toml`:
  ```toml
  [environments]
  base_dir = "C:/srv/acme-config"   # the config-repo root; environments/<env>.toml live under it
  ```
  or per run: `messagefoundry serve --config config --env prod --project-root C:/srv/acme-config`
  (the flag overrides `[environments].base_dir`; precedence is CLI > env > file > default, like every
  service setting). The startup log prints the **resolved** `environments/<env>.toml` path so you can
  confirm where values are read from. Running from the repo root keeps working unchanged (the empty
  default is the working dir).
- A referenced key that is **undefined for the target environment** makes the engine refuse to load
  or promote that graph (fail loud) — never a silent blank host. See the env files under
  [`environments/`](../environments/) and `samples/config/IB_ACME_ADT.py` for a worked example.
- **A boolean setting reads its value strictly.** Write it as `env("acme_allow_expired", cast=bool)`
  in a code-first module, or `{ env = "acme_allow_expired", cast = "bool" }` in `connections.toml`.
  Both read `true`, `1`, `yes` and `on` as true, and `false`, `0`, `no` and `off` as false, in any
  case. A TOML `true` or `false` in `<env>.toml` works as written. Any other value, such as `maybe`,
  stops the load with an error that names the setting and the key. A `default=` given with a
  bool cast is read the same way, on both routes. Before vault BACKLOG #3138, a code-first `cast=bool` used
  Python's own `bool`, which reads any non-empty text as true. A `MEFOR_VALUE_*` of `false` would
  then have turned on a loosening such as `tls_allow_expired` or `trust_server_certificate`.
  **Always give a boolean setting this cast.** An `env()` with no cast, or with a `str` cast, hands
  the setting text, and a connector reads any non-empty text as true. A cast you write yourself,
  such as `cast=lambda s: bool(s)`, runs as written and keeps that trap.
- **Per-face logic inside a transform:** `env()` is a *deferred reference* resolved only when a
  **connection** spec is built — using it in a handler is an always-truthy object (a bug). To branch a
  Router/Handler on the deployment, read the active environment **name** with
  [`current_environment()`](../messagefoundry/config/active_environment.py) (the free-form name, e.g.
  `"prod"`/`"test"`, or `None` in a dry-run):
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

  @handler("to_dietary")
  def handle(msg):
      msg["ODS-3"] = DIET.get(msg["ODS-3"], "")     # .get(key, default) — blank on a miss
      fac = code_set("facility_mnemonics").get(msg["MSH-4"])  # call-time lookup also works
      ...
      return Send("OB_DIETARY", msg)
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
- **Editing — by hand or from the IDE.** A code set is a plain `codesets/<name>.csv` you can edit in any
  editor, **and** a GUI-manageable artifact ([ADR 0033](adr/0033-gui-manageable-code-sets.md)). The VS
  Code extension opens a **grid editor** (rows × columns of strings — the first column is the lookup
  key) to **create / edit / rename / delete** a translation table; it shells a new
  **`messagefoundry codeset`** CLI that owns validation and the atomic write. Both editors write the
  same file (CSV-first), so a hand edit and a GUI save are interchangeable — mirroring the connections
  editor ([ADR 0007](adr/0007-gui-manageable-connections-toml.md)).
  - `messagefoundry codeset list  --config DIR` — summarize every set under `codesets/` (`.csv` **and**
    `.toml`; TOML sets are summarized and shown **read-only** in the grid — TOML-in-grid editing is a
    fast-follow).
  - `messagefoundry codeset show   --config DIR --name N` — the grid (headers + rows).
  - `messagefoundry codeset upsert --config DIR --data '{…}'` — validate → write an owner-only
    candidate of `codesets/N.csv` → **load the candidate as the final check** → replace the live
    file with it; a bad save never touches the live file, so the CLI never leaves an unloadable table.
  - `messagefoundry codeset rename --config DIR --name N --to M` / `… remove --config DIR --name N`.

  The CLI is **offline** (no engine start, no egress check — a code set is standalone data); it validates
  against the **same loader** that runs at startup, and the operator-supplied **name is treated as
  untrusted data** (rejecting path separators, `..`, absolute/drive paths, and an embedded extension, so
  a name can't escape `codesets/`). Apply a change with the existing audited promote/reload below.
- **Promote to apply (rename/remove caveat).** Editing a `codesets/` file changes nothing live; the
  running graph adopts the change only through **`POST /config/reload`** (the IDE promote), exactly like
  a connection or handler change. **Renaming or removing a code set can break a handler reference** — a
  `code_set("old_name")` call then raises at run time (that message's `ERROR` disposition). A plain
  `validate` only confirms each file parses, so it **won't** catch a now-dangling reference; **run
  `messagefoundry check` after a rename/remove**, whose dry-run executes the transforms and surfaces the
  broken `code_set(...)` lookup before you promote. See [docs/CODESETS.md](CODESETS.md) for the full grid
  editor + CLI reference.

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
  `default` (state is sparse, not a referenced table). The cache holds each value encrypted and
  decodes it on every read, so each call returns a fresh copy: changing the returned object does not
  change the stored state (BACKLOG #1174). **Non-linearization caveat:** a read reflects
  committed state as of its invocation, but is **not** linearized with a concurrent sibling handler's
  write — fine for read-mostly correlation; a race-sensitive read-modify-write within one namespace
  needs author care.
- **Encryption at rest.** State values may carry PHI (MRN↔id), so they are AES-256-GCM-encrypted with
  the store cipher just like `messages.raw`, and covered by key rotation (`messagefoundry rotate-key`).
- **Retention (TTL).** `[retention].state_max_age_days` ages out entries by the time they were last
  *written* (a global age purge; per-namespace policy is a follow-up). Off by default = keep forever,
  and `serve` then refuses under `enforce` unless
  `[security].allow_keeping_transform_state_indefinitely = true` acknowledges it (BACKLOG #1967). Prefer
  the acknowledgement: a read never refreshes the write time, so a window can delete an entry a
  Handler still reads. See the tier table under [`[retention]`](#retention). The whole-table cache
  assumes **bounded** state — unbounded estates (every MRN ever seen) are a documented follow-up
  ([ADR 0005](adr/0005-transform-accessible-state.md)).
- **SQL Server.** State writes ride the staged `transform_handoff`, which is implemented on the SQL
  Server backend, so the `state` table is **live** (parity with SQLite/Postgres); the read-through
  cache refreshes post-commit. Cross-node state convergence is N/A (single-node backend).

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
  read-only SQL query on the cadence (SQL Server via the `[sqlserver]` extra, **production / supported**; secrets
  via `env()`; the dial-out is gated by the fail-closed `[egress].allowed_db` allowlist). `key_column`
  is the lookup key; `value_column` (if set) is the value, else the value is a dict of the other columns.
- **Sync.** The engine's `ReferenceSyncRunner` materializes each set once at startup (before listeners
  serve, so `reference(...)` resolves on the first message) and every `refresh_seconds`. A source
  failure is **isolated**: it's logged + alerted and the **last-good snapshot is kept** (the write
  isn't attempted), so one bad source never blocks the others or the message path.
- **At rest:** snapshot values are AES-GCM-encrypted (they may carry PHI) and covered by key rotation,
  exactly like `state`/message bodies; the fail-closed `[egress].allowed_db` allowlist gates the
  `DatabaseRef` source's dial-out. The snapshot store ships on **all three backends** — SQLite,
  Postgres, and SQL Server ([BACKLOG #235](BACKLOG.md), 2026-07-16).
- **`[reference]` settings:** the sync cadence + startup behaviour — catalogued in
  [`[reference]`](#reference) immediately below.
- **Dry-run / `check`** resolve file-backed sets best-effort (literal paths) so a reference-using
  transform validates; DB-backed or `env()`-path sets are absent in a pure dry-run.

### `[reference]`
The sync knobs behind the reference sets above ([ADR 0006](adr/0006-external-data-lookups.md) Tier 1),
enforced by the engine's `ReferenceSyncRunner`
([pipeline/reference_sync.py](../messagefoundry/pipeline/reference_sync.py)). The runner is a **no-op when
no sets are declared**, so these defaults are safe on an existing deployment.

| Key | Type | Default | Notes |
|---|---|---|---|
| `refresh_interval_seconds` | float (s) | `3600` | base cadence the sync loop ticks at; each set re-materializes when its own `refresh_seconds` is due. Must be `> 0` (refused at load otherwise). |
| `sync_on_startup` | bool | `true` | materialize every declared set once at startup, **before** inbound listeners begin serving, so a transform's `reference(...)` resolves on the very first message. Strongly recommended on. |
| `max_staleness_seconds` | float (s) | `0` | **reserved / not enforced** — the intended freshness guard (alert/refuse when the active snapshot is older than this). Accepted so a forward-looking file still loads; `0` = off. Must be `>= 0`. |

### `[auth]` — authentication & RBAC
Implemented (see [SECURITY.md](SECURITY.md)). Authentication is **required** by default; the AD bind
password is a **secret**: supply it via env (`MEFOR_AUTH_AD_BIND_PASSWORD`) or a `[secrets]` reference, not the file.
A value in the file is still accepted, with a WARNING at load naming the key.
The full inventory of resource-demanding functionality the `*_rate_limit_*` throttles below defend —
including the surfaces that remain **unbounded** at this release — is
security/THREAT-MODEL.md §Resource-demanding functionality (ASVS 15.1.3), a maintainer-internal
document ([SECURITY-DOCS-POLICY.md](SECURITY-DOCS-POLICY.md)).

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | | | **→ REMOVED** (vault BACKLOG #2719). `serve` always requires sign-in, so there is nothing to set. Setting it is refused at load, from the file or as `MEFOR_AUTH_ENABLED`. ADR 0118 had relocated it to `[security].require_sign_in`, and that key is removed too. |
| `session_idle_timeout_minutes` | | | **→ moved to `[security].sign_out_after_idle_minutes`** (ADR 0118) — set it there; no longer accepted in `[auth]`. |
| `session_absolute_hours` | | | **→ moved to `[security].max_session_hours`** (ADR 0118) — set it there; no longer accepted in `[auth]`. |
| `max_sessions_per_user` | int | 5 | cap concurrent sessions per user (ASVS 7.1.2; `0` = unlimited); a login beyond the cap revokes the user's oldest live session; only live sessions count, and the same login revokes the user's sessions already past the idle or absolute limit. Sign-ins that still owe a second factor are counted apart: see the *Concurrent session count* row in `docs/SECURITY.md` |
| `step_up_max_age_seconds` | int | 300 | **step-up re-verification window** (ASVS 7.5.3): a highly sensitive operation requires the session to have re-verified its credential — at login or via `POST /me/reauth` — within this many seconds. A code accepted at `POST /auth/mfa-verify` (or the console's `POST /ui/mfa`) opens the window too. A **local** login that owes no second factor usually counts as the first verification (the sudo-timestamp model). The exception is an account that has signed in before, signing in from an address that is not among its recent completed sign-ins (the hosts it finished a sign-in or passed a step-up from, at most 90 days back): that session is born with no window, which is the first-seen address challenge (BACKLOG #288). A step-up from that address passes the challenge; signing in again does not. The check fails open, and the window opens, when the sign-in carries no client address or the account's known-address record cannot be read. A sign-in that proves the password and a TOTP code in one request counts from any address (ADR 0197). A directory login (Windows SSO by either route, or OIDC) does not: it is born with no window, so its first sensitive action asks for a step-up, or for its second factor where it owes one (BACKLOG #1144) |
| `require_action_step_up` | bool | `true` | **action-bound step-up** ([ADR 0077](adr/0077-action-bound-step-up.md); ASVS 7.5.1/8.2.4). On by default: a fixed set of routes requires a fresh proof **bound to that specific action** (`POST /me/reauth` with a matching `purpose`, single-use) instead of riding the session-wide `step_up_max_age_seconds` window. On the JSON API the set is `POST /me/mfa/enroll`, `POST /me/mfa/confirm`, `DELETE /me/mfa`, `DELETE /me/sessions` and `DELETE /me/sessions/{session_id}`, plus the administrator's `PATCH /users/{user_id}`, `POST /users/{user_id}/reset-password`, `POST /users/{user_id}/reset-mfa`, `PUT /users/{user_id}/federated-identity` and `DELETE /users/{user_id}/federated-identity`. Since vault BACKLOG #2625 the set also holds the injection and bulk-export routes: `POST /messages/{message_id}/resend`, `POST /messages/{message_id}/edit-resend`, `POST /uploads/{file_id}/resend`, `GET` and `POST /messages/export`, `POST /connections/{name}/purge` and `POST /config/reload`. The console binds the same actions, and passkey enroll and delete too. It closes the most-exploitable default: a session hijacked inside the 300 s login-seeded window could otherwise bind an attacker's authenticator, deliver a fabricated message to a partner, or export bodies in bulk, with no fresh proof. It changes **only** that set; every other step-up route, the rest of the admin surface and replay among them, keeps the session-window step-up. So `false` takes the bound proof off message injection, bulk export, purge and config reload as well as off the factor and admin routes. `false` reverts to the legacy session-window behaviour (0.2.x semantics), the documented org opt-out. **One refusal survives the opt-out and no setting reaches it:** an MFA-pending session on an account that **already holds** a second factor cannot bind a new one or end sessions, on either surface — it must prove the existing factor first. Without that bound, `false` would turn a config knob into an account-takeover path, because the enrollment ceremonies mark a session MFA-satisfied on success. Enrolling a **first** factor is untouched |
| `password_min_length` | int | 15 | local-password policy — ASVS 5.0-aligned, length-first |
| `password_require_uppercase` / `password_require_lowercase` / `password_require_digit` / `password_require_symbol` | bool | `false` | character classes — **opt-in**, each independently (ASVS 5.0 forbids mandatory composition); turn one on only for a legacy standard that still mandates it |
| `password_check_breached` | bool | `true` | reject known common/breached passwords against a bundled offline corpus (no live HIBP call). Its entry counts and the policy filter that built it are recorded once, in `common_passwords.NOTICE` beside the list. What makes an entry count at all is under `password_breach_corpus_file` below, and applies to the bundled list too |
| `password_check_context` | bool | `true` | reject a local password that **contains** any deny-list term — a case-insensitive substring test, anywhere in the value, not a whole-word or prefix match. The **twelve** terms are listed in full in [SECURITY.md](SECURITY.md) "Password policy"; an earlier revision of this row called them "app/vendor/HL7 terms" and gave four examples, which mis-stated the rule (five of the twelve are generic credential words unrelated to this application or to HL7). The shipped list is fixed in code (`CONTEXT_WORDS` in [`auth/policy.py`](../messagefoundry/auth/policy.py)): **this flag turns the whole check on or off, site terms included, and no setting removes a shipped term**. A site adds its own terms with `password_extra_context_words` below, and they are screened the same way. Turning this off while that list is set refuses the load |
| `password_extra_context_words` | list | `[]` | a site's **own** context words, added to the shipped `CONTEXT_WORDS` in the same screen (ASVS 6.1.2 / 6.2.11). Use it for organization, product, project, department or role names that a shipped list cannot know. **Additive only**: it can never remove a shipped term. The screen lower-cases the password and each term, then refuses the password if the term appears anywhere in it. Nothing else is normalised, so `acme.org` matches only that exact text and misses `acmeorg`. Prefer distinctive bare words. Each entry is trimmed and lower-cased at load, and must be one word with no inner whitespace. List `acmehealth` and `acme` rather than `acme health`, which would never match `AcmeHealth2026`. Each entry must also be at least **3** characters, the length of the shortest shipped term. A shorter substring would refuse a large share of ordinary passphrases. The floor stops a one-letter term, but a common fragment such as `the` would still refuse many passphrases. An empty or whitespace-only entry **refuses the load** rather than being dropped. A refusal for a site term says it is one of the site's additions. A term the shipped list already holds keeps the shipped refusal alone. Setting this while `password_check_context = false` also refuses the load, because the terms would screen nothing. Via env: comma-separated, or a JSON array, in `MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS`. In the comma form a trailing comma is an empty entry, so `acme,globex,` refuses; the OIDC and egress lists drop one instead. Publish the site's list in the site's own documentation, as ASVS 6.1.2 asks. Unlike `password_breach_corpus_file`, which matches the *whole* password, a term here is refused anywhere inside a longer passphrase. **Read once at start**: a `/config/reload` does not re-read it, so a change needs a restart of each engine shard and each cluster node. `MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS` overrides the file. A list too broad for any generated credential makes account creation and both resets answer 503. [SECURITY.md](SECURITY.md#admin-password-reset-wp-l3-12-asvs-646) gives the recovery steps |
| `password_check_username` | bool | `true` | reject a password containing the user's **own username**. No ASVS 5.0 requirement names this screen: 6.2.11 grades the documented context-word list (`password_check_context`), and a username is not on it |
| `password_breach_corpus_file` | path | — | optional path to a **larger offline breach corpus** that augments the bundled one (ASVS 6.2.12): a plaintext list **or** an HIBP-style SHA-1 hash export (`HASH[:count]` lines, auto-detected). Fully offline — still no live HIBP call. Use a curated subset, not the full ~40 GB HIBP set (it is loaded into memory). A path, not a secret. **Size this list by how many of its entries clear your policy, never by its line count**: an entry shorter than `password_min_length` can only reject a password the length rule already rejects, so it adds nothing. At the shipped minimum of 15 a general-purpose leaked-password list is mostly unreachable — the bundled corpus was rebuilt for exactly this reason (BACKLOG #1134), and a hashed HIBP export cannot be filtered this way at all, because a SHA-1 digest does not carry the entry's length |
| `lockout_threshold` | int | 5 | failed logins before lock (per account). One exception: while the credential in force is engine-generated (an administrator's account creation and both resets set it), wrong passwords are counted and audited but arm no sign-in lock (ADR 0197 Amendment A). The second-step lock arms as usual |
| `lockout_minutes` | int | 15 | lockout duration |
| `lockout_max_minutes` | int | 1440 | the **ceiling** an escalating lock doubles up to (ADR 0197, BACKLOG #1131). A lock doubles per cycle, `lockout_minutes` x 2^(cycle - 1), only where the owner has a way past it: the second-step lock on a local account, and the sign-in lock on a local account with TOTP enrolled, whose owner can sign in with the password and the authenticator code together. Every other lock keeps `lockout_minutes`. Must be at least `lockout_minutes`; set it equal to turn the escalation off. See [SECURITY.md](SECURITY.md), control 1 of the 6.1.1 protection set |
| `initial_password_expiry_hours` | int | 72 | **(ASVS 6.4.1):** an admin-issued initial/reset credential (a `must_change_password` temp password) that is never claimed **expires** this many hours after it was set. Without it an unused reset password grants an authenticated session indefinitely — and what it permits includes *setting the password*, i.e. account takeover. Keyed on `password_changed_at`; a user who set their own password has `must_change_password = false` and is unaffected. Past the deadline a session opened before it ends the first time it is presented, so it can neither set a new password with the credential ([BACKLOG #2009](BACKLOG.md)) nor finish the second factor ([BACKLOG #2298](BACKLOG.md)). `POST /me/password` and `POST /auth/mfa-verify` ask the deadline again during the request, and no sign-in ceremony re-keys a session once it has passed; a rotation that has passed its last check still completes. Every local account holding such a temporary password is in scope; the engine creates no default account. `0` = no expiry (not recommended on a PHI instance). **Reminder (ASVS 6.4.5, [BACKLOG #1141](BACKLOG.md)):** while such a credential is still unclaimed, an **`initial_credential_expiring`** [`[alerts]`](#alerts) event names the holder (as `user:<username>`) and the deadline once per engine process, in the last third of the window capped at 24 hours (24 hours at the default). At the same moment the holder, and the administrator who issued the credential, each get a security notice at their own notification address ([BACKLOG #2007](BACKLOG.md); see [`docs/SECURITY.md`](SECURITY.md)). The issuer is not told when the audit trail cannot say reliably who that was. None of the reminders has a setting of its own; at `0` nothing expires and none runs. The two notices travel as security notices, so they need `[auth].notify_security_events` and the `[alerts]` SMTP host and sender, not an `email_to`. The operator reminder needs an `[alerts]` **recipient** (`webhook_url`, or `email_to` beside the SMTP host and sender); without one it reaches only the log, so `serve` refuses under `enforce` and warns under `warn` ([BACKLOG #2008](BACKLOG.md); see `security_notifications_required` under [`[alerts]`](#alerts)). |
| `login_rate_limit_enabled` | bool | `true` | in-process sliding-window limiter on the **sign-in surface** — `/auth/login`, `/auth/negotiate`, `/auth/mfa-verify` plus the four console entry routes (`POST /ui/login`, `GET /ui/sso`, `POST /ui/oidc/start`, `GET /ui/oidc/callback`) — in front of the per-account lockout. `GET /ui/oidc/start` charges it only when its "you are leaving this site" page is skipped (see `[security].external_link_interstitial`). On shipped defaults that page is shown, and the GET charges nothing. The **same flag** also constructs the per-actor **credential-ceremony** limiter covering `/me/password`, `/me/reauth`, `/me/mfa/confirm` (+ the console re-auth routes); turning it off removes **both** (see [SECURITY.md](SECURITY.md) "Route → limiter map"). |
| `login_rate_limit_per_ip` | int | 10 | max attempts per client IP per window (`0` disables). **One number, two limiters:** it is also the per-**actor** budget of the credential-**ceremony** limiter (`/me/password`, `/me/reauth`, `/me/mfa/confirm` + the console re-auth routes) — the `_per_ip` name is historical, and retuning it retunes both |
| `login_rate_limit_global` | int | 60 | max attempts across all clients per window (`0` disables). Sign-in window only — the ceremony limiter has **no** global dimension (`glob=0`) |
| `login_rate_limit_window_seconds` | float | 60 | sliding-window length — shared by the sign-in window **and** the per-actor credential-**ceremony** limiter, exactly as `login_rate_limit_per_ip` is |
| `phi_read_rate_limit_enabled` | bool | `true` | per-actor anti-automation throttle (ASVS 2.4.1) — bounds scripted PHI harvesting on top of pagination + access auditing. Charged on **8 JSON routes** via `require_phi_read`, on the **4 bulk-PHI step-up GETs** at admission (`/messages/search`, `/messages/export`, `/uploads/{file_id}/messages`, `/search/layered` — `require_step_up` paces NON-GET only, so these charge it themselves), and on the **11 `/ui` PHI views** via `require_ui(…, phi=True)` |
| `phi_read_rate_limit_per_actor` | int | 120 | max PHI reads per user per window (generous — clears console/human use; `0` disables this dimension) |
| `phi_read_rate_limit_global` | int | 0 | max PHI reads across all users per window (`0` = off) |
| `phi_read_rate_limit_window_seconds` | float | 60 | sliding-window length |
| `admin_write_rate_limit_enabled` | bool | `true` | per-actor anti-automation pacing on the **state-changing admin surface** (ASVS 2.4.2) — **NON-GET only**, charged from one per-actor bucket by `require_step_up`, `require_step_up_action` and `require_paced`. Charged on the `/ui` surface too, by `require_ui` -- the console reaches the handlers in-process, so it re-applies the floor rather than inheriting it ([BACKLOG #287](BACKLOG.md)) |
| `admin_write_rate_limit_per_actor` | int | 12 | max state-changing admin writes per actor per window (`0` disables this dimension); there is deliberately **no global arm** — one operator's bulk work must never throttle another's |
| `admin_write_rate_limit_window_seconds` | float | 15.0 | sliding-window length, above 0. The default is a **provisional** human-timing floor ([BACKLOG #287](BACKLOG.md)). A script making more than 12 admin writes in 15 s is refused. Over budget → `429` + `Retry-After: 1` on the JSON API and `Retry-After: 10` on the `/ui` console, refused before any further work |
| `admin_write_min_interval_seconds` | float | 0.15 | the least time between two admin writes by one actor ([BACKLOG #2301](BACKLOG.md), ASVS 2.4.2). A write that lands sooner after the same actor's last admitted write is refused like an over-budget one, with the same `429`. The count above admits its budget back to back; this gap makes a burst wait. The default is a **provisional** human-timing floor from the keystroke-level model, derived in the comment on the setting. `0` turns the gap off. While `admin_write_rate_limit_enabled` is on, it must be shorter than `admin_write_rate_limit_window_seconds`, or the settings are refused at load |
| `notify_security_events` | bool | `true` | email the affected user on lockout / first-success-after-failures / password-email-role-disable changes (ASVS 6.3.5/6.3.7). Reuses the `[alerts]` SMTP transport, sent to the user's own address; no SMTP configured → email skipped. The `GET /me/security-events` feed (over the audit log) is always available regardless of this toggle. On a **PHI production** instance this push must be *effective* — see `[alerts].security_notifications_required` (BACKLOG #188). |
| `require_mfa` | | | **→ moved to `[security].require_mfa`** (ADR 0118) — set it there; no longer accepted in `[auth]`. |
| `require_mfa_scope` | | | **→ set it as `[security].require_mfa_scope`** (ADR 0118) — like its `require_mfa` sibling it is rejected in `[auth]`. |
| `totp_skew_steps` | int | `0` | TOTP clock-skew tolerance in 30 s steps applied at verify time (BACKLOG #187, ASVS 6.5.5). **Default `0` = STRICT: only the current 30 s step verifies** (tightest replay window — a captured code is valid at most for the rest of its own step). Set `1` (or `2`) — the documented opt-out — to restore RFC-6238 network-delay / clock-drift tolerance (`1` also accepts the immediately-prior and the fast-clock-clamped next step, i.e. the historical ±1 behaviour; the forward step is clamped to the current step so it never advances the single-use high-water mark). Range 0–2. |
| `mfa_recovery_code_count` | int | 10 | single-use recovery codes minted at TOTP enrollment (the lost-authenticator escape hatch; `0` disables them, leaving an admin reset as the only recovery path). Range 0–50. |
| `mfa_verify_min_elapsed_seconds` | float | 1.0 | the least time between sign-in and the second factor ([BACKLOG #2301](BACKLOG.md), ASVS 2.4.2). It covers a TOTP code, a recovery code and a passkey on an MFA-pending session. It also covers the two enrolment legs, `POST /me/mfa/confirm` and a passkey registration, when they would satisfy a pending session ([BACKLOG #2389](BACKLOG.md)). One that arrives sooner after the session was minted gets the leg's ordinary failure: `401 invalid code` on `POST /auth/mfa-verify`, `400 invalid code` on `POST /me/mfa/confirm`. The response says nothing about timing. It is audited with `reason=too_early`, charges no lockout and spends no code or passkey challenge. Under the default `require_action_step_up`, the confirm route has already spent its single-use password step-up, as it does for a wrong code. A session whose factor is already satisfied, or that owes none, is not floored. The default is a **provisional** human-timing floor from the keystroke-level model, derived in the comment on the setting. `0` turns it off |
| `admin_new_ip_step_up` | bool | `true` | admin-interface contextual-risk signal (WP-L3-13, ASVS 8.4.2): when on, a step-up (sensitive admin) request from a client IP the session has not verified from emits an `auth.admin_action_new_ip` audit + notice and **forces a fresh step-up** (a re-verify from that address clears it). Step-up-forcing only — never changes an RBAC decision. Since vault BACKLOG #2620 at least the PHI reads and the paced writes refuse a new address the same way, and the base gate never asks; [SECURITY.md](SECURITY.md#administrative-interface-defense-in-depth-wp-l3-13-asvs-842) names the gates. The audit + notice are debounced and capped per session in each engine process, as [SECURITY.md](SECURITY.md#administrative-interface-defense-in-depth-wp-l3-13-asvs-842) states. **On by default** since BACKLOG #288, and a no-op on loopback (`127.0.0.1` and `::1` are treated as one host). Setting it `false` is a **loosening** once auth is on — `security_loosenings()` names it; see [SECURITY-LOOSENING.md](SECURITY-LOOSENING.md). See [SECURITY.md](SECURITY.md) "Administrative-interface defense-in-depth". |
| `ad_enabled` | bool | `false` | **directory bind capability**: the engine binds to AD as the `ad_bind_dn` service account to resolve principals and their groups. Windows SSO (`kerberos_enabled`), OIDC (`oidc_enabled`) and the session reconciler each need it. It does **not** turn on a directory-password sign-in: that pathway is retired (BACKLOG #1137), and `POST /auth/login` with `provider=ad` is refused and audited. A bind **as the user** survives only as the step-up re-bind at `POST /me/reauth` and `POST /ui/reauth` |
| `ad_server` | str | — | e.g. `ldaps://dc1.example.com:636` (required when `ad_enabled`) |
| `ad_domain` | str | — | UPN suffix, e.g. `example.com` |
| `ad_user_search_base` | str | — | required when `ad_enabled` |
| `ad_group_search_base` | str | — | base for nested-group resolution |
| `ad_bind_dn` | str | — | service-account DN used for lookups. It must be able to read each user's `userAccountControl`: an account whose value it cannot read is refused at sign-in (BACKLOG #1639). The session reconciler reads it as **undetermined**, not absent. One undetermined answer strikes the way a disabled account does, but only when it is the only one the reconciler knows of across its rotation, the same pass read the attribute on another account, and no earlier wave has latched the hold. Otherwise the undetermined accounts are held: their sessions are not revoked and their strikes reset. Two or more known at once latch the hold, which then holds even a single one until none remains. The rest of the pass goes ahead, subject to the mass-revoke breaker ([ADR 0195](adr/0195-brake-the-ad-session-reconciler-on-an-undetermined-useraccountcontrol-wave.md)). |
| `ad_bind_password` | secret | — | supply via env (`MEFOR_AUTH_AD_BIND_PASSWORD`), or use `ad_bind_password_secret`. A value in the file is still accepted, with a WARNING at load; keep it out of the file |
| `ad_bind_password_secret` | str | — | connector `SecretProvider` reference (ADR 0019 §5) — when set and `[secrets].provider` is configured, the bind password is resolved from that backend (e.g. a Vault KV `path#field`) instead of `ad_bind_password`. A reference, not a secret. |
| `ad_use_nested_groups` | bool | `true` | resolve nested groups (`LDAP_MATCHING_RULE_IN_CHAIN`) |
| `ad_tls_verify` | bool | `true` | validate the LDAPS certificate |
| `ad_tls_ca_cert_file` | str | — | trust an internal CA for LDAPS without disabling verification. Read once at start, and every LDAPS bind trusts those bytes. **A changed file takes effect at the next restart.** The PEM rules, and what a reload does, are under `[api].tls_client_ca_file` (BACKLOG #2185) |
| `ad_tls_ca_cert_pin` | str | — | optional lowercase-hex SHA-256 pin over the corresponding CA anchor PEM (`ad_tls_ca_cert_file`); a mismatch refuses at load + reload (ASVS 6.7.1); unset = no pin (dormant); set but empty or whitespace refuses at load |
| `ad_allow_insecure_ldap` | bool | `false` | explicit opt-in to a non-`ldaps://` bind (trusted-network dev only). Inert under `[security].enforcement = enforce`; see its [SECURITY-LOOSENING.md](SECURITY-LOOSENING.md) entry |
| `ad_connect_timeout` | float | `10.0` | seconds — bounds the LDAP/LDAPS **TCP connect** on every `ldap3` `Server` the authenticator builds (ASVS 13.1.3). Must be finite and `> 0`; `0`, negative, `inf` and `NaN` are refused at config load, and so is anything above `3600`. `ldap3`'s own default is `None` (wait forever), so without this an unresponsive DC pinned a thread-pool worker indefinitely |
| `ad_receive_timeout` | float | `10.0` | seconds — bounds **each socket receive** during an LDAP response (both binds and every search) on every `ldap3` `Connection`. Same validation, up to `3600`. The engine rounds it up to whole seconds before handing it to `ldap3`, so `9.25` acts as `10` |
| `ad_session_recheck_seconds` | int | `300` | **Directory session reconciliation** ([ADR 0079](adr/0079-kerberos-idp-session-coordination.md) mechanism 2). How often to re-resolve directory principals holding **live** sessions and revoke those AD has disabled or deleted — without it, an AD disable does not take effect until the `[security].max_session_hours` cap (12 h). **`300` (five minutes) is the default** (ADR 0148 GIVEN 1 — the hardened path is the shipped path), floored at **60 s** (a pass costs one LDAP bind per signed-in directory user). `0` disables the loop and is a **loosening** once AD is on — `security_loosenings()` names it. The default is **inert without AD** (`should_reconcile()` also needs an LDAP client), so a non-AD deployment is unaffected; an **explicit** non-zero value without `ad_enabled` is still refused rather than left silently dead. |
| `ad_session_recheck_strikes` | int | `2` | Consecutive passes a principal must fail to resolve before its sessions are revoked. *The search matched nothing* cannot tell *deleted* from *moved out of the search base*, so a single ambiguous result must never revoke; a set disabled bit and an unreadable `userAccountControl` strike the same way. A wave of unreadable answers is held instead of revoked, with no setting ([ADR 0195](adr/0195-brake-the-ad-session-reconciler-on-an-undetermined-useraccountcontrol-wave.md)). Range 1–10. |
| `ad_session_recheck_max_users` | int | `200` | Per-pass bind budget. Beyond this, remaining users are picked up by later passes (least-recently-probed first), so a large estate degrades to a longer effective interval instead of a bind storm. |
| `ad_session_revoke_max` | int | `5` | **Mass-revoke circuit breaker**, absolute half. A bad search base / moved OU / service account that lost read rights on the entries answers "not found" for *every* user — indistinguishable from "everyone was deleted". A lost read right on `userAccountControl` alone is held instead ([ADR 0195](adr/0195-brake-the-ad-session-reconciler-on-an-undetermined-useraccountcontrol-wave.md)). |
| `ad_session_revoke_max_fraction` | float | `0.34` | Circuit breaker, proportional half. A pass exceeding **both** thresholds aborts, revokes nothing, logs at ERROR and writes an `auth.ad_reconcile_aborted` audit row. Requiring both means it fires only on a change simultaneously *large* and *broad* — the signature of a misconfiguration, not of offboarding (3-of-3 or 50-of-300 still applies). Range >0.0–1.0; `1.0` disables the proportional half. |
| `kerberos_enabled` | bool | `false` | Windows SSO (experimental, off by default; needs `ad_enabled`) |
| `kerberos_spn` | str | — | service principal, exactly `SERVICE/host`, e.g. `HTTP/host.example.com`. The engine splits it at the `/` into pyspnego's `service` and `hostname`. A malformed value is **refused at load**, including at least one with no `/`, more than one `/`, an empty half, whitespace or control characters, or a realm suffix (`HTTP/host@REALM`); the host's own domain supplies the realm. |
| `oidc_enabled` | bool | `false` | Federated SSO — OIDC auth-code + PKCE relying party ([ADR 0142](adr/0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md)). A third login for an identity that **already exists in on-prem AD** (needs `ad_enabled`; roles come from LDAP, not the token). Off = byte-identical **for an install with no bound account**. An account an administrator has bound to a federated identity signs in through the IdP only: Windows SSO refuses it whatever this key says, so turning this off leaves a bound account with no sign-in until it is unbound ([SECURITY.md](SECURITY.md#federated-sign-in-oidc-browser-only--adr-0142), vault BACKLOG #2609). Needs `[security].web_console_public_address` (the redirect origin). |
| `oidc_issuer` | str | — | https; exact-matched against the id_token `iss`. At most 256 UTF-16 code units, which is 256 characters for an ASCII URL, **refused at load** beyond that: an administrator's bind stores it, and the narrowest issuer column (SQL Server `NVARCHAR(256)`) holds no more (BACKLOG #2331) |
| `oidc_client_id` | str | — | also the required `aud`/`azp` |
| `oidc_client_secret` | str | — | confidential-client secret — supply via env (`MEFOR_AUTH_OIDC_CLIENT_SECRET`) or `oidc_client_secret_ref`. A value in the file is still accepted, with a WARNING at load; keep it out of the file |
| `oidc_client_secret_ref` | str | — | alternative: a `[secrets].provider` reference (`_ref`, not `_secret`, to avoid `oidc_client_secret_secret`). Setting it beside `oidc_client_secret`, or to whitespace only, is refused at load |
| `oidc_token_endpoint_auth_method` | str | `client_secret_post` | how the engine authenticates to the token endpoint (BACKLOG #296). `client_secret_post` sends the client secret above. `private_key_jwt` (OIDC Core section 9, RFC 7523) sends a JWT signed with `oidc_client_private_key` instead, valid for 120 s, with `iss` = `sub` = the client id, `iat`, a fresh `jti`, and **no secret**. The two are exclusive: under `private_key_jwt` a configured secret or secret reference is refused at load, and under `client_secret_post` any `oidc_client_private_key*`, `oidc_client_assertion_key_id` or `oidc_client_certificate` value, or a non-default `oidc_client_assertion_algorithm` or `oidc_client_assertion_audience`, is refused. Register the key's public half with the IdP first; the engine reads no discovery document, so it cannot check the IdP's `token_endpoint_auth_methods_supported` for you |
| `oidc_client_private_key` | str | — | the `private_key_jwt` signing key: inline PEM via env (`MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY`), or a path to a PEM file protected like a TLS key. Inline PEM in the config file is accepted with a WARNING at load; a path there is not warned about. Read at startup, so a missing, unreadable, encrypted-without-password, RSA-below-3072 or wrong-curve key refuses to start. `messagefoundry verify --section federation` loads it the same way |
| `oidc_client_private_key_ref` | str | — | alternative: a `[secrets].provider` reference holding the PEM itself; a reference that resolves to anything else, a file path included, refuses startup. Setting it beside `oidc_client_private_key` is refused at load |
| `oidc_client_private_key_password` | str | — | passphrase for an encrypted key; supply via env (`MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY_PASSWORD`). A value in the file is accepted with a WARNING at load |
| `oidc_client_assertion_algorithm` | str | `RS256` | one of `RS256`, `PS256`, `ES256`, `RS384`, `ES384`; must match the key (ES256 needs P-256, ES384 needs P-384). `none` and HMAC algorithms are not in the set and are refused at load |
| `oidc_client_assertion_key_id` | str | — | optional JWS `kid`, for an IdP that holds several keys for the client. A blank value, or one with leading or trailing whitespace, is refused at load |
| `oidc_client_certificate` | str | — | optional X.509 certificate holding the signing key's public half: inline PEM or a path to a PEM file (public, not a secret). When set, every assertion carries its `x5t#S256` thumbprint, which is how an IdP that registers a certificate rather than a key finds it (Entra ID; it also recommends `PS256`). A certificate that does not parse, does not hold the key's public half, or is outside its validity window refuses to start. Nothing watches its expiry after startup |
| `oidc_client_assertion_audience` | str | `token_endpoint` | the assertion's `aud`: `token_endpoint` sends `oidc_token_endpoint` (OIDC Core section 9; Entra ID and Okta require it), `issuer` sends `oidc_issuer` for an IdP that asks for its issuer identifier. Both are pinned and allow-listed, so the assertion is never addressed anywhere else |
| `oidc_authorization_endpoint` / `oidc_token_endpoint` / `oidc_jwks_uri` | str | — | https, **operator-pinned** (no `.well-known` discovery) |
| `oidc_allowed_endpoints` | list[str] | `[]` | defence-in-depth host allow-list; **refused empty when enabled**; every OIDC endpoint host must be listed |
| `oidc_tls_ca_cert_file` | str | — | the **engine's** back-channel TLS trust for the IdP (OpenSSL default trust ignores the Windows machine store). Read once at start and loaded as checked. **A changed file takes effect at the next restart.** The PEM rules, and what a reload does, are under `[api].tls_client_ca_file` (BACKLOG #1142, #2185) |
| `oidc_tls_ca_cert_pin` | str | — | optional lowercase-hex SHA-256 pin over the corresponding CA anchor PEM (`oidc_tls_ca_cert_file`); a mismatch refuses at load + reload (ASVS 6.7.1); unset = no pin (dormant); set but empty or whitespace refuses at load |
| `oidc_tls_crl_file` | str | — | optional PEM file of CRLs checked against the IdP's certificate on both legs (token and JWKS) (BACKLOG #299). A missing or blank path is refused when settings load, naming this setting, even with OIDC off (BACKLOG #1997). A file that is unloadable or past `nextUpdate` refuses at start. **Put only CRLs in it**: a certificate in it that is not already in the hop's trust store refuses start (BACKLOG #1890). On an enforcing instance an off-box IdP with no CRL here is refused when `serve` builds the auth service (BACKLOG #1887) |
| `oidc_redirect_path` | str | `/ui/oidc/callback` | joined to `web_console_public_address` for the redirect URI |
| `oidc_scopes` | list[str] | `["openid","profile"]` | no `email`, no `offline_access` |
| `oidc_signing_algorithms` | list[str] | `["RS256"]` | coerced through the closed JWS algorithm enum |
| `oidc_username_claim` / `oidc_username_strip_domain` | str / bool | `preferred_username` / `true` | strip the UPN suffix at the first `@`. The result is a hint only: since ADR 0184 the bound (issuer, sub) pair selects the account |
| `oidc_allowed_username_domains` | list[str] | `[]` | **defence in depth on the username claim.** Since ADR 0184 the bound (issuer, sub) pair selects the account, and the username claim selects none. The suffix is still checked because `preferred_username` is neither unique nor stable (OIDC Core §5.7) and is operator- or even self-editable on many IdPs. Before ADR 0184 this list was the control: without it a guest presenting `Administrator@attacker.example` stripped to `Administrator` and signed in as the on-prem Domain Admin. When `oidc_username_strip_domain` is on, the claim's UPN suffix **must** match one of these. Empty falls back to `ad_domain`; with neither set while stripping is on, `oidc_enabled` is **refused at load** rather than stripping unchecked. List the alternate UPN suffixes of a multi-domain forest here |
| `oidc_clock_skew_seconds` | int | `60` | wall-clock skew tolerance (0–300) |
| `oidc_require_mfa_claim` | bool | `true` | **#99(g) control** — refuse a token with no configured `amr`/`acr`. The engine verifies what the IdP **asserts**, not what it enforced |
| `oidc_mfa_amr_values` / `oidc_required_acr_values` | list[str] | `["mfa"]` / `[]` | either family satisfies the gate; both empty with the gate on is refused. Each value is stripped at load and a blank one dropped, in a TOML list as in an env string, so a list of blanks counts as empty ([BACKLOG #2325](BACKLOG.md)) |
| `oidc_acr_values` / `oidc_prompt` | str | — | requested authorize params. `oidc_acr_values` is a request only: the gate checks the returned `acr` against `oidc_required_acr_values` alone, and only while `oidc_require_mfa_claim` is on. So while `oidc_enabled` is on, a non-blank `oidc_acr_values` is **refused at load** if `oidc_required_acr_values` names no non-blank value (BACKLOG #2032). It is also refused while `oidc_require_mfa_claim` is off, whatever the required list holds (BACKLOG #2325). A whitespace-only `oidc_acr_values` loads as no request and is not sent. A token whose `amr` matches `oidc_mfa_amr_values` still passes whatever its `acr`; to rely on `acr` alone, also empty `oidc_mfa_amr_values` |
| `oidc_jwks_ttl_seconds` / `oidc_jwks_min_refetch_seconds` | int | `3600` / `300` | the JWKS cache TTL + the amplification (min-refetch) bound |
| `oidc_flow_ttl_seconds` / `oidc_flow_cache_max` | int | `300` / `512` | pending-flow TTL + the **reject-when-full** bound |
| `oidc_callback_min_elapsed_seconds` | float | 1.0 | the least time between a federated start and its callback ([BACKLOG #2301](BACKLOG.md), ASVS 2.4.2). A step-up callback that returns sooner is refused. A sign-in callback is refused the same way, but only when the verified `auth_time` shows the person signed in at the IdP during this flow: an IdP holding a live single sign-on session answers with no human step, and there is nothing to floor. The refusal is the leg's ordinary one (`federated sign-in failed`, or the generic step-up refusal), audited with `reason=too_early`. The default is a **provisional** human-timing floor, derived with `mfa_verify_min_elapsed_seconds`. `0` turns it off; it must be shorter than `oidc_flow_ttl_seconds` |
| `oidc_callback_floor_exempt_amr` | list[str] | `[]` | the `amr` values that mark a re-authentication with no human step, such as integrated Windows sign-in or a client certificate ([BACKLOG #2388](BACKLOG.md)). A sign-in or step-up callback whose signature-verified `amr` names one skips `oidc_callback_min_elapsed_seconds`. Every other callback keeps the floor. Values are stripped and a blank one dropped, as for `oidc_mfa_amr_values`. A value `oidc_mfa_amr_values` also accepts is **refused at load** while `oidc_require_mfa_claim` is on. The matched values are recorded as `callback_floor_exempt_amr`, under `evidence` on a sign-in's `auth.login_success` row and at the top of a step-up's `auth.reauth` row. With the list set, a too-early step-up's code is redeemed before it is refused, and a failed exchange is refused with its own reason. Any value is a **named loosening**: it proves a device answered, not that a person acted |
| `oidc_session_max_hours` | int | — | caps the federated session below `id_token.exp` if a tighter bound is wanted (ADR 0079 mechanism 1) |
| `oidc_max_age_seconds` | int | `43200` | the most time allowed between the user's sign-in **at the IdP** and the end of the engine session (ASVS 6.8.4 / 7.6.1, BACKLOG #1150). Sent as `max_age` on every authorization request; the `id_token` must return `auth_time`, a missing or stale one is refused, and the session ends at `auth_time + max_age` if that is sooner. `300`..`86400`; **no off switch** (`0` would be `prompt=login`, which ends single sign-on) |

> AD-group→role mappings live in the DB and are managed by an admin (`PUT /ad-group-map` or the
> console Users page), not in this file. Each group is named by its full distinguished name, such as
> `CN=MF-Admins,OU=Groups,DC=example,DC=com`; a short name is refused (BACKLOG #2610). Federated
> logins reuse the **same** AD-group→role mapping —
> the role source is on-prem AD, never a token claim ([ADR 0142](adr/0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md)).

#### When the reconciler's two alerts resolve themselves

The session reconciler's `ad_reconcile_aborted` (the breaker) and `ad_reconcile_held` (the hold)
alerts resolve on their own when a pass is evidence the condition has gone (BACKLOG #2136). So
does the referral's own `ad_reconcile_aborted` instance, under a separate source (below). This
needs alert state ([ADR 0044](adr/0044-operator-alert-state.md)). The pass must have an answer, from
this engine process, for every signed-in directory account it did not just revoke.

**An engine process resolves only an alert it watched open.** It resolves the breaker only after a
pass of its own tripped, and the hold only after a pass of its own held. It never resolves an
alert that was already open when it started, even after it trips or holds itself. A restart
forgets which accounts were behind a trip or a hold, and it cannot see the accounts that sign out
while the engine is down. So an operator resolves an alert the last run left open. After that, the
engine resolves the next trip or hold on its own.

- The hold resolves when no answer is undetermined and this pass read `userAccountControl` at
  least once. An account the pass just revoked still counts as an answer here.
- An engine can also give up resolving the hold. That happens when an account whose last answer
  was undetermined leaves, unless the engine has released a hold and has not held since. The
  reconciler may revoke it, or its sessions may end some other way. The engine then resolves no
  hold until its next restart.
- The breaker resolves when the pass did not abort, no answer is undetermined, no account carries a
  strike, and every account signed in at the last trip that is still signed in has read clean.
  So the breaker's alert stays open while a hold stands.
- An engine gives up resolving the breaker when an account signed in at the last trip leaves before
  it reads clean. Reading clean means a pass that did not abort found the account present and
  enabled. A held read, or one that adds a strike, does not count. The reconciler revoking the
  account counts as leaving. The engine then resolves no trip until its
  next restart. The engine logs a warning when it gives up any resolve.
- An LDAP referral opens its own `ad_reconcile_aborted` instance, with reason `directory_referral`
  and source `directory-reconciler-referral` (BACKLOG #2538). It follows the same rule: the engine
  resolves it only after a pass of its own saw a referral. It resolves once every account signed
  in at the last referral has since been read in full, present and enabled, on a pass with no
  referral. A pass with any referral resolves none of these alerts.
- So an account that never reads in full keeps the referral's alert open while it is signed in. A
  held account, a disabled one awaiting its strikes, and one that never answers all do this.
- An engine gives up resolving the referral when an account signed in at the last referral leaves
  before it reads in full. The reconciler revoking the account counts as leaving, including on the
  pass that saw the referral. The engine then resolves no referral until its next restart.
- A search base changes only on a restart, and a restarted engine resolves no alert its last run
  left open. So once you fix a referring base and restart, you resolve the referral's alert
  yourself. The engine resolves a referral on its own only when it clears without a restart, such
  as a directory-side change.

A pass judges only accounts that hold a session, and nothing reads an account again once it has
left. An account leaves at least when it signs out, reaches the session cap, is revoked by the
reconciler, is disabled locally, or is deleted. The give-up rules above stop an alert resolving
on the accounts that remain. The cost is a missed resolve when an account leaves for an ordinary
reason, such as a sign-out, while the evidence is still pending.

**They never resolve themselves on a `[cluster]` node or in an engine that runs more than one engine
shard.** Another engine's reconciler may still hold the condition there, so an operator resolves the
alert. A directory outage, a pass with nobody signed in, an account that never answers, and
`ad_session_recheck_seconds = 0` resolve nothing either.

At least one case can still resolve falsely. An engine that declares neither `[cluster]` nor more
than one engine shard trusts its own evidence, whatever else shares its store.

### `[ai]` — AI coding assistance policy
Implemented (see [AI.md](AI.md)). Controls the IDE AI assistant across the **OFF→PHI-safe** range;
the policy is centrally governed and **posture-clamped**. `mode`/`data_scope` plus the active
environment NAME + production tier (`environment` / `[security].production_instance`) govern the
policy — there is no data-class axis left to clamp against ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)); `provider`,
`model`, `endpoint`, `api_key` and `allowed_endpoints` are **live** under `mode = managed_endpoint` — the
engine broker ([ADR 0135](adr/0135-engine-brokered-ai-assistance-customer-managed-llm-egress-with-per-use-audit.md)).
Only `baa_attested` is still a forward-compat placeholder (accepted-but-ignored).
| Key | Type | Default | Notes |
|---|---|---|---|
| `mode` | enum | `byo` | `off` · `byo` · `managed_endpoint` · `managed_claude` · `managed_claude_baa`. **`managed_endpoint` is built** — the engine brokers one `code_only` prompt to a customer-managed / self-hosted LLM over `POST /ai/chat`, audited per use (ADR 0135); it never reaches `phi` scope. `managed_claude`/`managed_claude_baa` are **future** — not serviceable by the current IDE |
| `data_scope` | enum | `code_only` | `code_only` · `synthetic` · `deidentified` · `phi`, least→most sensitive; capped by `production` posture and by `mode` (only `managed_claude_baa` reaches `phi`) |
| `environment` | str | — | free-form active-environment **name** (ADR 0017); selects `environments/<name>.toml` + `current_environment()`. **Required** for `serve` (no default) |
| `data_class` | | | **→ REMOVED** ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)) — every instance carries patient data, so there is no data class to set. It moved to `[security].handles_real_patient_data` under ADR 0118 and that key is retired too; both spellings are refused at load. Relax the individual gate you mean instead. |
| `production` | | | **→ moved to `[security].production_instance`** (ADR 0118) — set it there; no longer accepted in `[ai]`. |
| `provider` | str | `claude` | names the provider the broker addresses, and is recorded in the per-use audit. It does **NOT** select a request shape — the broker builds one wire shape unconditionally (the Anthropic Messages body), and nothing dispatches on this value. **Validated at config load (BACKLOG #95):** only a provider the engine can actually service is accepted, so an unserviceable name is refused up front rather than failing at request time |
| `model` | str | `claude-opus-4-8` | the model the broker asks for; **read** under `mode = managed_endpoint` (also echoed on the reply) |
| `baa_attested` | bool | `false` | **accepted-but-ignored** — an operator attestation carried for the future `managed_claude_baa` path |
| `endpoint` | str | — | the customer-managed LLM URL. **Required** for `mode = managed_endpoint`; `http`/`https` only, and a cleartext `http` endpoint is **refused** (it would expose `api_key`) |
| `api_key` | secret | — | the LLM credential — **env only** (`MEFOR_AI_API_KEY`), never the file. **Required** for `mode = managed_endpoint` |
| `allowed_endpoints` | list | `[]` | fail-closed SSRF allow-list for `endpoint`'s host; each entry is `host` (any port) or `host:port`. **An empty list permits nothing** — deliberately independent of `[egress].allowed_http`, which is permissive when empty and so can't gate this surface |

> Only `code_only` context is ever sent in the MVP (graph names + active editor code) — **never
> message bodies**. The full resolution/clamping algorithm, the `GET /ai/policy` endpoint, the
> `messagefoundry ai-policy` CLI, and the `ai:assist` RBAC permission are documented in
> [AI.md](AI.md). Env keys: `MEFOR_AI_MODE`, `MEFOR_AI_DATA_SCOPE`, `MEFOR_AI_ENVIRONMENT`, etc.

### `[logging]`
| Key | Type | Default | Notes |
|---|---|---|---|
| `level` | enum | `info` | log level. `debug` can surface full message bodies / raw field values into the general log. **`serve` refuses `debug` on a `production_instance` only** (Gate #1, keyed on the production tier alone — see `[security].production_instance`). It is **not** keyed on PHI: since [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) a `dev`/`staging` instance also carries PHI, and one of those **will start at `debug` with nothing refusing**. Don't raise any PHI box to `debug` — the gate will not stop you. |
| `format` | enum | `text` | stdout rendering: `text` (default) or structured `json` (one object per line). Stdlib only — no structlog |
| `log_dir` | str | _unset_ | the directory NSSM (or another supervisor) **rotates the engine's captured stdout/stderr into**. The engine writes no log **file** of its own unless `file` below is set (opt-in, off by default); set this only to tell it where the supervisor parks the captured stdout, and `GET /status` then **meters that directory's total bytes + filesystem free space** alongside the DB metrics (#50). Unset = stdout-only, no metering. **Metadata only** — the file contents are never read. |
| `forward_enabled` | bool | _derived_ | ship a copy of every record off-box to a syslog/SIEM collector (sec-offbox-log) so evidence survives a host compromise. **Default-on-when-configured (ADR 0080):** unset ⇒ on iff `forward_host` is set. Set `false` to opt out even with a host; no `forward_host` ⇒ off (stdout-only, unchanged) |
| `forward_host` | str | — | syslog/SIEM collector host. Setting it turns forwarding on by default (above) |
| `forward_port` | int | `514` | collector port (1–65535) |
| `forward_protocol` | enum | `udp` | `udp` (fire-and-forget), `tcp`, or **`tls`** (RFC 5425 — native `ssl`-wrapped TCP, ADR 0080). A `tcp`/`tls` collector down at startup is retried from the on-disk spool (skipped with a warning when the spool is off), and a certificate that fails verification or a name that does not exist is a permanent ERROR; a runtime stall is bounded by a socket timeout (record dropped) and the TLS handshake is bounded too, so a wedged collector never blocks the engine. Synchronous send — prefer `udp`/a local agent for high volume |
| `forward_format` | enum | `json` | wire format sent off-box, independent of stdout `format`. JSON guarantees one record per line; `text` framing is best-effort (multi-line tracebacks span lines) |
| `forward_tls_ca_file` | str | — | PEM trust anchor for the collector's cert (**required** when `forward_protocol = "tls"` and verification is on). Only this CA is trusted — the public system bundle is **not** loaded, so an on-prem SIEM's private cert is anchored explicitly |
| `forward_tls_verify` | bool | `true` | verify + hostname-check the collector's certificate. `false` is the documented **insecure** opt-out (`CERT_NONE`, no CA file needed) — lab / pinned-network only |
| `forward_tls_client_cert` | str | — | optional PEM cert+key chain for **mutual** TLS to the collector |
| `forward_hop_attested` | bool | `false` | **acknowledged opt-out** for a plaintext / unverified-TLS collector hop (#200, ADR 0092 — the `[logging]` sibling of a connection's `tls_hop_attested`). A hop that is not verified TLS is now decided by the shared posture gradient: **refused** on an enforcing instance, warned on a non-enforcing one, allowed for a loopback collector. The synthetic arm is gone with the declaration that fed it ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)). Set this (with a reason) to affirm the hop is secure by other means — e.g. a dedicated out-of-band management VLAN |
| `forward_hop_attested_reason` | str | — | why the hop is secure, recorded for the audit trail. **Mandatory when `forward_hop_attested = true`** (ADR 0153 retro-fitted the flag-implies-reason rule: an attestation that suppresses a refusal must record WHY, or it is worthless when audited) — the flag alone now fails at load. Rejected without the flag, and must be non-empty |
| `forward_spool_dir` | str | `log-spool/<engine or shard id>` beside `[store].path` | the on-disk spool behind the forwarder (BACKLOG #1966, ADR 0200). Records the collector has not taken (down, backing off, or still queued at shutdown) are kept here in order and sent when it answers. Best effort, not at least once: after a collector reset the first send on the dead connection can be lost, a restart can resend up to one segment (12.5 MB at the default cap), and over UDP no failed send is detected (ADR 0200). It holds only text the PHI, credential and control-character filters already processed; PL-1 like the app log ([PHI.md](PHI.md) section 2). Each engine shard gets its own subdirectory, because the spool locks its directory. With a spool, a TCP or TLS collector down at start is retried instead of dropped for the process life |
| `forward_spool_max_bytes` | int | `100000000` | cap on the spool's size on disk. When full, the newest record is dropped and the drop reported, which keeps the oldest evidence. `0` turns the spool off, and with it the deferred start. It does NOT turn off the forwarding start gate: under `[security].enforcement = "enforce"` a PHI instance refuses to start unless forwarding is verified TLS (`forward_protocol = "tls"`, verification on) to a `forward_host` that is not loopback, whatever the spool (BACKLOG #1966, owner ruling R4 (a)). The gate reads configuration only; a host name that resolves to loopback passes it, a residual #1199 owns |
| `require_time_sync` | bool | `false` | **opt-in** startup clock-sync gate (ASVS 16.2.2, ADR 0080): before listeners start, probe `ntp_peer` and warn on skew. Requires `ntp_peer`. Default = no-op |
| `ntp_peer` | str | — | NTP/SNTP host to compare the local clock against (**required** when `require_time_sync`) |
| `time_sync_max_skew_seconds` | float | `2.0` | \|local − peer\| above this is "skewed" (must be > 0) |
| `time_sync_fail_closed` | bool | `false` | **refuse to start** (instead of warn) on skew or an unreachable peer. Further opt-in; requires `require_time_sync` |
| `file` | str | _unset_ | **opt-in application-log file the ENGINE owns end to end** (#122, ADR 0162) — it opens it, size-rotates it, and rolls it aside on a write failure. Distinct from `log_dir` above, which is where the **supervisor** parks the captured stdout: **one file, one rotation owner**, so a `file` inside `log_dir` is **refused at load** rather than left to fight NSSM. Unset (the default) = stdout-only, unchanged. A path the engine cannot open **refuses startup** — an engine that starts unable to log is the blindness this closes |
| `file_max_bytes` | int | `50000000` | size-rotate `file` at ~50 MB (`0` = never rotate on size). Engine-side rotation, unrelated to NSSM's. The legacy planned spelling `max_bytes` is **refused at load** naming this key, rather than silently ignored -- from the file by the unknown-key refusal, and from `MEFOR_LOGGING_MAX_BYTES` by a `[logging]` validator, which is the layer the general file refusal does not reach |
| `file_backup_count` | int | `5` | how many `file.1` … `file.N` backups to keep. The legacy planned spelling `backups` is likewise refused on both layers, though only the env one names this key: the file refusal's nearest-name hint does not reach it. The `*.broken-*` files a write failure rolls aside are **deliberately outside** this chain — they are incident evidence, and a rotation that could delete them would delete the record of the failure |
| `on_write_failure` | enum | `stop` | **fail-closed control (#122):** when a log sink cannot be written **and** the fresh sink rolled into its place cannot be written either, stop every connection this engine **process** owns, in all three tiers — inbounds stop accepting, messages already accepted stop being routed and transformed, and outbounds pause with their queued rows **retained** (never dead-lettered). Recover by **fixing the log and then** restarting the affected connections, inbound **and** outbound (or the service): a `/config/reload` re-arms the inbounds it re-binds but deliberately never resumes a paused outbound, so on its own it moves the backlog one stage and stops. Every re-arm path is **gated on the log working again** — the engine re-checks by writing a real record to each dead sink at the moment you ask, and a restart issued against a still-unwritable log is **refused** (the connection stays halted, its listener stays down, and another `log_write_failed` names the refusal), so restarting repeatedly is not a way around the control. A first failure alone never stops anything; the roll absorbs the transient. Scope is the process because the application log is process-global and no per-connection attribution exists (ADR 0162 §4); under engine sharding that is the shard's connections. `continue` is the documented opt-out — it still rolls and still alerts, it just keeps processing with no log. The stop is announced by a `log_write_failed` alert through the notifier, a `connection_stopped` per halted connection naming the cause, and `GET /status`'s `log_sinks` block |

> PHI redaction + control-char scrubbing are **always-on handler filters** (not a toggle) applied to
> **every** sink, including the off-box forwarder ([`logging_setup.py`](../messagefoundry/logging_setup.py),
> `_install_phi_filters`). **What they are is a conservative *redaction*, not de-identification**
> ([`redaction.py`](../messagefoundry/redaction.py)): a stdlib-regex pass over HL7 segment/field-delimited
> spans plus a free-text date/DOB and multi-token-name heuristic, erring toward over-redaction. Its own
> named residual is **an adversarially-crafted single-token or non-name-shaped identifier** — a lone MRN
> or surname with no second token and no delimiter — for which *"never put PHI in an exception message"*
> remains the control. So "always-on, every sink" is the coverage guarantee; it is **not** a guarantee
> that PHI cannot reach a log. Size log-handling risk accordingly, and keep `level` off `debug`.
> For an encrypted hop set `forward_protocol = "tls"`
> (native RFC 5425, no agent needed); the one plaintext alternative that still starts on a stock
> instance is a **loopback** `udp`/`tcp` forward into a local TLS-forwarding agent. "Plaintext across
> a trusted network" is **not** an option you can simply choose — an off-box plaintext hop is refused
> on an enforcing PHI instance and needs the explicit `forward_hop_attested` + reason below.
> See [PHI.md §7](PHI.md#7-logging--phi-redaction) and
> [ADR 0080](adr/0080-offbox-forwarding-tls-defaults.md).
>
> **The plaintext default is now gated, not silent (#200, ADR 0092).** The forwarded stream gets
> only best-effort PHI redaction and still carries usernames, connection names, message ids, client addresses, and the
> tamper-evident audit chain. `serve` therefore decides the forwarding hop with the **same** authority
> the transports use, *before* the handler is installed: a hop that is not verified TLS is **refused**
> on an enforcing instance, **warned** on a non-enforcing one, and **allowed** for a loopback
> collector. That loopback allowance is this hop check only: since BACKLOG #1966 the separate
> forwarding start gate refuses a loopback collector on an enforcing PHI instance, so "plaintext to
> `127.0.0.1` + a local agent" no longer starts under `enforce`. There is no
> longer a synthetic arm to fall into. To keep a plaintext off-box hop, either move to `forward_protocol = "tls"` or set
> `forward_hop_attested` with a reason — an acknowledged escape, not a silent default.

### `[retention]`
Enforced by the engine's retention/purge task ([pipeline/retention.py](../messagefoundry/pipeline/retention.py)).
A purge **NULLs the PHI *body*** past its window while **keeping the message row** (counts,
disposition, and the audit trail stay intact — the Mirth Data-Pruner pattern); it never deletes a
`messages` row and never touches a body still in flight. The *row* survives; its PHI *columns* do not
— `messages.metadata` is nulled in the same statement as the body (ASVS 14.2.7). The raw `[retention]` windows still default to
`0`/`""` = keep/off (the one default-on key, `min_free_disk_mb`, is a free-space floor and purges nothing), **but `serve` applies a posture gate on top of them, so retention is *not*
opt-in on a PHI instance**: each *unset* window that carries an auto-bound —
`[security].delete_message_bodies_after_days`, `[retention].dead_letter_days` and
`[retention].reference_snapshot_days` — is **defaulted to 30 days** at startup, under **both**
`[security].enforcement` dials, and the defaulted settings are named on stderr. A window set
**explicitly to `0`** is not defaulted: that **refuses to start (exit 2)** under `enforce`, and warns
under `warn`. This paragraph used to state the opposite split — refusal under `enforce`, auto-bound
only on a non-enforcing instance — which the shipped gate in
[`__main__.py`](../messagefoundry/__main__.py) refutes; an *unset* window has not refused since the
auto-bound moved to both dials. All three built-in environment names (`dev`, `staging`, `prod`)
derive PHI. The audited opt-out is `[security].allow_keeping_phi_indefinitely = true`, which
suppresses the auto-bound as well as the refusal. **Thirty days is the engine's floor against an
accidentally unbounded window, not your retention policy — set each window to the number your site
actually requires.** See [PHI.md §8](PHI.md#8-retention--purge).

The other classified tiers are never defaulted (owner ruling 2026-07-30), but they are not optional
either (owner ruling of 2026-09-24, BACKLOG #1967). Each needs a window or its own audited
acknowledgement. Under `enforce`, a tier with neither **refuses to start (exit 2)**, and the refusal
names the tier and its switch. Under `warn` it warns and starts. A start under an acknowledgement writes
a WARNING-level `AUDIT:` line naming the tier. `allow_keeping_phi_indefinitely` does not count for
these tiers, and one tier's switch does not cover another.

| Tier | Applies when | Its acknowledgement |
|---|---|---|
| `[retention].state_max_age_days` | always | `[security].allow_keeping_transform_state_indefinitely` |
| `[retention].search_preset_days` | always | `[security].allow_keeping_search_presets_indefinitely` |
| `[retention].app_log_days` | `[logging].log_dir` is set | `[security].allow_keeping_app_logs_indefinitely` |
| `[backup].retention_keep` | `[backup].destination` is set and `retention_keep = 0` | `[security].allow_keeping_backup_archives_indefinitely` |

**For transform state, choose the acknowledgement, not a window.** `purge_state` deletes by the time an
entry was last *written*, and a read never refreshes that time. So any window can delete a correlation
entry a Handler still reads. That stays true until state has an eviction key that a read moves.

| Key | Type | Default | Notes |
|---|---|---|---|
| `messages_days` | | | **→ moved to `[security].delete_message_bodies_after_days`** (ADR 0118) — set it there; no longer accepted in `[retention]`. |
| `dead_letter_days` | int | `0` | past N days, null the bodies of **dead-lettered** rows at **every stage**. A dead `ingress` or `routed` row carries the whole raw body, so the purge reaches it as well as a dead outbound row (BACKLOG #1188). This is their own window, because a dead row stays replayable until purged. Unset or `0`, this global window meets the startup posture gate described above this table; `0` = keep only where that gate allows it. An outbound's own `dead_letter_days` overrides it for that outbound's dead rows only (see *Per-connection overrides* below). The gate does not read that override. A dead row at any other stage always takes this global window. *Corrected 2026-09-28 (BACKLOG #1186):* this row used to scope the purge to outbound rows, which BACKLOG #1188 made false. |
| `allow_unbounded_phi` | | | **→ moved to `[security].allow_keeping_phi_indefinitely`** (ADR 0118) — set it there; no longer accepted in `[retention]`. |
| `state_max_age_days` | int | `0` | past N days, **delete** transform-state entries (ADR 0005) last written before the cutoff — keeps the in-memory state cache + table bounded. A simple global age purge (by `set_at`); per-namespace policy is a follow-up. `0` = keep |
| `connection_event_retention_hours` | int | `0` | past N **hours**, **delete** `connection_event` rows (the `[diagnostics]` #46 transport/lifecycle log — high-volume under a connect-per-message sender or a probe storm, so its own short window in **hours**, not days). `0` = inherit the `messages_days` body window (the ADR 0021 §7.5 default). |
| `app_log_days` | int | `0` | past N days, **delete** application **log files** (`.log`/`.txt`, one level) from the configured `[logging].log_dir` (#120). The supervisor (NSSM `AppRotateBytes`) rotates the daily logs by **size** but never by **age**, so the log dir grows unbounded; this bounds it (by file mtime, so the currently-written file is never eligible). `0` = keep. **No-op unless `[logging].log_dir` is set.** Metadata only — file content is never read. While `app_log_compress_days` is on, the same window also ages out the `*.log.gz`/`*.txt.gz` archives that setting produces — so compressing a log doesn't make it immortal; with compression off the eligible set is exactly what it was |
| `app_log_compress_days` | int | `0` | past N days, **gzip** application **log files** (`.log`/`.txt`, one level — the same selection as `app_log_days`, by mtime, so the currently-written file is never eligible) in `[logging].log_dir` to `<name>.gz` (#119). The log stays readable (`gzip -d`) at a fraction of the disk, so a long-running box keeps far more history for the same footprint. Each file is **free-space prechecked** (`shutil.disk_usage` must show room for the source **plus** its archive plus a `max(10%, 1 MiB)` margin — short, and the file is **skipped and logged**, never attempted) and each written archive is **integrity-validated** — staged to an **exclusively created, randomly named** temp file beside it (`tempfile.mkstemp`: `O_CREAT\|O_EXCL`, so it never truncates an existing file, never follows a symlink, and never collides with a sibling engine shard compressing the same directory), `fsync`ed, re-read **off disk**, decompressed and compared **byte-for-byte** against the original, renamed into place, and then **validated again at `<name>.gz` itself** — and it is that last check, on the bytes actually sitting where the log used to be, that authorizes removing the original. Any failure leaves the original **in place**, does not count it as compressed, and logs it; an existing `<name>.gz` is never clobbered. The archive inherits the source's mtime, so `app_log_days` still ages it out. Files over 64 MiB are skipped (the codec is in-memory), and so is a file whose archive would not be **smaller** than it (an empty or already-compressed log — compressing must never *cost* disk). Names/counts/sizes are logged, **never file content**. `0` = never compress. **No-op unless `[logging].log_dir` is set.** Set it **shorter** than `app_log_days` — a longer window compresses nothing, since the delete sweep runs first |
| `search_preset_days` | int | `0` | past N days, **delete** saved-search presets (ADR 0136) neither used nor edited since the cutoff. The stored `criteria` is the operator's own content/`field_value` needle — **PHI-shaped by construction**, encrypted at rest — so it needs a window like any other PHI tier (ASVS 14.2.7). The whole **row** is deleted, not blanked: a preset's entire payload *is* its criteria. **Keys on last-USED** (BACKLOG #306) — the cutoff is compared against the *later* of `updated_at` (written by a save) and `last_used_at` (written by a recall), so a preset you run daily but never re-save is **kept**. A preset last touched before the `last_used_at` column existed has it NULL and ages out on `updated_at` alone. `0` = keep forever (the default) |
| `audit_days` | int | `0` | **reserved / not enforced — keep-forever by design.** The rationale rests on the **audit-retention requirement** (45 CFR 164.316(b)(2)(i) six-year documentation retention; every framework floor is far below it — CIS Control 8.10 is 90 days, PCI DSS 4.0 §10.5.1 is 12 months, NIST SP 800-53 AU-11 defers to organizational policy), **not** on chain-breakage. *Corrected 2026-07-30:* this row used to argue "deleting rows would break the chain". That is true only of deleting the **oldest** rows, and it is exactly **inverted** for the threat that motivates audit retention — `MessageStore.verify_audit_chain`'s own docstring (`store/store.py:7535-7537`, and its `audit_anchor` sibling at `:7513-7518`) records that deleting the **newest** rows is *not* caught by the walk alone, because the surviving prefix still chains cleanly. An attacker hiding what they just did truncates the newest rows. *Updated 2026-08-04 ([BACKLOG #328](BACKLOG.md)):* **the anchor is now reachable from the CLI**, which is the condition this row set for changing this paragraph. `messagefoundry audit-anchor` prints `COUNT:HEAD`, and `messagefoundry audit-verify --expected-anchor COUNT:HEAD` (or `--expected-anchor-file PATH`) passes it back into `verify_audit_chain(expected_anchor=...)` (`_audit_verify`, `__main__.py:3727`). **A bare `audit-verify` is still clean after a tail-truncation** — that has not changed and is not a bug; the walk cannot see it, which is the entire reason the anchor exists. **Read the anchor's semantics before relying on it: it is an EXACT point-in-time seal, not a monotonic-prefix check.** It compares the row count *and* the head hash, so an anchor taken before any subsequent audit row reports `truncated or rewritten` on a chain that merely **grew**. It therefore seals a chain **at rest between two offline checks** — quiesce the engine, anchor, hold the value off-box, re-verify while the chain is still quiesced (across a maintenance window, a DB move, a backup/restore, a custodian hand-off) — and nothing else: anchoring and immediately re-verifying compares a value to itself, and re-checking a held anchor against a **running** engine alarms every boot. Do not write a compliance job that stores one anchor and re-checks it against a running engine; for a running engine the off-box tee is still the control. Do **not** restore the chain-breakage argument as the *reason* this key is reserved. *Confirmed by measurement 2026-09-03 ([BACKLOG #1421](BACKLOG.md)):* six rows were driven through the real `record_audit` against a throwaway store, deletion shapes applied out-of-band, and the walk re-run each time. At least these hold — an interior delete and an oldest-first delete each fail it, a newest-first delete verifies clean, and rows archived out and re-inserted **with their original `id` and `row_hash`** verify while the same content appended at the tail as new ids does not. **That last result is the archive contract.** Archive-first pruning stays the open path and is a tracked follow-up; an export that keeps row content but drops `id` or `row_hash` cannot be restored into a chain that verifies, so an archive format has to carry both. **No bound is sized here.** **This row is the source of record for the chain-truncation reasoning, and the other records now point here instead of restating it** — `config/settings.py`'s `audit_days` comment, `config/retention_classification.py`'s header, and `docs/PHI.md` §2/§7/§8 were reconciled against this row on 2026-09-03; `docs/PHI.md` §8 carries the retention-window inventory |
| `max_db_mb` | int | `0` | advisory only: warn (WARNING log + an `AlertSink` `storage_threshold` event) when the database exceeds this — measured as the **SQLite file + `-wal`/`-shm`**, `SUM(size)` over `sys.database_files` on **SQL Server**, and `pg_database_size()` on **Postgres**. Never auto-deletes. `0` = off |
| `min_free_disk_mb` | int | `1024` | the **low-disk storage floor** (BACKLOG #290), in **MiB free** on the volume that holds the **SQLite** store file. **On by default**: 1024 MiB is 1 GiB, the same line the DR-backup preflight already treats as low space. Below it, `serve` **refuses to start (exit 2)** and names this key; the check runs under both `[security].enforcement` dials. While the engine runs, each retention pass logs a **WARNING** while free space stays below it, and the engine **pauses intake** below it, resuming at the floor plus a tenth (the same pause as `[inbound].max_staged_depth`, whose row says how each inbound honours it). It never deletes, drops or NAKs anything. If the store's directory does not exist yet, the nearest existing parent is measured. If free space cannot be measured at all, `serve` warns and starts. **SQLite only**: on SQL Server and Postgres the disk belongs to the database server, so `serve` logs one INFO line and skips the floor. This measures the **volume**, not the store's own size, so it does not overlap `max_db_mb`. `0` = off |
| `purge_interval_seconds` | float | `3600` | how often the purge/maintenance loop runs a pass |
| `max_pass_seconds` | float | `0` | maximum wall-clock seconds **one maintenance pass** may spend (#121, [ADR 0137](adr/0137-time-boxed-retention-maintenance-pass-between-phase-cap.md)). A **between-phase soft cap**: `run_once` checks elapsed monotonic time before each phase and, once this is reached, **skips the remaining phases** (marking the pass `capped`) so a long pass can't run unbounded into the next maintenance window — the skipped tail re-runs next interval, and a skipped WAL-checkpoint/VACUUM does **not** advance its last-run marker. Checked only *between* phases, never inside one, so a running VACUUM is non-interruptible. `0` = off (the default — no cap); ~`14400` (4 h, the Corepoint off-peak ceiling) is the recommended value when enabled |
| `wal_checkpoint_seconds` | float | `0` | `PRAGMA wal_checkpoint(TRUNCATE)` cadence (PASSIVE, which does not truncate, while a DR snapshot copy runs; BACKLOG #1937) — **SQLite only; a documented no-op on SQL Server and Postgres**, where log management is a DBA operation. `0` = off (rely on auto-checkpoint). Evaluated once per pass, so a value below `purge_interval_seconds` is effectively rounded up to it |
| `vacuum_at` | str | `""` | daily local `"HH:MM"` to run `VACUUM` (reclaims space freed by purges) — **SQLite only; a documented no-op on SQL Server and Postgres**, where space reclamation is a DBA operation. `""` = off. A daily off-peak time, **not** a cron expression (no new dependency); VACUUM holds a write lock on the whole DB while it runs |

> **Per-connection overrides ([ADR 0027](adr/0027-per-connection-retention.md)).** `messages_days` and
> `dead_letter_days` are **global defaults** an individual connection may override: an **inbound** sets its
> own `messages_days`, an **outbound** its own `dead_letter_days` (both `None` = inherit this global window,
> `0` = keep that connection's bodies forever, `>0` = days). An inbound may also opt into **embedded-document
> pruning** (`prune_documents_after` + `prune_documents_min_bytes`, [ADR 0042](adr/0042-embedded-document-pruning.md))
> to strip bulky base64 attachments while keeping the readable message. These live on the connection (code-first
> or in `connections.toml`) — see [CONNECTIONS.md](CONNECTIONS.md).

> **Backend coverage.** The retention/purge pass is **backend-agnostic** and every PHI purge runs on
> **all three** backends (SQLite, SQL Server, Postgres). `wal_checkpoint_seconds` and `vacuum_at` are
> SQLite-only: on the server backends those methods are documented no-ops, and log management / space
> reclamation (plus the DB-tier `[backup]` snapshot) are DBA operations there. `min_free_disk_mb` is
> SQLite-only too, and it is the one backend branch in `pipeline/retention.py`: the runner skips the
> free-space probe unless the store is SQLite. Each pass that does real work
> writes one `retention_purge` `audit_log` entry (cutoffs + counts, **no** message content).
> Per-backend table: [PHI.md §8](PHI.md#8-retention--purge).

### `[update_check]`
Engine-side version-update check ([ADR 0026](adr/0026-off-box-egress-update-check.md)). The MVP is a
**no-network "pinned-vs-current" diff**: it compares the running `messagefoundry.__version__` against the
version in the installed distribution metadata (`importlib.metadata`) / the bundled `requirements.lock` —
**zero outbound traffic**. The result is one additive `/status` field and (optionally) one `update_available`
AlertSink event that the console/IDE render as a dismissible banner — **the console/IDE never call PyPI**.
Because the local diff is cheap and PHI-safe it is **on by default** (zero phone-home risk).
| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | emit the `/status` field + the `update_available` alert. `false` = suppress both |
| `check_interval_seconds` | float | `86400` | diff cadence (the diff is trivial; daily is ample). Must be `> 0` |
| `mode` | str | `"local"` | the no-network diff (the only MVP value). `"live"` (the constrained-egress path, ADR 0026 §2) is **defined but rejected at load**, so a config can never silently turn the check into a phone-home out of a PHI system |
| `index_url`, `index_allowed_hosts` | str / list | unset | forward-compat for the future `"live"` mode only — **accepted-but-unused** in the MVP |

### `[delivery]`
| Key | Type | Default | Notes |
|---|---|---|---|
| `retry_max_attempts` | int | `100` | attempts before a delivery dead-letters. **Finite by default** (BACKLOG #1051): 100 attempts under the backoff below is a 28,215 s / 7 h 50 m 15 s window, long enough to ride out a partner outage without letting a lane wedge indefinitely. Safe as a default because attempts are counted **per row** (an outage burns the cap on roughly the lane heads, not the backlog) and an exhausted row **dead-letters into the replayable DLQ**. Raise or lower it freely, but note the two edges: retry-forever has a TOML/env spelling — in **this file, `messagefoundry.toml`**, `retry_max_attempts = "forever"` under `[delivery]` (case-insensitive; also `MEFOR_DELIVERY_RETRY_MAX_ATTEMPTS=forever`) is coerced to `None` at load (BACKLOG #1217) — while `""`/`none`/`null` remain load errors; **a per-outbound override is a different file and a different key** — `connections.toml`, `[outbound.retry]`, `max_attempts = "forever"`, since `connections.toml` has no `[delivery]` table and no flat `retry_max_attempts` key (under FIFO that head then blocks its lane until it succeeds or is purged); and **`0` or a negative value is now REFUSED at load** (`ge=1`, BACKLOG #1051). It used to be accepted and dead-letter on the FIRST failure — the check is `attempts >= max_attempts` against a post-increment count, so `0` gave up immediately while *reading* like "no limit". That is why the floor is on this key rather than a documentation note. **The floor is on this operator-facing setting ONLY:** the code-first `retry=RetryPolicy(max_attempts=0)` stays legal and is the deliberate idiom for a permanent, no-retry failure. A permanent `AR` reject fails fast regardless. |
| `retry_backoff_seconds`, `retry_backoff_multiplier`, `retry_max_backoff_seconds` | num | 5 / 2 / 300 | exponential backoff between attempts (per-outbound `retry=` overrides): the delay is `min(retry_max_backoff_seconds, retry_backoff_seconds * retry_backoff_multiplier ** (attempt - 1))`, and once it reaches the cap it stays there at any attempt count, including under retry-forever. **Bounded, and refused at load otherwise** (vault BACKLOG #2761): the base and the cap must be greater than 0 and the multiplier at least 1, all three finite. A zero or negative base would retry a down partner in a tight loop. The per-outbound `retry=` / `[outbound.retry]` fields carry the same bounds. |
| `ordering` | enum | `fifo` | default queue ordering per outbound: `fifo` (strict in-order, head-of-line on failure) or `unordered` (batch + rotate-past-failures). `unordered` isolates a stuck message and never adds concurrency — a lane sends one message at a time either way. It works in both claim modes. Switching a lane that is already running from `fifo` to `unordered` takes effect at the next engine start, not on reload. Per-outbound `ordering=` overrides. |
| `internal_error` | enum | `continue` | what a delivery worker does on an **internal/code error** (a non-`DeliveryError` exception from `send` — our bug, not the partner's): `continue` (dead-letter the row + advance) or `stop` (halt the connection's worker, preserve the message for replay, raise a `connection_stopped` alert). Per-outbound `internal_error=` overrides. Partner NAKs / transport failures are unaffected. |
| `buildup_max_depth` | int | _unset_ | raise a `queue_buildup` alert when an outbound lane's pending depth reaches this. Unset = depth dimension off (a healthy ceiling is throughput-specific, so there's no safe default). Per-outbound `buildup=BuildupThreshold(...)` overrides. |
| `buildup_max_oldest_seconds` | num | 300 | raise `queue_buildup` when the lane's **oldest** pending message has waited this long (a stuck head retrying its way toward the cap is the classic cause). On by default — a head stuck >5 min is a problem in any environment. Set to unset/`0`-disable via a per-outbound override. The same age also pages a row held **in flight** that long since its claim, on every stage, read every 30 s (BACKLOG #1611). A store fault between a claim and its handoff can leave such a row in flight until a store recovery path re-pends it, and the pending age cannot see it. |
| `stall_max_oldest_seconds` | num | _unset_ | raise a `message_stall` alert (Corepoint "Max Message Stall", [ADR 0014](adr/0014-alerting-rules-engine.md)) when an outbound lane's **oldest undelivered message** has waited this long. **Unset (the default) = the stall alert is OFF** — deny-by-default/opt-in, because it overlaps `buildup_max_oldest_seconds`'s age dimension and would double-page if both fired. Set a threshold to turn it on; a per-outbound `stall=StallThreshold(...)` overrides it. The stall event routes through `[[alerts.rules]]` like any other ([ADR 0014](adr/0014-alerting-rules-engine.md)). When on, it also fires for a row held in flight that long since its claim (BACKLOG #1611). |
| `saturation_sustain_samples` | int | _unset_ | raise a `saturation` alert (BACKLOG #93, [ADR 0014 amendment](adr/0014-alerting-rules-engine.md)) when an outbound lane's pending backlog is **rising sustained** over this many consecutive samples — the queue **derivative** (ingest > drain), distinct from the absolute depth/age ceilings above. A bursty-but-**draining** lane (spike then fall) never fires; only a lane whose depth climbs monotonically does. **Unset (the default) = OFF** — deny-by-default/opt-in (it overlaps `buildup_max_oldest_seconds`'s age dimension). Floor of 2 (fewer can't tell a burst from sustained growth). Global-only for now; a per-outbound override is a documented follow-up (a `[[alerts.rules]]` `connection` glob with `transports = []` can suppress it for a known-bursty feed in the interim). |
| `priority` | enum | `normal` | **global DR / priority tier default** for every connection (#61, [ADR 0048](adr/0048-third-tier-disaster-recovery-standby.md)). A connection declaring no `priority=` of its own inherits this; resolution order is per-connection override > this global default > the built-in `normal`. The total order is `critical > normal > low`, and the [`[dr]`](#dr--third-tier-disaster-recovery-standby) run-profile starts only connections whose resolved rank is at or above `[dr].priority_threshold`. It governs **when a connection runs**, never what it does. `normal` keeps every connection at the same tier, so a deployment that never enables DR is byte-unchanged. An unknown value fails config load. |
| `outbox_workers` | int | — | **REFUSED** — not a `DeliverySettings` field, and an unrecognized key now fails the start rather than loading silently. Worker topology is set by `[pipeline].claim_mode` today |
| `dead_letter` | enum | — | **REFUSED** — not a `DeliverySettings` field, and an unrecognized key now fails the start rather than loading silently. A finite `retry_max_attempts` is what dead-letters a row today |

### `[pipeline]`
| Key | Type | Default | Notes |
|---|---|---|---|
| `max_correlation_depth` | int (≥1) | 8 | **Re-ingress loop cap** (ADR 0013 Increment 2). When a captured reply is re-ingressed (`reingress_to=`/`Loopback()`), the re-ingressed message carries a `correlation_depth`; a message at this depth still routes, but the next hop (depth+1) **dead-letters** its re-ingress work-row and marks the origin `ERROR`. Coarse by design — it bounds *total work*, not topology, so a chain that legitimately bounces A→B→A a few times needs headroom. 8 is safe for typical request→response→route feeds; raise it for deep correlation chains, lower it to fence a misbehaving loop. (A value of 0 would dead-letter every re-ingress, so the floor is 1.) |
| `per_lane_wake` | bool | `false` | **Per-lane wake events** (B12, [ADR 0061](adr/0061-per-lane-wake-events.md)). **Reliability-core, default-OFF.** When `false`, a committed message wakes every worker of its stage via an engine-wide event (the historical behavior). When `true`, it wakes **only its own (stage, lane) worker**, eliminating the thundering-herd empty-claim storm that dominates at high **connection** counts (~1,500 inbounds). Correctness is unchanged (the FIFO claim + the 0.25 s lost-wakeup poll backstop are untouched; a missed wake self-heals within the poll). **Read once at engine start — a `/config/reload` does NOT toggle it (restart to change).** Env override (for the connection-scale harness A/B): `MEFOR_PIPELINE_PER_LANE_WAKE=true`. The default `pooled` mode routes wakes through its dispatchers, so this knob is inert there for every lane a dispatcher drains — which is all of them except an outbound declaring `ordering = "unordered"`, whose own delivery worker still reads it ([ADR 0066](adr/0066-pooled-stage-claimers.md) D4). |
| `claim_mode` | enum | `pooled` | **Pipeline claim mode** ([ADR 0066](adr/0066-pooled-stage-claimers.md)). **Reliability-core.** `pooled` (the **default since #744**) runs one `StageDispatcher` per stage — a handful of shared claimer tasks batch-claim head-prefixes across lanes, collapsing the per-connection claim storm and holding zero-loss at high fan-out where `per_lane` drops messages. `per_lane` is the **byte-identical opt-out** (`[pipeline].claim_mode = "per_lane"`): the pre-ADR-0066 topology of one router+transform worker per inbound and one delivery worker per outbound, enforced by a test sentinel. **Read once at engine start — a `/config/reload` does NOT toggle it (restart to change).** Env override (harness A/B): `MEFOR_PIPELINE_CLAIM_MODE`. **Two caveats** (see [CONNECTIONS.md](CONNECTIONS.md) "Pipeline claim mode"): exactly-once degrades under load (no inbound de-dup — receivers must be idempotent; not pooled-specific) and active-passive failover-under-load is covered (the gated `test_load_failover_{postgres,sqlserver}` two-node kill-the-leader runs hold no-acknowledged-loss / per-lane FIFO / bounded dup-rate under pooled; only recovery *time* is host-dependent, and the T17 infra-fault spin is bounded by ADR 0070). Invariants (at-least-once / per-lane FIFO / poison-guard) are unchanged in both modes. |
| `pooled_claimers_per_stage` | int (≥1) | 1 | Pooled-only: K claimer tasks per stage (`>1` hash-partitions lanes across claimers so no two claim the same lane). |
| `pooled_sweep_interval` | float (>0) | 0.25 | Pooled-only: the clock-driven discovery-sweep interval (the bounded at-least-once backstop; 0.25 s = `poll_interval` parity). |
| `pooled_claim_lane_chunk` | int (1–500) | 256 | Pooled-only: max lanes batch-claimed per claim round-trip (clamped down to the backend store's chunk — SQLite 200, SS/PG 500). |
| `pooled_max_processing_lanes` | int (≥1) | 256 | Pooled-only: max concurrently-processing lanes per stage (the decrypted-body / crash-exposure bound). |
| `require_rcsi_for_pooled` | | | **Removed, and refused at load** in the file or as `MEFOR_PIPELINE_REQUIRE_RCSI_FOR_POOLED`, at either value (BACKLOG #2090, [ADR 0066 §12](adr/0066-pooled-stage-claimers.md)). A SQL Server store no longer opens with `READ_COMMITTED_SNAPSHOT` off, in any claim mode (BACKLOG #1628). Only `schema_management = "auto"` tries to turn it on first. A pooled start also checks RCSI and always fails closed if it is off, so there is no check left for this key to relax. To run pooled on SQL Server, turn `READ_COMMITTED_SNAPSHOT` on for the database. |
| `infra_fault_policy` | enum | `stop` | **Pooled T17 (infra/machinery-fault) handling** ([ADR 0070](adr/0070-t17-infra-fault-bound.md)). A store/handoff error — or any raise from **outside** the per-item body — is caught by the dispatcher's T17 handler, which always re-pends the faulting head at an exponential-capped backoff (collapsing the ~4×/s sweep spin). This key bounds a **persistent** such fault: `stop` (default) STOPs the head-of-line-blocked lane after `infra_fault_stop_after` consecutive zero-progress faults, reusing the `internal_error = stop` muscle (STOPPED phase + `connection_stopped` alert; reload / new work re-arms) and **never** dead-lettering the good message. `retry_forever` never STOPs — it retries the head at capped backoff forever and emits a throttled `lane_stuck` alert once the horizon is crossed (for a deliberately-unattended flaky-infra site). Reliability-core: **read once at engine construction — a `/config/reload` does NOT re-read it (restart to change).** |
| `infra_fault_stop_after` | int (≥1) | 10 | consecutive zero-progress T17 faults before a `stop`-policy lane transitions to STOPPED — and the stuck horizon at which `retry_forever`'s throttled `lane_stuck` alert first fires. Under the exponential backoff (capped by `infra_fault_backoff_cap`) 10 spans ~4 min of wall clock, so it is really a duration gate. The same count also STOPs a lane whose own dispatch kills its stage's claimer that many times in a row, with a `connection_stopped` alert, under **either** policy: each such death stalls every other lane on that claimer through the respawn backoff (BACKLOG #2074). A reload, a recovery broadcast, or an operator stop and start re-arms it with a fresh count. |
| `infra_fault_backoff_cap` | float (>0) | 60.0 | cap (seconds) on the T17 head re-pend backoff — base is the dispatcher's 1 s lane-error backoff, doubling per consecutive zero-progress fault. ~60 s picks a recovered dependency back up within about a minute while still collapsing the spin. |
| `fuse_thread_hops` | bool | `false` | **Thread-hop fusion** ([ADR 0071](adr/0071-cut-executor-round-trips-b5.md) B5). **Reliability-core, default-OFF, SQL-Server-scoped:** when `true` **and** the store backend is SQL Server **and** `claim_mode = "pooled"`, each fused stage (INGRESS/ROUTED) runs its off-loop CPU stage (`route_only`/`transform_one`) together with its store handoff on a **single** dedicated-executor worker hop, collapsing a multi-statement aioodbc handoff into one executor→loop completion (the profiled per-completion async-marshaling wall). Provably no-op elsewhere: Postgres (asyncpg is loop-native) and SQLite (loop-affine handoff lock) keep the async path by construction and log "ignored", and a sync-handoff-pool open failure downgrades to the async path with a loud warning + a degraded gauge — never a lane outage. **Read once at engine construction (restart to change).** Env/harness A/B: `MEFOR_PIPELINE_FUSE_THREAD_HOPS`. |
| `pooled_fusing_workers` | int (≥1) | 8 | worker count for **each** per-stage fusing executor (ADR 0071 B5). Every fused stage gets its own `ThreadPoolExecutor` of this width plus a matching-width dedicated synchronous pyodbc handoff pool (one connection per worker, so a fused hop never blocks acquiring). Small by default — a fused hop holds a worker across DB latency, so this *is* the fused-stage concurrency; it also clamps the fused stages' effective `pooled_max_processing_lanes` to ~2× this value, so the claimer doesn't reserve 256 slots for a handful of workers. Inert unless `fuse_thread_hops` is on. |
| `batch_handoff_statements` | bool | `true` | **Per-hop SQL statement batching** ([ADR 0075](adr/0075-per-hop-sql-statement-batching.md)). **Default-ON** (promoted 2026-07-08; retained as an emergency off-switch) and SQL-Server-scoped: each per-hop staged handoff (`route_handoff` / `transform_handoff`) folds the non-result-returning DML of its body into the fewest `pyodbc.execute()` T-SQL batches — the same ordered `(sql, params)` sequence, one round-trip per batch, still committing **exactly once per hop**. It cuts network round-trips, **not** transactions: no commit boundary moves, the claim stays its own poison-guard transaction, and the ACK-on-receipt fence is untouched. Each result-consuming statement whose value gates later control flow (the guard `DELETE`, the finalize `GROUP BY`, the finalize `sp_getapplock` rc-check) stays its own execute. Postgres and SQLite have no batched path and run byte-identically. **Read once at engine construction (restart to change).** Env: `MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS`. |
| `snapshot_on_send` | bool | `true` | **Copy-on-`Send`** ([ADR 0104](adr/0104-copy-on-send-outbound-message-model-recognition-first-handler-message-type-and-hl7-field-picker.md)) — snapshot each `Send`'s payload at construction so a **divergent fan-out** (mutate between `Send`s) delivers per-destination state instead of a last-write collapse. **Default-ON** since the BACKLOG #230 default-flip: the conservative estate AST scan flagged 1 of 152 handlers and human triage found that one mutates an independent clone, so genuine divergence is **0** and the flip changes delivered bytes for no handler; and `Message.copy()` is now genuine copy-on-write, so the common single-`Send` / no-post-mutation path is zero-copy and a deepcopy fires only on an actual divergence. Set `false` to restore the pre-ADR-0104 last-write behaviour. Backend-agnostic. **Read once at engine construction (restart to change).** Env: `MEFOR_PIPELINE_SNAPSHOT_ON_SEND`. |
| `credential_fault_policy` | enum | `stop` | **Partner-account-lockout protection** (#109, [ADR 0095](adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)). What an outbound File/FTP/SFTP sender does on a **permanent credential/auth fault** (bad password, key rejected). `stop` (default) halts the lane **immediately** (not after a streak) and **retains the queued rows un-errored** (they stay pending/claimable, never dead-lettered), so a backlog can't re-authenticate in a loop and trip the partner's account lockout — reusing the STOP muscle (`connection_stopped` alert; reload/restart re-arms the lane once the credential is fixed). `dead_letter` keeps the historical fail-fast (dead-letter just the offending row and advance). The policy also governs a permanent **configuration** fault (BACKLOG #2083): an FTP server that refuses `AUTH TLS`, `PBSZ`/`PROT P` or the greeting, or demands TLS of a plain session. Every queued row would meet that refusal too, so `stop` stops the lane and keeps the queue, and the alert names the configuration. A REST, SOAP, FHIR or DICOMweb outbound raises the same fault when its HTTP Digest handler refuses a challenge (BACKLOG #2323, code `auth-challenge-refused`). That needs Digest set up on the connection, for the endpoint or for the web proxy. The refused challenges are at least these: a Digest challenge naming a hash other than SHA-256, a malformed one, and one in a scheme other than Digest or Basic, such as NTLM. Other unanswered challenges do not raise it; [ADR 0095](adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md) Amendment B lists them. A **content**-permanent reject (AR/CR, no-such-dir) is unaffected — it still dead-letters. |
| `schedule_tick_seconds` | float (>0) | 30.0 | **Active-window scheduler tick** (#147, [ADR 0095](adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)). The reconcile granularity for a connection's per-connection `schedule` (a window boundary is honoured within one tick). Only affects connections that declare a `schedule`; connections with none are byte-identical always-on. |

### `[sandbox]`
**Opt-in subprocess isolation for Routers/Handlers** ([ADR 0087](adr/0087-sandbox-subprocess-isolation.md),
BACKLOG #197, ASVS 15.2.5).

**It does not stop config Python executing in the engine process — read that before anything else.**
The loader executes every `*.py` in your config directory in-process, as the service account, at every
`serve` and every reload, and no value of `mode` changes that. What `mode` governs is where a Router's
or Handler's **body** runs once the graph is built. Module top level is outside its reach either way.

Routers/Handlers are admin-authored pure Python. The engine's own address space holds the DEK, the audit
chain, and every live socket. `mode="off"` (**the default**) runs them in-process, **byte-identically and
with zero overhead**. `mode="subprocess"` runs each inbound's Router/Handler in a **persistent
per-inbound worker child** (never a per-message fork), enforcing a forbidden-import guard
(socket/store/crypto) and the resource caps below. An isolation denial (forbidden op, cap overrun,
worker crash, a rejected frame) routes the message to `ERROR`/dead-letter **post-ACK** (no NAK, never
dropped).
**Read once at engine start — a `/config/reload` does NOT re-read it (restart to change).**

**`mode` is engine-wide — there is no per-connection sandbox setting.** One policy is rendered for the
whole graph, so whichever mode you pick governs **every** Router and Handler in the process. That
matters most in the other direction: setting `mode="off"` because one Handler needs live enrichment
takes every other Router and Handler out of the sandbox too. To isolate some feeds and not others you
need separate engine processes.

**What turning it on costs you.** At least these things change relative to `mode="off"`:

| | At `mode="subprocess"` |
|---|---|
| **Live enrichment** | `db_lookup` / `fhir_lookup` are **refused, fail-closed**. They re-enter the event loop and a process boundary breaks that. **A Handler needing either must run `mode="off"`** — that escape is supported and is not going away, and per the note above it applies to the whole engine, not to that Handler alone. |
| **`wall_seconds`** | Only **enforced** here. At `mode="off"` there is no timeout at all, so this is a cap you gain by turning the sandbox on: a busy-loop Router/Handler can no longer wedge intake, and a legitimately slow one that used to finish now dead-letters. `startup_seconds` and the POSIX `mem_mb` arm with it. |
| **Throughput** | About **0.19 ms per dispatch** with no reference view; a 20k-entry crosswalk costs about **4.5 ms** marshalling and **6.2 ms** end-to-end, roughly 1.4x a pickle round-trip — inside the pipeline's existing per-interface bound. **One message is not one dispatch:** a message routed to one handler with an `accepts=` predicate costs **three** (router, predicate, transform), and fan-out to K handlers costs **1 + 2K**, each re-marshalling the reference view. |
| **Imports** | The worker starts with the interpreter's remote debugging disabled. It starts by running a script, so it does not search the engine's working directory for imports. **One exception is a source checkout.** When the engine runs from its checkout, the worker has that checkout on its path too. That folder is often the working directory, so a module there would import in the worker. [DANGEROUS-FUNCTIONALITY.md](DANGEROUS-FUNCTIONALITY.md) section 3, in its `_child_bootstrap.py` paragraphs, says where on the path the checkout goes. The worker also starts with `-P`, which keeps the engine package's own folder off its import path. Of an inherited `PYTHONPATH`, only the absolute entries reach it. A helper your config imports must be a `_`-prefixed file in the config directory, which the loader finds for its siblings, or an installed package. The same holds for each engine shard under `supervise`. `supervise` checks this rule before it starts a shard. It loads the config once in a child with an engine shard's import path, and refuses to start the fleet if that load fails. |
| **Processes** | Per inbound **that receives traffic**: one child process (a full interpreter with its own re-loaded copy of your config dir), two parent daemon threads (frame reader + stderr relay), three parent pipe fds, and on Windows a job-object handle. Nothing is spawned for an idle inbound — the child starts lazily on first dispatch. |
| **Environment variables** | The worker starts with a short allowlist, not the engine's environment: what the platform and the interpreter need to start (such as `PATH`, the temp and profile directories, `TZ` and the locale), the interpreter's own variables by name (such as `PYTHONPATH`, `PYTHONUTF8` and `PYTHONHASHSEED`), `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE` with the `MEFOR_SECURITY_ENFORCEMENT` dial that unlocks it, and the names you list in `pass_environment`. `messagefoundry/childenv.py` holds the full list. The worker loads your config directory again under that environment. **Config code that reads any other variable from `os.environ` finds it unset in the worker and set at `mode="off"`**, at the top of a module as much as inside a Router or Handler. If the read has no default, the worker fails to start. If it has a default, the worker can build a different graph. **The engine compares the two graphs when a worker starts, and refuses a worker whose graph differs**: the inbound, router, handler and outbound names, each inbound's router, and which handlers have an `accepts=` predicate. Each message on that inbound then dead-letters with an error that names what differs and on which side. Name the variable in `pass_environment` and restart. A config file changed on disk since the engine loaded it is refused the same way, until you reload. **The comparison is of names.** A function that keeps its name and branches on a variable the worker lacks is not caught, so list every variable your config reads. `current_environment()` names the active environment in both modes, and a value that differs by environment belongs in a connection spec (`env()`), a code set or a reference set. |

**Two more things the setting does not reach.** `messagefoundry check` and `messagefoundry dryrun`
always run Routers/Handlers **in-process** and never consult `mode`. On the default that costs nothing,
because `serve` runs them in-process too; once you set `mode="subprocess"` the preview stops matching
the engine in at least two ways. `wall_seconds` is unenforced in the preview, so test a slow Handler
under `serve`. And config code there sees the full environment, not the worker's allowlist that the
*Environment variables* row above describes. A Handler calling `db_lookup`/`fhir_lookup` is not one
of these. The dry run has no lookup runner, so the call raises there in every mode. Unless the
Handler catches that error, the fixture records `ERROR`. The gate then fails unless its `.expect`
file declares `ERROR`. Under `subprocess` that matches `serve`, which refuses the lookup; at
`mode="off"` it does not, because `serve` runs the lookup there. And
`[pipeline].fuse_thread_hops` is **hard-disabled** whenever `mode="subprocess"`: fusion runs
Router/Handler code in-process on an executor hop, so honouring both would silently unsandbox the code
you asked to isolate. The runner fails closed to the async sandboxed path and logs it. To get fusion you
must leave `mode="off"`.

**The pipe itself is a control, and it is not configurable.** Both directions speak a **non-executing
frame codec**: a closed tag set decoded with `json.loads` + `bytes.decode` and a literal tag match over a
fixed handful of types. Nothing is serialized by naming a type, so nothing a worker writes can construct
an arbitrary object — or run arbitrary code — in the engine. Each dispatch carries a fresh random
request id that a response must echo along with its phase and handler name, *and* a frame that turns up
outside a dispatch drops the worker — so a worker cannot pre-stage the answer to a later call. Fixed
bounds: **64 MiB** per frame and per frame header, **65536** out-of-band segments, and value nesting
depth **256**; each is a fail-closed rejection, not a truncation. The graph's code-set tables are sent
by the engine once per worker start, so a sandboxed `code_set(...)` always resolves to the value the
engine itself is serving — an unreloaded edit to `codesets/` changes nothing until you reload, exactly
as with `mode=off`.

**What this boundary does NOT cover.** It confines the *address space*, not the machine: a sandboxed
Router/Handler can still import `os`/`subprocess`/`ctypes`, open files, and spawn processes as the
service account — the forbidden-import guard is defence-in-depth (a module imported before it is
installed keeps a live reference), never a compensating control. The worker is not handed the
engine's `MEFOR_*` variables (the table above). **That is not a boundary by itself:** the child runs
as the same account as the engine, so it can still read what that account can read; see the
2026-10-01 correction in [ADR 0087](adr/0087-sandbox-subprocess-isolation.md). All of one inbound's Routers/Handlers
share a single worker, so this does **not** confine one Handler from another — the boundary is between
admin code and the engine, exactly as `mode=off` shares an address space. A grandchild the Handler
spawns inherits the response pipe and can stage a frame while the worker is alive; killing the worker
now reaps its whole process tree (a Windows kill-on-close job object / a POSIX process group), so such
a grandchild no longer outlives the kill (BACKLOG #342). That reap is best-effort process hygiene: what
makes a stray frame *harmless* is still the codec plus the request-answer binding (a live grandchild can
force a respawn, i.e. dead-letter messages on that inbound, but nothing more), not the process teardown.
The child's **stderr is captured by the engine, not inherited** (ADR 0176): a Handler that prints is
relayed into the engine's log attributed to the inbound, the child pid and the worker generation, with
**the content itself only at `DEBUG`**. At `INFO` and above you get a rate-limited `WARNING` naming the
inbound and counting the lines, and no content — that is deliberate, and it is how the never-log-bodies
rule is kept when a Handler prints a message body. To read what a Handler actually wrote, set
`[logging].level = "DEBUG"`, and treat that log as PHI-bearing while you do. Two things that will
surprise you otherwise: raising the level shows every `print` and raw write **plus** the child's own
`WARNING`+ records, but never the child's own `DEBUG`/`INFO` records — the worker's root logger is
pinned at `WARNING` when it starts and no knob plumbs a level into it (an unfiled follow-up, named by
subject rather than by a number that does not exist yet). And because that one relay thread is also
what keeps the child's stderr pipe from filling, a slow log handler — an off-box `[logging].forward_*`
collector that has stalled, say — becomes back-pressure on a `DEBUG`-level child rather than lost
output. ADR 0072 Router/Handler
tracing does not compose with `mode=subprocess` (the sandbox branch precedes the tracer branch), and a
`mode=subprocess` graph cannot use the ADR-0071 fused thread-hop path (it is hard-disabled).

**Check this before you flip the switch.** Turning the sandbox on is behaviour-neutral for a graph
whose Routers are pure — which is what the engine requires of them anyway. It is **not** neutral for a
Router that *mutates* the message it was handed: in-process that mutation is visible to an `accepts=`
predicate (they share one object), and across the pipe it is not, so such a graph can route
differently under `mode=subprocess`. Grep your Routers for writes to the message before enabling this
on a live feed; a Router that only reads is unaffected. Grep your config for `os.environ` and
`os.getenv` too: the table above says what a direct read of the environment does in the worker.

| Key | Type | Default | Notes |
|---|---|---|---|
| `mode` | enum | `off` | `off` (in-process, byte-identical, no subprocess) or `subprocess` (persistent per-inbound worker child). |
| `wall_seconds` | float (>0) | 5.0 | **Authoritative** wall-clock cap per Router/Handler call on **every** platform — the parent kills a worker that overruns it, so a pathological busy-loop can't wedge intake. The worker sets no `RLIMIT_CPU`, so CPU that admin code spends outside a call, such as a thread left running or a grandchild that leaves the worker's process group, has no bound at all ([ADR 0087](adr/0087-sandbox-subprocess-isolation.md), amendment of 2026-10-07). |
| `mem_mb` | int (≥1) or null | 512 | POSIX-only `RLIMIT_AS` address-space cap (MiB) inside the child (no-op on Windows). `null` disables it. |
| `pass_environment` | list of names | `[]` | Extra environment variable **names** the worker is given, beyond its allowlist. Use it for a variable your config code reads. Names only; the value comes from the engine's own environment at worker start. **Refused at load** if a name is one of the engine's own: any `MEFOR_*` name, and `VAULT_TOKEN` or `PGPASSWORD`. Give a variable your config reads a name outside `MEFOR_`. Whatever you list is readable by every Router and Handler, so do not list a secret of your own either. Env: `MEFOR_SANDBOX_PASS_ENVIRONMENT`, comma-separated. |
| `startup_seconds` | float (>0) | 30.0 | Bound on the one-time child bootstrap (config load + guard install) before start fails closed. |

### `[diagnostics]`
The Corepoint-style **event log** (#46) — a metadata-only record of connection lifecycle / pre-ingress
failures and the ACK/NAK the engine returns. **Both master switches are on by default and safe to be:**
they store only non-PHI metadata (connection name, peer IP, a scrubbed reason, the ACK disposition), and
the AA-ACK *body* is stored only when the store is encrypted (else NULL); a NAK body is never persisted.
A per-connection `capture_connection_errors` / `capture_ack` flag overrides the matching master switch for
one connection (see [CONNECTIONS.md](CONNECTIONS.md)). `message_events`, the third row below, is **not** a
master switch but a **verbosity dial** over the per-message disposition log — it defaults to `all` and
keeps a compliance floor even at `off`. The fourth row is a relocated key, rejected here since ADR 0118.

| Key | Type | Default | Notes |
|---|---|---|---|
| `connection_events` | bool | `true` | master switch for the **connection/transport event log**: inbound lifecycle (established/closed) + pre-ingress failures (allowlist/capacity/oversize/peer-reset/framing) + outbound lane transitions (connection_lost/restored). Metadata-only, written off the hot path by a drain task. Per-connection `capture_connection_errors` overrides it. |
| `response_sent` | bool | `true` | master switch for **"Response Sent"** — the ACK/NAK returned to an inbound sender. Always captures the disposition metadata (`ack_code`/`phase`/`outcome`); the AA body is stored only on an encrypted store, and every NAK body is NULL. Per-connection `capture_ack` overrides it. |
| `message_events` | enum | `all` | verbosity of the per-message **`message_events`** disposition log (#63) — how many rows the store writes to that table. `all` (default) records every event; `errors` drops the routine successes (`received`/`delivered`/`replayed`); `off` keeps only the floor. **A compliance floor is retained at every level, even `off`:** `viewed` (the HIPAA PHI-access trail) plus the terminal `dead`/`error`/`failed`. Not a master switch — it never touches the `messages`/queue disposition rows (count-and-log is separate) or the tamper-evident `audit_log` chain. |
| `audit_all_authz` | | | **→ moved to `[security].audit_all_authorization_decisions`** (ADR 0118) — set it there; no longer accepted in `[diagnostics]`. |

> Retention for the event log has its own short window — `[retention].connection_event_retention_hours`
> (in **hours**; `0` = inherit `messages_days`).

### `[egress]`
Fail-closed **outbound destination allowlist** (WP-11c; ASVS 13.2.4/13.2.5/14.2.3) — bounds where the
engine may **send** PHI, so a fat-fingered or hostile destination can't exfiltrate it. Once a
transport's list is set, an outbound of that transport not on it is **refused at config load/reload**
(a `WiringError` → 422 / refused reload), checked against the resolved (`env()`-substituted) destination.

> **Do not record "egress allowlist: opt-in, unrestricted by default."** The `EgressSettings` model
> denies by default (vault BACKLOG #2605). So every entry point that builds a connector, not only
> `serve`, refuses a destination whose transport's list is empty, unless the operator writes
> `[security].block_unlisted_outbound = false`. On top of that, `serve` runs a startup gate
> ([`__main__.py`](../messagefoundry/__main__.py), the `egress_open` expression;
> ASVS 13.2.4/13.2.5). **All three built-in environment names derive PHI**
> ([ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)), so this is
> what `serve --env dev|staging|prod` actually does under `[security].enforcement = enforce` (the default):
>
> | `[egress]` / `[security]` as configured | What `serve` does |
> |---|---|
> | **no counted list** set (see "Which lists the startup gate counts" below), `block_unlisted_outbound` left unset | **exits 2** with *"no outbound destination is declared … refusing to start"*. The deny default would refuse every outbound, so `serve` refuses to start rather than run lanes that fail every send. |
> | none of the six lists that count under the opt-out set, `block_unlisted_outbound = false` | **exits 2** with *"outbound egress is UNRESTRICTED … refusing to start"*; the explicit opt-out does not buy a fully-open PHI instance. |
> | **at least one counted list** set, `block_unlisted_outbound` left unset | starts deny-by-default (an `info:` line on stderr): every transport whose own list is **empty** refuses **every** destination of that type. This is the case that bites: a partially-configured instance does not allow-any the transports you didn't list. |
> | `block_unlisted_outbound = true` | starts deny-by-default, with or without a list; enumerate every permitted destination. |
> | at least one of those six set, `block_unlisted_outbound = false` | starts **allow-any** for the transports you left empty, with a `warning:` plus a WARNING-level `AUDIT:` line, and reported by `security_loosenings()`. |
>
> **Which lists the startup gate counts depends on the switch.** With `block_unlisted_outbound` left
> unset, the gate counts eight lists: `allowed_mllp`, `allowed_tcp`, `allowed_http`, `allowed_db`,
> `allowed_remote`, `allowed_file_dirs`, `allowed_smtp` and `allowed_direct`. So a mail-only or
> Direct-only instance passes the gate, and the deny default holds every other transport closed.
> With the switch written `false`, only the first six count, because the other transports would
> then stay allow-any. A mail-only instance with that opt-out **exits 2** with *"outbound egress is
> UNRESTRICTED … refusing to start"*, and the message names the override. `allowed_recipient_domains`
> and `allowed_proxy` never count. Every list still *gates* its own transport once the instance starts.
>
> Under `enforcement = warn` the two refusals become warnings and start. **No instance is exempt**
> — the synthetic declaration that used to exempt one entirely was retired in [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md).
> **Practical rule: enumerate the destinations you intend, per transport.**

| Key | Type | Default | Notes |
|---|---|---|---|
| `allowed_mllp` | list | `[]` | allowed MLLP destinations; each entry is `host` (any port) or `host:port`. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_MLLP` |
| `allowed_tcp` | list | `[]` | allowed raw-TCP destinations; each entry is `host` (any port) or `host:port`. **Covers three connectors, not one:** `Tcp(...)`, `X12(...)` and the **DICOM C-STORE SCU** (`DICOM()` outbound) all resolve to this list — they are all raw sockets ([`transports/egress.py`](../messagefoundry/transports/egress.py), `_allowlist_for`). Populate it for every one of them, or under the deny default your X12/PACS destinations are refused at load. An inbound `Tcp(...)`/`X12(...)`/`DICOM()` is a local listener and is not connect-gated. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_TCP` |
| `allowed_file_dirs` | list | `[]` | allowed File output directories; a destination's directory must resolve at/under one of these |
| `allowed_http` | list | `[]` | allowed HTTP destination hosts; each entry is `host` (any port) or `host:port` (ADR 0003). **Covers the whole HTTP family, not just REST/SOAP:** `Rest()`, `Soap()`, `FHIR()`, `DICOMweb()` (STOW-RS), the read-only `fhir_lookup` / `FhirLookup(...)` (ADR 0043), **and** the SMART / OAuth2 **token endpoints** — a token endpoint is a second egress host and is checked against this same list, so list it too. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_HTTP` |
| `allowed_db` | list | `[]` | allowed DATABASE destination servers; each entry is `host` (any port) or `host:port` (ADR 0003). Via env: comma-separated `MEFOR_EGRESS_ALLOWED_DB` |
| `allowed_remote` | list | `[]` | allowed RemoteFile (SFTP/FTP/FTPS) hosts — gates the connector in **both** directions (source poll + destination upload); each entry is `host` (any port) or `host:port`. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_REMOTE` |
| `allowed_smtp` | list | `[]` | allowed **email (SMTP)** destination hosts for the `Email(...)` outbound ([ADR 0029](adr/0029-email-smtp-destination.md)); each entry is `host` (any port) or `host:port`. Distinct from `[alerts].smtp_allowed_hosts`, which gates the **alert notifier's** own SMTP dial. **Whether it counts toward the open-egress startup gate depends on `[security].block_unlisted_outbound`**; see "Which lists the startup gate counts" above the key table. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_SMTP` |
| `allowed_direct` | list | `[]` | allowed **Direct** (S/MIME-over-SMTP HISP relay) destination hosts ([ADR 0085](adr/0085-direct-hisp-smime-connector.md)); each entry is `host` (any port) or `host:port`. Kept deliberately **separate from `allowed_smtp`** so an operator can permit a Direct HISP relay without opening generic email egress — a distinct trust relationship carrying encrypted PHI. **Counts toward the open-egress startup gate on the same terms as `allowed_smtp`**. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_DIRECT` |
| `allowed_recipient_domains` | list | `[]` | allowed **recipient domains** for the `Email(...)` outbound (vault BACKLOG #2616). `allowed_smtp` gates only the relay hop, and a relay forwards to whatever address the connection names, so this list bounds where the mail ends up: **every** address in an `Email()` destination's `recipients` must sit in a listed domain, or the destination is **refused at config load/reload**. Each entry is a bare domain (`hospital.example`), matched exactly and without regard to case; a subdomain needs its own entry. An entry that could never match, such as an address, URL, port, wildcard, IP address, or a dot at either end, is refused at load: each entry must pass the same host-name rule as a recipient's domain, described below (vault BACKLOG #2843). Each address the engine parses out of `recipients` must also be a plain `local@domain` that reads back unchanged, within the SMTP length limits, with a local part of letters, digits, dots and the RFC 5322 mailbox symbols other than `%`, `!`, `|`, `/`, `=` and `?`, not starting with `-`. A display name or comment in the setting is dropped, and the `To:` header carries only the checked addresses. Its domain must be ASCII: write an internationalized domain in its `xn--` form, in the recipient and in the list. The domain must also be a host name. Each label holds 1 to 63 letters, digits and hyphens, and does not start or end with a hyphen. No label may be empty, so a dot at either end is refused. The last label must start with a letter, so a bare IP address is refused. A list entry may hold at most 253 characters; an address's domain is held to 252 by the length limit above. The same address rule binds at least the `Email()` sender, the `Direct()` sender and recipients, the `[alerts]` sender, recipients and rule overrides, and per-user notification addresses. **Deny-by-default even under the `block_unlisted_outbound = false` opt-out, unlike the destination lists above:** an empty list refuses every `Email()` destination on every instance, whatever `[security].block_unlisted_outbound` says. It does not gate `Direct()`, which encrypts to one partner certificate, and it does **not** count toward the open-egress startup gate. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_RECIPIENT_DOMAINS` |
| `proxy_url` | str | _unset_ | site-wide **default forward/egress web proxy** for the HTTP family — REST/SOAP/FHIR/`fhir_lookup`/DICOMweb plus the OAuth2/SMART token endpoints ([ADR 0126](adr/0126-outbound-forward-egress-web-proxy-for-the-stdlib-http-family.md)). A connection that sets no per-connection `proxy` inherits this; a per-connection value overrides it. Unset (default) = no site-wide proxy from this file; only per-connection proxies apply. An off-box hop then still follows `HTTP_PROXY` / `HTTPS_PROXY` and the operating system's own proxy settings, which `urllib` reads on its own. `"default"` selects the OS default web proxy (`getproxies()`); an `http(s)://` address names an explicit one. **A loopback host is never sent through a proxy**, whichever of these named it (see the cleartext note below this table). **Proxy credentials stay per-connection** (secrets via `env()`), never a global TOML value. Via env: `MEFOR_EGRESS_PROXY_URL` |
| `proxy_no_proxy` | list | `[]` | the site-wide `NO_PROXY`-style **bypass list** inherited by a connection that sets no per-connection `proxy_no_proxy`. Each entry is a host, `.suffix`, `*.suffix` or `*`. Via env: comma-separated `MEFOR_EGRESS_PROXY_NO_PROXY` |
| `allowed_proxy` | list | `[]` | allowed **forward-proxy** hosts; each entry is `host` (any port) or `host:port`. Gates the proxy an http-family connection dials **through** — per-connection `proxy_url` or the `[egress].proxy_url` default above — on both the outbound and the `fhir_lookup` read arm. **Deny-by-default even under the `block_unlisted_outbound = false` opt-out, unlike the destination lists above:** a configured proxy with an empty `allowed_proxy` is **refused at config load**. Empty refuses nothing until you set a proxy, so the cost is one line for operators who use one; permissive-when-empty would leave the proxy ungated under that opt-out, and the proxy receives a `Proxy-Authorization` credential under `proxy_auth_type = basic`. Same shape as `[ai].allowed_endpoints` ([ADR 0135](adr/0135-engine-brokered-ai-assistance-customer-managed-llm-egress-with-per-use-audit.md)). `proxy_url = "default"` is exempt (it names no address at config time and cannot carry engine-minted proxy credentials). **Not a destination list:** it is deliberately separate from `allowed_http`, because [ADR 0126](adr/0126-outbound-forward-egress-web-proxy-for-the-stdlib-http-family.md) puts the proxy out of that gate's scope — one corporate proxy fronts many destinations and would otherwise have to be co-listed with every one — and it does **not** count toward the open-egress startup gate. Via env: comma-separated `MEFOR_EGRESS_ALLOWED_PROXY` |
| `deny_by_default` | | | **→ moved to `[security].block_unlisted_outbound`** (ADR 0118) — set it there; no longer accepted in `[egress]`. |

> **No counted destination list is a startup REFUSAL, not a warning** (see the table above).
> With no **counted** allowlist set (see "Which lists the startup gate counts" above), and
> `block_unlisted_outbound` not written `true`, `serve` **exits 2** on **every** instance — all three built-in env names, not
> just `prod`/`staging` — under `[security].enforcement = enforce`, the default; it downgrades to a
> stderr warning only under `enforcement = warn`, which is now the only dial that moves it. Lock it down with
> the per-transport lists above and/or **`[security].block_unlisted_outbound = true`** — note that key
> lives in `[security]`; `[egress].deny_by_default` is a relocated key and is **rejected at config
> load** (row below).

> The webhook/SMTP **alert** sinks carry no message bodies (no PHI) and keep their own host allowlists
> in `[alerts]` (`webhook_allowed_hosts` / `smtp_allowed_hosts`).

> **Cleartext (`http://`) egress is refused, whatever the data label (ASVS 12.2.1,
> [ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md)).**
> Separately from this allowlist, a plaintext `http://` outbound to a **non-loopback** host is decided by
> [`config/tls_policy.py`](../messagefoundry/config/tls_policy.py)'s `insecure_hop_disposition`, enforced
> at construction by `refuse_cleartext_egress`
> ([`transports/rest.py`](../messagefoundry/transports/rest.py)). The authority's precedence, in the
> order it is evaluated: a loopback / on-box hop is **allowed**; a `tls_hop_attested` hop is
> **allowed** (the operator asserts it is secure by other means — see the note below); a per-connection
> `cleartext_accepted` hop (+ a mandatory `cleartext_reason`) is **crossed with a loud, audited WARN**
> (the operator accepts that it is not secure); a non-enforcing instance
> (`[security].enforcement = warn`) **warns**; everything else is **refused** (fail-closed).
>
> **An on-box hop is dialled direct, never through a web proxy** (vault BACKLOG #2579). The loopback
> allowance rests on the hop staying on the box, and a proxy in the path would carry it off the box.
> So a request to a loopback host (at least `127.0.0.0/8`, `::1` and the name `localhost`; decided without DNS)
> goes straight to that host. That holds for a proxy from `HTTP_PROXY` / `HTTPS_PROXY`, the
> operating system's own proxy settings, `[egress].proxy_url` and a per-connection `proxy` alike, and
> no `NO_PROXY` entry is needed. A proxy setting that a loopback destination makes inert is logged at
> INFO when the connection is built, and the static-credential report lists no proxy credential for
> a connection whose every target is loopback. An off-box hop still uses the proxy.
>
> **This is a rule of the engine's own `urllib` openers**: at least the HTTP family and its token
> endpoints, the alert webhook, the OIDC legs and the AI broker. A client built on another HTTP
> library is outside it. Of those, the Vault clients refuse a loopback `http://` Vault behind a proxy
> rather than bypass it (see `[secrets]`). The operator API client and the `tee` tool follow the
> environment proxy even for a loopback engine address.
>
> **`tls_hop_attested` is a per-connection declaration, set with `tls_hop_attested_reason`** (owner
> ruling 2026-09-24). It is a keyword on `inbound()` / `outbound()` / `FhirLookup()` /
> `DatabaseLookup()` / `DatabaseRef()`, or a top-level key on a `connections.toml` table. It is **not**
> a transport setting. Written into `[settings]` or a factory's settings dict, it is refused at load.
> Use it only when the
> hop really is secured by something the engine cannot see, such as a TLS-terminating proxy. A hop
> that is simply not secure is `cleartext_accepted` + `cleartext_reason`, which WARNs at every
> construction. Both are reported by `messagefoundry check` and `GET /security/posture`; see
> [CONNECTIONS.md](CONNECTIONS.md#attesting-a-hop-secure-tls_hop_attested). The `[logging]`
> forwarder's `forward_hop_attested` (above) is its instance-level sibling. The revocation gate's
> per-connection `tls_revocation_attested` is a different claim. It is also settable, with a mandatory
> `tls_revocation_attested_reason`, as an `inbound()`/`outbound()`/`FhirLookup()` keyword or a
> top-level `connections.toml` key. On a `FhirLookup`, one declaration lifts two refusals: the
> https read and the lookup's SMART token endpoint
> ([ADR 0173](adr/0173-tls-peer-revocation-checking-and-ocsp-stapling-across-terminating-and-originating-surfaces.md)).
> It governs revocation on a *verifying* hop only and never reaches a cleartext or verify-off hop.
>
> **`data_class` is no longer read here** — a `synthetic` label used to allow every cleartext hop
> silently, which made a typo in one file indistinguishable from a deliberate declaration, with every
> transport hop in the product as its blast radius. `MEFOR_ALLOW_INSECURE_TLS` no longer influences this
> decision either; it survives for the non-connection cells that have nowhere to carry a declaration.

### `[shadow]`
Parallel-run / **shadow-instance** egress suppression (#15). A *shadow* MessageFoundry processes real
(teed) traffic to validate it against a legacy engine, but must **not** deliver to live partners (the
legacy engine is still the real sender). An outbound in **simulate** mode runs the full pipeline +
count-and-log and finalizes the message **`PROCESSED`**, but **suppresses the real egress** (no
bytes/SQL leave the box) and retains the would-send payload for parity comparison.

| Key | Type | Default | Notes |
|---|---|---|---|
| `simulate_all_egress` | bool | `false` | **deployment-wide master switch**: when `true`, **every** outbound runs egress-suppressed regardless of its own `simulate=` — so a shadow stand-up can't accidentally leave one outbound live. Default `false` = each outbound's own `simulate=` flag applies. |

> Per-outbound control is the precise mechanism — set `simulate = true` on an individual outbound
> (`outbound(..., simulate=True)` or `simulate = true` in `connections.toml`); this section is the blunt
> instance-wide override. A simulated lane is surfaced as `simulated` on `GET /connections` and shown as
> `[SIMULATED]` in the console. Simulate suppresses **egress only** — the `[egress]` allowlist, connector
> construction, and handler state writes are unaffected. With egress suppressed there is no real partner
> reply, so a **capturing / `reingress_to`** outbound captures (and re-ingresses) **nothing** in simulate —
> the message just finalizes `PROCESSED`.

> **Simulate is not "not deployed."** A simulated outbound is **fully wired** — its connector is built, its
> `env()` values are resolved, it receives rows, and it finalizes `PROCESSED`; it just suppresses the bytes
> on the wire. A **not-deployed** connection (`deployed=false`, [ADR 0111](adr/0111-not-deployed-connections.md))
> is the opposite: it is never built, its `env()` is never resolved, and a `Send` to it is recorded-and-dropped,
> not delivered-to-nothing. Use *simulate* for parallel-run; use *not deployed* for a feed that exists in config
> but is deliberately dark. See [CONNECTIONS.md → Connection lifecycle](CONNECTIONS.md#connection-lifecycle--deployed--auto_start).

### `[alerts]`
Where the delivery pipeline's operational alerts (e.g. `connection_stopped`, `queue_buildup`,
`connection_error`, `message_stall`, `integrity_drift`) are
delivered. **Both transports are off by default** — with neither configured, events are logged at
`WARNING` (the `LoggingAlertSink`). A transport turns on when its essentials are present. Payloads
carry the connection name + queue shape only — **never a message body** (no PHI). Delivery is
best-effort and runs on a background task, so it never blocks or hangs a delivery lane.

**`intake_paused` is the ingest-side alert** (BACKLOG #290). `queue_buildup` is about one lane.
`intake_paused` says the engine paused intake on one of its two bounds. **Not every source honours
the pause**; the `max_staged_depth` row under `[inbound]` above says which do. A backlog can keep
growing during a pause.

The engine raises it when a pause starts, and again every 300 seconds while the pause holds, as it
does `queue_buildup`. That spacing is fixed. The notifier's throttle (`realert_seconds`, or a rule's
`cooldown_seconds`) decides which of those raises pages, and escalation tiers and suspend windows
count them. So a cooldown under 300 seconds does not page faster. A second pause soon after the first
raises at once, but the throttle may hold its page; a later reminder in that pause sends it. With no
`[alerts]` transport the engine raises no event; its own WARNING line records each pause. Its
`connection` is `intake:staged_depth` or `intake:disk_floor`, so each bound is its own alert.
A rule cannot attach a `control_action` to `intake_paused`, because it is not a connection-scoped
event (see `control_action` in the rule table below).

The payload holds `reason` (`staged_depth` or `disk_floor`), `value`, `limit` and `store_kind`
(`sqlite`, `sqlserver` or `postgres`), plus a one-line `detail`. For `staged_depth`, `value` and
`limit` are message counts. The depth read stops at one past `limit`, so the real backlog may be far
larger than `value`; `detail` names only the limit. For `disk_floor`, both are MiB free, and `detail`
gives the free MiB now. `value` is the measurement taken when the event was raised. The
payload carries no message content and no PHI.

Its inverse, `intake_resumed`, pages nobody and cannot be a rule's `event_type`. It resolves the open
`intake_paused` for the same bound. After a start, the engine also raises it once for each bound that
is turned off, with `value` and `limit` at 0. It raises it once more for a bound first measured clear
of its resume line. This clears a pause that an earlier run left open when it stopped. A bound first
measured between its resume line and its limit reports nothing until it leaves that band, because
another node on the same store may still be paused there.

**`config_changed` says a start loaded different config bytes than the store's baseline** (vault
BACKLOG #2597). At each start the engine compares its config fingerprint (ADR 0041 D1) with the
newest usable `config_loaded`, `config_reload` or `connection_flag_set` audit row. That row may come
from any node or engine shard, because they all share one config directory. A start that sees a
change raises `config_changed` once. Its `config_loaded` row records the outcome as `comparison`
(`compared`, `no_start_digest`, `no_baseline`, `degraded_baseline`, `scheme_mismatch` or
`read_failed`), plus `previous_fingerprint` and `changed`. Starts that race, such as engine shards
started together, can each raise it; the alert list folds them into one instance.

- A change applied with `POST /config/reload` and then restarted does not alert. A change that only
  a restart picked up does, by design: nothing else tells that deploy apart from an unrecorded edit.
- A connection flag toggle does not alert either. Its row vouches for the directory it wrote only
  when nothing else changed since the load, so a toggle never hides an edit nobody loaded.
- A fresh store, a baseline row with no fingerprint, or one taken under another fingerprint scheme
  raises nothing. The engine logs that at INFO.
- The check is alert-only. A baseline read that fails or takes over five seconds is logged at
  WARNING, and the start goes on.
- A start that never checked its config, because its read failed or it took no fingerprint,
  marks its own row `baseline_unchecked`, and every flag toggle row that process writes too. A
  later start passes over those rows, and over any row whose detail is not a JSON object (at
  WARNING), and compares against the newest usable row before them. So the change the unchecked
  start could not see is reported by the next start that can read. A config reload's row is
  usually not marked: applying the directory by reload vouches for it. When it is marked, and
  when a later start passes over it, is stated once in [SECURITY.md](SECURITY.md) (vault BACKLOG
  #2257).
- A reload can swap the graph after a start loads it and before its `config_loaded` row is written;
  on a cluster node, the convergence loop does this. The row still names the graph the start
  loaded, with its comparison. It is marked `superseded` and `baseline_unchecked`, and its
  `loosenings` is `null`, since the loosenings reader sees only the reloaded graph. A later start
  passes over it to the reload's own row.
- A start that could not take that snapshot still starts, with comparison `no_start_digest`. Its
  row is degraded with the `start_snapshot` step. Its `dir`, counts and `loosenings` are `null`,
  and it has no `fingerprint` key at all. A start that could not tell whether a reload swapped its
  graph names its own graph, degraded with the `start_swap_check` step and `loosenings` `null`. A
  later start passes over both rows.
- A convergence reload writes its own `config_reload` row, in the shape an operator reload writes
  (vault BACKLOG #3076). Its actor is `system:cluster-convergence` and its `initiator` is
  `cluster_convergence`. So the store's newest baseline names the graph the node converged on,
  whether the reload lands before or after the start's row. A convergence row that could not take
  a fingerprint is marked `baseline_unchecked`, so a later start passes over it.
- The pass-over looks through the newest 50 config rows at most. If none is usable, the start
  begins a new baseline and says at WARNING that a change made before those rows is not reported.

Its `connection` is `config:` plus the first 12 hex characters of the new fingerprint, so each
distinct config is its own alert. Nothing resolves it; an operator does. A rule cannot attach a
`control_action` to it. The payload holds both fingerprints, this process's node and engine shard,
and the baseline row's action, actor, time and node, plus a one-line `detail`. It carries no config
path, no git commit and no message content.

| Key | Type | Default | Notes |
|---|---|---|---|
| `webhook_url` | str | _unset_ | enable the **webhook** transport: HTTP `POST` the event as JSON here (fronts Slack/Teams/PagerDuty/custom inbound webhooks). |
| `webhook_timeout` | num | 10 | seconds per POST |
| `webhook_allowed_hosts` | list | `[]` | egress allowlist for the webhook host (`[]` = any); SSRF defense (ASVS 15.3.2/1.3.6) |
| `email_smtp_host` | str | _unset_ | SMTP server; with `email_from` + `email_to` set, enables the **email** transport |
| `email_smtp_port` | int | 587 | SMTP port |
| `email_from` | str | _unset_ | sender address (required for email), and the envelope sender (`MAIL FROM`). It must be one plain `local@domain`; a display name, a group or an encoded word is refused at startup. The full address rule, the domain's shape included, is in the `[egress]` `allowed_recipient_domains` row |
| `email_to` | list | _unset_ | recipient(s) (required for email). Via env: comma-separated `MEFOR_ALERTS_EMAIL_TO`. Each address, and each rule's `recipients` override, is held to the `email_from` rule after any display name is dropped; `RCPT TO` carries exactly that address |
| `email_use_tls` | bool | `true` | issue STARTTLS before sending. Selects TLS vs **cleartext** — it does not by itself decide whether the relay is authenticated; that is `email_tls_verify` |
| `email_tls_verify` | bool | `true` | verify the relay's certificate on that STARTTLS hop — chain + hostname + strict RFC 5280, TLS 1.2 floor ([#323](BACKLOG.md)). `false` keeps the session encrypted but accepts **any** certificate (MITM-able). Both `false` values are **loosenings**: `security_loosenings()` names them, `messagefoundry check`'s `alert-smtp-tls` advisory reports them, and on an enforcing PHI instance `serve` **refuses to start** unless `[security].allow_unverified_alert_smtp_tls` is also set |
| `email_tls_ca_file` | str | *(unset)* | PEM bundle of trust anchors for that hop. Unset = `[tls].internal_ca_file` if configured, else the OS trust store. A path, not a secret |
| `email_username` | str | _unset_ | SMTP login user (omit for unauthenticated relays) |
| `email_password` | str | _unset_ | **secret** — supply via `MEFOR_ALERTS_EMAIL_PASSWORD`, never the file (or use `email_password_secret`) |
| `email_password_secret` | str | _unset_ | connector `SecretProvider` reference (ADR 0019 §5) — when set and `[secrets].provider` is configured, the SMTP password is resolved from that backend (e.g. a Vault KV `path#field`) instead of `email_password`. A reference, not a secret. |
| `email_timeout` | num | 30 | seconds per send |
| `smtp_allowed_hosts` | list | `[]` | egress allowlist for the SMTP host (`[]` = any); parity with `webhook_allowed_hosts` (WP-11c) |
| `email_subject_template` | str | _unset_ | optional **operator-editable** alert-email subject (#138, [ADR 0127](adr/0127-operator-editable-alert-email-templates-with-a-non-phi-variable-allowlist.md)). Unset (the default, with its two siblings) = the fixed subject + key/value body, byte-identical to before. When set it is a `{name}` template over a **closed non-PHI variable allow-list**, validated at config load and **fail-closed** — an unknown or message-derived reference raises rather than rendering |
| `email_body_template` | str | _unset_ | the same, for the **plain-text** body. The plain-text part is **always** sent, even when an HTML alternative is configured |
| `email_html_template` | str | _unset_ | the same, adding an **HTML alternative** part whose substituted *values* are HTML-escaped. Never HTML-only — it supplements `email_body_template`, it does not replace it |
| `security_notifications_required` | bool | `true` | **secure-by-default gate (BACKLOG #188, ASVS 6.3.5/6.3.7).** On a **PHI** instance, if no effective out-of-band security-notification channel is configured — `[auth].notify_security_events` on **and** `email_smtp_host` + `email_from` set — `serve` **refuses to start (exit 2)**. **The refuse/warn split is `[security].enforcement`, not the production tier:** the gate reads `enforcing` ([`__main__.py`](../messagefoundry/__main__.py)), which is `enforce` by default on **all three** built-in env names, and all three derive PHI ([ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)) — so `serve --env dev` and `--env staging` on shipped defaults with no `[alerts]` SMTP are refused exactly like `prod`, not warned. (Measured: `dev`/`staging`/`prod` all resolve `data_class=phi, enforcing=True, channel_ready=False`.) It downgrades to a warning only under `enforcement = warn`. **This gate is why `[alerts]` is not optional on a stock instance** — configure the SMTP transport, or set `false` to accept the pull-only `GET /me/security-events` feed instead (audited). **The same gate also requires a reminder recipient (BACKLOG #2008, ASVS 6.4.5).** Host and sender are enough for the per-user notices, which are addressed to each account. The credential reminders (`initial_credential_expiring`, `cert_expiry`) go to the `[alerts]` notifier instead, and that is built only from `webhook_url`, or from `email_smtp_host` + `email_from` + at least one `email_to`. So when either reminder can fire (`[auth].initial_password_expiry_hours` or `[cert_monitor].warn_days` above `0`) and neither recipient is set, `serve` refuses under `enforce` and warns under `warn`. Setting this flag `false` waives that check too, with an audit line saying the reminders reach only the log. |
| `realert_seconds` | num | 300 | suppress re-notifying the same (event, connection) more often than this (anti-spam for a flapping lane). A matching rule's `cooldown_seconds` overrides it. |
| `rules` | list | `[]` | ordered `[[alerts.rules]]` table array — per-event severity, transport routing, thresholds, suppression, cooldown (see below). Empty = today's behaviour (every event → every transport at `warning`). |

#### `[[alerts.rules]]` — per-event routing (ADR 0014)
Each rule is a row in an **ordered** `[[alerts.rules]]` array; the **first matching rule wins** (so
put the most specific rules first). An event matching **no** rule keeps the default: notify **every**
configured transport at `warning` with the global `realert_seconds` — so adding a rule never silently
silences an event you didn't name. Matching is pure config (no code/`eval`).

| Key | Type | Default | Notes |
|---|---|---|---|
| `event_type` | str | `any` | match this event. The validator (`AlertRule._check_event_type`) accepts `any` plus the names in `_ALERT_EVENT_TYPES` (`messagefoundry/config/settings.py`), and **rejects anything else at config load**, so a typo is loud rather than a rule that never matches. That set is the source of record; at the time of writing it holds at least: `ad_reconcile_aborted`, `ad_reconcile_held`, `ad_session_revoked`, `administrator_granted`, `approval_approver_provenance`, `approval_stale_requester`, `approval_too_early`, `audit_write_failed`, `backup_failed`, `cert_expiry`, `config_changed`, `connection_error`, `connection_stopped`, `dr_activated`, `gcm_invocations`, `initial_credential_expiring`, `intake_paused`, `integrity_drift`, `lane_stuck`, `leadership_acquired`, `log_write_failed`, `message_stall`, `queue_buildup`, `saturation`, `secret_rotation`, `storage_threshold`, `store_privilege_warning`, `update_available`. Note the **event names are shorter than the prose names** used elsewhere in this file — the secret-rotation reminder is routed as `secret_rotation`, not `secret_rotation_due` |
| `connection` | str (glob) | `*` | glob over the connection name (e.g. `OB_*`, `IB_ACME_*`) |
| `min_depth` | int | _unset_ | `queue_buildup` only — match only when pending depth is at/over this |
| `min_oldest_seconds` | num | _unset_ | `queue_buildup` only — …or the oldest pending message has waited at least this long |
| `severity` | str | `warning` | `info` \| `warning` \| `critical` — tagged onto the event (webhook JSON + email subject) for downstream triage |
| `transports` | list | _all_ | which transports fire: subset of `["webhook", "email"]`; **unset = all configured**; **`[]` = SUPPRESS** (drop silently) |
| `cooldown_seconds` | num | _global_ | override `realert_seconds` for matching events (e.g. re-page a critical sooner) |
| `control_action` | str | _unset_ | `restart_inbound` \| `restart_outbound` — restart a connection when the rule fires ([ADR 0128](adr/0128-alert-rule-connection-control-action-auto-stop-restart-on-fire.md)). **Allowed only with a connection-scoped `event_type`** (BACKLOG #1898). The source of record is `_ALERT_CONTROL_EVENT_TYPES` in `messagefoundry/config/settings.py`; at the time of writing it holds `connection_stopped`, `connection_error`, `queue_buildup`, `message_stall`, `saturation` and `lane_stuck`. Config load refuses the action with `any` and with every other type. Those other types put a stand-in in `connection`, such as a bare username, `store` or a cert label. A restart aimed at a stand-in could hit an unrelated connection with the same name. With no `control_target`, the action aims at the event's own name, so pair `restart_outbound` with events from outbound connections and `restart_inbound` with events from inbound ones |
| `control_target` | str | _the event's connection_ | the connection `control_action` restarts, when it is not the one that fired. Config load refuses a value that is not a connection name, and refuses it on a rule with no `control_action` |

```toml
[alerts]
webhook_url = "https://hooks.example.com/services/XXX"   # webhook transport on
email_smtp_host = "smtp.example.com"                      # email transport on
email_from = "alerts@example.com"
email_to   = ["oncall@example.com"]

# Page (webhook) immediately and re-page every minute when any inbound connection stops.
[[alerts.rules]]
event_type = "connection_stopped"
connection = "IB_*"
severity = "critical"
transports = ["webhook"]
cooldown_seconds = 60

# A deep backlog on any outbound is critical; a shallow one only emails.
[[alerts.rules]]
event_type = "queue_buildup"
min_depth = 1000
severity = "critical"

[[alerts.rules]]
event_type = "queue_buildup"
severity = "info"
transports = ["email"]

# Stay quiet about a known-bursty test feed.
[[alerts.rules]]
connection = "OB_LOADTEST"
transports = []   # suppress every event for this connection
```

> A rule routing to a transport that isn't configured (e.g. `transports = ["email"]` with a webhook
> but no SMTP settings) is rejected at startup, so a typo can't silently black-hole an alert.
> **That check has one gap worth knowing, because the recipes below sit in it:** it lives inside the
> notifier factory ([`pipeline/alert_sinks.py`](../messagefoundry/pipeline/alert_sinks.py),
> `notifier_from_settings`), which returns early when **no** transport is configured at all. So with
> **zero** `[alerts]` transports your `[[alerts.rules]]` are never validated and never applied —
> events fall through to the `LoggingAlertSink` and are logged at `WARNING`, which is not a
> black-hole but is also not the page you asked for, and nothing tells you. Measured: a file with a
> `transports = ["webhook"]` rule and no `[alerts]` block loads and starts with `notifier = None`;
> add an email-only `[alerts]` and the same rule becomes `exit 2`. **A routing rule is only ever live
> alongside a configured transport — write the `[alerts]` block first.** Severity travels in
> the payload; **timed multi-stage escalation** ("email now, page in 15 min") is future work (ADR 0014
> §3) — rules give the static routing primitive it would build on.

### `[cert_monitor]`
Periodic TLS-certificate **expiry monitor**. Now that native off-loopback TLS is the supported posture
([`DEPLOYMENT.md`](DEPLOYMENT.md)), a silently expiring certificate is a hard PHI-feed outage at renewal
time. The engine scans the certs it actually serves with — the `[api].tls_cert_file` and every
connection's `tls_cert_file` (MLLP server/client identity) — and raises a **`cert_expiry`** alert (an
[`[alerts]`](#alerts) event — route it with a `[[alerts.rules]]` rule) when one is expired or within
`warn_days` of expiry. Only the **public certificate** is read (its `notAfter`), never a private key.
On by default with a 30-day window; set `warn_days = 0` to disable.

**Service-caller (inbound mTLS) certs — ASVS 6.4.5.** A cert an inbound *caller* presents is one the
engine only **verifies**, never serves, so the scan above cannot see it. Two arms cover it: the
cert-identity resolver checks the `notAfter` of each verified, allow-listed client cert **at the mTLS
handshake** and raises the same `cert_expiry` alert when it is inside `warn_days` (throttled per cert at
the `check_interval_seconds` cadence, since that path runs per request); and
[`[api].tls_client_cert_files`](#api) lets you list caller certs you hold copies of, so they are scanned
like any other file. The file list is what covers a caller whose cert expires **while it has stopped
connecting** — a handshake can only reveal a cert that is still being presented.

**CRL files.** The same scan reads each configured CRL file and alerts when its `nextUpdate` is past
or within `warn_days`. Past `nextUpdate`, every TLS handshake the CRL verifies fails, not only those of
revoked certificates. The scan covers an inbound connection's `tls_crl_file`, labelled with the
connection's name, and at least these settings, labelled with their dotted names (BACKLOG #299):
`tls.crl_file`, `logging.forward_tls_crl_file`, `auth.oidc_tls_crl_file`, `store.ssl_crl_file` and
`api.tls_client_crl_file`. To the notifier this is a `cert_expiry` event whose connection is the label
followed by ` (CRL)`, such as `tls.crl_file (CRL)`; match that in a `[[alerts.rules]]` rule. The log
line reads `crl_expiry`. A file holding several CRLs is judged by the one that expires first.

The engine reads a CRL when it builds a hop's TLS context and keeps that copy. About once a minute it
checks each CRL file a running hop holds. When the file has been replaced, it adds the new CRL to that
hop's context, with no restart (BACKLOG #299). OpenSSL then uses the newest CRL it holds for each
issuer. The engine applies a replaced file only when all three of these hold:

1. The file passes the rules a start applies. Every CRL parses, has a `nextUpdate`, is not a delta CRL
   and has not expired. Its BEGIN line starts a line: OpenSSL skips an indented CRL block, so the
   engine refuses one. The file carries no certificate the hop does not already trust.
2. Each CRL's signature verifies against a CA certificate in the hop's own trust store. OpenSSL checks
   that signature only during a handshake, so a badly signed CRL would load and then fail every
   handshake it judges. The reload cannot see an intermediate CA that the peer sends in its handshake,
   and may not see a CA in a CA directory or the system store. A restart applies such a file. Where
   the hop has its own CA file, adding the issuing intermediate to it lets later reloads verify the
   CRL without a restart. The engine checks again every pass, because a CA directory adds a CA only
   when a handshake first needs it.
3. For each CRL the hop holds, the file carries the same CRL or a newer one from the same issuer.
   The newer CRL was issued later, is already in effect and runs at least as long. It also has the
   same scope, signing key and critical extensions.

Otherwise the hop keeps the copy it holds, and the engine logs an ERROR once that names the reason and
what to do. A file failing rule 1 would also stop the engine starting, so fix the file. A file whose
CRL fails its signature check under rule 2 loads at a start but fails every handshake it judges. Fix
that too. A file failing only rule 3 needs a restart to apply. Examples are a rollback to an older CRL,
a file that drops an issuer, and a CRL signed under a new key. When the hops holding one file need
different things, the ERROR names the strongest: fix the file, then restart, then wait. When it names
a restart for a file that is not in effect yet, it also says not to restart before that time.

**A CRL that is not in effect yet is the exception: wait.** The engine applies it once it takes effect.
Do not restart before then. A start refuses a file whose only CRL for some issuer is not in effect yet,
because a hop would refuse every peer with it. Nothing else in the file reaches the hop either. If
that CRL is from an issuer the hop does not hold yet, take it out to apply the rest now. One exception to the wait: some CRL the hop holds may
lapse before the new CRL takes effect. Waiting then leaves a gap in which its peers are refused. So
the engine says to fix the file with a CRL that is in effect now. A start and a reload both allow
five minutes of clock skew, so a CRL from a CA whose clock runs a little ahead still counts as in
effect. At a start, such a CRL refuses every peer it judges until its `thisUpdate` passes, and the
engine logs a WARNING that says so.

A reload changes what the next full TLS handshake checks. An established connection is not checked
again, nor is a session resumed from an earlier handshake. So a newly revoked partner that stays
connected stays connected until it reconnects or you restart. Every reload stays in the hop's trust
store. After `crl_max_reloads` reloads of one file, a hop refuses the next and asks for a restart.

Until a hop is current, the scan judges the copy it holds as well as the new file. So the alert does
not clear on the file alone, and the alert's date can be the held copy's rather than the new file's.
When it is, the notifier event carries `held_copy` set to `true` (vault BACKLOG #2319). Its `detail`
names the setting whose hop holds the copy, and says what to do: wait for the reload, fix the file, or
restart. The log line says the same. A replaced file that is not near expiry raises no alert. Each
scan still logs a warning that a running hop holds an older copy, and why. If the file cannot be read,
the scan judges the held copy instead of skipping it.

**A held copy is matched by its file, not by its hop.** When two settings or connections name one
CRL file, each gets its own row, and a copy that one hop holds is reported under both. Each alert
then lists the other rows in `shared_with`. Its `detail` names the setting that holds the copy, so
read that, not the row's label, to find the hop to restart.

**A CRL inside a CA file counts too, on an outbound hop that checks revocation** (vault BACKLOG
#2319). The outbound hops that resolve a trust anchor load `[tls].internal_ca_file`, or a
connection's own `tls_ca_file`, whole, CRL blocks included. So does the syslog forwarder with
`[logging].forward_tls_ca_file`. Once a CRL setting turns revocation checking on for that hop, those
CRLs are checked too, and past `nextUpdate` one refuses every peer under its issuer. The scan watches
each one in a row labelled `held-crl:` and the CA file's path. The reload does not apply a changed CA
file, so a refreshed CRL inside one needs a restart, and the alert's `detail` says so. Put a CRL in
the hop's CRL setting instead to have it applied without a restart. The listeners, OIDC and AD load
only the certificates from their CA files, so a CRL there is ignored, as the CA file rows above say.
The PostgreSQL store's `[store].ssl_root_cert` is not watched this way: it records no held copy.

At least two cases still need a restart: a CRL inside a CA file, and a replacement refused under rule
3. A hop may hold a CRL from a path no setting above names, such as an inbound `tls_crl_file` given
through `env()`. The scan then adds a row for it, labelled `held-crl:` and the path. The
`[store].ssl_crl_file` hop builds a fresh context for every new pool connection and records no held
copy. If another setting names the same file, that file's row still reports those hops' copies. CRLs
share `warn_days` with certificates. So a CRL reissued more often than `warn_days` sits inside the
window and alerts on every scan.

| Key | Type | Default | Notes |
|---|---|---|---|
| `warn_days` | int | 30 | alert when a served cert expires within this many days; **`0` disables** the monitor |
| `check_interval_seconds` | num | 43200 | rescan cadence (default 12h); the per-cert re-alert throttle is `[alerts].realert_seconds` |
| `crl_max_reloads` | int | 10000 | how many replaced copies of one CRL file a running hop takes before it refuses the next and asks for a restart (BACKLOG #299). Must be above 0. The CRL reload reads it even when `warn_days` is `0`. The default outlasts a year of hourly CRLs (8,760). **What each held copy costs**, measured on CPython 3.14 / OpenSSL 3.5.7: about four times the CRL file's size plus about 1.5 KB of memory. Each handshake takes about 2 microseconds longer per copy held for its issuer. So 10,000 copies of a 1 KB CRL hold about 40 MB and add about 20 ms to each handshake. Lower it for a large CRL that is reissued often. |

```toml
[cert_monitor]
warn_days = 45            # start warning 45 days out

# The rule below only does anything alongside a configured transport — a `[[alerts.rules]]` in a file
# with no [alerts] block is silently inert (the notifier is never built). Declare the webhook here:
[alerts]
webhook_url = "https://hooks.example.com/services/XXX"

# Page (don't just email) when a served cert is close to expiry.
[[alerts.rules]]
event_type = "cert_expiry"
severity = "critical"
transports = ["webhook"]
```

### `[secrets]` — connector `SecretProvider` selection
Selects **how a named connector credential is sourced** ([ADR 0019](adr/0019-pluggable-keyprovider-hsm-kms-vault.md)
§5) — from an external secrets backend **instead of** a `MEFOR_*` env var. The connector-secret twin of
[`[store].key_provider`](#store) (which sources the store DEK).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `provider` | str | `none` | `none` \| `env` \| `vault`. **`none` (default) consults no provider — every credential stays env-sourced (byte-identical).** `env` resolves a reference as an env-var name; `vault` reads **Vault KV v2** behind the lazy `[vault]` / `hvac` extra (the **same** dependency the store's Vault `key_provider` uses — no new dep). Names a *provider*, not a secret. |

A provider is consulted **only** for a credential whose per-credential `*_secret` reference is set — today
`[auth].ad_bind_password_secret` and `[alerts].email_password_secret` (the wired points); the SQL Server
store password is seam-only (managed identity is preferred there). A reference is `"<kv-path>"` or
`"<kv-path>#<field>"` for `vault` (field defaults to `value`; KV mount from `MEFOR_SECRETS_VAULT_KV_MOUNT`,
default `secret`); Vault address/token come from `MEFOR_SECRETS_VAULT_ADDR` / `MEFOR_SECRETS_VAULT_TOKEN`
(falling back to hvac's `VAULT_ADDR` / `VAULT_TOKEN`). Point `MEFOR_SECRETS_VAULT_CA_FILE` at the PEM of
the CA that issued your Vault server's certificate to verify that hop against your own PKI instead of the
public bundle `requests` ships with (BACKLOG #1180; the store KeyProvider's twin is
`MEFOR_STORE_VAULT_CA_FILE`) — a path, not a secret, and unset leaves the hop exactly as it was.
**A web proxy reaches both Vault clients with no engine setting.** They honour `HTTPS_PROXY`,
`HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY`, and on Windows the system proxy. Through an `https://` proxy,
the TLS leg to the proxy uses the same approved suites as the Vault leg. It is verified against the
same anchor too: the CA file when one is set, so the proxy's certificate must chain to it, and the
public bundle otherwise. There is no separate proxy anchor, on purpose (BACKLOG #2318). The proxy
leg does not protect the token; the Vault leg's own TLS, end to end inside the tunnel, does. So for
a proxy whose certificate comes from another CA, use an `http://` proxy in front of the `https://`
Vault address. **Do not add the proxy's CA to the Vault CA file:** the Vault leg would then accept
a certificate that CA issued for the Vault host name. An `http://` Vault address through an
`https://` proxy is **refused**, because that leg could not be verified. Use an `https://` Vault
address (BACKLOG #300). `NO_PROXY` is not a way around it either: a remote `http://` Vault reached
directly is refused too, as the next paragraph says.
**Each Vault client refuses a Vault address that is not `https://`** (BACKLOG #2317). That holds
for at least the KV secret provider here, the store key provider and the Transit cipher. It covers
a direct `http://` address and one behind an `http://` proxy, including hvac's own `VAULT_ADDR`
fallback. The one `http://` address allowed is a loopback Vault that the client reaches with no
proxy, because that hop stays on the box. Loopback is decided without DNS: the name `localhost` or
a loopback IP literal, and no other name, whatever it resolves to. An address that does not read as
one well-formed URL is refused too. The refusal comes when the client is built, as the provider's
own fail-closed error, and again before each send in case a proxy appeared since. Its text names no
part of the address, and `[security].enforcement` does not relax it. An `https://` Vault behind an
`http://` proxy is still allowed: the token rides inside the TLS tunnel to Vault.
**A proxy URL that carries credentials must be `https://`** (BACKLOG #2547). requests sends a
`user:password@` from the proxy URL to the proxy itself. Through any proxy that is not `https://`,
those credentials cross the network in cleartext. So the Vault clients refuse such a proxy,
whatever the Vault address and wherever the proxy is, loopback included. Any `@` in the proxy URL
counts as credentials. The check reads the proxy variables in either case, `ALL_PROXY` and the
Windows system proxy. It refuses at the same two points and in the same form as the rule above.
Its text names no part of the proxy URL, and `[security].enforcement` does not relax it. Use an
`https://` proxy, or one that takes no credentials in its URL.
**Fail-closed:** a reference with `provider = none`,
an unknown provider, a missing `[vault]` extra, or an unresolvable/empty secret raises at load/connect —
never a blank credential; the value is never logged.

### `[secret_rotation]`
Periodic **secret-rotation reminder** ([ADR 0019](adr/0019-pluggable-keyprovider-hsm-kms-vault.md) §5.1) —
the secret-side twin of [`[cert_monitor]`](#cert_monitor). A TLS cert carries its own expiry, but a
long-lived secret (the **store data-encryption key** today; connector credentials in a future
`SecretProvider`) has none, so a stale key can sit unrotated with no in-engine signal. The engine
periodically compares each tracked secret's operator-recorded **last-rotated date** against its **max
age** and raises the rotation-due alert (an [`[alerts]`](#alerts) event) when it is overdue or within
`warn_days` of due. **Route it as `event_type = "secret_rotation"`** — that is the wire name the rule
validator accepts; the longer `secret_rotation_due` is the internal `AlertSink` method name and is
**rejected at config load** if you write it in a rule. It reads only the rotation
**dates** you configure here — **never any secret value** (PHI-free). It never *rotates* a key (run
`rotate-key` for that). For every secret class except the store DEK it is a reminder only, unless you
opt that class into `enforce_secret_expiry_classes` (below).

**The store DEK's calendar expiry is ENFORCED** (ASVS 13.3.4, BACKLOG #1004). Under
`[security].enforcement = enforce` with a keyed store, a DEK past `store_key_max_age_days +
enforce_grace_days` escalates its alert at restart (`enforced = true`) **and refuses to start the
engine**. A DEK whose age cannot be determined — the rotation-meta reconcile failed and no
`store_key_last_rotated` is set — refuses on the same rule: an undetermined age is not a young one. This
matches the same key's **usage** ceiling, which has always refused unconditionally at 2^32 encrypts. Set
`enforce_store_key_expiry = false` to keep the alert and drop the refusal; that is a **security
loosening** and it is named on every boot and in `GET /security/posture`.

**The other secret classes refuse only if you opt them in** (ASVS 13.3.4, BACKLOG #1932). List a class
in `enforce_secret_expiry_classes` and the same rule applies to it. Under `[security].enforcement =
enforce`, a listed class the engine holds that is past `secret_max_age_days + enforce_grace_days`
refuses to start the engine, with an `enforced = true` alert. So does a listed class the engine holds on
a keyed store with no recorded age, which means the rotation-meta reconcile failed. The error names each
class, its age, the limit and the two ways out. Rotate the secret, and the next start detects the new
value and resets its clock. Or remove the class from the list, and it goes back to alert-only. The list
ships empty, so a class you do not list only alerts, as before. Under `enforcement = warn` the list does
nothing but log a warning. A keyless store, and a `vault_transit` store, fingerprint no secrets, so
there the list refuses nothing and the engine logs a warning saying so.

Valid entries are `MEFOR_STORE_PASSWORD`, `MEFOR_AUTH_AD_BIND_PASSWORD`, `MEFOR_ALERTS_EMAIL_PASSWORD`,
`MEFOR_AUTH_OIDC_CLIENT_SECRET`, `MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY`,
`MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY_PASSWORD`, `MEFOR_API_TLS_KEY_PASSWORD`, `MEFOR_STORE_VAULT_TOKEN`,
`MEFOR_SECRETS_VAULT_TOKEN`, `MEFOR_AI_API_KEY`, and `connector`. `connector` covers every per-Connection
`env()` credential, since their names are yours and unknown at load. Any other name is refused at config
load, and so is `MEFOR_STORE_ENCRYPTION_KEY`, which has its own knob.

The store DEK is tracked **live-by-default** (ASVS 13.3.4): at first keyed start the engine records a
non-secret tracked-since stamp (the DEK key-id + first-seen date) in store meta and watches the DEK off
it, so `store_key_last_rotated` is an **override**, not a prerequisite. The connector/AD/SMTP/Vault/OIDC
credentials the engine holds are tracked too — each fingerprinted with a DEK-derived keyed MAC, its clock
reset when the fingerprint changes (rotation auto-detected). A 14-day look-ahead applies once a secret is
tracked; set `warn_days = 0` to disable the reminder.

| Key | Type | Default | Notes |
|---|---|---|---|
| `warn_days` | int | 14 | alert when a tracked secret is due within this many days; **`0` disables** the reminder |
| `check_interval_seconds` | num | 86400 | rescan cadence (default 24h); the per-secret re-alert throttle is `[alerts].realert_seconds` |
| `store_key_last_rotated` | str | — | ISO `YYYY-MM-DD` the store DEK was last rotated; **unset ⇒ the DEK is still tracked live-by-default** off a persisted first-seen stamp (this date is an override) |
| `store_key_max_age_days` | int | 365 | rotate the store DEK within this many days of its effective last-rotated (the operator date if set, else the persisted stamp) |
| `secret_max_age_days` | int | 365 | max age for the **non-DEK** tracked secret classes (connector/AD/SMTP/Vault/OIDC), alerted this many days after their last observed fingerprint change |
| `enforce_grace_days` | int | 30 | under `[security].enforcement=enforce`, a DEK older than `store_key_max_age_days + this` escalates its rotation alert **and refuses to start** (see `enforce_store_key_expiry`) |
| `enforce_store_key_expiry` | bool | `true` | under `[security].enforcement=enforce`, a store DEK past `store_key_max_age_days + enforce_grace_days` — or one whose age cannot be determined — **aborts engine start**. `false` keeps the alert, drops the refusal, and is reported as a **security loosening** |
| `enforce_secret_expiry_classes` | list | `[]` | non-DEK classes whose calendar expiry **aborts engine start** under `[security].enforcement=enforce`, past `secret_max_age_days + enforce_grace_days` or with no recorded age. Entries are the `MEFOR_*` class names above or `connector`; an unknown name is refused at load. Empty keeps every non-DEK class alert-only |

```toml
[secret_rotation]
store_key_last_rotated = "2026-01-15"   # when you last ran rotate-key
store_key_max_age_days = 365            # remind me a year later
warn_days = 30                          # start 30 days ahead
# Optional: also refuse to start on an expired AD bind password or connector credential.
# enforce_secret_expiry_classes = ["MEFOR_AUTH_AD_BIND_PASSWORD", "connector"]

# As above: without a configured transport the rule is inert, so declare the email one here.
[alerts]
email_smtp_host = "smtp.example.com"
email_from = "alerts@example.com"
email_to   = ["oncall@example.com"]

# Notify when the store DEK is overdue for rotation.
[[alerts.rules]]
event_type = "secret_rotation"          # the WIRE name — "secret_rotation_due" is rejected at load
severity = "warning"
transports = ["email"]
```

### `[cluster]` — active-passive HA coordination (Track B)
**Server-DB-backed.** Introduces the multi-node coordination seam — a `nodes` table, a per-node
heartbeat, (Track B Step 4) **leader election**, and (Step 6) **cross-node reference + config-reload
convergence** — *without changing single-node behavior*. It runs as **active-passive** HA: one leader
runs the whole graph, a standby takes over on failure. (The horizontal **active-active** scale-out path
— per-lane ownership running the graph on every node — was **dropped (2026-06-18) and its code removed**;
it is not a planned milestone.) With
`enabled = false` (the default) the engine uses a no-op coordinator and runs **byte-identically** to
before. Enabling it requires a **server-DB** store **and** `[store].pool_size >= 2` — a clustered node
drives concurrent background work (the membership/lease-renewal maintenance loop + the per-stage workers)
against the pool, so a pool of 1 would serialize everything (prefer `>= 3`). A cross-section validator
refuses either violation at config load. Two backends qualify:

- **`postgres`** — the full coordinator: leader election, the row leases, and the leader reclaim sweep,
  run as active-passive HA (the leader runs the graph; a standby takes over on failure).
- **`sqlserver`** — **active-passive too**: the same self-fencing leadership lease (one leader drains
  the graph; a standby takes over on failure). A single active node (the leader) processes at a time, so
  the `reclaim_expired_leases` background sweep below applies on Postgres; on-promotion recovery covers
  both backends.

SQLite remains single-node (cluster coordination is refused on it).

With `[cluster].enabled` on Postgres, **leader election is built** as a **self-fencing lease**
(Workstream A2): exactly one node across the cluster holds the `leader_lease` row and is the
**leader** — it renews the lease every `heartbeat_seconds` (to `DB_now + leader_lease_ttl_seconds`,
on the database's own clock so node clock skew is irrelevant to who may hold it), and a standby
acquires only once that lease has **expired**. A leader that cannot renew within
`leader_fence_timeout_seconds` (which must be `< leader_lease_ttl_seconds`) **self-fences** — it stops
acting as leader *before* the lease can expire and a standby acquire it, so a network-partitioned old
leader never double-processes (the split-brain guard). The leader-only **WRITE singletons**
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
only the **leader** polls a poll source. Under active-passive HA the whole graph — **listen** sources
(`mllp`, `tcp`) and all the **staged-queue workers** (router / transform / delivery) alike — runs on the
**leader only**; a standby binds no listeners and runs no workers (so poll-source gating is
belt-and-suspenders, and the queue's `FOR UPDATE SKIP LOCKED` + row leases serve intra-node concurrency
and failover recovery rather than concurrent multi-node draining). The brief overlap during a leadership
transition (the old leader's last in-flight poll vs. the new leader's first) is bounded by the same
at-least-once guarantees that cover a crash mid-poll — the file-rename / row-claim atomicity and the
downstream queue's idempotent handoff make a re-read a tolerated duplicate, never data loss. The
worst-case transition window is bounded by the lease timing: a partitioned leader keeps polling until
it self-fences (within `leader_fence_timeout_seconds`), and a standby cannot take over until the lease
expires (`leader_lease_ttl_seconds`) — and `fence < TTL` guarantees the old leader has stopped first.
For a
`database` source the row-claim atomicity is the operator's `poll_statement`/`mark_statement` (claim
with a status flag or `UPDATE ... RETURNING`); the engine owns the atomic rename only for file sources.

If the leader stops cleanly it expires its lease so a follower acquires leadership at once; if it
crashes or is partitioned, the lease ages out and a follower acquires after at most
`leader_lease_ttl_seconds`. **Single-node operation is unchanged** (the no-op coordinator is always
leader, so every poll source always scans, runs the unconditional startup reset, and spawns no leader
sweep).

**Per-lane FIFO survives failover.** Because the graph runs on the **leader only**, per-lane FIFO is
naturally serialized by that single processor — there is no concurrent multi-node draining of a lane to
reorder. Across a failover the order still has to be preserved for a lane whose head was in flight on the
crashed/fenced prior leader: the ordinary FIFO claim (`claim_next_fifo`) reclaims that **stranded head**
— this lane's expired-lease inflight row, back to pending **in the same transaction, before the head
SELECT** — so the recovered head blocks the lane rather than being skipped, and a later row can never
deliver ahead of it (the recovery does not wait on the leader's periodic sweep). This **replaced** the
dropped active-active per-lane lease mechanism (the removed `lane_leases` table / per-lane ownership). The
wall-clock row lease carries the NTP assumption: keep `[store].lease_ttl_seconds` comfortably above clock
skew + the claim cadence. **Single-node is byte-identical** (the no-op coordinator is always leader);
SQLite and SQL Server behave the same single-active-processor way.

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

> The coordination seam is **built**: leader election (self-fencing lease), leader-gated singletons +
> poll-source intake, failover-safe per-lane FIFO (the stranded-head reclaim above), cross-node reference
> + config convergence, transform-STATE cross-node read-through (Step 6b), and the read-only `/cluster`
> ops API (Step 7) — a one-time startup `INFO` summarizes the operational assumptions. This is the
> supported **active-passive** HA model (one leader drains the graph; a standby takes over on failure),
> on **Postgres or SQL Server**. The horizontal **active-active** scale-out path (many nodes processing
> concurrently) was **dropped (2026-06-18) and its code removed** — it is not a planned milestone. On
> both backends, failover recovers the prior leader's in-flight rows on promotion, safe because the old
> leader self-fences before its lease expires.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | turn on the coordination seam; requires a server-DB store (`[store].backend` = `postgres` or `sqlserver`) and `[store].pool_size >= 2` |
| `node_id` | str | _unset_ | override the auto id (`host:pid:hex`); pin for a stable identity / tests. Unset → reuses the store's lease owner-id, so node-id == owner-id. Pinned, a restarted node also settles the dual-control releases it left `executing` (SECURITY.md, "A restart settles its own leftover releases") |
| `heartbeat_seconds` | num | 10 | how often a node refreshes its `last_seen` heartbeat **and** renews its leadership lease (no separate leader-check knob). Must be > 0 |
| `node_timeout_seconds` | num | 30 | a node is considered dead when its `last_seen` is older than this (the `/cluster/nodes` freshness filter). The leadership **lease** — not this timeout — is what transfers leadership. Must be > 0, and must exceed `heartbeat_seconds` |
| `reclaim_interval_seconds` | num | 30 | how often the **leader** runs the lease-reclaim sweep that recovers crashed nodes' in-flight rows (followers no-op). Must be > 0 |
| `leader_lease_ttl_seconds` | num | 30 | the leadership lease TTL (active-passive self-fencing). The leader renews to `DB_now + this`; a standby acquires only once the lease has expired (on the DB clock, so node skew is irrelevant). Must be > 0 |
| `leader_fence_timeout_seconds` | num | 20 | a leader that can't renew within this (its own monotonic clock, no DB I/O) self-fences — the split-brain guard. Must be > 0, `> heartbeat_seconds`, and `< leader_lease_ttl_seconds` |
| `lease_renew_timeout_seconds` | num | *derived* | statement timeout on the leadership-lease acquire/renew round trip (ADR 0157 Inc 0). Without it the renew inherits `[store].command_timeout` (30 — the lease TTL itself, and unbounded when an operator takes the documented `command_timeout = 0`), so a renew issued just before this node self-fenced could still land and re-extend the lease it is standing down from. **Leave it unset** and it is derived from the **detection margin** `leader_lease_ttl_seconds - leader_fence_timeout_seconds - the fence tick`: half the margin, capped at 5.0 s. At the shipped 10/20/30 the margin is 9.0 and this resolves to **4.5**; tighten the fence/TTL pair and it tightens with them, so lowering all three timings proportionally needs no change here. Set it explicitly and it is **checked, not clamped**: it must be > 0 and strictly below the margin, or the engine refuses the config. A fence/TTL pair leaving **no margin at all** is refused whatever this is set to. **Postgres only:** the SQL Server coordinator's renew still inherits `[store].command_timeout`, a named open residual of ADR 0157 Inc 0. **On Postgres it also bounds a stepdown's release write** (BACKLOG #2523): that write and the renew each get this long to run and this long to hand their connection back, so a statement cancelled on a hung server frees its connection within it rather than never. Waiting for a connection on a busy pool is bounded separately, by `leader_fence_timeout_seconds`, and does not count against this value. A stepdown whose write misses it answers `503 release-unconfirmed`, which a retry re-sends. The coordinator's other statements, such as the heartbeat, are bounded by `leader_fence_timeout_seconds` instead |
| `acquire_delay_seconds` | num | 0 | **leader-preference handicap** (ADR 0096, per-node). Seconds this node waits PAST the lease-expiry time before it may take over an **expired** lease, so a preferred (`0`) node wins the routine take-over race. NEVER delays a renewal by the current leader, and only ever makes a node claim later — so it can't open a two-leader window. Governs take-over of an expired lease only (the first election on an empty table is a plain race). Must be between `0` and `3600` (an hour); the engine refuses anything outside that, including `inf` and `nan`, because a planned stepdown pauses the drained node for the longest sibling delay (BACKLOG #2539). Surfaced per-node in `/cluster/nodes` |
| `promotable` | bool | true | **non-promotable standby** flag (ADR 0096, per-node). `false` = this node may never become leader (never inserts/takes-over/renews the lease); a node that somehow already leads steps down cleanly. Use for a warm, passive DR engine. **At least one promotable node must exist** or no node ever acquires the lease. `[dr].activate` cannot be combined with `[cluster].enabled` (a warm DR node is a non-promotable member, not a `[dr]` box). Surfaced per-node in `/cluster/nodes` |

#### `[cluster.vip]` — engine-managed virtual IP (ADR 0056, Windows-only)

**Windows-only.** Engine-managed VIP is a Windows feature at v1, and IPv4 only; IPv6 is deferred on every
platform. Linux and container deployments keep the external floating VIP or load balancer described in
[CLUSTERING.md](CLUSTERING.md) §"Client reconnect". The settings themselves load on any platform.

**The engine checks this block at load and does nothing else with it yet.** No code in this build binds,
releases or announces the address. That controller is a later change, so the engine logs a WARNING at
load when `enabled` is on. Keep the external floating VIP or load balancer in front of the cluster until
then. The design, including what it can and cannot promise about split-brain on the wire, is
[ADR 0056](adr/0056-engine-managed-vip-failover.md).

Leaving the block out, or switching `enabled` off, changes nothing. A switched-off block is never
refused for the values it holds, but unknown keys in it are still refused, as in every section. The
block is file-only. There is no `MEFOR_CLUSTER_VIP_*` environment override, and such a variable is
dropped like any other unrecognized env key.

With `enabled = true` the engine **refuses to load** when:

- `[cluster].enabled` is not `true`, or `[store].backend` is not `postgres` or `sqlserver`;
- both `prefix` and `netmask` are set, or neither is;
- `address` is missing, is not IPv4, or is unspecified, loopback, link-local, multicast, reserved, or the
  network or broadcast address of its own subnet;
- `interface` is missing or blank, or has leading or trailing spaces, a double quote, or a non-printable
  character;
- `release_grace_seconds` is below 0, or is not below `[cluster].leader_fence_timeout_seconds`.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | turn engine-managed VIP on. Needs `[cluster].enabled = true` on a `postgres` or `sqlserver` store |
| `address` | str | _unset_ | the floating IPv4 address. Required when enabled |
| `interface` | str | _unset_ | this node's Windows connection name, for example `Ethernet0`. Required when enabled, and matched exactly |
| `prefix` | int | _unset_ | subnet prefix length, 1 to 32. Set this or `netmask`, not both |
| `netmask` | str | _unset_ | subnet mask in canonical dotted-decimal form, for example `255.255.255.0`. Must be contiguous; a hostmask such as `0.0.0.255` is refused. Set this or `prefix`, not both |
| `gratuitous_arp` | bool | `true` | announce the address with an IPv4 gratuitous ARP after binding it |
| `release_grace_seconds` | num | 2 | how long a newly promoted leader waits before it binds and announces the address, so an old leader that just fenced has time to let go of it. Must be `>= 0` and below `[cluster].leader_fence_timeout_seconds`. The default is held to that rule too, so a fence timeout of 2 or less needs a smaller explicit value |

Either mask form reaches the privileged helper (`mefor-net-helper`) as one dotted-decimal string, the
`mask` field of its `bind` request.

```toml
[cluster]
enabled = true          # [cluster.vip] is refused at load without this

[cluster.vip]
enabled   = true        # off by default; see the refusal list above
address   = "10.20.0.50"
interface = "Ethernet0"
prefix    = 24          # or netmask = "255.255.255.0", never both
# gratuitous_arp        = true    (the default)
# release_grace_seconds = 2.0     (the default; keep it below leader_fence_timeout_seconds)
```

### `[backup]` — scheduled DR backup / restore-verify
Engine-managed **scheduled + on-demand DR backup** of the config bundle and the SQLite store, written as
one AES-256-GCM `.mfbak` archive to a local/UNC destination (#60,
[ADR 0049](adr/0049-turnkey-dr-backup-restore-verify.md)). **Opt-in:** `enabled = false` (the default) is a
complete no-op. When enabled, the leader-gated `BackupRunner`
([pipeline/dr_backup.py](../messagefoundry/pipeline/dr_backup.py)) takes a **consistent SQLite snapshot**
(read-only against the live store — it never claims or mutates a staged-queue row), bundles the config dir
the running graph came from (the last applied reload's root, else `--config`), encrypts under the existing
store DEK (ADR 0019 KeyProvider), applies keep-N retention, runs a lightweight restore-verify, and records one PHI-free `dr_backup` audit row. **No cloud target** — local /
UNC only, so it adds no egress. On a **server-DB** store (Postgres/SQL Server) the *database* backup is
DBA-delegated (#52): config-only, or skipped, per `config_only_on_server_db`.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | opt-in master switch; a deployment with no `[backup]` is unaffected |
| `destination` | path | `""` | local or UNC destination dir (e.g. `D:/mefor-backups`). **Required (non-empty) when enabled.** A cloud URL (`s3://`, `https://`, …) is **rejected** — there is no cloud target |
| `schedule_at` | str | `"02:00"` | daily local `"HH:MM"` the scheduled backup runs at (the same clock grammar as `[retention].vacuum_at`). `""` = **on-demand only** (the `messagefoundry backup` CLI), no scheduled pass |
| `retention_keep` | int | `7` | keep-N: after a successful, **verified** new archive, prune the oldest archives beyond the newest N at the destination. `0` = keep all, which on an enforcing instance needs `[security].allow_keeping_backup_archives_indefinitely = true` or `serve` refuses (BACKLOG #1967). Only archives that passed every configured check are counted: a backup is written as `<name>.part` and renamed onto its canonical name after the verify, so a verify-**failed** archive keeps a `.failed` name and can evict a good one in neither this prune nor any later one. The flip side: `.failed` and `.part` files at the destination sit **outside** keep-N and nothing expires them — clear them yourself (ADR 0049) |
| `snapshot_method` | str | `vacuum_into` | `vacuum_into` (default; a defragmented copy) or `online_backup` (a page-for-page copy). Neither holds the store write lock for the copy (BACKLOG #1937). The copy still has costs, so an off-peak `schedule_at` remains sensible; ADR 0049 points to where they are stated |
| `include_config` | bool | `true` | bundle the running config dir (the last applied reload's root, else `--config`) into the archive, so the cold seed is self-sufficient (store **plus** the config that interprets it) without assuming the DR box can reach the org's git repo. The manifest and the `dr_backup` audit row record `config_bundled`, the `config_dir` the pass read, and `config_bundle_error`. When that dir is gone or cannot be listed, a full backup still succeeds with the store snapshot, logs one WARNING naming the directory and the error class, and records `config_bundled: false` with that class; no alert is raised for it. A config-only backup fails instead, as a `snapshot` failure. The `messagefoundry backup` CLI bundles its own `--config` argument instead |
| `verify_after_backup` | bool | `true` | run the lightweight restore-verify after every backup (open + `integrity_check` + row-count). On by default — a backup nobody has opened is a backup that silently doesn't restore |
| `full_restore_verify` | bool | `false` | the heavier verify: restore the snapshot to a throwaway temp DB, open it through the real `open_store` path **under this instance's live `[store]` settings** (only the path and the backend substituted), then decrypt and authenticate its cipher-covered cells and report how many were opened. A snapshot holding sealed cells that these settings resolve no key for is reported `KEY_MISMATCH`, not `FAIL` — the archive is fine, the key configuration is not. On-demand / opt-in extra, deliberately **not** the per-backup default |
| `config_only_on_server_db` | bool | `true` | on a Postgres/SQL Server store the DB backup is DBA-delegated (#52), so back up the **config bundle only**. `false` = skip the backup entirely on a server-DB store (not even a config-only archive) |
| `allow_unencrypted` | bool | `false` | audited escape permitting a **cleartext** archive on a **no-key** instance (the parallel of `[security].allow_unencrypted_phi`). Left `false`, a keyless instance **refuses** to write the archive rather than putting message bodies on disk in the clear. **This row used to say a PHI instance refuses regardless of the flag. That was never true of the code** — `BackupRunner` reads the key and this flag and nothing else, so on a keyless instance setting it would write a plaintext archive. Every instance carries patient data now ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)), so configure `MEFOR_STORE_ENCRYPTION_KEY` instead of reaching for this |

### `[dr]` — third-tier disaster-recovery standby
A **right-sized DR box** that activates only when the whole HA pair / site is gone and then runs **only the
high-priority feeds** in a deliberately degraded mode — the inverse of the dropped active-active scale-out
(it runs *less*, not more) (#61, [ADR 0048](adr/0048-third-tier-disaster-recovery-standby.md)). **Opt-in:**
`enabled = false` (the default) is a complete no-op. The cold seed is **two steps, and the engine does not do
the first one for you**: restore the `[backup]` `.mfbak` archive to the DR box's store path yourself with
`messagefoundry restore <archive> --to <store path>` (it refuses to overwrite an existing store), then
activate. On activation the engine restore-**verifies** that archive (fail-closed if the KeyProvider/DEK is
unreachable at the DR site), **refuses if the DR store does not carry the verified seed** — an empty store
means the restore never happened — starts only the connections whose resolved priority tier is at or above
`priority_threshold` (the rest report `status: "filtered"`), and is fenced by **acquire-VIP-or-abort**. **Activation is manual** — `POST
/dr/activate`, gated by the `dr:operate` permission; no health probe ever activates it. `enabled`/`activate`
are read at engine start. `[dr].activate` **cannot be combined with `[cluster].enabled`** (refused at load):
a warm DR-site engine is a non-promotable cluster member, not a lease-contending DR box.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | is this deployment a DR standby box at all? `false` = the normal run-profile (every connection starts, subject only to ADR 0031), byte-unchanged |
| `activate` | bool | `false` | should this box come up **under the DR run-profile** on this boot — the startup activation latch, distinct from the runtime `POST /dr/activate` endpoint. Enabled but `activate = false` is *provisioned-but-passive*: the box binds **no** inbound listener, of any tier (vault BACKLOG #3140). ADR 0048's load balancer moves the VIP to the node that answers, so a passive box must answer on nothing. Each inbound reads `status: "filtered"`, and the start logs one WARNING saying why. Its outbounds are built as usual. A reload or dry run still checks the listeners an activation would bind. So a config the activation would refuse is refused before the disaster. A bind fault that only a bind can find, such as a port in use, shows only when the activation binds. An operator start of an inbound still binds it, until the next reload parks it again or the close of its schedule window stops it. An alert rule's restart and the scheduler bind nothing. `POST /dr/activate` then turns the run-profile on in place: it re-applies the graph the engine is already running, parks every connection below `priority_threshold` (`status: "filtered"`), and keeps it parked across later reloads. While an outbound is parked, an operator start, stop or restart of it answers `409`. An alert rule's restart of a parked connection does nothing. `POST /dr/release` parks every inbound before it unbinds them and drains, then stops parking outbounds. The next reload binds no listener, as on any passive box. A parked outbound then runs again, unless an operator or its schedule had paused it first. An `auto_start = false` outbound stays parked by its own gate. A failed release leaves the box active, with the run-profile's parks in place. It also parks a below-threshold inbound an operator had started, when the release stopped it and it is still down. Only an operator start binds that one again. The listeners at or above `priority_threshold` that it unbound stay down. `POST /config/reload` binds them again, and so can their schedule window or an alert rule's restart. A reload skips an `auto_start = false` one. The activation applies nothing from the config dir: it only digests it, for the audit record. If the running config dir on disk no longer matches the running graph, the `dr.activate` audit row records both digests and the engine logs a WARNING; only `POST /config/reload` applies those bytes. A no-op unless `enabled` |
| `activation_mode` | enum | `manual` | `manual` is the **only built mode** — the DR box promotes solely on the explicit, RBAC-gated operator action. `auto` (the box detects HA-pair loss and self-promotes) is named so a forward-looking config is explicit, but config load **rejects** it with a "not yet supported" error — never a silent no-op |
| `priority_threshold` | enum | `critical` | start **only** connections whose resolved priority rank is at or above this tier (`[delivery].priority` + a per-connection `priority=`). `critical` (owner-locked default) starts only the critical feeds; `normal` would also start normal-tier ones. A below-threshold connection reports `status: "filtered"` — distinct from ADR 0031's `"failed"`. An unknown value fails config load |
| `takeover_hook` | str | `""` | **optional** operator command run before binding the priority listeners: exit 0 = "VIP acquired", any non-zero or timeout = "not acquired" and **activation aborts**. For an ADR 0047 load-balancer topology the passive LB is the fence and this is belt-and-braces only. `""` = no hook; a whitespace-only value is rejected at load (it would run an empty shell and "succeed"). **Both hooks run with the engine's environment minus every `MEFOR_*` variable, `VAULT_TOKEN` and `PGPASSWORD`**, so a hook keeps ordinary variables such as `PATH` or a cloud profile and gets none of the engine's own settings. A secret you keep under any other name, such as a `[secrets].provider = "env"` reference that is not named `MEFOR_*`, still reaches the hook. Pass a hook what it needs on its command line or under another name |
| `release_hook` | str | `""` | the symmetric command run on `POST /dr/release` to hand the VIP back to the recovered primary. `""` = no hook; whitespace-only rejected at load |
| `takeover_timeout_seconds` | float (>0) | `30.0` | bound on the takeover/release hook **and** on the KeyProvider-reachability check at the DR site: a hook or key probe that doesn't succeed within this **aborts activation closed** — no hang, no silent retry-forever. It also bounds the activation's digest of the running config dir, taken only for the `dr.activate` audit row: a dir that does not answer in time is recorded as `unreadable` and does **not** abort the activation. A **takeover** hook that runs past it is killed, with the processes it started. If the engine cannot put the hook in a Windows job object, or cannot signal its POSIX process group, it logs one WARNING and the kill reaches only the hook's shell. The abort is recorded once the hook has exited, or after at most 5 more seconds (vault BACKLOG #2622). At least these escape that kill: on POSIX a process that leaves the hook's process group (`setsid`, and `sudo` in its default `use_pty` mode) or that the engine's account may not signal; on Windows, work the hook hands to another service, such as WMI or Task Scheduler. A **release** hook that runs past it is left to finish, as before |
| `seed_archive` | path | `""` | the `.mfbak` archive activation **verifies** the cold seed against. Activation does not load it — on a **SQLite** store, restore it first with `messagefoundry restore <archive> --to <store path>` and name the same archive here, so activation can check the store actually carries it. `""` = the operator supplies the archive path in the `POST /dr/activate` request body instead (the runbook path), which needs `seed_dir` below. A cloud URL is rejected — local/UNC only, like the backup destination. On a **SQLite** store a **config-only** archive cannot be a seed here and is refused: it carries no `store.db`, so nothing could have been restored from it — `messagefoundry restore` rejects one for the same reason. On a server-DB (Postgres/SQL Server) store that refusal does not apply, and **`messagefoundry restore` is not part of the drill** — it rejects a config-only archive on *every* backend, so running it here is a hard error. There the DBA restores the live database natively and the archive named here is the **config bundle**, which by default is all a server-DB backup writes (`[backup].config_only_on_server_db`). Activation instead gates the restored **live database**, not the archive: `POST /dr/activate` must carry `dba_attests_restored=true` **and** the restored database must already carry prior `dr_backup` history, or activation **refuses closed**; `restore_token` below adds an optional vintage floor on top of those two |
| `seed_dir` | path | `""` | the **one directory** a `POST /dr/activate` request body may name an archive under (vault BACKLOG #2581). `""` (default) = a request may name **no** archive, and activation uses `seed_archive`. Must be an **absolute** path on the DR box; a relative one is rejected at load. A request path is confined to this directory the way `[api].config_reload_roots` confines a reload path, and activation verifies the resolved path. A refusal aborts activation (422) with one generic message that names no part of the path; the `dr_activation_aborted` audit row records the path that was asked for. If this directory itself cannot be resolved within `takeover_timeout_seconds`, activation aborts and says so. `seed_archive` is operator configuration and is not confined by this key. A cloud URL is rejected, like `seed_archive` |
| `restore_token` | path | `""` | **opt-in server-DB DR restore token** (BACKLOG #223, [ADR 0102](adr/0102-server-db-dr-restore-vintage-completeness-attestation-residual.md)). A local/UNC path to a small JSON token the DBA places on the DR box recording the **expected** source-backup anchor of a native (Postgres/SQL Server) restore. When set, the server-DB seed gate cross-checks it against the restored database's own latest successful `dr_backup` archive — a **vintage floor** a bare boolean attestation cannot give: a stale or wrong native restore's latest anchor differs, so activation **refuses closed**. `""` (default) = off (the gate is byte-unchanged; SQLite is a no-op). A cloud URL is rejected |

### `[approvals]`
Optional **dual-control (maker-checker)** approval for high-value actions (ASVS 2.3.5) — see
[SECURITY.md](SECURITY.md). **Off by default**; turning it on holds the listed operations for a
*distinct* second approver holding `approvals:approve`, with the requester unable to approve their own.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | turn on dual-control; off = every action executes inline as before |
| `operations` | list[str] | `["connection_purge", "dead_letter_replay"]` | which operations require approval; each must be a known op key (a typo is refused at startup) |
| `expiry_hours` | num | 72 | a pending request can no longer be approved after this many hours (`0` = never expires). A value above `72`, or `0`, can be named as a [security loosening](SECURITY-LOOSENING.md) (BACKLOG #2489) |
| `min_dwell_seconds` | num (>= 0) | 2.0 | **(ASVS 2.4.2):** a pending request cannot be approved until it is this many seconds old. An earlier approve gets **409** and an `approval.too_early` audit row, and the request stays pending. `0` = no floor. With dual control on and requests expiring, startup refuses a floor as long as the expiry window. The check converts `expiry_hours` to seconds first. With `expiry_hours = 0`, any finite floor is accepted. A floor below `2.0`, or `0`, can be named as a [security loosening](SECURITY-LOOSENING.md) (BACKLOG #2489). The default is **provisional** and comes from published human-timing research. Where it comes from, and what the floor does not do, is in [SECURITY.md](SECURITY.md#dual-control-approval-for-high-value-actions-wp-l3-04-asvs-235) |

### `[integrity]`
Startup **self-attestation of the installed engine wheel** ([ADR 0041](adr/0041-load-path-attestation-and-change-attribution.md)
D3) — a runtime in-place-tamper tripwire (`messagefoundry/integrity.py`). At startup, and only at startup
(there is no on-demand surface), the
engine hashes every **loaded** first-party `messagefoundry` module file against the installed wheel's
`*.dist-info/RECORD` baseline; on **drift** (an attested file no longer matching its RECORD hash) it records
a hash-chained `startup_integrity` audit row and fires the `AlertSink`. A module file is any file Python
can import one from: source, a native extension, or a `.pyc` outside `__pycache__`. One with no RECORD
row is drift, and so are a link or a directory the walk cannot list under the package and a shipped
module that is gone (vault BACKLOG #2763, ADR 0041 AC-16). That is what the walk is built to catch, not
a proof that every planted file is caught. A `.pyc` reported beside a `.py` that still exists does not run, because
source wins, but no supported install leaves one there, so treat it as tampering. Compiled caches inside
`__pycache__` are **not** read, so a crafted cache there is not detected; that and the other residuals
are in the ADR 0041 2026-10-06 amendment. It also attests a short explicit set
of shipped security **data** assets (`_ATTESTED_ASSETS` in `messagefoundry/integrity.py`, BACKLOG #1432) --
the bundled common-password corpus and the packaged Semgrep handler rules -- because emptying one of those
neuters a control with no engine module edited at all. When the engine has **loaded** the web
console (`[security].serve_web_console` on), it attests that too: every file of the loaded
`messagefoundry_webconsole` package against the `messagefoundry-webconsole` wheel's own `RECORD`, under
the same rules and the same two keys (BACKLOG #1802). A console the engine has not loaded is not
attested, because its code never ran here. A loaded console that cannot be attested is treated like an
engine that cannot, with one exception: a console with no distribution of its own beside an engine that
declares itself editable is a checkout that installed only the engine, and shares its exemption. Its
audit row carries `"distribution": "messagefoundry-webconsole"`, and its alerts
use the subjects `webconsole-integrity` and `webconsole-unattested`. What the console arm covers, and
why, is ADR 0041 AC-15. It complements ADR 0036 (which guards
the *config dir*) by covering the installed *site-packages* an admin with venv-write + restart rights could
edit in place. Both keys default **safe**: attestation is on but **alert-only** (it never blocks startup), and
an **editable** install (`pip install -e .` — no RECORD baseline) is a **no-op**, so dev is never bricked.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | run startup attestation at all. On by default (alert-only is harmless); a **no-op** off an editable install. Set `false` only to suppress the check entirely (e.g. an unusual packaging where RECORD is known-stale) — you then lose the in-place-tamper tripwire. |
| `fail_closed_on_drift` | bool | `false` | when `true`, drift makes `serve` **refuse to start** (after recording the audit row + alerting), and so does an attestation that verified **nothing** — no `RECORD` baseline, a `RECORD` stripped of its package rows, or the package loaded from outside the install root (a pass that compared zero files cannot say the bytes are clean). Default `false` = **alert-only**: a legitimate reviewed in-place security hotfix (the documented vendored-parser patch contingency) would itself trip a RECORD mismatch, so fail-closed-by-default would brick a legitimate patch. Alert-only still logs a WARNING, records the row and alerts for both shapes. An install that **declares** itself editable (`pip install -e .`) is exempt either way, so dev is never bricked — and because that exemption silently cancels the opt-in, setting this on an editable install logs a WARNING naming the reason at startup (BACKLOG #1679). Opt in for hard enforcement on a locked-down instance. **Read the boundary before you record this as tamper-proof:** the baseline ships inside the same install the adversary would be writing, so it detects an *inconsistent* in-place edit and not a *consistent* one. Why no runtime anchor fixes that, where the out-of-domain anchoring actually lives, and what the resolution assumes about the install root are in [ADR 0041](adr/0041-load-path-attestation-and-change-attribution.md) D3, *"The baseline's trust domain"*. |
| `audit_verify_on_start` | bool | `false` | when `true`, the engine **re-walks the `audit_log` hash chain once at startup** (#190). **Alert-only by construction:** a broken chain logs a WARNING and fires the `AlertSink` but **never** crashes startup — a refuse-to-start on a tripped tamper alarm would be a self-inflicted DoS. Default `false` (opt in): on a very large `audit_log` the full re-walk adds startup latency, so it is not on by default. **On its own it is a bare walk, and a bare walk is blind to a truncated tail** (below) — set `audit_anchor_file` beside it to close that. **Read the two limits below before citing this as tamper detection.** |
| `audit_anchor_file` | str | `""` | path to a file holding one `COUNT:HEAD` anchor as written by `messagefoundry audit-anchor`. Empty (the default) leaves the startup walk exactly as it was. When set **and** `audit_verify_on_start` is `true`, the startup walk also compares the live chain against that anchor, which is **what lets it see a truncated tail** (BACKLOG #328). **The engine consumes it as a PREFIX, not as the CLI's exact seal** — `--expected-anchor` compares the *current* head and so diverges on the very next appended row, which a running engine produces constantly; this asks instead whether the recorded state was ever true and the chain has only **grown** since. It still catches a truncated tail and a mid-chain rewrite, and a **stale anchor stays valid** — it simply witnesses less, so re-anchor when you want the witness moved forward. **Alert-only, like its partner:** a missing, unreadable or malformed anchor logs a WARNING, names the file and the reason, and lets the bare walk run — it never crashes startup and **never fires the tamper alert**, because a config fault that raised a tamper alarm would train operators to ignore the real one. The refusal never quotes the file's contents into the log (a mis-pointed path is usually a path typo'd onto something else); the CLI still quotes it, because that lands on the operator's own terminal. `0:`, the anchor of an **empty** log, is reported rather than compared — it can witness nothing. Setting this **without** `audit_verify_on_start` is warned at startup: the anchor is never read. A truncated tail and a broken chain fire **different** alert subjects (`audit-chain-truncated` / `audit-chain`), so they route and throttle separately |

**The chain is *tamper-evident* only when the store is keyed.** With no store encryption key the cipher
is `IdentityCipher`, whose `audit_mac_key()` returns `None` — "no DEK → no derived key → the audit chain
stays the keyless SHA-256 chain" ([`store/crypto.py`](../messagefoundry/store/crypto.py)). An unkeyed
SHA-256 chain is a **corruption** detector: anyone who can write `audit_log` rows can recompute it end to
end, which is exactly the actor the control exists to catch. A keyed chain is an HMAC on an
HKDF-derived subkey (`mefor/audit-chain/v1`), which that actor cannot forge without the DEK; under
`cipher_provider = "vault_transit"` the MAC is computed **inside** Transit instead (`audit_mac_key()` is
`None` there **by design** — that is not the keyless case).

**Having a key today does not make an existing keyless chain keyed.** Which rows are keyed, and
what a store that holds a key does with a row that is not, is stated once, in
[ASVS-L2-PHASE0-CHANGES.md](ASVS-L2-PHASE0-CHANGES.md) section 4, the *Audit chain* row, and
[ADR 0194](adr/0194-refuse-to-start-a-keyless-audit-chain-at-the-store-open-seam.md) records how every
command refuses to start one without the opt-out. A store that has a key but opens onto keyless rows
logs an ERROR at open, fails `audit-verify`, and `GET /security/posture` lists it as the loosening
`audit_chain_unkeyed`. The startup loosening warning and `messagefoundry security show` do not read the
open store, so they do not show it. Check the key (`[store].encryption_key` / `encryption_key_file`)
and the posture read-out before you record "tamper-evident audit log" in a risk register. This
paragraph used to say that a key makes the chain an HMAC and that a normally-configured deployment
does get the keyed chain; both skipped the keyless-start case (BACKLOG #1906). **CORRECTED
2026-10-01:** it then said `messagefoundry rekey-audit` keys the rows written after it runs. That
command is removed, with the mark it set.

**And a bare walk does not catch a truncated tail.** `verify_audit_chain` detects modified or deleted
**older** rows, but deleting the **newest** rows leaves a prefix that still chains cleanly, so a bare
walk returns CLEAN after a tail-truncation. An attacker hiding what they just did truncates the newest
rows. `audit_verify_on_start` **on its own** is a bare walk and is therefore blind to exactly that.

**What closes it is an anchor, and there are now two ways to hold one**
([BACKLOG #328](BACKLOG.md)). `messagefoundry audit-anchor` prints `COUNT:HEAD`. Either pass it back by
hand as `messagefoundry audit-verify --expected-anchor COUNT:HEAD` (or `--expected-anchor-file PATH`),
or point `[integrity].audit_anchor_file` at the file and let **every startup** compare against it. The
anchor is a row count plus a digest — no PHI, no secret — so it is safe to hold in a ticket or an
object store, which is what makes it an *external* witness.

**The two consume it differently, and the difference is the whole reason the startup one can exist.**

**The CLI's `--expected-anchor` is an EXACT point-in-time seal.** It compares the count **and** the
head hash, so an anchor taken before any subsequent audit row reports `truncated or rewritten` on a
chain that merely **grew**. The head half is not redundant with the count: an attacker who cuts the
newest rows and forges the same number of replacements restores the count *and* leaves a chain that
walks cleanly, so the head hash is the only thing that differs. The sharp edge and that detection are
the same check.

**So the CLI check seals a chain AT REST between two offline readings — that is its whole workflow.**
Anchoring and immediately re-verifying compares a value to itself and proves nothing; re-checking an
*exact* anchor against a **running** engine alarms on every ordinary boot, because a running engine
writes audit rows. What sits between those two useless readings is a real control: **stop or quiesce
the engine, take the anchor, hold it somewhere the engine's operator cannot rewrite, and re-verify
while the chain is still quiesced** — across a maintenance window, a database move, a backup/restore,
or a hand-off between custodians. Anything that happened to the DB in that gap is what it detects. Do
not build a periodic job against a live engine on the **exact** comparison.

**`[integrity].audit_anchor_file` is the same artifact under a WEAKER comparison, and that is what
makes it survivable on a running engine.** It asks whether the recorded state was ever true and the
chain has only **grown** since — the head captured *at the recorded row position* against the recorded
one — so appended rows are irrelevant to it and it does not alarm on an ordinary restart. It still
catches the two shapes that matter: **fewer rows than recorded** (a truncated tail) and **a different
head at that position** (a mid-chain rewrite). What it gives up is the exact seal's sharpness about
*when*: it cannot tell you the chain is unchanged, only that it has not been cut or rewritten below
the anchor. Use both — the startup check for continuous coverage of every boot, the quiesced CLI check
for the custodial hand-offs above.

The full reasoning is the [`[retention]`](#retention) `audit_days` row, which is the source of record
for it. **An off-box log forward / tee remains the answer for continuous coverage, and neither anchor
check replaces it.** `audit_anchor_file` fires **at startup and only at startup**, so it detects a cut
made since the last boot — it says nothing about the window between two boots, and a host that never
restarts never checks. The tee is the only control that sees the trail as it is written.

### `[engine]`
**Not a section.** There is **no `EngineSettings` model**, so an `[engine]` block in
`messagefoundry.toml` is **refused at load** as an unknown section, like any other. Earlier versions of
this page listed `shutdown_timeout_seconds` and `data_dir` here as proposed keys; neither does anything.
The ASGI lifespan's `engine.stop()` is not bounded by a setting, and for relative paths use
`[environments].base_dir` / `serve --project-root` for `env()` value files, and `--db` / `[store].path`
for the store.

### `[service]` (NSSM / Windows)
The NSSM **install** knobs — auto-restart, stdout/stderr log paths — live in `scripts/service/`. The
section here is the engine's **read-only** report of its own Windows-service run state to the console
(L6a, [ADR 0065](adr/0065-web-ops-dashboard.md)): an unprivileged `sc query <service_name>` off the event
loop, surfaced at `GET /service/status` and gated by `monitoring:read`. There is deliberately **no
control** here — no start/stop/restart, the engine can't restart its own host over the API. Off by
default, and **file-only** (`[service]` has no `MEFOR_*` env layer).

| Key | Type | Default | Notes |
|---|---|---|---|
| `report_status` | bool | `false` | report the run state; off = no `sc query` ever runs and the route answers `state = "disabled"` |
| `service_name` | str | `""` | the Windows service to query. Letters, digits, space, `.`, `_`, `-` only (anything else is refused at load); empty = disabled |

### `[security]`
The **canonical, plain-language home for the high-value security posture switches**
([ADR 0118](adr/0118-secure-by-default-security-configuration-section.md)). Each switch **defaults to the
secure position**; loosening one is deliberate and **warned at `serve`** (see
[SECURITY-LOOSENING.md](SECURITY-LOOSENING.md) for what each opt-out gives up + its ASVS/NIST/HIPAA
mapping). This section **replaces** the scattered legacy keys — setting a moved key in its old section
(`[api].host`, `[api].serve_ui`, `[api].public_origin`, `[auth].require_mfa`,
`[auth].session_idle_timeout_minutes`, `[auth].session_absolute_hours`, `[store].allow_unencrypted_phi`,
`[egress].deny_by_default`, `[retention].messages_days`, `[retention].allow_unbounded_phi`,
`[diagnostics].audit_all_authz`, `[ai].production`) is **rejected at load** with a
pointer to its `[security]` replacement. `[auth].enabled` and `[ai].data_class` were removed rather
than moved, and are rejected at load as removed. Low-level *plumbing* (TLS cert paths, `[egress].allowed_*`
contents, `[retention].dead_letter_days`, DB identity, password policy, rate limits, AD/LDAP) stays in its
functional section.

Under the hood the loader **desugars** `[security]` into those internal fields, so every serve gate + the
`checks.py` commit/CI mirror keep enforcing exactly as before — **no shipped refusal is loosened**
(the *No-loosen rule*, [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) §5),
and a PHI weakening under **strict enforcement** (`enforcement = enforce`, the default) still fails closed
— byte-identical to the former production-PHI refusal
([ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)).

> **Two acknowledged exceptions — `enforcement = enforce` is not the whole answer.** The No-loosen rule
> ships with exactly two dedicated second-acknowledgment switches ([ADR 0140](adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md);
> [SECURITY-LOOSENING.md](SECURITY-LOOSENING.md) invariant 1), each of which drops **one** strict-enforcement
> refusal to a loud, audited warning that starts:
> `allow_unencrypted_phi_under_strict_enforcement` (keyless PHI at rest) and
> `allow_single_factor_admin_when_exposed` (single-factor sign-in on an exposed instance) — both rows below.
> Separately, `enforcement = warn` downgrades **every** PHI serve-gate refusal at once. So confirming
> `enforcement = enforce` is necessary but **not sufficient**: read those three values before recording
> a posture. Each is reported by `security_loosenings()` on `GET /security/posture`, so none is silent.

| key | type | default | meaning |
|---|---|---|---|
| `local_access_only` | bool | `true` | reachable only from this machine (loopback bind) |
| `listen_address` | str | `"127.0.0.1"` | bind address — used only when `local_access_only = false` |
| `require_encryption_for_remote` | bool | `true` | off-machine API access needs an operator certificate or a trusted terminator, and an off-machine inbound listener needs TLS where its connector has it (raw-TCP and X12 have none). Setting it `false` is the config-file twin of `--allow-insecure-bind`. For the API it permits an off-loopback bind with no `[api].tls_cert_file`: the engine then serves TLS on its generated self-signed placeholder ([ADR 0172](adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md)), which no trust store vouches for, so a remote client can authenticate the engine only by pinning that exact certificate, handed over out of band. For an inbound MLLP, HTTP, DICOM SCP, raw-TCP or X12 listener it permits a cleartext bind. It rides the **same** clamp: it cannot relax either bind on a **PHI instance under `enforcement = enforce`** — note that is *enforcing*-PHI, not merely production, so a `dev` or `staging` box on shipped defaults is refused exactly like `prod`. It also does not reach `/ui` (the browser surface refuses an unprotected off-loopback bind under either escape) |
| `serve_web_console` | bool | `true` | mount the browser ops console at `/ui` — **on by default** ([ADR 0143](adr/0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md)); set `false` to shrink to a JSON-only surface. Default-on applies to **local loopback** binds. On an **exposed** instance (a non-loopback bind, a declared TLS terminator, a set `[api].trusted_proxies`, **or** a set `web_console_public_address`) the two cases diverge and it matters which you are in: a **default-on** console — one you never asked for by name — **auto-degrades to JSON-only** with only a stderr warning, so `/ui` 404s on a cleanly-started engine; an **explicit** `serve_web_console = true` stays on and then must satisfy the exposure ladder or `serve` **refuses** (exit 2) — off-loopback `/ui` requires in-process TLS or a declared terminator, and behind a declared terminator it additionally requires `web_console_public_address`. So "explicit" is what stops the silent degrade; TLS and the origin are separate refusals on top |
| `web_console_public_address` | str | `""` | external origin when the console is exposed off-box (CSRF/CSWSH + WebAuthn RP-id) |
| `allowed_client_networks` | list[str] | `[]` | **`[BUILT]` ([ADR 0151](adr/0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md)):** source-address allow-list for the **operator API + web console**. **Empty (the default) = no restriction.** Non-empty = a request whose client address is outside every listed network is refused **403 in middleware, before routing and before sign-in** (also covers `/ui`, `/ui/static`, `/ws/stats`). **One route is exempt for *every* source address, not just loopback: `/health`** ([`api/client_networks.py`](../messagefoundry/api/client_networks.py), `_EXEMPT_PATHS = {"/health"}`) — the tokenless liveness probe an off-box monitor or load balancer needs, and the reason this row's own diagnostic below works from a blocked address at all. Do not read the enumerated coverage as "every operator-surface route is address-gated". Entries are CIDR networks or bare hosts (`"10.20.0.0/16"`, `"2001:db8::/48"`, `"10.20.4.7"` → `/32`), IPv4 + IPv6 mixed; malformed entries are **refused at load** and valid ones are stored normalized (`10.1.2.3/24` → `10.1.2.0/24`). **Loopback is always allowed**, with no knob (the tray `/health` poll, an on-box browser, `messagefoundry check` and a container HEALTHCHECK cannot be allow-listed). **Operator surface only** — the ingest listeners keep their own peer restriction, a per-connection `source_ip_allowlist` set on the `inbound(...)` call or in `connections.toml`. Note the spelling: it is **not** a key of the `[inbound]` service-settings section (that section carries only `bind_host`, `ack_after`, `stream_inflight_budget_bytes` and `max_staged_depth`), so writing `source_ip_allowlist` into `[inbound]` in `messagefoundry.toml` is **refused at load** — it used to be accepted silently and do nothing. **It matches the address uvicorn reports, so it is INERT behind an UNDECLARED proxy / NAT / a bridged container** — declare the proxy in `[api].trusted_proxies` (which needs `tls_terminated_upstream` or `tls_cert_file`, BACKLOG #2055) or this does nothing; `curl /health` and read `observed_client` to check. Setting it **tightens `[api].trusted_proxies` to single hosts** (a broad range would let every host inside it forge its own source address). Startup-only: a lockout costs a service restart. Defence-in-depth **behind** the host firewall, not the primary network control — read OFF-LOOPBACK-DEPLOYMENT.md first. Env: `MEFOR_SECURITY_ALLOWED_CLIENT_NETWORKS` (**comma**-separated). |
| `encrypt_stored_data` | bool | `true` | PHI encrypted at rest (key from the environment). `false` sets the **same** keyless-PHI opt-out as `allow_unencrypted_phi` (next row): a configured key still encrypts, and a keyless start meets the same refusals as it does under `allow_unencrypted_phi` ([SECURITY-LOOSENING.md](SECURITY-LOOSENING.md), BACKLOG #1906) |
| `allow_unencrypted_phi` | bool | `false` | audited escape: start a PHI instance with **no** key |
| `allow_unencrypted_phi_under_strict_enforcement` | bool | `false` | the **second acknowledgment** required to start a PHI instance keyless under strict enforcement ([ADR 0140](adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md)). Under `enforcement = enforce`, `allow_unencrypted_phi = true` on its own is **not** enough — `serve` still refuses to start (exit 2) unless this is also set, so the highest-risk posture (real PHI + strict enforcement) is never one flag away from plaintext at rest. Under `enforcement = warn` the single `allow_unencrypted_phi` flag still governs. With both set the instance starts with PHI bodies, summary/metadata and the error columns **unencrypted at rest**, and the startup AUDIT line names **both** flags. A **loosening** — `security_loosenings()` reports it, so it is never silent |
| `allow_single_factor_admin_when_exposed` | bool | `false` | permit **single-factor sign-in on an exposed PHI instance** (ADR 0140). With `require_mfa` explicitly off, and the instance exposed — a **non-loopback bind**, a declared TLS-terminating proxy (`[api].tls_terminated_upstream`), **or** a set `[api].trusted_proxies` (a loopback bind behind a proxy re-encrypting to an operator `tls_cert_file`; vault BACKLOG #2251) — a PHI instance under `enforcement = enforce` **refuses to start** (exit 2). Every account with no second factor enrolled, Administrators included, would then sign in over the network with a single factor. The one exception is an OIDC sign-in that carries an amr/acr claim checked while `[auth].oidc_require_mfa_claim` is on. The refusal, its exposure warnings and its AUDIT line name it only when this config has it. The `security_loosenings()` entry describes the switch, not one config, so it always names it. The gate reads at least exposure, `require_mfa` and `enforcement`, and never a tier or account kind. Setting this permits that start; it is recorded in a WARNING-level AUDIT line and the ordinary exposure warning still prints. A **loosening** — `security_loosenings()` reports it. **The exposure test does not consult the browser console** ([BACKLOG #326](BACKLOG.md); ADR 0140 amendment). It did, and that made the arm miss the topology this document recommends: a loopback bind behind a declared terminator with `serve_web_console` left at its default, where the ADR 0143 auto-degrade clears the console flag in place before the gate reads it. The exposed surface that authenticates with one factor is the **JSON operator API**, which the proxy serves whether or not `/ui` is mounted, so the predicate is the bind-and-proxy posture alone and the refusal fires on at least: an off-loopback bind; a declared proxy with the console left default-on; and a declared proxy with `serve_web_console = false`. **This refusal is one of at least two exceptions to the "a new refusal fires only on a new opt-in" scoping rule (another is the ADR 0199 store-login refusal)**, which the `require_memory_encryption_declaration` row below states — by owner ruling of 2026-08-04, recorded in the [ADR 0140](adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md) amendment, which is the single source for why. Nothing new gates it. **One residual is deliberately left open:** an **undeclared** proxy — `web_console_public_address` set with neither `tls_terminated_upstream` nor `trusted_proxies` — does not count as exposed here, because nothing was declared, so exposure would be an *inference*, and an inference must not refuse. It **warns** instead, on its own dedicated arm: on a PHI instance with `require_mfa` explicitly off, startup prints that if that origin is served by an undeclared proxy every account with no second factor enrolled is single-factor over the network, with the same OIDC exception, and this refusal cannot see it. Do **not** read the ADR 0068 §8 undeclared-proxy warning as that control — it is about the `/ui` session cookie and HSTS, and it is suppressed entirely when the ADR 0143 auto-degrade clears the console flag, which the same `web_console_public_address` triggers. **Prefer `require_mfa = true` — and know its scope.** Under the shipped `require_mfa_scope = "every_local_account"` it requires a second factor from **every** account, *not* only Administrators and (since BACKLOG #1144) *not* only local ones, so a non-interactive bearer-token service account becomes MFA-pending and cannot enrol unattended. **With `require_mfa` kept on, there is one remedy.** Set `require_mfa_scope = "administrators"` (itself reported as a loosening, and it leaves every Administrator in scope) — see that row below. **Making it a directory (AD/Kerberos) principal is no longer the other one:** directory identities used to be out of scope under either value, their factor delegated to the directory, and BACKLOG #1144 retired that. **mTLS is not one either.** A `[api].tls_client_cert_identities` mapping does grant a cert-identity that never meets the MFA gate, but that plane is admitted on exactly **one** route (`GET /service/identity`, `require_service_cert`) and carries no session, so an account "moved to mTLS" can read back its own identity and nothing else — it cannot replay, purge, poll status, or do any work a service account exists for. The `[api].tls_client_cert_identities` row above is the authority on that reach. An AD-only deployment is therefore in scope for **all** of its accounts — its directory principals, any local administrator, and any local service accounts |
| `allow_unverified_alert_smtp_tls` | bool | `false` | the **acknowledgment** required to start an enforcing PHI instance whose `[alerts]` SMTP hop does not authenticate the relay — i.e. `[alerts].email_use_tls = false` (cleartext) or `[alerts].email_tls_verify = false` (encrypted but accepts any certificate) ([#323](BACKLOG.md)). Covers BOTH shapes deliberately: cleartext is strictly worse than unauthenticated TLS, so gating only the second would hand an operator a bypass onto the worse posture. Without it `serve` refuses to start (exit 2); with it the start is permitted and named in a WARNING-level `AUDIT:` line. An **acknowledgment switch rather than the clamped `MEFOR_ALLOW_INSECURE_TLS` escape** the connectors use, because this cell is constructed outside the `active_hop_posture` scope, where that clamp reads no posture and so cannot carry an acknowledgment (since vault BACKLOG #2354 it refuses there; it used to be inert). A **loosening** — `security_loosenings()` reports it, so it is never silent |
| `allow_over_granted_store_principal` | bool | `false` | the **audited opt-out** from the refusal an over-granted store login earns under `enforcement = enforce` ([ADR 0199](adr/0199-an-over-granted-store-login-refuses-start-under-enforce-with-an-audited-opt-out.md), ASVS 13.2.2). The startup privilege preflight reads the `[store]` login's effective privileges; when it holds more than [`DEPLOY-SERVER-DB.md` §1.1/§1.2](DEPLOY-SERVER-DB.md) prescribes, `serve` refuses to start unless this is set. With it set the start goes ahead, a WARNING-level `AUDIT:` line names the switch, and the `store_privilege_preflight` audit row carries `over_grant_accepted: true`. It lifts that one refusal only: the warning and the `store_privilege_warning` alert still fire, an unobservable probe needs no opt-out (it only warns), and `[store].require_least_privilege = true` outranks it. SQLite never needs it. A **loosening** — `security_loosenings()` reports it. Env: `MEFOR_SECURITY_ALLOW_OVER_GRANTED_STORE_PRINCIPAL` |
| `require_nonstatic_credentials` | bool | `false` | **opt-in static-credential refusal** (ASVS 13.2.1, [BACKLOG #1182](BACKLOG.md)). Off by default, by owner decision (2026-09-23). When `true`, `serve` refuses to start while any backend hop the engine dials presents an unchanging credential or none and is not named in `static_credential_accepted`. The service-settings hops (`[store]`, `[alerts]`, `[auth]`, `[ai]`, `[secrets]`, `[logging]`) are checked before anything starts, and a refusal there exits 2. The connection graph is checked at the first load, where a refusal fails the server's startup, and at every `/config/reload`, where a refused reload leaves the running graph in place. Read once at start: a `/config/reload` judges the new graph against the value the engine started with, so an edit takes effect on restart. The refuse/warn split is `enforcement`, as for `[store].require_managed_identity`. Several hops have **no** compliant credential kind in the product, so with this on they can only run under an opt-out; the full list is in [`CONNECTIONS.md`](CONNECTIONS.md) §*Static credentials on every backend hop*. Not a loosening: it tightens. Env: `MEFOR_SECURITY_REQUIRE_NONSTATIC_CREDENTIALS` |
| `static_credential_accepted` | table | `{}` | the audited per-hop opt-outs for `require_nonstatic_credentials`: hop name to reason, e.g. `{ "OB_ACME_REST" = "partner offers HTTP Basic only" }`. Hop names are the ones `messagefoundry check`'s `static-credentials` line and `GET /security/posture` print: an outbound connection's own name, or a name with a prefix (`settings:` for a service-settings hop; `inbound:`, `fhir_lookup:`, `db_lookup:`, `reference:` or `proxy:` for the others). A blank reason is refused at load. Read only while the refusal is on. Then each honoured entry is logged at start by name and reason, never by secret; an entry that matches no hop is logged as doing nothing; and `security_loosenings()` names the set. Read once at start, like the rest of `[security]`: a `/config/reload` does not re-read it, so an added, changed or removed opt-out takes effect on restart |
| `memory_encryption_operator_declared` | bool | `false` | **`[BUILT]` ([ADR 0152](adr/0152-in-use-data-protection-for-phi-platform-memory-encryption-attestation-asvs-11-7-1.md) rung 2, ASVS 11.7.1):** the operator's **declaration** that this host provides hardware memory encryption (AMD SEV-SNP / Intel TDX), so PHI is protected in RAM **while it is being processed**. The engine cannot verify it — a local CPU flag is emitted by the OS whose integrity the requirement protects against — so this records **who took responsibility**, the same discipline as `MEFOR_TLS_REVOCATION_ATTESTED`. It is deliberately **not** called "attested": in confidential computing that word means a CPU-signed quote verified against the silicon vendor's root PKI (ADR 0152 rung 3, **not built**). An **exposed** PHI instance without it **warns and starts** — on every environment, at both `enforcement` settings; it refuses only if `require_memory_encryption_declaration` is also set. A **positive platform read-out does not substitute for it** (a read-out must never relax a control). **A loopback instance is byte-identical** (never consulted) — the arm keys on exposure alone, and the synthetic half of that pair went with [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md). If the platform read-out positively contradicts this, the contradiction is **warned at start and reported** as `memory_encryption_readout_contradicts_declaration` on `GET /security/posture` — but **never refused** (the read-out is a self-report, not evidence, and has known false negatives: driver not loaded, container without the device node mapped, Azure CVM paravisor). **Setting this does not make the instance ASVS 11.7.1-compliant** — see the read-out note below the table. Env: `MEFOR_SECURITY_MEMORY_ENCRYPTION_OPERATOR_DECLARED` |
| `require_memory_encryption_declaration` | bool | `false` | **`[BUILT]` (ADR 0152 rung 2):** turn the row-12 warning above into a **refusal** — an **exposed** PHI instance with no `memory_encryption_operator_declared` then **refuses to start** under `enforcement=enforce` (and still warns under `warn`). **Opt-in by design, and the default is load-bearing:** the property is a **host** property that no operator can satisfy on Windows (the read-out is always `null` there), and "exposed" includes the recommended loopback-behind-proxy topology, so a refusal by default would stop working dev/staging/prod deployments from booting on upgrade over something they cannot change. Same scoping rule as `[security].allowed_client_networks`' companion refusal (ADR 0151): a new refusal fires only on a new opt-in. **At least two exceptions exist, and each is recorded:** the `allow_single_factor_admin_when_exposed` refusal above was corrected under BACKLOG #326 and fires with no new opt-in gating it — see that row and the [ADR 0140](adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md) amendment for the reasoning; and an over-granted store login refuses under `enforce` with no opt-in, by the owner ruling [ADR 0199](adr/0199-an-over-granted-store-login-refuses-start-under-enforce-with-an-audited-opt-out.md) records (see `allow_over_granted_store_principal` above). Do not generalise either. Set it in an estate that has standardized on confidential-computing hosts and wants a missing declaration to be fatal. Env: `MEFOR_SECURITY_REQUIRE_MEMORY_ENCRYPTION_DECLARATION` |
| `organization_domains` | list[str] | `[]` | **`[BUILT]` (ASVS 3.7.3):** domains that count as **inside** your organization. The console interposes a "you are leaving this site" page, with a cancel, before any navigation to a destination **not** covered here. ASVS asks about destinations outside the application's **control**, and control is *organisational* rather than topological — your own AD FS is a different host, a different origin, and squarely yours — so this is a declared domain list, **not** a same-origin test. Matched on a **label boundary**: `hospital.example` covers `adfs.hospital.example` and **not** `evilhospital.example` (a bare suffix test would admit the lookalike, which is the failure that makes an interstitial worse than none). **Empty is the STRICT position, not the lax one:** with nothing declared, *every* absolute `http(s)` destination is treated as external and gets the page — including your own IdP. Declaring your domains here is the correct fix for that, **not** `external_link_allowlist`. Entries are bare domains, refused at config load unless they pass the host-name rule stated in the [`[egress]` `allowed_recipient_domains` row](#egress). So a URL, scheme or `*` wildcard is refused, because each looks right and matches nothing, and so is a dot at either end. No leading dot is needed, since subdomains already match. Write an internationalized domain in its `xn--` form, which is how the console compares a host. One exception: a dotted-quad IPv4 address such as `10.20.30.40` is accepted, because an identity provider can be reached by address, and it matches only that address. A partial, octal or hexadecimal form is refused. Env: `MEFOR_SECURITY_ORGANIZATION_DOMAINS` |
| `external_link_interstitial` | bool | `true` | **`[BUILT]` (ASVS 3.7.3):** show the "you are leaving this site" page at all. Setting it `false` means the console navigates off-site with **no notification and no cancel** — that is the control itself, so this is a posture decision rather than a convenience one, and `serve` prints a warning naming it at every start. The federated sign-in leg is affected: with the interstitial on and the IdP outside `organization_domains`, `GET /ui/oidc/start` renders the page and the flow is minted only on confirm (`POST`), which also closes the standing hole where any external page could begin a sign-in by linking to the start leg. Env: `MEFOR_SECURITY_EXTERNAL_LINK_INTERSTITIAL` |
| `external_link_allowlist` | list[str] | `[]` | **`[BUILT]` (ASVS 3.7.3) — WARNING: THE AUDITED ESCAPE, AND IT LOWERS SECURITY.** Destinations listed here are navigated to with **no notification and no cancel**, which is precisely what the requirement asks for. It exists for legitimate high-volume external destinations an operator does not want to declare as their own domain. Same entry rule as `organization_domains`, the IPv4 exception included, and the same label-boundary matching. Non-empty makes `serve` print a warning **naming every entry individually** — never a count, because "3 destinations exempted" is the shape of message that lets an entry nobody intended sit in a list for a year. **Prefer `organization_domains`**: declaring a domain you control is a statement about scope; allowlisting one you do not is a waiver. Env: `MEFOR_SECURITY_EXTERNAL_LINK_ALLOWLIST` |
| `require_sign_in` | | | **→ REMOVED** (vault BACKLOG #2719). Sign-in is always required, on every bind. Setting this key is refused at load, from the file or as `MEFOR_SECURITY_REQUIRE_SIGN_IN`, whatever its value. The loopback mode it used to allow named no person in the audit trail and could not repair an account. If every Administrator signs in through an outside service, keep a local Administrator ([SECURITY.md](SECURITY.md#keep-a-local-administrator)). |
| `require_mfa` | bool | `true` | second factor (native TOTP or a WebAuthn passkey), enforced as an **access gate** since ASVS 6.3.3 — an MFA-pending session is refused on *every* authorized route with `403` + `X-MFA-Required: 1`, and a browser session is redirected to `/ui/mfa`. **The enrolment path is a deliberate exemption, not a re-route:** `/ui/mfa` itself and the account/enrolment routes (`GET /ui/account`, the password and factor-enrolment routes) are declared `allow_mfa_pending=True` ([`messagefoundry_webconsole/_auth.py`](../messagefoundry_webconsole/_auth.py), `routes/account.py`), so a user with **no** factor enrolled is not stranded — send them to **`/ui/account`** to enrol. A local account that `require_mfa` and `require_mfa_scope` cover enrols **TOTP first**. Until TOTP is on, passkey registration is refused with `enrol an authenticator app first`, `POST /me/password` refuses with the same detail (403; a pending session that holds a passkey gets `X-MFA-Required` first), and the console's password page redirects to `/ui/account?m=enroll_first`, because in this release a passkey is not a way past the sign-in lock (ADR 0197 Amendment A). A directory account may enrol TOTP or a passkey. Say "redirected to", not "confined to": `/ui/mfa` renders a code field only once TOTP is enrolled and a passkey button only once WebAuthn is, so a zero-factor user who is told they cannot leave that page is looking at a page with no form. |
| `require_mfa_scope` | `"administrators"` \| `"every_local_account"` | `"every_local_account"` | **Which accounts must ENROL a factor** when `require_mfa` is on (ASVS 6.3.3). An account that has already enrolled one must satisfy it while it keeps one, under either value (an OIDC sign-in meets it while `[auth].oidc_require_mfa_claim` is on, the default) — this dial only decides who is required to enrol in the first place. `administrators` restores the pre-6.3.3 posture and is reported as a **loosening** on `GET /security/posture` (advisory, not a refusal: refusing to boot on it would break every existing deployment on upgrade). **The `every_local_account` value is wider than its name** (BACKLOG #1144): directory (AD/Kerberos) identities used to be out of scope under either value, and they are not any more — the directory legs assert no strength the engine can read, so a Kerberos session mints MFA-pending and its holder enrols an engine factor. The value's spelling is stale; renaming a `Literal` reaches the settings model, this table and the tests that pin both, which is its own coherent change rather than a rider on a security fix. **Operator note:** under the default a non-interactive **bearer-token service account** becomes MFA-pending and cannot enrol unattended. Two settings answer it, each with a limit. **Set this to `administrators`**, which frees only a **local** account that does not hold the Administrator role: the Administrator role stays in scope under either value, and a directory session that proved no factor stays MFA-pending under both. Or **set `require_mfa = false`**, which frees any account that has not enrolled a factor, whatever its role; on an exposed instance under `enforcement = enforce`, `serve` then refuses to start unless `allow_single_factor_admin_when_exposed` is set (see that row). An account that has enrolled a factor still owes it either way while it keeps one, with the same OIDC exception. With `require_mfa` off, or for an account `require_mfa_scope` leaves out (under `administrators`, any account without the Administrator role, directory ones included), the holder may remove its last factor. Under `administrators` with `require_mfa` on, a directory account that does so is still not single-factor: its next Kerberos session stays MFA-pending until it enrols again. Making it an AD principal is **no longer** an escape, and mTLS is not one either: a cert-identity is exempt from the MFA gate but is admitted on exactly one route (`GET /service/identity`), so it cannot carry a working service account (see the [`[api]`](#api) `tls_client_cert_identities` row). Env: `MEFOR_SECURITY_REQUIRE_MFA_SCOPE` |
| `sign_out_after_idle_minutes` | int | `30` | session idle timeout |
| `max_session_hours` | int | `12` | session absolute lifetime |
| `block_unlisted_outbound` | bool | `true` | deny-by-default egress — only allow-listed destinations send. Leaving it unset applies `true`, because the internal `[egress]` field defaults to deny too (see [`[egress]`](#egress)). `serve` still reads whether you **wrote** it, because its [`[egress]`](#egress) startup gate treats unset and written `true` differently |
| `delete_message_bodies_after_days` | int | `30` | bounded PHI-body retention; `0` = keep indefinitely (audited). **Leaving it unset does not apply 30 through the desugar** — the internal window stays `0`, and the `[retention]` startup gate then defaults it to 30 days on a PHI instance under **either** enforcement dial. This row used to say the gate refuses under `enforce` and auto-bounds only under `warn`; it does not — only an **explicit** `0` reaches the refusal. See the note under this table |
| `allow_keeping_phi_indefinitely` | bool | `false` | audited escape: unbounded PHI retention |
| `allow_keeping_transform_state_indefinitely` | bool | `false` | the acknowledgement for `[retention].state_max_age_days = 0` (BACKLOG #1967). Without it or a window, an enforcing instance refuses to start. With it, the start writes a WARNING-level `AUDIT:` line naming the tier. A **loosening**. See the tier table under [`[retention]`](#retention) |
| `allow_keeping_search_presets_indefinitely` | bool | `false` | the same, for `[retention].search_preset_days = 0` |
| `allow_keeping_app_logs_indefinitely` | bool | `false` | the same, for `[retention].app_log_days = 0` while `[logging].log_dir` is set |
| `allow_keeping_backup_archives_indefinitely` | bool | `false` | the same, for `[backup].retention_keep = 0` while `[backup].destination` is set |
| `audit_all_authorization_decisions` | bool | `true` | ePHI access is **always** audited regardless of this switch; this adds full *authorization-decision* tracing on top. **On by default since BACKLOG #1277** (2026-09-02), which reversed the scoped `false` [ADR 0118](adr/0118-secure-by-default-security-configuration-section.md) §5 recorded on 2026-07-17: the flooding that default guarded against was attributed to console polling, and the console never reaches the gate. Setting it `false` narrows the trail to the state-changing surface, leaves every authenticated read unrecorded, and is reported as a **loosening**. Cost of `true`: one `auth.permission_granted` row per authenticated request on each `require()`-gated route, and **nothing prunes it** — `[retention].audit_days` is reserved and unenforced, so watch [`[retention]`](#retention) `max_db_mb`. "Always audited" is about **coverage**, not about how hard those rows are to alter afterwards: the audit chain is only cryptographically tamper-*evident* on a **keyed** store, and its verify does not catch a truncated tail — see [`[integrity]`](#integrity) |
| `handles_real_patient_data` | | | **→ REMOVED** ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)) — **every instance carries patient data** and the PHI gates apply unconditionally. Setting it is refused at load, with a message naming the per-gate switch to reach for instead. It turned off nineteen start-up gates on one line, each of which already had its own named, audited, separately-reported switch: `allow_unencrypted_phi`, `block_unlisted_outbound`, `allow_keeping_phi_indefinitely`, `allow_single_factor_admin_when_exposed`, `allow_unverified_alert_smtp_tls`, `[alerts].security_notifications_required`, a per-connection `cleartext_accepted`, a per-connection `tls_revocation_attested` with its mandatory reason (settable since [ADR 0173](adr/0173-tls-peer-revocation-checking-and-ocsp-stapling-across-terminating-and-originating-surfaces.md); audited at construction, and listed by `security_loosenings()` and `messagefoundry check`), the process-wide `MEFOR_TLS_REVOCATION_ATTESTED`, or the `enforcement` dial below. |
| `enforcement` | `enforce` \| `warn` | `enforce` | the serve-gate **refuse/warn dial** + the [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) escape-clamp key ([ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) GIVEN 2). `enforce` (default) **refuses** every PHI serve-gate violation and shuts every blunt escape-clamp — byte-identical to the former production-tier behaviour; `warn` logs + audits + continues and honours the escapes (a loud, audited loosening, named by `security_loosenings()`). **Decoupled from `production_instance`** (env `MEFOR_SECURITY_ENFORCEMENT`) |
| `production_instance` | bool | *derived* | production-tier posture (was `[ai].production`). Derived from the environment name when unset (`prod` → yes; `dev`/`staging` → no). **Informational since [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)** — drives the AI data-scope ceiling, the DEBUG-log refusal, and reporting, **not** the serve-gate refuse/warn dial (that is `enforcement`) |

> **The Default column is the *field* default — for one row that is not what an
> unconfigured instance runs.** The loader desugars `[security]` **presence-gated**: only a switch you
> set *explicitly* is written through to its internal field, so an omitted switch leaves the internal
> default in place and lets the posture gate decide. With no `[security]` block at all, the other
> pass-throughs agree with their rows; this one does not. `block_unlisted_outbound` was a second
> such row until vault BACKLOG #2605 made its internal field default to deny:
>
> | Row | Reads as | Internal field with `[security]` absent | What an unconfigured PHI instance actually does |
> |---|---|---|---|
> | `delete_message_bodies_after_days` | `30` | `retention.messages_days = 0` | the [`[retention]`](#retention) gate defaults each *unset* window to 30 days on a PHI instance under **both** enforcement dials; an **explicit** `0` refuses to start (exit 2) under `enforce` and warns under `warn`. There is no synthetic instance left to exempt ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)); the audited keep-forever opt-out is `[security].allow_keeping_phi_indefinitely`. This cell previously had the refuse / auto-bound split backwards |
>
> It is not a silent fail-open. Unless `[security].allow_keeping_phi_indefinitely` is set, an unset
> window is bounded at 30 days, and an explicit `0` is refused under `enforce` and warned under
> `warn`. With that opt-out set, an enforcing start writes an `AUDIT:` line instead. `serve`
> back-fills the `[security]` object from the resolved internal values before serving, so
> `GET /security/posture` reports the **effective** posture rather than this field default. But do
> not read the Default column as "what my unconfigured box is doing": **set the switch you intend to
> rely on**, and read the [`[retention]`](#retention) section for the row above. (An unrecognized
> `[security]` key is **refused at load**, from the file or the environment, so a typo stops the
> start. Check spelling against this table.)

**Editing is IDE-only**: the VS Code extension's *Edit Security Settings* command (which shells
`messagefoundry security show|set`) is the sole authoring surface. The **web console is read-only** — the
effective posture and the active loosenings are surfaced at
`GET /security/posture` (authenticated, `monitoring:read`). The `synthetic_relaxation` field went with
the declaration it described ([ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)); a relaxed control is a per-gate switch now and is named
individually in `loosenings`. Authentication & RBAC *plumbing* remains in
**`[auth]`** (see [SECURITY.md](SECURITY.md)); the at-rest-encryption *key* is a secret supplied via
`MEFOR_STORE_ENCRYPTION_KEY` / `[store].encryption_key_file` ([PHI.md](PHI.md#3-encryption-at-rest)).

The section is read at engine **startup**, so an edited switch takes effect on the next engine restart
(`POST /config/reload` re-runs the `--config` graph, not `[security]`).

### The memory-encryption read-out is *not* a compliance claim

`GET /security/posture` also carries a **report-only** platform read-out beside the FIPS attestation
([ADR 0152](adr/0152-in-use-data-protection-for-phi-platform-memory-encryption-attestation-asvs-11-7-1.md)
rung 1): `memory_encryption_self_reported_capability`, `memory_encryption_self_reported_active`,
`memory_encryption_self_reported_mechanism` and `memory_encryption_readout_source`. On Linux these come
from `/proc/cpuinfo` flags (**capability** — "this silicon *can*") and guest device-node presence
`/dev/sev-guest` / `/dev/tdx_guest` (**activation** — "this guest *is*"), which are deliberately reported
as **separate fields** and never derived from one another. On **Windows every field is `null`**
(undeterminable): the in-guest attestation path is an ADR 0152 spike that has not landed, and guessing
would be worse than saying so.

**No value of any of these fields satisfies ASVS 11.7.1**, and none may be cited as though it did.
They are values the **host OS emits about itself**, and 11.7.1 exists precisely because that host may be
the adversary — a compromised kernel or hypervisor forges every one of them. Only a **CPU-signed
attestation report verified against the silicon vendor's root PKI** would be evidence; that is ADR 0152
rung 3 and is **not built**. Treat the read-out as configuration confirmation, never as proof.

**The response says so itself.** Every posture body carries `memory_encryption_note` — the same sentence
the startup warning prints — so the disclaimer travels with any copy of the artifact rather than living
only here. Two more fields are deliberately shaped so they cannot be quoted as compliance:
`memory_encryption_operator_declared` (named for what it is: an operator's word, not an attestation) and
`memory_encryption_readout_contradicts_declaration`, which is **tri-state**. `null` on that field means
*nothing was measured that could contradict anything* — the answer on Windows, on an AMD SME / Intel TME
host (memory-controller-wide encryption, which has no guest interface to find), in a container without
the device node mapped, and whenever nobody declared anything. A `false` means the read-out **agrees**,
and it is never emitted by vacuity.

**The property itself is a host requirement, not a switch.**
`memory_encryption_operator_declared = true` records a claim; it does not create memory encryption. An
ASVS **Level 3** PHI deployment must actually run the engine as a **confidential guest** on an AMD
SEV-SNP or Intel TDX host —
[SYSTEM-REQUIREMENTS.md](SYSTEM-REQUIREMENTS.md#hardware-memory-encryption--required-for-an-asvs-level-3-phi-deployment)
states the requirement and the (verified) availability picture, which today is **not reachable for a
Windows guest on on-premises Hyper-V or ESXi**. On a host that does not provide the property, the honest
configuration is **not** to set this: leave it unset, keep the startup warning, and assess 11.7.1
against your own deployment. *(Corrected 2026-08-02: this previously said "disclose 11.7.1 as
**Partial**" — pre-filling a verdict you had not reached, and one this project no longer holds.)*
Reaching for `[security].enforcement = warn` is the wrong lever — that is the global
refuse/warn dial and downgrades every other posture refusal at the same time; nothing about this control
requires it, because it never refuses unless you opt in via `require_memory_encryption_declaration`. The
step-by-step is in OFF-LOOPBACK-DEPLOYMENT.md
§ *In-use data protection*.

## Example

A **complete, startable** `messagefoundry.toml` for a loopback PHI instance on a SQL Server store,
run as `messagefoundry serve --config <dir> --env prod` (the active environment is required and has
no default; `--env` is the CLI layer over `[ai].environment`, which is why it is not in the file).

**Two of these blocks exist only because a shipped serve gate refuses without them** — they are not
optional garnish. An earlier version of this example carried neither and would have hit `exit 2`
twice over. `[retention]` is here for a different reason, given on its own line below. This paragraph
previously said three blocks and four refusing gates; the retention gate stopped refusing over an
unset window when the 30-day auto-bound moved to both enforcement dials. The gates a stock PHI
instance meets, and what satisfies each:
**keyless PHI** → `MEFOR_STORE_ENCRYPTION_KEY` in the environment; **no counted egress list** → at least one
*counted* `[egress]` list, or `[security].block_unlisted_outbound = true` (see "Which lists the
startup gate counts" under [`[egress]`](#egress));
**unbounded retention** → nothing you must configure to boot: `serve` defaults each *unset* PHI
window to 30 days rather than refusing, and only an **explicit** `0` is refused (see
[`[retention]`](#retention)) — set `[security].delete_message_bodies_after_days` and
`[retention].dead_letter_days` anyway, so the windows carry your site's numbers instead of the
engine's floor; **no security-notification channel** → the `[alerts]` SMTP transport.
`[logging]` and `[api]` here are illustrative, not gate-required. `backend = "sqlserver"` also needs
the `sqlserver` extra + ODBC Driver 18 installed (see the note under [`[store]`](#store--message-store--db)).

```toml
# messagefoundry.toml
[store]
backend = "sqlserver"
server = "sql01.hospital.local"
database = "MessageFoundry"
auth = "sql"
username = "mefor_service"
encrypt = true
# The at-rest key itself is env-only: MEFOR_STORE_ENCRYPTION_KEY (see the shell block below).
# Without it a PHI instance — which is every built-in env name — refuses to start.

[security]
local_access_only = true                # loopback bind (ADR 0118; the bind host lives here, not [api])
delete_message_bodies_after_days = 30   # the PHI-body window (ADR 0118; NOT [retention].messages_days)

[api]
port = 8765

# REQUIRED on a PHI instance: with no counted allow-list set, and
# [security].block_unlisted_outbound not written true, serve exits 2.
[egress]
allowed_mllp = ["epic-adt.hospital.local:6661"]
allowed_db   = ["sql02.hospital.local"]
# Any transport left empty here refuses every destination of its type: deny-by-default is on
# unless [security].block_unlisted_outbound is written false. Enumerate what you actually send to.

# REQUIRED on every instance: no out-of-band security-notification channel is an
# exit 2 under the default [security].enforcement = enforce, on dev and staging as much as prod.
[alerts]
email_smtp_host = "smtp.hospital.local"
email_from = "mefor@hospital.local"
email_to   = ["oncall@hospital.local"]

[logging]
level = "info"
format = "json"                       # structured stdout (one JSON object per line)
# Setting forward_host turns forwarding ON by default (ADR 0080); forward_enabled = false opts out.
forward_host = "siem.hospital.local"  # ship a copy off-box to a syslog/SIEM collector
forward_port = 6514                   # RFC 5425 syslog-over-TLS default
forward_protocol = "tls"              # udp (default) | tcp | tls (native RFC 5425, no agent)
forward_tls_ca_file = "C:/mefor/siem-ca.pem"   # required for tls unless forward_tls_verify = false
# Opt-in startup clock-sync gate (ASVS 16.2.2) — warns on skew; add fail-closed to refuse start:
# require_time_sync = true
# ntp_peer = "ntp.hospital.local"

[retention]
# The inbound-body window is [security].delete_message_bodies_after_days above — setting
# messages_days here is REJECTED at load (ADR 0118). Only the plumbing keys stay in this section:
dead_letter_days = 90   # RECOMMENDED: left unset this is auto-bounded to 30 days; an explicit 0 is
                        # an exit 2 under enforce. Set it so the window is your number, not the engine's
# NOTE: vacuum_at / wal_checkpoint_seconds are SQLite-only and a documented NO-OP on this
# backend = "sqlserver" store — space reclamation is a DBA operation there. Deliberately not set.
```
```bash
# secrets via env (never in the file)
set MEFOR_STORE_PASSWORD=...
set MEFOR_STORE_ENCRYPTION_KEY=...   # `messagefoundry gen-key` mints one; without it, exit 2
```

## Build order (incremental)

1. ✅ **Done** — `ServiceSettings` model + loader (file + env + CLI precedence); `[api]`/`[logging]`
   and `[store] backend=sqlite|path|synchronous` wired into `serve` (`--service-config` + the
   `--db`/`--host`/`--port`/`--log-level` overrides).
2. ✅ **Done** — `[delivery]` defaults feed the default `RetryPolicy` (`DeliverySettings.retry_policy()`),
   alongside the ordering / internal-error / buildup-stall-saturation / priority defaults an outbound
   inherits when it declares none.
3. ✅ **Done** — `[store]` server-DB keys landed with the SQL Server **and** Postgres backends (both
   consume `server`/`database`/`username`/`pool_size`/`command_timeout`/`ssl_root_cert`); they are
   **implemented**, not accepted-but-ignored.
4. ✅ **Done** — `[retention]` purge/maintenance job (body-null + WAL/VACUUM, audited; `audit_days`
   reserved). `[logging]` structured-JSON `format` + off-box `forward_*` syslog shipping land
   (sec-offbox-log); PHI redaction is an always-on handler filter (no structlog).

## Open decisions (to confirm)

- ✅ **Decided and built** — **TOML file + env + CLI** as above, chosen for consistency with
  `pyproject.toml` and ops-friendliness; secrets via env.
- ✅ **Settled — the IDE authors, the web console reads.** Settings are **edited from the VS Code
  extension** (its *Edit Security Settings* command shells `messagefoundry security show|set`, which owns
  the TOML write) or by hand in `messagefoundry.toml`; there is **no settings-write API**. The web console
  is **read-only** on posture — `GET /security/posture` (authenticated, `monitoring:read`) surfaces the
  effective switches and active loosenings. This is the reverse of the split originally sketched here.
- Whether per-connection overrides (e.g. a connection's own retry) stay in code (today) or also move
  into settings. Recommendation: **keep per-connection logic in code**, service settings are defaults.
