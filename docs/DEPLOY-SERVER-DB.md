# MessageFoundry — Server-DB Deployment (PostgreSQL & SQL Server)

**Status: skeleton (2026-06-15) — structure + guidance are final; backend-specific bootstrap snippets
are filled in as the Gate #3 staging runs confirm them.** How to run the engine on a **production
server database** (PostgreSQL or SQL Server) instead of the single-node SQLite default. For the network
exposure / TLS posture of every channel, see [`DEPLOYMENT.md`](DEPLOYMENT.md); for the full settings
reference, [`CONFIGURATION.md`](CONFIGURATION.md); for clustering, [`CLUSTERING.md`](CLUSTERING.md).

---

## Scope & the greenfield-only rule

v0.1 supports **new** server-DB deployments only. There is **no in-place data migration** from SQLite
to a server DB: an operator **drains the SQLite store** (lets the pipeline empty — `in_pipeline → 0` on
`/stats`) and cuts over to a fresh server-DB store. Plan the cutover as a quiet-window switch, not a
copy. (A migration tool is out of scope for v0.1.)

Both server backends are **production-supported** (no "experimental" label):

- **PostgreSQL** — full staged pipeline, advisory-lock concurrency, row leases; backs active-passive HA.
- **SQL Server** — full staged pipeline + query/response capture; **active-passive too** — the
  leader-gate + self-fence keep a single active processor.

---

## 1. Connection settings

Configure `[store]` in the service settings (full reference: [`CONFIGURATION.md`](CONFIGURATION.md)
`[store]`). The essentials:

- `[store].type` — `postgres` or `sqlserver` (vs the default `sqlite`).
- The connection target (host/port/database/auth) — supply secrets via `MEFOR_*` env, never the file.
- `[store].encrypt` (default **true**) + `[store].trust_server_certificate` (default **false**) —
  encrypt the DB connection; only weaken with `MEFOR_ALLOW_INSECURE_TLS` on a trusted lab segment.
- `[store].ssl_root_cert` — pin the DB server certificate by **file** so it verifies **without**
  installing anything box-globally into the OS trust store, on the secure posture only (`encrypt = true`,
  `trust_server_certificate = false`). **Postgres:** a **CA-bundle** PEM (chain + hostname still checked) —
  the make-before-break-friendly path. **SQL Server:** the ODBC Driver **18.1+** `ServerCertificate`
  keyword, which pins the **leaf** cert (an exact-cert match — see the leaf-pin rotation caveat in §5.3);
  for CA-chain rotation the machine-store import (§5.2) stays the lighter-touch SQL Server option. Rejected
  for SQLite; a missing file fails loud at load.
- `[store].pool_size` — see *Pool sizing* below.

> _Filled by staging:_ a minimal `[store]` block for each backend (Postgres DSN; SQL Server ODBC).

### 1.1 Integrated (gMSA) authentication — SQL Server worked example (#99)

The turnkey Windows/AD posture: the engine service runs under a **group Managed Service Account (gMSA)**
and authenticates to SQL Server with **that Windows identity** (no SQL password anywhere) — set
`[store].auth = "integrated"`, which connects with `Trusted_Connection=yes`. This is also what
`[store].require_managed_identity = true` demands (it refuses a static `auth = "sql"` login on
production PHI). End to end:

**1. Provision the gMSA + let the engine host retrieve its password** (domain admin, once):

```powershell
New-ADServiceAccount -Name mefor-svc -DNSHostName mefor01.corp.example.com `
  -PrincipalsAllowedToRetrieveManagedPassword "MEFOR-Hosts"   # a group the engine host is in
# On the engine host (elevated), install + verify the account:
Install-ADServiceAccount -Identity mefor-svc
Test-ADServiceAccount   -Identity mefor-svc      # must return True (the installer runs this too)
```

**2. Install the service under the gMSA** — `install-service.ps1` runs the gMSA preflight and grants
"Log on as a service" automatically; NSSM's `ObjectName` is the gMSA with a trailing `$` and **no
password**:

```powershell
.\scripts\service\install-service.ps1 -Environment prod `
  -ServiceAccount "CORP\mefor-svc$"          # gMSA — passwordless; preflight + SeServiceLogonRight auto
```

**3. Grant the gMSA a SQL login** (DBA, on the SQL Server) — the Windows account, mapped to a
least-privilege database user; the engine bootstraps its own schema on first open (§2), so the user
needs table create/CRUD on the MessageFoundry database only:

```sql
CREATE LOGIN [CORP\mefor-svc$] FROM WINDOWS;               -- the gMSA's Windows identity ($ suffix)
USE [MessageFoundry];
CREATE USER [CORP\mefor-svc$] FOR LOGIN [CORP\mefor-svc$];
-- Least privilege: schema bootstrap (§2) + row CRUD; NOT sysadmin/db_owner.
ALTER ROLE db_datareader  ADD MEMBER [CORP\mefor-svc$];
ALTER ROLE db_datawriter  ADD MEMBER [CORP\mefor-svc$];
ALTER ROLE db_ddladmin    ADD MEMBER [CORP\mefor-svc$];    -- schema DDL: first open + upgrades
```

**4. The engine `[store]` block** — integrated auth, encrypted, verifying the DB cert against the
Windows machine trust store (§5); **no secret in the file or env**:

```toml
[store]
backend = "sqlserver"
server = "sql01.corp.example.com"
database = "MessageFoundry"
auth = "integrated"                # Trusted_Connection=yes — the gMSA's identity authenticates
encrypt = true                     # default; TLS to the DB
trust_server_certificate = false   # default; verify the DB cert (import its CA into LocalMachine\Root, §5.2)
require_managed_identity = true    # refuse a static SQL login on production PHI (ASVS 13.2.1)
```

> **Why the `$`:** a gMSA authenticates as a *computer-class* principal, so its SQL login name carries the
> trailing `$` (`CORP\mefor-svc$`) — the same name NSSM's `ObjectName` uses.
>
> **Why exactly these three, and never `db_owner` / `sysadmin`:** the store issues `CREATE TABLE` /
> `CREATE INDEX` / `ALTER TABLE ... ADD` / `DROP INDEX` / `DROP TABLE` (`db_ddladmin`), then only
> `SELECT` (`db_datareader`) and `INSERT` / `UPDATE` / `DELETE` / `MERGE` (`db_datawriter`). It never
> creates the database, never `TRUNCATE`s, calls no DMV and no extended procedure, and its two
> `ALTER DATABASE ... SET` statements (`READ_COMMITTED_SNAPSHOT` and `ALLOW_SNAPSHOT_ISOLATION`) each
> degrade to a warning — §2.
>
> **The one thing a higher role would unlock — and why §2's RCSI pre-enable is a prerequisite, never a
> tuning knob.** `db_owner` holds `ALTER` on the database, so it would let the engine turn RCSI on
> itself at open; this login cannot, and the shipped default (`[pipeline].claim_mode = "pooled"` with
> `require_rcsi_for_pooled = true`) **refuses to start** while RCSI is off. Have a DBA run the RCSI and
> `ALLOW_SNAPSHOT_ISOLATION` statements once, before first start. That is the price of the reduced
> role, and it is the only one — it is never a reason to grant a higher role.
>
> **`EXECUTE` is not in the set.** The only **user** stored procedures the engine calls are the two
> lane-family claim procs, and only when `[store].fifo_claim_proc = true` — SQL Server only, default
> `false` ([`CONFIGURATION.md`](CONFIGURATION.md) `[store]`). (`sp_getapplock`, used on every finalize
> and at schema init, is a **system** procedure `public` can already execute — no grant.) Their
> *creation* rides the schema batch either way, but it is permission-guarded and self-no-ops when the
> principal cannot take it, so a login without `CREATE PROCEDURE` still opens cleanly. If you do enable
> the flag with a split bootstrap/runtime principal, the runtime one also needs `VIEW DEFINITION` on
> both procs — without it the startup gate cannot read the bodies it verifies and degrades to the
> shipped batch.
>
> **`db_ddladmin` is a schema-change grant, not a first-run-only one** (§2). Dropping it after the
> first open is supported *only* if you re-grant it for the first start of any upgrade whose schema
> moved: that start issues the DDL batch and **fails outright** without it. Pre-creating the schema
> and never granting it is the other supported posture, and it takes the same upgrade discipline.

### 1.2 PostgreSQL — the least-privilege role

The SQL Server set in §1.1 does **not** transfer: Postgres has no fixed **database** roles, the schema
uses `BIGSERIAL` sequences rather than `IDENTITY`, and there is no stored-procedure path
(`fifo_claim_proc` is SQL Server only). The Postgres equivalent is a role with **no attributes**, plus
object grants. Two supported postures — pick one:

**Posture A — the engine role owns its own schema** (simplest; the engine bootstraps and upgrades
itself, §2):

```sql
CREATE ROLE mefor LOGIN PASSWORD :'pw';          -- NOSUPERUSER NOCREATEDB NOCREATEROLE are the defaults
GRANT CONNECT ON DATABASE messagefoundry TO mefor;
CREATE SCHEMA mefor AUTHORIZATION mefor;         -- run by a DBA; the role owns only this schema
-- then set [store].db_schema = "mefor" so the pool's search_path lands there
```

**Posture B — a DBA pre-creates the objects; the engine role holds only row CRUD** (the analogue of
"pre-create the schema and never grant `db_ddladmin`"; it carries the same upgrade discipline — the
first start of any build whose schema moved must be run by a principal that may issue DDL):

```sql
CREATE ROLE mefor LOGIN PASSWORD :'pw';
GRANT CONNECT ON DATABASE messagefoundry TO mefor;
GRANT USAGE ON SCHEMA mefor TO mefor;                                  -- USAGE, not CREATE
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA mefor TO mefor;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA mefor TO mefor;         -- the BIGSERIAL sequences
```

> **Why nothing wider, derived from the store rather than asserted.** The Postgres store issues
> `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` inside its own schema, then only
> `SELECT` / `INSERT` / `UPDATE` / `DELETE`. Its concurrency primitives are `pg_advisory_xact_lock`
> and `SET LOCAL statement_timeout`, both available to any role. It installs no extension, creates no
> function, and never uses `LISTEN`/`NOTIFY` or `COPY`.
>
> **Never `SUPERUSER`**, and never `CREATEROLE` / `CREATEDB` / `REPLICATION` / `BYPASSRLS`. Do **not**
> make the engine role the **owner of the database** — ownership carries `CREATE` on the database and
> the right to drop it, neither of which the engine uses. Do not grant `pg_read_all_data`,
> `pg_write_all_data`, `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`,
> `pg_signal_backend`, `pg_checkpoint`, `pg_maintain` or `pg_create_subscription`, nor a managed-cloud
> umbrella role (`rds_superuser`, `cloudsqlsuperuser`, `azure_pg_admin`).
>
> **No managed identity.** Postgres has no managed-identity auth mode, so `[store].auth` is a static
> role+password (supply it via `MEFOR_STORE_PASSWORD`, never the file) and
> `[store].require_managed_identity` is unsatisfiable on this backend — see
> [`CONFIGURATION.md`](CONFIGURATION.md). `[store].require_least_privilege` is the orthogonal control
> and **does** apply here (§1.3).

### 1.3 The startup privilege preflight (`[store].require_least_privilege`)

The grants in §1.1 and §1.2 used to be prescriptions the engine could not check. They are now
**observed at every start**, before any listener binds:

| Backend | What the probe reads | On SQLite |
|---|---|---|
| SQL Server | fixed **server**-role and **database**-role membership by name (`IS_SRVROLEMEMBER` / `IS_ROLEMEMBER` — authoritative and independent of catalog visibility), plus `CONTROL SERVER` / database `CONTROL`, plus any user-defined database role the catalog exposes | n/a |
| PostgreSQL | every role the principal may assume and the **attributes** each carries (`SUPERUSER`, `CREATEROLE`, `CREATEDB`, `REPLICATION`, `BYPASSRLS`), plus database ownership and `CREATE` on the database | n/a |
| SQLite | — | reported **not applicable**: a local file has no server principal; access is the filesystem ACL on the `.db` and its `-wal`/`-shm` sidecars |

- **The WARN arm ships on and cannot block an install.** Every start logs what was observed, writes a
  `store_privilege_preflight` audit row, and — when the principal holds more than the documented set —
  names each extra grant in `security_loosenings()` and in `GET /security/posture`.
- **Refusal is opt-in:** set `[store].require_least_privilege = true` to refuse to start on an
  over-grant. Like `require_managed_identity`, the refuse/warn split reads `[security].enforcement`,
  not the deployment tier.
- **It does not fail open.** If the probe cannot run — permission denied, a driver error, a backend
  with no probe — the status is `unobservable`, which is reported as its own loud condition and is
  **never** rendered as a clean result. Under `require_least_privilege` an unobservable probe refuses,
  because a declared refusal that passed a principal it could not read would be a control in name only.

---

## 2. Schema bootstrap & evolution

- **Bootstrap on open:** the store creates its tables on `open()` if absent — no separate migration
  step to run. Point the engine at an empty database (and a login that may create objects on first run,
  or pre-create the schema from the documented DDL).
- **Schema-evolution policy:** schema changes are **idempotent additive DDL applied on open** (new
  columns/indexes added if missing; nothing destructive). An engine upgrade that adds a column brings it
  in on the next start. Because v0.1 is greenfield-only, there is no cross-version data backfill to plan.
- **Steady state issues no DDL at all.** Both server backends stamp a content hash of the shipped DDL
  batch into a one-row `schema_meta` table; when it matches at open, the batch and its serializing lock
  are skipped entirely ([ADR 0064](adr/0064-schema-init-fastpath.md)). So the batch runs only against a
  virgin database and on the **first start of a build whose schema moved** — and on that start a login
  without DDL rights **fails the open**; it does not degrade. Plan the DDL grant as an upgrade-window
  privilege, not a one-time bootstrap one.
- **SQL Server specifics:** RCSI (`READ_COMMITTED_SNAPSHOT`) is enabled at open (with a DBA-fallback
  warning if the login can't `ALTER DATABASE`); pre-enable it if your security policy forbids that grant.
  With the §1.1 least-privilege login this is **not conditional** — that login cannot `ALTER DATABASE`,
  and pooled claim mode (the shipped default) fails closed when RCSI is off.
  The engine login's grants are §1.1 — `db_datareader` + `db_datawriter` + `db_ddladmin`, and never
  `db_owner` or `sysadmin`.

> _Filled by staging:_ the **PostgreSQL** bootstrap role grants + the pre-create DDL per backend. The
> SQL Server set is settled in §1.1 and is **not** transferable: Postgres has no equivalent of SQL Server's fixed **database** roles
> (`db_datareader`/`db_datawriter`/`db_ddladmin`),
> the schema uses `BIGSERIAL` sequences rather than `IDENTITY`, and there is no stored-procedure path
> (`fifo_claim_proc` is SQL Server only), so the Postgres grants are a role/schema-ownership question
> this doc does not yet answer.

---

## 3. Pool sizing

The default `[store].pool_size` is **40** (server-DB only; a no-op on the SQLite default, which uses a fixed
read pool + single writer). Raised from 5 in [ADR 0062](adr/0062-default-store-pool-size.md): the
connection-scale study found the pool is an **inverted-U** — it helps up to ~40 per engine, and
**over-provisioning is catastrophic** (past ~40 the extra connections thrash one shared instance — WRITELOG +
finalizer applocks — and ACK latency explodes 30–90×). 40 is the measured **optimum**, not a floor: **do not
set it higher to chase connection count** (that path is refuted — scale is *sharding*, not a bigger pool).
Tunable via `[store].pool_size` / `MEFOR_STORE_POOL_SIZE`; re-measure for a materially different deployment
shape (transform cost, message size, disk, SQL-box sizing).

- **Single node:** `[store].pool_size ≥ 3` recommended. Each stage handoff is a committed round-trip and
  the per-stage workers (router, transform, per-outbound delivery) run concurrently against the pool — a
  pool of 1 serializes them against intake.
- **Clustered (active-passive):** `pool_size ≥ 2` is **required** (a cross-section validator refuses a
  smaller pool when `[cluster].enabled`), `≥ 3` recommended — a clustered node also drives the
  membership / lease-renewal maintenance loop against the pool.
- **Connection-budget ceiling (important on a shared server DB):** `pool_size` is **per engine**. Every
  Postgres/SQL Server engine that shares the store — multi-process shards (all connect to the *same*
  database) and the active-passive standby's warm pool — counts against one server limit. So budget
  **peak connections ≈ engines × `pool_size`** (+ the standby's `warm_pool_target`) and keep it well under
  the DB server's `max_connections` (**Postgres default ~100**; SQL Server is bounded by sessions/memory).
  At the default `pool_size = 40`, ~2 co-located engines already reach ~100 — **a config that connected at
  5 can fail to connect at 40.** Co-locating several server-DB engines (a sharded fan-out)? **Raise
  `max_connections`, front the DB with a connection pooler (PgBouncer), or use SQL Server** (more sessions);
  or size `pool_size` **down**. **Do NOT give each shard its own database/server** — that is a split store,
  which is disallowed ([ADR 0063](adr/0063-no-split-store-unified-store-for-sharding.md)); one unified store
  scales *vertically* (faster box/disk) + *cheaper-per-message*, never by fragmenting. Also budget the startup
  warm burst (~20 pre-opened/engine at the default; set `warm_pool_target` or `warm_pool = false` on a
  connection-/license-constrained site).
- **Commit-depth at high interface counts (`fifo_claim_batch`):** the pool is not the only per-engine wall —
  above ~48 inbound interfaces an engine becomes bound by *commits per message* on the shared store (WRITELOG
  + the per-message finalizer applock), which a bigger pool **cannot** fix. For a **high-interface-count,
  commit-bound** server-DB engine, set **`[store].fifo_claim_batch = 8`** (range 8–16, [ADR 0058](adr/0058-batch-claim-fifo-prefix.md)):
  the INGRESS/ROUTED FIFO claim then takes the contiguous due head-prefix in one commit instead of one-per-row,
  amortizing the claim commit toward `1/N` on backlogged lanes. It **preserves strict per-lane FIFO (#285) +
  at-least-once**, is **byte-identical at `1` (the default)** and on caught-up (low-backlog) lanes, and never
  batches the outbound/delivery claim. Size it against worst-case message size (N decrypted bodies are resident
  per lane between the claim and its N handoffs). This — not the pool — is the *raise-interfaces-per-engine*
  lever.

---

## 4. High availability (active-passive)

Engine HA in v0.1 is **active-passive**: exactly one node (the leader) binds listeners and processes the
graph; a standby stays warm and takes over on failure. Full design + operations: [`CLUSTERING.md`](CLUSTERING.md).

- **Engine tier (MessageFoundry):** set `[cluster].enabled` on a server-DB store. Leadership is a
  **self-fencing lease** in the shared DB (DB-clock TTL + a no-DB fence watchdog); only the leader
  processes, so there is no split-brain double-processing. `GET /cluster/status` + `/cluster/nodes`
  expose role/lease/roster.
- **DB tier:** database HA — PostgreSQL replication / SQL Server **Always On** — is **delegated to your
  DB administrators**, not built by MessageFoundry. The engine cluster rides the shared store connection,
  so its availability follows the DB tier's.
- **Front it with a floating VIP / load balancer** pointed at the active node's listeners (the standby
  refuses new inbound work until it is promoted). Inbound TLS posture per [`DEPLOYMENT.md`](DEPLOYMENT.md).

> _Filled by the Gate #3 failover run:_ the measured recovery/promotion time + the
> kill-primary-mid-load characteristics (see [`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md)).

---

## 5. DB-TLS trust: import the DB CA + rotate certificates

The engine connects to the server database over TLS (`[store].encrypt = true`, the default) and
**validates the server certificate** — `[store].trust_server_certificate` stays **false**. For that
validation to succeed, the database's certificate must chain to a CA the host already trusts. With a
**private / internal CA** that means establishing trust explicitly. Disabling validation
(`TrustServerCertificate=true`) is **not** the answer — it re-opens a man-in-the-middle path to PHI.

> **Standards.** Validate the full chain to a trusted CA and check certificate expiry/rotation — NIST
> SP 800-52r2 (TLS for government/enterprise use); HIPAA **§164.312(e)(1)** (transmission security);
> CWE-295 (improper certificate validation). Never remediate a chain-build failure with
> `TrustServerCertificate=true` / `[store].trust_server_certificate = true`.

### 5.1 Where trust is anchored, per backend

| Backend | How the DB CA is trusted | Disable validation? |
|---|---|---|
| **PostgreSQL** | **Either** pin the CA by file with `[store].ssl_root_cert = <ca.pem>` (no machine-wide install — see §1), **or** import it into the Windows machine trust store (§5.2). The file pin is the lighter-touch path. | Never. |
| **SQL Server (ODBC Driver 18)** | **Machine trust store** (`LocalMachine\Root`, §5.2) is the CA-chain path — recommended for make-before-break rotation. **Or** pin the server's cert by file with `[store].ssl_root_cert = <cert>` (ODBC Driver **18.1+** `ServerCertificate`), a **leaf** pin that must be rotated in lockstep with the server cert (§5.3 caveat). | Never. |

### 5.2 Import a private / internal CA into the machine store (`LocalMachine\Root`)

The CA must go into the **machine** store (`Cert:\LocalMachine\Root`), **not** the per-user store
(`Cert:\CurrentUser\Root`): the engine runs as a **service principal** — LocalSystem, a gMSA, or a
dedicated service account — which only reads the machine store. A per-user import is invisible to the
service.

From an **elevated (Administrator)** PowerShell, use the helper:

```powershell
.\scripts\service\import-db-ca.ps1 -CaPath C:\certs\internal-root-ca.crt
```

or run the equivalent built-in directly:

```powershell
# PowerShell:
Import-Certificate -FilePath C:\certs\internal-root-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
# certutil equivalent:
certutil -addstore -f Root C:\certs\internal-root-ca.crt
```

Both write `LocalMachine\Root` and are idempotent (keyed on thumbprint). After import, the DB server
certificate that chains to this CA validates with `[store].trust_server_certificate = false` —
`TrustServerCertificate=true` is **never** needed.

### 5.3 CA / server-cert rotation — make-before-break (no connection outage)

Rotate **before** expiry, and overlap the old and new trust anchors so there is **no window where a
connection fails validation** (NIST SP 800-52r2: rotate certificates before expiry). The order is
*add-new-then-remove-old* on every node that connects to the DB:

**Rotating the CA (root/intermediate):**

1. **Add** the new CA alongside the old one — both trusted at once (the overlap window):
   - **SQL Server:** import the new CA into `LocalMachine\Root` (§5.2) on every connecting host; the
     old CA stays imported. Both chains now validate.
   - **PostgreSQL (file pin):** point `[store].ssl_root_cert` at a **multi-root PEM bundle** containing
     **both** the old and new CA certs (concatenate them in one PEM file), then reload. `libpq`
     accepts a server cert that chains to **either** root.
2. **Roll the DB server certificate** to one issued by the new CA (a DB-administrator action). Because
   both CAs are trusted, connections keep validating across the swap.
3. **Remove the old CA** once every host trusts the new one and the server cert has rolled:
   - **SQL Server:** delete the old CA from `LocalMachine\Root` (e.g.
     `Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq <old> | Remove-Item`).
   - **PostgreSQL:** drop the old CA from the PEM bundle and reload.

**Rotating only the server leaf cert** (same CA): no trust-store change is needed — the new leaf still
chains to the already-trusted CA. Just roll it before expiry. **Caveat — leaf pinning:** if you pinned
the *leaf* instead of the CA (PostgreSQL `ssl_root_cert` pointed at the server cert itself; or SQL
Server ODBC 18.1+ `ServerCertificate=<file>` leaf-pin), a leaf rotation **breaks validation** until you
update the pin in lockstep — pin the **CA**, not the leaf, to keep rotations make-before-break.

> Windows-box gate: §5.2's machine-store import + §5.3's SQL Server steps run on the deployment host
> (LocalMachine store), not on hosted CI. Validate them on the target Windows box / the dogfood box.

---

## 6. Pre-flight checklist

- [ ] `[store].type` set to `postgres`/`sqlserver`; connection + auth via `MEFOR_*` env.
- [ ] `[store].encrypt = true` (and **not** `MEFOR_ALLOW_INSECURE_TLS`) for any PHI deployment.
- [ ] DB CA trusted so `trust_server_certificate = false` validates — Postgres `ssl_root_cert` **or**
      machine-store import; SQL Server **machine store only** (§5). Never `TrustServerCertificate=true`.
- [ ] `[store].pool_size` sized (default **40**, server-DB only; ≥ 2 hard-required in cluster mode) **and**
      the connection budget checked: engines × `pool_size` (+ standby warm) well under the DB `max_connections` (§3).
- [ ] Bootstrap login can create the schema on first open, **or** the schema is pre-created.
- [ ] SQL Server: RCSI enabled (auto, or pre-enabled by a DBA).
- [ ] Source store drained (`in_pipeline → 0`) before cutover — greenfield, no in-place migration.
- [ ] (HA) `[cluster].enabled`; DB-tier replication/Always On configured by DBAs; VIP/LB in front.
- [ ] Off-loopback exposure reviewed against [`DEPLOYMENT.md`](DEPLOYMENT.md) (TLS on every channel).

---

*Companion: [`CONFIGURATION.md`](CONFIGURATION.md) (`[store]`/`[cluster]`), [`CLUSTERING.md`](CLUSTERING.md)
(HA topology + failover), [`DEPLOYMENT.md`](DEPLOYMENT.md) (channel × TLS), and the v0.1 plan
(`releases/v0.1-EXECUTION-PLAN.md`).*
