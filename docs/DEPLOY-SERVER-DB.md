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
- `[store].ssl_root_cert` (**Postgres only**) — pin a private / self-signed DB CA by PEM path so the
  server cert verifies **without** installing the CA box-globally into the OS trust store. **SQL Server
  (ODBC Driver 18) has no connection-string CA-file option** — it validates against the OS trust store,
  so install the DB's CA into the Windows machine trust store instead (setting `ssl_root_cert` for the
  `sqlserver` backend is rejected at load, not silently ignored).
- `[store].pool_size` — see *Pool sizing* below.

> _Filled by staging:_ a minimal `[store]` block for each backend (Postgres DSN; SQL Server ODBC).

---

## 2. Schema bootstrap & evolution

- **Bootstrap on open:** the store creates its tables on `open()` if absent — no separate migration
  step to run. Point the engine at an empty database (and a login that may create objects on first run,
  or pre-create the schema from the documented DDL).
- **Schema-evolution policy:** schema changes are **idempotent additive DDL applied on open** (new
  columns/indexes added if missing; nothing destructive). An engine upgrade that adds a column brings it
  in on the next start. Because v0.1 is greenfield-only, there is no cross-version data backfill to plan.
- **SQL Server specifics:** RCSI (`READ_COMMITTED_SNAPSHOT`) is enabled at open (with a DBA-fallback
  warning if the login can't `ALTER DATABASE`); pre-enable it if your security policy forbids that grant.

> _Filled by staging:_ the exact bootstrap login privileges + the pre-create DDL per backend.

---

## 3. Pool sizing

- **Single node:** `[store].pool_size ≥ 3` recommended. Each stage handoff is a committed round-trip and
  the per-stage workers (router, transform, per-outbound delivery) run concurrently against the pool — a
  pool of 1 serializes them against intake.
- **Clustered (active-passive):** `pool_size ≥ 2` is **required** (a cross-section validator refuses a
  smaller pool when `[cluster].enabled`), `≥ 3` recommended — a clustered node also drives the
  membership / lease-renewal maintenance loop against the pool.

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
| **SQL Server (ODBC Driver 18)** | **Machine trust store only.** ODBC 18 has **no connection-string CA-file keyword**, so it validates against the Windows **LocalMachine\Root** store. There is **no `[store].ssl_root_cert` for the `sqlserver` backend** (it is rejected at load) — import the CA into the machine store (§5.2). | Never. |

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
- [ ] `[store].pool_size ≥ 3` (≥ 2 hard-required in cluster mode).
- [ ] Bootstrap login can create the schema on first open, **or** the schema is pre-created.
- [ ] SQL Server: RCSI enabled (auto, or pre-enabled by a DBA).
- [ ] Source store drained (`in_pipeline → 0`) before cutover — greenfield, no in-place migration.
- [ ] (HA) `[cluster].enabled`; DB-tier replication/Always On configured by DBAs; VIP/LB in front.
- [ ] Off-loopback exposure reviewed against [`DEPLOYMENT.md`](DEPLOYMENT.md) (TLS on every channel).

---

*Companion: [`CONFIGURATION.md`](CONFIGURATION.md) (`[store]`/`[cluster]`), [`CLUSTERING.md`](CLUSTERING.md)
(HA topology + failover), [`DEPLOYMENT.md`](DEPLOYMENT.md) (channel × TLS), and the v0.1 plan
([`releases/v0.1-EXECUTION-PLAN.md`](releases/v0.1-EXECUTION-PLAN.md)).*
