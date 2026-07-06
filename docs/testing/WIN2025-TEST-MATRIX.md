# MEFOR Test Coverage — Windows Server 2025, all 3 databases

Test coverage matrix for validating MessageFoundry (MEFOR) setups on the new Windows Server 2025
box, which has all three supported store backends: **SQLite**, **SQL Server**, and **PostgreSQL**.

**"Per-DB?" = run the row once on each backend (SQLite / SQL Server / PostgreSQL).** That per-backend
dimension is the spine of this exercise since the box has all three.

---

## A. Environment & prerequisites (run once)

| # | Test item | Notes / Win 2025 specifics |
|---|---|---|
| A1 | Python 3.14+ present; project `.venv` builds; `requirements.lock` installs hash-verified | Confirm interpreter arch (x64) matches DB drivers; engine requires Python >=3.14 |
| A2 | Optional extras install cleanly: `[postgres]`, `[sqlserver]`, `[dicom]` | `[sqlserver]` pulls ODBC stack; `[dicom]` pulls pydicom/pynetdicom |
| A3 | SQL Server ODBC Driver (18) installed & discoverable | OS-level driver, not pip — verify version on Server 2025 |
| A4 | PostgreSQL client (`asyncpg`) imports & reports a version | asyncpg speaks the wire protocol directly — no libpq/psycopg needed |
| A5 | Windows Firewall rules for listener ports (MLLP 2575, DICOM, TCP, API loopback) | Server 2025 firewall defaults are stricter |
| A6 | Service account: file ACLs on store dir, config dir, log dir | NSSM service identity vs interactive user |
| A7 | Console runs (Desktop Experience present, not Server Core) | PySide6 needs a GUI session |

## B. Database backend setup & connectivity — Per-DB x3

| # | Test item | Notes |
|---|---|---|
| B1 | `[store].backend = sqlite\|sqlserver\|postgres` opens cleanly | The single backend-selection seam (`open_store`) |
| B2 | Schema auto-creates on first start (tables, queue, response, audit) | |
| B3 | Connection string / auth from `MEFOR_*` env (no secrets in config) | SQL Server: Windows-auth vs SQL-auth; Postgres: password/SSL |
| B4 | Encryption at rest: detail-class columns encrypted; `key_provider` byte-identical across backends | ADR 0019 KeyProvider parity |
| B5 | Off-box audit tee emits (single PHI-redaction path, all backends) | `emit_audit_tee` |
| B6 | Reconnect / transient-error handling under DB restart | Server reboot, SQL service bounce |

## C. Store functional parity (staged pipeline) — Per-DB x3

| # | Test item | Notes |
|---|---|---|
| C1 | Ingress->routed->outbound handoffs each commit atomically; no loss/dup | Reliability invariant |
| C2 | ACK-on-receipt: raw committed to ingress **before** ACK | Count-and-log invariant |
| C3 | Disposition finalizer correctness: RECEIVED->ROUTED/UNROUTED->PROCESSED/FILTERED/ERROR | Finalizer = sole authority |
| C4 | **Strict per-lane FIFO** ordering preserved (regression-sensitive on SQL Server) | SQL Server FIFO bug #285 — keep as hard gate |
| C5 | `reset_stale_inflight` recovers in-flight rows of every stage on startup | Crash/kill recovery |
| C6 | Dead-letter capture + bulk replay across backend | |
| C7 | Request/response (reply) capture: `complete_with_response` | `captures_responses` True on all 3 |
| C8 | Retry/back-off, error->dead-letter routing | Post-ingress failures don't NAK |

## D. Transports / connectors (on Windows) — inbound + outbound

| # | Test item | Per-DB? |
|---|---|---|
| D1 | MLLP in + out, ACK/NAK modes (AA/AE/AR; original vs enhanced vs none) | once (smoke per-DB) |
| D2 | File in + out (Windows paths, locking, atomic move) | once |
| D3 | RemoteFile SFTP/FTP in + out | once |
| D4 | TCP in + out (raw framing) | once |
| D5 | X12 in + out (ISA/IEA framing, interchange split) | once |
| D6 | DICOM C-STORE SCP inbound; SR->HL7 handler | once |
| D7 | Database source (poll) + destination; `db_lookup` read-only enrichment | **x3** (DB egress per backend) |
| D8 | REST / SOAP / FHIR destinations | once |
| D9 | Timer + Loopback sources | once |
| D10 | Per-connection count-and-log: nothing accepted-and-dropped | once |

## E. HL7 / payload handling (run once)

| # | Test item |
|---|---|
| E1 | Tolerant peek (python-hl7) routing on the hot path |
| E2 | Strict validation opt-in per inbound (hl7apy); explicit version |
| E3 | Non-conformant input routes to ERROR, never crashes the connection |
| E4 | Payload-agnostic ingress: `content_type` selects HL7 vs RawMessage (X12/DICOM/binary) |
| E5 | Binary carriage (`mfb64:v1:`) NUL-safe through str/TEXT store |
| E6 | Raw message preserved alongside transformed |

## F. Auth, RBAC, API, Console (run once)

| # | Test item |
|---|---|
| F1 | Local + AD (LDAP/Kerberos) login on a domain-joined Server 2025 |
| F2 | Native TOTP MFA for local accounts (WP-14) |
| F3 | Deny-by-default per-route RBAC; admin-defense controls |
| F4 | API binds 127.0.0.1; auth required; in-process TLS option |
| F5 | Config reload (`POST /config/reload`) confined to allow-listed roots |
| F6 | Console connects over HTTP API only; monitors/operates |
| F7 | **No console-window flash** on Status-page service poll (CREATE_NO_WINDOW) — regression of commit 901f31d |
| F8 | PHI access audited with acting user |

## G. HA / clustering & deployment — Per-DB where noted

| # | Test item | Notes |
|---|---|---|
| G1 | NSSM service install/uninstall; autostart; crash-restart; stdout->log capture | Server 2025 service control |
| G2 | Active-passive leadership lease + leader-gated graph | Postgres + SQL Server |
| G3 | **Failover under load** (SIGKILL/equiv), per-lane FIFO preserved | Gate #3 harness (#283); **x3 server DBs** |
| G4 | `/cluster` observability + alerts + dead-letters page | |
| G5 | SQLite single-node = byte-identical baseline | sanity anchor |

## H. Performance & security validation (run once + per-DB throughput)

| # | Test item | Per-DB? |
|---|---|---|
| H1 | Throughput baseline under load harness (#294) | **x3** |
| H2 | No full PHI payloads at INFO+; dryrun/generate output not logged | once |
| H3 | Secrets only from `MEFOR_*`; none in config/logs | once |
| H4 | Off-box log shipping reachable from the server | once |

---

**Notable Windows Server 2025 risk areas to weight more heavily:** A3 (ODBC 18 driver),
C4/G3 (SQL Server per-lane FIFO — there is a real prior bug here), F7 (console-window flash
regression), and G1 (NSSM behavior on the newer OS).
