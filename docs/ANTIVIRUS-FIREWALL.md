# MessageFoundry — Antivirus Exclusions & Firewall Permissions (Windows Operations Guide)

This guide is for the **Windows server administrator, endpoint-security/EDR administrator, and firewall administrator** standing up MessageFoundry as a Windows service (NSSM). It tells you exactly which **paths and processes** to exclude from antivirus scanning and which **inbound/outbound firewall openings** the engine needs — and, just as importantly, which it does **not**.

## Guiding principle: narrowest exclusions only

MessageFoundry carries **PHI**. Every antivirus exclusion and every firewall opening **widens the PHI attack surface**, so the rule throughout this document is:

- **Exclude the narrowest specific path or process that works — never a whole drive, a whole `C:\ProgramData`, or a whole process tree.**
- **Open the narrowest specific port/program/remote-address that works** — scope outbound rules to the engine program and to the specific partner addresses you actually talk to.
- Ports for HL7/DICOM/X12 listeners are **per-connection** (set by the admin in config), **not** fixed product defaults. Enumerate the real ports from *your* configuration; do not copy sample numbers blindly.

If an exclusion or rule is not justified below for *your* deployment, do not add it.

---

## Key facts at a glance

| Fact | Value |
|---|---|
| Windows service name | `MessageFoundry` (installed via **NSSM** wrapper) |
| Registered service binary (`Application`) | `<repo>\.venv\Scripts\messagefoundry.exe` (a console-scripts shim) |
| **Actual long-running process** (socket owner) | the venv **`python.exe`** that `messagefoundry.exe` re-execs |
| Service wrapper process | `nssm.exe` (at `<DataDir>\bin\nssm.exe` by default) |
| `DataDir` default | `C:\ProgramData\MessageFoundry` |
| Message store DB | `C:\ProgramData\MessageFoundry\messagefoundry.db` |
| DB sidecars (WAL mode) | `messagefoundry.db-wal`, `messagefoundry.db-shm` (hyphenated suffix on the **full** filename) |
| Rollback journal | **Does not exist** — the store runs `PRAGMA journal_mode=WAL` unconditionally (no setting disables it), so no `-journal` sidecar appears in any supported deployment |
| Logs | `C:\ProgramData\MessageFoundry\logs\service.out.log`, `...\service.err.log` (rotated at ~10 MiB) |
| API bind (default) | `127.0.0.1:8765` (loopback) |
| Bootstrap secret | `C:\ProgramData\MessageFoundry\bootstrap-admin.txt` (owner-only `0o600`, alongside the DB) |

> The service you see in `services.msc` and Task Manager is `messagefoundry.exe`, but the process that actually owns the listening/connecting sockets is the venv **`python.exe`** it launches. That distinction matters for program-scoped firewall rules below.

---

## Antivirus / EDR exclusions

Two kinds of exclusion are needed: **path** (so the scanner does not open/lock/quarantine live data files) and **process** (so the scanner does not throttle or false-positive the interpreter).

### Why AV exclusions matter for a healthcare engine

- **WAL corruption / latency (see the dedicated section below).** Real-time scanning of the live SQLite store and its `-wal`/`-shm` files can hold file locks and corrupt the at-least-once delivery queue.
- **Quarantined PHI is unrecoverable.** If the scanner quarantines the store DB, a sidecar, the DPAPI store key, or a connector key/cert, the engine **fails closed** — it will not start and PHI at rest becomes unreadable. There is no "re-download" for your message store.

### Path exclusions

Exclude these specific paths (substitute your real `DataDir`, repo path, and configured key/cert locations). **Scope to the file or the smallest containing folder — not the whole `ProgramData`.**

| Path (default) | What it is | Why exclude | Risk if not excluded |
|---|---|---|---|
| `C:\ProgramData\MessageFoundry\messagefoundry.db` | SQLite message store | Live, constantly-written queue/inbox/outbox | Lock contention, **WAL corruption**, quarantine → engine fail-closed |
| `C:\ProgramData\MessageFoundry\messagefoundry.db-wal` | WAL sidecar | Write-ahead log, written on every commit | Corruption of in-flight messages; lost/duplicated delivery |
| `C:\ProgramData\MessageFoundry\messagefoundry.db-shm` | Shared-memory index | WAL coordination file | WAL breakage; failed opens |
| `C:\ProgramData\MessageFoundry` (DataDir folder) | Data dir | Holds DB trio, `bootstrap-admin.txt`, etc. | Misc. data-at-rest quarantine |
| `C:\ProgramData\MessageFoundry\logs\` | Service logs | High-frequency append + rotation | Rotation failures, scan thrash |
| `C:\ProgramData\MessageFoundry\bootstrap-admin.txt` | One-time bootstrap admin secret (`0o600`) | Owner-only secret, written next to the DB | **Also exclude from AV cloud-sample upload** — never let it leave the host |
| **`[store].encryption_key_file`** (operator-configured path — **may sit outside DataDir**) | DPAPI-wrapped store encryption key (for `key_provider=dpapi`/`auto`) | Decrypted into memory at startup to unlock the store | **Quarantine/lock → `DpapiError` (fail-closed) → store key cannot be provisioned → engine won't start and PHI at rest is unreadable.** Exclude its *actual* path. |
| Connector **key/cert files** referenced by path (operator-configured, **may be anywhere on disk**) | JWS signing key (`signing.py` `private_key`), SMART Backend Services key (`smart_private_key` PEM file path), SOAP mTLS `client_cert_file` / `client_key_file` | Read on demand for outbound signing / SMART token / mTLS | Quarantine → broken outbound **signing / SMART auth / mutual-TLS delivery** to those partners. *(Inline-PEM-via `env()` deployments have no file to exclude.)* |
| File-connector **inbound (source) directory** + its `.processed` and `.error` subdirs | Watched intake dir (default poll **1.0 s**) and move-aside targets | Constant directory polling + file moves | Scan thrash, file-move races, quarantined intake |
| File-connector **outbound (destination) directory** + `*.part` + `*.probe` | Write-temp (`*.part`, `tempfile.mkstemp` suffix), then rename; reachability probe (`*.probe`) | Temp files churned on every delivery | Failed renames → stuck/duplicated delivery |
| `<repo>\.venv\` | Engine Python virtual environment | Interpreter + dependencies, constantly memory-mapped | Import-time scan latency; DLL/`.pyd` false positives |
| `<repo>\samples\config` or your real **config dir** | Connection/Router/Handler modules | Loaded at startup; not data, but scanned on read | Startup latency; spurious quarantine of `.py` |
| `<DataDir>\bin\nssm.exe` | Cached service wrapper | Long-running supervisor binary | False-positive quarantine kills the service |

> **REMOTEFILE is different.** The directory exclusions above are for the **local File connector only**. If you use the **REMOTEFILE** connector (SFTP/FTP/FTPS), its files live on the **remote** server, not in a local watched directory — there is no local intake dir to exclude. REMOTEFILE instead needs an **outbound firewall rule** (see the firewall section). Do not invent a local-dir exclusion for it.

> **Sharded (L3) deployments.** Each shard runs `<stem>_<shard>.db` plus its own `-wal`/`-shm`. Cover them with the globs `*.db`, `*.db-wal`, `*.db-shm` (equivalently `*.db*`) under the shard data directory.

> **Developer / IDE boxes (out of scope here, noted for completeness).** A workstation running the IDE/test bench additionally has a local **`.mefor/`** dev store directory (with its own DB sidecars) worth excluding. The production NSSM service does **not** write `.mefor/` — it uses the explicit `--db` under `DataDir` — so a server deployment omits it.

### Process exclusions

| Process | Why exclude |
|---|---|
| venv **`python.exe`** (`<repo>\.venv\Scripts\python.exe`) | The real long-running engine process: listeners, connect sockets, store I/O. Interpreters are a frequent heuristic false-positive, and on-access scanning of its memory-mapped modules adds latency to a real-time message path. |
| `messagefoundry.exe` (`<repo>\.venv\Scripts\messagefoundry.exe`) | The registered service shim that re-execs `python.exe`. Exclude so the launcher isn't blocked/quarantined. |
| `nssm.exe` (`<DataDir>\bin\nssm.exe`) | The service wrapper. A quarantine here stops the whole service. |

> There is **no** `.venv\Scripts\nssm.exe`. NSSM is resolved only from `-NssmPath`, from an on-`PATH` `nssm`, or auto-downloaded to `<DataDir>\bin\nssm.exe`.

### WAL corruption / latency — why the DB trio is the most important exclusion

The store is a **transactional staged queue on SQLite in WAL mode**, providing at-least-once delivery, retries, replay, and dead-lettering **without** a separate broker. Three files are involved on every commit:

- `messagefoundry.db` — the main database,
- `messagefoundry.db-wal` — the write-ahead log appended on each commit,
- `messagefoundry.db-shm` — the shared-memory index coordinating WAL readers/writers.

Real-time antivirus that **opens, locks, or quarantines** any of these mid-write can:

1. **Hold a file lock** the engine needs to commit, stalling intake (the inbound ACK is sent only after the raw message is durably committed — a held lock delays the ACK and backs up the sender).
2. **Corrupt the WAL/SHM pair**, which can lose or duplicate in-flight messages and break the at-least-once invariant.
3. **Quarantine a sidecar**, leaving the DB unopenable → the service fails to start → **PHI at rest becomes inaccessible**.

This is why the DB and **both** sidecars are excluded explicitly, with the exact hyphenated suffixes `-wal` / `-shm` (not `.wal` / `.shm`, not `.db.wal`).

### Sample Microsoft Defender commands

```powershell
# --- Path exclusions (substitute your real DataDir / repo / key paths) ---
Add-MpPreference -ExclusionPath 'C:\ProgramData\MessageFoundry\messagefoundry.db'
Add-MpPreference -ExclusionPath 'C:\ProgramData\MessageFoundry\messagefoundry.db-wal'
Add-MpPreference -ExclusionPath 'C:\ProgramData\MessageFoundry\messagefoundry.db-shm'
Add-MpPreference -ExclusionPath 'C:\ProgramData\MessageFoundry\logs'
Add-MpPreference -ExclusionPath 'C:\ProgramData\MessageFoundry\bootstrap-admin.txt'
Add-MpPreference -ExclusionPath 'C:\Path\To\MessageFoundry\.venv'
Add-MpPreference -ExclusionPath 'C:\ProgramData\MessageFoundry\bin\nssm.exe'
# DPAPI store key + connector key/cert files — exclude their ACTUAL configured paths:
Add-MpPreference -ExclusionPath 'C:\Path\To\store-key.bin'        # [store].encryption_key_file
Add-MpPreference -ExclusionPath 'C:\Path\To\signing-key.pem'      # JWS / SMART / SOAP mTLS keys & certs
# File-connector dirs (only if you use the local File connector):
Add-MpPreference -ExclusionPath 'C:\Feeds\inbound'
Add-MpPreference -ExclusionPath 'C:\Feeds\outbound'

# --- Process exclusions ---
Add-MpPreference -ExclusionProcess 'C:\Path\To\MessageFoundry\.venv\Scripts\python.exe'
Add-MpPreference -ExclusionProcess 'C:\Path\To\MessageFoundry\.venv\Scripts\messagefoundry.exe'
Add-MpPreference -ExclusionProcess 'C:\ProgramData\MessageFoundry\bin\nssm.exe'
```

**Third-party EDR (CrowdStrike, SentinelOne, Defender for Endpoint, Sophos, etc.):** create the equivalent **file/folder exclusions** and **process/executable exclusions** for the same paths and processes through your management console, and ensure `bootstrap-admin.txt` and any key/cert files are excluded from **cloud sample submission / upload**, not just on-access scanning.

---

## Windows Firewall

### Inbound (the engine *listens*)

Listener ports are **per-connection** — the admin assigns them in config; there is **no product-wide default MLLP/X12 port**. Open only the ports your configured inbound connections actually bind.

| Inbound flow | Port | Notes |
|---|---|---|
| **MLLP inbound** (HL7 v2) | **Per-connection (admin opens the port they assigned)** | No hard-coded default. The shipped samples use *several distinct* ports — e.g. `IB_ACME_ADT` → **2600**, `IB_Test_ADT` → **2575**, `IB_IMMUNIZATION_VXU` → **2620**. (`2575` is also the **verify smoke-test** `--mllp-port` default, not a connection default.) **Enumerate the real ports from your config.** |
| **DICOM C-STORE SCP** (inbound DIMSE) | **Per-connection (admin opens the port they assigned)** — sample/conventional default **104** | No hard-coded default; **104** is the conventional DICOM port (not `11112`). Open the port your `DICOM()` inbound is configured to bind. Behind the `[dicom]` extra. |
| **X12 raw-TCP inbound** (ISA/IEA-framed) | **Per-connection (admin opens the port they assigned)** | No hard-coded default. Open the port your `X12()` inbound binds. |
| **API / WebSocket** | `127.0.0.1:8765` (default) | **Loopback — needs no firewall rule.** Console/IDE reach it over `127.0.0.1`. Only add an inbound rule if you deliberately bind the API to a routable NIC for a **remote console** (the one documented exception), and then front it with TLS. |

> **Loopback needs no rule.** Windows Firewall does not filter `127.0.0.1` traffic, so the default API bind requires no inbound rule at all. Keep it on loopback unless you have an explicit remote-console requirement.

### Outbound (the engine *connects out*)

Outbound destinations are gated **at the application layer** by the `[egress]` allowlists — `allowed_mllp`, `allowed_tcp`, `allowed_http`, `allowed_db`, and `allowed_remote`. **Every outbound firewall rule you open should be mirrored by the matching `[egress]` allowlist entry** (and vice-versa), so the two layers agree on exactly which partners are reachable.

| Outbound flow | Port | App-layer gate | Notes |
|---|---|---|---|
| **MLLP outbound** (HL7 sender) | Per-connection (partner host:port) | `[egress].allowed_mllp` | Open to each configured downstream MLLP receiver. |
| **Raw-TCP outbound** | Per-connection (partner host:port) | `[egress].allowed_tcp` | Generic TCP destinations. |
| **X12 raw-TCP outbound** | Per-connection (partner host:port) | `[egress].allowed_tcp` | ISA/IEA-framed sender. |
| **DICOM SCU / C-ECHO** (outbound DIMSE) | Per-connection (partner host:port; conventionally 104) | `[egress].allowed_tcp` | `[dicom]` extra. |
| **DICOMweb (STOW-RS) / REST / SOAP / FHIR / SMART** | HTTPS **443** (host:port from each URL) | `[egress].allowed_http` | HTTPS to each service base URL. **FHIR** is a distinct REST-sibling destination; **SMART** Backend Services adds a token endpoint (often a *different* host) — open both. |
| **REMOTEFILE** (SFTP / FTP / FTPS) | **SFTP TCP 22** (default), **FTP TCP 21** (default), **FTPS = explicit TLS over the FTP control port (21 by default; `PROT P` encrypts the data channel)** | `[egress]` + per-connection host:port | Behind the `[sftp]` extra (paramiko, for SFTP). **Also an inbound *polling source* — but it has no listener; it dials *out* to poll**, so it needs only **outbound** openings to each configured remote file server. |
| **DATABASE connector** (partner DB poll/write) | TCP **1433** (partner SQL Server, `aioodbc`, `[sqlserver]` extra) | `[egress].allowed_db` | **Distinct from the message-store backend.** `DatabaseSource` polls a partner table (leader-gated, no listener — it dials out); `DatabaseDestination` writes to it. Open a *separate* rule from any store-backend rule below. |
| **AD / LDAP outbound** *(only if you use AD auth)* | **636** for `ldaps://`, or **389** if `ad_allow_insecure_ldap` | — | Port comes from the `ad_server` URL (e.g. `ldaps://dc1.example.com:636`); it is **not** hard-coded. **Kerberos (88) is *not* an engine outbound** — the engine validates a SPNEGO ticket the *client* already obtained from the KDC (server-side validation), so do **not** open outbound 88 from the engine box. |
| **Message-store backend** *(only if you use a remote store)* — SQL Server **1433** / PostgreSQL **5432** | 1433 / 5432 | — | Open only if the **store** itself is a remote SQL Server / Postgres rather than the default local SQLite. |
| **NSSM download** — `nssm.cc` (HTTPS 443) | 443 | — | **🔧 INSTALL-TIME ONLY.** One-time download of the wrapper; close after install. |
| **PyPI** — `pypi.org` / `files.pythonhosted.org` (HTTPS 443) | 443 | — | **🔧 INSTALL-TIME ONLY.** Package install; not needed at steady state. |

> Rows marked **🔧 INSTALL-TIME ONLY** are needed once to install the service and its dependencies. They are **not** part of steady-state operation — remove or disable them after install.

### Sample `New-NetFirewallRule` commands

Scope every rule to the **engine program** (`python.exe`, the real socket owner) and to **specific remote addresses** — never "any".

```powershell
# --- Inbound: one MLLP listener (use YOUR assigned port; 2600 = IB_ACME_ADT sample) ---
New-NetFirewallRule `
  -DisplayName 'MessageFoundry MLLP inbound (IB_ACME_ADT)' `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 2600 `
  -Program 'C:\Path\To\MessageFoundry\.venv\Scripts\python.exe' `
  -RemoteAddress 10.0.0.0/24      # restrict to the partner subnet(s) that send to you

# --- Outbound: one MLLP partner (mirror with [egress].allowed_mllp) ---
New-NetFirewallRule `
  -DisplayName 'MessageFoundry MLLP outbound (OB_ACME_ADT)' `
  -Direction Outbound -Action Allow -Protocol TCP -RemotePort 6000 `
  -Program 'C:\Path\To\MessageFoundry\.venv\Scripts\python.exe' `
  -RemoteAddress 10.0.50.10       # the specific downstream receiver host
```

> **`-Program` targets `python.exe`, not the `messagefoundry.exe` shim**, because the venv `python.exe` is the process that actually owns the socket. (The shim only launches it.)
>
> **Firewall profile:** the samples omit `-Profile` so they apply to all profiles. If you scope by profile, **match the server's actual network profile** — `Domain` on a domain-joined host, but `Private`/`Public` on a workgroup/standalone test box (where there is no domain profile and a `-Profile Domain` rule would never be active).

---

## Loopback & least-exposure

- The **API, console, and IDE** communicate over `127.0.0.1:8765` by default. Loopback traffic is not firewalled and is never exposed to the network — keep it that way.
- The **only** sanctioned exception is a **remote console**, which requires deliberately binding the API to a routable NIC and fronting it with **TLS**. Do not open the API port otherwise.
- Prefer per-partner, program-scoped, address-scoped rules over broad ones. Each open port is PHI attack surface.

---

## Install-time vs runtime

Separate the **one-time install** from **steady-state operation**:

- **Install-time only (close afterward):** outbound HTTPS 443 to **`nssm.cc`** (NSSM download) and to **PyPI** (`pypi.org` / `files.pythonhosted.org`) for package install. These are the only two install-time openings and are marked 🔧 in the outbound table.
- **Steady state:** the per-connection inbound listeners, the per-partner outbound connections, and (if configured) AD/LDAPS and a remote store backend. No PyPI or `nssm.cc` access is required once installed.

---

## Verification checklist

After applying exclusions and firewall rules:

- [ ] **Service starts and stays running** — `Get-Service MessageFoundry` shows `Running`; `service.err.log` is clean of DPAPI/store/open errors.
- [ ] **API health on loopback** — `Invoke-WebRequest http://127.0.0.1:8765/health` succeeds **without** any inbound firewall rule (proves loopback needs none).
- [ ] **MLLP round-trip** — send a synthetic test message to a configured inbound port and confirm an `AA` ACK and a `PROCESSED` disposition.
- [ ] **DB sidecars intact** — `messagefoundry.db`, `messagefoundry.db-wal`, and `messagefoundry.db-shm` all present and untouched; no `-journal` file (expected — WAL mode).
- [ ] **Clean quarantine log** — AV/EDR quarantine history shows **no** MessageFoundry DB, sidecar, key/cert, `bootstrap-admin.txt`, or interpreter detections.
- [ ] **Outbound reaches partners** — a test delivery to each configured downstream succeeds, and each is covered by both a firewall rule **and** the matching `[egress]` allowlist entry.

---

## Keep it tight

Exclude the **specific files and processes** above — never a drive or a process tree. Open the **specific ports, programs, and remote addresses** above — never "any/any". Every exclusion and every open port is PHI attack surface, so the smallest set that makes the engine work is the correct set. Re-audit after every config change that adds a connection or a partner.
