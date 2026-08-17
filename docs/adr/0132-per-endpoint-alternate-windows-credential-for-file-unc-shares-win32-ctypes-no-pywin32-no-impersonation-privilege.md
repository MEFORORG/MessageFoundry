# ADR 0132 — Per-endpoint alternate Windows credential for File/UNC shares (win32 ctypes, no pywin32, no impersonation privilege)

- **Status:** **Accepted (2026-07-18, owner go).** DEMAND-GATE-BACKLOG Wave 4 / S3b. Built in the same
  change. `0132` was allocated atomically (`scripts/coord/alloc.ps1`); its index row is added to
  [README.md](README.md) in the same commit. Ratified before the code it governs.
- **Decision in one line:** a **File** endpoint may authenticate to a local/UNC (SMB) share under a
  Windows identity **distinct from the engine service account** — configured per-endpoint
  (`credential_username` / `credential_domain` / `credential_password`, the password via `env()` only)
  — established with **win32 ctypes** `LogonUser` + per-thread `ImpersonateLoggedOnUser` (**no pywin32,
  no privilege**), with the connector's blocking filesystem I/O run on a **dedicated impersonated
  thread**; **win32-only** (a non-Windows host fails loud, never a silent no-op).
- **Backlog:** [BACKLOG #111](../archive/backlog/BACKLOG-CLOSED.md#111-file-endpoint-alternate-windows--network-share-credentials). Corepoint-parity gap: the File connector today reads/writes
  local/UNC paths **only** under the engine service account's ambient token, and
  [`transports/remotefile.py`](../../messagefoundry/transports/remotefile.py)'s username/password auth
  covers **FTP/FTPS/SFTP**, not SMB/UNC Windows-share credentials.
- **Related:**
  - [ADR 0113](0113-windows-tray-service-manager-stdlib-ctypes-tokenless.md) — the **ctypes-not-pywin32**
    precedent this follows: the tray package + [`tray/winsvc.py`](../../messagefoundry/tray/winsvc.py)
    (`ctypes.WinDLL('advapi32', use_last_error=True)` + `ctypes.wintypes`, `sys.platform`-guarded) and
    [`service.py`](../../messagefoundry/service.py) (`ctypes.windll.shell32.ShellExecuteW` at
    `service.py:124` / `service.py:270`). All present on this branch; no new dependency is added.
  - [ADR 0129](0129-process-in-place-file-disposition-and-cross-backend-processed-file-dedup-ledger.md)
    (#142) + the [ADR 0031](0031-startup-connection-fault-isolation.md) #114 amendment — the S3a File
    disposition/validation work this **wraps**: the credential context brackets `_scan_once` /
    `validate_startup` / `_probe_dir_startup` / the `after_read='leave'` path / `_file_key` / the dedup
    ledger reads, so the whole poll cycle runs under the endpoint's identity.
  - [ADR 0001](0001-staged-pipeline-architecture.md) — the **count-and-log** + **never block the loop**
    invariants: a credential/logon failure is a logged `ERROR`/retry (never a connection crash, never an
    accept-and-drop), and the blocking win32 I/O runs off the event loop.
  - [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) — the PHI-hop
    posture work; this ADR **expands the PHI-access surface** (message files on a UNC share read/written
    under a new identity, plus a credential secret handled) and is treated accordingly (§4).

## Context

A File connection accesses local/UNC paths only under the **engine service account's ambient Windows
identity**. For most deployments, granting that service account share access is a clean workaround. But a
site that **isolates share access per-feed** — a distinct AD service principal per partner, so a
compromise of one feed's credential can't reach another partner's share — has no way to express that: the
File connector carries no per-endpoint credential, and `remotefile.py`'s credentials are FTP/FTPS/SFTP
only, not SMB/UNC.

Establishing an alternate Windows identity for network-share access has two classic mechanisms:

1. **`WNetAddConnection2W`** — map the share (`\\host\share`) under alternate credentials. The mapping is
   **process-wide**: two File connections that map the *same* host under *different* credentials
   **collide** (Windows keys a connection per remote server, per session). Detecting/serialising that is
   fragile, and a leaked mapping outlives the connection.
2. **`LogonUser` + `ImpersonateLoggedOnUser`** — get a token for the alternate identity and impersonate
   it **on the current thread**. Per-thread, so two connections never collide; but impersonation is a
   **thread-local** property, so the blocking I/O must run on a thread we own and impersonate — never the
   shared asyncio loop thread, and never the shared `asyncio.to_thread` pool (where the impersonation
   would leak to unrelated tasks).

The privilege question decides feasibility: an interactive/batch `LogonUser` needs `SeTcbPrivilege`, and
impersonating an arbitrary token needs `SeImpersonatePrivilege` — neither of which a plain service
account reliably has. But the logon type **`LOGON32_LOGON_NEW_CREDENTIALS`** (9, with provider
`WINNT50`) authenticates **outbound network hops only** (exactly the SMB case) and produces a token its
creator can impersonate **without any privilege**. That is the seam #111 needs.

## Decision

### §1 Per-endpoint credential model — `env()`-only password

The `File(...)` factory gains three optional settings — `credential_username`, `credential_domain`
(optional; omit for a `DOMAIN\user` or `user@domain` UPN), and `credential_password`. A new
[`WindowsCredential`](../../messagefoundry/config/models.py) sub-model (`extra='forbid'`, non-empty
username/password) is assembled from these flat `credential_*` settings via `from_settings` (mirroring
`OutboundSigning.from_settings`), so each value stays a **top-level** setting that `env()` resolution and
`connections.toml` decoding already handle (a nested table would not resolve `env()`).

The password is a **secret**: the factory **rejects an inline literal** — `credential_password` **must**
be an `env()` reference, with no `default=`/`cast=` (mirroring the SOAP `body_secrets` rule) — so a
fallback secret can never slip into source/config. `credential_username` and `credential_password` are
registered in `_SECRET_SETTING_KEYS`, so both are redacted in the `/metadata` and `graph --json` settings
views (`credential_domain`, a non-secret AD domain name, is not). Setting `credential_username` without
`credential_password` is a load error.

### §2 The credential context — `LogonUser` + per-thread impersonation, dedicated thread

A new **win32 util**, [`transports/wincred.py`](../../messagefoundry/transports/wincred.py), owns the
ctypes. It calls `advapi32.LogonUserW(user, domain, password, LOGON32_LOGON_NEW_CREDENTIALS,
LOGON32_PROVIDER_WINNT50, &token)`, then `ImpersonateLoggedOnUser(token)` / `RevertToSelf()` /
`CloseHandle(token)`. Every DLL call is gated behind an early `sys.platform != "win32"` check (so mypy
narrows to the win32 typeshed and the module type-checks on a non-Windows host too), using
`ctypes.WinDLL('advapi32', use_last_error=True)` — **the exact pattern already in `tray/winsvc.py`** — so
**no pywin32** is introduced.

`CredentialContext` owns a **dedicated single-worker thread** (a `ThreadPoolExecutor(max_workers=1)`).
Each call is bracketed on that thread: **`LogonUser → ImpersonateLoggedOnUser → fn() → RevertToSelf →
CloseHandle`**. The token is created and closed **inside one call**, so:

- the blocking I/O never runs on the event loop (it runs on the dedicated thread, awaited via
  `run_in_executor`);
- the impersonation never leaks to the shared `asyncio.to_thread` pool (it is on a thread this context
  exclusively owns);
- **nothing persists to leak across a reload** — there is no long-lived token or share mapping; `close()`
  only has to shut the worker thread down (off the event loop), which it does on the source's `stop()`
  and the destination's `aclose()`.

`WNetAddConnection2W` is **rejected** for its process-wide collision surface; the per-thread token is the
chosen mechanism.

### §3 Wrapping the S3a disposition/validation logic

The File connectors route **every** filesystem touch through a single `_run_fs(fn, *args, **kwargs)`
helper: under a configured credential it dispatches to `CredentialContext.run` (the impersonated thread),
otherwise to `asyncio.to_thread` (**byte-identical** to before #111). `_run_fs` therefore **wraps the S3a
work rather than bypassing it** — the same `_scan_once` (candidate listing, `_file_key` stat, oversize
`stat`, `read_bytes`, `_move`, `_after_processing`), the same `validate_startup` → `_probe_dir_startup`
(the `#114` opt-in startup probe, including the `after_read='leave'` read-only-share path), and the
`start()` subdir creation all run under the endpoint's identity. The dedup-ledger **hash + store reads**
(#142) are unchanged (the hashed key crosses the runner-injected `ProcessedFileLedger` seam as before).

**One deliberate exception:** the pre-ingest **scan hook** (`scan_inbound_file`) runs on the **shared
pool**, *not* under the share credential — it operates on already-read bytes and may itself dial an
AV/ICAP service, so impersonating the SMB identity for that unrelated call would be wrong.

### §4 Win32-only, PHI & failure behaviour

- **Win32-only, loud.** Constructing a File connector with a credential on a non-Windows host raises
  `CredentialUnsupportedError` (a `ValueError`) at build — a clear message telling the operator to remove
  the settings or run on Windows — **never a silent no-op**. This is the one path CI can exercise (a real
  alt-credential UNC share cannot be stood up on a hosted runner), so it is fully unit-tested; the live
  Windows path is a **Windows-CI / manual** gate.
- **Secret handling.** The password lives only in memory for the connector's lifetime and is **never
  logged**; a logon/impersonation failure carries the **Win32 error code only** (never the username,
  domain, or password). Any host:path logging reuses the existing redaction discipline (no payload
  bodies at INFO+).
- **Failure = logged `ERROR`/retry, never a crash.** `CredentialLogonError` is an **`OSError`**, so a bad
  credential rides the connectors' existing `except OSError` paths: a destination maps it to
  `DeliveryError` (retry/dead-letter), a source's `validate_startup` to `SourceStartupError` (the
  connection is isolated `failed` per ADR 0031), and a poll scan logs-and-retries (never a connection
  crash, never an accept-and-drop — the count-and-log invariant holds).

### §5 The credentialed endpoint tester

A **disjoint** API route, `POST /connections/{name}/test-credential`
([`api/app.py`](../../messagefoundry/api/app.py)), probes a File endpoint's reachability **under its
configured alternate credential** — the "credentialed endpoint tester" #111 asks for. It reuses the same
RBAC (`connections:test`), pacing, and fresh-connector `_run_connection_test` probe as
`POST /connections/{name}/test` (the probe dials the share under the impersonated identity, sending no
real data), but **400s** unless the connection is a File endpoint with a `credential_*` identity
configured, so an operator wiring the share gets a *targeted* answer. Audited as
`connection_credential_test`.

## Consequences

- **Per-feed share isolation is now a first-class File capability** on Windows — no blanket
  service-account grant, no external mount workaround.
- **Additive, default-off, byte-identical when unused.** A File connection without `credential_*`
  settings is unchanged (same `asyncio.to_thread` path); no store/schema change, no new dependency
  (stdlib ctypes only).
- **New PHI-access + secret surface**, treated per §4: env()-only password, redacted in every settings
  view, never logged; the impersonated I/O reads/writes PHI files under a distinct audited identity.
- **Windows-only feature with a tested clean failure off Windows.** The live path is a Windows-CI/manual
  gate; the non-Windows refusal and the config/redaction/wiring behaviour are unit-tested everywhere.

## Options considered

1. **`WNetAddConnection2W` share mapping (rejected).** Process-wide; two connections to the same host
   under different credentials collide, and a leaked mapping outlives the connection.
2. **`LogonUser` + per-thread impersonation on a dedicated thread (chosen).** Per-connection isolation,
   no privilege required (`LOGON32_LOGON_NEW_CREDENTIALS`), per-call token so nothing leaks across a
   reload, and the blocking I/O stays off the event loop and off the shared pool.
3. **pywin32 (`win32security`) (rejected).** A large new native dependency for what four `advapi32`
   calls do; the tree already establishes the ctypes-not-pywin32 precedent (ADR 0113).
4. **Grant the engine service account access to every share (status quo workaround).** Coarse — no
   per-endpoint isolation — which is exactly the gap #111 files.
