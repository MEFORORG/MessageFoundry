# ADR 0036 — Windows config-source trust (in-process NTFS-DACL check, not a documented-only ACL)

- **Status:** **Accepted (2026-06-26).** Built in the same change (SEC-003). Renumbered `0034` → `0036`
  after a concurrent branch landed its own `0034` (static-analysis triage, #567) and `0035` was taken by
  the IDE-trust ADR — `0036` is the next free number (see [README.md](README.md)).
- **Built:** yes — [`_assert_safe_config_source`](../../messagefoundry/config/wiring.py) now dispatches
  to a real Windows check (`_assert_safe_config_source_windows` + the pure `_evaluate_config_dacl`
  policy) instead of an unconditional early-return; [`install-service.ps1`](../../scripts/service/install-service.ps1)
  gains an opt-in `-LockConfigDir` switch + an always-on WARNING when the config dir is not locked.

## Context

`load_config()` / `validate_config()` execute **every** `*.py` in the `--config` directory in-process
as the engine service account (`_exec_module → spec.loader.exec_module`). The directory is the trust
boundary: anyone who can write a `.py` there runs code as the service (which holds PHI + DB
credentials). The only source-trust control, `_assert_safe_config_source`, robustly rejected
group/world-writable and foreign-owned files on POSIX — but **hard-returned on Windows** (`os.name !=
"posix"`), performing **zero checks**. Windows is the documented primary deployment target (CLAUDE.md
§2, NSSM), so the control was a silent no-op on the platform that matters most (SEC-003, CWE-732).

Corroborating: the automated installer hardens the **data** dir with `/inheritance:r` but
`Set-ConfigReadAcl` is deliberately **additive** (no `/inheritance:r`), so inherited write/modify ACEs
on the config dir survive — the config-dir lockdown was a manual operator step, and there was no
startup signal that the guard was unenforced. A low-privileged local user with an inherited write ACE
could drop/rewrite a config module that executes as the service account on the next start or
`/config/reload` — a local privilege-escalation / code-execution into the PHI-bearing identity.

## Decision

1. **Do a real in-process Windows DACL/owner check** (parity with POSIX), not documented-delegation.
   On Windows the loader resolves the owner + DACL of the directory **and each `*.py`** (incl. `_*.py`
   helpers — same candidate set as POSIX) and **refuses** to load when any ALLOWED ACE grants a
   **write-class** right (`FILE_WRITE_DATA`/`APPEND`/`WRITE_EA`/`WRITE_ATTRIBUTES`, `DELETE`,
   `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE`, `GENERIC_ALL`) to a rejected principal. **Rejected**
   principals: Everyone (`S-1-1-0`), Authenticated Users (`S-1-5-11`), `BUILTIN\Users` (`S-1-5-32-545`),
   INTERACTIVE (`S-1-5-4`), Anonymous (`S-1-5-7`), **or any SID that is not the file owner, not the
   current process user, and not SYSTEM (`S-1-5-18`) / Administrators (`S-1-5-32-544`)**. Read/execute
   ACEs (e.g. a repo checkout's `Users:RX`) carry no write bits and **pass** — that is why the mask
   filters to write-class rights only. A **NULL/absent DACL** (everyone implicitly allowed) is
   **refused**.

2. **ctypes, not a new pywin32 dependency.** The DACL parse uses `ctypes`/`advapi32`
   (`GetNamedSecurityInfoW`, `GetAce`, `ConvertSidToStringSidW`, `OpenProcessToken` +
   `GetTokenInformation`), behind a `sys.platform == "win32"` guard so mypy/lint pass on the Linux CI
   leg (mirrors [`secrets_dpapi.py`](../../messagefoundry/secrets_dpapi.py) and
   [`console/service_control.py`](../../messagefoundry/console/service_control.py)). This keeps the
   DEP-1 / pip-audit surface flat — **no new runtime dependency**.

3. **Fail OPEN with a loud WARNING on a Win32 API *error*** (not a policy decision). A
   `GetNamedSecurityInfoW`/`GetAce` failure must **not brick a previously-working service** — the guard
   logs a `WARNING` (the config-dir ACL could not be evaluated; verify it manually) and **proceeds**,
   so the worst case is "no worse than the old no-op". A WARNING about an *unevaluable* guard means
   "fix/lock the config-dir ACL", not "ignore it". An *observed insecure ACL* (rejected principal, or a
   NULL DACL) is a **refusal**, not a warning.

4. **Installer `-LockConfigDir` (opt-in) + always-on WARNING.** `install-service.ps1` gains
   `-LockConfigDir`, which runs `icacls <Config> /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F'
   '*S-1-5-32-544:(OI)(CI)F' '<account>:(OI)(CI)RX'` — stripping inherited (incl. low-priv write) ACEs
   and matching the runtime guard's expectation. It is **opt-in** because the config dir commonly lives
   inside a developer's repo where stripping inheritance is surprising. When the switch is **not**
   passed, the installer prints an always-on WARNING that the dir still inherits its parent ACL and the
   in-process guard will refuse to load if a low-privileged principal has write, pointing at
   `docs/SERVICE.md` and `-LockConfigDir`.

5. **SEC-019 (CWE-427), folded in.** `_SiblingHelperFinder` (inserted at `sys.meta_path[0]` during a
   load) is now restricted to the documented `_`-prefixed helper convention: `find_spec` returns
   `None` for any top-level name not starting with `_`. A config-dir file named after a real
   stdlib/installed module (`os.py`, `json.py`, `ssl.py`, `requests.py` — none start with `_`) can no
   longer shadow that module for the duration of the load. No allow-set / `find_spec`-elsewhere probe is
   needed: every legitimate sibling helper is `_`-prefixed and no stdlib/installed top-level module is.

## Alternatives considered

- **Keep the documented-delegation status quo** (no-op + install-time ACL). Rejected: Windows is the
  primary target, the installer does not lock the config dir, and there was no signal the guard was
  inactive — a realistic installer-driven precondition for local privesc.
- **Add `pywin32`.** Rejected: a new runtime dependency widens the DEP-1 / pip-audit surface for a
  check the stdlib `ctypes` pattern (already used twice in this codebase) covers.
- **Fail closed on any API error.** Rejected: a transient/edge `GetNamedSecurityInfoW` failure would
  brick a service that started fine before this change — strictly worse than today. Fail-open-with-
  WARNING bounds the worst case to the prior behavior.

## Consequences

- Windows installs now get real config-source trust enforcement; a foreign-writable config dir/module
  is **refused at load**, not merely discouraged. Operators who relied on an inherited-write config dir
  must lock it (`-LockConfigDir`, or point `-Config` at an admin-owned dir).
- A too-strict check could refuse a legitimate dir; mitigated by (a) the write-class mask (read/execute
  passes), (b) trusting owner + current user + admin/SYSTEM, and (c) fail-open-on-API-error.
- **Dev/CI escape (fail-closed by default).** A default Windows checkout grants `BUILTIN\Users` write
  (the runner workspace and most dev trees), so the guard would refuse every config load outside a
  locked-down install. `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE` (off by default) downgrades the refusal to a
  loud WARNING for a user-writable dev/CI checkout — symmetric with the POSIX guard and mirroring
  `MEFOR_ALLOW_INSECURE_TLS`. It is **never set in production** (the installer locks the dir, so the
  guard never trips there); the test suite sets it only on win32, and the guard's own refusal test pins
  it back OFF. See `insecure_config_source_allowed()` in `config/settings.py`.
- `docs/SERVICE.md` "Lock down the config directory" is updated to say the guard is now actively
  enforced and to document `-LockConfigDir`.

## Related

- [CLAUDE.md](../../CLAUDE.md) §2 (Windows/NSSM primary deployment, the engine runs least-privilege),
  §9 (PHI guardrails — the service account holds PHI + DB credentials).
- [`secrets_dpapi.py`](../../messagefoundry/secrets_dpapi.py) /
  [`console/service_control.py`](../../messagefoundry/console/service_control.py) — the established
  `ctypes`-behind-`sys.platform` Win32 pattern reused here.
- [docs/SERVICE.md](../SERVICE.md) "Lock down the config directory (CONFIG-2)".
