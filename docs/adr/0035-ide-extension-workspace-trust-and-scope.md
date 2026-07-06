# 0035 — IDE extension: workspace-trust gating, machine-scoped promote targets, and fail-closed AI policy

- **Status:** Accepted  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-26
- **Related:** ADR 0007 (GUI-manageable connections.toml) · ADR 0024 (AI policy) · CLAUDE.md §9 (PHI/HIPAA), §10 (Console) · SEC-004, SEC-005, SEC-022

---

## Context

The VS Code extension (`ide/`) runs untrusted *workspace* content with the developer's privileges and
can reach an auth-required engine that carries PHI. CLAUDE.md §9 requires: *"On-premises by default: no
PHI leaves the local environment without explicit, reviewed configuration"* and *"every PHI access … is
audited with the acting user"*. Three gaps were found in a security review:

- **SEC-004 (CWE-426, untrusted search path).** `pythonPath()` auto-detected and *preferred* a
  workspace-local `.venv/Scripts/python.exe` (Windows) / `.venv/bin/python` (POSIX) over PATH, and the
  extension execs `python -m messagefoundry …` on activation and on every Python-file save. A cloned
  "starter config" repo could ship a trojaned `.venv` interpreter that runs on first open. The settings
  override was already blocked (`pythonPath` is machine-scoped) but the filesystem `.venv` probe was a
  parallel path that defeated that control. `package.json` declared **no** `untrustedWorkspaces`
  capability and there was no `vscode.workspace.isTrusted` gate anywhere.
- **SEC-005 (CWE-918, SSRF / credential exfil).** `messagefoundry.engineUrl` and
  `messagefoundry.environments` were window/resource-scoped, so a checked-in `.vscode/settings.json`
  could retarget Stage → Promote at an attacker host, which then receives a typed account password and
  the returned bearer token (`engineClient` uses plain http for `http:` URLs). Only `pythonPath` had
  been machine-scoped.
- **SEC-022 (CWE-636, fail-open).** `resolveAiPolicy()` fell back to `DEFAULT_POLICY = {mode:'byo',
  assistPermitted:null}` when the engine was unreachable, and `assistantState()` treats that as
  *enabled*. A user under a central `mode='off'` (or `ai:assist` deny) could re-enable the BYO
  assistant simply by stopping their local engine. (No PHI was ever at risk — `chat.ts` enforces the
  `code_only` cap unconditionally — but it defeats a governance control.)

## Decision

Harden the extension's trust posture in three coordinated ways, mirroring the existing machine-scope of
`pythonPath`:

1. **Workspace-trust gating (SEC-004).** Declare `capabilities.untrustedWorkspaces.supported =
   "limited"` so completion/snippets/chat still load read-only, and gate every CLI exec on trust. A
   new pure `resolvePythonPath()` only considers the workspace `.venv` when `isTrusted === true`; a new
   `isExecGated()` short-circuits `cli.run()`/`runJson()` (and the activation / save handlers) in an
   untrusted workspace so no workspace-supplied binary is ever launched.
2. **Machine-scoped promote targets + non-TLS refusal (SEC-005).** Mark `engineUrl` and
   `environments` `scope: "machine"` so a checked-in workspace settings file cannot retarget promote.
   A shared `engineTarget.ts` (`assertTargetAllowed`) refuses plain `http://` to a non-loopback host
   before any credential prompt or token send, and promote shows an explicit host-naming modal for an
   https off-box target. Loopback over http (the default `127.0.0.1` dev flow) is unchanged.
3. **Fail-closed offline AI policy (SEC-022).** Cache the last authoritative (engine) policy in
   `globalState`; when offline, return the cached policy, else a positively-returned CLI policy, else a
   new `mode:"unverified"` sentinel that `assistantState()` maps to disabled. The `code_only` cap in
   `chat.ts` is untouched.

This must **not** weaken any existing control: the loopback dev flow, the `code_only` PHI cap, and an
online-permitted BYO assistant all keep working.

## Acceptance Criteria

- **AC-1** — WHILE a workspace is untrusted, THE EXTENSION SHALL NOT prefer a workspace-local `.venv`
  interpreter and SHALL fall through to PATH `python`.
  → `ide/src/test/suite/pythonpath.test.ts`
- **AC-2** — IF a workspace is untrusted, THEN THE EXTENSION SHALL NOT exec the workspace Python CLI
  (validate/graph/codeset/promote disabled), declaring `untrustedWorkspaces.supported = "limited"`.
  → `ide/src/test/suite/settings-scope.test.ts`
- **AC-3** — THE EXTENSION SHALL treat `engineUrl` and `environments` as machine-scoped so a checked-in
  workspace settings file cannot retarget promote.
  → `ide/src/test/suite/settings-scope.test.ts`
- **AC-4** — IF a promote/login target is plain `http://` and the host is non-loopback, THEN THE
  EXTENSION SHALL refuse to send credentials and SHALL NOT prompt for them.
  → `ide/src/test/suite/engine-target.test.ts`
- **AC-5** — WHEN the engine is unreachable AND no cached authoritative policy exists AND the local CLI
  cannot confirm a policy, THE EXTENSION SHALL disable AI assistance ("could not be verified").
  → `ide/src/test/suite/ai-policy.test.ts`
- **AC-6** — WHEN the engine policy is read successfully, THE EXTENSION SHALL cache it so a
  previously-seen central "off" is not overridable by going offline.
  → `ide/src/test/suite/ai-policy.test.ts` (`pickOfflinePolicy` cached-wins case)

## Options considered

1. **`untrustedWorkspaces.supported = "limited"` + code gates** — keeps read-only features (completion,
   snippets, chat-without-CLI) working untrusted while disabling exec. **CHOSEN.**
2. **`supported: false`** — blocks the whole extension in untrusted workspaces. Rejected: strictly
   safer in isolation, but it kills harmless read-only UX; the code gates already provide the safety, so
   "limited" is the better trade. (Verified the cli.ts gate ships alongside, so "limited" is not weaker
   here.)

## Consequences

**Positive** — A cloned repo can no longer auto-run a trojaned `.venv` interpreter or silently retarget
promote to exfiltrate credentials; a central AI "off" survives the engine going offline. The fixes reuse
the patterns already in the codebase (machine scope, the loopback classifier), so the host enforces them
at the settings/trust layer.

**Negative / risks** — A team that legitimately committed `engineUrl`/`environments` into a repo's
`.vscode/settings.json` will find those ignored (promote targets are now a per-machine user setting). A
team running a remote engine over bare `http://` will be blocked (intended hardening — use https). The
off-box promote flow gains one host-naming confirmation modal. A brand-new install that has never reached
an engine and has no local `off` toml now shows assistance disabled ("could not verify") instead of
silently enabling BYO — the intended governance fix.

**Out of scope** — Remote/TLS engine exposure beyond loopback (tracked elsewhere); the `managed_claude`
provider path; any change to the `code_only` PHI cap (untouched).
