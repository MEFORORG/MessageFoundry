# 0212 -- EnterWorktree safety check

- **Status:** Accepted (2026-10-21, on build). The owner asked for it in session on 2026-10-21;
  the eight checks are the Manager's adversarially reviewed design, and the owner may overrule
  them at review.
- **Date:** 2026-10-21
- **Related:** ADR 0211 (the AFK kill switch this check reads); `scripts/hooks/worktree_gate.ps1`
  rule 4; CLAUDE.md section 5 (worktrees) and section 11 (SDS-3.7)

## Context

The owner is shown *"Allow Claude to use EnterWorktree? permission-root relocation"* each time a
session enters a throwaway worktree it made under its own scratchpad, for example
`%TEMP%\claude\D--Code-MessageFoundry\<session-uuid>\scratchpad\eng-main-569b`.
The owner asked, in session, for *"a way to check that the session is safe to enter the
worktree"*, and *"a way to safely disable this"*.

Entering a worktree moves the session's permission root. The prompt is the owner's chance to see
that the new root carries no hooks or permissions the session did not already have, that it is
the session's own, and that the move does not re-file the chat transcript.

## Decision

### 1. A read-only check, `scripts/worktree/enter-check.ps1`

It prints `SAFE` or `UNSAFE` and the reasons, and exits 0 only for SAFE. The verdict starts false
and is set by one statement at the end, and only when each of the eight checks recorded its own
pass by name. A check that throws, times out, or is skipped because an earlier one failed records
no pass. Every line it prints is folded through `Get-SafeForMessage`, parsed out of
`worktree_gate.ps1` at run time rather than copied, because a path and a git message are
attacker-choosable text.

SAFE requires all of these:

| Check | What it requires |
|---|---|
| a | The path canonicalises: full path, every junction and symlink along it resolved to its final target, every segment on disk under the name given. An 8.3 short name is refused, not expanded. A `\\?\`, `\\.\` or UNC path is refused. |
| b | It is a linked worktree, never a primary, listed by `git worktree list --porcelain -z` of a fleet repository (`D:/Code/MessageFoundry`, `D:/Code/MessageFoundry-vault`, `D:/Code/korus`), compared canonical to canonical. |
| c | It is under this session's own scratchpad, by segments: `<temp>\claude\<one segment>\<session id>\scratchpad\<more>`, the session id a uuid matched exactly at that position. `.claude/worktrees/` is never allowed: another session's subagent trees live there, and the session registry cannot see them. |
| d | The session's cwd is not in the primary checkout of a fleet repository. Relocating from a primary re-files the transcript, which is why `worktree_gate.ps1` rule 4 exists, so that case keeps its prompt. |
| e | The worktree is not locked, and its git dir shows no rebase, merge, cherry-pick, revert or bisect in progress. |
| f | Its HEAD's `.claude` and `.mcp.json` have the same object ids as `origin/main`'s, an absent path absent on both sides. Its working tree holds no modified, untracked or ignored file under either path, except the seat marker and the role card copy this repository's own hooks write. |
| g | `scripts/coord/afk-kill.ps1 -Status` prints `OFF`. Any other output, an error or a timeout fails. |
| h | No file exists at `<engine git common dir>/mefor-coord/enter-check/OFF`. |

### 2. A PreToolUse hook, `scripts/hooks/enter-worktree-check.ps1`

Wired in `.claude/settings.json` under matcher `EnterWorktree`, as an added entry. It reads the
hook input as UTF-8 bytes through `_hookinput.ps1`. With no `path` (a new worktree by `name`) or
no `cwd`, it says nothing. Otherwise it runs the check. On SAFE it returns
`permissionDecision: allow`. On anything else it returns no decision, so the owner's prompt shows
as before, with `additionalContext` saying why the call was not auto-allowed. **It never returns
`deny`**, and any fault returns no decision.

### 3. Three ways to disable it

- **Fleet-wide:** set the repository variable `MEFOR_AFK_KILL` to anything but `off` (check g).
- **This machine:** create the OFF file (check h), and delete it to turn the check back on:

      New-Item -ItemType File -Force -Path "$(git -C D:/Code/MessageFoundry rev-parse --path-format=absolute --git-common-dir)/mefor-coord/enter-check/OFF"

- **Permanently:** remove the `EnterWorktree` entry from `.claude/settings.json`.

Every disable leaves the prompt in place, which is the state before this ADR.

### 4. What it does not change

- If the opt-in `-EnterWorktreeGate` matcher of `worktree_gate.ps1` is installed, its rule 4 deny
  wins over this allow. That is intended.
- It does not change the workspace-trust prompt.
- A session-made worktree anywhere else, including `.claude/worktrees/`, still prompts.

## Consequences

- The owner is no longer asked about a session's own scratchpad worktree while the kill switch
  reads OFF. While it reads ON, which is also what an unset or unreadable variable reads, every
  EnterWorktree still prompts.
- The check costs about two seconds per EnterWorktree call, most of it the kill-switch read.
- Check f's working-tree half is stricter than the brief, which named only the HEAD tree. A
  `.claude/settings.local.json` left in the working tree would carry its own permissions and is
  invisible to a tree comparison.

## Rejected

- **Allowing `.claude/worktrees/`.** Another session's subagent trees live there, and nothing can
  tell whose a tree is.
- **Matching the scratchpad with `-like` and `*`.** A `*` matches a backslash, so a path with extra
  segments would pass.
- **A fail-open check**, in the pattern of `ErrorAction SilentlyContinue` with a default of allow.
  A check that could not run must cost a prompt, never grant one.
- **Returning `deny` on UNSAFE.** That would block an entry the owner might approve.
