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
| a | The path canonicalises: full path, every junction and symlink along it resolved to its final target, every segment on disk under the name given. An 8.3 short name is refused, not expanded. A `\\?\`, `\\.\`, UNC, drive-relative (`C:x`) or root-relative (`\x`) path is refused, as is a colon inside a segment. |
| b | It is a linked worktree, never a primary, listed by `git worktree list --porcelain -z` of a fleet repository (`D:/Code/MessageFoundry`, `D:/Code/MessageFoundry-vault`, `D:/Code/korus`), compared canonical to canonical. |
| c | It is under this session's own scratchpad, by segments: `<temp>\claude\<one segment>\<session id>\scratchpad\<more>`, the session id a uuid matched exactly at that position. `.claude/worktrees/` is never allowed: another session's subagent trees live there, and the session registry cannot see them. |
| d | The session neither is nor was launched in the primary checkout of a fleet repository. Relocating from a primary re-files the transcript, which is why `worktree_gate.ps1` rule 4 exists, so that case keeps its prompt. A `cd` moves the hook input's `cwd`, so two reads: the `cwd`, and the project directory of `transcript_path`, which is where the transcript is filed. A slug maps a separator and a `-` alike, so only an exact match with a primary's slug counts; a launch in a primary's subdirectory is caught only while the session's cwd stays in that primary. The transcript's records are not read: measured on 2026-10-21, a desktop-app worktree session's first recorded `cwd` is the primary while its transcript is filed under the worktree's slug. |
| e | The worktree is not locked. Its `.git` file names its own admin dir under the repository's `worktrees/`, and that dir names it back, so a repointed `.git` cannot choose the state e and f read. That dir shows no rebase, merge, cherry-pick, revert, sequencer or bisect in progress. |
| f | Its HEAD is a commit of the remote's `main`: an ancestor of, or equal to, the commit `git ls-remote origin refs/heads/main` names. A local ref is never the anchor, because any session can move `origin/main`, or shadow it with a branch or tag of that name. So every tracked file, settings, hook code and instructions alike, is one that merged. Its working tree is HEAD byte for byte: every tracked file's on-disk hash, through git's own filters, equals its HEAD blob, because `git status` trusts a stat cache that a same-size edit with restored timestamps fools (measured); no index entry is flagged assume-unchanged or skip-worktree; nothing is modified or untracked; no ignored file sits under `.claude` or is a `.mcp.json`, `CLAUDE.md` or `CLAUDE.local.md`, at any depth; and the tree holds no symlink or submodule. The remote's `main` must already be fetched. |
| g | `scripts/coord/afk-kill.ps1 -Status` prints `OFF`. Any other output, an error or a timeout fails. |
| h | No file exists at `<engine git common dir>/mefor-coord/enter-check/OFF`. |

### 2. A PreToolUse hook, `scripts/hooks/enter-worktree-check.ps1`

Wired in `.claude/settings.json` under matcher `EnterWorktree`, as an added entry. It reads the
hook input as UTF-8 bytes through `_hookinput.ps1`. With a `tool_name` other than
`EnterWorktree`, no `path` (a new worktree by `name`) or no `cwd`, it says nothing. Otherwise it
runs the check, passing `session_id`, `cwd` and `transcript_path`. On SAFE it returns
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
- Checks a, d, e and f are stricter than the brief, after two review rounds. The brief's f
  compared `.claude` and `.mcp.json` against `origin/main`. Review showed a list of protected paths
  keeps missing one: the hook runs `scripts/worktree/enter-check.ps1` itself, the role cards and
  `CLAUDE.md` feed the session's instructions, and a local `origin/main` can be forged. So f now
  requires a merged commit and a byte-exact working tree.
- Only a worktree at a commit of `main`, untouched, is auto-allowed. A worktree on a branch, one a
  session has committed or edited in, one whose seat it declared (`.claude/seat.local.txt`), or
  one cut from a `main` newer than the clone's last fetch, prompts.
- The check reads the remote once per call (`git ls-remote`), so with no network every
  EnterWorktree prompts.
- The allow is a time-of-check decision. A process sharing the scratchpad, such as a subagent or
  a background task, could change the worktree between the check and the harness entering it.
- The fleet repositories are fixed paths, as the brief set them, so on a clone anywhere else check
  b never passes and the feature is inert there, which costs a prompt and nothing else.
- The temp root is read as Node's `os.tmpdir()` reads it (TEMP before TMP on Windows), not as
  .NET's GetTempPath does. A TEMP spelled with an 8.3 short name fails check c.

## Rejected

- **Allowing `.claude/worktrees/`.** Another session's subagent trees live there, and nothing can
  tell whose a tree is.
- **Matching the scratchpad with `-like` and `*`.** A `*` matches a backslash, so a path with extra
  segments would pass.
- **A fail-open check**, in the pattern of `ErrorAction SilentlyContinue` with a default of allow.
  A check that could not run must cost a prompt, never grant one.
- **Returning `deny` on UNSAFE.** That would block an entry the owner might approve.
- **A list of protected paths in f**, the brief's design and the first build's. Each review round
  found a path it missed.
- **Reading the launch directory from the transcript's records.** A desktop-app worktree session
  records the primary there, so every such session would prompt.
- **Exempting the seat marker and role card copy from f.** `role-card-inject.ps1` reads them to
  choose the seat card it injects, so a planted one changes the session's instructions.
- **Telling the session how to turn the kill switch off** in the UNSAFE reason. Only the owner sets
  it, and the reason reaches the model.
