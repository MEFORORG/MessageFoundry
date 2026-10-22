# 0212 -- EnterWorktree safety check

- **Status:** Accepted (2026-10-21, on build; made advisory 2026-10-22). The owner asked for it
  in session on 2026-10-21. The checks are the Manager's adversarially reviewed design. After the
  third review pass, the Manager made the hook advisory (class B, 2026-10-22): it shows the
  verdict in the owner's prompt and never allows. The owner may overrule either at review.
- **Date:** 2026-10-21
- **Related:** `scripts/hooks/worktree_gate.ps1` rule 4; CLAUDE.md section 5 (worktrees) and
  section 11 (SDS-3.7)

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

It prints `SAFE` or `UNSAFE` and the reasons, and exits 0 for SAFE and 1 for UNSAFE. The verdict
starts false and is set by one statement at the end, and only when each of the six checks
recorded its own pass by name. A check that throws, times out, or is skipped because an earlier
one failed records no pass. The whole run is bounded by `-BudgetSeconds` (40 by default), which
caps every child process's own timeout, so the hook finishes inside its 60-second settings
timeout. Every line it prints is folded through `Get-SafeForMessage`, parsed out of
`worktree_gate.ps1` at run time rather than copied, because a path and a git message are
attacker-choosable text.

The verdict is advice. The check runs from the session's own tree, so the session can change
what it prints.

SAFE requires all of these:

| Check | What it requires |
|---|---|
| a | The path canonicalises: full path, every junction and symlink along it resolved to its final target, every segment on disk under the name given. An 8.3 short name is refused, not expanded. A `\\?\`, `\\.\`, UNC, relative, drive-relative (`C:x`) or root-relative (`\x`) path is refused, never joined to a directory, as is a colon inside a segment. |
| b | It is a linked worktree, never a primary, listed by `git worktree list --porcelain -z` of a fleet repository (`D:/Code/MessageFoundry`, `D:/Code/MessageFoundry-vault`, `D:/Code/korus`), compared canonical to canonical. |
| c | It is under this session's own scratchpad, by segments: `<temp>\claude\<one segment>\<session id>\scratchpad\<more>`, the session id a uuid matched exactly at that position. `.claude/worktrees/` is never allowed: another session's subagent trees live there, and the session registry cannot see them. The path given must already be canonical: one through a link is refused, because the session can repoint its own link after the check while the harness keeps the path it was given. |
| d | The session neither is nor was launched in the primary checkout of a fleet repository. Relocating from a primary re-files the transcript, which is why `worktree_gate.ps1` rule 4 exists, so that case keeps its prompt. A `cd` moves the hook input's `cwd`, so two reads: the `cwd`, and the project directory of `transcript_path`, which is where the transcript is filed. A slug maps a separator and a `-` alike, so only an exact match with a primary's slug counts; a launch in a primary's subdirectory is caught only while the session's cwd stays in that primary. The transcript's records are not read: measured on 2026-10-21, a desktop-app worktree session's first recorded `cwd` is the primary while its transcript is filed under the worktree's slug. |
| e | The worktree is not locked. Its `.git` file names its own admin dir under the repository's `worktrees/`, and that dir names it back, so a repointed `.git` cannot choose the state e and f read. That dir shows no rebase, merge, cherry-pick, revert, sequencer or bisect in progress. |
| f | Its HEAD is a commit of the remote's `main`: an ancestor of, or equal to, the commit `git ls-remote <pinned URL> refs/heads/main` names, read with no repository and no user or system config. Neither a local ref nor `origin` is the anchor: any session can move `origin/main` or shadow it with a branch or tag of that name, and can repoint `origin` (or add a `url.*.insteadOf`) in the clone's shared config. So every tracked file, settings, hook code and instructions alike, is one that merged. The clone's shared state may not stand in for an object either: replace refs and the commit-graph are turned off, an `info/grafts` file fails f, and the HEAD the verified admin dir names must be the commit git listed for the worktree, before and after the reads. Its working tree is HEAD byte for byte: no tracked path carries a `filter`, `ident` or `working-tree-encoding` attribute, whose rules `.git/info/attributes` and the shared config can set (a clean filter made an edited file hash as its HEAD blob, measured); every tracked file's on-disk hash equals its HEAD blob, because `git status` trusts a stat cache that a same-size edit with restored timestamps fools (measured); no index entry is flagged assume-unchanged or skip-worktree; nothing is modified or untracked; no ignored file sits under `.claude` or is a `.mcp.json`, `CLAUDE.md` or `CLAUDE.local.md`, at any depth and in any case; ignored means ignored by the tree's own `.gitignore` files, never by `info/exclude` or `core.excludesFile`; and the tree holds no symlink or submodule. The remote's `main` must already be fetched. |
When `<engine git common dir>/mefor-coord/enter-check/OFF` exists, the check runs none of these,
prints `OFF`, and exits 2.

### 2. A PreToolUse hook, `scripts/hooks/enter-worktree-check.ps1`

Wired in `.claude/settings.json` under matcher `EnterWorktree`, as an added entry. It reads the
hook input as UTF-8 bytes through `_hookinput.ps1`. With a `tool_name` other than
`EnterWorktree`, no `path` (a new worktree by `name`), any `tool_input` field besides `path`, or
no `cwd`, it says nothing. Otherwise it runs the check, passing `session_id`, `cwd` and
`transcript_path`.

**It never returns `allow`, and never `deny`.** On SAFE it returns `permissionDecision: ask` with a
`permissionDecisionReason` that starts `enter-check: SAFE` and says in one line what passed. On
UNSAFE it returns `ask` with a reason that starts `enter-check: UNSAFE` and gives the first three
reasons, folded onto one line, stripped of control and format characters, and bounded in length.
The Claude Code hooks reference (PreToolUse decision control, read 2026-10-22) says an `ask`
reason is *"shown to the user in the permission prompt"*. On the OFF file, a missing check, a
check that throws, or output that is not a verdict with its exit code, it returns no decision,
and the normal prompt shows unannotated.

### 3. Two ways to silence it

- **This machine:** create the OFF file, and delete it to turn the annotation back on:

      New-Item -ItemType File -Force -Path "$(git -C D:/Code/MessageFoundry rev-parse --path-format=absolute --git-common-dir)/mefor-coord/enter-check/OFF"

- **Permanently:** remove the `EnterWorktree` entry from `.claude/settings.json`.

The first build's fleet-wide disable, the AFK kill switch of ADR 0211 read as a check, is
dropped. It gated the allow, and there is no allow left to gate; reading it cost most of the
check's run time and a child process.

### 4. What it does not change

- If the opt-in `-EnterWorktreeGate` matcher of `worktree_gate.ps1` is installed, its rule 4 deny
  wins over this `ask`, as the hooks reference orders `deny` before `ask`. That is intended.
- It does not change the workspace-trust prompt.

## Consequences

- The owner still answers every EnterWorktree prompt by path. What changes is that the prompt
  carries the check's verdict and, on UNSAFE, its first reasons.
- **Auto-allow is deferred.** It may return only when the allow comes from an installed copy of
  the hook and the check outside every session-writable tree, and only if the owner wants it.
  The third review pass found at least ten ways a SAFE verdict could still name an unsafe
  worktree. Nine remain open, and each is a reason the verdict is advice:
  1. The hook and the check run from `${CLAUDE_PROJECT_DIR}`, the session's own tree, so a plain
     edit there changes the verdict. This is the root one.
  2. Check f trusts the clone's shared object database. A forged loose object, pack or
     multi-pack-index can stand in for a merged commit's trees.
  3. Check f accepts any ancestor of main, including old commits with fewer deny rules and guard
     hooks, and the intermediate commits of merged branches.
  4. `CLAUDE.md` files in directories above the worktree, which the harness loads, are not checked.
  5. An untracked `.gitignore` the session creates can hide untracked content from f's scans.
  6. f's instruction-file scan does not descend into a nested repository under an ignored
     directory.
  7. A junction replacing a tracked directory is read through, so f can pass while the junction
     can be repointed later.
  8. The vault's `main` requires no approval, so a commit of it is not evidence of review
     (SDS-3.7).
  9. `git status` can still run a clean filter for an index entry HEAD does not hold. The verdict
     is UNSAFE, but a command has already run.

  The tenth, a relative `-Path` joined to the session's cwd, is closed: check a refuses any path
  that is not fully qualified.
- The hooks reference says `ask` prompts the user, so where a permission rule or mode would
  otherwise have let a path-bearing EnterWorktree through, the hook can bring a prompt back. That
  case is not measured. With no `path`, nothing changes.
- The check costs a few seconds per EnterWorktree call with a path, most of it `git ls-remote`
  and hashing the tree. With no network, f fails and the prompt reads UNSAFE.
- Only a worktree at an untouched commit of `main` reads SAFE. A worktree on a branch, one a
  session has committed or edited in, one whose seat it declared (`.claude/seat.local.txt`), or
  one cut from a `main` newer than the clone's last fetch, reads UNSAFE.
- The verdict is a time-of-check reading. A process sharing the scratchpad, such as a subagent or
  a background task, could change the worktree between the check and the owner's answer.
- The fleet repositories are fixed paths, so on a clone anywhere else check b never passes and
  every verdict reads UNSAFE.
- The temp root is read as Node's `os.tmpdir()` reads it (TEMP before TMP on Windows), not as
  .NET's GetTempPath does. A TEMP spelled with an 8.3 short name fails check c.

## Rejected

- **Allowing `.claude/worktrees/`.** Another session's subagent trees live there, and nothing can
  tell whose a tree is.
- **Matching the scratchpad with `-like` and `*`.** A `*` matches a backslash, so a path with extra
  segments would pass.
- **A fail-open check**, in the pattern of `ErrorAction SilentlyContinue` with a default of SAFE.
  A check that could not run must never read SAFE.
- **Returning `allow` on SAFE**, the first build's design. The allow came from code the session
  can edit, and the third review found at least ten paths to a SAFE verdict on an unsafe
  worktree. Deferred, not dropped: see Consequences.
- **Returning `deny` on UNSAFE.** That would block an entry the owner might approve.
- **A list of protected paths in f**, the brief's design and the first build's. Each review round
  found a path it missed.
- **Reading the launch directory from the transcript's records.** A desktop-app worktree session
  records the primary there, so every such session would read UNSAFE.
- **Exempting the seat marker and role card copy from f.** `role-card-inject.ps1` reads them to
  choose the seat card it injects, so a planted one changes the session's instructions.
- **Reading main from `origin`**, as review round 2 did. The clone's config names `origin`, and any session can write that config.
- **Naming the OFF file's path** in a reason. The reason can reach the model, in a `-p` run where
  no one answers the prompt.
