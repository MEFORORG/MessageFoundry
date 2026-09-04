# The worktree gate

**What it does in one line:** it stops a Claude Code session from *building* in the shared primary
checkout — mechanically, not by reminding you — while leaving reads, planning, and writes into any
worktree completely untouched.

It is opt-in, installed by hand, governs only the checkouts you list, and comes back out cleanly
(`settings.json` is restored byte-for-byte). See [Backing it out](#backing-it-out).

> This page is the gate's own design rationale. For the gate **in context** — the whole drift-control
> estate, which parts are actually installed and enforcing, and an audit of what they miss — see
> [SESSION-DRIFT-CONTROLS.md](SESSION-DRIFT-CONTROLS.md).

---

## Why it exists

MessageFoundry is developed with many concurrent Claude Code sessions against one repo.
[`docs/WORKTREES.md`](WORKTREES.md) already gives each session an isolated worktree
(`scripts\worktree\new.ps1`) and a `SessionStart` hook that **asks** a session in the primary checkout to
go create one.

Asking does not work. Measured over 30 days:

| Measurement | Value |
|---|---|
| Sessions whose cwd was the shared primary checkout | **166** |
| Their Edit/Write calls that landed **inside the primary's tree** | **6,075 (44%)** |
| Their Edit/Write calls that landed **inside a worktree**, by absolute path | **4,010 (29%)** |
| Response rate to the existing advisory `SessionStart` warning | **~0%** |

Two things follow, and they define the whole design.

**First, the warning is ignored, so the control has to be a gate rather than a message.** In the same
period, a working, one-command, dry-run-by-default cleanup script (`prune-merged.ps1`) — nagged in *every*
session — accumulated 12 stale worktrees. Advisory text has no measurable effect on this machine, on the
human or on the model.

**Second — and this is the part that is easy to get wrong — the gate must key on the write's TARGET PATH,
never on the session's cwd.** The worktree row of the table above is the 29%: those sessions already
write *correctly* into a worktree by absolute path, and a cwd-keyed gate would have denied all 4,010 of
them. Both percentages are shares of the same 166 sessions' Edit/Write calls, so the 29% and the 44%
are two numerators over one denominator rather than two measurements. Where a session *sits* is
irrelevant; only where it *writes* matters.

## What it blocks

Installed by [`scripts/worktree/install-gate.ps1`](../scripts/worktree/install-gate.ps1), the
[`PreToolUse`](https://code.claude.com/docs/en/hooks) hook
[`scripts/hooks/worktree_gate.ps1`](../scripts/hooks/worktree_gate.ps1) denies the following, and only
for the checkouts named in its allowlist:

1. **A `Write` / `Edit` / `MultiEdit` / `NotebookEdit` whose target path is inside the primary's working
   tree.** Paths are canonicalised with `GetFullPath()` first, so `..\MessageFoundry-x\..\MessageFoundry\`
   traversal cannot walk around the prefix check.

2. **A `Task` / `Agent` / `Workflow` dispatch made *from* the primary.** A subagent inherits the parent's
   cwd, cannot create a worktree for itself, and — measured — its blocked edits do **not** reliably surface
   back to the parent: the parent's result came back with an empty `permission_denials` list. A fan-out
   from the primary would therefore appear to succeed while writing nothing. Stopping the dispatch costs
   one second; letting it run costs the whole workflow.

3. **A git command that swaps the primary's working tree** — `checkout`, `switch`, `reset`, `restore`,
   `stash`, `clean`, `rebase`, `merge`, `cherry-pick`, `revert`, `am`, `apply`.

   This one is not hypothetical either. A sibling session ran `git checkout <its-branch>` **inside the
   shared primary** and then left HEAD detached, and every other session standing in that directory
   silently found itself reading a different commit's files. It is strictly worse than a stray write: a
   write dirties one file; a branch switch **replaces the entire working tree under everyone at once**.

   Rules 1 and 2 cannot see it — a git command is a **shell** call, not an `Edit`, so no amount of
   tool-argument inspection catches it. The rule is scoped tightly to verbs that change *which commit the
   tree reflects* or that *discard work*. Reads (`status`, `log`, `diff`, `show`, `fetch`, `branch`,
   `worktree`, `merge-base`, `merge-tree`, …) are untouched, and so are `add` / `commit` / `push` and a
   `pull --ff-only`. Within a linked worktree everything a worktree does to its *own* branch stays free —
   only switching it onto *another existing branch* is denied (rule 3b, next). It also catches
   `git -C <primary> checkout …` and `cd <primary> && git checkout …` from a session sitting elsewhere,
   which a cwd-only check would miss.

   To read another branch without touching any tree, the deny message points at the plumbing
   (`git show <ref>:<path>`, `git ls-tree`, `git diff <ref>..<ref>`). To *repair* a primary that is already
   detached or on the wrong branch — which an agent is still allowed to do — see below.

3b. **A git command that hijacks a *linked worktree* onto an already-existing branch** — `checkout <branch>`
   / `switch <branch>` in a worktree, where `<branch>` names a branch that already exists. This is the move
   that actually keeps happening: a session with no worktree of its own runs `git checkout <a-branch>`
   inside **someone else's** worktree, yanking that session's files onto a different branch mid-task. git
   permits it because its native guard only blocks a branch that is *already checked out somewhere* — a
   "free" branch can be grabbed by any worktree. Rule 3 protects only the shared primary; 3b protects every
   other governed worktree.

   Deliberately narrow: only a switch onto an **existing local branch** is denied. Creating a new branch
   (`-b` / `-c`), restoring files (`checkout -- <path>`), and `reset` / `rebase` / `merge` of the
   worktree's *own* branch stay allowed. The gate can't tell a worktree's rightful session from a squatter
   (both share the cwd), so it blocks the move for both; the rightful owner's escape hatch is a **plain
   terminal** (never gated) or a fresh worktree for the other branch (git then refuses the second checkout,
   which is the protection you wanted). This closes the gap the old rule left open — that a worktree "may
   switch its own branch freely."

**Everything else is allowed.** Reads are never gated — asking a question or planning in the primary stays
frictionless. Writes into any worktree, the scratchpad, or any other repo are allowed **from a session
sitting in the primary**: there is no need to `cd`, relocate, or restart. Worktrees that git nests *inside*
the primary's path (`.claude/worktrees/<name>/`, the first-party `claude --worktree` mechanism) are
recognised as worktrees, not as the primary.

## What happens when it fires

The deny message is written for the agent that receives it, and tells it how to proceed rather than merely
refusing. It offers: create a worktree with `new.ps1` and re-issue the write against an absolute path
inside it; or, if the primary is already dirty, move that work with `rescue.ps1`; or, failing both, stop
and escalate to the user in a fixed form of words. It also lists the worktrees that **already exist**, so a
retry reuses one instead of minting a fresh worktree every time.

Verified against live headless sessions running in `bypassPermissions` — where there is no permission
prompt to fall back on:

| Scenario | Result |
|---|---|
| Session in the primary edits a file **in the primary** | **Denied.** File unchanged; the session escalated to the user. |
| Same session (still cwd = primary) edits a file **in a worktree**, absolute path | **Allowed.** Write landed. |
| Session in the primary **dispatches a subagent** | **Denied.** |

## Rescuing work already in the primary

A gate that stops you when you are half-way through a change is infuriating, so
[`scripts/worktree/rescue.ps1`](../scripts/worktree/rescue.ps1) moves the work instead of asking you to
redo it:

```powershell
pwsh -NoProfile -File scripts\worktree\rescue.ps1 -Name <task>
```

It stashes the primary's changes (tracked **and** untracked), creates a worktree branched off the primary's
**current commit** — not `origin/main`, so the stash applies cleanly — and pops it there. If any step
fails, the work stays in `git stash list` and the script says so. Nothing is ever discarded.

## Repairing a primary that is already detached or on the wrong branch

Rule 3 denies a raw `git checkout` in the primary, so the gate would be a **trap** without a sanctioned way
back. An agent may **repair** the primary; it just may not **hijack** it:

```powershell
pwsh -NoProfile -File scripts\worktree\restore-primary.ps1
```

It re-attaches HEAD to the primary's home branch — `git config mefor.homeBranch`, else `main-current` if it
exists, else `main` — and **refuses if the tree is dirty**, pointing at `rescue.ps1` instead, because
re-attaching would otherwise drag someone's uncommitted work onto another branch. It passes the guard
because it is not a `git …` command string; that is deliberate, and it is also the guard's honest limit —
an agent determined to write its own checkout script could. This stops the accident, which is the thing
that actually happens.

## Installing

```powershell
# from a PLAIN pwsh terminal -- NOT from inside Claude Code
pwsh -NoProfile -File scripts\worktree\install-gate.ps1                 # add this repo
pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Repo <path>    # add some other checkout
pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Status
```

The installer **refuses to run when `$env:CLAUDECODE` is set**: a session that can install its own gate can
also remove it, so installation stays a human act. After installing, run `install-gate.ps1 -Status` to
confirm every config dir shows hook entries.

### The allowlist is merged, never replaced

An install **adds** the roots it was given to the roots `worktree-gate.repos.txt` already carries, keeps a
`.bak` of the previous list beside it, and prints every root it is about to stop governing. To govern
exactly the roots you name and drop the rest, say so:

```powershell
pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Repo <path> -ReplaceAllowlist
```

**Why the switch, rather than a note telling you to re-name every root each time** (BACKLOG #1375). The
write used to be a bare replace and `-Repo` defaults to **one** root, so a plain run from either of two
governed checkouts un-governed the other. Nothing anywhere reported it: a dropped root is simply absent
from the gate's roots list, so it matches no rule and the gate exits 0 on every tool call into that tree
with **nothing printed**. This is *not* the instant-off kill switch under [Backing it out](#backing-it-out),
which fires only when the allowlist holds no roots at all. One root is not zero, so the gate stayed **on**
and just stopped looking at the checkout you cared about, which reads exactly like the gate working.

Two structural choices worth understanding:

- **Every config dir, not just `~/.claude`.** The hook is registered into `~/.claude/settings.json` **and**
  every `~/.claude-account-<N>/settings.json` (the VS Code launchers that set `CLAUDE_CONFIG_DIR`) — that
  name shape **exactly**, anchored on a decimal N, because an unanchored `.claude-account-*` also matched
  `~/.claude-account-2.lock`, a directory the installer then wrote gate wiring into on every run while the
  wiring check read it back as evidence (BACKLOG #1024). `-Status` now enumerates `~/.claude*`
  independently of that predicate, so its audit cannot agree with the writer by construction, and it names
  any dir outside the wire set that still carries gate wiring. This mirrors
  what `install-selfheal.ps1` already does. This is not a detail: the gate originally wired only
  `~/.claude`, which left every account-N session **ungated** — and those are where the parallel VS Code
  chats run. A session under an ungoverned account then checked its own branch out inside another session's
  linked worktree (rule 3b's exact scenario) and the gate that would have blocked it simply wasn't there.
  Override the set with `-ConfigDir`. The gate **script** and its allowlist still live once, shared, under
  `~/.claude/hooks/`, referenced by absolute path from each account — one copy, one kill switch, all
  accounts. (User scope, not the repo's `.claude/settings.json`: a project-scoped hook is git-tracked, so it
  lives on **one branch** and would protect nothing in the other worktrees until each merged it.)

- **An installed copy, not a path into a working tree.** The registered command points at
  `~/.claude/hooks/worktree_gate.ps1`. If it pointed into a checkout, a `git checkout` would delete the
  script; a hook whose script is missing exits non-zero-but-not-2, which means **the tool call runs anyway,
  silently** — the gate would be off in every session with nothing to say so.

- **A SessionStart drift-detector backstop.** Because the gate is a guardrail (it inspects tool arguments,
  so a checkout routed through an indirect script slips past), `worktree-selfheal.ps1` — wired into *every*
  account already — also **warns** at session start when this session's own linked worktree has drifted off
  its recorded home branch (recorded by `new.ps1` at creation). Warn-only: it never switches a worktree
  under the session using it.

## Backing it out

Installing takes effect **immediately, in sessions that are already running** — verified: a live session's
next `Edit` into the primary was denied with no restart. Removing it is the same (below).

| Level | Command | Effect |
|---|---|---|
| **Instant off** | delete `~/.claude/hooks/worktree-gate.repos.txt` | Gate stops firing immediately, **including for sessions already running** — the allowlist is re-read on every invocation, so it does not matter whether Claude Code cached `settings.json` at session start. |
| **Full uninstall** | `install-gate.ps1 -Uninstall` | Removes both hook entries, the installed script, and the allowlist. Verified: `settings.json` returns **byte-for-byte identical** to its pre-install content, with all other hooks and settings intact, and zero leftover files. |
| **Safety net** | automatic | Every install writes `settings.json.bak` and validates the JSON before moving it into place, so a botched write cannot break hooks across every session at once. It also writes `worktree-gate.repos.txt.bak` and `worktree_gate.ps1.bak`. Three different files, three different `.bak`s: do not read one as evidence for another. |

Nothing lives in the repo or in `.git`. Merging this branch changes no behaviour by itself — the gate only
becomes real when someone runs the installer.

## Limits (stated plainly)

- **It is a guardrail, not a security boundary.** It inspects tool arguments, so a file written by a *shell
  command* (`Set-Content`, `python -c`, a redirect) is not seen. The backstop for that is a `pre-commit`
  hook in the shared `.git/hooks`, which inspects the staged **tree** rather than a tool call and therefore
  catches every write route — see [LEDGER-GATE.md](LEDGER-GATE.md). (Today it polices the ADR/BACKLOG
  number space; it is the seam any further commit-time rule should hang off.)
- **It does not stop one session writing into another session's worktree** by absolute path. That is the
  unavoidable price of keying on the target path, and the alternative (keying on cwd) is strictly worse.
- **It does not prevent merge conflicts** — and does not need to. The measured cross-session conflict rate
  in this repo is **zero** (28/28 merged branches and 6/6 in-flight pairs merge clean). This gate exists to
  stop concurrent sessions trampling one shared working tree, not to arbitrate merges.
- **It does not solve the shared number space** (two sessions both allocating "the next ADR number", which
  merges clean and silently corrupts the ledger). That is a real, separately-measured defect class and it
  needs an allocator, not a file gate.
