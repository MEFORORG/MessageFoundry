# mefor-spawn-a-session

> Split out of [CLAUDE.md](../../CLAUDE.md) on 2026-09-05. Prohibitions that bind
> before this task starts stay in that file, which loads automatically. Read it first.

here. That page is the long form; this section is the short form and it binds.

This section replaced the pre-2026-09-01 method. The retired rules are not repeated here as
retractions. At least these went:

- plan, then wait for the owner's "go" before writing code, as a rule binding a Builder. It still
  binds the Console;
- the ultracode warn-and-offer gate, as a rule binding a Builder. It still binds the Console, for
  the same reason the planning gate does: the Console is the seat that can warn somebody and wait;
- `/clear` and `/compact` as the fix for a stuck session;
- declaring your own seat with `seat.ps1 -Declare`;
- routing owner questions through a Liaison.

Seven seats went with them: Dispatcher, Liaison, PM, Cleaner, Role Manager, Process Improvement,
ASVS Tracker. If a document you are reading names a retired seat or a retired rule, treat that
document as stale and follow this section.

The Console spawns a Builder where it holds the spawn permission, and that is per config root. The
grant is a rule matching `Bash(claude:*)` or `PowerShell(claude:*)` under `permissions.allow` in the
`settings.json` of the config root named by `CLAUDE_CONFIG_DIR`. Measured 2026-09-02:
`.claude-account-1` carries both and spawned one, exit 0 in 38.8 seconds; every root measured that
day without them was refused. Exit 0 alone does not prove the spawn worked, because a prompt
swallowed by a list-taking flag exits 0 too (see the spawn bullet below), so check what the child
did. On a root without the grant the owner starts each Builder. Nothing else in the roster spawns
one.

The brief is disposable. The BACKLOG item is the record.

Every notice is polled, and nothing is pushed. `stalled-prs.yml` reports green-but-unmergeable PRs on
a daily 07:05 UTC cron. `failure-signal.yml` adds a `ci-red` label to a PR whose required check went
red, and no workflow reads that label back. So the Console finds both by asking.


### A Builder gets one turn, and a brief that forgets this deadlocks it

1. The brief must hold for one turn. A Builder cannot ask and wait. It may mail a question, but the
   answer lands in the reader's next turn, not in its own. `mail.ps1` requires `-To` and refuses to
   guess, so the Console puts its own worktree path in the brief. Do not use `-To all`: that path
   spawns a nested process and may be refused. With no address, put the question in the PR body.
2. At least two kinds of refusal reach a Builder while it runs. Local git hooks fire at commit and
   push time; the live list is `.pre-commit-config.yaml`. The user-scope PreToolUse guards fire at
   tool-call time: `worktree_gate.ps1`, installed to `%USERPROFILE%\.claude\hooks\` by
   `scripts/worktree/install-gate.ps1`, and `collision_gate.ps1`, wired by
   `scripts/coord/install-coordination.ps1`, deny the Write, Edit or
   Bash call itself. CI arrives later, when the process is gone.
3. It runs the checks below **before** it commits, because nobody downstream can ask it to.
4. Its process exits when the PR opens. The worktree stays behind.
5. **It CAN declare its own seat, through the Bash tool.** Measured 2026-09-02: a headless `-p`
   Builder ran `seat.ps1 -Declare` and its record carries `seatSource: declared` with a real goal,
   which no hook can write. **Quote the Windows path.** Unquoted, the SHELL eats the backslashes:
   `echo C:\Temp\demo` prints `C:Tempdemo`, so `pwsh` reports the argument is not a
   script file, which reads as a missing script rather than a quoting bug. Measured 2026-09-02. This
   is ordinary POSIX quoting and is **not** BACKLOG #1397, which is the Bash tool unescaping inside
   a QUOTED heredoc.
   The **PowerShell tool** does refuse a nested `pwsh`, with `Command spawns a nested PowerShell
   process which cannot be validated`. That refusal belongs to one tool, not to the harness, and
   the Bash tool has no such check. **This line previously said a seat cannot declare itself.**
   That was wrong, and it was self-confirming: a Builder told it cannot declare does not try,
   renders undeclared, and confirms the rule. Two Builders on one root, 33 minutes apart: the
   second's brief asked it to declare and the first's did not, and only the second declared. They
   also differed in task, worktree and grant list, so that is the cause and not a controlled arm.
   A SessionStart hook (`scripts/hooks/seat-declare-prompt.ps1`) prints a line telling every
   starting session to declare. **Do not ignore it.** The Console should still supply seat and goal
   at spawn, because no hook will invent a goal, by design: a machine that invents one writes a
   record that looks declared and says nothing.

### The Console plans, spawns, and holds the owner's attention

- **Plan first, then spawn.** For anything past a trivial change the Console produces a plan and
  waits for the owner's explicit "go". Point the brief at the relevant existing code; it measurably
  improves the result.
- Prefer **ultracode** for substantive work. The keyword is session-only and opt-in, so the Console
  warns the owner up front and offers to re-send with it. You cannot switch it on yourself. This gate
  never applies to a Builder, which has no user to warn and exits without a reply.
- One brief per Builder. After about two failed attempts at the same problem, spawn a fresh Builder
  with a better brief rather than reuse a poisoned context. A Builder cannot do this. When you are
  stuck after two attempts, push what is green and say in the PR body that the brief needs re-cutting.
- Give each session its own git worktree (`scripts/worktree/new.ps1 -Name <x>`, cleanup with
  `remove.ps1`). Each gets an isolated checkout, branch and `.venv` on the same remote and the same
  PR flow. See [`docs/WORKTREES.md`](../../docs/WORKTREES.md). The AI project memory is shared across
  sessions, so coordinate memory writes.
