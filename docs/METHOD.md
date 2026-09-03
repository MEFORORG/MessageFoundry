# The method: how a session works here

**Read this first if you were spawned to build something.** Your brief says what to build. This page
says what you are, what will refuse you, and what outlives your process.

The brief dies with your session. The BACKLOG item is the record. This page is the standing
explanation that neither of those carries.

---

## The KORUS seats, and only these

KORUS stands for Keep One Repo, Unblock Sessions, and it is the name of this method. That expansion
is defined here and nowhere else, so other pages point at this line rather than repeat it.

| Seat | Lives how long | What it does |
|---|---|---|
| Console | Long-lived | The only seat the owner talks to. Reads the record and writes a brief citing an item, then polls. The record is two ledgers: `docs/BACKLOG.md` here, and the `wshallwshall/claude-multisession` issues that track KORUS itself. Nothing pushes to it. |
| Builder | One brief, then exits | Works, commits, pushes, opens the PR, and stops. That is you, most of the time. |
| Reviewer | Spawned per PR | Runs quality checks on the diff. A pass adds the `reviewed` label and posts the head SHA it read. A fail posts findings on the PR, for whichever Builder the Console spawns next. |
| Regulator | Spawned on a red | Decides whose failure a red belongs to: the PR's, main's, a flake, or the queue's. Only a PR's own failure comes back to a Builder. |
| Steward | A cron, no model calls | Reads account usage and names the account with headroom. It cannot interrupt a running session. |
| Lander | Standing authority | Merges. |

**Whether a session can spawn a session depends on its account, and it turns on one grant.** Check
your own root: in the `settings.json` of the config root named by `CLAUDE_CONFIG_DIR`, look under
`permissions.allow` for a rule matching `Bash(claude:*)` or `PowerShell(claude:*)`. A root that
carries the grant starts its own Builders. A root without it leaves every Builder for the owner to
start by hand. Key this on the grant, not on which account you are: a root that gains the grant
later is served wrongly by a rule written about identity.

Measured 2026-09-02: `.claude-account-1` carries both rules and spawned a Builder, exit 0 in 38.8
seconds. Every root measured that day without them was refused by the classifier. Read that exit
code as weak evidence rather than proof. A prompt swallowed by a list-taking flag also exits 0, so
confirm the child did the work instead of trusting the code.

**Confirmed by a second run, because the first could not tell the two apart.** The child was given
a one-time token and told to write it to a named file. It never wrote the file, because the path
sat outside its own scratchpad and it lacked the grant. But its reply quoted the token and the
path back. A swallowed prompt cannot echo a token it never received, so the spawn reached the
child, and the failed write is a separate and smaller problem. **Prove a spawn by something the
child produced, never by its exit code.**

Do not write a count of config roots into this page. Roots get added, and a count goes stale without
saying so. `pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Status` discovers roots by
name pattern and prints `Roots examined: <n>` with a line per root, so enumerate them there and read
each root's own `settings.json` for the grant.

Seven seats were retired by owner decision on 2026-09-01: Dispatcher, Liaison, PM, Cleaner, Role
Manager, Process Improvement and ASVS Tracker. If a document names one, that document is stale.

Three rules went with those seats, and they are not repeated anywhere. Routing an owner question
through the Liaison is retired. Getting owner approval before your own push is retired. Falling back
to the Lander when no Reviewer is running is retired too. A `reviewed` label now gates the merge, and
no seat can merge without it.

Nothing in this system gets pushed to anybody. Everything is polled.

---

## Your brief holds for exactly one turn

The Console wrote your brief so you can finish without asking anything. Treat that as the contract.
Plan the turn as if no answer is coming, because none is.

**You cannot ask a question and wait for the answer.** Your process exits when your turn ends. Mail
reaches the reader's next turn, never yours.

The Console puts its own worktree path in your brief. Mail it directly:

```powershell
pwsh -NoProfile -File scripts\coord\mail.ps1 -Send -To <the path from your brief> -Body "<question>"
```

`-To` is required. `scripts/coord/mail.ps1` line 349 throws rather than guess a recipient. Do not
substitute `-To all`. That broadcast path spawns a nested PowerShell process, which the PowerShell
tool refuses. Run it through the Bash tool with the path quoted. If your brief carries no address,
put the question in the PR body instead.

You can declare your own seat, through the Bash tool. Measured 2026-09-02: a headless Builder ran
`seat.ps1 -Declare` and its record carries `seatSource: declared`, which no hook writes. Quote the
Windows path. Unquoted, the shell eats the backslashes, so `pwsh` reports the argument is not a
script file and it reads as a missing script.

The PowerShell tool refuses a nested `pwsh` with `Command spawns a nested PowerShell process which
cannot be validated`. That is one tool's refusal, not the harness's. Use Bash.

A SessionStart hook (`scripts/hooks/seat-declare-prompt.ps1`) prints a line telling you to declare.
Do not ignore it. Your brief should carry seat and goal too, because no hook will invent a goal.

Rules a session needs live in the account's `settings.json`, outside git. Every worktree carries its
own tracked copy of `.claude/settings.json` from its own branch. An uncommitted edit in the primary
checkout reaches nothing else.

---

## At least three things outlive your process

1. **The commits on your branch**, pushed.
2. **The pull request**, carrying your `docs/BACKLOG.md` update in the same PR as the code.
3. **The worktree**, which stays on disk after you exit. That is expected, not a leak.

Three more land without your help. A Stop hook (`scripts/hooks/seat-record.ps1`, wired by
`scripts/coord/install-coordination.ps1`) writes an episode record carrying your writes, touched
paths, dirty count and tip. Mail sent with `mail.ps1` leaves a receipt. An allocation from
`alloc.ps1` lands under the git common dir at `mefor-coord/alloc`, whether or not you commit.

None of those carries your reasoning. Your session transcript does not survive in any form another
seat can act on. If a fact matters, put it in the commit, the PR body, or the BACKLOG item.

A headless Builder can do all of this. PR 739 proved it: commit `f075acfd0` on branch
`it2-docs-readme`, clean worktree afterwards, process gone.

---

## Every refusal here is automatic, and most print the remedy with the refusal

### At least these git hooks fire while you are still running

Read `.pre-commit-config.yaml` for the live list. The table below is a reading of that file, not a
replacement for it, and hooks get added.

| Refusal | Meaning |
|---|---|
| ruff-format, ruff-check | Ordinary quality gates. Fix and re-commit. |
| licence-header, control-char | A missing SPDX header, or a control character in a tracked file. |
| gitleaks, bandit, actionlint | Secret scan, Python security lint, and workflow lint. |
| username-access-key | A username used where an access key belongs. |
| backlog-parses | Your `docs/BACKLOG.md` edit no longer parses. |
| ledger gate (`scripts/hooks/ledger_check.py`) | You used an ADR or BACKLOG number you did not allocate. See below. |
| claim gate (`commit-msg`, `scripts/hooks/claim_check.py`) | Your subject line says it implements `BACKLOG #N`, your diff touches code, and you hold no claim on N here. |
| forbidden-content | The leak guard found customer or PHI-shaped content. See below. |
| push guard (`pre-push`) | You tried to push a protected branch directly. Branch and open a PR. |

**mypy does not run at commit.** No pre-commit hook invokes it. mypy strict is a CI leg that reports
after your process is gone, so run `mypy messagefoundry` by hand before you commit.

Never use `--no-verify`, and never rename a file to slip past a gate. A gate you bypassed is a gate
nobody will re-run.

If a commit message fails to parse, it is probably too long. The harness reported a 1015-byte
ceiling on 2026-09-02; that number appears in no file here, so treat it as a measurement rather than
a contract. Use
`git commit -F <file>`, with the file inside the project tree.

### A forbidden-content trip leaves no commit, so mail is the durable channel

The leak guard blocks the commit, so there is no commit and no PR to carry the news. Stop, and do not
work around it. Mail the Console path from your brief, naming the file and the rule that fired.

If your brief carries no address, name the file and the rule in your final message, then stop. Leave
the worktree in place and untouched either way, so the next session can see what you saw.

### The harness guards refuse the tool call, not the commit

The worktree gate is not a git hook. `scripts/worktree/install-gate.ps1` installs it as a PreToolUse
hook in user scope. It denies the tool call itself, long before commit time. It also denies two kinds of Bash or PowerShell call.
One swaps the primary checkout onto another branch. The other points a git command at a worktree
that is not yours. It fires when
you try to write inside the primary checkout, so write inside your own worktree, by absolute path.

### Stage explicit paths, though nothing enforces that today

Nothing blocks `git add -A`, `git add .`, or `git commit -a`. The blanket-stage guard is written and
fully tested, and it is wired in no settings file. `tests/test_claude_settings_contract.py` records
that under `_KNOWN_UNWIRED` as BACKLOG #1339, and wiring waits on the quote-state repair, BACKLOG
#1341. Treat this as a rule with no enforcement behind it.

### Required contexts refuse the merge, not you

A set of status checks must pass before `main` will take a PR. Read the live set from branch
protection. Never memorise the count, and never write a count into a document.

`.github/required-contexts.txt` is a checked-in claim that can lag the server. Its header explains
the required-but-absent trap: a required context that no job can report blocks every PR forever. It
does not tell you that its own set-equality reading has an expiry date.

When the server set moves, move that file and the pinned count in `tests/test_required_contexts.py`
in the same PR. That pin only fails when somebody edits the file. A server move that nobody mirrors
turns a required test leg red for everyone.

You will not see CI while you run, so you cannot triage a red yourself. The Regulator decides whose
it is.
If your brief already names a red and says it belongs to the PR, that judgement is made and the fix
is yours.

### The reviewed label is one label and one command

`gh pr edit <N> --add-label reviewed` is the entire protocol. Nothing automated ever adds it, and a
`synchronize` run strips it, so commits nobody has read are unread again.

Pushing to your own PR after it was labelled un-labels it. That is the design. If you push, the PR
needs reading again.

The gate records that a step happened. It does not establish that an independent party looked.
Labelling your own unread PR satisfies the machine and defeats the point.

### The merge queue re-checks everything

`main` uses a merge queue. A required check's workflow must declare a `merge_group:` trigger, or it
never reports on a queue entry and nothing merges at all. If you add or rename a workflow job that is
or may become required, check that trigger.

### The ledger gate protects a number space git cannot see

Two sessions that both grep for the next free ADR number pick the same one. They create differently
named files, and the two **merge clean**. It has fired three times here. Full reasoning:
[`docs/LEDGER-GATE.md`](LEDGER-GATE.md).

---

## A PR's state is a join over three clocks

**This section is for the Console, the Regulator and the Lander. A Builder never evaluates it,
because its process exits before any run reports.**

`mergeStateStatus` alone will mislead you. It reports `BEHIND` or `DIRTY` in preference to `BLOCKED`.
A PR that is only waiting on a review can therefore read as though it needs a rebase. A seat that triages on
that field will push, strip the `reviewed` label, and wedge the PR further from green.

Settle it this way instead.

1. Find the gate run for the PR.
2. Compare that run's originating `createdAt` against the newest `reviewed` label event.
3. If the run was created before the label event, the verdict is stale, whatever it says.
4. If no run at all is newer than the label event, the state is unknown and the Console keeps
   polling.

Never inherit the last verdict when the state is unknown. The gate's own version of this staleness
was BACKLOG #1417, and it is fixed: `review-gate.yml` reads the label live inside the running job
rather than from the snapshotted event payload. The steps above still bind, because they answer a
different question -- whether a verdict exists for this head yet, not whether the verdict is honest.

Two more measured facts about PR state, so you do not re-derive them:

- The `reviewed` label is stripped by a `synchronize` run only when that run executes. While the run
  is queued the label is present and already invalid.
- A PR rollup cannot tell "never ran" from "not yet registered". Both look like an empty string. The
  lag has measured nine minutes. Use `gh run list --branch <branch>`.

---

## At least six actions break the fleet, so never take them

Never rewrite `docs/BACKLOG.md` beyond your own item. Update the item your brief cites, in the same
PR as the code. Read the ledger from `origin/main`, not from your working tree, and fetch first. A
working-tree copy 36 commits behind once reported 19 closed items as open.

Never grep for the next free ADR or BACKLOG number. Allocate it:

```powershell
pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"
```

Add the ADR's index row in the same commit.

Never cite a `#N` you have not allocated. While the number is unissued the citation resolves to
nothing, which is honest. The day someone allocates it, your citation quietly starts resolving to
unrelated work. If you must gesture at unfiled work, name the subject rather than a number. Where the
number exists but has not merged, say that in the same sentence.

**Never arm auto-merge.** Enqueuing a PR is the Console's decision, and merging is the Lander's.
Arming a PR and then pushing to it is a silent race. Auto-merge fires on the head it saw and drops
your later push. The PR reads MERGED, the branch stays alive, and nothing reports it.

Never announce a hold, a freeze, or a promise about future state. A 2026-08-01 rehearsal of that
shape stayed "in force" for hours after its condition had cleared. `main` moved four times underneath
it.

Never spawn a session from a root that does not carry the spawn grant. The classifier refuses it
there, and on that root the owner starts each Builder. Where the grant is present, spawning belongs
to the Console and to nothing else in the roster. The grant, and how to check your own root for it,
are in "The KORUS seats" above.

---

## Push before the turn runs out, green or not

Report honestly. A truthful "I got this far and stopped here" is worth more than a guess.

You have one turn and no way to ask, so when the brief runs out of road, do this.

1. Push the branch before your turn ends, green or not. Open the PR as a draft if the checks did not
   finish. An unpushed branch is lost; a red draft PR is recoverable.
2. Name in the PR body what you ran, what you skipped, and what is therefore unproven.
3. If you need a decision, mail it to the Console path from your brief. It reaches the reader's next
   turn, not yours.
4. Leave the BACKLOG item honest. Do not flip a banner to closed for work you did not finish.

The full suite can outlast a turn. This repo collects two testpaths under a per-test timeout, so a
whole `pytest` run is not a safe bet against the clock. Run the tests covering your change, push, and
record what you skipped.

Two habits that cost this project real time, so they are worth naming.

- A plausible result is not evidence the instrument worked. An empty result and a clean-looking
  result both hide a failed lookup, and the plausible one gets checked least. Print the needle beside
  the zero.
- A zero is a fact about the spelling you searched. One search for `already-checked-out` returned
  zero while `already checked out` sat in the same file.

---

## Never wait for CI, because the worst way to wait costs more than working

**End your turn. Waiting is the single most expensive thing a session can do, and the worst way to
wait costs more than working does.**

A session spends metered tokens only while the model runs. Measured on this fleet:

| What the session is doing | Tokens a minute |
|---|---|
| Actively working | 10,041 |
| Waiting on a 3-minute heartbeat | 2,108 |
| Waiting on a 10-minute sleep loop | 22,275 |
| Turn over, idle | 0 |

**Read the third row against the first.** A sleep loop costs more per minute than doing the work.
That is not a frequency effect: the more frequent heartbeat is ten times cheaper per minute than the
less frequent sleep loop. The mechanism is what costs. A sleep loop re-enters the model each
iteration and pays for the whole context again. A heartbeat does not start a turn of its own, so its
cost rides turns the session was already taking. It is still billed, as the table shows. Only the
ended turn is free.

CI legs here take 6 to 19 minutes. Against one 19-minute run:

| What the session does | Metered tokens |
|---|---|
| Waits on a 10-minute sleep loop | about 423,000 |
| Waits on a 3-minute heartbeat | about 40,000 |
| Ends its turn, respawned when there is work | a few thousand |

**So the rule has two halves and you need both.**

Poll at a checkpoint the work already produces, and never in a loop that exists only to wait.
Reading your mailbox between two steps you were taking anyway is a tool call and nearly free.
Sitting in a timer to see whether something changed is the 22,275 row.

And end the turn rather than watching for a result you cannot act on. Respawning a session when
there is actually something to do costs a small fraction of the wait.

**The same arithmetic governs a question.** A worker that hits something its brief does not answer
must not wait for the answer either. Write the question to the Console, comment it on the pull
request, and stop. The answer arrives as the next spawn, not as a reply to a session that is still
burning tokens to hear it. Stopping costs nothing; waiting for a reply is the 22,275 row.

**Ending your turn does not release a claim.** A claim you still hold blocks other work until
somebody releases it, so release yours before you go:

```powershell
pwsh -NoProfile -File scripts\coord\claim.ps1 -Release <key>
```

Leave the worktree and the branch where they are. Both are meant to outlive you, and where there is
no commit and no PR the worktree is the only record of what you saw.

---

## Nothing tells a Reviewer your PR is waiting

No workflow notifies a reviewer that a PR needs reading. That gap is BACKLOG #1413, which is filed
and on `main`. The corpus is the 27 files in `.github/workflows`, and the needle is a job that
messages a reviewer about an unread PR.

`stalled-prs.yml` comes closest, and it reports green-but-unmergeable PRs on a daily cron rather than
unread ones. `failure-signal.yml` labels a red PR `ci-red`, and nothing reads that label either.

So say in your PR body what state you left it in. For now the prose is the signal.