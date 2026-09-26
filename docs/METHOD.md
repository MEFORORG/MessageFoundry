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
| Manager | Long-lived, several at once | The seat the owner talks to. Reads the record and writes a brief citing an item, dispatches subagent workers, then polls. It decides when to cut a PR and what goes in it, usually one PR per wave of workers (owner ruling 2026-09-23). The record is two ledgers, and NEITHER IS IN THIS REPOSITORY any more: the item ledger moved to the maintainer-internal repo (BACKLOG #1250), and the `wshallwshall/claude-multisession` issues track KORUS itself. Nothing pushes to it. |
| Builder | One brief, then exits | Works, commits, pushes its branch, reports, and stops. The Manager opens the PR (since 2026-09-18). That is you, most of the time. |
| Watchdog | As needed | Watches the Lander and keeps it draining. Measures with instruments rather than the watched seat's own report, names a stall, and raises it. It never drains, never takes the claim, and never says whose a red is. Added 2026-09-19. |
| Steward | A cron, no model calls | Reads account usage and names the account with headroom. It cannot interrupt a running session. |
| Lander | Standing authority | Enqueues and merges. Both, since the Console's retirement. |

**A MANAGER AND THE LANDER MAY SPAWN A SESSION; every other seat needs permission first (owner
ruling 2026-09-16).** The owner still starts each Manager in the ordinary case, and a Manager's
workers are **subagents in its own process**, on its own account, rather than spawned sessions. So a
Manager needs no spawn grant for its workers, no account roster, and still no way to reach another
Manager -- spawning makes a NEW session rather than addressing an existing one, so the shape still
dissolves the cross-account coordination problem rather than solving it. Several Managers run at
once, usually one per account, and what binds them is the repository they share.

**The case spawning exists for is a PR that needs a fix with no Manager alive**, which nothing else
resolves: no workflow reads a red PR back. `CLAUDE.md` section 5 carries the reasoning and the two
spelling hazards. This replaced a rule reading *"NOTHING IN THE ROSTER SPAWNS A SESSION ANY MORE"*,
true when written and false by 2026-09-16.

**The grant below is LIVE again, and the measurements are kept because they still apply.** It gated
the retired Console's session-spawning, went unused while nothing spawned, and is what a Manager or
the Lander now spawns under. In the `settings.json` of the config root named by
`CLAUDE_CONFIG_DIR`, under `permissions.allow`, it is a rule matching `Bash(claude:*)` or
`PowerShell(claude:*)`. **Measured 2026-09-16: present on all six config roots** -- the base
`~/.claude` was missing it and was corrected that day; accounts 1 through 5 already carried both.
`~/.claude-account-2.lock` holds a `settings.json` and four backups and nothing else, so it is a
backup directory rather than a root, and carries no grant by design.

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
Manager, Process Improvement and ASVS Tracker. **An eighth went on 2026-09-05**, with the
`reviewed` label and `review-gate.yml`; it is deliberately unnamed, here and everywhere else in this
repository, by owner instruction 2026-09-16. **The CONSOLE went on 2026-09-10, and the Manager above
replaces it.** If a document names one, that document is stale.

**A Manager is not a renamed Console, and substituting one for the other is the measured failure
this retirement was written to stop.** A Console's workers were separate sessions across several
accounts under a spawn grant, and one Console ran; a Manager's workers are subagents in its own
process on one account, it needs no grant, and several Managers run. A Console enqueued; a Manager
does not. `docs/roles/seats.json` resolves every spelling of `console` to a notice saying so.

Three rules went with those seats, and they are not repeated anywhere. Routing an owner question
through the Liaison is retired. Getting owner approval before your own push is retired. Falling back
to the Lander for a second reading is retired too.

**RETIRED 2026-09-05, and the retraction is kept because the wrong version was load-bearing.** This
paragraph used to end "A `reviewed` label now gates the merge, and no seat can merge without it."
Measured 2026-09-05: that context was already absent from live branch protection while this file,
`CLAUDE.md`, `docs/CI.md` and the vault all still asserted it was armed, so it gated nothing. The
owner retired the label and the seat rather than restore the gate. **Nothing now requires that anyone
read a PR before it merges.** What blocks a merge is the required check set and nothing else.

Nothing in this system gets pushed to anybody. Everything is polled.

---

## Your brief holds for exactly one turn

Your Manager wrote your brief so you can finish without asking anything. Treat that as the contract.
Plan the turn as if no answer is coming, because none is.

**You cannot ask a question and wait for the answer.** Your process exits when your turn ends. Your
final report and any mail reach the reader's NEXT turn, never yours.

As a subagent your report is the channel back, so put the question there. Where a worker is its own
session instead, the Manager puts its own worktree path in the brief. Mail it directly:

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
2. **The pull request**, once your Manager opens it. It carries code only. The ledger left this
   repository (BACKLOG #1250), so the Lander writes the banner in the vault after the merge, from
   the banner text in your last commit message. No check here can see that update.
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
| ledger gate (`scripts/hooks/ledger_check.py`) | You used an ADR or BACKLOG number you did not allocate. See below. |
| claim gate (`commit-msg`, `scripts/hooks/claim_check.py`) | Your subject line says it implements `BACKLOG #N`, your diff touches code, and you hold no claim on N here. |
| forbidden-content | The leak guard found customer or PHI-shaped content. See below. |
| push guard (`pre-push`) | You tried to push a protected branch directly. Branch and open a PR. |

**mypy does not run at commit.** No pre-commit hook invokes it. mypy strict is a CI leg that reports
after your process is gone, so run `mypy messagefoundry` and `mypy --explicit-package-bases tests`
by hand before you commit.

Never use `--no-verify`, and never rename a file to slip past a gate. A gate you bypassed is a gate
nobody will re-run.

If a commit message fails to parse, it is probably too long. The harness reported a 1015-byte
ceiling on 2026-09-02; that number appears in no file here, so treat it as a measurement rather than
a contract. Use `git commit -F <file>`, with the file inside your own worktree, under a name no
sibling would pick, and delete it once the commit lands.

**Never the harness scratchpad, whatever its system prompt says about isolation.** A session shares
that directory with every subagent and background task it spawns. A sibling writing the same generic
name between your write and your `commit -F` silently substitutes its message for yours, and the
output of the commit shows nothing. Measured 2026-09-03, BACKLOG #1440. Not the per-worktree git dir
either: it sits under the primary checkout's path, so `worktree_gate.ps1` refuses a write there. The
same rule covers any file whose content is later fed to a command.

### A forbidden-content trip leaves no commit, so mail is the durable channel

The leak guard blocks the commit, so there is no commit and no PR to carry the news. Stop, and do not
work around it. Report it, or mail the Manager path from your brief, naming the file and the rule
that fired.

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

You will not see CI while you run, so you cannot triage a red yourself. **Nobody attributes a red
now.** The Regulator retired 2026-09-19 and nothing replaced it: a red is the Lander's to triage and
route, or the owner's to rule on. Do not wait for a verdict; no seat issues one.
If your brief already names a red and says it belongs to the PR, that judgement is made and the fix
is yours.

### There is no reviewed label

**RETIRED 2026-09-05.** This section used to give the protocol: `gh pr edit <N> --add-label reviewed`,
stripped by a `synchronize` run so unread commits were unread again. The label, the workflow and the seat that
owned them are gone. Read a diff because it is worth reading; no machine records that you did.
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

**This section is for the Manager, the Lander, and the Watchdog because it reads merge state to
tell a draining queue from a stalled one. A Builder never evaluates it, because its process exits
before any run reports.** The Watchdog is here on that reading duty, not as the Regulator's
replacement: that seat retired 2026-09-19 and nothing took its ruling.

`mergeStateStatus` alone will mislead you. It reports `BEHIND` or `DIRTY` in preference to `BLOCKED`.
A seat that triages on that field will push and wedge the PR further from green.

Settle it this way instead.

1. Gate on `mergeable == CONFLICTING` first. A PR that conflicts after its checks ran keeps passing
   but stale checks, and the merge ref persists, so it discriminates nothing.
2. Read the required set from LIVE branch protection, never from a checked-in file.
3. Join that set against the PR's rollup. A required context that has not reported is not a pass.

Never inherit the last verdict when the state is unknown. The gate's own version of this staleness is
BACKLOG #1417. That item is open in PR 731 and not yet on `main`, so it does not resolve on
`origin/main` today.

Two more measured facts about PR state, so you do not re-derive them:

- A PR rollup cannot tell "never ran" from "not yet registered". Both look like an empty string. The
  lag has measured nine minutes. Use `gh run list --branch <branch>`.

---

## At least six actions break the fleet, so never take them

Never edit the ledger. It lives in the vault (`MEFORORG/MessageFoundry-vault`) since 2026-09-13
(BACKLOG #1250), and only the Lander writes a banner, after the merge. Put the banner text you would
write in your last commit message instead. This read *"Update the item your brief cites, in the same
PR as the code"* until 2026-09-23.

Read the ledger from the vault's `origin/main`, not from a working tree, and fetch first. A
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

**Never arm auto-merge.** Enqueuing a PR and merging it are BOTH the Lander's, since the Console's
retirement on 2026-09-10. A Manager talks to the Lander and leaves the queue to it.
Arming a PR and then pushing to it is a silent race. Auto-merge fires on the head it saw and drops
your later push. The PR reads MERGED, the branch stays alive, and nothing reports it.

Never announce a hold, a freeze, or a promise about future state. A 2026-08-01 rehearsal of that
shape stayed "in force" for hours after its condition had cleared. `main` moved four times underneath
it.

Do not spawn a session without permission. Only a Manager and the Lander may spawn freely
(owner ruling 2026-09-16). This read *"No seat in the roster does"* until 2026-09-23, which
contradicted "The KORUS seats" above.

---

## Push before the turn runs out, green or not

Report honestly. A truthful "I got this far and stopped here" is worth more than a guess.

You have one turn and no way to ask, so when the brief runs out of road, do this.

1. Push the branch before your turn ends, green or not. An unpushed branch is lost; a red pushed
   branch is recoverable. Under a Manager you do not open the PR: the Manager does, often one PR for
   a whole wave. This step read *"Open the PR as a draft"* until 2026-09-23.
2. Name in your report what you ran, what you skipped, and what is therefore unproven. The Manager
   puts it in the PR body.
3. If you need a decision, put it in your report, or mail it to the Manager path from your brief.
   It reaches the reader's next turn, not yours.
4. Keep the proposed banner honest. Do not propose closed for work you did not finish.

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
must not wait for the answer either. Put the question in your report, comment it on the pull
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

## Nothing tells anyone your PR is waiting

No workflow reports that a PR is finished and unread. `stalled-prs.yml` comes closest, and it reports
green-but-unmergeable PRs on a daily cron. `failure-signal.yml` labels a red PR `ci-red`. No workflow
reads that label back, though `scripts/ci/report_ci_red.py` does when a seat runs it by hand, and it
names the run that reddened each labelled PR. Nothing delivers that to you; you have to ask.

`unread-signal.yml` used to report unread PRs. It outlived the review gate by a week: the owner ruled
it off on 2026-09-08, the workflow was disabled on the server that day, and it was deleted on
2026-09-13 (BACKLOG #1490), because "unread" stopped being a state anything tracked.

So say in your PR body what state you left it in. For now the prose is the signal.

## Why four of these rules changed, recorded so nobody re-derives it

This is history, not instruction. No rule fires from it. It moved here out of `CLAUDE.md` section 5,
which every session loads in full, because it costs every reader and binds none of them.

### Seat declaration: why it was retired is not recorded, and both available explanations fail

**WHY IT WAS RETIRED IS NOT RECORDED, AND BOTH AVAILABLE EXPLANATIONS FAIL.** Written down so nobody
re-derives them. `f0e1365bc` retired a section on the stated ground that four of its rules deadlock a
one-turn Builder -- wait for a go, the ultracode gate, `/clear`, and ask before pushing. Declaring is
not one of the four. The Builder section below says *"It CAN declare its own seat, through the Bash
tool"*, measured the same day. And the retired rule's own stated purpose, feeding the fleet view,
survives: `scripts/coord/fleet.ps1` is a live pure reader over the seats layer. **So treat the
retirement as unexplained rather than as a judgement you would be overturning by declaring.**

### The spawn grant: what this replaced, and the measurements behind it

**THIS REPLACED A RULE READING "NO SEAT SPAWNS A SESSION ANY MORE, so the spawn grant binds
nothing."** That was true when written and false by 2026-09-16, when the grant was measured present
on all six config roots. It is named rather than deleted because a seat that read it did not try,
rendered unable to spawn, and confirmed it -- the same self-confirming shape this section already
records for seat declaration.

**The grant's measurements are kept, not deleted, so nobody re-derives them and nobody mistakes this
for a capability that was lost.** The grant is a rule matching `Bash(claude:*)` or
`PowerShell(claude:*)` under `permissions.allow` in the `settings.json` of the config root named by
`CLAUDE_CONFIG_DIR`. Measured 2026-09-02: `.claude-account-1` carries both and spawned a session,
exit 0 in 38.8 seconds; every root measured that day without them was refused. Exit 0 alone does not
prove a spawn worked, because a prompt swallowed by a list-taking flag exits 0 too (see the dispatch
bullet below), so check what the child did. **What binds a Manager's workers instead is the
tool-grant spelling, and the careful spelling is the broken one** -- same bullet.

### The korus playbooks: the pointer moved and the thing it pointed at did not

- **SUPERSEDED 2026-09-05, recorded rather than deleted because seats still quote it.** This line
  named the `MessageFoundry-vault` primary's `roles/` folder (owner ruling, vault commit
  `5e361756`).
- **Name the ref, not the checkout.** The superseded line said a checkout, and its own next sentence
  warned that a checkout is not a ref. Both halves were right and the first one won.
- **What that costs, measured 2026-09-06.** The korus primary sat on a branch 15 commits ahead of
  `origin/main` and 14 behind it. One seat's playbook was absent from its working tree and present
  on `origin/main`.
- **So a seat reading the folder finds no playbook for itself, and no error.** An `ls` of a directory
  is not evidence that you have a file, and a missing file is the quietest failure in this list.
- **The failure this cost is the one to carry forward.** A pointer and the thing it points at are
  two edits, and nothing fails when only the first is made. The playbooks moved on 2026-09-04 and
  this line was not changed until 2026-09-06, so every seat in between read a stale copy and no
  gate reported it.

### Auto-merge: the hazard kept, because nobody has measured it under a queue

  **The hazard this bullet was written against is KEPT, not deleted, because nobody has measured it
  under a queue.** It read, in full: *"Never arm auto-merge. Auto-merge fires on the head it saw, so
  a later push is dropped: the PR reads MERGED, the branch stays alive, and nothing reports a
  problem."* Whether a QUEUED entry does that when its branch is pushed underneath it is
  **unmeasured** — what is measured on this repository is eviction and group rebuild, which is a
  different event with a different cause. Until somebody watches a push land under a live entry, the
  safe course is to dequeue before pushing, and the claim above must not be read as covering it.
