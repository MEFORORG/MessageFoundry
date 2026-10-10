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
resolves: workflows label and report a red PR, but none sends it to a seat (see "Nothing tells
anyone your PR is waiting" below). The reasoning is under *CLAUDE.md text moved in wave 2* below,
and the two spelling hazards are in [`WORKTREES.md`](WORKTREES.md). This replaced a rule reading *"NOTHING IN THE ROSTER SPAWNS A SESSION ANY MORE"*,
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
*Count note, 2026-10-07:* the blocks under *Retired CLAUDE.md notices* call the Console the eighth,
because that file never counted the unnamed seat; the note at the head of that section says the same.

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
owner retired the label and the seat rather than restore the gate. **CORRECTED 2026-09-29:** this
paragraph read *"Nothing now requires that anyone read a PR before it merges."* Since an owner ruling
that day, the Lander merges only on proof that code review ran, or sends the change to code review.
CLAUDE.md section 5 carries the rule. No machine gate beyond the required check set blocks a merge.

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

A lesson that outlives the item belongs in the fleet wiki, and another Stop hook asks for one. It is
`scripts/hooks/wiki-write-prompt.ps1`, wired by the same installer under the marker `mefor-wiki`. It
prompts only an attended session. A headless `claude -p` run, a spawned Builder or a scheduled job
is never prompted, because the prompt would replace its final report. The script header says which
reading of Claude Code that rests on. In an attended session it fires after enough tool uses or a
`git commit` or `git push`, with a cooldown between prompts, and never while `stop_hook_active` is
set. The thresholds are named constants at the top of that
script. If nothing qualifies, reply `wiki: nothing to record`. To turn it off, create the file
`mefor-coord/wiki-prompt/OFF`, which reaches sessions already running. `MEFOR_WIKI_PROMPT=off` works
too, but only for sessions started with it set. Each prompt it fires is logged under
`mefor-coord/wiki-prompt/`, beside its per-session state.

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
| claim gate (`commit-msg`, `scripts/hooks/claim_check.py`) | Your subject line says it implements `BACKLOG #N`, your diff touches code, and you hold no claim on N here. Or, on any commit, your subject has a `#N` that no `BACKLOG #` token governs, that is not labelled `PR #N`, and that is not the one trailing `(#N)` of a squash merge. Write items as `(BACKLOG #a, #b)`. |
| forbidden-content | The leak guard found customer or PHI-shaped content. See below. |
| push guard (`pre-push`) | You tried to push a protected branch directly. Branch and open a PR. |

**mypy does not run at commit.** No pre-commit hook invokes it. mypy strict runs in CI and reports
after your process is gone, so run the four legs `ci.yml` runs by hand before you commit:

    mypy --platform linux messagefoundry messagefoundry_webconsole messagefoundry_toolkit --exclude 'messagefoundry/tray/'
    mypy --platform win32 messagefoundry messagefoundry_toolkit
    mypy --explicit-package-bases tests
    mypy --platform linux scripts/asvs

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
that under `_KNOWN_UNWIRED` as BACKLOG #1339. What wiring waits on is in
[`BLANKET-STAGE-GUARD-FAIL-OPENS.md`](BLANKET-STAGE-GUARD-FAIL-OPENS.md), *What wiring waits on*.
Treat this as a rule with no enforcement behind it.

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

**Never arm auto-merge**, unless you are the Lander acting under its 2026-10-07 exception in the
CLAUDE.md section 5 roster. Enqueuing a PR and merging it are BOTH the Lander's, since the
Console's retirement on 2026-09-10. A Manager talks to the Lander and leaves the queue to it.
Arming a PR and then pushing to it is a silent race with two outcomes. If the merge fires first,
your push is dropped: the PR reads MERGED and the branch stays alive. If the push lands first, a
write-access push leaves auto-merge armed, so the new head can merge with no review. Nothing
reports either one. The safeguards are in the 2026-10-07 note under that roster.

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
green-but-unmergeable PRs on a daily cron.

`failure-signal.yml` labels a PR `ci-red` when at least some workflows go red on it. Its header says
which ones it watches and where a red with no PR goes instead.

It also comments on a PR the merge queue ejected, meaning a queued PR the queue dropped after a red
run on the merged result. That PR's own head can still be green.

`ci-red-report.yml` reads the label back on a schedule, through `scripts/ci/report_ci_red.py`. The
script names the run, job and step behind each label it can attribute, and it sees queue runs.

That report lands only in its own run summary, so nothing delivers it to you. A seat that wants a
fresh answer runs the script, whose docstring gives the flags and exit codes.

Nothing removes the label on its own. A seat can run `scripts/ci/clear_stale_ci_red.py`; its
docstring says when it clears and when it keeps.

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
*Since 2026-10-07 both bullets this paragraph points at are in [`WORKTREES.md`](WORKTREES.md):
"Put the prompt first, or a list-valued flag eats it and the lane dies quietly" and "Grant tools by
bare name in the `--allowedTools` flag".*

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

  *Added 2026-10-07:* for a deferred auto-merge request, the quoted claim is half the story. A
  push that lands before the merge fires does not disarm it when the pusher has write access, so
  that head can merge unreviewed. This addendum says nothing new about a QUEUED entry.

## Retired CLAUDE.md notices, kept verbatim

These blocks moved out of the root `CLAUDE.md` on 2026-10-07, word for word. `CLAUDE.md` loads
into every session, and these blocks are mostly history: retired rules, a resolved collision, and
measurements. Where a block still states a live rule, `CLAUDE.md` section 5 now carries a short form
of it and points here. The verification recipe under the positional ruling stays live in full.
The korus *4a-quinquies* condition the positional block quotes is the 2026-09-21 form; read korus
for the current one.

Read each block as `CLAUDE.md` at `ddf350e1d0`. There, *above*, *below*, *this file*, *this
section*, *this notice* and a bare section number all mean `CLAUDE.md` and its sections, not this
page. The ordinals *eighth* and *ninth* follow that file's count, not the count earlier on this
page. Where a block and `CLAUDE.md` now disagree, `CLAUDE.md` wins. The section *Why four of these
rules changed* above holds older history of the same kind.

### The Console and the Regulator, retired 2026-09-10 and 2026-09-19

**An eighth went on 2026-09-10, by owner decision: the CONSOLE. The MANAGER replaces it, and a
Manager is NOT a renamed Console.** A Console's workers were separate `claude -p` sessions across
several accounts, spawned under a per-root grant, and exactly one Console ran. A Manager's workers
are **subagents inside its own process on its own account**, it needs **no spawn grant for them**, and
**several Managers run at once, usually one per account**. The Manager also does **not enqueue** --
that moved to the Lander. **So a Console rule does not transfer by substitution.** Read the Manager's
row below and korus `MANAGER.md`, and decide as a Manager; do not reach for what a Console would have
done. `docs/roles/seats.json` resolves `console` to a retirement notice saying exactly this, because
reading its old "the Console runs instead" line as *"substitute the Console"* is the measured error
this retirement was written to stop.

**A ninth went on 2026-09-19, by owner decision: the REGULATOR. NOTHING replaced it, and NO SEAT
ATTRIBUTES A RED NOW.** A red is the Lander's to triage and route, or the owner's to rule on. The
**WATCHDOG** joined the same day, which is exactly why this has to be said plainly: it is **not the
Regulator's successor**. A Regulator returned a binding verdict on one red. A Watchdog returns
evidence, measures whether reds are being cleared at all, and never says whose one is. So a red sent
to a Watchdog gets a reading and no verdict, and a session waiting for that verdict waits forever.
`docs/roles/seats.json` resolves `regulator` to a retirement notice saying this, for the same reason
the Console's does.

### Seat declaration crosses accounts, measured 2026-09-12

**IT IS NOW THE ONLY THING THAT MAKES A SEAT FINDABLE FROM ANOTHER CLAUDE ACCOUNT, and that was not
true when it was retired.** Measured 2026-09-12: `SendMessage` and `ListAgents` do not cross
accounts -- a Lander enumerated exactly two peers, both on its own config root, while a session on a
different account held finished work for it and kept retrying an address that cannot resolve. The
coordination directory DOES cross: six config roots write seat records into one `.git/mefor-coord/`.
**But a mailbox is keyed by WORKTREE while a searcher is looking for a SEAT**, so guessing a box from
a role name finds only the dead ones. The seats registry is the bridge, and it bridges only if you
declared: that Lander's record was live that minute, 158 writes that day, with `seat` absent and
`declaredAt` null. **A live record with no seat is indistinguishable from no record at all.**

korus `roles/COMMON.md`, section *"The seat registry is the only channel that crosses accounts"*,
carries the read side: how to find a live seat from any account, and why that search must sort by
recency.

### The Lander row's duty and the ASVS re-score, 2026-09-21 and 2026-09-23

**THE LANDER ROW'S DUTY WAS CORRECTED BY THE OWNER ON 2026-09-21, IN SESSION.** That cell read
*"Merging, and the vault scorecard re-score (owner ruling 2026-09-05)"*, and the owner has said
directly that the Lander was never meant to always handle rescoring. The duty is **flipping row
statuses after items merge**, which is what the row now says. **That left the ASVS scorecard
re-score UNASSIGNED on 2026-09-21, and no part of it is the Lander's** -- the owner named no seat
for it that day, so neither did this file; **the 2026-09-23 ruling below names one.** Only the
re-score half of that wording moved; the separate "Merge when ready" ruling of the same date,
further down this section, is untouched.

**THE RE-SCORE IS ASSIGNED NOW. OWNER RULING 2026-09-23, GIVEN TO A MANAGER SEAT.** ASVS record
work belongs to a **Manager dispatching vault Builders**. It covers three acts: re-scoring a cell,
editing the record's own prose, and reconciling the record against a ledger row when the two
disagree. **The Lander keeps the row-status flip**, which is its 2026-09-21 duty above, unchanged;
in the vault ledger that flip is the status banner. The paragraph above is kept as this file's
record of when the gap opened, and this one records when it closed.

### The positional ledger-conflict ruling, retired 2026-09-21

**THE 2026-09-11 POSITIONAL LEDGER-CONFLICT RULING IS RETIRED. The owner authorised the retirement
directly on 2026-09-21, in session, after reading an adversarial review of the question.** It is
recorded rather than deleted because seats still quote it.

**What it said**, in its own words. *The Lander may resolve a POSITIONAL ledger conflict, and only
that* -- permitted when `git merge-tree --name-only origin/main <head>` named **`docs/BACKLOG.md`
alone** and the fix was re-placing an existing, already-reviewed row at a vacant numeric slot;
forbidden the moment code was touched or a choice about what an item *said* was required, and those
went back to the authoring session, *"because a peer writing to another session's branch is how two
sessions silently collide"*. A companion paragraph held that *the filename is necessary and not
sufficient*, because two sessions editing one item's **body** also conflict in that file, and that
the discriminator was whether the resolution decided *where a row sits* or *what it says*.

**Read the retired text as a GRANT WITH A LIMIT, which is the form it had:** *may resolve a
positional conflict, and only that*. Retiring it removes the engine-local sentence, both halves.
**It issues no licence in its place: this notice adds no permission to this repository**, and the
Must-not column above keeps its code clause untouched. *(The owner ruling of 2026-09-29, in the note directly under the roster table, removed that clause.)* What the Lander may now do where the retired
rule used to speak is a korus playbook question, named below.

**Three grounds. They are CUMULATIVE, and are laid out separately rather than as three independent
proofs: one is scoped to this repository, and one expires when a filed repair lands.**

**One: in THIS repository the rule is a dead letter.** It governed `docs/BACKLOG.md`, and the ledger
left for the maintainer-internal repository (§11). Measured 2026-09-21 at engine `origin/main`
(`92292fa50`): `git show origin/main:docs/BACKLOG.md | grep -c '^## [0-9]\+\.'` returns **zero**
over a 23-line stub. The control, same regex and same instrument, returns **868** at vault
`origin/main` (`6f0f7690f`), so the probe is armed and the zero means what it says. There is no
numeric slot here to re-place a row into. **This ground does not reach the vault** -- the roster row
above carries standing authority over both repositories, and ground three is what covers the other
one.

**Two: the rationale was CONDITIONED and relocated, which is weaker than retracted -- say the
weaker thing.** The retired *"Why the line sits there"* paragraph rested entirely on separation of
duties: *"the Lander's value is being a second reader, and authoring plus landing the same change
means nobody checked it"*. korus `roles/LANDER.md` section *4a-quinquies*, owner ruling
**2026-09-21**, read at `origin/main`, reads *"you are not a second reader **as long as the Builder
ran its own code review**"*, and the same table routes an ABSENT QA line to a `code-review` subagent
at `xhigh`. **Quote that condition, never the headline alone.** So the premise survives in korus in
conditioned form, and korus answers the AUTHORING case separately in 4c-quinquies, by requiring
disclosure rather than abstention. What fails is the engine-local carve-out's exclusivity: a rule
licensing only the positional slice no longer tracks how korus allocates the work.

**Three: the tool refused the resolution in the repository that does hold the ledger, and this
ground EXPIRES. IT HAS NOW EXPIRED -- do not quote it.** The vault's
`scripts/hooks/ledger_check.py` keyed ownership on an exact worktree-string match with no
merge-parent awareness, so a Lander resolving a positional tail conflict on a branch it did not
allocate was refused at commit time. Measured 2026-09-21 at vault `origin/main` (`6f0f7690f`): a
grep for `_merge_parents|MERGE_HEAD|merge_parent` over that file returned **0**, against controls of
**5** for `rev-parse` and **5** for `owns` on the same file and the same instrument. **Re-measured
later the same day at vault `origin/main` (`76d7f1552`), same needle and same instrument: it returns
6**, against controls of **8** for `rev-parse` and **7** for `owns`; `_merge_parents` is defined at
`:824` and called at `:1122`. The repair was filed as vault BACKLOG **#1861** and its code has
landed, though that row's banner still reads FILED -- the row and the tree disagree and the tree
wins. **This is the expiry condition firing, and it settles nothing about the RULE this notice
records.** #1861 warned that a path-keyed port would be *a guard that cannot fail* and that the
correct shape is heading-keyed. It landed heading-keyed, at vault `55b0211d6`, and
`tests/test_ledger_check.py` covers a Lander's own resolution shape --
`test_a_merge_carrying_ANOTHER_worktrees_number_is_committable`, docstring *"A Lander resolving a
tail conflict on another session PR"*, with `test_exactly_ONE_of_the_three_merge_shapes_is_refused`
as the discriminating arm. So the tool no longer refuses. **That is a fact about the GATE, and a
gate that stops refusing grants no permission** -- the measurement is dead and the ground is gone,
and the rule question stands exactly where the rest of this notice leaves it.

**What is live instead is a korus playbook rule, read at `origin/main`. Its SUBSTANCE is
deliberately not copied here.** korus `roles/LANDER.md` section *4c-quinquies. A content conflict is
YOURS to resolve* (owner ruling 2026-09-21), and the same file's section *Filing a new ledger item
routes to the Lander*, whose ledger duties the owner set on 2026-09-20. Read them there. A
restatement in this repository is the pointer that goes stale while the thing it points at moves,
which is the failure this section documents about itself.

**THAT PREDICTION CAME TRUE AS A CITATION RATHER THAN A RESTATEMENT, AND WITHIN MINUTES.** This
paragraph was written citing `4g`, and Ground Two above cited `4a-quater`. korus renumbered both on
2026-09-21 -- `4g` to `4c-quinquies`, `4a-quater` to `4a-quinquies` -- because a section id is a
repository-wide name and each was already taken elsewhere in that tree. **Neither old id is free, so
the dead pointers resolved to plausible wrong text instead of to nothing**: at korus `origin/main`
(`49416f9f8`), `4g` names *"If you build a drain, these are its failure modes"* in the
`lander-empty-queue` skill and `4a-quater` names *"A broadcast caution has a cost"* in
`lander-relay-or-correct-a-claim`. All three citations in this notice are corrected above. **Check a
korus section id against its file before you quote it.** One command does it, and a renumber is
invisible to a reader who greps only for the heading text:

    git -C <korus clone> show origin/main:roles/LANDER.md | Select-String '^### '

**THE VERIFICATION RECIPE OUTLIVES THE PERMISSION, and it is the half worth keeping.** It is the
standard for checking ANY ledger conflict resolution, whoever performed it: `merge-tree` exit 0,
paired with a self-merge control (**0**) and the pull request's own pre-fix head (**non-zero**, so
the 0 is attributable to *this* merge rather than to a probe that cannot fail), the ledger gate
green, the `parse_items` count up by the expected number, and both items present and whole.

**Its last two legs are the weak ones, and they are the two that look strongest.** A COUNT cancels:
added-correctly plus quietly-dropped-something-else nets to the expected number, so a count paired
with a presence test passes in exactly the case it exists to catch. The stronger form is **three set
comparisons** over `parse_items` output, compared by item NUMBER and never by total: nothing lost
from `main`, nothing lost from the branch, and the set present beyond `main` exactly the numbers
intended. korus skill `lander-resolve-a-conflict`, section *8b*, at `origin/main`, is the source of
record -- read it there rather than relying on this summary.

*The retired rule's own measurement is kept, because it is still a true reading of that day.*
*Measured 2026-09-11:* all four open conflicts (PRs 1029, 1030, 1032, 1049) were this one positional
shape, and #1030's authoring session had died -- leaving its PR unlandable by anyone until the owner
routed a new session to it.

### The code-conflict collision, resolved 2026-09-29

**RESOLVED 2026-09-29 BY OWNER RULING, IN SESSION: THE LANDER MAY RESOLVE A CONFLICT THAT TOUCHES
CODE.** korus *4c-quinquies* governs the route, and the Lander's own resolution needs its own code
review before the merge. The notice below stays only as the record of the collision. None of its
instructions apply any more: do not hold a pull request, raise the question, or ask it.

**THE CODE CLAUSE AND korus 4c-quinquies COLLIDE ON ONE CASE. THE COLLISION IS UNRESOLVED AND NO
SEAT MAY PICK.** *CORRECTED 2026-09-29: resolved by the owner. This heading is history; the banner
above governs.* Recorded here because a Lander hit it on 2026-09-21 and stopped, correctly, with
nothing in either repository telling it what had happened.

**The two texts, verbatim, both live at `origin/main` on 2026-09-21.** This file's roster row,
Must-not column: *"Resolve a conflict that touches code, or decide which of two deliberate changes
to an item survives."* korus `roles/LANDER.md` *4c-quinquies*, opening ruling: *"Owner ruling
2026-09-21. A DIRTY pull request is this seat's work. It is not a routing decision."* Its
standing-rules row: *"A CONTENT conflict is YOURS. Owner ruling 2026-09-21. Resolve it yourself. Do
not route it to a Builder and do not wait for a person."* The rest of korus's substance -- its
route, its traps, its verification -- stays there and is not copied here.

**THE COLLIDING SET IS ONE CASE, AND NAMING IT IS MOST OF THE ANSWER.** Do not read this notice as a
general standoff about conflicts. Everything around the contested case already agrees.

| Case | Where the two documents stand |
|---|---|
| A conflict touching no code | **Agreed, and it is the Lander's.** korus grants it, this file's Must-not does not reach it, and *"A Builder gets one turn"* item 6 below already treats *"the Lander resolving prose by hand"* as the ordinary outcome. |
| Deciding which of two deliberate changes survives | **Agreed, and it is NOT the Lander's.** Both say so; this file adopted korus's wording for it on purpose on 2026-09-21. |
| Rewriting a pushed ref | korus forbids it and routes you to a fresh ref or a question. This file is silent, so korus binds unopposed. |
| A conflict whose resolution touches a code file | **The Lander's, since the owner ruling of 2026-09-29.** Until then this cell read *"CONTESTED. UNRESOLVED. Raise it; do not choose."* |

**korus IS NOT SIMPLY LATER -- IT DECLINED TO CLAIM THIS, AND THAT IS MEASURABLE.** korus has a form
for overriding this file and uses it: `roles/BUILDER.md` names the point, quotes the stale engine
text verbatim, says *"Read the ruling as the winner"*, and carries a note that the row exists
because *"The stale `CLAUDE.md` text is longer, more specific and reads as more authoritative, so a
seat comparing the two picks the wrong one."* **`roles/LANDER.md` carries no such row.** Measured
2026-09-21 at korus `origin/main` (`49416f9f8`): `SUPERSEDES` returns **1** in `roles/BUILDER.md`
and **0** in `roles/LANDER.md` and in the `lander-resolve-a-conflict` skill; the only two
case-insensitive *supersede* hits in `LANDER.md` (`:746`, `:1464`) are about superseding a CI run.
Control on the same read: case-insensitive *owner ruling* returns **23** in `LANDER.md` (**18**
case-sensitive), so the zero is a fact about that file and not a dead instrument.

**AND THIS FILE DID NOT DEFER THE CODE CASE, BY ITS OWN TERMS.** The deferral above is scoped to
*what the Lander may now do where the retired rule used to speak*, and the retired rule, quoted in
its own words at the top of this notice, was *"forbidden the moment code was touched"*. It never
spoke there, so the deferral does not reach there -- which is what the preservation sentence in the
same paragraph says.

**SO NEITHER AUTHOR WROTE AGAINST THE OTHER, ON THE SAME DAY, EACH WITH THE OTHER TREE OPEN.** There
is no later text, no supersession claim in either direction, and no seat holds a signature for
either side. That is what makes this an owner question and not a stale pointer.

**DO NOT SETTLE IT BY PROVENANCE, AND THAT INCLUDES THE TEMPTING ARGUMENT.** The tempting one is
that the code clause is an orphaned fence: it arrived on 2026-09-11 in the **same row edit** as the
positional grant, as that grant's limit, and the grant is retired. **Two things hold it up anyway.**
The owner-authorised retirement kept it in an affirmative sentence rather than by inaction, and PR
1397's commit body states the same split -- *"The retirement removes a restriction and issues no
licence ... The code clause of that column is untouched."* And the principle behind it is held
independently elsewhere in this section, under a different owner ruling on a different date:
*"Spawning a Manager is also better than the **Lander** fixing the PR itself: authoring plus landing
means nobody checked it"* (owner ruling 2026-09-16, under the spawn grant). **That worked case is a
red CI fix and not a conflict, so it is adjacent evidence and not a holding here** -- it is enough to
sink the orphan reading, which needs the clause to have no support outside the retired grant, and
not enough to decide the question.

**WHAT A SEAT DOES WHILE THIS IS OPEN IS ALSO OPEN, AND MUST NOT BE INVENTED.** korus
`roles/COMMON.md`, *Where a role playbook and this file disagree*, flags exactly that gap for its own
analogous pair: *"Still open | What a seat DOES while it waits for the clarification. 'Follow COMMON
until told otherwise' is an inference, not the ruling. Ask; do not assume."* Say on the pull request
that you are holding on an unresolved rule collision and name this notice, so the stall is visible
rather than silent. **That is disclosure. It is not a resolution, and it is not permission either to
resolve or to hand over.**

**THE ONE-LINE OWNER QUESTION, so this costs one answer.** *When a DIRTY pull request's conflict
touches code in this repository or the vault, does the Lander resolve it under korus 4c-quinquies,
or does this file's Must-not clause stand and the pull request route elsewhere -- and which applies
until you answer?* Whoever asks it should paste the two verbatim sentences above and nothing else.

## CLAUDE.md text moved in wave 2, kept verbatim

These blocks moved out of the root `CLAUDE.md` on 2026-10-07, in a second pass after the section
above, word for word. The reason is the same: `CLAUDE.md` loads into every session, and each block
binds only one seat or one kind of work. `CLAUDE.md` keeps a short form of the rules in them that it
still states, and points here. Link targets were changed so they resolve from `docs/`.

Read each block as `CLAUDE.md` at `d62308d8be`. There, *above*, *below*, *this file*, *this
section* and a bare section number mean `CLAUDE.md` and its sections, not this page. Where a block
and `CLAUDE.md` now disagree, `CLAUDE.md` wins.

### The Manager's dispatch rules, from section 5

From *The Manager plans, dispatches, and holds the owner's attention*. The `--allowedTools`
bullet went to [`WORKTREES.md`](WORKTREES.md), beside the prompt-first section. The bullets
korus `roles/MANAGER.md` already carries were not copied: push then report, the three
who-else-is-running fields, readings not conclusions, and announcing files rather than subjects.
Nor were the prompt-first, own-worktree and never-relocate bullets, which `WORKTREES.md` states in
its sections on putting the prompt first, creating a worktree and starting the session in it.

- One brief per Builder. After about two failed attempts at the same problem, dispatch a fresh Builder
  with a better brief rather than reuse a poisoned context. A Builder cannot do this. When you are
  stuck after two attempts, push what is green and say in the PR body that the brief needs re-cutting.
- **If you take back part of a brief you already dispatched, mail the receiver, because you cannot
  update the chip.** `dismiss_task` withdraws only a chip the user has **not** acted on, so a
  started one stays live and frozen around your stale text, and no channel carries the correction.
  Say which item is already done and where it landed. **This binds whichever seat dispatched:** any
  seat can raise a chip, and in the 2026-09-04 case above the spawner was
  the session that then pushed the fix. It corrected its own BACKLOG item in the same change and
  still could not reach the chip, which is the whole shape of the defect -- BACKLOG #1448.
- Rules a Builder needs belong in the **account's** `settings.json`, outside git.
  `.claude/settings.json` is tracked, and every worktree carries its own copy from its own branch, so
  an uncommitted edit to the primary checkout reaches nothing else.

### The Special seat and the spawn grant, from section 5

From the notes under the section 5 roster. `CLAUDE.md` keeps the roster row, a short form of each
ruling, and pointers to korus `roles/SPECIAL.md` and `docs/roles/special.card.md`.

**THE SPECIAL SEAT IS THE OWNER'S, AND IT HAS NO STANDING DUTIES (owner decision 2026-09-16).** It
exists for work that falls outside the other five, so its instruction is the whole of its scope and
it has none until the owner gives it one. It does not take a BACKLOG item, a brief, or a red. It is
an ADDITION -- nothing retired to make room for it -- and it is not a spawn-authorised seat, so the
ruling below binds it.

**Standing by is its normal state, not a fault in it.** An idle Special session is the owner holding
one in reserve, and work it finds itself spends that. It announces and declares before its first
SHARED write rather than on arrival, which is the one point where it parts company with every other
seat here: the arrival prompt that tells each session to declare is the line this seat alone does
not act on. The cost of that silence is real and lands on nobody while the seat touches nothing --
`fleet.ps1` omits it and no peer can forecast a collision with it -- which is why the deferral ends
at the first shared write and not later. Its card is
[`docs/roles/special.card.md`](roles/special.card.md); the full playbook is korus
`roles/SPECIAL.md`, read at `origin/main` like every other playbook.

**A MANAGER AND THE LANDER MAY SPAWN A SESSION. EVERY OTHER SEAT NEEDS PERMISSION FIRST (owner
ruling 2026-09-16).** The owner still starts each Manager in the ordinary case, and a Manager's
workers are still subagents in its own process rather than spawned sessions. A Manager still needs
no account roster and still cannot reach another Manager: spawning makes a NEW session, it does not
address an existing one, so the shape still dissolves the cross-account problem rather than solving
it.

**The case spawning exists for is a PR that needs a fix with no Manager alive.** Nothing sends a
red PR to a seat -- `failure-signal.yml` sets a `ci-red` label that only an advisory daily report
reads back, and `stalled-prs.yml` reports green-but-unmergeable PRs rather than red ones -- so the
work stops until somebody happens to look. **CORRECTED 2026-09-26:** this read "a `ci-red` label no
workflow reads back"; `ci-red-report.yml` (PR 1240) reads it daily into its own run summary. Spawning a Manager is also better than the **Lander** fixing the PR itself: authoring plus
landing means nobody checked it, and a fix written to turn CI green is checked by the very signal it
was written against.

**SPAWNING SHOULD BE RARE, AND REACHING FOR IT IS WORTH NOTICING.** A Manager's subagents already
cover almost everything it does, and the load-bearing property is that **a subagent cannot outlive a
mistake** -- it needs no grant and it dies with its Manager. **A spawned session can outlive one**,
which is the whole of the added risk. So a spawn is better read as a SIGNAL THAT SOMETHING UPSTREAM
HAS FAILED -- a seat died with work outstanding, or nobody was alive to take a red -- than as a
routine tool. Raised by a Manager seat on 2026-09-16, about its own grant, which is the direction
that argument is most credible from.

### A Builder gets one turn, items 2, 5 and 6, from section 5

`CLAUDE.md` keeps items 1, 3 and 4 whole and a short form of each of these three. The full items
follow.

2. At least two kinds of refusal reach a Builder while it runs. Local git hooks fire at commit and
   push time; the live list is `.pre-commit-config.yaml`. The user-scope PreToolUse guards fire at
   tool-call time and deny the tool call itself. Each one sees only some tools.
   `collision_gate.ps1`, wired by `scripts/coord/install-coordination.ps1`, sees Write, Edit,
   MultiEdit and NotebookEdit, and nothing else. `worktree_gate.ps1`, installed to
   `%USERPROFILE%\.claude\hooks\` by `scripts/worktree/install-gate.ps1`, sees at least those four
   tools and Bash and PowerShell. On the four edit tools it judges the file being written. On a
   shell call it judges only git commands, by verb, config key and the repository or worktree they
   target. **So neither guard intercepts an ordinary shell write, such as a redirect into a
   file.** The worktree gate's own deny text says a shell route around a denied write still breaks
   its rule. CI arrives later, when the process is gone.

<!-- list break: keeps the CLAUDE.md item number -->

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
   starting session to declare. **Do not ignore it.** The Manager should still supply seat and goal
   at dispatch, because no hook will invent a goal, by design: a machine that invents one writes a
   record that looks declared and says nothing.

<!-- list break: keeps the CLAUDE.md item number -->

6. **A brief can be wrong by the time you read it, and nothing will tell you.** Verify it against
   the tree before you act on it: read the diff of **every PR it names**, at hunk granularity, and
   re-locate every line number by symbol. **Where the brief and the tree disagree, the tree wins.**
   ***Do not scope this check to how recently the brief was written.*** Two windows give the same
   symptom and **the wider one dominates**: a brief goes stale AFTER dispatch, in minutes, and it is
   written stale because the ITEM it was cut from is stale, over weeks. A Manager seat reported six
   of eleven briefed items already answered at spawn on 2026-09-04 -- by an ADR accepted before the
   brief, by work shipped under a different number, by a PR the item itself says not to rebuild.
   **Attributed, not verified here.** The structural cause is that an item records its own research
   and nothing records the work that ANSWERS it, so a settled row still reads as current.
   **Line numbers are navigation aids and never evidence** -- the same seat measured four anchors
   adrift by 50, 86, 581 and 593 lines in one day, one item with both of its anchors dead.
   Measured here 2026-09-04, the after-dispatch window: a chip named three drift sites, and minutes
   later the spawner took item 3 itself and pushed it as `c2f549f42` on PR 837. The receiver read
   that diff before touching anything, saw both hunks already rewritten, and skipped it. Trusting
   the brief would have put two PRs on the same two comment blocks, to meet at merge with the Lander
   resolving prose by hand. **Two of the same brief's other three items also failed to survive a
   read of their sources**, so one confirmed drift is a reason to re-check the rest, not to correct
   that line and carry on. ***"The brief is disposable" above says it may be thrown away; it does
   not say it was true when written.*** **Finding an item already answered is a GOOD outcome** --
   record it with evidence and stop, rather than building it again. BACKLOG #1448, same family
   as #1391.

### The glyph rule's reasoning, history and census, from section 11

From the first bullet of section 11. `CLAUDE.md` keeps the rule, a short form of its reasoning, the
backticked-token exception, the `backlog-hygiene.yml` warning, the ban on new glyph vocabulary, the
U+26A0 ruling and the positive-control rule.

  **Why this is a correctness rule and not a style preference.** A glyph's meaning is *positional*, and
  that is invisible to anyone who learns it from examples rather than from its definition. Measured
  2026-08-04: the backlog's `✅` means "this item is closed" **only** in the leading blockquote — quoted
  in an item's prose it is narrative. Two parsers of the same file disagreed on exactly that, one
  reading "the glyph appears in this item" and the other "this item declares closed status", and they
  **agreed on the current corpus by luck** because no item happens to have the discriminating shape.
  Words carry their scope in the sentence around them; a bare glyph does not, so it invites
  presence-equals-meaning reading and hides the ambiguity from review.

  Secondary but real: emoji need variation-selector handling (`️`) in every regex that touches
  them, and they raise `UnicodeEncodeError` on a stock Windows cp1252 console — which cost four
  separate failures in one session.

  **THE ONE HOLDOUT IS RETIRED, AND IT LEFT BY MIGRATION RATHER THAN BY EDIT (BACKLOG #1250).** It was
  a machine-parsed contract: `docs/BACKLOG.md` and `docs/archive/backlog/BACKLOG-CLOSED.md` encoded
  item status as a banner alphabet, `scripts/docs/backlog_status_check.py` defined it, and
  `.github/workflows/backlog-hygiene.yml` quoted it. The PARSING went to the maintainer-internal
  repository on 2026-09-13 with the ledger itself.

  **TWO OF THOSE FOUR FILES ARE STILL TRACKED HERE, AND DELETING ONE OF THEM WEDGES EVERY PULL
  REQUEST.** This paragraph previously read "all four went", which invites a tidier to remove a merge
  gate. Measured 2026-09-16 with `git ls-files`: `BACKLOG-CLOSED.md` and `backlog_status_check.py` are
  gone, `docs/BACKLOG.md` is still tracked as a stub, and `.github/workflows/backlog-hygiene.yml` is
  still tracked **because its `name:` is a REQUIRED status-check context in branch protection**. The
  job itself is a deliberate no-op that prints why it has nothing to check. Deleting it, renaming it,
  or dropping either trigger makes the context never report -- and a required context that never
  reports does not fail, it WEDGES, in the queue and out of it. Retiring it is a branch-protection
  change, not an in-repo edit. That file's own header is the source of record; read it first.

  **SO NO GLYPH IN THIS REPOSITORY CARRIES MACHINE-PARSED MEANING ANY MORE, AND THE RULE ABOVE IS NOW
  UNCONDITIONAL HERE.** Nothing reads a status banner; nothing may start.

  **THAT IS NOT THE SAME AS THE GLYPHS BEING GONE, and the difference is the next person's trap.**
  Measured 2026-09-13, git-tracked files, after the move: the five former status glyphs still appear
  **557 times across 61 files** — 133 in `docs/FEATURE-MAP.md`, 124 in `docs/CONNECTIONS.md`, 63 in
  one benchmark status page, and a long tail. Every one of them is now plain decoration, which the
  rule forbids outright. They were tolerated only because a parser depended on them, and that parser
  is gone. **Removing them is a migration with its own item, not a doc edit** — the same standing this
  paragraph used to give the holdout — so do not start sweeping them out of files you are editing for
  another reason. **No NEW glyph vocabulary may be introduced anywhere.**

  **THE WARNING SIGN (U+26A0) IS NOT A SIXTH HOLDOUT — owner-ruled 2026-08-14, "not sanctioned".** It
  is in neither `_CLOSED` nor `_OPEN`, so `parse_items` ignores it and it carries no status semantics
  anywhere; it is decoration, which the rule above forbids outright. Retiring it is **BACKLOG #1265**,
  a filed migration, sliced by owner go (the 2026-09-30 ruling quoted below is the latest) — *not* a
  licence to edit lines outside a ruled slice, and not a cp1252 hazard (the cp1252 gate covers
  `scripts/**/*.py`, which contains none of them).

  **The measured population is recorded here so nobody re-derives the false zero that stalled this
  question once already. Re-censused over git-tracked files 2026-09-13, after the ledger left: 256
  occurrences across 67 files** — 172 under `docs/`, 37 in `docs/adr/`, 26 in `harness/`, 8 in
  `tests/`, 4 in `ide/`, 3 in engine source, 3 at the repository root, 2 in the web console, 1 under
  `.github/`, and **zero in `scripts/`**. 23 tracked files did not decode and were not counted.
  **Re-censused 2026-09-30 by codepoint: 223 across 48 files at `a4c42c86e9`, and 161 across 26
  after the live-docs slice below.** After the `CONFIGURATION.md` slice it read 154 across 24, at
  `cf9224acca`. The control `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` read 93 each time,
  and the same 23 undecodable files were skipped. 142 of the 154 sit under `docs/benchmarks/`.

  **The previous figure was 476, and 218 of those left with the ledger rather than being fixed.** That
  is the whole of the drop: `BACKLOG.md` carried 125 and `BACKLOG-CLOSED.md` 93. A migration is not
  remediation, and reading the smaller number as progress on #1265 would be wrong.

  Earlier slices were real, and `tests/test_operator_docs_no_warning_sign.py` pins each at zero or
  at a named ceiling: the five shipped operator docs — `SECURITY.md`, `PHI.md`, `INSTALL-GUIDE.md`,
  `DEPLOYMENT.md`, `CONNECTIONS.md`; every top-level `docs/adr/*.md` (PR 1604, 31 sites, with
  `README.md` finished later); and the live docs plus code comments and docstrings, 62 sites. That
  last slice rests on the owner ruling of 2026-09-30, given to the batch 183 Manager in session:
  *"the sweep extends beyond docs/adr/ to live docs and code comments. Dated benchmark and status
  records are exempt and must be named as exempt. The CLA and license banners are reviewed
  separately, not in this sweep."* What still carries the glyph is named in that test with its
  reason: `docs/benchmarks/` and `CHANGELOG.md` as dated records, `CLA.md` and
  `COMMERCIAL-LICENSE.md` for the owner's separate review, seven glyphs inside user-visible string
  literals, and test data in `tests/test_ledger_check.py`. `docs/CONFIGURATION.md` and
  `messagefoundry/config/settings.py` were held until BACKLOG #1504 landed, then swept, 7 sites.

  **Two rows of the filed table were instrument errors, both SDS-3.8, and they are kept because the
  errors recur.** It read the web console as zero by counting `packaging/`; the console's source is
  `messagefoundry_webconsole/`. And it had no `harness/` row at all, so 26 occurrences sat outside
  every bucket while the buckets still printed a confident total.

  **CENSUS THIS POPULATION WITH A POSITIVE CONTROL, AND THE OLD CONTROL IS GONE.** The first attempt
  ever made returned a false zero off a broken shell escape, and a pattern that finds nothing anywhere
  is indistinguishable from a clean repo. The control used to be the ledger's own counts; those files
  are no longer here. Use `docs/FEATURE-MAP.md` and `docs/CONNECTIONS.md`, which carry 133 and 124
  status glyphs: an instrument that cannot find those proves nothing by returning zero anywhere else.
  **Do not print a glyph to a Windows console while measuring** — a stock cp1252 terminal raises
  `UnicodeEncodeError` and kills the run mid-report, which happened during this very census.

## CLAUDE.md text moved in wave 3, kept verbatim

These blocks moved out of the root `CLAUDE.md` on 2026-10-08, word for word, for the reason the
two sections above give. `CLAUDE.md` keeps a short form of each rule and points here. One link
target was changed so it resolves from `docs/`.

Read each block as `CLAUDE.md` at `436cf5c657`. There, *above*, *below*, *this bullet* and a bare
section number mean `CLAUDE.md` and its sections, not this page. Where a block and `CLAUDE.md` now
disagree, `CLAUDE.md` wins.

### Three Lander bullets, from section 5

From *Branch, commit one layer, open the PR*. Korus `roles/LANDER.md` carries most of what they
say, but not all of it, so each is kept whole: the 2026-09-05 ruling's history and the
Console-by-substitution warning in the first, the corrected wording in the second, and the
stale-checks rule and the BACKLOG #1417 amendment in the third. Two bullets from the same
subsection were not copied. Korus `roles/MANAGER.md` holds the batching bullet in *When to cut a
pull request* and *A Builder in its own session opens its own pull request*. The announce
bullet's 2026-08-01 rehearsal is already stated above, under *At least six actions break the
fleet, so never take them*.

- **"Merge when ready" is the ENQUEUE action here. Arming auto-merge on a branch that would merge
  WITHOUT the queue stays forbidden, except for the Lander on a repository with no queue.** The
  Lander's roster row and its 2026-10-07 note say how (owner ruling 2026-10-07). What the button
  does was settled by **owner ruling 2026-09-05**, given when a seat stopped and asked rather than guess which of the two operations it
  was: `main` requires a merge queue, so the mutation behind "Merge when ready" adds a queue entry
  rather than merging on green.

  **WHO may press it changed with the Console's retirement on 2026-09-10: enqueuing and merging are
  BOTH the Lander's now.** A Manager does not enqueue, and that is not a narrowing of an old
  permission -- the seat that held it no longer exists, and korus `MANAGER.md` has never granted it.
  Hand the PR to the Lander once it is open, and leave the queue to it. Reading this bullet's
  earlier wording as *"the dispatching seat enqueues"* is exactly the Console-by-substitution error
  §5's retirement paragraph names. **CORRECTED 2026-09-23:** the sentence before it read *"Talk to
  the Lander before you open a PR"*. Korus `MANAGER.md` retired that pre-open check on 2026-09-18.

  **Dequeue before pushing.** Whether a QUEUED entry drops a later push is unmeasured. The hazard
  this bullet was written against, and why it is kept rather than deleted, is in
  [`METHOD.md`](METHOD.md).

- **The merge is the Lander's, and NO LABEL BLOCKS IT.** What blocks a merge is branch protection and
  the required contexts, nothing else. **The Lander checks for PROOF THAT CODE REVIEW RAN on the
  change (owner ruling 2026-09-29, in session).** Proof is a code-review tag on the PR, such as the
  Builder's QA line under the `qa` label. Other evidence that code review ran against this change
  also counts. With proof, the Lander does not need to review the diff. Without it, the Lander sends
  the change to code review: an `Agent` subagent that runs the `code-review` skill at `xhigh`. The proof must cover the change
  being merged. A review of an earlier head still counts after a push that only merges `main` in
  cleanly. A conflict resolution the Lander wrote itself needs its own review. So does a later
  commit that changes content. Read what the review found, not only that a tag exists: a label
  records that a step *happened*, not what it found. The Lander posts the review's findings on the
  PR. A finding that names a defect the merge would ship goes back to the owner for a ruling, as
  korus `roles/LANDER.md` *4a-quinquies* says. **CORRECTED 2026-09-29:** this bullet read
  *"Reading a diff before merging it is still the job; no check now asks whether you did."* The
  owner replaced it because the Builders already run code review.

- **A PR's merge state is a join over clocks, and the join is the part you must not miss.**
  `gh pr view <N> --json mergeStateStatus` is the starting read, never the verdict: it reports
  `BEHIND` or `DIRTY` in preference to `BLOCKED`, so it hides one blocking reason behind another.
  Poll the check RUNS for the contexts that are still required, and gate on `mergeable ==
  CONFLICTING` first: a PR that conflicts *after* its checks ran keeps them passing but stale.
  BACKLOG #1417 recorded the stale-payload defect and PR 731 was built against a workflow that no
  longer exists; see that item's 2026-09-04 amendment before acting on either.
