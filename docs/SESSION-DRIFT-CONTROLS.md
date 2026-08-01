# Session-drift controls — what we built, what it buys, and what to do next

**Scope.** This repo is developed by many concurrent Claude Code sessions against one `.git`. Over time
we accumulated a set of controls to stop those sessions colliding. This document inventories that
estate as **one system**, states which parts are actually enforcing, and records an audit of the gaps.

**Drift**, here, means four distinct failures, not one:

| # | Failure | Blast radius |
|---|---|---|
| D1 | A session **writes into the shared primary checkout** while others are standing in it | One file, one tree |
| D2 | A session **swaps the primary's working tree** (`checkout`/`reset`/…) | Every file, under every session, at once |
| D3 | A session **hijacks another session's worktree** onto a different branch | Every file under one other session |
| D4 | Two sessions **build the same work** independently | Duplicate PRs, untested merge |

D2 is the worst and the least intuitive: a write dirties one file; a branch switch replaces the entire
tree under everyone simultaneously.

Companion docs: [WORKTREES.md](WORKTREES.md) (how to use worktrees), [WORKTREE-GATE.md](WORKTREE-GATE.md)
(the gate's own design rationale and backout), [LEDGER-GATE.md](LEDGER-GATE.md) (the number space).

> **Fixed since this audit ran** — G2, G3, G7 and G12 are closed in the repo, and rule 4 is now opt-in
> (`install-gate.ps1 -EnterWorktreeGate`) so re-installing cannot activate it by accident. Each fixed gap
> is marked below.
>
> **They are not live yet.** The gate executes from an installed copy; none of it takes effect until, from
> a plain terminal:
>
> ```powershell
> pwsh -NoProfile -File scripts\worktree\install-gate.ps1
> ```
>
> `tests/test_gate_installed_parity.py` is **red until that runs** — deliberately. That test is the fix for
> G1, and the first thing it detected was itself.

---

## 1. The estate

Four layers. Only the middle two enforce anything.

### Prevention — `PreToolUse` hooks

**[`scripts/hooks/worktree_gate.ps1`](../scripts/hooks/worktree_gate.ps1)** (417 lines when this audit
ran; 609 after the fixes below) is installed at
**user scope** by [`install-gate.ps1`](../scripts/worktree/install-gate.ps1) into `~/.claude/settings.json`
*and* every `~/.claude-account-*/settings.json`. User scope is deliberate: a project-scoped hook is
git-tracked, so it lives on one branch and a worktree cut from an older base would carry no gate at all.
The registered command points at an installed **copy** under `~/.claude/hooks/`, because a hook whose
script path lives inside a working tree vanishes on a checkout — and a hook whose script is missing exits
non-zero-but-not-2, which means **the tool call runs anyway, silently**.

It carries five rules. `Write-Deny` exits, so **the first rule to fire is the only one that speaks** —
there is no defence in depth between them.

| Rule | Fires on | Keyed on |
|---|---|---|
| 1 | `Write`/`Edit`/`MultiEdit`/`NotebookEdit` targeting the primary's tree | **target path** |
| 2 | `Task`/`Agent`/`Workflow` dispatch from the primary | **session cwd** |
| 3 | 11 git verbs that swap or discard the primary's tree | target path parsed out of the command string |
| 3b | `checkout`/`switch` moving a *linked worktree* onto an existing branch | ditto |
| 4 | `EnterWorktree` (relocating a live session) | tool name only |

The single most important design decision is that **rules 1/3/3b key on the target, never on the cwd**.
The gate's own docstring records that 29% of Edit/Write calls came from a session *sitting* in the primary
that wrote *correctly* into a worktree by absolute path; a cwd-keyed gate would have denied all of them.
Rule 2 is the sole exception, and that exception is the source of the ultracode friction in §4.

**[`scripts/hooks/block-blanket-git-stage.ps1`](../scripts/hooks/block-blanket-git-stage.ps1)** (project
scope, [`.claude/settings.json`](../.claude/settings.json)) refuses blanket `git add -A`/`.`/`-u` and
`git commit -a`, so two sessions in one tree can't sweep each other's files into one commit.

### Detection — `SessionStart` hooks

**[`worktree-selfheal.ps1`](../scripts/worktree/worktree-selfheal.ps1)** (user scope) does one mutation —
auto-`checkout` of a **clean** primary that has drifted off its home branch — and two warnings: a
ghost-stub cwd, and this worktree's HEAD not matching its recorded home branch.

**[`session-context.ps1`](../scripts/worktree/session-context.ps1)** (project scope) injects the
coordination banner: which worktree this chat owns, the full worktree list, the shared-memory write rule,
and the open work claims.

### Coordination — commit-time gates (the D4 layer)

Frequently forgotten in discussions of "the gate", but it is the same problem class:

- **[`scripts/coord/claim.ps1`](../scripts/coord/claim.ps1)** — atomic exclusive-create of
  `<git-common-dir>/mefor-coord/claims/<key>.json`. Claims work, not numbers.
- **[`scripts/hooks/claim_check.py`](../scripts/hooks/claim_check.py)** — `commit-msg` gate: a commit whose
  *subject* declares `BACKLOG #N` with a code-touching diff must hold a claim on N **for this worktree**.
  Motivated by a recorded incident: three sessions independently fixed one npm advisory; two PRs were
  closed as duplicates and the one that merged had not tested the failure mode the others found.
- **[`scripts/coord/alloc.ps1`](../scripts/coord/alloc.ps1)** + **[`ledger_check.py`](../scripts/hooks/ledger_check.py)**
  — the same test-and-set for ADR/BACKLOG *numbers*. See [LEDGER-GATE.md](LEDGER-GATE.md).

Both use exclusive-create because a read-modify-write on a shared list silently lost 4 of 8 concurrent
writes when measured.

- **[`scripts/hooks/announce-session.ps1`](../scripts/hooks/announce-session.ps1)** — a
  `UserPromptSubmit` hook that closes the **push** direction of D4. Every control above is pull-based or
  commit-time: the peers of a new session learn nothing until someone trips a gate or writes a commit
  subject, which is too late for two sessions building the same *thing* in different files. This one
  hands the model its live peer roster plus the id-resolution rule at the first prompt that has intent
  to report, and asks it to introduce itself. It cannot send anything by itself — hooks cannot call MCP
  — so it is an instruction, and whether a message was actually delivered is recorded by the model in
  `sent/<key>.tsv`, not by the hook. See [WORKTREES.md](WORKTREES.md), "Announcing yourself".

### Recovery and lifecycle

`rescue.ps1` (move dirty primary work into a worktree), `restore-primary.ps1` (re-attach a detached
primary, refuses if dirty), `sessions.ps1 -Rehome` (find and re-file a relocated transcript), and
`new.ps1` / `spawn.ps1` / `remove.ps1` / `prune-merged.ps1`.

### Status table

Statuses below were established by driving crafted `PreToolUse` JSON into the **installed** hook and
reading the emitted decision — not by reading source alone.

| Control | Scope | Status |
|---|---|---|
| Rule 1 — write into primary | user | **LIVE** (probe-verified DENY) |
| Rule 1a — write to the gate's own script or allowlist | user | **NEW** — the kill switch sat outside every governed root, so rule 1 allowed an `Edit` to it |
| Rule 3c — `git config` that disarms the shared repo | user | **NEW** — `core.hooksPath` / `core.worktree` / `alias.*` / `include.path`; asks git for the common dir, so a *linked worktree* is covered too |
| Rule 3d — `git worktree remove` / `move` on another session's checkout | user | **NEW** — every other rule protects a tree from being *swapped*; this protects it from being *deleted* |
| Rule 2 — dispatch from primary | user | **LIVE** (probe-verified DENY) |
| Rule 3 — git verbs vs primary | user | **LIVE, partial** — the `-c` and relative-`cd` holes are fixed in source (G2/G3); enumerated-verb gaps remain (G9) |
| Rule 3b — worktree hijack | user | **LIVE but narrow** — 2 of 11 verbs, existing-local-branch destinations only |
| Rule 4 — `EnterWorktree` | — | **INERT BY DESIGN** — now opt-in behind `-EnterWorktreeGate`; was inert by accident (absent from the installed script *and* unmatched in all 5 config dirs) |
| Deny receipts (`worktree-gate.log`) | user | **NEW** — every deny logs rule/tool/cwd/detail; never the raw command |
| Installed-vs-source parity check | local test | **NEW** — `tests/test_gate_installed_parity.py`; skips on CI, red on a stale box |
| Blanket-stage guard | project | **LIVE but leaky** — 7 of 8 trivial rephrasings bypass it |
| Selfheal — primary auto-repair | user (4 of 5 dirs) | LIVE |
| Selfheal — hijack warning | user (4 of 5 dirs) | **LIVE and currently mis-firing** (§3, G4) |
| `session-context.ps1` banner | project | LIVE where the branch carries the file |
| Announce-on-join (`announce-session.ps1`) | user | **NEW** — the only **push** control; asks, cannot send, and every decision leaves a receipt |
| Announce wiring reaches a real script | test | **NEW** — `tests/test_announce_wiring.py`; nothing asserted this for *any* hook before, which is how a wired-but-inert shim survived weeks |
| Announce missing-script notice | user | **NEW** — the one surface that still reports when the script itself fails to resolve |
| Claim / alloc / ledger gates | git hooks | LIVE |
| `new.ps1` / `remove.ps1` / `prune-merged.ps1` | manual | LIVE, **sibling-layout only** |
| `tests/test_worktree_gate*.py`, `test_install_gate_wiring.py` | CI + local | Was **85 green, and blind** — every one bound the repo copy; nothing read the installed copy or any live `settings.json`. Now 91 across six files, plus the local-only parity check below |

Rule 4 being inert is **deliberate and announced** — the commit that landed it says "ships INERT …
nothing changes until `install-gate.ps1` is re-run." It is listed as INERT here because a control that
has never been installed is a source artefact, not an enforcement.

---

## 2. What it demonstrably buys

**Closed.** The accidental primary *edit* — the highest-frequency event and the gate's design centre — is
closed and probe-verified. So is the literal-spelling tree swap: `git checkout main` at cwd = primary,
`git -C <abs primary> checkout main`, `git -C ../../.. checkout zzz`, and `cd <abs primary> && git checkout main`
all DENY. Fan-out from the primary is closed for the three named dispatch tools. Duplicate-branch checkout
across worktrees is closed — though git enforces that one for free, so rule 3b fills a narrower gap than
its 73 lines suggest.

**Only nominally closed.**

*Shell writes into the primary.* The gate inspects tool arguments, so `Set-Content`, `python -c`, a
redirect, or `pip install -e .` into the primary is invisible to it. The gate's own header points at
`.git/hooks/pre-commit` as the backstop for this. That file is a stock pre-commit-framework shim
dispatching ledger-gate, ruff, forbidden-content, gitleaks and bandit — **none of which has a
primary/worktree predicate**. The backstop claim is unbacked as written. The only control on this path is
the deny text's "do not route around it with a shell command" — persuasion, in a repo whose whole premise
is that persuasion doesn't work here.

*Any agent-authored script defeats rule 3 entirely.* Rule 3 requires a `git` token in the command string.
`pwsh -File whatever.ps1` has none. This is not hypothetical or adversarial — `restore-primary.ps1` is a
sanctioned example of exactly this shape, and its header states outright that an agent may run it.

*Hijack detection.* Rule 3b covers `checkout`/`switch` onto an **existing local branch** only.
`git checkout <sha>`, `<tag>`, `origin/main` and `git reset --hard` inside another session's worktree all
return early. The selfheal detector meant to catch the residue is currently wrong (G4).

*Writes into another session's worktree are allowed — and advertised.* This is the unavoidable price of
keying on the target path, and the alternative is strictly worse. But rule 1's own deny text says
"Writes to any linked worktree … are allowed FROM THIS SESSION", so the gate actively teaches the
behaviour. The only counterweight is prose in the session banner, printed only when 2+ worktrees exist.

*Test coverage.* 85 tests pass. Every one binds the repo copy of the gate. Nothing anywhere reads the
installed copy or a live `settings.json`. This is the repo's own documented "green gate that cannot see"
pattern, reproduced inside the drift machinery itself.

---

## 3. Gaps

Ranked by expected harm × likelihood. G1–G4 survived an adversarial verification pass; the rest are
probe- or source-verified.

### G1 — Nothing can observe what is actually installed *(root cause)* — **FIXED IN SOURCE**

`install-gate.ps1` copies the script with no version, hash, or marker. `-Status` prints an **uncalibrated
count** of hook entries — it reports "3" where 4 is now expected, and states no expectation. Worse, the
`CLAUDECODE` refusal precedes the `-Status` branch, so **a session cannot audit the gate through the
supported interface at all**. Reverse drift is equally unseen: delete a rule from source and the stale
installed copy keeps enforcing it forever while every test correctly reports it gone.

Measured today: installed 23,430 B (Jul 24) vs repo 25,423 B (Jul 29). This is why rule 4 is inert, and it
will recur for the next rule.

### G2 — `cd` to the primary by a non-literal spelling defeats rule 3 — **FIXED**

Rule 3 resolves the target from cwd or `-C` only; `cd <primary> && git …` is caught solely by an in-text
scan for the allowlist root's canonical spelling. Rule 3b *does* resolve `cd`, then returns with the
comment "Rule 3 owns it" — but rule 3 already declined. Both bow out. And rule 3b only handles two verbs,
so for the other nine there is no hand-off at all.

Probe-verified ALLOW from a nested worktree, where `../../..` **is** the primary:
`cd ../../.. && git checkout main`, `… && git reset --hard origin/main`, `… ; git clean -xfd`,
`… ; git stash`, `… && git rebase origin/main`, `pushd ../../.. ; git restore .`,
`cd ~/Code/<repo> && git switch main`. `../../..` is the natural way for a session in a nested worktree
to name the repo root, so this is reachable **by accident**. [WORKTREE-GATE.md](WORKTREE-GATE.md) asserts
coverage of exactly this shape.

### G3 — `git -c <cfg>` redirects rule 3's target off the primary — **FIXED**

Rule 3 parses `-C <path>` with `-match`, which is case-**in**sensitive in PowerShell, so git's lowercase
global `-c name=value` is captured as if it were a path. `git -c core.pager=cat checkout main` at
cwd = primary → **ALLOW**. Rule 3b guards against precisely this with `-cmatch` and a comment explaining
why; the hardening was applied to the narrower rule and never back-ported to the one protecting the
shared tree.

Upstream hit the same class and fixed it: Claude Code 2.1.216 — *"Fixed worktree-isolated subagents
redirecting git into the shared checkout via `git -C`, `--git-dir`, or `GIT_DIR`/`GIT_WORK_TREE`."*
Note `--git-dir` and the env vars are absent from our gate entirely.

### G4 — The home-branch detector is wrong now, and it has no update path

`worktree-selfheal.ps1` compares HEAD against an untracked `mefor-home-branch` file. That file has two
writers (`new.ps1` at creation, selfheal's bootstrap-on-first-sighting) and **no update path**. `new.ps1`
only ever creates *siblings*, so for a nested `.claude/worktrees/<dir>` the record is whatever branch the
hook first saw — and re-tasking such a directory, which is the normal lifecycle, mismatches forever.

Live right now: this worktree records `…mefor-jdbc-support…`, HEAD is `…session-drift-prevention…`; a
second nested worktree mismatches too. Two of three. The printed remedy is a `git … switch <recorded>`,
which would swap a live session off its real branch — though it is conditioned on "if that was not
intentional", scoped to a plain terminal, and **rule 3b would deny it** if an agent tried. So the harm
channel is a human following stale advice, not in-session drift. No test mentions `mefor-home-branch`.

Note also a naming collision worth cleaning up: `mefor.homeBranch` (a git config key, read by
`restore-primary.ps1` and selfheal) and `mefor-home-branch` (an untracked file written by `new.ps1`) are
two different mechanisms one letter apart.

### G5 — The gate's own enforcement surface is writable by every governed session — **FIXED**

The live gate is `~/.claude/hooks/worktree_gate.ps1`; the kill switch is
`~/.claude/hooks/worktree-gate.repos.txt`; the matchers are in five `settings.json` files. **None of those
paths is under a governed root**, so `Test-Governed` returns null and rule 1 allows an `Edit`/`Write` to
any of them. There is no user-scope `permissions.deny` in any config dir. A one-line write to the
allowlist disarms the gate for every session on the box, permanently and silently.

The gate's header says the kill switch is "deliberately NOT named in the deny message: a model running in
`bypassPermissions` would use it." That is security by obscurity over a file one `ls` away. By contrast
`<primary>/.git/hooks` **is** governed by rule 1 already, and a test asserts it.

### G6 — The shared `.git` is unprotected against config-level disarm — **FIXED**

`config` is not in rule 3's verb list, so `git config core.hooksPath …` and `git -c core.hooksPath=… commit`
pass (probe-verified ALLOW) — disabling the ledger/claim/leak commit gates for **all eight worktrees at
once**. This is already biting passively: the installed `pre-commit` shim hard-codes an interpreter path
inside a *sibling worktree*, so that worktree is load-bearing for every tree's commit gates, and
`prune-merged.ps1 -Apply` on it would break commits everywhere.

Upstream draws this boundary explicitly — the worktrees documentation states that a worktree shares the
repository's `.git` and that sandboxing allows those writes, which is exactly why `hooks/` and config need
their own rule.

### G7 — Rule 1's deny message advertises the primary as a worktree to reuse — **FIXED**

The "worktrees that already exist — REUSE one if it is yours" filter compares a string to the
`PSCustomObject` returned by `Test-Governed`, so the comparison is always true and the primary is never
filtered out. The message refuses a write to the primary and then lists the primary first, displacing a
real worktree off the 8-item cap. This is the remediation channel — the part whose entire job is steering
the next action — and no test asserts on deny-text content.

### G8 — Two allowlists, two installers, no sync

The gate reads `~/.claude/hooks/worktree-gate.repos.txt`; the selfheal backstop reads
`~/.claude-hooks/worktree-gate.repos.txt`. `install-gate.ps1` rewrites its own unconditionally;
`install-selfheal.ps1` seeds the other only if absent. Adding a governed repo via one installer never
reaches the other, and `install-gate.ps1 -Uninstall` leaves the backstop armed and still willing to
`git checkout` the primary — so the "verified byte-for-byte clean uninstall" claim is true of the gate and
false of the estate. They agree today by luck.

Related: `install-selfheal.ps1` lacks the `CLAUDECODE` refusal its sibling has, and its source is
`$PSScriptRoot` — the calling session's own worktree copy, which that session may freely edit. The
**higher-privilege** component (it runs `git checkout` on the primary unattended) is the **less
protected** one. `~/.claude-account-2.lock` has the three gate matchers and no selfheal hook at all.

### G9 — Coverage is enumerated, so every hole is silent

Rule 3's verb list omits `rm`, `mv`, `sparse-checkout`, `checkout-index`, `bisect`, `worktree`,
`branch -f`, `update-ref`, `read-tree` — all ALLOW at cwd = primary. `worktree remove` is the notable one:
it destroys *another session's* checkout. `sparse-checkout` cannot match by construction (the pattern
requires whitespace before the verb; a hyphen precedes `checkout`). `gh pr checkout <n>` carries no `git`
token and exits early. Rules 1 and 2 key on tool *names*, so any tool not in those lists is unmatched at
**both** the settings matcher and the rule — the hook never runs, and nothing says so.

### G10 — False positives train sessions to route around the only control on the shell path — **FIXED**

The verb scan's exclusion class does not exclude newline, so `git status\necho about to merge stuff`
denies with verb=`merge` from prose on line 2. The git-detection class includes quote characters, so
`echo "git checkout main"` denies. A commit message containing a blocklisted word (`git commit -m
"chore: clean up dead code"`) denies. The sibling blanket-stage hook splits on newlines; this one does
not — **the two hooks disagree about what a command is**. Two read-only commands were denied during this
audit. Every false positive erodes compliance with the deny text, which per §2 is the *only* control on
shell writes.

### G11 — The two worktree layouts have diverged, and only one has teardown

`new.ps1` builds **siblings** (`<parent>/<repo>-<name>`). Claude Code's own `--worktree`, the desktop app,
and subagent isolation all build **nested** worktrees under `<primary>/.claude/worktrees/`. Both
populations are live (5 sibling, 3 nested). The gate's exemption and rule 3's third lookahead are written
for the nested form and their rationale comment asserts "that is exactly where `new.ps1` puts every
worktree" — false. No hole results (siblings fall outside the root prefix entirely), but the code
documents a reason that does not hold, leaving no correct model for the next edit. Meanwhile `remove.ps1`
and `prune-merged.ps1` are sibling-only, so the nested population — where every first-party session lands
— has creation but no scripted teardown, and `prune-merged.ps1` run from a worktree prints a green
"No sibling worktrees to consider" and exits 0. A wrong-cwd run reports a clean bill of health.

### G12 — The gate has never produced a receipt — **FIXED**

`Write-Deny` writes JSON to stdout and exits 0. There is no log, no counter, no audit file. Nothing can
answer "how many drift events were prevented last month", "is G10's false-positive rate 1/day or 1/1000",
or "did the fix change anything". Every severity ranking above — including "highest-frequency event" — is
therefore unfalsifiable. A deny-logging line is smaller than any other fix here and is the prerequisite
for ranking the rest.

### Considered and rejected

- **Bare-repo layout** (no primary working tree to drift into) — structurally the strongest answer, but
  `install-gate.ps1` derives the primary as the first `worktree list` entry and hard-requires
  `<path>/.git`, so the installer would abort; and the owner works in the primary by design.
- **WSL2 / containers / OS sandbox** — Anthropic's OS-level sandbox does not run on native Windows. This
  is the load-bearing constraint: a fail-open `PreToolUse` hook is not a lazy substitute here, it is the
  highest tier available without moving the whole stack.
- **Windows ACLs / restricted tokens** — principal-based, not process-based; needs dedicated local
  accounts, which would fork `~/.claude`, the account-N settings, the venvs and the credential stores.
- **`git worktree lock` as hijack prevention** — prevents prune/move/delete only; no option makes a
  worktree refuse a branch switch.
- **Native `Edit(<primary>/**)` permission deny** — deny beats allow with no exceptions, and
  `.claude/worktrees/` is nested inside that path, so it would block every worktree too. Viable only
  after a layout move, and it would lose the deny *text*, which is most of rule 1's value.
- **Device/UNC path bypass** (`//?/C:/…`) — real, probe-verified ALLOW, but requires a spelling no model
  produces by accident.
- **`reference-transaction` hook to pin a worktree to its branch** — the only mechanism found that could
  refuse a tree swap rather than a tool call, and the only one that would also cover the owner's own
  terminal. But it could not be demonstrated that `git checkout` routes its HEAD update through a
  transaction that fires the hook, and the hook sits on the path of every fetch/commit/rebase. Worth a
  timeboxed spike that fails on purpose first; not worth a build on present evidence.

---

## 4. Is this limiting ultracode?

**Yes — rule 2 is, and it is the only rule that does. But the limitation is narrower than it has been
recorded as, and the correct response is not to weaken it.**

**The mechanics.** Rule 2 denies `Task`/`Agent`/`Workflow` **only when the session's cwd is a governed
primary**. `Test-Governed` exempts `<primary>/.claude/worktrees/…`, and sibling worktrees fall outside
the root entirely — so **dispatch works from every worktree, nested or sibling**. What is blocked is a
Workflow launched from a session hand-started in the primary. Because the owner runs many VS Code windows
and opens the primary himself, that collision is frequent enough to *feel* like a general prohibition,
which is how it got recorded as "an ultracode Workflow CANNOT launch there". That reading is too broad.

**But rule 2's stated premise has expired.** The rule's rationale is that a subagent "inherits the
parent's cwd, cannot create a worktree for itself, and its denied edits do not reliably surface to the
parent."

The middle clause is now **false**, on first-party evidence:

- The `Agent` tool exposes `isolation: "worktree"`, documented as "creates a temporary git worktree so the
  agent works on an isolated copy of the repo."
- The worktrees documentation: *"Subagents can run in their own worktrees so parallel edits don't
  conflict… add `isolation: worktree` to its frontmatter."* Claude Code also runs `git worktree lock` on
  an agent's worktree while it is live, and sweeps it afterwards.
- Two changelog entries confirm it is a maintained surface: 2.1.210 (`isolation: 'worktree'` subagents
  running git against the main checkout — fixed) and 2.1.216 (the `git -C` / `GIT_DIR` redirection fix).

The first clause (cwd inheritance) still holds by default. The third — the empty `permission_denials`
list — is an **undocumented one-off observation**, and it is precisely the half that justifies a *deny*
rather than a warning. It has never been re-measured.

**And rule 2 is leaky, so it pays the cost without buying the benefit.** It matches three tool names.
`Skill`, `spawn_task`, `CronCreate` and `RemoteTrigger` all start work and are unmatched at both the
settings matcher and the rule (probe-verified ALLOW at cwd = primary). A session in the primary that
wants fan-out can get it under another name; the rule mostly stops the *sanctioned* path.

**Recommendation on rule 2 — keep the deny, fix the cause, don't broaden it blindly.**

- **Keep it, but know what it is now worth.** Measured (§6): rule 1 already denies a subagent's writes
  into the primary on target path, the denial surfaces loudly rather than silently, and the receipt records
  it against the subagent's pid. So rule 2 is no longer the only thing between a primary-resident dispatch
  and silent loss — its remaining value is failing **fast**, at the parent, before a long fan-out rather
  than after. That is worth something; it is not worth what the deny text claims. Revisit deny-vs-warn.
- **Do not add `Skill` to it.** That would block every slash command and skill invocation — `/code-review`,
  `/security-review`, this repo's own skills — from a session the owner opened deliberately. `spawn_task`
  is also wrong: it creates an advisory chip the user clicks; nothing inherits cwd until they act.
  `CronCreate`/`RemoteTrigger` are the only defensible additions.
- **Remove the friction at the source** rather than at the deny: make worktree-first the default entry
  point (§5, B6), so a primary-resident session is the exception rather than the normal case.
- **Do not install with `-NoDispatchGate`.** It drops the rule with no runtime trace, so a session cannot
  tell whether rule 2 is live — G1 all over again.

**Recommendation on rule 4 (`EnterWorktree`) — do not install it. Retire it.**

The compounding argument in [WORKTREES.md](WORKTREES.md) is correct and is the decisive one: with rules 2
and 4 both live, a primary-resident session has **no in-session path to isolation at all**. It cannot
dispatch, and it cannot relocate. It must be re-started elsewhere by a human. That is a hard stop on
workflow-by-default from the directory sessions naturally open in.

Three further facts, all first-party:

1. **The transcript relocation is designed behaviour, not a bug.** Since v2.1.198: *"When Claude enters or
   exits a worktree that Claude Code created with git, the transcript follows: Claude Code records the
   session under the session's new working directory, the same way `/cd` does, so `/desktop` and
   `--resume` find it there. Exiting moves it back the same way."* Nothing is lost — the session is
   **re-filed, and findable by `--resume`**. The residual is a session that *ends* while still inside,
   which is a discoverability problem, and `sessions.ps1 -Rehome` already cures it.
2. **Upstream added its own guard where the risk is real.** Since v2.1.206, `EnterWorktree` into a path
   **outside** `.claude/worktrees/` raises a confirmation prompt that no permission rule or "don't ask
   again" can suppress — only `bypassPermissions` skips it. Our rule 4 would duplicate that for the
   outside case and add a prohibition for the inside case, which is where every first-party worktree
   lives and where the prompt was deliberately omitted.
3. Installed build is 2.1.217, so both behaviours are present today.

**One caveat to carry:** a worktree created by a `WorktreeCreate` hook *keeps its transcript at the launch
directory* — so if we ever adopt such a hook to relocate worktrees (§5's rejected layout move), this
analysis must be redone.

---

## 5. Better ways — ranked

### Do this

| # | Change | Closes | Effort | Wedge risk |
|---|---|---|---|---|
| **B1** | **Make the installed state observable.** A test that skips unless the installed gate exists, then asserts SHA-256 equality with the repo copy *and* that the union of live `PreToolUse` matchers supersets the gate's handled-tool list. It must **print what it scanned**, so a skip never reads as a pass, and it should emit a liveness receipt through the existing `scripts/quality/liveness.py` machinery rather than becoming a fifth blind local test. Add a `$GateVersion` to the gate; have `-Status` print the rule inventory and per-dir matchers against an **expectation**, not a bare count. Move the `CLAUDECODE` throw **below** the `-Status` branch so a session can audit but not install. | G1 | S | none |
| **B2** | **Log every deny.** One append to `~/.claude/hooks/worktree-gate.log`: timestamp, rule, tool, cwd, target, decision. | G12 | XS | none |
| **B3** | **One target-resolution helper, shared by rules 3 and 3b.** Parse `-C` **case-sensitively** (`-cmatch`, as 3b already does), then `cd`/`pushd`, then cwd; canonicalise; `Test-Governed` that. Invert 3b's early return: when it resolves the acted-on tree to the primary, **deny with rule 3's message** instead of bowing out. Add `--git-dir`, `--work-tree`, `GIT_DIR=`, `GIT_WORK_TREE=`. | G2, G3 | S/M | low — widens denials, so ship with B4 |
| **B4** | **Stop deciding from prose.** Exclude newline from the verb-scan class; drop quote characters from the git-detection class; strip quoted string literals before scanning. Share one "split into simple commands" helper with the blanket-stage hook so the two cannot disagree. Add ALLOW-asserting tests for a multi-line command, an echoed command, and a commit message containing a verb word. | G10 | S | none (strictly reduces denials) |
| **B5** | **Govern the gate's own surface.** Add `~/.claude/hooks/` and every wired `settings.json` to the governed set (or a user-scope `permissions.deny` on those paths). Add `config` to rule 3's surface: deny `core.hooksPath` / `core.worktree` / `alias.*` writes and `-c core.hooksPath=` overrides from any governed tree. Make `pre-commit install` use a repo-relative interpreter so no sibling worktree is load-bearing. Must not block the installers — gate on `CLAUDECODE`. | G5, G6 | S/M | low |
| **B6** | **Worktree-first as the default entry point.** Adopt `claude --worktree` / desktop auto-worktrees as *the* documented way to start a build session. Add a `.worktreeinclude` (none exists — `new.ps1` hand-copies the gitignored token list for exactly this reason). Use `isolation: worktree` on file-editing subagents. This is the field-standard answer and the only durable win: it reduces how often any rule has to fire. | reduces D1/D2 rate | S/M | low |
| **B7** | **Retire rule 4; add only `CronCreate`/`RemoteTrigger` to rule 2.** Correct the memory entry in the same commit or the next session re-adds the rule. **Note the doc numbering collision:** [WORKTREES.md](WORKTREES.md) calls the `EnterWorktree` rule "Rule 3" while the code's rule 3 is the git-verb rule — a commit saying "delete rule 4" will not match the doc it must also edit. | §4 | S | low |
| **B8** | **Fix the home-branch record, or delete it.** `extensions.worktreeConfig` is already on, so record intent as `git config --worktree mefor.homeBranch <ref>` — the key that already exists — instead of the untracked `mefor-home-branch` file. Better still, read the registered branch from `git worktree list --porcelain`, which is authoritative and needs no sidecar. Either way, **stop printing a `git switch` command** — downgrade to "ask the user". Add tests for absent / matching / re-tasked / genuinely-switched. First settle the design question underneath it: **is re-tasking a nested worktree directory legal?** If yes, the record is wrong by design; if no, the missing teardown (G11) is the actual bug and G4 is a symptom. | G4 | S | medium if left as-is |
| **B9** | **Fix the deny message.** Compare `$root.Compare`, not the object; assert in a test that the primary's path never appears under "worktrees that already exist". | G7 | XS | none |
| **B10** | **Collapse the two allowlists; harden the second installer.** One allowlist path referenced by both scripts; `-Uninstall` removes it; give `install-selfheal.ps1` the `CLAUDECODE` throw, the multi-config-dir discovery loop, a `-Status` and an `-Uninstall`. Extend B1's check to assert the set of dirs carrying a gate matcher equals the set carrying the selfheal hook. | G8 | S | none |
| **B11** | **Close the verb and teardown holes.** A second alternation for hyphenated/two-token forms (`sparse-checkout`, `worktree remove|move`, `branch -f`, `update-ref`, `read-tree`, `rm`, `mv`, `checkout-index`, `bisect`), with its own message for `worktree remove` (cross-session destruction, not a tree swap); teach the detector about `gh`. Give `prune-merged.ps1` a **loud failure** when its root is not the primary instead of a green no-op, and add nested-worktree teardown. Correct the false rationale comment. | G9, G11 | M | low |

**Status**, stated exactly — an overstated one here is worse than none, because the next session acts on it.

| | State | What is actually true |
|---|---|---|
| B2, B9 | **Done** | Receipts (sanitised, one record per line, retried under contention) and the deny-message fix, with tests. |
| B1 | **Mostly done** | Parity check, `-Status` audit, `-EnterWorktreeGate` opt-in. **Not** done: it emits no liveness receipt through `scripts/quality/liveness.py`, so on CI it is three honest skips rather than a tracked result. |
| B3 | **Mostly done** | Shared resolver, case-sensitive `-C`, `cd`/`pushd` from the prefix only, `--work-tree` / `GIT_WORK_TREE` / `--git-dir` as additional candidates. **Not** done: `GIT_DIR=` is unhandled. Rule 3b's early return is now moot — both rules resolve through the same function — rather than literally inverted. |
| B4 | **Mostly done** | Per-line scanning, continuation folding, interpreter-argument recursion, quoted spans blanked. **Not** done: the split helper is still not shared with `block-blanket-git-stage.ps1`, so the two hooks can still disagree about what a command is. |
| B5, B8 | **Done** | Rules 1a and 3c: the gate's own script and allowlist are governed, and the `git config` keys that disarm the shared repo are denied from any worktree. **Not** done: `~/.claude/settings.json` is deliberately left writable — the `update-config` skill exists to edit it, and blocking it would break a supported workflow to close a hole needing a far more deliberate act. |
| B7 | **Half done** | Rule 4 is opt-in, not retired — preserving the owner's decision while removing the trap where re-installing would activate it. |
| B10 | **Done** | One allowlist, shared by the gate and the backstop, with the legacy path kept as a fallback so a version-skewed installed copy cannot silently disarm the backstop. `install-selfheal.ps1` gained the `CLAUDECODE` refusal its sibling always had — the *higher*-privilege installer was the unprotected one. |
| B6 | **Started** | `.worktreeinclude` added, so the leak gate's gitignored token list reaches every worktree Claude Code creates itself (`--worktree`, desktop sessions, `isolation: worktree` subagents) — previously only `new.ps1`'s own worktrees got it, and a fresh first-party worktree could not commit at all. **Not** done: worktree-first as the documented default entry point, and `new.ps1` calling `git worktree lock` while a session is live. |
| B11 | **Started** | Rule 3d closes the worst of G9: `git worktree remove` / `move` on another session's checkout. **Not** done: the rest of the absent verbs (`rm`, `mv`, `sparse-checkout`, `checkout-index`, `bisect`, `branch -f`, `update-ref`, `read-tree`), `gh pr checkout`, and G11's teardown half — `prune-merged.ps1` is still sibling-only and still prints a green "nothing to consider" when run from the wrong cwd. |

Remaining order: the rest of B6, the rest of B11, then the B1/B3/B4 remainders.

Each shipped fix was proved to catch its own regression by mutation — five mutations applied to the shipped
script one at a time, all five went red — and an adversarial review of the first attempt found three
regressions it had introduced, since fixed and pinned by
[`tests/test_worktree_gate_shell_semantics.py`](../tests/test_worktree_gate_shell_semantics.py).

One caveat carried forward: **none of the merged work is live until the gate is re-installed.** That is the
same property that made rule 4 inert, now with a test watching it.

### Considered, not worth doing now

| Idea | Why not |
|---|---|
| Move worktrees to a sibling root and express rule 1 as a native permission deny | Mechanically sound and removes a PowerShell process per tool call, but `--worktree`, the desktop app and subagent isolation all default to `.claude/worktrees/`. Relocating them needs a `WorktreeCreate` hook — which makes transcripts stay at the launch directory and disables `.worktreeinclude`, re-opening what B6 and B7 close. |
| A commit-time drift rule on `pre-commit` | Would make the backstop claim true and catches shell writes route-agnostically, but fires after the damage and needs a discriminator to avoid blocking the owner's own commits in the primary. **Minimum action instead: delete or caveat the unbacked backstop sentence** in the gate header and `install-git-hooks.ps1`. An unbacked backstop is worse than an admitted gap. |
| Bare repo / WSL2 / containers / ACLs / `worktree lock` / `reference-transaction` | See §3 "Considered and rejected". |

---

## 6. Method and provenance

Produced by a 22-agent adversarial workflow: 5 mapping agents (68 controls inventoried), 3 web-research
agents, 4 adversarial lenses (52 findings), 8 refutation agents over the high-severity findings
(7 confirmed, 1 downgraded), a synthesis pass and a completeness critic. Behavioural claims about the gate
were established by **piping crafted `PreToolUse` JSON into the installed hook and reading the emitted
decision**, not by reading source.

**Verified fresh:** 85 tests pass; installed vs repo gate sizes and dates; the absence of an
`EnterWorktree` matcher in all five config dirs; the asymmetric `.claude-account-2.lock`; both allowlists'
contents; `extensions.worktreeConfig=true`; 3 nested + 5 sibling worktrees; Claude Code 2.1.217; the
2.1.198 / 2.1.206 / 2.1.210 / 2.1.216 behaviours (official docs + changelog); `isolation: worktree`
(tool schema + docs).

**Measured fresh, 2026-07-29, and it corrects a load-bearing claim.** Rule 2's third justification —
"a subagent's denied edits do not reliably surface back to you, so the fan-out would appear to succeed
while writing nothing" — was one undocumented observation. It was tested directly: a subagent was
dispatched from this worktree and instructed to make exactly one `Write` into the primary.

| | Result |
|---|---|
| Did the subagent inherit the parent's cwd? | **Yes** — it reported this worktree. Premise holds. |
| Did the write land? | **No.** Rule 1 denied it; `ls` confirmed the file was never created. |
| Did the denial surface? | **Loudly.** The subagent received the full deny text, reported it verbatim, and continued working. It did *not* silently report success. |
| Could the parent detect it independently? | **Yes — now.** The deny left a receipt stamped with the subagent's own pid. |

Two consequences. First, **rule 1 already contains a fan-out from the primary** — the subagent's writes are
denied on target path regardless of where the parent sat, so the "appears to succeed while writing nothing"
scenario requires a subagent that swallows an explicit hard error. Second, **the receipt closes the
observability gap rule 2 was built to work around**: a parent can now read the log and see exactly what its
subagents were denied, which is precisely what the empty `permission_denials` list failed to provide.

Rule 2's remaining value is therefore narrower than its deny text claims — it fails *fast*, at the parent,
before a long fan-out rather than after — but it is no longer the only thing standing between a
primary-resident dispatch and silent data loss. That is a reason to revisit whether it should be a deny or
a warning; it is not, on this evidence, a reason to keep it at deny by default.

Also confirmed live in the same probe: the primary is **no longer offered** in the deny message's
"worktrees you could reuse" list (G7's fix, in production). Still open: that list names *other sessions'*
worktrees, which the gate explicitly permits writing into.

**Cited, not re-measured — treat with care:**

- **"29% of Edit/Write calls landed in a worktree; 44% in the primary; 166 sessions over 30 days."** From
  the gate's own docstring. This is the *sole* quantitative justification for the target-keyed design.
  Nothing in the repo lets it be recomputed, and nobody has asked whether it still holds.
~~**"A subagent's denied edits came back with an empty `permission_denials` list."**~~ **Superseded** —
  re-measured above. The denial surfaces clearly to the subagent, the write never lands, and the receipt
  now records it against the subagent's pid.

The 29% / 44% figures still deserve a re-measurement before the next round of changes; nothing in the repo
can recompute them.
