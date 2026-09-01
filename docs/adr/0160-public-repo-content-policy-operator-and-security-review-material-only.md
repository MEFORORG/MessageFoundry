# ADR 0160 — Public-repo content policy: operator and security-review material only

- **Status:** **Accepted (2026-08-06). Phase 1 EXECUTED; Phase 2 ACCEPTED 2026-08-31 WITH PRECONDITIONS, reversing the 2026-08-06 decline; Phase 3 still Proposed; Phase 4 EXECUTED 2026-08-31, merged 2026-09-01. Phase 2's preconditions MEASURED 2026-09-01 and NOT met -- P1 and P2 both fail today, and P3 carries a landmine; see D5.**
  The owner ratified the D1 test and Phase 1 on 2026-08-05, chose the vault as the destination
  (resolving open question 3), and set a governing rule for the work: **do not break anything**,
  applied per item as *prove the mechanism or leave the item alone*. On 2026-08-06 the owner
  **declined Phase 2** — the process tooling and the documents describing it stay tracked, on the
  cost measurement in D5. That is a decision, not a deferral: nothing is pending that would reopen
  it. Phase 3 (stripping process prose from documents that stay) is untouched by this and remains
  proposed.
  
  **REVERSED 2026-08-31 (owner).** Asked to choose between this ADR and a restated content policy,
  the owner ruled: *"use today's decision, but add what's needed to the vault to address whatever was
  behind 0160."* So Phase 2 proceeds and the process tooling moves. **D5 is overridden, not
  discarded** — its three measurements were correct and become PRECONDITIONS, listed in D5 below.
  Each must be satisfied before anything is removed from this repository. The 2026-08-06 decline is
  left in place rather than deleted, because it was live for three weeks and a reader who remembers
  it needs to see it named as reversed rather than silently absent.

  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-08-04
- **Supersedes nothing.** Records a policy that has been in force, and enforced, while being written
  down nowhere.

## Context

**The policy exists and was unrecorded.** The owner stated it twice in one working session
(2026-08-04): the public repository should carry only what someone **running** MessageFoundry needs,
plus what a **security review** needs — ADRs named explicitly as belonging to the second category —
and material about **how the project is built with Claude Code** should come out. Two narrower rulings
came with it: remove Claude-Code plan-usage material, and stop citing `login.microsoftonline.com`.

**None of that was in the repository.** A session grepped every local and remote ref for it and found
nothing. That is the defect this ADR fixes, and the reason it is filed at all.

⚠️ **It was enforced before it was recorded, and that is the part worth naming.** The coordinating
session cited this policy as a constraint on four other sessions' work while it existed only in one
conversation. That is precisely the standing that same session had **refused** from a peer earlier the
same day — declining to arm a PR on a relayed owner ruling — so the rule was applied to others and not
to itself. An unrecorded policy enforced across isolated sessions is indistinguishable, to the session
receiving it, from an invented one. **Until this ADR is ratified, treat the application below as
context, not constraint.**

**Why the question arose now.** Before the 2026-07-27 cutover ([ADR 0130 lineage](README.md), memory
`mf-public-mirror`), a publish pipeline stripped non-public content on the way out, so the question
"does this belong in public?" was answered by a deny-list at publish time. That pipeline is retired.
Development now happens **directly in the public repository**, and the deny-list's job passed to
`.gitignore` — which means the question is now answered **per file, at authoring time, by whoever is
writing**, with no gate and no written rule.

### Measured state, 2026-08-04 at `c90dcb5f`

Counts are from `git ls-files` and `git check-ignore -v`, not from recollection.

| Surface | Tracked | Status |
|---|--:|---|
| `docs/` total | 580 | mixed |
| `docs/adr/` | 156 | **stays** — owner named ADRs as security-review material |
| `docs/releases/` | **101** | the largest concentration of process material; most are `*-MULTISESSION-PLAN.md` |
| `scripts/` | 61 | mixed; `coord/`, `hooks/`, `worktree/` are process tooling |
| `.github/` | 31 | operator-irrelevant but CI-load-bearing |

Already excluded, each by an explicit `.gitignore` rule: `.claude/`, `/docs/security/` (`:144`),
`/docs/reviews/` (`:145`), `/docs/marketing/` (`:146`), `docs/CI-TOPOLOGY.md`, `TRANSCRIPTS.md`.

**Tracked today and squarely process material:** `CLAUDE.md`, `docs/WORKTREES.md`,
`docs/SESSION-DRIFT-CONTROLS.md`, `docs/LEDGER-GATE.md`, `docs/STEERING.md`, plus Claude-Code
references inside `docs/AI.md`, `docs/ARCHITECTURE.md`, `docs/BACKLOG.md` and
`docs/Code_Quality_Standards.md`.

## Decision

### D1 — The test, and it is owner-stated

A tracked file must satisfy at least one of:

1. **An operator running MessageFoundry needs it** — install, configure, connect, route, transform,
   monitor, secure, upgrade, troubleshoot.
2. **A security reviewer assessing MessageFoundry needs it** — threat model, controls, decisions and
   their rationale. **ADRs are in this category by the owner's explicit statement.**

Material whose subject is **how this project is developed** — session orchestration, worktree
mechanics, coordination protocol, ledger process, plan documents, prompt and usage practice — fails
both and comes out. The subject is what matters, not the vocabulary: a document is not process
material because it mentions a tool, and it is not operator material because it mentions a connector.

### D2 — Application, proposed, in phases, and each phase is separately reversible

**Phase 1 — `docs/releases/` (101 files). EXECUTED 2026-08-05.** Predominantly multisession plans:
work breakdowns, wave schedules, per-session briefs. No operator or reviewer reads these. Removed
from the public repo and preserved in the vault.

Scope grew by **two files** during execution: `HANDOFF-344-instance-2.md` and `HANDOFF-ha-recheck.md`
were tracked in the **repository root** — session handoffs in the project's front door. They are
covered by a `/HANDOFF-*.md` rule rather than by their two filenames, so the next one fails closed
instead of waiting to be noticed. **103 files** in total.

⚠️ **A 104th followed, and the shape is the lesson.** `docs/releases/HANDOFF-232-router-steps.md`
entered `main` via **PR #225** *while the Phase 1 PR was open*. Phase 1 removed 101 paths **named
individually**, so a file created after that commit was built was never in the list — and a
`.gitignore` rule **does not untrack**, so `/docs/releases/` left it behind and the directory came
back holding one file. Removed in the follow-up that also records this paragraph.

**A removal that enumerates paths has a window, open for exactly as long as the PR is, during which
the directory it is clearing can be refilled.** Nothing detected this: it surfaced only because the
merge conflict forced a re-read of the tree. If a future phase clears a directory, re-check it at
merge time rather than trusting the file list computed when the branch was cut.

**Order of operations, and it is the load-bearing part.** Custody moved to the vault
(`wshallwshall/MessageFoundry`) and was committed there **before** anything left the public tree.
Gitignoring alone would have left 103 files as single **unversioned** copies — no history, no
backup, erased by `git clean -xdf`. "Move to the vault" and "gitignore" are not alternatives: the
first provides durability, the second keeps the paths working in place. Both were done.

⚠️ **The inbound-citation surface is 23 files, and a single grep finds at most two thirds of it.**
Measured at `c90dcb5f`, excluding the directory itself:

| Citation form | Files | Note |
|---|--:|---|
| `docs/releases/...` | 12 | the form most people grep for |
| relative `(releases/...` or `../releases/...` | 15 | **invisible to the grep above** |
| **union** | **23** | neither form alone is sufficient |

This is not a footnote about method — it is the constraint. An earlier draft of this ADR named
**one** file, `docs/FEATURE-MAP.md:5` and `:13`, because that is what the notes carried. Those two
citations are real (`[v0.1 Release Plan](releases/v0.1-PLAN.md)` and a `[plan](...)` table cell) and
they use the **relative** form, so a `docs/releases` grep does not see them — while 22 other files
do cite the directory. **Grep both forms, or the removal lands dangling references in files nobody
checked.** `docs/README.md` is among them, so the docs front door breaks.

**Re-measured at execution (2026-08-05), and the shape held but the numbers did not.** The union is
**25 files / 52 citation lines**, of which **37 are markdown links** — the ones that actually 404.
The rest are bare path mentions in prose. Only the links were rewritten (to the document's plain
name); bare mentions in archived records were left alone, because there they narrate where a plan
lived at the time, and rewriting archived history is the worse defect. `docs/README.md`'s
directory row was **deleted** rather than unlinked — the directory is gone, so an unlinked row would
have described something absent.

⛔ **Phase 1 CANNOT be docs-only — and the recorded reason was the weak one.** The earlier draft
rested this on three non-doc files citing the path. Two of those three are **comments**
(`tests/test_lint_scope_parity.py:22`, `harness/load/profiles/closed-loop.toml:7`), and the third
behaves opposite to how it was described: `tests/test_cutover_slug_rot.py:53` carries
`"docs/releases/"` in `_HISTORICAL`, which is an **exclusion** list, so those 101 files were never
scanned and the prose ratchet (54) cannot move when they leave. That draft would have had the PR
depend on comment edits it might reasonably have dropped.

The real cause is structural and cannot be dropped: **the removal mechanism IS a `.gitignore`
change**, and `.gitignore` is deliberately excluded from ci.yml's docs-only allowlist (BACKLOG #327,
because `tests/test_private_paths_stay_ignored.py` is the guard for exactly those rules and runs
only under pytest). So `code=true` follows from the mechanism itself, not from which incidental
files a phase happens to touch. **Confirmed on this PR rather than assumed.**

⚠️ **`tests/test_feature_map_claims.py` is the guard for dangling links, and gitignore-in-place makes
it BLIND LOCALLY.** It resolves each relative link against the **filesystem**. Under this decision the
removed files are still **on disk** (ignored, not deleted), so in any working tree the targets still
`exist()` and the check passes on links that would 404 for a reader. Measured while executing Phase 1:
a `releases/` link re-introduced into `docs/FEATURE-MAP.md` **passed** in the working tree and
**failed** — correctly, naming file and line — when the same tree was exported with `git archive`
(tracked files only, which is what CI checks out).

The gate is not broken and needs no change; its scope is now narrower than it looks. **Do not read a
local green on this test as evidence.** Verify a link-affecting change against a tracked-files-only
checkout — **`git clone --no-hardlinks . <tmp>`, and NOT the `git archive $(git write-tree)` export
this paragraph originally prescribed.** An archive carries no `.git`, which is fine for a guard that
tests the filesystem (this one) and wrong for any guard that shells out to `git`; P4 below records
what that cost a later reviewer. Use the clone for both and the distinction stops mattering. The same
caveat applies to any future guard that tests *existence* rather than *trackedness* — after this
decision, presence on disk and presence in the repository are different facts.

**Phase 2 — REVERSED. DECLINED 2026-08-06, then ACCEPTED 2026-08-31 (owner), subject to the preconditions in D5. The process tooling and its documentation MOVE.**
The proposed set was `docs/WORKTREES.md`, `docs/SESSION-DRIFT-CONTROLS.md`, `docs/LEDGER-GATE.md`
and `docs/STEERING.md`, plus — added during Phase 1 planning — the tooling those documents describe.
**It moves, once D5's preconditions are met.** The paragraph below is the 2026-08-06 reasoning, kept as the record of why this was declined for three weeks. The reasoning is in D5, and it is a cost decision resting on a measurement, not
a deferral waiting on someone. Keeping the documents with the tooling they describe is the coherent
half: relocating the rationale for a control that stays is the defect the Consequences section below
already names.

**Phase 3 — in-file references.** Strip Claude-Code process prose from documents that otherwise stay
(`docs/AI.md`, `docs/ARCHITECTURE.md`, `docs/Code_Quality_Standards.md`). Surgical edits, not removals.

**Phase 4 — business material and internal engineering records (46 files). EXECUTED 2026-08-31,
merged 2026-09-01 as PR 714; `main` at `921db74a1`.** Verified by CONTENT rather than by the pull
request reporting merged: on `main` afterwards, `docs/research` holds 0 files, `docs/testing` holds
exactly 1 (`VERIFY.md`), `docs/design` holds 4, and `docs/BRAND.md` is absent. Two sets Phase 1 did not reach, on an owner ruling the same day. Six business and legal
working documents (brand, positioning, the dual-licensing plan, the counsel engagement brief, the
contributor program and its first-issues list), 25 files of `docs/testing` maintainer QA planning,
nine `docs/research` exploratory notes, and six superseded `docs/archive/throughput` plans. All fail
D1 both ways: the audience is a maintainer deciding project direction or planning QA, not an operator
running the engine or a reviewer assessing it.

**D1 CATEGORY 2 GOVERNS OVER A WIDER READING OF "SECURITY MATERIAL COMES OUT", and the question was
put and answered rather than left implicit.** The owner was asked directly whether a restated policy
sending all security material to the vault should override D1's second limb. It does not.
`SECURITY.md`, `PHI.md`, `SUPPLY-CHAIN.md`, `SECURITY-LOOSENING.md`, the ASVS phase inventory and the
`Secure_*` standards are what a reviewer reads to assess the engine, so they stay.
`docs/SECURITY-DOCS-POLICY.md` continues to state that boundary publicly and was not touched.

**Two carve-outs, both found by measurement AFTER the set was drafted**, which is the argument for
measuring rather than reasoning from a directory name:

* `docs/testing/VERIFY.md` STAYS. It documents `messagefoundry verify`, the wheel-only on-box
  acceptance check a real deployment runs, and `docs/README.md` lists it as step 6 of the
  new-operator path while warning in terms that it "is an operator tool, not a test plan". It passes
  D1 category 1 outright. This is why its rule is `/docs/testing/*` and not `/docs/testing/`: git
  does not descend into an excluded directory, so a directory rule makes the negation a silent no-op.
* `docs/design/` STAYS, and was in an earlier draft of the set. `docs/design/freethread.md` is a
  CLAIM FILE for the required-status-check drift guard, and `tests/test_required_contexts.py` treats
  a missing claim file as an ERROR rather than a skip — deliberately, because silently dropping a
  claim file is how a drift guard comes to guard nothing. Untracking it turns that guard's own
  anti-narrowing assertion red.

**THE INBOUND-LINK SURFACE WAS THE DEFECT, AND EXEMPTING IT WAS THE WRONG FIX.** The first draft
untracked the 46 files and added their paths to `link_check.py`'s `WITHHELD` tuple, which turned **59
reader-visible 404s green** instead of repairing them — the compensating-control-on-a-false-premise
shape D2's Phase 1 record already warns about, committed by the session that had just quoted it.
Phase 1's precedent is explicit and was not followed: *"Only the links were rewritten."* An
independent review caught it and withheld its approval. The 49 links outside `docs/BACKLOG.md` were
then repaired — repointed where a tracked successor genuinely covers the sentence, otherwise unlinked
to the document's plain name so the citation survives as provenance. Measured both ways with
`WITHHELD` forced back to its four long-standing prefixes: `origin/main` 0 failures, the first draft
59, the repaired branch 10.

The residual 10 are in `docs/BACKLOG.md` and could not be repaired in the same change: eight open
pull requests held that file. Two narrowly scoped `WITHHELD` entries cover exactly those targets —
ONE file and ONE subdirectory, not the parent trees — and their removal condition is *"no open PR
touches `docs/BACKLOG.md`"* rather than a PR number, because a number goes stale silently. An earlier
wording said "once PR 713 lands"; 713 merged while that sentence was being written and nothing
noticed, which is the same defect one level down.

**A LIMIT OF D1 THAT PHASE 4 FOUND BY WALKING INTO IT, AND IT IS THE MOST REUSABLE THING HERE.
D1 CLASSIFIES A DOCUMENT BY ITS SUBJECT. IT NEVER ASKS WHETHER THE DOCUMENT CARRIES AN OBLIGATION
BINDING IT TO ENGINE CODE.** A document that merely DESCRIBES code goes stale quietly, and a reader
can tell. A document that says *edit me in the same change* cannot be honoured once it is one
repository away: the commit that triggers the obligation cannot reach it, and nothing in either
repository reports the breach.

Found by a peer session, not by this pass, and it found it by TRIGGERING it.
`docs/testing/master-test-plan/17-performance-and-scale.md` carried a pin added 2026-08-28: *"the
empty-claim monotonicity assertion in `test_connscale_smoke.py` is under active review as a known-
noisy leg. IT IS CORRECT TODAY. IF IT IS DISARMED, SKIPPED OR DELETED, THIS ROW MUST BE EDITED IN THE
SAME CHANGE."* That session's branch is the change that disarms the assertion. It had discharged the
pin correctly; Phase 4 merged mid-build and took the row out of reach. **The pin's own predicted
failure then occurred by a route it did not anticipate: the disarm ships, and the false claim
survives -- in the vault, where the triggering change cannot edit it in the same commit, which is the
one thing the pin demanded.**

**Censused after the fact rather than left at one instance: 10 of the 46 files carry a same-change
obligation**, measured at `72bfddfad` over the removed set. Besides the pin above, they include
`19-execution-phasing-and-sign-off.md` (*"the chapter matrix must gain that row in the same commit"*),
`00-strategy-and-governance.md`, `16-security-phi-and-supply-chain.md`, `09-engine-api.md`, and
`docs/research/ad-step-up-after-simple-bind-retirement.md` (*"`_reauth_ad` may therefore not be
deleted in the same change that removes `_login_ad`"*).

**IF YOU TAKE ONE THING FROM THIS PARAGRAPH, TAKE THIS: GREP FOR `in the same
(change|commit|PR|pull request)` BEFORE MOVING ANYTHING.** It costs nothing, and this pass did not
run it and should have. Everything below is the reasoning; that line is the remedy.

**THE NEEDLE IS WRITTEN WITH FOUR SPELLINGS BECAUSE AN EARLIER DRAFT HAD TWO AND SAID "it catches
all ten".** Both halves of that were wrong, and a non-author review measured it over the 46 removed
paths at `921db74a1^`:

| needle | files |
|---|--:|
| `in the same (change\|commit)` — the earlier draft's | **9** |
| adding `in the same (PR\|pull request)` | **2 more** — `12-vs-code-ide-extension.md`, `13-steps-editor.md` |
| negative control, a nonexistent string | **0** |

So the old needle caught 9 of at least 11, and the count in the prose was 10. **The two-spelling
needle was generalised from the single pin phrased "in the same change" — a screen built from one
case finds one shape, and it reported clean on the two documents that spell the same obligation
"PR".** Write it as **at least**: this is an enumeration over prose written by many hands, and a
fifth spelling is likelier than not.

**NOTHING IS PROPOSED HERE AND NOTHING IS FIXED.** The at-least-eleven obligations are now unsatisfiable as
written, and the three candidate answers are genuinely different with different owners: keep an
obligation-carrying document tracked regardless of subject; rewrite the obligation as a CI check
BEFORE moving it; or accept the breach and say so somewhere it can be read.

Worth noting without deciding it: **only the middle one survives the document being in EITHER
repository.** Keeping the document tracked works only while it stays; accepting the breach depends on
a reader finding the note. A check that fails when the assertion and the row disagree holds wherever
the row lives, because it is anchored to the code rather than to the prose. That is an observation
about the remedy space, not a decision, and the decision is not a session's to make.

What is recorded is that **D1's subject test is insufficient on its own.**

**Custody first, as Phase 1 requires.** The 46 files were committed to the vault and pushed BEFORE
leaving the tracked tree, at `wshallwshall/MessageFoundry` branch `lander/adr0160-custody`, verified
byte-identical. That ordering mattered more than Phase 1 knew: measured across both repositories,
**1702 paths are shared and 760 of them DIVERGE**. The vault is a stale fork, not a mirror — the
publish pipeline that synced them was retired at the 2026-07-27 cutover. 15 of these 46 already
existed there and 7 were divergent, so a bare untrack would have left the vault holding the older
text and nothing holding the newer.

### D6 — considered and LEFT, so the next sweep does not re-derive them

Three sets were found while executing Phase 1 and deliberately not acted on. They are recorded
because a sweep run against D1 will surface all three again, and an unrecorded "we looked and left
it" is indistinguishable from an oversight.

**1. Eleven files citing `docs/releases/` paths in PROSE.** Not links — nothing 404s. They read as
provenance: *"the v0.1 execution plan §Q3 set the two-tier gate"* stays true after the file moves.
The two citations that *were* rewritten during Phase 1 are a different case: a `.toml` comment and a
test docstring naming a path a reader would try to open. ⛔ **ADR 0160's own citations must never be
"cleaned"** — this is the ADR that removed the directory, and the paths are the evidence.

**2. Twenty-two handoff DOCUMENTS outside `docs/releases/`** — 21 under `docs/benchmarks/`, one at
`docs/quality-gates/HANDOFF-mutation-coverage.md`. ⚠️ A name-based sweep reports **155** matches
here; **133 of those are benchmark DATA files** (json/txt) that merely sit inside directories named
`HANDBACK_*`. Overstating the finding six-fold is the first trap. The second is that the bench
handoffs carry the **measurement narrative** for the data beside them — removing them strips the
rationale from records that stay, which is the defect the Consequences section below names. And the
Phase 1 justification does not transfer: `docs/releases/` **misrepresented the project** to a first
reader, whereas a benchmark handoff reads as exactly what it is.

**3. Unanchoring `/HANDOFF-*.md`.** Rejected, with the reasoning kept in `.gitignore` beside the rule
so it is refuted where it will next be proposed: the two locations that matter are already covered,
and an unanchored pattern would fail closed on `docs/benchmarks/`, where handoffs are tracked on
purpose.

### D5 — the process TOOLING moves, and these are the PRECONDITIONS

**Superseded 2026-08-31.** The measurements below stood and still stand; the decision they supported
did not. They are now the conditions the move must satisfy, and each has a failing reading that looks
like success, which is why they are conditions rather than advice.

**P1. The vault's CI must actually run the moved tests before anything is removed here.** A repository
holding a `ci.yml` that never runs is indistinguishable, at a glance, from one whose tests pass.

**P2. That CI must run on WINDOWS.** A Linux-only leg would read as proof and would not be one.

> **MEASURED 2026-09-01, AND BOTH P1 AND P2 ARE UNMET. The earlier prose describing them was stale in
> both directions and is corrected here rather than left.**
>
> **P1 is worse than "every workflow except the ASVS scorecard is disabled".** Live from the API:
> **8 workflows active, 17 `disabled_manually`** — and **`ci.yml`, the only one that runs a test
> suite, is among the disabled**. It is not the exception; it is the casualty. It carries **2,911
> historical runs** and last ran **2026-07-27 (failure)**, so the vault *did* run tests until late
> July and then stopped. Of the 8 active workflows, two mention `pytest` at all — 1 and 4 references,
> both narrow content checks — against **83** in the engine's `ci.yml`. **Nothing in the vault runs a
> test suite today.**
>
> **P2's "13 of 26 files" is a FILE-COUNT denominator and it overstates the gap by two orders of
> magnitude.** The move-set is **70 test files, not 26**. Run on Windows in this worktree:
> **1767 passed, 1 skipped, 0 failed, in 26m47s** — so the suite is green on the platform that
> matters. The ubuntu exposure is **NOT 27 test functions**, and the figure is WITHDRAWN. An earlier
> revision of this line said 27, which reproduces under no reading of the tree and errs in the
> direction that makes this precondition look easier to satisfy than it is. Measured 2026-09-01 at
> `bdffd6479` by walking every `tests/**/*.py` with `ast` and asking which `test_` functions sit
> under a gate whose own source contains `os.name`: **6** carry a per-function decorator, **606**
> sit in **34 files** under a MODULE-level gate, so **612** in all. The gate is
> `shutil.which("pwsh") is None or os.name != "nt"` -- it skips on NON-Windows, so every one of
> those 612 is lost on an ubuntu-only leg. Three readings, three different numbers -- 6, 35 gate
> lines, 612 functions -- and 27 is none of them; the table below counts 13 FILES for the same
> predicate where this walk finds 34, so the old figure appears to have conflated files with
> functions and then undercounted the files as well.
>
> **THE DENOMINATOR IS NOT RECONCILED AND IS DELIBERATELY NOT RESTATED.** 1768 comes from a
> Windows run of the 70-file move-set; 612 is measured over the WHOLE of `tests/`, which collects
> 11,158 test functions here. The two have different corpora, so 612/11158 is not a drop-in
> replacement for 27/1768 and no ratio should be computed across them. What IS established is
> that the 34 module-gated files are exactly the coord, worktree, session, announce and collision
> suites -- the PowerShell tooling this move is about -- so the ubuntu loss is in the hundreds of
> functions rather than in the tens. Whoever closes this must re-measure against the enumerated
> move-set; nobody has enumerated it here.
>
> **P2 still stands, and it now stands for a bigger reason than it claimed.** It should still be
> argued on *which* tests are lost, never on how many. Every active vault workflow is `ubuntu-latest`; there
> is **no Windows leg at all**, and `selfhosted-win2025-sql.yml` is disabled.
>
> **THE COST IS NOW KNOWN RATHER THAN ESTIMATED.** The vault is **private**, so a ~27-minute Windows
> run bills at 2x, per run. That is the number D5 declined this phase over, and it is the real one.

**P3 HAS A LANDMINE THAT "COPY" DOES NOT DESCRIBE, MEASURED 2026-09-01.** The vault is a stale fork,
not an empty destination: it already carries `scripts/coord` (20 files), `scripts/worktree` (10),
`scripts/hooks` (9) and 526 test files. So Phase 2 is a **reconciliation**, not a move. Across the
126 files in scope:

| | scripts (56) | move-set tests (70) |
|---|--:|--:|
| identical to engine | 5 | **0** |
| differing | 21 | 7 |
| absent from vault | 30 | 63 |

Of the 33 files present in the vault, **30 are past engine versions** — safe to overwrite, merely
behind — and **3 have CHANGED INDEPENDENTLY**: `scripts/coord/install-git-hooks.ps1`,
`scripts/coord/lane.ps1`, `scripts/hooks/lane-level.ps1`. **A blanket copy of the engine's versions
would destroy work that exists nowhere else**, silently, because the files look merely stale. Those
three need a decision before P3 begins; the other 123 are mechanical.

*(Method, so it can be re-run: hash each engine blob against the vault's file, and for each
difference walk that path's engine history looking for the vault's blob. Found means the vault is
behind; not found means it diverged. A sample cannot answer this — a first pass over 7 of the 33
found 2 divergent and would have implied ~10 across the set, against a true 3.)*

**P3. Copy, prove green, THEN remove.** Never `git rm --cached` first: it removes the file from every
working tree including the machine running it, and no restore step exists.

**P4. Verify on a CLONE that carries only tracked files, never on the working tree.** Added
2026-08-31 from Phase 4's execution, where it caught a real break that every local run reported
green. Untracking leaves the files **on disk** under a gitignore rule, so any guard that tests
whether a path EXISTS passes locally and fails on the runner. Phase 1 recorded this for one test;
Phase 4 found it is the general case, and it is worse for Phase 2 than for either, because
`scripts/` holds more existence-testing guards than `docs/` does.

Three parts, and the second is the one that bites:

* **Use `git clone --no-hardlinks`, NOT `git archive`.** An archive export has no `.git`, so a guard
  that shells out to `git` is running outside a repository. **It fails BOTH ways, and an earlier
  draft of this bullet stated only one of them and stated it as universal.** Measured: `git ls-files`
  in an exported tree exits **128** with `fatal: not a git repository` and empty stdout, against a
  positive control of 452 paths in a real checkout. So a guard that CHECKS the exit code goes red --
  a reviewer hit exactly that and produced 25 red tests that were all instrument artifact -- while a
  guard that IGNORES it parses zero lines and **passes vacuously**, asserting over an empty list.
  Which one you get depends on the guard, not on the export.

  **The silent green is the one that ships**, which is why the conclusion stands either way; but a
  precondition that names only the green half sends a reader looking for the wrong symptom, and the
  earlier draft contradicted itself inside two sentences by then citing 25 RED tests as the evidence
  for it.
* **Grep the SEGMENT-JOINED path form as well as the slash form.** Phase 4's first sweep for inbound
  references missed a test that builds its path as `_REPO / "docs" / "testing" / "FILE.md"`. The
  string `docs/testing/` never appears in that source, so a slash-form grep cannot see it, and the
  test failed on CI after the branch was declared clean. Search for `"docs", "testing"` and
  `"docs" / "testing"` and the bare basenames too.
* **Prefer an announced skip to a deleted assertion** when a guard reads a document that has left.
  `tests/test_threat_model_doc_drift.py` is the idiom: warn loudly, skip that one test, keep the
  code-only assertions in the same module running, and offer an environment variable that makes the
  absence a hard failure. Phase 4 reused it verbatim for the CRIT-2 coverage-plan drift check.

  **BUT THE ANNOUNCEMENT FIRES WHERE NOBODY IS WATCHING, AND THAT IS THE HALF PHASE 4 DID NOT SEE.**
  The removed files stay ON DISK under the gitignore rule in any tree that held them before the
  removal landed. There the document still exists, the accessor finds it, and the assertion runs
  ENFORCED AND GREEN with no warning at all. The skip -- and therefore the warning -- is reachable
  only where the file is genuinely absent, which is CI and a fresh clone. **A maintainer running
  pytest locally will never see the warning; only the runner will.** So the loud announcement is
  loud in the one place no human is reading, and silent in the place they are.
  Raised by a peer session verifying Phase 4's deletions for silently-disabled guards; it found none,
  and found this instead. It does not make the idiom wrong -- an inert test that says so is still
  better than one that does not -- but "warn loudly" overstates what the reader actually gets, and a
  future phase should not count on the warning reaching a person.

**Unchanged by the reversal:** any path called by `.pre-commit-config.yaml` or by a workflow stays in
this repository. That is about an outside contributor passing the gates on their own clone, which is
independent of where the tooling lives.

### D5 (2026-08-06, superseded) — the original decline, on measured cost

The obvious next step after Phase 1 is `scripts/coord/` (9), `scripts/worktree/` (11) and
`scripts/hooks/` (8, excluding `ledger_check.py`), with the four Phase 2 docs that describe them.
**Owner decision, 2026-08-06: it stays.** Moving it is affordable only by paying for a second CI or
by losing coverage, and the gain is cosmetic. The measurements that produced that decision follow —
they are recorded because the *next* person to propose this move will re-derive them otherwise:

⛔ **The vault's CI is off.** `gh workflow list --all` on `wshallwshall/MessageFoundry` reports every
workflow except `ASVS scorecard` as `disabled_manually`; `ci.yml` last ran **2026-07-27** and failed.
The last 50 runs are 42 `ASVS scorecard` plus 8 Dependabot. So "move the tooling to the vault, where
its tests keep running" is **false**, and it is false in the most dangerous way: the vault *contains*
a `ci.yml`, so the claim survives inspection and fails only in fact. That is precisely
[ADR 0158](0158-silent-controls-green-signals-that-mean-nothing-and-shape-over-detection.md)'s
second sub-class — a control that cannot observe its own failure.

**~20 test files** exercise this tooling (`test_worktree_gate*`, `test_coord_*`, `test_announce_*`,
`test_collision_gate`, `test_session_registry`, `test_installed_coord_hooks`, and siblings) and they
run today inside the **required** `test` legs. Untracking the scripts without the tests turns those
legs red; untracking both retires the gate. Neither is acceptable under the owner's rule.

⛔ **The cheap gate does not work, and the split is exactly even.** The tempting fix is a Linux-only
workflow in the vault, since hosted ubuntu ships `pwsh`. Measured across the 26 test files on
2026-08-06 by reading each file's `pytestmark`:

| Skip predicate | Files | On a Linux-only leg |
|---|--:|---|
| `shutil.which("pwsh") is None` | 13 | run |
| `shutil.which("pwsh") is None or os.name != "nt"` | **13** | **silently skip** |

So a Linux-only vault leg covers **half the suite and reports green**. That is not a cheaper version
of the gate; it is the same silent-control defect relocated. A correct gate needs **ubuntu plus
windows**, and the vault is **private**, so the Windows leg bills at **2x**. The suite is also slow:
three of the 26 files alone ran **94 tests in 64 seconds** locally, dominated by `pwsh` process
spawns, and the full set exceeded a two-minute timeout — the total was **not** measured, so treat
"several minutes per run" as an estimate and nothing firmer.

**A second unknown was never closed:** `.worktreeinclude` copies gitignored files into worktrees
Claude Code creates, but that is a first-party mechanism (`--worktree`, desktop sessions,
`isolation: worktree` subagents) and it is **untested for these paths** — `git worktree add` does not
exercise it, so the check requires creating a real Claude Code worktree. It matters because
`CLAUDE.md` instructs sessions to run `scripts/coord/alloc.ps1` from their own worktree, and a
missing `alloc.ps1` means no ADR/BACKLOG number can be allocated — which the ledger gate turns into
a **refused commit**.

⚠️ **A third hazard applies to any phase, and Phase 1 CONFIRMED it rather than predicting it.**
`git rm --cached` spares only the tree it runs in. Rebasing the Phase 1 branch onto `main` **deleted
`docs/releases/` and both root handoffs from the working tree** — the same thing that happens to the
primary and to every active worktree (52 at the time) when the removal lands. For documents that is
acceptable: the vault holds them, pushed first. For the tooling it is not — it would vanish from the
machine that runs it, so any such move needs a restore step that does not exist.

**Why that adds up to declined rather than deferred.** Phase 1 removed 103 files that actively
*misrepresented the project*: a public `docs/` whose largest directory was session plans and wave
schedules. The tooling is different — a reader correctly identifies it as this project's development
tooling, and it is not mistakable for product. Against that, moving it costs a second paid CI in
perpetuity, an unproven delivery mechanism, and a restore path. **The benefit is cosmetic and the
cost is structural, so it is not worth doing.** Recording it as *blocked* would have been the
dishonest shape: nothing is coming to unblock it, and a permanently-blocked item reads to the next
session as work someone still owes.

**If this is ever reopened**, the bar is unchanged and stated here so it is not re-litigated from
scratch: a gate on **both** operating systems, proven able to **fail** on a deliberately broken test
and audited for **skips** (`-rs`) rather than trusted on green, plus `.worktreeinclude` demonstrated
on these paths, plus a restore step. Absent all three, the move trades a working control for a
silent one.

### D3 — `CLAUDE.md` is a genuine conflict between the policy and the tooling, and it stays tracked

By D1, `CLAUDE.md` should come out: its subject is how to work on this project with Claude Code.
**It cannot.** `git worktree add` **cannot deliver an untracked file**, so when `CLAUDE.md` was
untracked, every new worktree came up with **zero project conventions loaded** — verified on two live
worktrees, and it only looked correct in the primary because an untracked copy happened to sit on
disk there. It was moved back into tracking in MEFORORG PR #6 for exactly this reason.

**Decision: `CLAUDE.md` stays tracked, as a named exception with a recorded mechanical cause.** This
is the honest shape. The alternative — an untracked convention file — is a control that silently
fails to load, which is the defect class [ADR 0158](0158-silent-controls-green-signals-that-mean-nothing-and-shape-over-detection.md)
exists to name.

### D4 — No enforcement gate is proposed, and the reason is stated

A gate that classified files by path would be either trivially evaded or constantly wrong, and a
keyword gate would fire on every legitimate mention of the word "session". **This ADR is a written
rule, not a mechanism.** Do not read that as a promise to add one later; read it as a bounded claim
about what this decision covers. If the rule proves insufficient in practice, that is a finding and
wants its own item.

## Options considered

**Keep everything and rely on the vault for what must stay private.** Rejected: the vault already
holds the attacker-roadmap material, and the question here is different — a public repository whose
`docs/` is majority development-process material misrepresents what the project is to the first
reader who arrives, and that reader is the audience the repo exists for.

**Reinstate a publish-time deny-list.** Rejected: that pipeline was retired deliberately at the
cutover and its removal fixed a class of self-contradictory code (memory `mf-public-mirror` records
the slug-rewrite damage). Re-introducing a second tree to keep in sync trades a clear rule for a
synchronisation problem.

**Move process material to the separate public repository.** ⛔ **Rejected on 2026-08-05** — the
owner ruled directly that this material is not to go to `claude-multisession`. The vault is the
destination. This closes what the earlier draft left open as context.

## Consequences

- The public repository becomes readable as what it is: an integration engine plus the decisions
  behind it.
- **A reader loses the process record.** That is the intended trade, but it is a real loss: several of
  those documents contain the reasoning behind controls that remain in the repo. Where a control
  stays and its rationale leaves, the rationale must be relocated, not deleted — otherwise the next
  reader finds a gate with no recorded reason, which is its own defect class.
- Sessions gain a citable rule, so a constraint no longer arrives as an unverifiable assertion from
  a peer.
- `git log` still contains everything removed. **This is not a confidentiality control** and must not
  be described as one. Nothing here has been treated as secret; the material is process noise, not
  sensitive content. Anything genuinely sensitive belongs in the vault and always did.

## To resolve on acceptance

1. **Does `docs/BACKLOG.md` stay? STILL OPEN, and still the owner's call.** It is process material by
   D1 and it is also **CI-load-bearing**: `scripts/docs/backlog_status_check.py` and
   `.github/workflows/backlog-hygiene.yml` both read it, and the second is a **required merge
   context**. Removing it is not a doc edit; it retires a gate.

   It no longer "blocks Phase 2" — that framing died with the Phase 2 decline. Note the question is
   now shaped by D5 rather than independent of it: D5 declined a move whose cost was *rebuilding* a
   gate elsewhere, and removing `BACKLOG.md` would retire one outright with no replacement proposed.
   That is the same trade on worse terms. **Recorded as an observation, not a decision** — the owner
   has not been asked this one, and D5's ruling does not answer it by implication.
2. **RESOLVED 2026-08-05 — D2 ratified and Phase 1 executed** at 103 files: the 101 measured here
   plus the two root handoffs found during execution.
3. **RESOLVED 2026-08-05 — the vault is the destination**, and custody transfers *before* removal,
   never after. Deletion-with-git-history-as-the-only-record was rejected: `git log` is a recovery
   path, not a home, and it is not a place anyone will look for a plan they need.
4. **`docs/Secure_Development_Standards.md`** is tracked, scans clean, and was deliberately pulled
   from the public PyPI sdist. Decide whether it is reviewer material that stays, or process material
   that goes — the sdist exclusion suggests the question was already asked once and answered
   differently.
