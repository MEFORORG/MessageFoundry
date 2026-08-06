# ADR 0160 — Public-repo content policy: operator and security-review material only

- **Status:** **Accepted for Phase 1 (2026-08-05); Phases 2-3 remain Proposed and are now BLOCKED on a
  measured finding — see D5.** The owner ratified the D1 test and Phase 1 on 2026-08-05, chose the
  vault as the destination (resolving open question 3), and set a governing rule for the work:
  **do not break anything**, applied per item as *prove the mechanism or leave the item alone*.
  Phase 1 is executed. Phase 2 is held, not deferred by preference: the gate its tests depend on
  does not currently exist anywhere.
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
export, which is a two-command check:
`git archive $(git write-tree) | tar -x -C <tmp>` then run the test there. The same caveat applies to
any future guard that tests *existence* rather than *trackedness* — after this decision, presence on
disk and presence in the repository are different facts.

**Phase 2 — the individually-tracked process docs.** `docs/WORKTREES.md`,
`docs/SESSION-DRIFT-CONTROLS.md`, `docs/LEDGER-GATE.md`, `docs/STEERING.md`. Each needs its inbound
references audited first; `docs/LEDGER-GATE.md` in particular is cited by `CLAUDE.md` and by hook
error text, so it is not a delete-and-go.

**Phase 3 — in-file references.** Strip Claude-Code process prose from documents that otherwise stay
(`docs/AI.md`, `docs/ARCHITECTURE.md`, `docs/Code_Quality_Standards.md`). Surgical edits, not removals.

### D5 — the process TOOLING is held, because moving it would silently retire ~20 tests

The obvious next step after Phase 1 is `scripts/coord/` (9), `scripts/worktree/` (11) and
`scripts/hooks/` (8, excluding `ledger_check.py`), with the four Phase 2 docs that describe them.
**Held**, on a measurement taken while planning that removal:

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

**Two conditions gate Phase 2, and each must be demonstrated, not argued:**

1. **A live gate for the moved tests** — the vault's `ci.yml` re-enabled (it bills private-repo
   minutes, and its full matrix is far more than these tests need, so a lean Linux-only workflow
   scoped to them is the cheaper shape), *and* proven able to **fail** on a deliberately broken
   test. A green run on a suite that silently skipped is the same defect in a new place: many of
   these tests are Windows/`pwsh`-shaped, so a Linux leg must be checked for **skips**, not just
   for green.
2. **Delivery into fresh worktrees** — `.worktreeinclude` copies gitignored files into worktrees
   Claude Code creates, but that is a first-party mechanism covering `--worktree`, desktop sessions
   and `isolation: worktree` subagents, and it is **untested for these paths**. It must be shown to
   deliver them before they are untracked, because `CLAUDE.md` instructs sessions to run
   `scripts/coord/alloc.ps1` from their own worktree, and a missing `alloc.ps1` means no ADR/BACKLOG
   number can be allocated — which the ledger gate then turns into a **refused commit**.

⚠️ **A third hazard applies to any phase and was live during Phase 1: `git rm --cached` spares only
the tree it runs in.** When the removal reaches `main`, checkout **deletes** those paths from every
other worktree and from the primary — 45 worktrees were active on this machine at the time. For
Phase 1 that is acceptable (the content is documents, and the vault holds them). For the tooling it
is not: the files would vanish from the machine that runs them. Any Phase 2 lands with a restore
step, or it does not land.

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

1. **Does `docs/BACKLOG.md` stay?** It is process material by D1 and it is also **CI-load-bearing**:
   `scripts/docs/backlog_status_check.py` and `.github/workflows/backlog-hygiene.yml` both read it,
   and the second is a required merge context. Removing it is not a doc edit; it retires a gate.
   **Still open, and still the owner's call** — though it is no longer the *first* thing blocking
   Phase 2, since D5 blocks the tooling on a separate and unmet condition.
2. **RESOLVED 2026-08-05 — D2 ratified and Phase 1 executed** at 103 files: the 101 measured here
   plus the two root handoffs found during execution.
3. **RESOLVED 2026-08-05 — the vault is the destination**, and custody transfers *before* removal,
   never after. Deletion-with-git-history-as-the-only-record was rejected: `git log` is a recovery
   path, not a home, and it is not a place anyone will look for a plan they need.
4. **`docs/Secure_Development_Standards.md`** is tracked, scans clean, and was deliberately pulled
   from the public PyPI sdist. Decide whether it is reviewer material that stays, or process material
   that goes — the sdist exclusion suggests the question was already asked once and answered
   differently.
