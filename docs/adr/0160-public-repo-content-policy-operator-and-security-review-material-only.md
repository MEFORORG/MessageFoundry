# ADR 0160 — Public-repo content policy: operator and security-review material only

- **Status:** **Proposed (2026-08-04)** — the RULING in D1 is owner-stated and already in force; the
  APPLICATION in D2/D3 is proposed and needs ratification before any file moves.
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

**Phase 1 — `docs/releases/` (101 files).** Predominantly multisession plans: work breakdowns, wave
schedules, per-session briefs. No operator or reviewer reads these. **Proposed: remove from the public
repo, preserving them in the vault.**

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

⛔ **Phase 1 CANNOT be docs-only, and that is structural rather than a discipline rule.** Three
non-doc files cite the path: `tests/test_cutover_slug_rot.py:53` carries `"docs/releases/"` as a
literal **scan-scope entry**, `tests/test_lint_scope_parity.py:22` cites a plan by name, and
`harness/load/profiles/closed-loop.toml:7` cites an execution plan. So the PR necessarily touches
code, which happens to satisfy the separate rule that a doc migration must not be docs-only — every
doc-drift guard here lives in pytest gated on `code == 'true'`, making docs-only the **blind** mode
rather than the cheap one (already recorded as BACKLOG #327 for `.gitignore`). **Do not treat that as
luck to rely on:** confirm the guards actually ran, because the reason they would run is a test file
this phase happens to touch, not a property of the phase.

**Phase 2 — the individually-tracked process docs.** `docs/WORKTREES.md`,
`docs/SESSION-DRIFT-CONTROLS.md`, `docs/LEDGER-GATE.md`, `docs/STEERING.md`. Each needs its inbound
references audited first; `docs/LEDGER-GATE.md` in particular is cited by `CLAUDE.md` and by hook
error text, so it is not a delete-and-go.

**Phase 3 — in-file references.** Strip Claude-Code process prose from documents that otherwise stay
(`docs/AI.md`, `docs/ARCHITECTURE.md`, `docs/Code_Quality_Standards.md`). Surgical edits, not removals.

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

**Move process material to the separate public repository.** Partially applicable and **not decided
here.** A `claude-multisession` repository exists and is owner-authorised for the *tooling*
(`scripts/coord|hooks|worktree` and their tests). Whether the process **documents** follow it is a
separate decision, and the tooling move itself is recorded in no ruling — treat it as context.

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
   **This one blocks Phase 2 and is the owner's call.**
2. **Ratify or reject the phase scoping in D2**, and confirm Phase 1's 101 files are the right set.
3. **Confirm the vault is the destination** for what leaves, versus deletion with git history as the
   only record.
4. **`docs/Secure_Development_Standards.md`** is tracked, scans clean, and was deliberately pulled
   from the public PyPI sdist. Decide whether it is reviewer material that stays, or process material
   that goes — the sdist exclusion suggests the question was already asked once and answered
   differently.
