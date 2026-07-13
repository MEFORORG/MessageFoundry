# AI-off completeness matrix — the deterministic build experience

**Why this exists.** In a PHI environment, builders often cannot use AI assist at all — MessageFoundry's
AI is environment-clamped on an OFF→PHI-safe spectrum, RBAC-gated by `ai:assist`, and even when on only
ever sends `code_only`, never message bodies (CLAUDE.md §9, [`docs/AI.md`](AI.md)). A prod/PHI instance can
clamp it **OFF** entirely. So the IDE must be a **complete** authoring experience with AI off — not a
degraded one.

**The design principle (enforced by this matrix):** *every AI feature has a first-class deterministic
sibling.* The `@messagefoundry` chat participant ([`ide/src/chat.ts`](../ide/src/chat.ts)) is an *optional
accelerator*, never the load-bearing on-ramp. Below, each chat subcommand is mapped to the deterministic,
fully-offline path that a no-AI builder uses instead.

| `@messagefoundry` subcommand | Deterministic sibling (AI-off path) | State | Owning item |
|---|---|---|---|
| `/transform` | **Insert Element** palette — ~30 editable-Python idioms (field/format/date/lookup/loop/regex/`match`/fan-out), inserted verbatim | ✅ base shipped; expanding | BACKLOG **#48** (base #595) + PLAN-7 **L1** |
| `/router` | **Router Wizard** + `route-by-type` / `route-to-multiple` palette idioms | ✅ shipped | `ide/src/newRoute.ts` + #48/L1 |
| `/review` | `messagefoundry check` + `validate` (Problems panel, on-save) | ✅ shipped | `ide/src/validate.ts`, `checks.py` |
| `/test` | **Test Bench** (dry-run, disposition, before/after) + **Generate Samples** (synthetic corpora) | ✅ shipped; deepening | `ide/src/testBench.ts`, `generate.ts` + PLAN-7 **L4/L7** |
| `/explain` | **Cookbook + Walkthrough** — searchable "solved problems" gallery that inserts editable Python + `contributes.walkthroughs` onboarding + HL7-schema hover/autocomplete | ✅ shipped (Cookbook gallery + walkthrough) | BACKLOG **#104** + PLAN-7 **L3** |
| `/migrate` | **Deterministic Corepoint import** — `messagefoundry import corepoint <export> --out <dir>` scaffolds one editable `@router`/`@handler` module per channel ([`corepoint_import.py`](../messagefoundry/corepoint_import.py)) | ✅ shipped (synthetic schema) | BACKLOG **#105**, [ADR 0086](adr/0086-deterministic-corepoint-import.md) |

**The immediacy an interactive AI loop would give** is supplied deterministically by the **#92 live-debug
loop** (PLAN-7 L2 v1 + L6 v2): edit → save → watch per-line values + disposition update inline, no
breakpoints, no AI, fully offline. That is the deterministic analogue of "ask the assistant what this does"
— you *watch* it do it.

## Findings
- **All six** chat subcommands now have a first-class deterministic sibling that is shipped or actively
  being deepened by PLAN-7 (L1/L4/L7) — a builder with AI off loses **no essential capability** today
  except discoverability-of-examples, which the now-shipped **#104 Cookbook** (gallery + walkthrough) closes.
- **The former `/migrate` gap is closed** — the deterministic Corepoint import shipped 2026-07-10 (BACKLOG
  **#105**, [ADR 0086](adr/0086-deterministic-corepoint-import.md)): `messagefoundry import corepoint`
  scaffolds editable `@router`/`@handler` Python from a Corepoint action-list export. The export **schema is
  synthetic-until-validated** (no real Corepoint export exists in-repo, #87 recon is git-ignored), so it
  needs reconciliation against a real export before it is trusted on production channels — but the AI-off
  migrator now has a deterministic starting point instead of leaning on the AI `/migrate` subcommand.

## Guardrail (why "deterministic sibling" is safe where "no-code" is not)
Every sibling above **emits editable Python** (or is pure validation/visualization/testing). None is a
declarative/visual **logic**-authoring surface — that stays declined-by-design (CLAUDE.md §12, BACKLOG
**#26**; the visual correlation editor **#79** and Fix-All **#80** are declined for the same reason). The
deterministic build experience lowers the *barrier* to code-first authoring; it never replaces the code
with boxes.

---
*Source deliverable for MULTISESSION-PLAN-7 (L0). Not a decision record — the decisions live in
[`docs/BACKLOG.md`](BACKLOG.md) (#26/#48/#84/#92/#104/#105) and [ADR 0072](adr/0072-traced-dryrun-mode.md).*
