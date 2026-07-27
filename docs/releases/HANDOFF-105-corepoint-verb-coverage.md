# Handoff — BACKLOG #105: Corepoint import, verb coverage (2026-07-24, **updated 2026-07-25**)

> ## ⚠️ READ THIS FIRST — the 2026-07-25 pass changed the premise
>
> The framing below ("this needs build time, not a decision") turned out to be **wrong**, and the
> correction is the most useful thing in this document. A verb-coverage pass ran on
> `claude/<branch>` (commit `f97e4a45`). What it found:
>
> 1. **`@Data`'s markup is semantically ROLE-TAGGED, not syntax-coloured.** The span classes are
>    `keyword` / `path` / `literal` / `input-handle` / `other-handle` / `variable` / `detail` /
>    `description`. Flattening them fused the operator's prose into the statement: `ItemCopy` shows
>    1,285 distinct shapes flat and **13** by role. The importer now reads roles (`parse_roles` →
>    `RoleToken` → `Operand`), with the flat tokenizer kept as the fallback.
> 2. **Corepoint writes DASH coordinates** (`PID-5-1`) where `Message` writes dotted (`PID-5.1`), and
>    path spans begin `/`, not `%`. Before that translation **0 of 5,013 paths resolved** — which is
>    why `ItemCopy`/`ItemClear`/`ItemAppend`, nominally "the three that map", mapped essentially
>    **never** against real data. The old fixture passed only because its synthetic statements omitted
>    the connective and the handle. *If you write a fixture, write it from the real grammar.*
> 3. **Three defects were live in the EMITTED code** — this pass was as much a bug fix as a feature:
>    a bare `else:` under a dead `if False:` **ran its branch for every message**; the "inert"
>    passthrough stub `msg.set(p, msg.field(p) or "")` raises `KeyError` on an absent segment and
>    *materialises* empty fields on the wire; and `<If>`/`<Try>` **branch-group wrappers** (no `@Data`,
>    one child per branch) each emitted a second, condition-less `if False:` that was counted as mapped.
> 4. **Coverage is BOUNDED, not merely unfinished.** See **[BACKLOG #313](../BACKLOG.md)** — a Corepoint
>    action-list drives several message trees and a Handler has one `msg`. **2,032 statements are
>    refused for that reason alone.** That is an owner *design decision*, not build time.
>
> **Result:** `mapped` 2,386 → **1,664**, deliberately DOWN, because 789 of the old count were the
> phantom wrappers; net of those, genuine mappings rose 1,597 → 1,664, and 5,396 markers now name
> their cause. #105 stays 🚧 **PARTIAL**.
>
> **Before you build anything, read
> [`SPEC-105-corepoint-verb-mapping.md`](SPEC-105-corepoint-verb-mapping.md)** — an adversarially
> verified per-verb specification (11 agents, ~1.9M tokens) with measured guard sets, accounting
> corrections, and an explicit *"considered and rejected"* section. It is the artifact that stops the
> next session re-deriving all of this. Two items in it are **specified but unbuilt**: `EnvLogText` →
> `log_note` (63 mappings; needs an `Action` form with no leading `msg` **and** a
> `messagefoundry`-vs-`messagefoundry.actions` import split — half-done it raises on every message),
> and the three-part `MsgSend` wrong-message fix (parked in #313, because the naive version turns sends
> into `FILTERED` or emits a spurious unconditional trailing `Send`).
>
> Everything below is the **original 2026-07-24 handoff**, kept because its PHI rules, gates, and
> working method are all still exactly right.

---

> **Status going in (2026-07-24):** #105 is 🚧 **PARTIAL**. The schema half is **done and validated**;
> what remains is **coverage**. Nothing here is blocked — this needs build time, not a decision.
> *(Superseded: see the 2026-07-25 note above — the remainder turned out to be gated on a decision.)*

## Claim it first

```powershell
pwsh -NoProfile -File scripts\coord\claim.ps1 -Take 105 -Note "corepoint verb coverage"
pwsh -NoProfile -File scripts\coord\claim.ps1 -List     # check nobody else holds it
```

BACKLOG #309's `commit-msg` gate will block a code commit whose subject says `BACKLOG #105` unless this
worktree holds the claim. Release it when you stop.

---

## ⛔ Read this before you touch anything

A **real customer Corepoint export** lives on the owner's machine — the single `.xml` file under:

```
<your local Corepoint export folder>
```

(The filename is deliberately not written here: it *contains the customer name*, and this document is
committed. That is the standard you are being asked to hold for everything downstream of it.)

**The export must never be committed, quoted, or pasted — not into code, tests, fixtures, comments, commit
messages, PR bodies, or this repo in any form.** It carries partner/vendor names, site codes and
hostnames.

Use it **locally, read-only**, to answer questions about the grammar. Everything you commit must be
**synthetic** — invented names, RFC 2606 domains (`demo.example.org`, `ACME`, `TEST_LAB`). The existing
fixture `tests/fixtures/corepoint/acme_adt_package.xml` is the pattern to follow.

Verify before every commit:

```powershell
python scripts\security\scan_forbidden.py --path .   # must exit 0
```

---

## What is already done (do not redo it)

`messagefoundry/corepoint_import.py` parses the **real** export format. ADR 0086 §2's
*"synthetic-until-validated"* caveat is **discharged** (see the ADR 0086 amendment):

| | Was assumed | Actually is |
|---|---|---|
| Format | JSON | **XML**, root `<Package>` |
| Actions | typed objects with a `class` field | **`@Data` statement strings wrapped in rich-text markup** |
| `<Block>` | an action | a **comment / section label** |

**The markup wrapper is the detail that matters.** `@Data` is wrapped in syntax-colouring spans plus HTML
entities; strip with `html.unescape(re.sub(r"<[^>]+>", "", data)).strip()`. Without stripping, ~79% of
statements fail to classify — which makes the whole corpus look unmappable for entirely the wrong reason.

Also already correct, and **load-bearing — do not regress it**: the module's *count-and-log* contract.
Every source element yields a mapped call, an `UnmappedAction`/TODO marker, or an explicit disabled
marker, and is counted. An adversarial review found four silent-drop paths in the first cut; they are
fixed and pinned by tests. **If your change can drop an element silently, it is wrong.**

---

## What remains — in value order

### 1. Verb coverage (the main job)

**42 distinct verbs; the top 30 cover 99.4%.** Only **three** map today: `ItemCopy`, `ItemClear`,
`ItemAppend`. Everything else emits a `# TODO: Corepoint <Verb> — hand-finish` marker.

Frequencies from the reference corpus (10,282 executable elements), highest first — work down this list,
because the head is most of the value:

```
ItemCopy(2829)  If(1050)  ItemClear(530)  MsgTreeCopy(518)  Returns(429)  EnvLogText(334)
MsgLoad(306)  MsgLog(261)  ForEach(254)  ItemAppend(224)  MsgSend(219)  Else(206)
MsgCreate(199)  ActionListExit(144)  ActionListCall(143)  RaisesAlert(143)  LogsText(143)
RequestsGearStop(143)  MsgError(84)  ElseIf(81)  Matching(62)  Try(46)  Catch(46)
ChooseFrom(42)  LoopExit(33)  MsgParse(30)  MsgAddHistory(21)  Loop(19)  ActionListStop(13)  MsgPass(13)
```

Map onto the existing `messagefoundry.actions` vocabulary — read `_ACTION_MAP` and `_map_action` first.
**Map only what genuinely corresponds.** A forced mapping that quietly changes semantics is worse than a
TODO marker a human will read; the marker is the honest output.

### 2. Operands

Every `$variable` operand and every non-HL7-shaped `%tree/path` currently comes out as a TODO, even when
the verb itself maps. Statement syntax after stripping is `Verb operand ...` with `$variable`,
`%tree/path`, `"literal"`, `[options]`, `(conditions)`.

### 3. Known degradation to close

An **unmodelled container's body is inlined at the parent's indentation**, so if the real element was
conditional its body becomes *unconditional* in the generated Python. The marker says so explicitly. This
was a deliberate choice — dropping the body was the original defect, and guessing its scope would be
worse — but it is a real fidelity gap worth closing once containers are modelled.

### 4. Lower priority

- **`<Connection>` subtrees are unmodelled**, so endpoint wiring emits a `deployed=False` placeholder.
- **Routing is not reverse-engineered** — the generated router forwards to all handlers.
- **Conditions are dead `False` placeholders.**
- **The `ide/` TypeScript wrapper is deferred.**

---

## How to work

1. **Derive grammar from the real export locally** — element/attribute *names*, verb *tokens*, masked
   operand *shapes*. Never copy values out of it.
2. **Extend the synthetic fixture** to exercise whatever you're mapping.
3. **Then validate coverage against the real export locally** and report only **counts** (e.g. "mapped
   rises from 3,583 to 8,100 of 10,282"). Counts are safe; content is not.

### Gates

```powershell
python -m ruff format <touched>;  python -m ruff check <touched>
python -m mypy messagefoundry
python -m pytest tests/test_corepoint_import.py -q
python scripts\docs\backlog_status_check.py
python scripts\security\scan_forbidden.py --path .
```

⚠️ `scan_forbidden` also blocks the **spaced** two-word form of *action-list* — the repo convention is the
hyphenated spelling. It bit this work twice: once in the importer's prose, and once in an earlier draft of
this very warning.

### Done means

Update `## 105.`'s banner honestly. Keep it 🚧 **PARTIAL** and name precisely what still isn't covered
unless you genuinely closed everything — the previous pass deliberately stayed PARTIAL because it bought
*accounting integrity, not coverage*, and an inflated ✅ is the exact stale signal this backlog has been
paying down all week.
