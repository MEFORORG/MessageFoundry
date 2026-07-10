# ADR 0076 — Typed action vocabulary + structured action-list lens over Python Handlers

**Status:** Accepted (2026-07-10) — ratified by the owner 2026-07-10; the PLAN-8 lanes may build. Gating rule: **phase 1 (the vocabulary) requires only the #26-amendment merge; phases 2–3 require this ADR Accepted.** In practice phase 1 builds after Acceptance anyway — its v1 roster is fixed by §2 and MULTISESSION-PLAN-8 bundles it with phase 2a in one lane.
**Deciders:** owner + IDE/DX working group
**Related:** BACKLOG **#222** (this build), **#26 amendment** (the narrow carve-out this ADR operates under), **#221** (sibling IDE-polish lane), the deep-research findings ([`docs/research/ide-low-code-options.md`](../research/ide-low-code-options.md) — verified precedents: InterSystems low-code custom editors, Kaoto/Karavan/AWS Workflow Studio, Iguana annotations, Corepoint action-lists), ADR 0007/0033/0014 (the sanctioned config-as-data GUIs), ADR 0072 (traced dry-run — the live values rendered beside action rows), ADR 0010/0043 (`db_lookup`/`fhir_lookup` — the sanctioned read-only lookups the lens renders as DBSelect-style rows), ADR 0035 (IDE workspace-trust — `lens` CLI calls are exec-gated like every CLI call), CLAUDE.md §9 (PHI), §12 (the amended bright line).
Plan: [`docs/releases/MULTISESSION-PLAN-8.md`](../releases/MULTISESSION-PLAN-8.md) (L2 builds phases 1+2a; L3 builds phase 2b; L4 = phase 3, owner-gated).
**Code references** are `origin/main @ 954bd22`; line numbers drift — locate exactly at implementation time.

---

## 1. Context — the analyst gap, and the line we must not cross

MessageFoundry's authoring is code-first Python by design (#26). The 2026-07-10 deep-research verified the two halves of the analyst problem: **Corepoint's approachability comes from typed actions** (a structured, non-visual action-list editor practitioners confirm non-programmer HL7 analysts run production interfaces on), and **its documented frustration is having no code underneath in-product** ("felt a bit fenced in", "seemingly simple tasks took lots of steps"). Iguana — the code-first analog — wins on **making code legible** (live per-line annotations), which MessageFoundry now ships (#92 v1/v2, ADR 0072). The remaining gap is the typed-action layer: an enterprise HL7 interface analyst who doesn't know Python cannot yet read or safely edit a Handler.

The round-trip literature verified in the same research draws the boundary: **structural constructs round-trip; behavioral code does not** (hand edits that break a generated pattern cannot be reverse-engineered; protected regions cannot guarantee hand edits survive). InterSystems ships the working guardrail set for exactly this shape inside VS Code: custom editor over the real document, **sync on save only**, **one editor at a time**, **graceful fallback to the text editor**.

## 2. Decision

Build, in phases, a **typed action vocabulary** (plain Python helpers) and a **structured action-list lens** — a VS Code custom editor that renders any *parseable* Handler: typed rows for vocabulary code, in-place read-only `code` rows for everything else, whole-file refusal only on parse failure (§4). The `.py` file remains the **only artifact and the only execution path** — the lens is a projection of real code, never a stored model. There is **no runtime interpreter, no declarative artifact, no canvas**: that is what keeps the #26 rationale (diffable, reviewable, version-controlled config) fully intact.

### Phase 1 — the vocabulary (`messagefoundry/actions.py`, engine, no IDE dependency)

Small composable helpers mirroring the Corepoint action classes, mapped onto the existing mutable
[`Message`](../../messagefoundry/parsing/message.py) API (`field`/`__getitem__`, `set`/`__setitem__`,
`add_repetition`, `add_segment`, `delete_segments`, `repetitions`, `groups`):

| v1 helper | Corepoint analog | Maps to |
|---|---|---|
| `copy_field(msg, src, dst)` | ItemCopy | read `src` path → `msg.set(dst, …)` |
| `set_field(msg, path, value)` | ItemReplace | `msg.set(path, value)` |
| `append_to_field(msg, path, suffix)` | ItemAppend | read + `msg.set` |
| `format_date(msg, path, out_fmt, *, in_fmt=None)` | ItemFormatDate / ItemTransformDate | parse/reformat TS values |
| `convert_case(msg, path, mode)` | ItemFormat / ItemConvert | upper/lower/title |
| `split_field(msg, src, sep, dests)` | ItemSplit | read, split, `msg.set` each |
| `code_lookup(msg, path, table, *, default=…)` | ItemCodeLookup | translation tables (ADR 0033 code sets) |
| `copy_segment(msg, …)` / `delete_segment(msg, seg_id)` | segment ops | `add_segment` / `delete_segments` |

Rules: helpers are **pure** (message in-place mutation only, no I/O — the reliability invariant is untouched); fully type-hinted, mypy-strict, SPDX-headed; exported on the `messagefoundry` authoring surface; the existing `db_lookup`/`fhir_lookup` are *not* wrapped — the lens recognizes them directly (DBSelect analog). Control flow is **native Python** (`if`/`elif`/`else`, `for` over `msg.groups()`/segments) — the vocabulary deliberately adds **no** flow wrappers, so vocabulary-authored handlers read as ordinary idiomatic code. The v1 roster above is finalized at phase-1 build from the Corepoint tab inventory (owner screenshots, 2026-07-10) + the #87 recon; **widening the roster is an ordinary addition, widening the *grammar* (§4) requires amending this ADR.**

Standalone value: the vocabulary immediately becomes the target for Insert Element snippets, completion, `@messagefoundry` codegen, and wizard scaffolds — with or without the lens.

### Phase 2 — `lens parse` (engine CLI) + the read-only action-list editor (IDE)

- **`messagefoundry lens parse <module.py> --json`** — a **static** `ast` parse (stdlib only, **never imports or executes** the config module) that classifies each `@handler` body into the row contract of §3. Engine-owned so the grammar lives in one place beside the vocabulary; the IDE consumes the JSON contract only (the ADR 0072 L5/L6 split, repeated).
- **IDE custom editor** (`CustomTextEditorProvider` over the Handler `.py`): renders rows as a Corepoint-style ordered, nested action-list view with parameter forms, an in-editor toolbar, and Test (Test Bench inline). Entry is **opt-in**: a "Reopen in Action-List view" CodeLens on `@handler` defs + a command (the InterSystems pattern) — **not** the default editor for `.py` (Python files broadly belong to the user's Python tooling). Live-debug values (ADR 0072 — PHI-redacted by default, synthetic samples only) render beside rows via the existing #92 lanes.

### Phase 3 — editing (separately gated: phase-2 bake + owner go)

Row edits/inserts/deletes/moves become **row-scoped line splices** of the same file (`lens rewrite`, §5): only the edited row's lines are regenerated from the row template; every other byte is untouched. Saves go through the normal `TextDocument`/`WorkspaceEdit` path.

## 3. The action-list contract (v1)

`lens parse` emits, per `@handler` (routers are **out of v1 scope**):

```
{ "handler": "<registered name>", "module": "<path>", "def_line": <int>,
  "rows": [
    { "kind": "action",  "action": "copy_field", "params": {"src": "PID-5.1", "dst": "NK1-2.1"},
      "line_start": <int>, "line_end": <int>, "nesting": <int> },
    { "kind": "lookup",  "call": "db_lookup" | "fhir_lookup" | "code_lookup", "params": {…}, … },
    { "kind": "control", "control": "if" | "elif" | "else" | "for",
      "test_src": "<verbatim source>", "recognized": true|false, … },
    { "kind": "send",    "outbounds": ["OB_…"], … },
    { "kind": "code",    "line_start": <int>, "line_end": <int> }        // verbatim, unrecognized
  ] }
```

**Coverage invariant (load-bearing):** the rows' line ranges **exactly partition** the def body — every line is in exactly one row; nothing is dropped, reordered, or synthesized. An unparseable *file* is a lens refusal (the IDE stays in/steps aside to the text editor), not a guess.

## 4. Recognition grammar + the degradation ladder

Recognized rows are deliberately **bounded** (the structural subset that round-trips):

- **action/lookup rows** — single expression-statements calling the v1 vocabulary (or `db_lookup`/`fhir_lookup`/`code_lookup`) with literal args or bounded `Message`-read expressions (`msg["…"]`, `msg.field(…)`).
- **control rows** — `if/elif/else` whose test is a bounded expression (Message reads, comparisons, boolean ops, string methods over them, literals), and `for` over `msg.groups(…)`/segment iterations; bodies are nested row sequences.
- **send rows** — `return Send(…)` / list-of-`Send` returns.
- **everything else** — a **`code` row**: rendered *in place, in order* in the list as read-only code. This is the key UX decision: one hand-written line does **not** eject the whole handler from the lens; it appears as an opaque-but-visible step between typed rows (degradation ladder: typed row → code row → whole-file refusal only on parse failure).

## 5. Rewrite semantics + PHI (the load-bearing correctness section)

- **Row-scoped splice, never reformat.** `lens rewrite` regenerates only the edited/inserted row's line range from its template; untouched rows/blank lines/comments are byte-preserved (test gate §6.2). No AST unparse of the whole file (stdlib `ast.unparse` discards formatting/comments — rejected); no `libcst` in v1 (new runtime dep, DEP-1 — revisit only if splicing proves brittle, as an ADR amendment).
- **Sync on save only; one editor at a time; update-loop guard; Reopen With: Python always available** — the verified InterSystems/VS Code guardrail set, adopted wholesale.
- **Static analysis only.** `lens parse`/`rewrite` never import or execute config modules — a module whose top level would raise still parses. No message content is involved at all in parse/rewrite; **PHI enters only via the live-value annotations, which reuse the ADR 0072 stream and its `--show-phi` gate unchanged** — the lens adds no second PHI gate and no persisted artifact.
- **IDE trust:** the lens shells the CLI, so it inherits the ADR 0035 workspace-trust exec gate like every other extension CLI call.

## 6. Consequences + test gates (acceptance criteria)

1. **Coverage property:** for a corpus including every `samples/config` handler + adversarial hand-written handlers, `lens parse` row ranges exactly partition each def body; unrecognized constructs appear as `code` rows in position — never dropped/reordered.
2. **Byte-stability (phase 3 — tests `lens rewrite`, which does not exist until then):** parse → no-op rewrite is **byte-identical** for the whole corpus; a single-row edit changes only that row's line range.
3. **Emitted code is first-class:** rewritten files pass `ruff check`, `ruff format --check`, `mypy` (strict), and `messagefoundry check` on the samples corpus.
4. **Static-only:** a config module with a top-level `raise` parses successfully (proves no import/execution).
5. **Vocabulary purity:** `actions.py` helpers do no I/O (enforced by review + a no-new-imports test); SPDX header present; **no new runtime dependency** in phases 1–2 (stdlib `ast` only); crypto-inventory gate not tripped (no crypto imports).
6. **IDE:** lens editor degrades to the text editor on parse failure with a notice; edits sync on save only; live values render redacted unless the existing show-PHI opt-in is set (never auto-enabled).

Two-way door: if the lens disappoints, phase 1's vocabulary remains independently valuable and nothing else in the product depends on the lens.

## Acceptance Criteria

- The `lens parse` row ranges SHALL exactly partition each `@handler` def body, with unrecognized constructs emitted as in-place `code` rows — never dropped, reordered, or synthesized → test refs added by the L2 build (coverage-partition property over `samples/config` + adversarial handlers).
- `lens parse`/`lens rewrite` SHALL never import or execute a config module; a module whose top level would raise SHALL still parse → L2 test ref.
- Vocabulary helpers SHALL perform no I/O and SHALL pass `ruff` + `mypy --strict`; phases 1–2 SHALL add no new runtime dependency → L2 test ref + review gate.
- Rewritten files (phase 3) SHALL be byte-identical outside the edited row's line range, and SHALL pass `ruff check`, `ruff format --check`, `mypy --strict`, and `messagefoundry check` on the samples corpus → L4 test refs.
- The IDE lens SHALL degrade to the text editor on parse failure with a notice, SHALL sync edits on save only, and SHALL render live values redacted unless the existing show-PHI opt-in is explicitly set (never auto-enabled) → L3 test refs.

## 7. Alternatives considered

- **Declarative action artifact (a TOML/YAML action-list executed by the engine)** — rejected: a second execution path and a stored non-Python logic artifact is precisely #26's declined pattern; it also forfeits the Python escape hatch that the verified Corepoint testimony shows analysts eventually hit.
- **Full-Python projection (render any handler as rows)** — rejected: behavioral round-trip is the verified failure mode; the bounded grammar + code rows is the honest subset.
- **`libcst`-based rewriting** — deferred (dep + DEP-1 cost vs. the splice approach; revisit via ADR amendment if splicing proves brittle).
- **Notebook (`.ipynb`) authoring surface** — rejected for authoring (a second artifact format); the notebook *rendering* fork stays a #92-side presentation question.
- **Standalone designer / Theia studio** — rejected for now per the research §7 ranking (parked exit path; nothing here is stranded by a later move since the lens is a custom editor over files).
