# ADR 0076 — Typed action vocabulary + structured action-list lens over Python Handlers

**Status:** Accepted (2026-07-10) — ratified by the owner 2026-07-10; the PLAN-8 lanes may build. Gating rule: **phase 1 (the vocabulary) requires only the #26-amendment merge; phases 2–3 require this ADR Accepted.** In practice phase 1 builds after Acceptance anyway — its v1 roster is fixed by §2 and MULTISESSION-PLAN-8 bundles it with phase 2a in one lane. **Amendment A — ACCEPTED, ratified by the owner 2026-07-30 and IN FORCE:** a `note` row kind so comment-only rows stop projecting as opaque `code`, superseding ADR 0106 §5 (L); §3's enum and §4's ladder read as amended, and BACKLOG #248 is the build. **Amendment B — still PROPOSED and NOT ratified:** ADR 0089 Phase D "helper descent" is specified and priced but **not buildable**; its yield is unmeasured and may be negative, and its three §B.4 preconditions are unmet. Do not read A's ratification as covering B.
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
- **send rows** — `return Send(…)` / list-of-`Send` returns / `sends.append(Send(…))` accumulator sends ([ADR 0108](0108-steps-view-accumulator-send-fan-out-copy-on-send-authoring.md)).
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

---

## Addendum (2026-07-10): live-value acquisition (BACKLOG #225)

Phase 2b shipped the lens with the live-value slot **stubbed** (each row rendered the redacted placeholder; no values were fetched). This addendum records how the shipped lens actually obtains those per-row values, wiring #225.

**Decision.** The lens acquires live values by shelling a **second traced dry-run** — `messagefoundry dryrun --trace json` (ADR 0072) — against a chosen **synthetic** sample, and folds the result onto rows. Concretely: the provider runs the trace, filters the invocations to the open module (`invocationsForFile`), folds the per-line assigned locals + `msg[...]` writes into inline annotations (`traceRowValues`), and attaches them to rows by **line containment** via the already-tested `mergeLiveValues` (a trace event on 0-based line *n* belongs to the row whose 1-based `[line_start, line_end]` contains *n+1*).

**Sample selection** reuses the Test Bench's existing pattern — an open dialog defaulting to `messageSetsDir`, `.hl7`-filtered — surfaced as a lens toolbar control ("Pick Sample…"); the pick is remembered and reused across the open lens editors. No new sample manager is introduced.

**Dirty-buffer alignment (skip while unsaved).** The trace reads the module **from disk**, but the rows are projected from the **live buffer** (`lens parse -` over stdin). After an unsaved **structural** edit (insert/delete/move) the buffer's rows shift relative to disk, so the disk trace's line numbers describe the pre-edit file; mapping them onto the shifted rows by line containment would attach a marker to the **wrong row**. A dry-run cannot reflect an unsaved buffer, so the lens **skips** live values while `document.isDirty` (`shouldAttachLiveValues`) — the redacted placeholder stands — and **re-attaches** them on the next save, when `disk == buffer` realigns the coordinates. This is the same "sync on save" guardrail the projection itself follows.

**Rejected alternative — reading `LiveDebugController`'s last-trace state.** The #92 live-debug controller already holds a last trace in memory, so the lens could have read it directly. Rejected: it **couples the lens to the controller's internal state**, and it **only works when live-debug is already toggled on** (the lens must annotate whether or not the user has enabled the live loop). A self-contained second dry-run keeps the lens independent; the extra dry-run is a dev-time preview cost, not a hot path.

**PHI posture — reuses ADR 0072's `--show-phi` redaction gate, adds no second gate, persists nothing (CLAUDE.md §9):**
- **Redacted by default.** The lens's trace argv **never contains `--show-phi`** (`buildLensTraceArgs` cannot emit it), so the CLI redacts every captured value at the source; the fold renders the same `▸ ⋯` placeholder the #92 inline path uses. This is the same redaction gate as live-debug — not a new one.
- **Never auto-reveal.** The fold defaults `reveal` off and the provider **always** calls it off; nothing in the lens flips it on or auto-passes `--show-phi`. (A future reveal control, if added, must match live-debug's separate, off-by-default, per-session "reveal values" convention exactly.)
- **Never persisted.** The trace JSON is consumed **in-memory over stdout** — there is no on-disk trace artifact to leak or accidentally commit.
- **Synthetic only.** The picker defaults to `messageSetsDir` (PHI-free corpora); tests use synthetic samples exclusively.
- **Graceful, never an error.** No sample picked, an exec-gated (untrusted) workspace, or a failed/empty trace all yield no values — the rows carry none and the toolbar's redacted placeholder stands; a live-value failure is never surfaced as an error.

## Amendment A (2026-07-30) — a `note` row kind: comment-only rows stop projecting as opaque `code` (BACKLOG #248)

> **Status of this amendment: ACCEPTED — ratified by the owner 2026-07-30.** It supersedes an
> owner-ratified decision (ADR 0106 §5 (L), ratified 2026-07-13); that supersession is now in force, and
> ADR 0106 §5 (L)'s "honest degrade" projection of an inserted Comment as a `code` row no longer holds.
> The evidence in §A.3 was verified against `main` before ratification.
>
> **In force means the grammar changed, not that the build is done.** §3's row enum now includes `note`
> and `diagnostic`; §4's ladder gains `note` as a sibling of the typed rows. BACKLOG #248 is the build
> and is now unblocked. The invariants in §A.4 are **build gates, not caveats** — in particular the
> pragma allowlist, the `_merge_code_rows` docstring exclusion, and the rule that a note edit takes its
> indentation and `#` prefix form from the existing line rather than the insert normalizer. §A.6's two
> known-wrong behaviours are **not** fixed by this amendment and must not be reported as fixed.

§3's row enum ends at `{ "kind": "code", … } // verbatim, unrecognized`, and §4's ladder sends
"everything else" there. A standalone comment is therefore projected as an opaque `Code` step. This
amendment **widens the grammar** under §2 ("widening the roster is an ordinary addition, widening the
*grammar* (§4) requires amending this ADR") to add a sixth-and-seventh row kind and one recognition
rule, and reconciles §3's enum with what the lens has actually emitted since ADR 0106.

**This amendment supersedes an accepted decision, not merely an omission.** ADR 0106 §3 (`0106:62`)
lists the palette's Comment item with row kind `code`, and §5 (L) (`0106:105`) states `insert_comment`
"reads back as a read-only `code` row (**honest degrade**)"; the owner ratified shipping it that way on
2026-07-13 (`0106:134`). That projection is hereby superseded. The honesty argument stands for
*unrecognized* constructs; it does not survive three shipped defects (below) in which the comment is not
degraded but **lost, absorbed, or frozen**.

### A.1 Decision

`lens parse` emits, in addition to the §3 kinds:

```
{ "kind": "note", "text": "<comment body, verbatim, without the leading '#'>",
  "raw": "<the physical line, verbatim>", "pragma": true|false,
  "line_start": <int>, "line_end": <int>, "nesting": <int> }
```

A `note` row is emitted for a **run of one or more standalone comment lines** at the same suite and
indent inside a handler def body. A comment sharing a line with a statement (trailing/inline) is **not**
a note and is not extracted — it stays inside the owning statement's row span, where the §5 byte-span
splice already preserves it.

`note` is added to §4's ladder as a *sibling of the typed rows*, not a new rung: **typed row (action /
lookup / control / send / diagnostic / note) → `code` row → whole-file refusal only on parse failure.**
The ladder still has exactly three rungs. `LensParseError` remains the only refusal, and it remains
file-scoped.

### A.2 §3 enum reconciliation (drift that predates this amendment)

§3 as written lists five kinds. The shipped parser emits **six**, and carries four optional fields §3
does not name. Recorded here so the contract is not restated wrongly:

- `diagnostic` (`lens.py:757`) — `log_note` / `checkpoint`, shipped under ADR 0106 §5 (K) without a
  0076 amendment; `_EDITABLE_KINDS = frozenset({"action", "lookup", "send", "diagnostic"})`
  (`lens.py:1377`).
- optional `assign_to` on `lookup` rows; optional `literal_params` on `action`/`lookup`/`diagnostic`
  rows; optional `appended` on `send` rows; optional `scaffold` (`collector_init` / `return_collector`,
  ADR 0108) on `code` rows.
- `lens.py`'s own module docstring (`:3-8`) still names five kinds and is stale the same way; the build
  fixes it.

**With this amendment the §3 enum is: `action`, `lookup`, `control`, `send`, `diagnostic`, `code`,
`note`.** No numbered section is added or renumbered — §3/§4/§5 are amended **by name**, deliberately,
because ADR 0089 (`:55`) and ADR 0108 (`:5`) already mis-cite the row-scoped-splice contract as "§6"
when it is **§5** (§6 is Consequences + test gates). Renumbering would rot every inbound citation
further.

### A.3 Rationale — three shipped defects, not a coverage percentage

The coverage motivation is **reproducible from `main` as of PR #81 (merged 2026-07-30)**:
`scripts/quality/lens_coverage.py` drives the shipped `lens parse --json`, so the de-identified-estate
scan (388 files · 145 handlers · 1,423 rows · 0 parse refusals; **editable share 42.0%**, **fully-typed
handlers 14.5%**) can be re-run rather than taken on trust. Its comment-only split — **28% of opaque
rows, 146 of 522** — was reported in PR #81's comments and is **not committed as data**, so it must be
**re-derived by running the scan**, not quoted from this ADR, before it is used as a build warrant. Note also that #239's pre-registered rule fired RED and the RED prescription was overridden
on the "comment-only + helper delegation ≈ 70% of the opaque mass" argument — recorded on that same
branch as **a delegated judgment call never explicitly ratified by the owner**.

What *is* reproducible today, against `main`, is that the Comment palette item is broken in three ways:

1. **A Comment inserted after the last statement of a handler disappears entirely.** The partition
   covers `[body[0].lineno, node.end_lineno]`, and `FunctionDef.end_lineno` is the last *statement's*
   last line (`lens.py:307-311`, by design per `:19-21`). The comment is outside every row, so it is
   not rendered at all — not degraded, absent. The row context menu offers **Insert after** on any
   non-return row (`stepsModel.ts:1187`), so this is one click away on any handler not ending in a
   `return`.
2. **A Comment adjacent to any other opaque or blank line produces no row at all.**
   `_merge_code_rows` (`lens.py:1245-1266`) coalesces contiguous same-nesting `code` rows; an existing
   Code row silently grows by one line and the user's insert is invisible as a step.
3. **An inserted Comment cannot be edited, deleted, or moved.** `rewrite_source` gates on
   `_EDITABLE_KINDS` (`lens.py:1479-1484`), which excludes `code`. This contradicts the shipped user
   doc, `docs/STEPS-PALETTE.md:70-71` — "Everything is editable after insert" — for which Comment is
   the sole exception.

The existing test does not protect any of this: `test_insert_comment_reads_back_as_code_row`
(`tests/test_lens_palette.py:751`) asserts only `any(r["kind"] == "code" …)`, which passes even when
the comment merged into an unrelated row. **The build lands failing tests for (1) and (2) first.**

### A.4 Invariants this widening must preserve (each is a build gate, not a caveat)

- **Coverage partition (§3) — unchanged in kind, and the sub-tiling must be exhaustive.** A gap
  `[cursor, g_start-1]` that today becomes one `code` row may now split into note/code/blank rows; the
  sub-rows must be contiguous and exhaustive over that exact range. `tests/test_lens_parse.py:41-52`
  asserts `prev["line_end"] + 1 == nxt["line_start"]` literally and must stay green unmodified.
- **Byte-stable splice (§5) — a note edit is a NEW class of rewrite and must be built as one.** A
  comment has no `ast` node, so every existing locator is unusable: `_find_stmt` (`lens.py:1661-1676`)
  and `_locate_stmt` (`:1913-1932`) match on **exact** `[lineno, end_lineno]`, `_splice_slots`
  (`:1741`) splices an argument's byte span, `_apply_delete_row` (`:1991`) deletes a statement span.
  Editing note text is the lens's first regeneration of a whole physical line, which breaches the
  stated property at `lens.py:1361-1363` (the template "reuses each unchanged argument's verbatim
  source segment") — there is no verbatim segment to reuse. **The edit must therefore take
  indentation, the `#` prefix form, and the line terminator from the existing line**, never from
  `_paste_anchor_indent` and never from the insert normalizer.
- **Do not reuse the `insert_comment` normalizer for edits.** `lens.py:3021-3022`
  (`text.strip().lstrip("#").strip()` → `f"# {body}"`) is correct for *authoring* and lossy for
  *editing*. Measured: `## banner` → `# banner`; `#region Setup` → `# region Setup`;
  `  #   spaced  ` → `# spaced`.
- **Round-trip.** parse → `set_params{text}` with the *same* text SHALL be byte-identical (the no-op
  property `rewrite_source` already promises at `lens.py:1435-1436`); parse → edit → reparse SHALL
  yield the same `kind`, span, nesting, and suite.
- **Whole-file refusal only on parse failure (§4) — unchanged.** No comment content may cause a
  refusal. Anything a note recognizer declines falls back to `code`, never up to a refusal.
- **Pragmas are functional code and are read-only.** A note whose text matches a prefix allowlist —
  `# fmt: off` / `# fmt: on` / `# noqa…` / `# ruff: noqa` / `# type: ignore` / `#region` /
  `#endregion` — is emitted with `"pragma": true` and is **not editable, not movable, not deletable**.
  Without this, a movable note can relocate a `# fmt: off` and break §6 gate 3
  (`ruff format --check`), or delete a standalone `# noqa` and turn CI red.
- **`_merge_code_rows` becomes kind-aware.** A note must never glue onto a docstring: the handler
  docstring is `body[0]`, a real `ast.Expr(Constant)`, and today merges with a following comment into
  one row. The docstring **stays a `code` row** — it is an executable statement and `_apply_delete_row`
  already handles it correctly as one.
- **Control-header spans must shrink, and that is a fixture-visible contract change.** `_emit_if`
  (`lens.py:566-583`) emits the header as `[node.lineno, first-1]`, so a comment placed as the *first*
  line of any `if`/`for`/`else` body is currently swallowed into the header row. Emitting it as a note
  requires shrinking `line_end` and tiling the remainder, which changes `expect_src` and every
  committed fixture for such blocks. Blast radius is bounded (only blocks with a leading comment or
  blank) and `_locate_stmt_by_header` (`:1935-1956`) keys on `line_start` only, so move/delete survive
  — but this is a real change, not free.
- **`_paste_anchor_indent` must be fixed before blank-only rows become common.** Anchoring an insert on
  a blank-only row **already fails today** (`LensRewriteError: … unexpected indent`) because
  `_paste_anchor_indent` (`lens.py:1995-2014`) finds no non-blank line and derives indent `""`; its own
  docstring at `:2002` calls that case "defensive — a real row always has a non-blank line", which is
  already untrue. Splitting notes away from adjacent blanks multiplies the refusal.

### A.5 Non-goals (explicit — each of these is how this becomes a different, declined feature)

- **A note is a LEAF row with no membership semantics.** No grouping, no collapse, no "the steps below
  belong to this note", no start/end pairing, no `#region` folding, no nesting of other rows under it.
  The moment it acquires any of those it **is** BACKLOG #231, **declined by owner ruling 2026-07-20**
  on the #26 grounds that such a row "would project **nothing executable** — it is chrome authored in
  the canvas." #231's own rejected options included the "bare section-header comment" as a soft
  boundary. This sentence exists so the next session does not re-litigate #231 in good faith.
- **No module scope.** Notes are emitted inside handler def bodies only. Shebang, SPDX, module
  docstring, and imports are verified outside every partition and stay there.
- **No attachment to a following statement.** Widening an action row's span upward to swallow its
  leading comment breaks `_find_stmt` / `_locate_stmt` exact-span matching, so `set_params` and
  `delete_row` would begin failing with "internal: could not locate the statement" on **every** action
  that has a leading comment. Attachment ("a statement travels with its leading comment block") is a
  separate, larger item and is gated on BACKLOG #233 — `blockExtent` / `walkMove` / `resolveDrop` are
  implemented twice (`ide/src/stepsModel.ts:1767` vs `ide/media/stepsWebview.js:68`) with no
  differential test.
- **No inline/trailing-comment extraction.** Verified working today: `set_params` on
  `msg.set("PID-3.1", "X")  # noqa: E501` preserves the pragma exactly, and interior comments in a
  multi-line call are absorbed into the action row's span. A note kind must not touch either.
- **No heuristic for commented-out code.** A parseable-as-Python test to exclude `# msg.set(…)` is a
  mini-language, already rejected by ADR 0106 §7. The row is titled honestly ("Comment", verbatim text)
  rather than "Note", and no heuristic is added.
- **No docstring reclassification.**

### A.6 Known-wrong behaviours this amendment does NOT fix (stated so they are not mistaken for fixed)

- **Move/delete of a *recognized* row already re-attaches neighbouring comments to the wrong step.**
  `_apply_move_row`'s docstring (`lens.py:2502-2503`) states this as intended "comment-tolerant"
  behaviour. Verified: moving the second of two commented actions leaves it under the first action's
  comment and orphans its own. A `note` row does **not** fix this — it makes the misattribution
  *legible*, which is worse: a grey Code box becomes a clean "Note" step confidently asserting
  something false. **v1 must therefore either land the extent fix or render notes as explicitly
  positional (a divider-styled row, not a caption on the step beneath).** It may not be silent on this.
- **A comment at the END of an `if`/`for` body projects at the PARENT nesting.** Verified: an
  8-space-indented comment after the last body statement emits with `nesting: 0`. Harmless as a grey
  box; as a "Note" it renders visually outside the loop while the `.py` has it inside, and it feeds
  `walkMove`/`resolveDrop` if notes ever become movable.

### A.7 Contract-version skew (must be handled, not discovered)

`parse_source` emits no schema version and the extension shells whatever `messagefoundry` is on `PATH`
(§5). An older IDE receiving `kind:"note"` hits `rowTitle`'s default-less switch
(`stepsModel.ts:288-312`) → `undefined` title, and `buildRowViewModel` (`:459-461`) populates `vm.code`
only for `kind === "code"` → the text never renders. Result: a **blank, titleless row**. Not corrupting
(the webview's read-only guards key on `draggable`, which `isRowMovable` leaves false for an unknown
kind), but a visible break. **`note` emission is gated behind a flag or a contract version.** The kind
must also be threaded through both implementations — `stepsModel.ts` (`359`, `371-376`, `384-386`,
`401`, `459`, `1187-1192`) and the CSP-isolated `stepsWebview.js` (`87`, `388`, `469`, `688`,
`700-701`), which cannot import from `src/`.

### A.8 Measurement discipline

`note` rows are counted in **their own bucket** and are **excluded from the editable-share numerator**
in the BACKLOG #239 scan. Reclassifying ~146 of 522 opaque rows as editable would move a P1 investment
metric by roughly ten points without converting a single transform statement. #239 is re-run before and
after so the delta is attributable.

### A.9 Consequence deltas

§6's ladder consequence ("one hand-written line does not eject the whole handler") is unchanged. §6
gate 1 (coverage partition) is unchanged in substance and gains sub-tiling cases. §6 gate 2
(byte-stability) gains a new op class and the round-trip property above. §6 gate 3 (`ruff format
--check`) is now load-bearing in a second way — the pragma allowlist exists to protect it.
`docs/STEPS-PALETTE.md:70-71`'s "everything is editable after insert" becomes true for the first time.
New residual: pragma notes are visible but read-only, an intentional and documented asymmetry.

## Acceptance Criteria

- **AC-N1** — WHEN a handler def body contains a run of standalone comment lines, THE SYSTEM SHALL emit
  a `note` row spanning exactly those lines at the enclosing suite's nesting, and the emitted rows SHALL
  still exactly partition the def body → coverage-partition property test, extended with
  comment/blank/pragma corpora.
- **AC-N2** — WHEN a Comment is inserted after the last statement of a handler, THE SYSTEM SHALL either
  render it as a `note` row or refuse the insert with a clean error; it SHALL NOT accept the insert and
  render nothing → regression test for the vanishing-comment defect, written failing first.
- **AC-N3** — WHEN a `note` row's text is set to its current value, THE SYSTEM SHALL produce a
  byte-identical file; WHEN it is set to a new value, THE SYSTEM SHALL change only that row's line
  range, SHALL preserve the original indentation and `#` prefix form, and the result SHALL re-parse to
  the same kind, span, nesting, and suite → byte-stability + round-trip test refs.
- **AC-N4** — WHERE a comment matches the pragma allowlist, THE SYSTEM SHALL emit `"pragma": true` and
  SHALL refuse `set_params`, `delete_row`, and `move_row` on that row → pragma-immutability test refs.
- **AC-N5** — THE SYSTEM SHALL NOT emit a `note` row at module scope, for a handler docstring, or for a
  comment sharing a line with a statement; a trailing `# noqa` SHALL survive a `set_params` on its
  statement byte-for-byte → negative test refs.
- **AC-N6** — WHEN a construct is unrecognized, THE SYSTEM SHALL emit a `code` row; a whole-file refusal
  SHALL occur only on `ast.parse` failure → unchanged ladder assertion, re-run over the note corpus.

## Amendment B (PROPOSED, 2026-07-30) — ADR 0089 Phase D "helper descent"

> **Status of this amendment: PROPOSED — owner-gated, not ratified, not buildable.** Amendment A above
> is independent of this one and does not depend on it. This section exists so the grammar change Phase
> D implies is specified and priced *before* anyone builds it, per §2's amendment rule; it is not a
> licence to start.

ADR 0089 §2 names Phase D — "descend into same-module helper functions … projecting each `_fn(msg, …)`
call as an expandable group whose rows are the helper body's recognized actions, edited in place
(rewrites target the helper's own line span)" — and grades it "the largest structural lever and the
highest-risk (cross-function byte-stable rewrite)". That is a paragraph of intent. It commits to five
things (same-module scope; an expandable group; rewrites targeting the helper's span; ships after A–C;
highest risk) and specifies **none** of: the row shape, line-range semantics, recursion rule,
duplicate-call-site rule, the coverage-invariant restatement, or a test list.

Phase D is a **grammar widening under §2** and, unlike every prior Steps widening, it is **not
additive**: ADR 0104/0106/0108 each added only fields an older consumer could ignore. Descent changes
the *shape* of `rows`.

### B.1 What descent breaks, and what the build must therefore decide

- **§3's coverage partition.** Rows today are a flat, contiguous, source-ordered partition of one def
  body; `tests/test_lens_parse.py:41-52` asserts contiguity literally. A helper body is a disjoint line
  range and may be defined *above* the handler. So gate 1 must be restated as one of: **(a)** a nested
  `children` array (the "expandable group" reading) — "the origin-handler rows partition the def body,
  and each descended group's children partition *its* helper def body"; or **(b)** a flat list with an
  `origin` field, in which case `rows == sorted(rows, key=line_start)` no longer holds. **Not decided.**
- **Every rewrite op is hard-scoped to the handler def.** `rewrite_source` resolves
  `handler_node = _handler_def(...)` (`lens.py:1486`) and threads it into eight ops (`:1493-1524`);
  `_find_stmt` (`:1661`), `_locate_stmt` (`:1974`) and `_locate_stmt_by_header` (`:2507`) walk
  `handler_node.body` only. A row whose statement lives in another `FunctionDef` is simply not found →
  `LensRewriteError("internal: could not locate the statement …")`. Descent is not a parser change with
  a rewrite follow-on; it changes scope resolution in **all eight ops at once**. The ops that reason
  about handler-ness — `_delivering_accumulators`, `_accumulator_footer/_init`, `_is_send_return`,
  `_convert_return_to_accumulator` — must **refuse** when the owning def is a helper: a `return` in a
  helper is not a Send, and a `sends.append` in a helper is not a fan-out.
- **Aliasing — the most likely user-visible corruption.** `_find_contract_row` (`lens.py:1640-1650`)
  returns the **first** row whose span matches exactly. If `_pid(msg)` is called twice, both descended
  groups carry identical child spans. Row identity can no longer distinguish the call sites; `expect_src`
  (`:1533-1551`), the stale-coordinate guard, matches both and provides **zero** protection; an edit
  "in call site 2" mutates the bytes of call site 1. Reorder and delete are worse. **No ADR text
  addresses this. It must be decided before any code.**
- **Live values become structurally impossible.** §Addendum folds `dryrun --trace json` onto rows by
  line containment, but the ADR 0072 tracer **deliberately refuses helper frames** —
  `dryrun_trace.py:27-29` ("line-traces **only** the exact Router/Handler frame, matched by code-object
  identity"), implemented at `:297-303`. Every descended row would show the redacted placeholder
  **forever**. Phase D therefore requires an **ADR 0072 amendment** as well as this one, plus a rule for
  the same helper line executing twice in one message (`traceRowValues` currently resolves collisions
  newest-invocation-wins, `stepsModel.ts:621-628`, which would show call site 2's value on call site
  1's row).
- **A fourth §5 byte-scoping exception, larger than the existing three.** ADR 0106 §6 established the
  format: "**three** sanctioned exceptions, all idempotent and `_assert_reparses`-gated" (import
  injection, clause-append, code-set binding). Descent writes outside the *handler*, not merely outside
  the row range. It must be adopted explicitly as a fourth, with the same gating.
- **Recursion and cycles.** No guard exists. `_a → _b → _a` needs a depth cap, a cycle detector, and a
  decision on what a truncated group renders as. **Unspecified.**
- **The `msg` name is a hard, unmeasured precondition.** `_is_msg_method` (`lens.py:145-155`) requires
  the receiver to be the bare name `msg`. A helper written `def _msh(message): message.set(...)`
  recognizes **nothing** — descent projects an all-opaque group. Nobody has measured what fraction of
  the estate's helpers name their first parameter `msg`.
- **Non-literal arguments display names that do not exist at the call site.** Descending
  `_carry_then_clear_visit(msg, orig_patient_class)` yields a row reading
  `msg["PV1-18"] = orig_patient_class`, a *helper parameter*. Same for `for i in …: _obx(msg, i)` →
  `occurrence=i`. The user is shown an identifier they cannot see.

### B.2 The evidence problem — Phase D's yield is unmeasured and can be NEGATIVE

- **Three incompatible populations.** ADR 0089 §1 counts **3,852 statements / 486 `msg`-manipulating
  functions / 87 files** (2026-07-13); the 2026-07-30 scan counts **1,423 rows / 145 handlers / 388
  files**; ADR 0104's scan cites **152 handlers**. "~66% opaque → 42.0% editable" is **not** a
  like-for-like delta and must not be presented as a measured lift. §4's "~80–90%" is of *transform
  statements*; 42.0% is of *projected rows*. BACKLOG #239 already warns: "state which population any new
  number describes."
- **`218/522` (41.8%) is re-derivable but not committed as data** (see Amendment A.3) and is a **heuristic superset**:
  the scan's `classify_code_row` is explicitly "a HEURISTIC on source text, not a parse" and never
  checks whether the callee resolves to a `def`, let alone a same-module one. Phase D's own "265
  delegating call-sites" is a *statement*-scan number from a different population.
- **Descent makes nothing editable by itself.** It replaces N opaque delegating rows with the helper
  bodies' rows, whose editability is whatever Phases A/B/C already achieve *inside* helpers. Worked on
  the real numbers (1,423 rows, ~598 editable, 218 delegating): if each expands into ~6 rows at the
  estate-wide 42% recognition rate, the result is ≈ **45.6%**, a **+3.6pt** move.
- **And it can go the other way.** `msg["X"] = v` is **not recognized** — only `msg.set(...)` is
  (verified: `msg["MSH-4"] = mnemonic` → `code` row; `msg.set("PV1-18", "X")` → `action` row). The
  shipped sample helper `samples/config/_demo_oru_transforms.py` writes **exclusively** in the subscript
  form; descending into it today yields **six opaque rows and zero editable ones** — a strict regression
  of the headline metric.
- **A same-module probe over `samples/config` found zero descent targets.** Of 12 `code` rows, the
  scan's own heuristic classifies **8** as helper-descent candidates; **none** resolves to a same-module
  `def` (they are cross-module transform calls, dict lookups, engine-library parsers, a method on a
  second `Message`, and a parenthesized f-string with no call at all). The sample corpus is too small to
  estimate the estate, but it does show the heuristic admits a great deal that is not helper delegation.

### B.3 The scope may already be obsolete

ADR 0089 §4 excludes cross-file helpers; Phase D says "same-module". But the project's **own recommended
layout for exactly this estate** puts transforms in a **separate module** — `docs/CONNECTIONS.md:168-185`
("the per-feed *Hybrid* layout … `_<feed>_transforms.py` … **Transforms → a `_`-prefixed helper** keeps
the Handler a thin *filter → delegate → Send*"), and the estate is being actively migrated onto it (§7
erratum, #226 closed 2026-07-16 to the migration estate's own backlog). **Same-module-only descent could
ship obsolete for the very corpus that justified it.** Cross-module descent is a materially larger
change (module resolution, multi-file byte-stable rewrite, multi-file dirty-buffer alignment) and is
**not** proposed here.

### B.4 Preconditions — all three must clear before this amendment is put to the owner

1. **Measure the actual yield.** Extend the (unmerged) scan to (a) resolve each candidate callee to a
   same-module `def` via AST and (b) run `lens parse` semantics over those helper bodies, reporting
   their *internal* editable share. Until this exists, "218 rows = 41.8%" is an upper bound on a
   superset of a thing whose yield is unmeasured.
2. **Land the cheaper lever first and re-measure.** Teaching Phase A the `ast.Assign`-to-`ast.Subscript`
   form (`msg["X"] = v`) converts writes to editable rows **without touching the row shape**, and it is
   on no phase list. It may move the metric further than descent for a fraction of the risk — and if
   helper bodies are written in the subscript form, descent *depends* on it to not regress.
3. **Respect ADR 0089's own ordering.** §7's recommended order is **A → C → B → D → E**; Phase B
   (inline value transforms, ~155 write-sites) is **unbuilt**. Phase D as the next increment jumps the
   ADR's queue, and the phase it jumps is the one that determines how editable helper bodies are.

Additionally: ADR 0089 §6 requires Phase D to "clear the same **3-breaker byte-stability bar** the
structural edits did". ⚠️ **That term appears exactly once across the entire ADR set and is defined
nowhere** — presumably ADR 0076 §6 gates 1/2/3, but an implementer would be guessing. **It must be
defined before it can be a gate.**

### B.5 Non-goals for Phase D as proposed

- **No cross-module descent** (§B.3), notwithstanding that this is where the estate is heading.
- **No descent into anything but a plain same-module `def`** — no classes, no closures, no nested
  `def`s (ADR 0106 §11 already rejected nested `def` for Block on scope-hazard grounds).
- **No editing across a helper boundary until aliasing is solved** (§B.1). A defensible v1 is
  **read-only descent**: expand and *see* helper rows, edit nothing. It delivers the legibility half of
  the owner goal at a fraction of the corruption risk, and it needs no rewrite-scope change at all.
- **No general Python structured editor** — ADR 0089 §4's ceiling is inherited unchanged.

### B.6 Consequence deltas (if accepted)

§3's coverage invariant is **restated, not preserved as written** — the first such change since the ADR
was accepted. §5's row-scoped-splice contract gains a fourth sanctioned exception. §6 gate 1's property
test must be rewritten. The ADR 0072 frame-scoping decision must be reopened. `lens parse`'s JSON
contract stops being additively back-compatible, which forces the contract version that Amendment A §A.7
already recommends.

## Acceptance Criteria (Amendment B — proposed, not ratified; deliberately outside the counted block)

*(Kept under a distinct heading so unratified criteria do not merge into this ADR's accepted
Acceptance Criteria bucket. Promote to the block above if and when the owner accepts.)*

- **AC-D1** — WHEN `lens parse` descends into a same-module helper, THE SYSTEM SHALL emit rows such that
  the origin-handler rows exactly partition the handler def body AND each descended group's children
  exactly partition the helper def body, with no line in two rows.
- **AC-D2** — WHERE the same helper is called from more than one site, THE SYSTEM SHALL either give each
  descended row a call-site-unique identity that `expect_src` can validate, OR refuse every mutating op
  on rows in that group with a clean, user-facing reason.
- **AC-D3** — WHEN an op targets a row whose owning def is a helper, THE SYSTEM SHALL resolve the owning
  def rather than the handler, and SHALL refuse handler-only semantics (Send-return conversion,
  accumulator init/footer) in helper scope.
- **AC-D4** — WHEN a helper call graph contains a cycle or exceeds the configured depth, THE SYSTEM
  SHALL truncate the group deterministically and render the truncation, and SHALL NOT recurse without
  bound.
- **AC-D5** — Descended rows SHALL either carry live values (requiring an accepted ADR 0072 amendment
  widening the tracer's frame scope) or SHALL render an explicit "not traced" state distinguishable from
  PHI redaction — never a redacted placeholder that can never resolve.
