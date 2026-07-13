# ADR 0106 — Steps-view authoring palette (ADR 0076 Phase B)

**Status:** Proposed (2026-07-12) — awaiting owner ratification. This is the **design + palette + build plan**; the `ide/` implementation is the owner's lane (BACKLOG #222) and must be coordinated with the `mefor-ide-build` worktree — do not build `ide/` from another session.
**Deciders:** owner + IDE/DX working group
**Related:** [ADR 0076](0076-typed-action-vocabulary-action-list-lens.md) (the typed action vocabulary + action-list lens this extends — §2 "widening the roster is an ordinary addition"; the recognition grammar §4; the row-scoped-splice contract §5), [ADR 0089](0089-recognition-first-lens-native-idioms.md) (recognition-first lens / native idioms — control rows recognized-but-read-only today; this ADR makes them **insertable**), [ADR 0103](0103-steps-view-row-context-menu.md) (row context menu — shares `INSERT_ACTION_LABELS`), [ADR 0104](0104-copy-on-send-outbound-message-model-recognition-first-handler-message-type-and-hl7-field-picker.md) (the HL7 field picker the path args reuse), [ADR 0033](0033-*) (code sets — the translation data), [ADR 0010](0010-*)/[ADR 0043](0043-*) (`db_lookup`/`fhir_lookup`), BACKLOG **#222** (Steps view), **#231** (deferred "Block" grouping), **#26** (the declined visual-authoring line + its structured-Steps-view carve-out). Derived from two code-grounded multi-agent design passes this session (Corepoint-action evaluation over the 53-action palette + a full-spec design with three adversarial critics; 13 findings folded in).
**Code references** are `origin/main`; line numbers drift — locate exactly at build time (key files in `mefor-ide-build`). *(This supersedes the transform-only roster the first draft of this ADR carried; the transform half is unchanged and folded in as Group 1.)*

---

## 1. Context

The shipped **Steps view** (ADR 0076/0089) renders any parseable `@handler` as an ordered list of typed **steps** whose **Add** menu inserts a new one. Today it offers only **three** items (Set/Copy Field, Delete Segment) — far short of what an HL7 interface analyst needs to author a real interface: string/date/segment ops, translation tables, branching, iteration, routing, and diagnostics. Corepoint's own palette has ~53 actions; an analyst who doesn't know Python cannot use an operation that isn't in the menu.

This ADR defines the full **authoring palette** — four groups, ~22 items — so an analyst can build a complete handler (branch → transform → translate → route/filter → log) in the Steps view, while every row remains a projection of **real native Python**.

**Invariant (unchanged from ADR 0076 §2/§4, CLAUDE.md §12).** The `.py` file is the **only** artifact and the **only** execution path. Inserting a palette item **generates native Python the lens then recognizes** — it is codegen, never a declarative logic engine or canvas (#26). Transforms stay **pure** (message in → message out); the only non-pure inputs are the sanctioned read-only `db_lookup`/`fhir_lookup`, and the only output-independent side effect is logging (a re-run yields an identical message; the extra log line is harmless). Control flow is **native Python** — the change here is making the lens *insert* it, not interpret it.

## 2. Decision

Grow the Add menu to a grouped **authoring palette**: **Transform** (16), **Translate & lookup** (2), **Structure & flow** (7), **Diagnostics** (2). Four new pure helpers (`trim_field`, `substring_field`, `pad_field`, `replace_literal`) plus two more (`date_diff_field`, `arith_field`) land in `actions.py`; two diagnostics helpers (`log_note`, `checkpoint`) land in a **separate** `messagefoundry/diagnostics.py` (logging doesn't belong beside `actions.py`'s pure/no-I/O contract). The load-bearing engine work is making the lens **insert** control/send/diagnostic rows (recognized-but-read-only today) via native codegen, plus idempotent import injection. **"Block" is deferred to BACKLOG #231** (no idiomatic native-Python fit yet).

## 3. The palette

Columns: **Label | Generated Python | Helper | Params (+ picker/injection) | Row kind.**

### Group 1 — Transform
| Label | Generated Python | Helper | Params | Row |
|---|---|---|---|---|
| Set Field | `msg.set("MSH-9.1", "ADT")` | native, shipping | path (field picker), value | action |
| Copy Field | `msg.set("PID-6.1", msg.field("PID-5.1") or "")` | native, shipping | dst, src (pickers) | action |
| Clear Field | `msg.set("PID-19", "")` (HL7-null seed `'""'`) | Set-Field preset | path | action *(reads back as Set Field)* |
| Trim | `trim_field(msg, "PID-5.1")` | **NEW** | path | action |
| Substring | `substring_field(msg, "PID-3.1", 0, 6)` | **NEW** | path, start, end | action |
| Pad | `pad_field(msg, "PID-3.1", 10, fill="0", side="left")` | **NEW** | path, width; fill/side kw | action |
| Convert Case | `convert_case(msg, "PID-8", "upper")` | existing | path, mode enum | action |
| Replace Literal | `replace_literal(msg, "PID-5.1", "MRS", "MS")` | **NEW** | path, old, new (**`str.replace`, not regex**) | action |
| Append to Field | `append_to_field(msg, "PID-5.1", ", Jr")` | existing | path, suffix | action |
| Format Date | `format_date(msg, "PID-7", "%Y%m%d", in_fmt="%m/%d/%Y")` | existing | path, out_fmt; in_fmt kw | action |
| **Date Diff** | `date_diff_field(msg, "PV1-44", "PV1-45", "ZLS-1", unit="days")` | **NEW** | start/end/dst pickers; unit kw | action |
| **Compute** | `arith_field(msg, "OBX-5", "*", 2.20462, ndigits=1)` | **NEW** | path; op **closed 4-enum**; operand; ndigits kw | action |
| Insert Segment | `msg.add_segment("NTE")` | native (new branch) | segment_id; index kw | action |
| Copy Segment | `copy_segment(msg, "PID", index=2)` | existing | segment_id; occurrence/index kw | action |
| Delete Segment | `msg.delete_segments("ZID")` | native, shipping | segment_id | action |
| Add Repetition | `msg.add_repetition("PID-3", "MR123^^^HOSP")` | native (new branch) | path, value; occurrence kw | action |

### Group 2 — Translate & lookup
| Label | Generated Python | Helper | Params | Row |
|---|---|---|---|---|
| **Code Lookup** *(reclassified insertable)* | `code_lookup(msg, "PID-8", GENDER)` + module `GENDER = code_set("gender")` | existing | path picker; `table` = **named code-set picker** (ADR 0033) → injects the binding; default kw. `table` is a Name, **not** inline-editable | lookup |
| Live Lookup *(Handler-only)* | `row = db_lookup("CLARITY", "SELECT …", (msg.field("PID-3.1"),))` / `fhir_lookup(...)` | sanctioned live reads | assign_to id; connection picker; statement/query; params tuple (edit-in-`.py`) | lookup (assignment) |

### Group 3 — Structure & flow
| Label | Generated Python | Helper | Params | Row |
|---|---|---|---|---|
| If | `if msg.field("PID-3.1") == "A":` ⏎ `    pass` | native (insert template) | field picker · operator ∈ **{exists, equals, not-equals, contains}** · value · power-user `test:{expr}` escape hatch | control (+ seeded `pass`) |
| Else If | `elif …:` ⏎ `    pass` | native (**clause-append**) | same form; only inside an `if` | control |
| Else | `else:` ⏎ `    pass` | native (clause-append) | none; only if the `if` has no `else` | control |
| For Each | `for i in range(1, msg.count_segments("OBX") + 1):` ⏎ `    pass` | native (segment-count form only) | segment_id picker; **gated on occurrence-aware actions** | control |
| Send | `return Send("OB_ACME_ADT", msg)` | native (recognized send, now insertable) | destination = outbound picker; message (seed `msg`); inject `Send` import | send |
| Filter | `return []` | native (new discriminant) | none — drop the message | send *(`filtered: true`)* |
| Raise Error | `raise ValueError("PID-3 missing")` | native (new `ast.Raise` branch) | exc-type ∈ {ValueError, RuntimeError}; message | control (`raise`) |
| Comment | `# fix ORC-2 before send` | native (**raw-line** op) | text | code |

*(Block → deferred to BACKLOG #231.)*

### Group 4 — Diagnostics *(the one output-independent side effect; PHI-gated)*
| Label | Generated Python | Helper | Params | Row |
|---|---|---|---|---|
| **Log Note** *(≠ "EnvLogText")* | `log_note("MRN {} adm {}", msg.field("PID-3.1"), msg.field("PV1-44"))` | **NEW** `diagnostics.py` | template (inline); operands = field paths (recognized-only) | diagnostic (new kind) |
| **Checkpoint** *(≠ "MsgLog")* | `checkpoint(msg, "after PID normalize")` | **NEW** `diagnostics.py` | label (inline); msg read-only | diagnostic |

## 4. New helpers

`actions.py` (pure, `msg`-first, in-place, no clock/file/socket/DB; register in `__all__` + `_ACTION_PARAMS` with scalar positional params so literals are inline-editable):

| Helper | Signature | Hardening |
|---|---|---|
| `trim_field` | `(msg, path)` | read → `.strip()` → set; no-op on absent |
| `substring_field` | `(msg, path, start, end=None)` | pure decoded-value slice + structural re-encode |
| `pad_field` | `(msg, path, width, *, fill="0", side="left")` | pure `rjust`/`ljust`; `side` validated → `ValueError` |
| `replace_literal` | `(msg, path, old, new)` | `str.replace` **only** — never regex (mini-language → #26 / non-determinism) |
| **`date_diff_field`** | `(msg, start_path, end_path, dst, *, unit="days")` | parses **two message fields** via `parse_hl7_timestamp`, **never `now()`** → re-run identical; `unit` validated; unparseable → `ValueError` → dead-letter |
| **`arith_field`** | `(msg, path, op, operand, *, ndigits=None)` | **bounded**: `op` validated in-helper against `{"+","-","*","/"}` via `if/elif` — **no `eval`, no `operator` reflection, no dict-of-callables**; a hand-spliced `"**"` fails loud; div-by-zero → `ValueError`; `round()` = banker's; deterministic → pure |

`diagnostics.py` (a **separate** module — `actions.py` promises no-I/O; logging belongs elsewhere):

| Helper | Signature | Guardrail |
|---|---|---|
| **`log_note`** | `(template, /, *values)` | `logger.debug` only; **every** value → `TRACE_REDACTED` placeholder by default (raw only under a `dev`-clamped diagnostic-reveal setting, mirroring `dryrun --show-phi`). Test: default path emits **zero** operand values |
| **`checkpoint`** | `(msg, label="")` | `logger.debug` only; emits a **redacted structural summary** (segment/field *names*), never field values / full body; references the store's raw-preservation |

## 5. Engine changes (lens grammar / insert / recognizer) — each with its guardrail

- **(A) Multi-line statement templates through the audited paste machinery.** Generalize `_apply_insert_row` on a `template` selector; If/For Each/Send/Filter/Raise render to source and route through `_parse_pasted_block` → reindent → per-line length guard → keepends splice → `_assert_reparses`. Reuses the already-verified paste helpers, so validity + `ruff`-format cleanliness come for free; single-line vocabulary calls keep the fast path.
- **(B) Nested bodies + degrade-to-code-row.** Control templates render header + a seeded `pass` (an empty suite is invalid); readback partitions into a control-header row + a `pass` code row; a hand-edit past the grammar already degrades to a read-only `code`/`control(recognized:false)` row (no new code).
- **(C) For Each recognizer + inhabitability.** Tighten `_is_message_iteration` to **validate arity** (so a bad `msg.segments("OBX")` degrades to a code row instead of a false-green row — a real corruption caught in review); the insertable iter-kind is the **already-recognized** segment-count loop only; add `occurrence=`/`repetition=` passthrough to the `msg`-first helpers so the loop var is inhabitable (bound as `occurrence={expr:"i"}`, read-only display). `repetitions(...)`/`groups(...)` loops stay **recognized-only**.
- **(D) Clause-append for Else If / Else** (`_apply_insert_clause`, new op). Renders the **whole enclosing `if` span** with the new clause via the paste machinery; **refuses (zero change)** unless every non-clause byte is reproduced, or when there's no enclosing `if`, or a duplicate `else`. → an **explicit ADR-sanctioned exception** to §6's row-scoped byte-splice.
- **(E) Filter discriminant.** Recognize empty `return []`/`return ()` as a send row with **`filtered: true`** — **not** by overloading `outbounds: []` (which already means a dynamic-destination Send). Store-FILTERED mapping + subtitle key on `filtered`.
- **(F) Raise recognizer.** New `ast.Raise` branch → single-line `control:"raise"` row (`recognized:true`). Built-in exceptions avoid the import-scope refusal; `raise` maps to the post-ACK ERROR/dead-letter + AlertSink path (does **not** NAK the already-ACKed sender).
- **(G) `contains` labeling.** Extend `_field_condition`/`_classify_if_control` to also match `<literal> in msg.field(<literal>)` → `when field <path>` (a required recognizer change, not a freebie).
- **(H) Import injection (Q1) — the core enabling change.** Replace the insert-path refusal with **idempotent** `from messagefoundry import <name>` injection for every Tier-3 wrapper, `Send`, and the diagnostics helpers; idempotent, byte-stable elsewhere, `ruff` F821-clean, `_assert_reparses`-gated. → the **second** sanctioned exception to §6 byte-scoping (imports sit outside the row's range).
- **(I) Code-set binding injector** (`insert_code_lookup`, new op). Code Lookup injects module-level `NAME = code_set("<set>")` (blank-line-separated from the import block, per `ruff format`) + the `code_set`/`code_lookup` imports and emits `code_lookup(msg, path, NAME)` with `table` as a bare `Name` → stays out of the inline quick-form (no-inline-dict line holds). Idempotent (reuses a same-set capture) and **collision-guarded** (refuses a `NAME` already bound to a different code set or a non-code-set value). → the **third** sanctioned exception to §6 byte-scoping (the binding sits outside the row range). *The `code_set` registry it targets already exists (ADR 0033); this is lens-side injection only.*
- **(J) Live-lookup insert + `assign_to` tightening.** Introduce `_ASSIGNABLE_LOOKUPS = {"db_lookup","fhir_lookup"}` and gate `assign_to` on **that**, not on `_LOOKUPS` membership — else `code_lookup` (mutating, returns `None`) would emit a dead `x = code_lookup(...)`.
- **(K) Diagnostics recognition.** `_DIAGNOSTIC_PARAMS` + `_DIAGNOSTICS`; a `kind:"diagnostic"` branch; add `"diagnostic"` to `_EDITABLE_KINDS`. Only the `template`/`label` **literal** is editable; operands render verbatim.
- **(L) Comment raw-line op.** `insert_comment` splices a `# …` keepends line at the anchor indent, bypassing `_parse_pasted_block`; re-parse still passes; reads back as a read-only `code` row (honest degrade).
- **(M) Role gate (corrected premise).** Routers render **no** Steps view today (`parse_source` emits nothing for a `@router`), so the palette simply never renders for them — the router gate is a **forward/defensive** note, not a built deliverable; no `parse_source` change here.
- **(N) IDE surface — owner `ide/` lane, not built here.** `stepsModel.ts`/`stepsView.ts` (grouped catalog, template/clause insert requests, pickers, Handler-only badge, `"diagnostic"` RowKind, `filtered`/`raise` movable rows) consume this ADR's row contract; this ADR does not implement `ide/`.

## 6. Rewrite semantics + the three byte-scoping exceptions + PHI

- **Row-scoped splice, never reformat** (ADR 0076 §5) still governs single-row edits. This ADR introduces **three** sanctioned exceptions, all idempotent and `_assert_reparses`-gated: **import injection** (H — imports sit outside the row range), **clause-append** (D — renders the whole enclosing `if` and refuses unless every non-clause byte is preserved), and the **code-set binding injection** (I — a module-level `NAME = code_set("<set>")` capture, blank-line-separated from the imports, injected only when the variable is unbound and refused on a name collision). All three keep every *other* byte of the file intact and are bracketed by the `ruff` / re-parse gates.
- **Static analysis only; sync on save; one editor at a time** — unchanged.
- **PHI (CLAUDE.md §9).** Diagnostics default to redaction: `log_note` interpolates `TRACE_REDACTED` for every operand; `checkpoint` emits only a structural summary — real values appear only under a `dev`-clamped reveal setting. No new PHI gate beyond ADR 0072's stream.

## 7. Explicitly OUT (and why)

Regex `matches` operator (mini-language in a widget; regex only via `test:{expr}`); inline-dict `code_lookup` table (declarative mapping data = #26; named code set only); Compute-as-string/`eval` (closed enum only); `now()`/clock reads (non-deterministic); DB/web writes + any live read beyond `db_lookup`/`fhir_lookup`; **Loop/Call/ChooseFrom/Try-Catch** (owner-declined — native Python); `repetitions`/`groups` loops as insertable body-composable (recognized-only until a rep/group-scoped action exists); **Block** (BACKLOG #231); Move/Set-if-empty/Remove-if-empty/Join/custom-script/cross-message (redundant, control-flow, list-valued, or stateful); router palette (routers have no Steps view).

## 8. Consequences + acceptance criteria

- Each palette item generates exactly the §3 Python and **round-trips** (recognized as its stated row kind; parse→rewrite byte-identical outside the edited range) → lens test refs.
- New helpers do **no I/O** (except the two diagnostics → `logger.debug` only), pass `ruff` + `mypy --strict`, add **no new runtime dependency**; `arith_field` rejects unknown `op`, diagnostics default to redaction (tests assert both).
- Inserting any item yields a file that passes `ruff`/`ruff format --check`/`mypy --strict`/`messagefoundry check`, with imports/code-set bindings injected idempotently and every other byte preserved.
- No OUT item is insertable; control/unrecognized constructs stay in-place read-only rows (coverage-partition holds); a bad-arity `msg.segments(...)` degrades to a code row (not falsely recognized).

**Two-way door:** Group 1 (transform) stands alone if the other groups are deferred; nothing else depends on the expansion.

## 9. Open questions

1. **For Each scope** — ship the segment-count loop **with** occurrence-aware actions in one phase, or ship the recognizer *hardening* now (bad loops degrade) and defer the insertable loop? *(Recommend: harden now, insertable loop follows.)*
2. **Occurrence slot** — insert-time-bound + read-only (recommended), or an editable-expression slot?
3. **`contains` recognizer** — extend `_field_condition` for the membership form (recommended), or accept a generic bounded row without the `when field` label?
4. **Diagnostics reveal** — confirm the reveal flag is `dev`-only + environment-clamped (per `docs/AI.md`).
5. **Comment timing** — ~~ship via the raw-line op now, or hold with the Structure grammar?~~ **Resolved (owner, 2026-07-13): ship now** — built as the `insert_comment` raw-line op (L).

## 10. Build plan (engine → lens → IDE)

- **Phase 1 — engine helpers + recognizer safety (pure, low-risk, no new grammar).** `actions.py`: `date_diff_field`, `arith_field` (+ the four wrappers), each with its `ValueError` guard + test. `diagnostics.py`: `log_note`, `checkpoint` (redact-by-default + "zero operand values" test). Recognizer hardening: `_is_message_iteration` arity check, `ast.Raise` branch, `return []` → `filtered:true`, `contains` membership label, `_ASSIGNABLE_LOOKUPS`. Register `_ACTION_PARAMS`/`_DIAGNOSTIC_PARAMS`/`_EDITABLE_KINDS`. *(Verifiable with `pytest`/`mypy`/`ruff` alone.)*
- **Phase 2 — lens insert/recognize (the grammar work).** Multi-line template dispatch (A/B); import injection (H); code-set injector (I); Tier-2 native branches (Insert Segment, Add Repetition); diagnostics insert (K); Comment raw-line op (L); live-lookup insert + assign_to tightening (J); then the two byte-scoping exceptions — clause-append (D) and For-Each insertable loop + occurrence slots (C).
- **Phase 3 — IDE surface (owner `ide/` lane; coordinate with `mefor-ide-build`).** Grouped Add-palette catalog, structured param forms, pickers (destination/code-set/segment/connection), Handler-only badge, movable/enablement rules, `"diagnostic"` RowKind. Contract-first against Phase 2's row shapes.

## 11. Alternatives considered

- **Companion ADR 0107 instead of expanding 0106** — rejected while 0106 is Proposed/unbuilt: the transform half and this expansion share one insert dispatcher, one recognizer, one byte-scoping contract, and the import-injection mechanism (0106's own open Q1); splitting would fork one grammar across two documents. Reach for a companion only if the owner later wants a built-vs-planned boundary at the document edge.
- **Per-item native recognizers for all transforms (no import injection)** — rejected: `format_date`/`copy_segment` have no single-`msg.*` form, and bespoke recognizers raise the "unsure → silent degrade" risk. Import injection is one change, not many.
- **`with block(...)` / bare header comment / nested `def` for Block** — all weighed and rejected (invented wrapper / soft boundary / scope hazard); Block deferred to BACKLOG #231.
- **Regex Replace / `matches`; inline-dict Code Lookup; Compute-as-expression** — rejected as mini-languages / declarative mapping data (§7).
