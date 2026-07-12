# ADR 0089 — Recognition-first lens: render native Message-API idioms as editable action rows

**Status:** Proposed (2026-07-11) — draft for owner ratification. Extends ADR 0076. Build is **gated on Acceptance**.
**Deciders:** owner + IDE/DX working group
**Related:** ADR **0076** (the Steps lens this extends — vocabulary + `lens parse`/`rewrite` machinery, byte-stability gate 2, sync-on-save, one-editor, text fallback), BACKLOG **#222** (the lens), **#225** (live values), **#226–#230** (this ADR's build phases), ADR **0072** (traced dry-run / live values rendered beside rows), ADR **0010/0043** (`db_lookup`/`fhir_lookup` — the read-only lookups a value expression may call), CLAUDE.md §8 (Message API), §9 (PHI).
**Code references** are `origin/main @ 1bbb409`; line numbers drift — locate at implementation time.

---

## 1. Context — the lens is blind to the code people actually write

ADR 0076 shipped a **vocabulary-first** lens: it renders editable "action" rows only for calls to the typed `messagefoundry.actions` wrappers (`set_field`, `copy_field`, …). Everything else becomes an in-place read-only `code` row (or an `UNRECOGNIZED` `control` row). The bet was that analysts would *author* in the vocabulary, so the lens would light up.

That bet does not survive contact with a real estate. A full AST scan of a real-world production config repository — **87 files, 486 `msg`-manipulating functions, 3,852 statements** — found:

- **0 uses of the `actions` vocabulary.** Every handler is written in the **native `Message` API** (`msg.set(path, value)`, `msg.field(path)`), plus plain Python control flow.
- **100% of handlers render with zero editable action rows.** ~66% of the projected rows are opaque `code`/`UNRECOGNIZED control`.
- The single dominant operation is **native `msg.set(...)` — 1,283 occurrences** (883 with a literal value, 78 field-to-field copies, 268 value-from-a-local, plus inline conditionals/transforms), which the lens shows as gray `Code` boxes like `msg.set("MSH-11.1", "T")`.

**Owner goal (2026-07-11):** *"Open any item in the estate and see everything in editable action rows."* The vocabulary-first lens cannot reach that goal, because it recognizes a form nobody writes. The migrated estate will not be rewritten into wrapper calls to satisfy a viewer.

The round-trip boundary from ADR 0076 still holds (structural constructs round-trip; arbitrary behavioral code does not), so "**everything** editable" has a real ceiling. The decision below maximizes editable coverage against that ceiling rather than pretending it is absent.

## 2. Decision

Pivot the lens from *vocabulary-first* to **recognition-first**: teach the parser to recognize the **native Message-API idioms and common control-flow patterns directly**, mapping each to the same editable row contracts ADR 0076 already defines, so a Handler written in idiomatic native Python renders as editable actions **without being rewritten**. The `.py` stays the only artifact and execution path; all ADR 0076 guardrails are inherited unchanged (byte-stable gate-2 rewrite via the existing byte-space splice, sync-on-save, one-editor-at-a-time, whole-file refusal only on parse failure, "Open as Text" fallback). The `actions` wrappers remain valid and are still the recommended way to author *new* Handlers — they are simply **no longer required** for the lens to be useful.

Recognition is added in phases, ordered by leverage (statement counts from the scan in §5):

### Phase A — native write/read atoms → editable rows  (~1,035 statements)
| Native idiom | Editable row | Editable fields |
|---|---|---|
| `msg.set("X", "lit")` | **Set Field** | path, value (883) |
| `msg.set(dst, msg.field(src))` | **Copy Field** | src, dst (78) |
| `msg.set("X", localvar)` / `msg.set("X", expr)` | **Set Field** (value = expression) | path editable; value editable as an expression string (268) |
| `x = msg.field("Y")` | **Read Field → var** | path, var name (22) |
| `msg.delete_segments("SEG")` | **Delete Segment** | segment id (33) |
| `msg.add_segment(...)` / `set_segment` | **Add/Copy Segment** (19) |
- **Must preserve `occurrence=`/kwargs.** Many native writes carry `occurrence=i` (inside segment loops). Recognition **and** the edit rewrite must round-trip these kwargs byte-stably (they become read-only or bound fields on the row, never dropped).

### Phase B — inline value transforms → editable transform rows  (~155 write-sites)
When a `msg.set` value (or a computed local) is a recognizable transform of a field, render the transform, editable:
`A if cond else B` → **Conditional/Environment set** (45); `code_set(...)`/`db_lookup`/`fhir_lookup`/`dict.get` → **Code Lookup** (39); `+`/`join` → **Append/Concat** (21); `.replace`/`re.sub` → **Replace** (21); `.split` → **Split** (14); slice `[a:b]` → **Substring** (7); `.strip` → **Trim** (5); `.upper/.lower/.title` → **Convert Case** (4). Most map to verbs the vocabulary already names; the work is recognizing the **inline** native form and letting the operands be edited.

### Phase C — control flow → structured/editable rows  (~850 statements)
`for i in range(1, msg.count_segments("SEG")+1)` → **For each SEG segment** (segment id editable) (111); `for x in msg.groups()/segments()` → native iteration (24, already recognized — keep); `if current_environment() in (...)` → **Environment gate** (44); `if <field cond>` → **When field …** condition (206); `if <regex>.search(...)` → **Filter/guard** (36); `return None` → **Filter (drop)** row (150). Control rows may stay structure-only (read-only header) where the body is what's edited, but the *header operands* (segment id, environment list, field path) should be editable where unambiguous.

### Phase D — helper descent  (265 delegating call-sites + the writes inside them)
Handlers delegate to `_`-prefixed helper functions (`_msh(msg)`, `_pid(msg)`); the bulk of the 1,283 native writes live **inside** those helpers, invisible when you open the calling Handler. To satisfy "see *everything* editable," the lens must **descend into same-module helper functions** — projecting each `_fn(msg, …)` call as an expandable group whose rows are the helper body's recognized actions, edited in place (rewrites target the helper's own line span). This is the largest structural lever and the highest-risk (cross-function byte-stable rewrite); it ships after A–C prove the recognition rules.

### Phase E — compute chains  (688 computed locals; partial by design)
`simplified = <transform of msg.field(...)>; msg.set("PV1-2", simplified)` — a read→transform→write across statements. Where a local is written once and consumed by one `msg.set`, collapse the chain into a single editable transform row; otherwise leave the local as a read-only `code` row. This is the tail; full coverage is **not** promised (see §4).

## 3. What "editable" means per row
Editing a recognized row rewrites **exactly** its native call/statement via the ADR 0076 §6 byte-space per-argument splice — every un-edited byte preserved, result re-parsed, coverage-partition invariant upheld. No new rewrite engine. New surface vs. ADR 0076: the splice must now target native `msg.set(...)`/`msg.field(...)` calls (incl. `occurrence=` kwargs and expression-valued arguments), not only wrapper calls.

## 4. Non-goals / the ceiling (honest scope)
- **Not a general Python structured editor.** Arbitrary conditions, multi-consumer locals, loops that aren't segment/message iteration, `while`/`try`/`break`/`continue`, and genuinely computational code **remain read-only `code` rows**. The goal is to *minimize* them, not eliminate them.
- **"Open as Text" stays the escape hatch** for anything the lens can't edit (and becomes a view toggle — a sibling UX item, not this ADR).
- Cross-file helpers, dynamic field paths, and reflection are out of scope.

Projected effect of Phases A–D on the scanned estate: editable/recognized coverage rises from **~13%** (sends only) to an estimated **~80–90%** of transform statements; the residual is the genuine behavioral tail above.

## 5. Evidence (scan methodology, reproducible)
An `ast`-based scan walks every function that references `msg` across the config repo and classifies each statement (native write/read, control idiom, helper call, return/filter) and each `msg.set` value expression (literal / field-copy / conditional / lookup / concat / replace / split / substring / trim / case). Counts above are its output. The scan is a **repeatable coverage check** — re-running it after each phase measures the coverage lift and surfaces the shrinking residual (the "what's still opaque" list). It reads only code (no PHI) and runs on any estate.

## 6. Consequences
- **Positive:** the lens becomes useful on real, un-rewritten estates; the owner goal becomes reachable for the large majority of transform logic; the `actions` wrappers become an *optional* authoring nicety rather than a precondition; a data-driven coverage metric now exists per estate.
- **Cost/risk:** more recognition rules = more parser surface and more byte-stable-edit cases to adversarially verify (each native form is a new corruption-risk class — the ADR 0076 review history shows this is where bugs hide). Helper descent (Phase D) is a genuine cross-function rewrite and must clear the same 3-breaker byte-stability bar the structural edits did. `occurrence=`/kwargs preservation is a hard invariant.
- **Relationship to ADR 0076:** this **supersedes ADR 0076's assumption** that Handlers must be authored in the vocabulary for the lens to help; it does **not** retire the vocabulary or the lens machinery — it reuses both and broadens what the parser recognizes.

## 7. Build plan / prep
Phases A–E map to BACKLOG **#226–#230**. Recommended order: **A → C(filters+segment-loop+env-gate) → B → D → E**, each landing its own recognition rules + adversarial byte-stability tests + a coverage-scan delta in the PR. Phase A alone (native `msg.set`/copy/segment/read) converts ~1,035 statements and is the single highest-value first step.
