# ADR 0108 — Steps-view accumulator Send fan-out (copy-on-Send authoring)

**Status:** Accepted (2026-07-14) — owner-directed ("do it") after two model iterations; built + adversarially verified this session (engine `lens.py` + `ide/`).
**Deciders:** owner + IDE/DX
**Related:** [ADR 0076](0076-typed-action-vocabulary-action-list-lens.md) (the action-list lens + row-scoped-splice contract §5/§6 this extends), [ADR 0089](0089-recognition-first-lens-native-idioms.md) (recognition-first / honest degradation §4), [ADR 0104](0104-copy-on-send-outbound-message-model-recognition-first-handler-message-type-and-hl7-field-picker.md) (copy-on-Send — the snapshot-at-construction model this lets an analyst *author*), [ADR 0106](0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md) (the Add palette this repoints the **Send** item within; §6 byte-scoping exceptions), [ADR 0103](0103-steps-view-row-context-menu.md) (the insert-after-on-send suppression rule this refines), BACKLOG **#222** (Steps view), **#26** (the declined visual-authoring line + its structured-Steps-view carve-out — native `.py` stays the only artifact).
**Code references** are this branch (`send-fanout`); locate by symbol, not absolute line.

---

## 1. Context

A **Handler** delivers to one or more outbound connections by returning `Send`s. The estate writes three shapes: `return Send("OB", msg)` (single), `return [Send(A, msg), Send(B, msg)]` (inline-list fan-out), and the accumulator `sends = []; sends.append(Send(...)); return sends` (already documented at [`config/graph.py`](../../messagefoundry/config/graph.py) and used in `test_graph_static.py`). The Steps view recognized only the two **returned** forms; an append-built send showed as a read-only `code` row.

The owner asked for two things: (1) a Handler must be able to **send to multiple outbounds**, authored in the Steps view; and (2) a send must not be forced to the end of the function — you must be able to **"send earlier"** and interleave transforms between sends (the [ADR 0104](0104-copy-on-send-outbound-message-model-recognition-first-handler-message-type-and-hl7-field-picker.md) copy-on-Send divergence). Crucially, the owner **rejected authoring a `Send` inside a `return`** (`return Send(...)` / `return [a, b]`): a send should read as an **action**, not as the function's return value.

The inline-list form (`return [Send(A), Send(B)]`) is insufficient: every Send in one return snapshots the **same** final message state, so it cannot express "send earlier". The named-sends-in-a-return form (`a = Send(A); ...; b = Send(B); return [a, b]`) still puts the collection in a `return`, which the owner declined.

## 2. Decision

Recognize and author the **accumulator idiom** as the fan-out authoring form:

```python
@handler("route_adt")
def route_adt(msg):
    sends = []
    sends.append(Send("OB_A", msg))     # a Send ACTION — snapshots msg here (ADR 0104)
    msg.set("MSH-5", "SYS_B")           # ...interleave a transform...
    sends.append(Send("OB_B", msg))
    return sends
```

- A `sends.append(Send(dest, msg))` statement is an editable **send action row**, positioned AT the append (not in a return); a Handler may hold several, interleaved with transforms.
- The `sends = []` init and bare `return sends` footer are **managed scaffold** — read-only `code` rows the lens lays down and renders muted; the analyst never authors a `Send` inside a `return`.
- Deleting every append leaves `sends = []; return sends` — an empty accumulator = **FILTERED** at runtime, honest, with **no coupled name-scrub**.
- The three legacy returned forms (`return Send(...)`, `return [Send, ...]`, `return []`) stay **byte-identically** recognized for the estate; the palette simply stops *authoring* the return form.

**Invariant (unchanged, #26).** Native `.py` is the only artifact and execution path. Every op emits Python the lens re-recognizes (byte-stable codegen), never a declarative logic engine. **No engine runtime change** — `dryrun.py::_partition` already delivers a NAME-built list identically to a returned list (it keys on `isinstance(result, list)` and never inspects the collector name); this is a pure recognizer + rewrite + view change.

## 3. Recognizer

- **Append send** — `NAME.append(Send("OB", msg))` with a **bare-name** receiver, a single positional `Send(...)` arg, no keywords/splat → a `send` row carrying `outbounds` (a literal dest → `["OB"]`; a dynamic dest → `[]`, parity with a returned Send) and an additive `appended: true` discriminator. Placed in `_classify_simple` after the `ast.Return` block, so the returned forms match first and are untouched.
- **Delivering-accumulator gate (honesty).** An append is only a send row when its collector is a **clean delivering accumulator**: exactly one top-level `NAME = []` init, a top-level `return NAME`, `NAME` assigned nowhere else in the handler's own scope, not a parameter. An append into a discarded / aliased / rebound / closure-local list **honestly degrades to a read-only `code` row** (ADR 0089 §4) — the lens never shows a "Send" that does not deliver.
- **Scaffold tags.** For a delivering accumulator that carries a visible append, its `NAME = []` and `return NAME` code rows are tagged `scaffold: "collector_init" | "return_collector"` (additive; kind stays `code`, so already read-only). Runs post-partition, matching exact single-statement spans, so the coverage-partition invariant (ADR 0076 §6) is untouched.

## 4. Ops (rewrite)

- **`insert_send`** (the Add→Send palette item) and **`add_destination`** (a per-row **＋ dest** button) both route through one `_apply_add_send`, dispatched by handler state: a clean accumulator → insert one `sends.append(...)`; a **single top-level** send/filter return → convert it up to the accumulator preserving each existing `Send` verbatim; no return → lay `sends = []` (body top) + append + `return sends` (body end); anything else (a nested/early-exit return, >1 return, a non-send return, a rebound `sends`) → **refuse** (edit as text).
- **Placement.** Appends land at the accumulator's own **top-level** suite indent, before the footer; the anchor position is honored only for a top-level anchor (a nested anchor lands the append top-level, one delivery per message — never inside a loop/if). Idempotent `from messagefoundry import Send` injection at the **leading** import block (index-stable across body splices).
- **`set_params`** edits an append's destination (the inner `Send` arg0); **`delete_row`** / **`move_row`** work on append rows as ordinary send rows. Scaffold rows are `code` → already refused by the edit gate.
- All ops go through the audited splice + `_assert_reparses` + per-line ≤100-col + ruff-canonical rendering (gate 2/3).

## 5. IDE (view)

`stepsModel.ts` adds additive `appended?` / `scaffold?` `LensRow` flags and an **`isReturnRow(row)`** helper — a terminal return (a returned send OR the `return sends` footer), NOT a mid-body append. The six position sites that conflated "is a Send" with "is the terminal return" (`contextMenuEnablement`, `buildToolbarInsertRequest`, `buildAddMenuRequest`, `buildPasteRequest`, `resolveDrop`, `buildDropSlots`) key on `isReturnRow` instead — so an append allows insert-after / gets a normal two-zone drop, while a return / scaffold footer suppresses insert-after (no dead code). The **Send** palette item repoints from `template:"send"` to `op:"insert_send"`; a per-row **＋ dest** button — and a right-click **Add destination** context-menu item (added in the #1045 follow-up) — posts `add_destination`. The precomputed `isReturn` + flags are stamped on the `<li>` (`data-is-return`/`data-appended`/`data-scaffold`) so the CSP-isolated `stepsWebview.js` mirror agrees with the model (model==mirror fixture tests).

## 6. Acceptance criteria (EARS)

- The lens SHALL recognize `NAME.append(Send(dest, msg))` (bare-name receiver, single Send arg) as a `send` row with `appended: true`, `outbounds = [literal]` or `[]` for a dynamic dest — but ONLY where `NAME` is a clean delivering accumulator; otherwise it SHALL degrade to a read-only `code` row.
- WHEN a delivering accumulator's `NAME = []` init or bare `return NAME` footer carries a visible append, the lens SHALL tag it `scaffold` and keep its kind `code` (read-only).
- The lens SHALL continue to recognize `return Send(...)`, `return [Send, ...]`, and `return []`/`()` byte-identically, and the emitted rows SHALL exactly partition the def body.
- WHEN `insert_send` / `add_destination` runs, the lens SHALL author `sends.append(Send(dest, msg))` at the accumulator's top-level suite (laying `sends = []` / `return sends` in a fresh handler, or converting a single top-level send/filter return up preserving each Send verbatim), injecting `Send` iff not in scope, and byte-preserving every line outside the edit.
- The lens SHALL refuse (zero change) an empty destination, a line over 100 columns, a scaffold-row edit, a nested/early-exit or multi-branch return, a non-empty tuple return, a non-Send list element, or an append onto a rebound/non-accumulator `sends`.
- WHEN every append is deleted, the lens SHALL leave `sends = []; return sends` intact (FILTERED at runtime), with no name-scrub.
- The engine runtime SHALL deliver a NAME-built accumulator identically to the equivalent returned list, independent of the collector name; per-append copy-on-Send divergence SHALL occur iff `[pipeline].snapshot_on_send` is enabled (flag-independent of accumulator-vs-list).
- The Steps webview SHALL allow insert-after on an append row and suppress it on a returned send / scaffold footer (via `isReturnRow`), render scaffold rows muted + non-editable/movable/deletable, and keep the model and the CSP-isolated mirror in agreement.
- The Add→Send palette SHALL emit `insert_send` (accumulator idiom), never the retired `template:"send"` return-form.

## 7. Adversarial pass (caught + fixed)

A multi-agent review (10 confirmed findings, 0 refuted) hardened the build before commit: the `Send` import was injected at a stale index when a top-level import trailed the edited handler (→ `_leading_import_end`); a destination containing `"` emitted a non-canonical escaped literal ruff reflows (→ `_str_lit` honors ruff's single-quote escape-avoidance); syntactic recognition mis-showed an append into a non-returned/rebound/closure list as a delivering send and mis-tagged its scaffold (→ the delivering-accumulator gate + demotion); the convert gate keyed on return **count** not top-level terminality (→ would move a nested guard's fan-out branch); a non-empty tuple return would flip 0→N deliveries on convert (→ refused); and a nested anchor could place an append inside a loop/if at the wrong indent (→ top-level placement). Each fix carries a regression test.

## 8. Declined / out of scope (v1)

- **Nested per-iteration authored fan-out** (an append the ops place *inside* a loop): recognized when hand-written, never authored by the ops (they place top-level, one delivery per message); reorder via move, or hand-edit.
- **Renaming the accumulator var** from the Steps view (`sends` is hard-coded — the estate convention, and the runtime ignores the name); edit as text.
- **Deleting an append that is the sole statement of an `if`/`for` block** — refused (an empty suite is invalid), honest degradation, edit as text.
- Recognizing the accumulator with a non-`sends` collector name in the **ops** (recognition accepts any clean delivering name; the ops author `sends`).

## 9. Consequences

The Steps view can author real multi-destination fan-out with sends as first-class mid-body actions, matching the owner's mental model, with **zero** engine-runtime change and the estate's returned forms untouched. The delivering-accumulator gate makes recognition honest (no phantom sends). The one cost is a `sends`-name convention for authored fan-out and a modestly larger recognizer (a handler-local accumulator analysis alongside the statement-local classifier).
