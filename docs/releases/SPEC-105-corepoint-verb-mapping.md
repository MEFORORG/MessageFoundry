# BACKLOG #105 — Corepoint verb coverage: implementable specification

**Target file:** `C:/Users/<you>/Code/MessageFoundry/.claude/worktrees/<worktree>/messagefoundry/corepoint_import.py`
**Fixture:** `C:/Users/<you>/Code/MessageFoundry/.claude/worktrees/<worktree>/tests/fixtures/corepoint/acme_adt_package.xml`
**Tests:** `C:/Users/<you>/Code/MessageFoundry/.claude/worktrees/<worktree>/tests/test_corepoint_import.py`
**CLI consumer:** `C:/Users/<you>/Code/MessageFoundry/.claude/worktrees/<worktree>/messagefoundry/__main__.py` lines ~2845–2875

Every count below was re-measured by me against the real export in this session (read-only, counts/shapes only). Nothing was written to the repository.

---

## 0. Ground truth I re-verified before writing this

| Fact | Measured |
|---|---|
| `<ActionList>` elements | 187 |
| Elements inside action-lists | 19,682 |
| `@Data`-bearing elements | 12,953 |
| Statement positions (non-`<List>`/`<Actions>`) | 14,049 |
| **`@Data`-bearing NON-`<Block>` statements** | **10,282** ← the handoff's denominator, reconciled exactly |
| … split | **7,518 live / 2,764 disabled** |
| `<Block>` with `@Data` | 2,671 (2,149 live / 522 disabled) |
| No-`@Data` container elements | `<If>` 1,050 · `<Try>` 46 (the **phantom wrappers**) |
| Shipped ledger | **mapped 2,386 · unmapped 5,931 · disabled 475 = 8,792** |
| Vocabulary `Action` objects produced | **0** |
| Live `Control` kinds | if 1521 · block 2829 · exit 468 · for 179 · send 164 · call 113 · try 64 · while 20 · match 27 · break 26 · case 18; branches: else 160 · elif 62 · except 32 |
| `if` Controls with **empty** detail (live phantom `<If>`) | **757** |
| `try` Controls with **no** `except` branch (phantom `<Try>`) | **32** |
| `send` Controls with **no** args | **4** |
| Orphan `match` Controls | **27** |
| Generated module | 17,876 lines · 1,583 `if False:` · 160 bare `else:` |
| Literal spans | 4,461 — **3,029 quote-wrapped inside the span**, 1,432 bare; **all 221 whitespace-bearing spans are bare** |

**The mapped bucket sums exactly:** 1521+62+160+179+20+64+32+18+27+26+164+113 = **2,386**. Every one is control scaffolding; not one is a transform.

**The role layer already exists in the file and is dead code.** `parse_roles`, `RoleToken`, `Operand`, `_operands_from_roles`, `_role_verb`, `_role_prose`, `_path_leaf`, `_corepoint_path`, `_corepoint_segment`, `_COREPOINT_LEAF` (lines 529–884) are referenced **nowhere** — not by `_parse_statement`, not by any test. I verified this by grep. `_parse_statement` still calls `strip_markup` + `_split_verb`. So §1 is *wire and correct the existing layer*, not *write one*.

I exercised the dead layer on synthetic markup and it works, including nesting (a `detail` label nested inside a `path` span pops out as its own token). Its four real defects are named in §1.3.

---

## 1. Role parser

### 1.1 Keep both paths. Dispatch on **verb recovery**, never on span presence.

This is the single most important structural decision, and it overrules the operand-model proposal's rule.

**Measured:** 6,869 of 12,953 `@Data` statements (53%) have **no usable `keyword` span**. Of those, 3,583 *do* carry real role spans (2,149 `block`, 690 `comment`, 664 `action-list-call-pass`, 14 `action-list-call-custom`, and the 678 `<Call>` property rows which are a single whole-statement `action-list-call-pass` span with **zero** keyword spans). A "spans present ⇒ role parser" rule routes all of those to a parser that recovers no verb — and every existing probe `continue`s past exactly that population. **That is an accept-and-drop.**

```python
def _parse_data(data: str) -> _Statement:
    """Parse one @Data into the statement model. NEVER returns None — every input yields a
    countable statement, because a dropped statement is the accept-and-drop this importer refuses."""
```

Dispatch inside `_parse_data`:

1. `tokens = parse_roles(data)`.
2. `role_verb = _role_verb(tokens)`.
3. `flat = strip_markup(data)`; `flat_verb, flat_ops = _split_verb(flat)`.
4. **`verb = role_verb or flat_verb`.** The flat verb is the fallback and is load-bearing: it is the *only* way the 678 property rows and the 3,286 markup-free disabled rows recover a verb name.
5. Operands come from `tokens` when `tokens` is non-empty, else from `flat_ops`.
6. `role_source` records which produced the verb, so a marker can say *"this statement carried no role markup"* vs *"this statement's operands did not resolve"*.

`markup ⟺ live` is exact in this corpus (9,667 live all have markup, 3,286 disabled all have none, both off-diagonals zero), so the fallback never silently degrades a live statement — but it must exist anyway, because the property rows are live *and* keyword-span-free.

### 1.2 Data model

Keep `RoleToken` and `Operand` as they are; **extend** `Operand` and add two new types.

```python
@dataclass(frozen=True)
class Operand:
    kind: str            # "path" | "literal" | "variable" | "numeral" | "handle"
    text: str            # for "literal": the UNWRAPPED value (see 1.3-a)
    handle: str = ""     # the handle text a path is addressed against
    primary: bool = False        # handle span class was `input-handle`
    handle_class: str = ""       # NEW: "input-handle" | "other-handle" | ""
    quoted: bool = False         # NEW: the literal span carried its own quotes

@dataclass(frozen=True)
class _Statement:
    """One @Data, parsed. The unit `_map_role_statement` matches against."""
    verb: str
    operands: tuple[Operand, ...]
    details: tuple[str, ...]        # `detail` spans — QUALIFIERS, never dropped (1.3-c)
    connectives: tuple[str, ...]    # unspanned runs — OPERATORS/MODE FLAGS, never dropped (1.3-d)
    prose: str                      # `description` + `comment` spans, joined
    verb_from: str                  # "role" | "flat" | ""
    flat: str                       # strip_markup(@Data) — kept for the disabled/pseudo-source path only

@dataclass(frozen=True)
class _ListContext:
    """Per-<ActionList> facts every mapping guard needs. Built ONCE per action-list, before
    any statement is mapped — several guards are not evaluable per-statement."""
    input_handles: frozenset[str]      # texts carried by an `input-handle` span anywhere in the list
    clone_handles: frozenset[str]      # WHOLE-TREE clones of an input handle (see §2.2)
    itemnew_segments: frozenset[str]   # (handle, SEG) pairs an ItemNew creates — flattened "handle\x00SEG"
    is_call_target: bool               # this list's @Name is an operand of some ActionListCall
```

### 1.3 Four measured defects in the existing role layer — all must be fixed

**(a) Literal spans carry their own quotes.** `parse_roles` returns the span body verbatim. I measured **3,029 of 4,461** literal spans are `"…"`-wrapped *inside the span*; passing that straight to `_lit`/`json.dumps` emits `set_field(msg, "MSH-6", "\"ACME\"")` — a value carrying two literal quote characters, on 68% of every literal mapping. Fix: unwrap **exactly once**, conditionally.

```python
def _literal_value(text: str) -> str:
    """The value of a `literal` span. The exporter wraps SOME literals in their own quotes
    (3,029 of 4,461 measured) and leaves others bare, so the unwrap is conditional and happens
    EXACTLY once. An odd/unbalanced quote is NOT guessed — the caller degrades to a marker."""
```
Return a sentinel (or raise a private `_AmbiguousLiteral`) on unbalanced quoting; that statement becomes a TODO.

**(b) `parse_roles.flush()` strips whitespace.** `flush` calls `strip_markup(...)`, which `.strip()`s. I measured **221 literal spans with meaningful outer whitespace, and all 221 are bare (unquoted)** — zero wrapped ones are affected. A padding literal is a real HL7 idiom and the loss is invisible. Fix: `flush` must strip only *non-literal* runs; a `literal` span's text is taken verbatim (entity-unescaped, tag-stripped, **not** `.strip()`ed).

**(c) `detail` is in `_PROSE_ROLES` and is therefore silently dropped.** `detail` (2,875 spans) is **not prose** — it carries verb qualifiers, operators and format masks: `MsgTreeCopy [A A]` ×420, `MsgLoad`/`MsgCreate` `A9A9` ×184/95, and `ItemExpr` bare arithmetic glyphs. Fix: remove `"detail"` from `_PROSE_ROLES`; route it to `_Statement.details`. **Any `detail` token a verb's closed vocabulary does not recognise — including an EMPTY one (51 on `ItemExpr`, 52 on `ItemFormat`) — forces the whole statement to TODO.** Never emit a transform with its qualifier dropped.

**(d) Unspanned `text` runs are dropped.** They are not uniformly connectives. Measured outside verbless lines: bare `=` ×934 (If 449, ItemNew 147, ItemReplace 98, ItemExpr 85, ItemCodeLookup 62, ItemFormat 52, ElseIf 41), `<>` ×88, `contains` ×31, `<` ×8, plus `and`/`or`/`not`; and `ItemReplace` mode flags `interpret escapes` ×95, `replace all` ×19, `single line` ×10. Fix: route them to `_Statement.connectives` and gate per verb against a **closed** set. The only verbs whose unspanned run is provably inert are `ItemCopy` (`to` ×1994, nothing else), `ItemAppend` (`to` ×191), `MsgTreeCopy` (`to` ×423), `MsgSend` (`to`/`connection`). Anything outside a verb's enumerated set ⇒ TODO for the whole statement.

**(e) `_role_verb` returns `""` for the 678 property rows** — handled by the §1.1 fallback, not by changing `_role_verb`.

### 1.4 Prose separation and re-emission

`_role_prose` already collects `description` + `comment`. Wire it: `_parse_statement` currently emits `Control("block", "Comment", note)` for `@Comment`; extend that to `note or sp.prose`. Positions are exact and were re-verified: **`description` is the LAST span 1,251/1,251**; **`comment` is the FIRST span 690/690**; **`block` spans never co-occur with a `keyword` span, 2,149/2,149**.

Emit prose through `_comment_text` only. **Never into `log_note()` or any runtime log** — 40 `description` and 38 `comment` spans contain a ≥6-digit run and 44/59 contain a 4–5-digit run. Generated modules from a real export are customer-derived data and must be classified as such (this is a doc/ADR statement, not a code change).

### 1.5 Path resolution — tighten and refuse

```python
_HL7_PATH = re.compile(r"^[A-Z][A-Z0-9]{2}-\d+(?:\.\d+){0,2}$")     # was [A-Za-z0-9]{3}
_COREPOINT_LEAF = re.compile(r"^([A-Z][A-Z0-9]{2})((?:-\d+){1,3})$") # was [A-Za-z0-9]{3}
_SEPARATOR_PATHS = frozenset({"MSH-1", "MSH-2"})
```
`_corepoint_path` must return `None` for `_SEPARATOR_PATHS`. This is **reachable**, not hygiene: `Message.parse_path` accepts `MSH-1`, `msg.set("MSH-1", …)` does **not** raise — it rewrites the separator glyph in the MSH-1 position and leaves the rest of the line on the old separator, producing a structurally broken message, silently. The export carries 2 `MSH-1` and 2 `MSH-2` coordinate references.

The `[A-Za-z0-9]{3}` loosening is *not* independently reachable (all 15 non-uppercase segment ids are bare-segment leaves with no coordinate, which never translate), so tighten it as defence, not as a fix.

Add:
```python
def _is_root_path(text: str) -> bool:
    """A ROOT path span — the WHOLE tree, not a node. Empty after the leading '/' and the label."""
    return _path_leaf(text) == ""
```

### 1.6 Tests that must change, and why

| Test | Change | Reason |
|---|---|---|
| `test_unmapped_verb_emits_a_todo_marker_and_is_counted` (L390) | drop `assert 'msg.set("OBX-5", msg.field("OBX-5") or "")' in src`; update `unmapped_classes`/`total_unmapped` | the passthrough stub is suppressed on the XML path (§4.1); `MsgParse`/`EnvLogText` counts change |
| `test_a_path_that_does_not_resolve_is_never_guessed` (L404) | drop `assert 'msg.set("PID-3.1"…'` / `'msg.set("NK1-2.1"…'`; assert the marker names the blocker instead | same — the recovered target now rides into the marker text, not into a live statement |
| `test_import_summary_counts_mapped_and_unmapped` (L147) | JSON path — unchanged (9/1). Add an XML-ledger sibling asserting the new buckets | new `inert`/`properties` buckets |
| `test_nested_control_flow_round_trips` (L456) | `kinds` list changes if the fixture gains lists; the `if False:`/`else:` assertions change to `elif False:` for `Else` (§4.4) | phantom-wrapper removal + Else re-render |
| `test_conditions_are_dead_placeholders_never_guessed` (L486) | **keep verbatim** — it is the regression guard for the whole change | must still pass: no mapped call adds a live condition |
| `test_try_without_catch_reraises_rather_than_swallowing` (L505) | keep; the *fixture's* `<Try>` has a `@Data`-free wrapper, so verify the phantom removal doesn't delete the real one | 32 phantom trys removed, 32 real ones kept |
| `test_maps_every_vocabulary_class` (L52) | unaffected — `ItemFormat` is not in the JSON fixture, so removing it from the `convert_case` arm is safe | §4.6 |
| `test_markup_stripped_statements_classify_in_the_fixture` (L359) | **keep verbatim** — it drives the *existing* fixture, whose invented `kw`/`pth` classes and `&amp;quot;`-escaped class attributes are invisible to `parse_roles`, so it exercises the flat fallback | proves §1.1's dispatch does not regress the flat path |
| `test_strip_markup_recovers_the_verb`, `test_tokenize_keeps_literals…` | keep verbatim | `strip_markup`/`tokenize_statement` stay public and stay the fallback |
| **new** | `test_role_layer_is_reached_and_flat_layer_still_works` | asserts both dispatch arms on the same fixture |

---

## 2. Operand resolution

### 2.1 `ADDRESSABLE(op)` — when a `(handle, path)` pair is writable by `Message.set`

All of:
- `op.kind == "path"`;
- `_corepoint_path(op.text)` returns non-`None` (depth-1 paren-aware `/` split; leaf = `SEG-F[-C[-S]]` + optional ` (Label)`; dash→dot);
- the result is not in `_SEPARATOR_PATHS`;
- `SAME_MESSAGE(op, ctx)` (2.2);
- the statement has **no `<Foreach>`/`<Loop>` ancestor** (2.4);
- the destination segment is in `_SINGLE_OCCURRENCE` (2.5);
- no `ItemNew` in this list creates that `(handle, segment)` (2.6).

Notation translation is the one thing that survived every attack: **3,484 depth-1 coordinate leaves, 3,484/3,484 uppercase-strict, 3,484/3,484 labelled, 3,484/3,484 accepted by `parse_path`, 0 rejects, 0 dot-notation leaves anywhere**, and `_message_path` resolves **0/5,013** today. The paren-aware split is mandatory — a naive `str.split("/")` mis-splits labels containing `/`.

### 2.2 `SAME_MESSAGE(op, ctx)` — the load-bearing predicate

```
INPUT = { h : h carried an `input-handle` span anywhere in this <ActionList> }
CLONE = { h : some MsgTreeCopy in this list copies i→h where i ∈ INPUT
               AND BOTH path operands are ROOT (_is_root_path)
               AND that MsgTreeCopy has NO control-construct ancestor }
SAME_MESSAGE(h) ⟺ h ∈ INPUT ∪ CLONE
                   AND |ctx.input_handles| == 1
                   AND not ctx.is_call_target
```

**The `CLONE` restriction to whole-tree copies is not optional.** Measured: of 403 MsgTreeCopy statements whose first operand is an input handle, only **63 are whole-tree clones**; **340 are partial sub-node copies** (194 bare-SEG→bare-SEG, 85 named node, 30 coordinate, 30 multi-segment, 1 mixed). Each of those 340 admits a handle that is *not* the transformed message. Failing case: `MsgTreeCopy %in/PID → %out/PID` then `ItemCopy "L" → %out/PID-3-1` emits `set_field(msg, "PID-3.1", "L")` **against the inbound message**, where Corepoint wrote a separate tree that had only ever received a PID copy.

The identity half is solid and I re-verified it: 187 lists, **0 lists ever use one handle name in both span classes**, 51 distinct handle names (15 input-only, 34 other-only, 2 in both across *different* lists), inputs-per-list `{0:3, 1:111, 2:56, 3:15, 4:2}`, `ItemCopy`'s first handle is input-class only 41.7% of the time — so the class is an *identity*, not an operand position. **State in the ADR that this is inference from the corpus, not from Corepoint documentation.**

`is_call_target` needs a **package-level pass before any statement is mapped**: 92 of 187 lists are named as `ActionListCall` targets (143 call statements; 110/143 resolve to an exact `<ActionList Name>`, 2 match none, 31 name no literal). A called list's input handle is bound by the *caller*, not by the pipeline, yet the importer routes every list as its own `@handler` over the pipeline's `msg`. Until that pass exists, **no mapping in this family may ship**.

```python
def _call_targets(root: Element) -> frozenset[str]:
    """@Name of every <ActionList> that some ActionListCall names, matched EXACTLY (not by
    substring). A list whose input handle is supplied by a caller is never `msg`."""
```

### 2.3 `$VAR` — never maps, v1

514 distinct names; **547 of 2,252 spans are not valid Python identifiers** once `$` is stripped; 514 names sanitise to **499** identifiers = **15 silent collisions**. 664 `action-list-call-pass` spans pass variables by name into called lists the importer inlines at the *same* indentation, so the namespaces merge. Do not auto-generate locals. The marker must count the downstream readers (that is the useful half) and **should not name the variable** — analyst-authored variable names can encode partner/site identifiers.

### 2.4 Repetition / occurrence — the trap that has no subscript

There are **zero** `[n]` subscripts in the export (8 `[` hits, all inside human labels). **That does not mean occurrence is unambiguous.** Corepoint encodes occurrence by *loop context*: **768 of 1,861 coordinate write targets have a `<Foreach>`/`<Loop>` ancestor** (575 at depth 1, 184 at 2, 9 at 3), and 683 of those address a repeatable segment. `msg.set("OBX-5", …)` writes occurrence 1 unconditionally — runtime-verified on a two-OBX message, only OBX#1 changed.

`lens.py` *does* support `occurrence={"expr": "i"}`, but supplying it needs a loop-variable model, which is deferred with `$VAR`. **Therefore: any `<Foreach>`/`<Loop>` ancestor ⇒ TODO.** This is subsumed by guard G9 (top-level only) but must be implemented as its own named predicate so that relaxing G9 later cannot silently re-open it.

### 2.5 Segment occurrence class — fail closed

```python
# Segments Message.set may write at occurrence 1 without ambiguity. An ALLOW-list, not a
# deny-list: an unknown/Z segment defaults to "assume repeatable" ⇒ marker, which is the
# safe direction. Widening this set is an ordinary, reviewable addition.
_SINGLE_OCCURRENCE = frozenset({"MSH", "EVN", "PID", "PD1", "PV1", "PV2", "MRG"})
```
166 of the field-transform family's 312 candidates target a repeatable segment; this guard is what removes them.

### 2.6 Non-HL7 tree nodes — three distinct sub-classes, three distinct markers

| Sub-class | Count | Marker must say |
|---|---|---|
| bare segment leaf (`/SEG`) | 500 | *"`<SEG>` is a whole SEGMENT node, not a field. Re-express as per-field copies, or `msg.delete_segments`/`msg.add_segment`."* |
| named tree node (no coordinate) | 1,029 (63 of them ROOT) | *"addresses a NAMED NODE of a Corepoint message tree; it carries no HL7 coordinate."* / for ROOT: *"the ROOT of the tree (the whole message), not a field."* |
| multi-segment path (depth > 1) | 369 | *"navigates `<n>` named tree nodes before its leaf; no HL7 coordinate exists on that route."* Never read a `- <n>` intermediate node as an HL7 occurrence. |

### 2.7 Composite-operand contract (parser, not a mapping)

Verified in **both** directions: 5,013/5,013 path spans are immediately preceded by a handle span; 6,056/6,056 handle spans start with `%`; 5,013/5,013 path spans start with `/`. **But the converse does not hold** — **1,043 of 6,056 handle spans are NOT followed by a path** (591 unspanned, 221 literal, 196 end-of-statement, 28 detail, 7 description). An operand builder that only materialises a handle when a path follows would **silently drop `MsgSend`'s message operand**. `_operands_from_roles` already handles this correctly (bare handle → its own `Operand`); do not "simplify" it.

---

## 3. Verb table — the implementation checklist

Ordered by occurrence descending. **Occurrences are LIVE counts** unless marked. "Emitted" is what ships; every guard failure yields a counted marker, never a drop.

| # | Verb | Occ (live) | Verdict | Emitted call | Guard | Marker when the guard fails |
|---|---|---|---|---|---|---|
| 1 | **ItemCopy** `"LIT" → @H %PATH` | 2,829 total; **33** survive | **MAP** | `set_field(msg, "<dst>", "<lit>")` | G1–G10 (§3.1) | name the *failing* guard; 9 distinct texts (§3.2) |
| 2 | **ItemCopy** `@H %P → @H %P` | 75 candidates | **TODO** | — | never | `copy_field` writes `""` on an absent src (docstring: *"An absent/empty src copies an empty value (clearing dst)"*). The export does not say whether Corepoint leaves the destination untouched instead, and **52 of 75 destinations are component/subcomponent paths**. Silent deletion of a populated field. Emit: *"NOT auto-mapped: confirm against Corepoint, or guard with `if msg.field(<src>):`"* |
| 3 | **ItemCopy** `→ $VAR` | 546 | **TODO** | — | never | *"assigns to a Corepoint variable, read by N later statement(s); introduce a Python local and re-point them."* Count the readers; do not name the variable |
| 4 | **ItemCopy** — GUID source | 1 | **REFUSE** | — | categorical | *"source is a GUID generator; this is non-deterministic and MUST NOT be mapped (routers and transforms must stay pure so a retry re-derives identical output)."* Not a guard — a refusal |
| 5 | **MsgTreeCopy** | 423 (356 node + 67 root) | **TODO** | — | 0/423 qualify (re-run: *"423 not mappable"*) | **and suppress `_first_path`** — this is the family's only KeyError site: 35 live statements get a `msg.set` stub whose path is the copy **SOURCE** on the **wrong message** |
| 6 | **ItemClear** `@H %PATH` | 530 total; **16** survive (upper bound) | **MAP** | `set_field(msg, "<dst>", "")` | G2–G10 | add: *"`Message.set` REFUSES an absent segment (KeyError) where Corepoint's clear is a no-op."* For a bare 3-char leaf (17 cases): *"clears an entire segment — consider `msg.delete_segments`"* |
| 7 | **Returns** | 339 | **TODO → `properties`** | — | never | **not an executable statement.** 429/429 have parent `<Actions>`, grandparent `<Call>`, at indices 0/1/2, exactly 143 each. Fold into the `ActionListCall` marker. **216 of 339 sit in an unconditional position** — mapping this to `return` would have silently killed 216 handlers |
| 8 | **MsgLoad** | 262 | **TODO** | — | unsatisfiable | no primitive binds a materialised message to a named handle inside a Handler |
| 9 | **ItemAppend** | 224 total; **0** survive | **TODO** | — | 0/8 candidates pass | 180/224 append to a `$VAR`. **Also re-point the inverted arm** (§4.7) |
| 10 | **MsgLog** | 185 | **TODO** | — | provable yield **0** | the "single input handle ⇒ that handle is `msg`" guard admits 3 rows, **2 of which are in an ActionListCall target** (51% of single-input lists are). Four markers (§3.3) |
| 11 | **MsgCreate** | 169 | **TODO** | — | unsatisfiable | *"creates a SECOND, empty message; a Handler carries exactly one `msg`."* `msg.add_segment` adds a segment, not a message |
| 12 | **MsgSend** `@OTH → "LIT"` | 101 (67 in a **live** position) | **TODO** | — | handle class is `other-handle` | **today ships 67 executing wrong-message Sends.** *"Do NOT substitute `msg`."* **And do NOT feed the destination to `_collect_sends`** (§4.2) |
| 13 | **MsgSend** `@IN → "LIT"` | 63 | **PARTIAL — 6** | `sends.append(Send("<dest>", msg))` | (1) class `input-handle`; (2) list declares exactly ONE input handle; (3) **list is NOT an `ActionListCall` target**; (4) a `literal` supplies the destination; (5) no later live statement writes that handle | (3) is new and non-negotiable: it removes 1 of the 7 the naive guard admits |
| 14 | **ActionListCall** | 113 | **TODO** | — | argument passing | **not** target ambiguity — 110/143 resolve exactly. The blocker is that the call passes a *message-tree argument* and MessageFoundry has one `msg`. Drop the false `(called list inlined)`; name the resolved callee; fold the 6 property rows in |
| 15 | **RaisesAlert / LogsText / RequestsGearStop** | 113 each = 339 | **TODO → `properties`** | — | structural test 143/143 | `<Line>` with parent `<Actions>`, grandparent `<Call>`, exactly 1 descendant (an empty `<List>`), one operand shape, one distinct operand string. **Collapse gate: role class is `action-list-call-pass` AND the nested `<List>` is empty.** 14 live `Returns` are `action-list-call-custom` and 4 have a non-empty `<List>` — those 18 keep markers |
| 16 | **ActionListExit** | 118 | **PARTIAL** | `return sends  # Corepoint ActionListExit` | (a) `_has_inline_send(h.steps)` is true (106/118); (b) not inside an inlined orphan scope (0 today); (c) `Returns` must not share the `exit` kind | for the 12 non-accumulator handlers, the current marker **inverts the damage**: *"the source stops the action-list HERE, but the generated code below this line STILL RUNS."* |
| 17 | **EnvLogText** | 152 | **MAP — 63** | `log_note("<lit>")` | exactly one `literal` operand and NO other operand span. **Flat guard ≡ role guard exactly (63 vs 63, zero either-only).** Two HARD preconditions (§3.4) | shape-specific: `$VAR` / other-handle path / non-HL7 leaf |
| 18 | **ItemReplace** | 98 | **TODO** | — | 0/98 | destination-first assignment form (`_split_verb` returns `""` for all 98). `replace_literal` replaces **every** occurrence; Corepoint replaces the **first** unless `-for all` (present on 2/98). `interpret escapes in replace` (67/98) has no equivalent |
| 19 | **ItemExpr** | 85 | **TODO** | — | 0/85 | 74/85 write to a `$VAR`; `arith_field` is **in-place**; `mod` is outside its closed `{+,-,*,/}`. **Note: `-A`/`-A A A A` details are option tokens, NOT the subtraction operator** — only 82 bare glyphs are arithmetic, and 51 details are empty |
| 20 | **MsgError** | 36 | **TODO** | — | never | Corepoint **records and continues** — proved by six non-exit successors (If ×3, MsgLog, ItemCopy, unverbed Line) and by all 69 "last in list" rows sitting in a branch/Try body, never at top level. `raise` aborts; `log_note` downgrades to DEBUG. *"Choose deliberately."* |
| 21 | **MsgEncode** | 21 | **TODO** | — | 0/21 | infix form; `_split_verb` returns `""` for all 21 so they report as **`<unparsed>`** today. §1.1's role verb fixes the label |
| 22 | **ItemTransformDate** | 19 | **TODO** | — | never | multiplexes `-convert` (tz, 8) and `-compute` (offset, 6). Split the marker by sub-operation |
| 23 | **MsgParse** | 16 | **TODO** | — | unsatisfiable | `Message.parse()` returns a NEW Message; verified inert today (16/16 no stub) |
| 24 | **ItemFormatDate** | 14 | **TODO** | — | never | VB masks (`yyyymmddhhmmss`, `nn`=minutes), **not** strftime. Emit the suggested strftime string **in a comment only** |
| 25 | **MsgAddHistory** | 14 | **TODO** | — | never | `log_note` is DEBUG-only + redact-by-default; CLAUDE.md §9 forbids production DEBUG, so the audit record vanishes |
| 26 | **ItemFormat** | 52 (across the corpus) | **TODO** | — | never | printf-style multi-source composition; no helper composes multiple sources. **Also fix the mis-attribution** (§4.6) |
| 27 | **ItemCodeLookup** | 62 | **TODO** | — | 0/62 | in-place + direction unknown. **Emit the set NAME and entry COUNT and a `code_set("<name>")` reference (ADR 0033) — NEVER the entries** (§7) |
| 28 | **WSCall** | 11 | **TODO** | — | never | synchronous SOAP from inside a transform breaks purity. Do **not** put the SOAP endpoint literals in the marker |
| 29 | **MsgPass** | 11 | **TODO** | — | never | the marker must **not** promise a trailing `Send` — a list whose only lifecycle verb is MsgPass emits `return None`, i.e. FILTERED |
| 30 | **ActionListStop** | 11 | **TODO** | — | never | halts the **component**, requires an operator restart. `raise` only dead-letters one message. Needs its own kind (§4.5) |
| 31 | **If** | 1,059 tokens / 1,521 Controls | **TODO** | — | none on this corpus | the `@IN` gate proves nothing (§7); 82/203 compare a whole-field leaf; 2 of 5 proposed forms are **not** lens-recognised |
| 32 | **ElseIf** | 62 | **TODO** | — | none | a live `elif` under a dead `if` runs branches the source never took; **7 statements qualify while a preceding arm does not** |
| 33 | **Else** | 160 | **TODO** (render `elif False:`) | — | none | **160/160 bare `else:` sit under a dead chain opener** — this is the highest-priority live hazard (§4.4) |
| 34 | **ForEach** | 179 | **TODO** | — | none | **0 of 168 ForEach iterables normalise to an HL7 coordinate**; the loop var binds a node handle |
| 35 | **Try / Catch** | 32 / 32 | **PARTIAL** | `try:` / `except Exception:` + **`raise`** | the `except` must **re-raise** while the Catch body is untranslated (64/64 today) | 17 blocks are comments+`pass`, 47 contain only the no-op stub — a **swallow**, converting a dead-letter into a PROCESSED half-transformed message |
| 36 | **ChooseFrom** | 18 | **TODO** | — | none | 9 of 42 subjects normalise (not 12/12); arms unrecoverable |
| 37 | **Matching** | 27 | **TODO** | — | none | **all 27 are ORPHANS** whose arm bodies are inlined **unconditionally** at the parent indent (§4.3) |
| 38 | **LoopExit** | 26 | **MAP** (already) | `break` | `in_loop` | 33/33 have zero children; 26/26 have a loop ancestor; no target-loop naming in the vocabulary |
| 39 | **Loop** | 20 | **TODO — permanently** | — | never | a bounded retry with a wall-clock delay. `time.sleep` blocks the whole engine's event loop. The marker must say *"this must NOT become a live loop — move the retry to the outbound connection's delivery/retry settings"*, and carry the recovered trip count + delay |
| 40 | **ItemNew** | 147 | **TODO** | — | never | creates an empty node + binds a handle. **It is a PRECONDITION blocker for 66 otherwise-mappable writes** — guard G7 exists because of it, and the two must land in the same commit |

### 3.1 The ItemCopy `"LIT" → @H %PATH` guard set (G1–G10)

| Guard | Rule | Removes |
|---|---|---|
| G1 | verb `ItemCopy`; exactly 2 role operands: one `literal`, one `path`; connectives ⊆ `{to}`; **no `detail` token** | — |
| G2 | `_corepoint_path(dst)` resolves | — |
| G3 | `SAME_MESSAGE(dst.handle)` — INPUT ∪ whole-tree-CLONE only | the 340 partial-copy handles |
| G4 | list declares exactly ONE input handle **and is not an `ActionListCall` target** | 60% of naive candidates |
| G5 | no `[option]`/extra token on the statement | 99 non-candidates carry them |
| G6 | the establishing root `MsgTreeCopy` has **no control ancestor** | 18 |
| G7 | destination segment is not created by an `ItemNew` on the same tree in this list | 46 |
| G8 | destination segment ∈ `_SINGLE_OCCURRENCE` | 105 |
| G9 | statement is at **TOP LEVEL** (no control ancestor at all) | 136 |
| G10 | destination ∉ `{MSH-1, MSH-2}` | ≤4 |

**Survivors: 33** (measured under G1–G9; G10 can only reduce it, so **33 is an upper bound**).

G9 subsumes the loop-occurrence predicate (§2.4), but implement §2.4 as its own named check so relaxing G9 later cannot re-open it.

**Attacks that FAILED against these 33 — recorded so they are not re-litigated:** delimiter injection (all 191 literal sources are delimiter-free); modifier leakage through the coord regex's trailing `(\(.*\))?` (312/312 trailing parentheticals are plain human labels — 0 positional words, 0 bare numbers); option tokens (0 candidates carry one); ordering (0 candidates precede the root MsgTreeCopy); root-copy provenance (36/36 root copies source an input handle, never a MsgCreate/MsgLoad tree); lens recognition (`lens.py` lines 72–74 accept `set_field(msg, path, value)` as an editable action row).

**The residual divergence that must be in the ADR, not glossed:** Corepoint's tree write **creates** missing nodes; `Message.set` **refuses** an absent segment (`KeyError`) and pads intervening components. This is fail-loud (post-ACK ERROR/dead-letter, no NAK), which is why the verdict stays PARTIAL — but "a constant-source copy is exactly a set" is not the whole truth.

### 3.2 Marker texts for the nine ItemCopy blockers

Each names the guard, not a generic hand-finish. Two the earlier proposal never wrote:

- G7: *"destination segment `<SEG>` is created by an `ItemNew` in this action-list, which has no Message equivalent — `Message.set` REFUSES an absent segment (KeyError), so this write must follow a hand-written `msg.add_segment("<SEG>|…")`."*
- G8: *"destination `<SEG>` is a repeating segment and the Corepoint path carries no occurrence — `Message.set` would write occurrence 1; confirm which occurrence Corepoint addressed."*
- G6: *"this action-list's root `MsgTreeCopy` is inside a conditional, so the sent tree is only sometimes a copy of the input — mapping onto `msg` is unsound on the other branch."*

### 3.3 MsgLog's four markers

(1) other-handle: *"logs a different message tree; `checkpoint(msg, …)` would snapshot the WRONG message."* (2) multiple input handles: *"this action-list carries N distinct input handles."* (3) operand-bearing: *"also interpolates N value(s); `checkpoint(msg, label)` takes only a label."* (4) **new and required**: *"this action-list is the target of an `ActionListCall`, so its input handle is supplied by the caller, not by the channel's inbound message."* **Never name the handle text** — it is a customer tree name.

### 3.4 EnvLogText's two HARD preconditions

Both are **blocking**. If either is not implemented, the mapping **must not ship** — it is strictly worse than the TODO.

**(a) `Action` must gain a no-`msg` form.** `_generate_steps` hard-codes `msg` as the leading positional:
```python
parts = [f"msg, {', '.join(step.args)}"] if step.args else ["msg"]
```
`log_note`'s signature is `log_note(template, /, *values)`, so `msg` becomes the **template** and `template.format(...)` raises `AttributeError: 'Message' object has no attribute 'format'` at runtime. `diagnostics.py` catches only `(IndexError, KeyError, ValueError)`, so it **propagates and dead-letters every message**. Worse, `lens.parse_source("log_note(msg, \"note\")")` returns a clean `diagnostic` row with `template="msg"` and **no error** — the round-trip check the importer relies on does not catch it.

```python
@dataclass(frozen=True)
class Action:
    ...
    takes_msg: bool = True   # False ⇒ emit `vocab(<args>)` with NO leading msg positional
```

**(b) The import line must come from `messagefoundry`, not `messagefoundry.actions`.** `_vocabulary_used` drives `from messagefoundry.actions import …`, and `log_note` is **not** in `actions.__all__` — it lives in `messagefoundry.diagnostics` and is re-exported from `messagefoundry`. `from messagefoundry.actions import log_note` raises `ImportError` and fails the whole generated module at load. Split the renderer:

```python
_SURFACE_VOCAB = frozenset({"log_note", "checkpoint"})   # re-exported from `messagefoundry`
def _vocabulary_used(steps) -> tuple[set[str], set[str]]:  # (actions_module, surface)
```
This also matches STEPS-PALETTE.md's note: *"Every other action emits a wrapper call the lens auto-imports (`from messagefoundry import <name>`)."*

**Residual semantic difference, to be stated in the provenance comment, not hidden:** Corepoint `EnvLogText` writes to the operationally-visible environment log; `log_note` writes at DEBUG to `messagefoundry.diagnostics`, which is off in production. **The text is preserved exactly; the visibility is not.**

**PHI invariant to encode in code, not in a review note:** never generate a value-in-template form (concatenation, f-string, `%`-formatting) — `log_note` redaction protects **arguments only, never the template**. Zero instances arise here (0 of 152 live rows pair an input-handle with an HL7-shaped leaf), so the hazard is prospective.

---

## 4. Accounting corrections

The current ledger has **five** defects. Three make "mapped" go **DOWN**. That is required.

### 4.1 The passthrough `msg.set` stub is not inert — suppress it on the XML path (DOWN, and a live bug)

`_first_path` returns the first operand that resolves — on a two-path statement that is the **source**, not the destination — and it never consults the handle. Its own comment claims *"so nothing is corrupted"*. Runtime-verified, that is false in **two** ways:

- `Message.set` raises `KeyError("cannot set absent segment …")` (`parsing/message.py` L288–290) **before** writing.
- On a **present** segment with an absent field, `msg.set("PID-11.7", msg.field("PID-11.7") or "")` turned `PID|1||…|M` into `PID|1||…|M|||^^^^^^` — it **materialised** an empty field and six empty components on the wire, for a line whose only purpose was to be a visible marker.

**Fix:** `UnmappedAction.stub_path` is forced to `None` on the XML path. The recovered destination rides into the **marker text** instead:
> `# TODO: Corepoint <Verb> — intended target <SEG-F.C> on tree <handle-role>; no live stub emitted (a self-assign raises KeyError on an absent segment and materialises empty structure on an absent field).`

Live stub sites removed: MsgTreeCopy 35, EnvLogText 10, MsgLog 10, plus the fixture's ItemCustomScript. **Direction: `mapped` unchanged, but ~55 live statements stop executing.** This is also what defuses §4.4's Else hazard, so it must land **first or in the same commit**.

### 4.2 A degraded `MsgSend` must NOT feed `_collect_sends` (the prescription that was a regression)

`_collect_sends` populates `Handler.destinations`; `_generate_handler` (L1357, L1371) sets `inline_sends = _has_inline_send(steps)`, which goes **False** once every send has degraded to a TODO, and falls through to `return Send(dest, msg)` — **unconditional, at the tail**. Demonstrated: a degraded send nested in `if False:` produced `return Send("OB_ACME_ADT", msg)` at handler level.

Blast radius: **81 of 138** action-lists with a live MsgSend have all live sends `@OTH` and all 81 recover a destination ⇒ 81 spurious unconditional trailing Sends; **16** of those have every send inert today, so the "fix" would make 16 currently-harmless handlers actively wrong; 4 lists have 2–4 destinations and would fan the wrong message to all of them.

The other horn is equally bad: dropping the destination makes `h.destinations` empty and the handler emits `return None`, turning a send into a **FILTERED** disposition.

**Fix — three parts, all in one commit:**
1. `Channel` gains `placeholder_destinations: tuple[str, ...]` — a channel-level collection that declares the inert `outbound(..., deployed=False)` placeholder. **Never `Handler.destinations`.**
2. `_generate_handler` gains a **third tail** for "this list sent something we cannot represent": neither `return Send(...)` nor `return None`. Emit
   `raise NotImplementedError("Corepoint MsgSend not translated — see the TODO markers above")`, which is honest (post-ACK dead-letter + AlertSink) and cannot be mistaken for a working handler. It is safe because XML-sourced endpoints are `deployed=False` and bind nothing.
3. `_collect_sends` only collects from a send whose handle passed the §3 row-13 guard.

### 4.3 The phantom wrappers are counted but are not source statements (DOWN, −789)

`<If>` (1,050) and `<Try>` (46) elements carry **no `@Data`** — they are pure containers wrapping the `<Line>` that carries the condition. Today each emits its own `Control`, so the module carries **757** condition-less `if False:  # TODO: Corepoint If condition — hand-finish` and **32** false `except Exception:  # TODO: Corepoint Try with no Catch` (all 32 constructs **do** have a Catch).

**Fix:** in `_parse_statement`, a container element in `_CONTAINER_KIND_BY_TAG` with **no `@Data`** emits **nothing of its own** and returns its parsed body straight through. The marker then always lands on the line that carries the condition.

`mapped` falls by **757 + 32 = 789**.

### 4.4 `Else` renders as `elif False:` — and it must land in the SAME commit as 4.3

**160/160 bare `else:` in the generated module have a dead (`False`) chain opener.** The moment the phantom wrapper is removed, `if False: A else: B` runs **B unconditionally** — the import would start executing the fallback path for every message. Today this is survivable only because the branch bodies contain nothing live *except* the §4.1 stubs.

**Fix:** `_generate_conditional` renders every `Else` as `elif False:` + `pass` + a marker, until its `if`/`elif` chain carries a recovered condition (a set that is currently empty). The marker is the one it does not have today:
> `# TODO: Corepoint Else — rendered as \`elif False:\` because the If/ElseIf above it is still a dead placeholder. A bare \`else:\` there would run this branch for EVERY message. Write the If condition first, then change this back to \`else:\`.`

`test_conditions_are_dead_placeholders_never_guessed` remains the regression guard and must still pass.

**Cross-family resolution:** because guard **G9** requires every mapped call to be at TOP LEVEL, no `set_field` this change emits can land inside an `Else`, a `Matching` arm, or a dead loop. So 4.3/4.4 cannot promote a *mapped* call to unconditional execution — only the §4.1 stubs, which are removed. That is what makes this ordering safe.

### 4.5 Bucket corrections (mapped DOWN, honestly)

| Correction | mapped | new bucket |
|---|---|---|
| `call` (113) is in `_MAPPED_CONTROL_KINDS` but emits **no invocation** and a **false** `(called list inlined)` comment | −113 | `todo` +113 |
| `send` with **no args** (4) is counted mapped by kind alone — `_count_steps` never inspects `args` | −4 | `todo` +4 |
| dead-by-construction scaffolding: `for` 179, `while` 20, `case` 18, `match` 27, plus the surviving `if` 764, `elif` 62, `else` 160 | −1,230 | **`inert`** +1,230 |
| the 678 `<Call>` property rows, minus 14 `action-list-call-custom` + 4 non-empty-`<List>` Returns | `todo` −660 | **`properties`** +660 |
| phantom wrappers (§4.3) | −789 | *removed from the ledger entirely* |

Also split `_KIND_BY_VERB`'s single `"exit"` kind — `Returns` / `ActionListExit` / `ActionListStop` share one marker text across three unrelated meanings, and only `ActionListExit` maps.

```python
_KIND_BY_VERB = {..., "returns": "returns", "actionlistexit": "exit", "actionliststop": "stop"}
```

`_count_steps` returns a `StepCounts` dataclass (`mapped`, `todo`, `inert`, `properties`, `disabled`, `todo_classes`) rather than growing the tuple; `ChannelResult`/`ImportResult.to_json` gain `inert` and `properties`; `__main__.py` L2850–2859 prints them.

### 4.6 `ItemFormat → convert_case` is a mis-attribution (JSON path, latent)

`_map_action` L332 maps `cls in ("ItemConvert", "ItemFormat")` to `convert_case`, and `actions.convert_case`'s docstring claims *"Corepoint `ItemConvert`/`ItemFormat`"*. `ItemFormat` is printf-style multi-source composition with no operation selector. **Correct both to `ItemConvert` only.** The JSON fixture does not exercise `ItemFormat`, so `test_maps_every_vocabulary_class` is unaffected.

### 4.7 `ItemAppend`'s operand inversion, and the live strftime trap

- `_map_statement` L934–938 reads `operands[0]` as the target and `operands[1]` as the suffix, but the grammar is `ItemAppend <value> to <target>`. Unreachable today (it needs exactly 2 flat operands; real statements tokenize to 3–4), but re-point it now — otherwise a future arity relaxation appends the target onto the literal.
- `_map_action` L321–331 passes the export's raw `outputFormat`/`inputFormat` straight into `format_date` as **strftime** formats with no translation and no validation. Corepoint's masks are VB-style (`nn` = minutes, `mm` = months), so this emits the mask text verbatim into the field — silent corruption, **live on the JSON path today**. Gate it: reject a mask that is not a valid strftime string, and degrade to `UnmappedAction`.

---

## 5. Fixture additions

Append to `tests/fixtures/corepoint/acme_adt_package.xml`, **before** the closing `</Package>` and after the existing `</ActionList>`. Everything below is invented from the grammar (ACME / TEST_LAB / demo.example.org, RFC 2606) and uses the **real span classes** with the export's escaping skeleton: tags single-XML-escaped (`&lt;span class='keyword'&gt;`), `class=` single-quoted, the statement's own quotes double-escaped (`&amp;quot;`).

The existing `ACME ADT Transform` list keeps its invented `kw`/`pth` classes and therefore keeps exercising the **flat fallback** — do not touch it.

```xml
  <!-- ============================================================================================
       ROLE-AWARE fixture (BACKLOG #105). Uses the REAL span classes and the real escaping skeleton
       (single-XML-escaped tags, single-quoted class=, the statement's own quotes double-escaped).
       Every value is INVENTED: ACME / TEST_LAB / demo.example.org (RFC 2606). No real export is
       read and no customer value appears here.

       This list satisfies the mapping guards: exactly ONE input handle (%in), not an
       ActionListCall target, no ItemNew, all writes at TOP LEVEL, all destinations
       single-occurrence segments.
       ============================================================================================ -->
  <ActionList Name="ACME ROLE Positive" Desc="Statements that MUST map">
    <List>
      <!-- ItemCopy "LIT" to @IN %PATH  → set_field(msg, "MSH-6", "TEST_LAB") -->
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;TEST_LAB&amp;quot;&lt;/span&gt; to &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/MSH-6 (Receiving Facility)&lt;/span&gt;"/>

      <!-- A BARE (unquoted) literal span with meaningful padding — the .strip() regression guard. -->
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;  A  &lt;/span&gt; to &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/PID-8 (Sex)&lt;/span&gt;"/>

      <!-- ItemClear @IN %PATH → set_field(msg, "PID-19", "") -->
      <Line Data="&lt;span class='keyword'&gt;ItemClear&lt;/span&gt; &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/PID-19 (SSN)&lt;/span&gt;"/>

      <!-- EnvLogText with EXACTLY one literal operand → log_note("...") with NO leading msg. -->
      <Line Data="&lt;span class='keyword'&gt;EnvLogText&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;ACME ADT normalised&amp;quot;&lt;/span&gt;"/>

      <!-- MsgSend @IN to "LIT" — single input handle, not a call target → sends.append(Send(...)) -->
      <Line Data="&lt;span class='keyword'&gt;MsgSend&lt;/span&gt; &lt;span class='input-handle'&gt;%in&lt;/span&gt; to &lt;span class='literal'&gt;&amp;quot;OB_TEST_LAB_ADT&amp;quot;&lt;/span&gt;"/>
    </List>
  </ActionList>

  <!-- The CLONE branch of SAME_MESSAGE: an UNCONDITIONAL, WHOLE-TREE (root→root) MsgTreeCopy
       makes %work a clone of %in, so a later write to %work maps. A ROOT path span is empty
       after the leading '/'. -->
  <ActionList Name="ACME ROLE Clone" Desc="Whole-tree clone establishes the destination handle">
    <List>
      <Line Data="&lt;span class='keyword'&gt;MsgTreeCopy&lt;/span&gt; &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/&lt;/span&gt; to &lt;span class='other-handle'&gt;%work&lt;/span&gt;&lt;span class='path'&gt;/&lt;/span&gt;"/>
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;ACME&amp;quot;&lt;/span&gt; to &lt;span class='other-handle'&gt;%work&lt;/span&gt;&lt;span class='path'&gt;/MSH-3 (Sending Application)&lt;/span&gt;"/>
    </List>
  </ActionList>

  <!-- A PARTIAL (sub-node) MsgTreeCopy must NOT establish a clone: the later write is a marker. -->
  <ActionList Name="ACME ROLE Partial Copy" Desc="Sub-node copy is NOT a clone">
    <List>
      <Line Data="&lt;span class='keyword'&gt;MsgTreeCopy&lt;/span&gt; &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/PID&lt;/span&gt; to &lt;span class='other-handle'&gt;%scratch&lt;/span&gt;&lt;span class='path'&gt;/PID&lt;/span&gt;"/>
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;X&amp;quot;&lt;/span&gt; to &lt;span class='other-handle'&gt;%scratch&lt;/span&gt;&lt;span class='path'&gt;/PID-3-1 (Patient ID)&lt;/span&gt;"/>
    </List>
  </ActionList>

  <!-- ============================================================================================
       NEGATIVE list: every statement here MUST become a marker, and each fails a DIFFERENT guard.
       ============================================================================================ -->
  <ActionList Name="ACME ROLE Negative" Desc="One statement per blocking guard">
    <List>
      <!-- G8: OBX is a REPEATING segment; the Corepoint path carries no occurrence. -->
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;F&amp;quot;&lt;/span&gt; to &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/OBX-11 (Result Status)&lt;/span&gt;"/>

      <!-- G10: MSH-1 is the field separator — msg.set accepts it and CORRUPTS the framing. -->
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;!&amp;quot;&lt;/span&gt; to &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/MSH-1 (Field Separator)&lt;/span&gt;"/>

      <!-- G7: an ItemNew creates PV2 on this tree, so the later write must NOT be emitted
           (Message.set raises KeyError on an absent segment). ItemNew is destination-first. -->
      <Line Data="&lt;span class='variable'&gt;$pv2&lt;/span&gt; = &lt;span class='keyword'&gt;ItemNew&lt;/span&gt; &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/PV2&lt;/span&gt;"/>
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;ACME&amp;quot;&lt;/span&gt; to &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/PV2-3-1 (Accommodation Code)&lt;/span&gt;"/>

      <!-- ItemCopy PATH -> PATH never maps (copy_field clears dst on an absent src). -->
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/PID-5-1 (Family Name)&lt;/span&gt; to &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/PID-9-1 (Alias)&lt;/span&gt;"/>

      <!-- Destination is a Corepoint $variable. -->
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;ACME&amp;quot;&lt;/span&gt; to &lt;span class='variable'&gt;$facility&lt;/span&gt;"/>

      <!-- EnvLogText with an extra operand: must NOT become log_note. -->
      <Line Data="&lt;span class='keyword'&gt;EnvLogText&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;facility=&amp;quot;&lt;/span&gt; &lt;span class='variable'&gt;$facility&lt;/span&gt;"/>

      <!-- MsgSend from an OTHER handle: NOT the message this Handler carries. It must NOT emit a
           Send, must NOT declare a Handler destination, and must NOT gain a trailing Send. -->
      <Line Data="&lt;span class='keyword'&gt;MsgSend&lt;/span&gt; &lt;span class='other-handle'&gt;%built&lt;/span&gt; to &lt;span class='literal'&gt;&amp;quot;OB_ACME_BUILT&amp;quot;&lt;/span&gt;"/>

      <!-- G9: inside an If, so the mapped call would land in a dead `if False:` block. -->
      <If>
        <List>
          <Line Data="&lt;span class='keyword'&gt;If&lt;/span&gt; (&lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/MSH-9-2 (Trigger Event)&lt;/span&gt; = &lt;span class='literal'&gt;&amp;quot;A08&amp;quot;&lt;/span&gt;)&lt;span class='keyword'&gt; Then&lt;/span&gt;"/>
          <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;ACME&amp;quot;&lt;/span&gt; to &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/MSH-4 (Sending Facility)&lt;/span&gt;"/>
          <Line Data="&lt;span class='keyword'&gt;Else&lt;/span&gt;"/>
          <Line Data="&lt;span class='keyword'&gt;ItemClear&lt;/span&gt; &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/MSH-4 (Sending Facility)&lt;/span&gt;"/>
        </List>
      </If>
    </List>
  </ActionList>

  <!-- G4: this list IS an ActionListCall target, so its input handle is the CALLER's, not the
       pipeline's — the write must stay a marker even though every other guard passes. The <Call>
       also carries the invariant six-row PROPERTY manifest, which must collapse to ONE comment. -->
  <ActionList Name="ACME ROLE Caller" Desc="Invokes the callee below">
    <List>
      <Call Data="&lt;span class='keyword'&gt;ActionListCall&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;ACME ROLE Callee&amp;quot;&lt;/span&gt; with &lt;span class='input-handle'&gt;%in&lt;/span&gt;">
        <Actions>
          <Line Data="&lt;span class='action-list-call-pass'&gt;Returns - defaulted&lt;/span&gt;"><List/></Line>
          <Line Data="&lt;span class='action-list-call-pass'&gt;Returns - defaulted&lt;/span&gt;"><List/></Line>
          <Line Data="&lt;span class='action-list-call-pass'&gt;Returns - defaulted&lt;/span&gt;"><List/></Line>
          <Line Data="&lt;span class='action-list-call-pass'&gt;RaisesAlert - defaulted&lt;/span&gt;"><List/></Line>
          <Line Data="&lt;span class='action-list-call-pass'&gt;LogsText - defaulted&lt;/span&gt;"><List/></Line>
          <Line Data="&lt;span class='action-list-call-pass'&gt;RequestsGearStop - defaulted&lt;/span&gt;"><List/></Line>
        </Actions>
      </Call>
    </List>
  </ActionList>

  <ActionList Name="ACME ROLE Callee" Desc="Its input handle is bound by the caller, never by the pipeline">
    <List>
      <Line Data="&lt;span class='keyword'&gt;ItemCopy&lt;/span&gt; &lt;span class='literal'&gt;&amp;quot;ACME&amp;quot;&lt;/span&gt; to &lt;span class='input-handle'&gt;%in&lt;/span&gt;&lt;span class='path'&gt;/MSH-5 (Receiving Application)&lt;/span&gt;"/>
    </List>
  </ActionList>
```

**Assertions the new tests must make**

Positive: `set_field(msg, "MSH-6", "TEST_LAB")`, `set_field(msg, "PID-8", "  A  ")` (padding preserved — no `.strip()`, no doubled quotes), `set_field(msg, "PID-19", "")`, `log_note("ACME ADT normalised")` **with no leading `msg`**, `from messagefoundry import ... log_note` (**not** `messagefoundry.actions`), `sends.append(Send("OB_TEST_LAB_ADT", msg))`, `set_field(msg, "MSH-3", "ACME")` from the clone list.

Negative: `set_field(` appears **zero** times in the Negative / Partial Copy / Callee handlers; each marker names its guard (`OBX-11` repeating, `MSH-1` separator, `PV2` created by `ItemNew`, `copy_field` absent-source, `$facility` variable, other-handle send, dead block, call target); the six-row `<Call>` manifest produces **one** properties comment and **zero** per-row TODOs; the `%built` send produces **no** `outbound(...)` from `Handler.destinations` and **no** trailing `return Send(...)`; `ast.parse(src)` succeeds; every `ast.If`/`ast.While` test is still `Constant(False)`.

---

## 6. Expected coverage

**Denominator:** the **10,282** `@Data`-bearing non-`<Block>` statements = **7,518 live + 2,764 disabled** (reconciled exactly; `<Block>` labels are 2,671 more and are correctly counted in no bucket, and the 1,050 `<If>` / 46 `<Try>` containers carry no `@Data` at all).

### Vocabulary mappings (the coverage number)

| Verb | Survivors | Note |
|---|---|---|
| `ItemCopy "LIT" → @H %PATH` → `set_field` | **33** | upper bound (G10 can only reduce) |
| `ItemClear @H %PATH` → `set_field` | **16** | upper bound (G7/G10 can only reduce) |
| `EnvLogText "LIT"` → `log_note` | **63** | flat guard ≡ role guard exactly |
| `MsgSend @IN → "LIT"` → `Send` | **6** | after the call-target pass |
| **Total** | **118** | of which **112** are `messagefoundry.actions`/surface calls |

**Today: 0.** `118 / 10,282 = 1.15%`. Against live non-block statements: `118 / 7,518 = 1.57%`.

### Full ledger, before → after

```
BEFORE (measured):     mapped 2,386 + unmapped 5,931 + disabled 475           = 8,792
                       …of which vocabulary Actions = 0

mapped 2,386
  − 757  phantom <If>  (no @Data; not a source statement)
  −  32  phantom <Try> (no @Data; the "no Catch" comment was false 32×)
  − 113  ActionListCall  (emits no invocation)   → todo
  −   4  MsgSend with no args (counted by kind, never by args) → todo
  − 1,230 dead scaffolding (if 764 · elif 62 · else 160 · for 179 ·
          while 20 · case 18 · match 27)                       → inert
  + 112  NEW vocabulary Actions (33 + 16 + 63)
  =  362   ← of which 250 are genuinely-executing constructs
            (try 32 · except 32 · break 26 · send-with-args 160)
            and 112 are transform/diagnostic calls

unmapped 5,931
  − 112  newly mapped
  + 117  call 113 + send-no-args 4
  − 660  <Call> property rows (678 − 14 custom-Returns − 4 non-empty-<List>) → properties
  = 5,276  (renamed `todo`)

inert       = 1,230   (NEW bucket)
properties  =   660   (NEW bucket)
disabled    =   475   (unchanged)

AFTER: 362 + 5,276 + 1,230 + 660 + 475 = 8,003
CHECK: 8,792 − 8,003 = 789 = 757 + 32  ✓  (exactly the phantom wrappers, which were never
                                            source statements and are now off the ledger)
```

**The honest headline: `mapped` falls from 2,386 to 362 — an 85% DROP — while the number of statements that actually do something rises from 0 to 118.** The old 2,386 was entirely unearned scaffolding.

### What remains uncovered — for the 🚧 PARTIAL banner

- **5,276 statements (51% of the corpus) stay TODO markers.** The deliverable of this change is not coverage; it is that the markers finally name the verb, the recovered coordinate, and the *specific* blocker.
- **477 destination-first assignment statements** (`ItemNew` 147, `ItemReplace` 98, `ItemExpr` 85, `ItemCodeLookup` 62, `ItemFormat` 52, `ItemTransformDate` 19, `ItemFormatDate` 14) currently emit `"statement does not begin with a verb"` — they name **no Corepoint verb at all**. §1.1's role verb fixes all 477. **This is the cheapest and highest-value item in the whole change and should ship first.**
- **21 `MsgEncode`** stop reporting as `<unparsed>`.
- **1,230 inert constructs** need a human to write the condition/iterable before anything runs.
- **Nothing in the If/ElseIf/ChooseFrom/Matching/ForEach families is mapped**, and none of it can be until the input-handle identity premise is discharged against Corepoint itself (out-of-band).
- **The 67 executing wrong-message Sends are stopped** (§4.2) — a correctness win with **negative** coverage.
- **~55 live passthrough stubs are removed** (§4.1) — also correctness, also negative coverage.

---

## 7. Explicitly NOT doing

Each of these was considered and rejected. Do not re-litigate without new evidence from Corepoint itself.

1. **`ItemCopy @H %P → @H %P` → `copy_field`.** `actions.copy_field` is `msg.set(dst, msg.field(src) or "")` and its docstring is explicit: *"An absent/empty src copies an empty value (clearing dst)."* Under guard G3 the destination already holds the input's original value, so if Corepoint instead leaves the destination untouched on an absent source, this **silently deletes a populated field**. 52 of 75 destinations are component/subcomponent paths. Zero option tokens select the behaviour, so the export gives no evidence either way. Only 18 survive the structural guards; 18 statements is not worth a silent-data-loss risk. **The operand-model family's roll-up counted 84 `copy_field` mappings — the field-transform family's TODO verdict wins the tie, per the governing rule.**
2. **`ItemAppend` → `append_to_field`.** All 8 candidates fail at least one guard (4 in a ForEach/Loop, 4 in an If/ChooseFrom/Try — every one would be emitted inside dead code). Relaxing the dead-block guard leaves exactly **one** mappable statement in a 12,953-element export. Additionally: the export does not establish whether `ItemAppend` is string concatenation at all, or adds a **repetition** (180/224 append to a `$VAR`).
3. **`ItemNew` → `msg.add_segment`.** `add_segment` needs a complete segment line up front; `ItemNew` creates an *empty* node and binds a handle. Message has no handle space.
4. **`ItemFormat` → `convert_case`** — actively removed (§4.6). No operation selector exists; it is printf-style composition.
5. **`ItemFormatDate`/`ItemTransformDate` → `format_date` with the export's raw masks** — actively gated (§4.7). VB masks are not strftime (`nn` = minutes); passing one emits the mask text verbatim into the field.
6. **`ItemCodeLookup` → `code_lookup` with an inlined table.** Emitting the resolved code set as a commented-out dict would inline up to **1,945 customer Code/Desc pairs** (facility/location/provider descriptors) into a generated `.py` in a repository. Emit the set **name**, the entry **count**, and a `code_set("<name>")` reference (ADR 0033) — never the entries. Direction is also unestablished (`<Element>` carries Code and Desc; nothing says which side is the input) and `code_lookup` is in-place.
7. **`MsgLog` → `checkpoint`.** Provable yield **0**. The "one input handle ⇒ that handle is `msg`" guard admits 3 rows and at least 2 are wrong (their list is an `ActionListCall` target). 51% of single-input lists are call targets. `checkpoint` also logs only segment ids, losing the content the operator asked for; and `from messagefoundry.actions import checkpoint` raises `ImportError`.
8. **`MsgAddHistory` → `log_note`/`checkpoint`.** Both are DEBUG-only and redact-by-default; CLAUDE.md §9 forbids production DEBUG, so a durable audit record would vanish in production while the module still looked correct.
9. **`MsgError` → `raise ValueError` or `log_note`.** Corepoint **records and continues** (proved by six non-exit successors). `raise` aborts the handler; `log_note` erases the disposition. Name the choice in the marker; make neither.
10. **`RequestsGearStop` / `ActionListStop` → anything.** A defaulted, never-exercised call property must never be given power over engine lifecycle, and a Handler has no sanctioned route to stop a connection.
11. **`Returns` → `return`.** **216 of 339 live `Returns` sit in an unconditional position** — mapping this would have silently killed the tail of 216 handlers. It is a `<Call>` signature slot, never executable.
12. **`ForEach` → `for i in range(1, msg.count_segments("<SEG>") + 1)`.** **0 of 168 ForEach iterables normalise to an HL7 coordinate**; there is no segment id to put in the palette form. Even a resolvable iterable would need every body path rewritten with `occurrence=`.
13. **`Loop` → any live loop.** A bounded retry with a wall-clock delay. `time.sleep` blocks the asyncio event loop for the **entire engine**; a busy `while` is a hot spin. This belongs in the outbound connection's delivery/retry settings. `while False:` is the **permanent** answer, not a placeholder.
14. **If/ElseIf conditions → `msg.field(p) == v`.** Three independently sufficient refutations: (a) `input-handle` is not proof of message identity — 73/187 lists carry 2–4 distinct input handles and hold 60% of the qualifying conditions; (b) 82/203 compare a **whole-field** leaf, where `Message.field` returns every `~` repetition and the component separators; (c) `lens.parse_source` returns `label: null` for `not msg.field(p)` (Is Empty, 40) and `"v" in (msg.field(p) or "")` (Contains, 7) — 23% are **not** recognised as field conditions. The qualifying count is also 203, not 247.
15. **A real `else:` for `Else`.** Only 21 of 206 have every preceding arm recovered, and all 21 depend on the refuted If mapping. `elif False:` + marker until If lands.
16. **`Matching` arm values → `in ("a", "b")`.** Arm values are `detail`-role spans, never literals; **35 of 62 carry none at all**; their semantics (code-set reference? display form?) is unestablished. (The *adoption* fix — a `match` marker whose **parent** Control is a `case` — is still required so arm bodies stop being inlined unconditionally.)
17. **A repetition-subscript translator.** Zero `[n]` subscripts in the corpus. Do not build speculatively — and do **not** conclude occurrence is therefore unambiguous (§2.4).
18. **`numeral` → `substring_field`/`pad_field`.** Numerals by verb: Loop 30, ActionListOptions 4, ItemExpr 2, DBUpdate 2, ItemFormat 2, ForEach 1, DBSelect 1 — **not one sits on a substring or pad verb**. And Corepoint substring indices are conventionally 1-based while `substring_field` slices 0-based; nothing establishes the base. Extract the numeral as a **role** (a parser contract); claim no vocabulary equivalence.
19. **Keeping a degraded `MsgSend` destination in `_collect_sends`.** Executed and measured: it produces an **unconditional trailing `return Send(dest, msg)`** in 81 action-lists, makes 16 currently-harmless handlers actively wrong, and fans the wrong message to 2–4 destinations in 4 lists (§4.2).
20. **Widening `_HL7_PATH` without the handle-identity gate.** `_message_path` discards the handle entirely. Any widening must land in the **same commit** as G3 (identity), G6 (unconditional root copy), G7 (ItemNew), G9 (top level) and the MSH-1/2 refusal — otherwise every widened path resolves against the wrong message.
21. **Dispatching to the role parser on span presence.** 3,583 statements carry real role spans but no recoverable verb; that rule drops them uncounted (§1.1).

---

## Implementation order (each step is independently green)

1. **§1.1 dispatch + §1.5 path tightening + §4.5 `exit`-kind split.** No behaviour change beyond marker text: 477 assignment-form + 21 MsgEncode statements start naming their verb. Highest value, lowest risk.
2. **§4.1 stub suppression.** Removes ~55 live statements. Must precede step 3.
3. **§4.3 phantom-wrapper removal + §4.4 `Else` → `elif False:` — SAME COMMIT.** Splitting them puts 160 fallback branches live under dead guards.
4. **§4.2 `MsgSend` triple fix** (placeholder collection + third handler tail + guarded `_collect_sends`). Stops the 67 wrong-message Sends.
5. **§4.5 bucket model** (`StepCounts`, `inert`, `properties`, `_MAPPED_CONTROL_KINDS` revision, `__main__.py`). Makes step 6's numbers legible.
6. **§2 `_ListContext` + `_call_targets` package pass**, then **§3 row 1 (ItemCopy) and row 6 (ItemClear)** with guards G1–G10. **Guard G7 and the `ItemNew` marker must land together.**
7. **§3.4 `Action.takes_msg` + split import renderer**, then **EnvLogText → `log_note`**. Do not ship the mapping without both preconditions.
8. **§3 row 13 `MsgSend @IN`** (6 statements) — last, because it depends on step 4's collection change and step 6's context pass.
9. **§4.6/§4.7 JSON-path fixes** (`ItemFormat`, the strftime arm, the `ItemAppend` inversion) — independent, can land any time.
10. **Matching adoption fix** — not strictly blocking, because G9 keeps every mapped call out of an orphan arm, but it should ship in the same release; it is the one remaining "arm bodies run unconditionally" hazard.

Verification gate for every step: `ruff check` + `ruff format --check`, `mypy` (strict), `pytest`, plus `ast.parse` + `messagefoundry check` on the regenerated fixture module, and the unchanged `test_conditions_are_dead_placeholders_never_guessed`.