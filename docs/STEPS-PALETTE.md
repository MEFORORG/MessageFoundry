# Steps view — Add palette reference

The **Steps view** (`/ui`, ADR 0076/0089) renders any parseable `@handler` as an ordered list of typed
**steps**. Its **Add** dropdown offers **27 authoring steps** across four groups — the "commands" you use to
build a handler without hand-writing Python. **Every item inserts native Python** that the lens then
recognizes back as an editable step, so the `.py` file stays the only artifact and the only execution path
(#26). Placeholders below (`<…>`) are what you fill in via the item's prompts / inline fields.

> **Source of truth:** [`ide/src/stepsModel.ts`](../ide/src/stepsModel.ts) → `ADD_MENU_CATALOG` (the labels,
> ops, and pickers) and [`messagefoundry/lens.py`](../messagefoundry/lens.py) (the codegen). If an item
> changes there, update this table. Palette design: [ADR 0106](adr/0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md);
> Send fan-out: [ADR 0108](adr/0108-steps-view-accumulator-send-fan-out-copy-on-send-authoring.md).

## Transform (14)

| Item | Generates | What it does |
|---|---|---|
| Set Field | `msg.set("<path>", "<value>")` | Set a field to a value |
| Copy Field | `msg.set("<dst>", msg.field("<src>") or "")` | Copy one field into another |
| Trim Field | `trim_field(msg, "<path>")` | Strip surrounding whitespace |
| Replace | `replace_literal(msg, "<path>", "<old>", "<new>")` | Literal find/replace in a field |
| Substring Field | `substring_field(msg, "<path>", <start>, <end>)` | Slice a field by index |
| Pad Field | `pad_field(msg, "<path>", <width>)` | Pad a field to a width |
| Arith | `arith_field(msg, "<path>", "<+ - * />", <operand>)` | Arithmetic on a numeric field |
| Split Field | `split_field(msg, "<src>", "<sep>", [<dests>])` | Split a field into several |
| Date Diff | `date_diff_field(msg, "<start>", "<end>", "<dst>")` | Units between two date fields |
| Format Date | `format_date(msg, "<path>", "<out_fmt>")` | Reformat a date field |
| Copy Segment | `copy_segment(msg, "<SEG>")` | Duplicate a segment |
| Delete Segment | `msg.delete_segments("<SEG>")` | Remove a segment |
| Insert Segment | `msg.add_segment("<segment line>")` | Add a whole segment line (e.g. `ODS\|R\|…`) |
| Add Repetition | `msg.add_repetition("<path>", "<value>")` | Add a field repetition |

## Translate & lookup (3)

| Item | Generates | What it does |
|---|---|---|
| Code Lookup | `code_lookup(msg, "<path>", TABLE)` + module `TABLE = code_set("<set>")` | Translate a field via a named code set (ADR 0033) |
| DB Lookup | `row = db_lookup("<conn>", "<sql>", {})` | Read-only DB enrichment (`[egress].allowed_db`, ADR 0010) |
| FHIR Lookup | `pat = fhir_lookup("<conn>", "<path>", {})` | Read-only FHIR read/search — search fields go in the `params` mapping, never a `?`-query (`[egress].allowed_http`, ADR 0043) |

## Structure & flow (8)

| Item | Generates | What it does |
|---|---|---|
| If | `if msg.field("<path>") == "<v>":` + `pass` | Branch on a field condition — operator ∈ {exists, equals, not-equals, contains} |
| Else If | `elif …:` | Add a branch to the if-chain |
| Else | `else:` | Fallback branch |
| For Each | `for i in range(1, msg.count_segments("<SEG>") + 1):` + `pass` | Loop over each occurrence of a segment |
| Filter | `return []` | Drop the message (→ `FILTERED`) |
| **Send** | `sends.append(Send("<OB>", msg))` + managed `sends = []` / `return sends` | Deliver to an outbound; repeat / ＋ dest to fan out (ADR 0108) |
| Raise | `raise ValueError("<msg>")` | Error → dead-letter (post-ACK; does **not** NAK the sender) |
| Comment | `# <text>` | A comment line |

## Diagnostics (2)

| Item | Generates | What it does |
|---|---|---|
| Log Note | `log_note("<template>")` | DEBUG log line (redact-by-default) |
| Checkpoint | `checkpoint(msg, "<label>")` | Named trace checkpoint |

## Notes

- **Native vs. wrapper.** Set Field, Copy Field, Delete Segment, Insert Segment, and Add Repetition emit the
  native `msg.…` Message API (no import needed). Every other action emits a wrapper call the lens
  **auto-imports** (`from messagefoundry import <name>`).
- **Send is fan-out-aware (ADR 0108).** The first Send lays down `sends = []` … `return sends`; each extra
  destination is another `sends.append(Send(...))`. A legacy `return Send(...)` is still recognized — use the
  per-row **＋ dest** button or right-click **Add destination** to fan it out. The `sends = []` / `return
  sends` scaffold render as muted, read-only rows.
- **If / For Each** seed a `pass` body; insert steps into it to fill the block.
- **Everything is editable after insert** — each inserted step is a recognized row whose params you edit in
  place; the code stays the source of truth. This now includes **Comment**: an inserted comment reads back
  as its own editable `note` row (ADR 0076 Amendment A), where it used to disappear, merge into a
  neighbouring Code row, or be frozen as read-only. **One documented exception:** a comment matching the
  pragma allowlist (`fmt: off` / `fmt: on`, a `noqa` or `ruff: noqa` suppression, `type: ignore`, `region`
  / `endregion`) is functional code — it changes what ruff and mypy do to the file — so it is shown but
  read-only. Editing one is a text-editor job.
- **Routers get Steps too (ADR 0076 Amendment D).** A `@router` opens as Steps, its returns projected as
  **Route** rows (or **Unrouted** for a `return []` / `return None` / bare `return`, which the store logs
  as UNROUTED — routed nowhere, never dropped). A Router's palette offers routing constructs only —
  **Route To**, **If** / **Else If** / **Else**, **For Each**, **Raise**, **Comment** — because a Router
  selects destinations rather than transforming the message; the transform verbs, lookups, diagnostics and
  Send are greyed out there, and the engine refuses them.
- **Escape hatch.** Anything the Steps view will not edit — a pragma comment, a `code` row, a control
  test — is edited by dropping to the `.py` (Reopen With → Python). That is awkward, and it is deliberate:
  the lens refuses what it cannot reproduce byte-for-byte rather than guessing.
- **Recognized but not in the menu:** `convert_case`, `append_to_field` (valid if hand-written; just not
  offered as Add items).
