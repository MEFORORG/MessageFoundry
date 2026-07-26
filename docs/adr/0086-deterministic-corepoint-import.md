# ADR 0086 — Deterministic Corepoint action-list import → code-first Handlers

*(final ADR number assigned at merge — placeholder to avoid multisession churn)*

**Status:** Accepted (2026-07-10) — owner-ratified for BACKLOG #105 under the #26 amendment; the engine
importer + CLI + synthetic fixtures may build. **Amended 2026-07-24 (§2(a′)): the input schema is now
VALIDATED and it is XML, not JSON.** §2(a)'s "SYNTHETIC-until-validated" caveat is **discharged** — see
§2(a′) for the real shape and §5 for what the reconciliation changed.
**Deciders:** owner + IDE/DX working group
**Related:** BACKLOG **#105** (this build), **ADR 0076** (the typed action vocabulary + action-list lens
this is the *inverse* of), **#26 amendment** (the narrow structured-action-list carve-out both operate
under), ADR 0035 (IDE workspace-trust — the optional `ide/` wrapper shells the CLI under the exec gate),
CLAUDE.md §5/§8 (untrusted config/HL7 as data), §9 (PHI — the importer touches no message content),
§12 (the bright line: `.py` stays the only artifact + execution path).
**Code references** drift; locate exactly at implementation time.

---

## 1. Context — importing a Corepoint interface without a canvas

Corepoint's approachability comes from a **typed action-list** (ADR 0076 §1): an interface analyst
builds a transform as an ordered list of typed actions (`ItemCopy`, `ItemReplace`, `ItemFormatDate`,
`ItemCodeLookup`, `ItemSplit`, segment ops, …). ADR 0076 already ships the *read* direction — the
**lens** projects a vocabulary-authored Python Handler back into that action-list. #105 is the **write**
direction of the same bridge: mechanically translate a Corepoint export **forward** into a real
code-first `@router`/`@handler` module, so a shop migrating off Corepoint gets diffable, reviewable
Python instead of hand-retyping every channel.

Two hard constraints frame the decision:

1. **No real export exists in this repository.** The #87 Corepoint recon corpus is git-ignored (it
   carries partner/site data — kept private, never published), so we cannot pin the import schema
   against a captured artifact here. Building against it would either leak customer data or block the
   lane indefinitely.
2. **The bright line (#26 / ADR 0076 §2).** The output must be a plain `.py` file that is the **only**
   artifact and the **only** execution path — no interpreter, no declarative model, no canvas.

## 2. Decision

Build a **pure, stdlib-only engine importer** (`messagefoundry/corepoint_import.py`) + an `import`
CLI subcommand that parses a Corepoint action-list **export** and emits one code-first config module
per channel. The grammar lives in the engine beside the vocabulary + lens (ADR 0076 §5 "grammar in one
place"); the `ide/` wrapper is a thin, optional CLI shell (deferred / out of scope for the Python-only
build lane).

### (a) The export input format — SYNTHETIC-until-validated *(SUPERSEDED by §2(a′), 2026-07-24)*

> **Superseded.** The reconciliation §1.1 called for has happened: the real format is **XML**, and the
> validated schema is §2(a′). The JSON model below is kept working (its fixtures and tests still pass,
> and `parse_export` still parses it) but it is **not** the production input path.

Because no real export is available (§1.1), this ADR **defines** a plausible JSON model and states
honestly that it is unvalidated. A real Corepoint export will need a reconciliation pass (field names,
nesting, action-class inventory) before production use; the parser is deliberately isolated so only it
changes when the real shape is known.

```jsonc
{
  "format": "corepoint-actionlist",
  "version": 1,
  "channels": [
    {
      "name": "ACME_ADT",
      "inbound":  { "connector": "mllp", "name": "IB_ACME_ADT", "port": 2600 },
      "destinations": [
        { "name": "OB_ACME_ADT", "connector": "mllp", "host": "10.20.30.40", "port": 6000 }
      ],
      "handlers": [
        { "name": "acme_adt_transform",
          "destinations": ["OB_ACME_ADT"],          // optional; defaults to all channel destinations
          "actions": [
            { "class": "ItemCopy", "source": "PID-5.1", "destination": "NK1-2.1" },
            { "class": "ItemReplace", "target": "MSH-6", "value": "ACME" }
            // …
          ] }
      ]
    }
  ]
}
```

`connector` is `mllp` (inbound: `port`; outbound: `host` + `port`) or `file` (`directory` [+ `filename`]).
The importer treats every value as **untrusted data**: each value lifted into generated source is
rendered through `json.dumps`, whose fully-escaped literal cannot break out into executable code
(CLAUDE.md §5/§8). No new dependency — `json` parse + string codegen only.

### (a′) AMENDMENT 2026-07-24 — the VALIDATED export format is XML

A real Corepoint export was inspected (privately; nothing from it is in this repository — the fixtures
remain hand-authored synthetics). §2(a)'s caveat is discharged, and the reconciliation moved more than
field names: **the container format is different**.

**Structure.** The root element is `<Package>`. Transform logic lives at
`<Package>/<ActionList Name= Desc=>/<List>`. A `<List>`'s statement children are `<Block>`, `<Line>`,
`<Call>`, `<Case>`, `<Foreach>`, `<If>`, `<Loop>`, `<Try>`; `<Block>`/`<Call>` and the control elements
carry a nested `<List>`/`<Actions>`, so an action-list is a **recursive control-flow tree**, not the
flat array §2(a) assumed. Attributes are `@Data` (the statement), optional `@Disabled`, optional
`@Comment`; `<If>` and `<Try>` may carry **no** `@Data` at all (pure containers).

**`@Data` is rich text, not a statement — the single biggest surprise.** Each statement is stored
syntax-coloured: markup tags plus HTML entities, escaped again for the XML attribute. It must be run
through `strip_markup()` (tag-strip, *then* `html.unescape`, in that order) to recover the plain
`Verb operand …` form. Skipping the strip leaves the leading token as markup rather than a verb, and
the overwhelming majority of statements fail to classify.

**`<Block>` is a comment / section label, not an action.** It is preserved as a comment in the
generated module and its body is emitted at the *same* indentation. Emitting it as a step would invent
an action the export never had.

**Statement grammar.** After stripping: `Verb operand …`, where an operand is `$variable`,
`%tree/path` (a message-tree path whose leaf carries the HL7 coordinates), `"string literal"`,
`[bracketed option]` or `(parenthesised condition)`. The verb vocabulary is **42 verbs**, of which 30
account for 99.4% of statements; 83.8% of executable elements start with a clean verb once stripped.
Executable elements are `<Line>`, `<Call>`, `<Foreach>`, `<Case>`, `<Loop>`, plus `<If>`/`<Try>` as
containers. Branch continuations (`Else`, `ElseIf`, `Catch`, `Matching`) are carried as ordinary
statements **inside** their construct's own `<List>`.

**Out of scope (tolerated, not modelled).** `<Connection>`/`<Table>`/`<Row>`/`<Cell>`, `<Codeset>`,
`<Association>`, `<Namespace>`, `<FtpEndpoint>`, `<SOAPWSEndpoint>`, `<DataPoint>`, `<OtherObjects>`
are ignored rather than parsed — so the importer must not crash on a full package, but endpoint wiring
comes out as an inert `deployed=False` placeholder (#233 / ADR 0111) to hand-finish. A placeholder
binds no socket and polls no path, so an unfinished import can never affect a running engine.

**Security.** XML widens the attack surface, so the parse goes through **defusedxml** with
`forbid_dtd` / `forbid_entities` / `forbid_external` all ON (the same posture as
`RawMessage.xml()`, ADR 0004 / BACKLOG #31): a billion-laughs or external-entity payload raises
`CorepointImportError` instead of expanding. `defusedxml` is already an in-tree dependency, so §2(a)'s
"no new dependency" property survives. Values still ride into generated source only through
`json.dumps`; text that rides into a *comment* is additionally whitespace-flattened, so a crafted
`@Data` carrying a newline cannot escape the `#` and become a statement.

**Dispatch.** `parse_package()` is the validated path, `parse_any()` sniffs (a leading `<` ⇒ XML), and
`parse_export()` keeps the superseded JSON model working.

### (b) The action → vocabulary mapping (the INVERSE of ADR 0076 §2)

| Corepoint action class | v1 vocabulary call (`messagefoundry/actions.py`) |
|---|---|
| `ItemCopy` | `copy_field(msg, source, destination)` |
| `ItemReplace` | `set_field(msg, target, value)` |
| `ItemAppend` | `append_to_field(msg, target, suffix)` |
| `ItemFormatDate` / `ItemTransformDate` | `format_date(msg, target, outputFormat, in_fmt=inputFormat?)` |
| `ItemConvert` / `ItemFormat` | `convert_case(msg, target, mode)` |
| `ItemCodeLookup` | `code_lookup(msg, target, table, default=default?)` |
| `ItemSplit` | `split_field(msg, source, separator, destinations)` |
| `SegmentCopy` / `ItemSegmentCopy` | `copy_segment(msg, segment, occurrence=occurrence?)` |
| `SegmentDelete` / `ItemSegmentDelete` | `delete_segment(msg, segment)` |

Each emitted handler runs its mapped calls, then `return Send(...)` (one destination), `return [Send(...), …]`
(several), or `return None` (no destination — a filter). The router forwards to every handler with a
`# TODO: Corepoint routing` marker to refine by hand.

**(b′) AMENDMENT 2026-07-24 — the verb mapping is deliberately narrow.** The XML verbs map onto the
same vocabulary, but only where the helper is a *genuine* equivalent **and** every operand resolves:

| Corepoint verb | v1 vocabulary call | condition |
|---|---|---|
| `ItemCopy A B` | `copy_field(msg, A, B)` | both operands resolve to HL7 paths |
| `ItemCopy "lit" B` | `set_field(msg, B, "lit")` | a literal source *is* a set |
| `ItemClear A` | `set_field(msg, A, "")` | clearing == setting empty |
| `ItemAppend A "lit"` | `append_to_field(msg, A, "lit")` | the helper takes a literal suffix |

A `%` operand resolves only when its **last** path segment matches the `SEG-F[.C[.S]]` grammar
`Message` addresses (`%ADT/PID-5.1` → `PID-5.1`). A `$variable`, a named tree node, a whole-subtree
copy (`MsgTreeCopy`), and the message-lifecycle / logging / alerting verbs (`MsgLoad`, `MsgLog`,
`EnvLogText`, `RaisesAlert`, …) all fall through to the §2(c) TODO marker. **A path is never guessed**:
without the export's data dictionary a fabricated path would silently write the wrong field, which is
strictly worse than a marker a human must clear.

**Control flow is emitted as real nested Python** — `if`/`elif`/`else`, `for`, `while`, `break`,
`try`/`except` — with the *condition* left as an explicit dead placeholder (`if False:` /
`for _item in []:`) beside the original text, because a Corepoint condition is not a Python
expression. `Returns`/`ActionListExit`/`ActionListStop` have no faithful form (a bare `return` would
swallow the handler's `Send`s), so they emit a marker. A `MsgSend` appends to a `sends` list **where
the export put it**, so a conditional send stays conditional. Nothing is ever silently flattened.

### (c) Unmapped actions are never silently dropped (count-and-log)

An action whose `class` has no v1 mapping emits, **in place**, an
`# TODO: Corepoint <ActionClass> — hand-finish` marker plus a best-effort field-preserving
`msg.set(<target>, msg.field(<target>) or "")` passthrough stub when a target field is recoverable.
The import summary counts mapped vs. unmapped actions per channel (the count-and-log ethos, CLAUDE.md
§1). In the lens round-trip the stub degrades to a single in-place `code` row — never a whole-file
refusal.

**(c′) AMENDMENT 2026-07-24 — `@Disabled` is a third bucket.** An element carrying `@Disabled` is
**never** emitted as live code and is **never** dropped either: its whole subtree is preserved as
commented-out pseudo-source under a `# DISABLED in Corepoint (@Disabled)` header, and the summary
counts it separately (`disabled` / `total_disabled`). So every source statement lands in exactly one
bucket — *mapped* (a vocabulary call or real control flow), *unmapped* (an in-place TODO), or
*disabled* (a preserved comment). Counting a disabled element as mapped would claim it shipped;
omitting it would claim it vanished.

## 3. Acceptance criteria

- **AC-1 (mapping)** — WHERE an export action has a v1 mapping, the importer SHALL emit the
  corresponding vocabulary call with the exported field paths as arguments.
  → `tests/test_corepoint_import.py::test_maps_every_vocabulary_class`
- **AC-2 (count-and-log)** — WHERE an export action has no mapping, the importer SHALL emit an in-place
  `# TODO: Corepoint …` marker (+ best-effort stub) and count it — never drop it silently.
  → `tests/test_corepoint_import.py::test_unmapped_action_is_stubbed_not_dropped`
- **AC-3 (check gate)** — the emitted modules SHALL pass `messagefoundry check` (validate leg).
  → `tests/test_corepoint_import.py::test_generated_module_passes_check`
- **AC-4 (lens round-trip)** — every emitted `@handler` SHALL classify through `lens parse` into typed
  rows with no whole-file refusal; mapped calls become `action`/`lookup` rows, the `return` a `send` row.
  → `tests/test_lens_parse.py::test_generated_handler_round_trips_through_lens`
- **AC-5 (untrusted input)** — a hostile value (quotes/newlines/backslashes) SHALL ride across as an
  inert literal, never injected code; a malformed export SHALL raise `CorepointImportError`, not a
  traceback. → `tests/test_corepoint_import.py::test_hostile_values_are_escaped_not_injected`,
  `::test_malformed_export_raises`

### AC-6 (amendment, 2026-07-24 — the validated XML layer)

- **AC-6a (markup)** — a markup-wrapped `@Data` SHALL yield its plain statement, and the fixture's
  wrapped statements SHALL classify into vocabulary calls.
  → `::test_strip_markup_recovers_the_verb`, `::test_markup_stripped_statements_classify_in_the_fixture`
- **AC-6b (`<Block>`)** — a `<Block>` SHALL emit a comment with its body inline, never an action.
  → `::test_block_becomes_a_comment_never_an_action`
- **AC-6c (`@Disabled`)** — a `@Disabled` subtree SHALL be preserved as a comment, never emitted as
  live code, and counted separately. → `::test_disabled_element_is_preserved_as_comment_not_live_code`
- **AC-6d (control flow)** — If/ElseIf/Else, ForEach + LoopExit, Try/Catch and Call SHALL keep their
  shape through parse → codegen, with every emitted condition an inert placeholder.
  → `::test_nested_control_flow_round_trips`, `::test_conditions_are_dead_placeholders_never_guessed`
- **AC-6e (accounting + gate)** — every statement SHALL land in mapped/unmapped/disabled, and the
  emitted module SHALL compile, pass `messagefoundry check`, and wire through the loader.
  → `::test_every_statement_is_accounted_for`, `::test_generated_xml_module_compiles_and_passes_check`
- **AC-6f (hardened XML)** — a DTD/entity payload and malformed XML SHALL raise
  `CorepointImportError`; a hostile `@Data` SHALL NOT inject code.
  → `::test_malformed_or_hostile_xml_raises_cleanly`, `::test_hostile_xml_values_cannot_inject_code`

## 4. Consequences

- **Positive:** a migrating shop gets first-class, reviewable Python; the vocabulary/lens/import bridge
  is symmetric (one grammar); no new dependency, no PHI surface (no message content). Since the
  2026-07-24 amendment the input schema is **validated against the real format**, so the import is a
  real starting point rather than a shape-of-things demo.
- **Negative / residual:** the mapping is deliberately narrow (§2(b′)) — a `%tree/path` that is not
  HL7-shaped, a `$variable`, and the message-lifecycle verbs all come out as TODO markers, so a real
  package yields a scaffold with substantial hand-finishing rather than a runnable transform. Endpoint
  wiring is a `deployed=False` placeholder (the `<Connection>` subtrees are not modelled). Routing is
  not reverse-engineered (forwards to all handlers with a TODO). The optional
  `ide/src/corepointImport.ts` wrapper is still deferred.

## 5. What the 2026-07-24 reconciliation changed

| §2(a) assumed | The real export |
|---|---|
| JSON document | **XML** `<Package>` |
| flat `actions` array per handler | recursive `<List>` control-flow tree |
| `class` + typed fields per action | one markup-wrapped `@Data` **string** per element |
| ~71 action classes | **42 verbs**, 30 covering 99.4% |
| channel carries its own connector config | connection subtrees present but **not modelled** |
| no disabled/comment concept | `@Disabled` + `@Comment` on any element |

The parser was isolated exactly as §2(a) promised, so the reconciliation landed as a new input layer
plus a recursive generator — the intermediate model, the vocabulary mapping table, the count-and-log
accounting, the CLI, and the emitted-module contract are unchanged.
