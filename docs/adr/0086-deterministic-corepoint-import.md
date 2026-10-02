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
an action the export never had. *Amended 2026-10-02 (§2(b.4)):* a label that is itself a statement
also gets a counted TODO marker.

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

**(b″) AMENDMENT 2026-09-30 — a `MsgSend` of a handle that is not `msg` raises (BACKLOG #313, step
1).** A Handler has one `msg`, the inbound message. An action-list can build and send another tree.
The importer rendered that send as `Send(dest, msg)`, which delivers the unmodified input in place of
the message Corepoint built.

A role-parsed `MsgSend` now sends only when its handle is the list's single input handle, or a
whole-tree clone of it that nothing else overwrites. Anything else renders as a TODO marker and
`raise NotImplementedError(...)` at the send site: another handle, a `$variable`, a partial path, or
no handle. A `Try` whose body holds such a raise gains an `except NotImplementedError: raise` arm
ahead of its `Catch` arms, so a `Catch` cannot swallow it. The destination stays declared and the
handler keeps its `sends` list, so the handler neither filters silently nor gains a trailing `Send`.
`messagefoundry check` reports that outbound as unreferenced until someone finishes the send, which
is accurate. The summary counts the statement as unmapped.

Field writes map onto `msg` only for the one handle the list delivers. A list that delivers two
different handles maps no field write at all.

At least these gaps remain:

- A markup-free `MsgSend` carries no handle role, so it renders as before.
- The handle scan does not see statement order or branches. A send that runs before its clone is
  made, or a clone made on one branch only, still counts as `msg`.

Building the other tree, and the flow the scan cannot see, is step 2 of #313.

**(b‴) AMENDMENT 2026-09-30, REVISED 2026-10-01 — each handle becomes a Python local, in a fully
understood list only (BACKLOG #313, step 2).** The owner ruled on 2026-09-26 for an importer-only fix:
no engine change and no change to ADR 0001. A Handler can already build and send a second `Message`
(`samples/config/IB_RADIOLOGY_SR.py` does).

**The whole-list gate (Manager decision, 2026-10-01).** Before a list renders, the importer decides
once whether the WHOLE list is fully understood. It is only when every element in it, at every
depth, is on this allow-list, and each statement's `@Data` is exactly the canonical spelling of its
verb's one shape, character for character:

| Element | The one shape it is read in |
|---|---|
| `MsgTreeCopy` (a plain clone) | keyword verb, handle, path `/`, the word `to`, handle, path `/` |
| `MsgCreate` | keyword verb, handle, `as`, a caret-form type literal, `version`, a `2.x` or `2.x.y` literal |
| `ItemCopy`, `ItemAppend` | keyword verb, a quoted value, `to`, handle, a writable HL7 field path |
| `ItemClear` | keyword verb, handle, a writable HL7 field path |
| `MsgLog` | keyword verb, one handle |
| `MsgSend` | keyword verb, one handle, `to connection`, a non-blank destination literal |
| `<Block>` | no label: `@Data` absent or empty |
| a surely disabled step | a `<Line>` or `<Block>` above with `@Disabled` of `1`, `true` or `yes` |
| `<List>` | no attribute; flattened |

Each statement is a `<Line>` whose only attribute is `@Data`. The verb is a `keyword` span spelled
exactly so, and connectives are unstyled words. The canonical spelling quotes each span class with
`'`, puts one space between tokens, and puts a path span directly after its handle span; any other
spacing, quoting or adjacency is not understood. A written value is printable ASCII with no `"`,
`&`, `<`, `>` or HL7 delimiter (`|`, `^`, `~`, `\`). A handle is an `input-handle` or `other-handle`
span matching `%` plus up to 40 ASCII letters, digits and underscores. A field path is `/SEG-F`,
optionally with up to two more `-n` coordinates, on a single-occurrence segment and never MSH-1 or
MSH-2. A `(...)` annotation after it may carry a mode or a repetition, and no export is known to
write the dotted form, so neither is understood. A `<Block>` label is never read: whether Corepoint
runs a label that is a statement is not known, and no word list tells prose from a verb. Spans
carry only plain text: no nesting, no entity, no attribute but `class`. Across the list, no two
handle spellings may differ only in case, each handle carries one span class everywhere, there is
at most one input handle, and no clone or `MsgCreate` writes the input. The list's own tag is
exactly `ActionList`, every element enclosing it is a `<Package>`, and the list and each of those
carry only `Name` and `Desc`. In the list and around it, tags are matched exactly, so a namespaced
or differently cased tag is not understood. A
list nested more than 25 `<List>` and `<Block>` levels deep is not understood either, so a depth
step 1 refuses is refused the same way.

**In a package that may call any list, no list is fully understood.** A called list runs when and
as often as its caller runs it. The router forwards to every handler, so it cannot express that.
The call check asks one question of every element in the file: may it call a list? It may when its
tag is `Call`. That one tag is read as step 1 reads it, on the local name and in any case. It may
also when any string it holds names a call verb. Every string is read: the tag, each attribute's
name and value, and the text in and after the element. Each string is read three ways: raw, with
the markup stripped, and span by span with the markup stripped. The last two are how step 1 takes a
verb from `@Data`. Only the letters `a` to `z` count, after lower-casing, so `Action_List_Call`
and the `action-list-call-pass` span class name a call too. A string on an element that only
mentions a call closes the gate as well. The check does not see an XML comment or a processing
instruction, because the parser drops both, for step 1 too.

**Closing the gate is not free.** Every list in that package then renders as step 1 renders it,
with the gaps *The cost* names below. A list the open gate would refuse at a send may send `msg`
there under step 1. So a mention costs more than a hand-finish. The check is eager all the same: a
called list sent for every message is the worse error, and step 1's gaps are known and recorded.

**No construct is on the list:** no `If`, `ElseIf`, `Else`, `Case`, `ChooseFrom`, `Matching`,
`ForEach`, `Loop`, `While`, `Try`, `Catch`, `Call`, `ActionListExit` or other exit, and no
unmodelled element, anywhere in the list. At least these also make the list NOT fully understood:
a lowercase or variant verb, a `description`, `comment` or `detail` span on a statement line, any
attribute but the ones above (`Enabled`, `Comment`, unknown names), a markup-free statement, a path
such as `//ADT`, a path annotation, and any `<Block>` label. When in doubt, it is not.
*Corrected 2026-10-01 (code review of the gate, round 2):* a `<Block>` with a prose label, a path
with a `(...)` annotation, a dotted path, a list another list calls, and a list nested in another
list's construct each opened the gate. A label such as `While x` or a path such as
`/PID-8 (replace all)` passed the word rules, and a called sub-list became a handler that built and
sent its message for every inbound message.
*Corrected 2026-10-01 (Lander QA on f0a62ef70a):* the call check read only the raw attribute
value. So `ActionList&#67;all`, `ActionList&#x43;all` and `ActionList<b></b>Call` each left the gate
open while step 1 read a call. A sub-list called under an `If` then sent its message for every
inbound message, where step 1 raises. The whole value stripped is not enough alone: after an
unclosed `&#x`, the whole value loses the verb and only the span still holds it. The code review of
that repair widened the check twice more: from attribute values to every string, and from the
verb's spelling to its letters. A call named by an element tag, an attribute name, element text or
a call-marking span class had left the gate open, though step 1 reads none of those as a call. The
same audit found the list's own tag was not matched exactly, so `<actionlist>` and a namespaced
`<q:ActionList>` were understood. No wrong delivery is known from that. The gate now refuses both.

**A list that is not fully understood renders exactly as step 1 renders it,** byte for byte, with the
same summary counts: the importer runs step 1's code path on it, untouched, so there is no partial
binding. The gaps (b″) names stay as they are for such a list.

**In a fully understood list,** the importer walks the statements in order:

| Corepoint statement | Generated Python | When |
|---|---|---|
| the input handle | `msg` | the list's one `input-handle` |
| `MsgTreeCopy <src>/ to <dst>/` | `<dst>_msg = <src local>.copy()` | `<src>` holds a local here; else a TODO, and `<dst>` is unknown |
| `MsgCreate <handle> as "ADT^A04" version "2.5.1"` | `<handle>_msg = Message.parse("MSH\|^~\\&\|...")` | always (the gate checked the type and version) |
| `ItemCopy`/`ItemClear`/`ItemAppend` on `<handle>/path` | `set_field(<local>, ...)` | `<handle>` holds a local here; else a TODO |
| `MsgSend <handle>` | `sends.append(Send(dest, <local>))` | `<handle>` holds a local here; else the step 1 raise |

Each local is the handle's name, lower-cased, without the `%`, suffixed `_msg`. The skeleton holds
the default encoding characters, the type in MSH-9 and the version in MSH-12, and nothing else. It
is built through the `Message` API and emitted as one literal. A write to a built message maps only
onto its MSH; a write to another segment is a TODO, because `Message.set` raises on a segment the
skeleton lacks. **A write to a handle after a send of it is a TODO,** because a `Send` holds the
object, so the write would otherwise change the message already sent. `[pipeline].snapshot_on_send`
(ADR 0104) defaults to on in service settings and would snapshot it, but it can be turned off and a
handler called directly holds the live object, so the importer does not rely on it. That was the
one fail-open of round 3 inside the open gate. **Any write the binder declines leaves its handle
unknown from there,** so a later send of it raises rather than deliver the message without the
write. *Corrected 2026-10-01 (code review of the gate):* a declined write to a built message's
non-MSH segment kept the handle, and its send delivered the bare skeleton where step 1 raised.

**The cost.** Any list holding a construct, or anything the gate does not read, is finished by hand
exactly as under step 1. Step 1's gaps stay with such a list: a send of a clone may still send `msg`
where its flow-insensitive scan holds the clone, and a write to the input after a send of it still
lands on `msg`, which only `snapshot_on_send` keeps out of the sent message. Step 2 helps only
straight-line lists, and the canonical-spelling rule is strict: an export whose labels are wrapped in
spans, or whose spacing differs at all, gets no help. That is deliberate.

**History: why a gate, after six rounds.** Step 2 first walked every construct, tracking which local
each handle held on each path and joining the paths. Each of six review rounds on PR 1900 built a
shape in which the handler sent a message Corepoint never sent, and most were introduced by the
previous round's repair: a call that stopped unbinding a handle it passed (9b8f13481); name matching
that missed `-`, `.`, non-ASCII and `%`-free handles (d401cdb5b); a branch that came loose from its
construct and ran for every message (d26545d6f, a HIGH); span classes trusted on a `ForEach` line
(db8873d19e); six shapes past the first narrowing; and seven past the second (6fa49a9d5): a loose
`Catch` or `Matching` line, an unread statement that never stopped binding, a lowercase verb label,
a write after a send, prose spans on `MsgTreeCopy` and `MsgCreate`, an unread attribute, and a
`//ADT` path. Each repair added a rule, and the rule set grew past what a reviewer could hold. The
gate replaces all of it with one question asked of the whole list, and deletes the join, loop, `Try`,
call scope, branch adoption and lost-scope machinery.

**The differential guard.** `tests/test_corepoint_import_differential.py` imports every shape of a
battery twice: with the head, and with the step 1 importer, vendored byte for byte from main at
`bca583f2a` and pinned by its git blob id (once step 2 merges, main is the head). It asserts the
gate's invariant directly. EITHER the head's module and summary counts equal step 1's byte for byte,
OR the guard's own allow-list walker, written apart from the importer and never calling its gate,
finds the list fully understood AND every oracle check passes. The oracle is an abstract interpreter
over the shape, in a case-sensitive and a case-insensitive reading of handle names. It says which
trees the export may send at each `MsgSend`, and which literals each tree held at the send. Both
handlers run against one synthetic input, past every refusal, and the guard fails when the head
renders a list step 1 refuses or refuses one step 1 renders, delivers a tree the oracle cannot
prove, sends `msg` for another handle, sends a message carrying a literal its tree did not hold at
the send or lacking one it did, lifts a send out of a branch, or binds a local below the handler's
level. Where the head differs from step 1, none of these checks exempts a send step 1 also makes,
so a write leaking into `msg` is caught too. The oracle applies `ItemCopy`, `ItemAppend` and
`ItemClear` to the field each names. The battery's shapes all sit in one package frame, so a
separate test checks 17 other frames. A list another list calls, before it or after it, by the verb
or by a `<Call>` tag in any case or namespace. A list nested in another list's construct. A root
that is no `<Package>`. An unread package attribute. A list tag in another case or in a namespace.
A call named, or a `<Call>` tag, outside every list. Each renders exactly as step 1. The walker
matches each
statement against one whole-string template per verb rather than walking tokens as the importer
does, so the two read the specification by different methods. *Amended 2026-10-02 (§2(b.4)):* the
guard now runs that vendored file plus one amendment made as it loads. The file itself is unchanged
and still pinned.

**A call the attribute does not spell** has its own tests in the same file. They write one character
of the verb as a character reference or behind a tag. They do so at every position, in ten ways, six
frames and five casings. A second arm writes several characters at once in 600 seeded values. Step
1's own parse of the package says which of them hide a call. The head's gate never says, and no list
of spellings does. Each hidden call must render exactly as step 1, with the called list after its
caller and before it. More tests carry a hidden call under a `data`, `DATA` or namespaced key and
as a `<Block>` label, and name a call in twelve ways step 1 reads no call from. A control holds a
reference and a tag in a verb that is no call, and the gate still opens.

Measured 2026-10-01: 4,050 single-character spellings and 560 of the 600 hide a call. These tests
and the package frames are 102 in all. With the importer at f0a62ef70a, 86 of them fail, on every
one of those spellings. Each of 22 mutation arms fails too. The count after each arm is how many of
the 102 tests fail.

| Mutation of the gate | Fails |
|---|---|
| no call rule at all | 95 |
| reads the raw value only | 75 |
| reads the raw and the whole value (misses 650 of the 4,050 and 91 of the 560) | 11 |
| reads the raw value and the spans (misses 675 and 82) | 25 |
| drops the raw reading | 3 |
| matches the spelling, not the letters | 5 |
| drops only `-` and `_` | 3 |
| reads attribute values only | 4 |
| reads the `Data` key only | 9 |
| reads values under a `data` key only, with every other string | 2 |
| drops the tag, the attribute names, the text or the tail | 1 each |
| reads elements inside lists only | 2 |
| reads the first list only | 84 |
| reads the last list only | 94 |
| reads `<Line>` elements only | 3 |
| matches the `Call` tag exactly | 3 |
| drops the `Call` tag | 5 |
| drops the ancestor rule | 3 |
| drops the list-tag rule | 2 |

The battery holds 7,787 shapes, measured 2026-10-01: 331 fixed seeds (every repro from every review
of PR 1900 and every Lander repro, the 23 round-3 shapes and the gate review's 41 among them), 4,056
ordered construct pairs, 1,000 random shapes and 2,400 drawn from the allow-list alone, a quarter of
those carrying one spoiler just off it. The guard's walker finds 1,686 fully understood, the head
binds a local in 1,088 of them, and the head's output differs from step 1 in 1,656. At this head it
fails none. Each mutation arm tried fails it. Measured in the first review round: dropping the
write-after-send rule (38 shapes), tolerating prose spans (68), folding verb case (33), ignoring
`Enabled` and `Comment` attributes (80), sending `msg` for an unknown handle (1,042), keeping a
handle after a declined write to its skeleton (21), tolerating whitespace (4), and dropping the
depth bound (3). In the second: accepting any `<Block>` label (2,312), accepting path annotations
and the dotted form (12), landing a write to an unbound handle on `msg` (180), rendering
`ItemAppend` as a set (4), and dropping `ItemClear` (2). The package-frame test fails on dropping
the call rule (11 of 17 frames), the ancestor rule (3 of 17) or the list-tag rule (2 of 17). Against
the previous head, 6fa49a9d5,
the first battery of 7,746 shapes failed 5,937, including 20 of the 23 round-3 seeds.

**Unverified assumptions, shared by the importer and the oracle.** At least these: that
`MsgTreeCopy %A/ to %B/` makes B a copy of A; that `MsgSend` leaves its handle holding the message it
sent; that a `<Block>` with no label runs its body once, in line; that a `@Disabled`
value of `1`, `true` or `yes` means the step never runs; that every caller of a list sits in the
same export file, which is all the call check reads, so a list exported apart from its caller is
read as never called; and that `MsgCreate` and `MsgSend` stamp no
header field the skeleton lacks, such as MSH-7, MSH-10 or MSH-11. If Corepoint stamps those, a built
message goes out without them, and the generated module does not flag it. Each was read from the
validated export, not measured in Corepoint.

**What the Steps lens shows.** `set_field(out_msg, ...)` projects as an `action` row that looks the
same as `set_field(msg, ...)`. The row carries no field naming the message it writes. A send row
lists only its outbound. The `.copy()` and `Message.parse(...)` lines are plain `code` rows. The
module still round-trips with no whole-file refusal, which AC-4 requires. Showing the receiver is a
follow-up for ADR 0076/0089.

**(b.4) AMENDMENT 2026-10-02 — a statement anywhere but on a `<Line>` is marked, never emitted, and
its list holds no handle (BACKLOG #2632).** A `<Block>`, `<Call>`, `<Case>`, `<Foreach>`, `<If>`,
`<Loop>` or `<Try>` can carry a statement in `@Data`, such as
`<Block Data="MsgTreeCopy %ADT/ to %OUT/">`. The render kept it only as label text, or as the text
of a dead condition, and counted nothing for it. The handle scan read its `MsgTreeCopy` as a clone
that was made. So a later send of `%OUT` rendered as a send of `msg`, with no marker anywhere. The
same held for an element whose tag the importer does not model, and for a `<List>` or `<Actions>`
wrapper, whose own `@Data` the render never read at all. A `MsgSend` in a Block's or a Call's
`@Data` rendered as a live send.

One function, `_label_statement`, now decides it for the render and the scan alike, for every
element that is not a `<Line>`. The `@Data` is a statement when the element does not render its verb
itself, and either:

- the verb, in any case, is one the importer reads on a `<Line>`: `ItemCopy`, `ItemClear`,
  `ItemAppend`, `MsgTreeCopy`, `MsgCreate`, `MsgLog` or `MsgSend`; or
- the element is a `<Block>` or a list wrapper and its `@Data` leads with a verb the exporter styled
  as a `keyword`. Neither has a verb of its own. A construct or a `<Call>` leads with its own
  keyword, which no table lists in full, and an unmodelled element may.

A container renders a control verb itself: its own construct, a call, an exit, a `LoopExit`. A
`MsgSend` is the exception, because it would deliver a message. So in a Block's or a Call's `@Data`
it is a statement too. It stays a send, and it is always refused: the handler raises where the
send stands, as it does for a send of a handle that is not `msg` (§2(b″)). Its body stays at the
element's own level, where a send's body always went. A `<Call>` carrying any other statement
renders as a plain label: it names no list, so it is not counted as a call. That label remembers
the kind it had, for the one test that reads it (below). *Corrected 2026-10-02 (the Lander's first
hold on PR 1938):* at first only a `MsgSend` made a Call a label, and a `<Call Data="MsgLog …">`
still counted as a mapped call. *Corrected again 2026-10-02 (the Lander's second hold):* a
`MsgSend` there was itself rendered as a plain label with a marker, which is quieter than main.
"Never quieter than main", below, has the rule. A `LoopExit` there still renders its `break`,
which only ever sits in a loop that is itself a dead placeholder.

Whether Corepoint runs such a statement is not known. So:

- The render emits a counted TODO for it, naming the statement, ahead of the element's body: after
  a Block's or a Call's label comment, before a construct's placeholder, and before a list wrapper's
  flattened statements. An unmodelled element is one counted marker already, so the statement is
  named in that marker and not counted twice.
- A marker never changes the shape of the tree. Which construct holds which branch, which
  branch marker opens a branch, and which element is a branch-group are all decided as they are
  with every marker taken out. An orphaned branch renders its body live, so this is what keeps a
  marker from turning dead code into live code. The marker is its own step type, `LabelMarker`,
  which stands for no statement position of the export. At least three places decide shape, and
  each leaves it out:
  - `_parse_list` holds a marker back from its list until a statement position follows it. So
    the one rule that adopts a sibling branch, `_adopt_branch`, never finds a marker as the step
    before a branch, and the marker follows the whole chain. That holds at any depth of wrapper,
    and wherever a flattened body leaves a marker last: a wrapper nested in another, a
    branch-group `<If>`, a `<Line>` carrying a list.
  - `_split_branches` opens a branch at a branch marker that holds no statement of its own. A
    label marker is none, so `<Line Data="Catch"><List Data="MsgLog …"/></Line>` still opens its
    branch, and the label marker leads it.
  - The branch-group test reads the kind a label had before it was demoted from a call
    (`Control.demoted_from`). So a demoted label makes no group appear and none go. A send in
    a Block's or a Call's `@Data` is a send still, so it needs no such memory.

  Among the steps that are not adopted, every marker stays where its element sat, in source
  order. *Corrected 2026-10-02, three times.* The first cut let the sibling adoption see the
  marker as a step, and an `Else` after such a wrapper ran for every message (code review, round
  2). The second moved a wrapper's marker ahead of the step before it, by looking one step back
  in one call. A wrapper nested in another starts a new call, so its marker orphaned the branch
  again (the Lander's hold on PR 1938). The third repaired the sibling adoption alone. Code
  review of it found the other two places above, each with a branch main keeps dead that
  rendered live. Moving one marker, and then guarding one test, were both too narrow. The rule
  is now stated for the whole tree, and a test compares that tree with main's.
- A send in a Block's or a Call's `@Data` is no marker. It is a refused send, in the tree where
  main's send is. So
  it selects the handler's `sends` list exactly where main's send does. That matters: a handler
  with no send the render reaches ends on a `return Send(...)` for every destination in its tree,
  rendered or not. *Corrected 2026-10-02 (code review of the repair, round 2):* an earlier cut
  took the send out of the tree, and a send the render never reaches was then delivered for every
  message. The last limit below says where such a send comes from.
- Nothing is mapped for it, and it is never emitted as a write or a delivery.
- The scan holds no handle for the whole list. Every role-parsed send the render reaches raises,
  and no role-parsed field write maps onto `msg`. So a clone or a send counts only on a `<Line>`.

That fails toward the visible side: a clone such a statement names is never treated as made, and an
overwrite it names is never ignored. The scan is never more permissive than it was.

**Never quieter than main.** This is the rule for the whole amendment. It is written out because
each round of review on PR 1938 found one more list on which the branch did worse than main: a
branch main keeps dead rendered live, and then a refusal became a silent filter. For every list,
against main's step 1 tree:

- **(a)** The head adds no live send, inline or in a closing `return`, and no vocabulary call.
- **(b)** Where main sends or refuses, the head sends or refuses. No `raise NotImplementedError`
  goes, at any depth, and no send becomes a comment. A handler ends on the closing `return` main
  gives it. So one that main ends on the `return None` that says no destination was named never
  ends on a bare `return sends`.
- **(c)** What main counted unmapped is still counted. What main marked `# TODO` is still marked.

Louder is allowed, and it is all this amendment does: a delivery becomes a refusal, and a mapped
step becomes a counted TODO. Quieter is the defect. A refusal sends the message to ERROR, where an
operator sees it. A handler that returns nothing sends it to FILTERED, and nobody is told.

*Corrected 2026-10-02 (the Lander's second hold on PR 1938).* A `MsgSend` in a Block's or a Call's
`@Data` was rendered as a label and a comment. main refuses that send when its handle is not
`msg`, so main's handler raises. The branch returned an empty list in its place. The same cut gave
a send that names no destination a `sends` list, so its handler ended on `return sends` where main
ends on the marked `return None`. One rule repairs both: such a send is the send main made of it,
and it is refused. Its destination stays declared for the hand-finish. The handler ends as main
ends it. A `try` around it re-raises ahead of every Catch. It counts unmapped once. Where main
delivered that send, the head now raises. That is louder, and on purpose: the statement may never
have run, so it is no delivery, and it is no silent filter either.

The whole-list gate is unchanged and stays closed for such a list. It admits a `<Block>` only with
no label, a `<List>` only with no attribute, and no construct or other tag at all. Prose stays a
label: `<Block Data="Patient identity">` renders as before.

At least these limits remain:

- The verb is read as a `<Line>`'s is: the first `keyword` span, or with none, the first word. So a
  table verb after other unstyled words, such as `Step 1: MsgTreeCopy ...`, still reads as a
  label. So does a verb outside the table with no leading `keyword` span, and one in a
  construct's, a Call's or an unmodelled element's `@Data`, styled or not. No word list tells
  prose from every verb.
- The rule is blunt on purpose. Any table verb off a `<Line>`, a `MsgLog` included, leaves the
  whole list holding no handle, so its role-parsed sends raise until someone finishes them.
- A `<Block>` label that merely leads with a word the exporter styled as a `keyword` is read as a
  statement. So is the `@Data` of a list wrapper that leads with one. How often a real label does
  that was not measured: the validated export is not in this repository.
- The marker and the statement share one 200-character comment, so a statement longer than about
  90 characters is cut. Under a `@Disabled` ancestor the preview shows only the verb.
- A statement with no role markup names no handle the scan can read. So a markup-free write still
  maps onto `msg` and a markup-free send still sends it, in such a list as in any other (§2(b″)).
  The same holds for a markup-free `MsgTreeCopy` on a `<Line>`.
- The refusal at a send on a `<Line>`, and the reason on a declined write, still name the two
  older causes: no single input handle, or an overwritten input. The marker carries the true one.
  A send in a Block's or a Call's `@Data` names its own cause in its refusal.
- A construct carrying a statement counts twice: once as the construct, as before, and once
  unmapped for the statement. A `<Call>` carrying one counts once, for the statement. A send in
  a Block's or a Call's `@Data` counts once, as the refusal it is.
- A wrapper that holds a statement of its own, between a construct and its sibling branch, orphans
  that branch. main does the same whatever the wrapper's `@Data`, and this amendment leaves it as
  it found it. `test_a_wrappers_marker_changes_nothing_where_main_already_orphans` pins that.
- Where main never renders an element, this amendment does not either. main keeps a branch held
  by another branch in the tree, and neither renders it nor counts it. A statement off a `<Line>`
  in there gets no marker and no count, as nothing in there gets one. A send in there is still
  collected as a destination. A handler with no send the render reaches then delivers to it in
  its closing `return`, role-marked or not. That is main's defect and it is not repaired here.
  It is where "every role-parsed send in the list raises" does not hold. One list that shows it:
  a `<Loop Data="Catch">` holding a `<Call Data="ElseIf (y)">`, which holds `<Line Data="Else"/>`
  and a `MsgSend`. main and the head both end that handler on `return Send(...)` and count one
  step.

The differential guard compares a gate-declined list with step 1. That step 1 path now carries this
rule. So the guard runs the vendored step 1 file with one amendment made as it loads. The file
itself stays as vendored and pinned. The amendment is listed in the guard's `_STEP1_AMENDMENTS`, with
the rule copied as text, so a later change to the head's rule turns the guard red until the copy is
amended on purpose. Two more tests run the battery against the file exactly as vendored. They check
that the amendment changes only lists that may carry a statement off a `<Line>`, by a wider reading
written apart from the rule. Where it changes a list it must only narrow: no new live send, no new
vocabulary call, and one more unmapped step, or else only comment lines and refusals change. A
live send is read inline and in the handler's closing `return`. *Corrected 2026-10-02 (code review
of the repair, round 2):* the bound read the inline form alone, so it could not see a closing
`return Send(...)` that the amendment added.

The bound now also checks clauses (b) and (c) of "Never quieter than main". It reads every send
and every refusal of the handler, by depth and by destination. A refusal of a send stands for
that send. None may go. A `try` that holds a refusal must open on the guard that re-raises it,
or the Catch would swallow it. The closing `return` must be main's line. Every name main counted
unmapped must still be counted. Every `# TODO` main writes must still be written, at its depth
and naming the same word. Depth stands in for "runs": a line one level in sits under a dead
placeholder, or in a `try`. The shape test is what keeps a line from moving between those two.
*Corrected 2026-10-02 (code review of this repair):* the first cut counted lines by depth
alone, so a send that went could hide behind a refusal gained elsewhere at the same depth.
At least one limit remains: the unmapped names are compared as a set of counts, so a name main
counted can go unseen where the amendment adds a marker of the same name.

It holds the head to the same bound, against the same vendored file, wherever the
gate is closed. And `test_no_raw_list_is_quieter_than_main` runs it over the 4,000 lists drawn
with no grammar, which the next paragraphs describe. *Corrected 2026-10-02 (the Lander's second
hold):* the bound checked none of that and read the battery alone. Every seed put a send main
DELIVERS where a label belongs, so no shape it read held a refusal that could go.
`test_the_bound_sees_a_refusal_turned_into_a_quiet_filter` is the control: it renders a send off
a `<Line>` as a comment once more, and the bound must then be red.
`test_the_bound_sees_each_mutant_of_the_ending_and_the_guard` breaks the closing `return` and
the guard in turn, and the bound must be red on the seed written for each.

That bound is what catches a rule that is wrong in the head and in its copy alike, where the
head-equals-baseline check is blind. It missed the wrapper defect twice, each time for want of a
seed. At first no seed put a wrapper between a construct and a sibling branch. Eight seeds then
did, each with one wrapper, and the bound stayed green on a wrapper nested in another. The seeds
now also nest the wrapper to a depth of two and three, with the statement on the inner wrapper,
the outer, or each, with and without a statement inside, for each of the four branch kinds. They
end a branch-group, a `<Line>`'s list and a wrapper around the construct with such a wrapper, and
they put a send label over a construct. After code review of the repair they also put a marked
wrapper inside a bare branch marker, and a demoted label inside a bare `<Call>` and a bare
`<Block>`.

Seeds cover only the routes someone thought of, and three reviews in a row found one nobody had.
So a second test states the rule for the whole tree and draws shapes of its own.
`test_no_branch_main_adopts_is_orphaned` parses a list with the vendored file as it is, with the
amended baseline and with the head. It compares the shape of the three trees: every construct
with its body and its branches, label markers left out, a demoted label read as the kind it had.
The shapes must be equal. The head is held to that wherever the gate is closed. The test runs
over the battery, and over 4,000 lists drawn with no grammar: any tag, any `@Data` from a pool of
statements, conditions and branch verbs, nested four deep. Three of the statements carry role
markup, one element in ten is `@Disabled`, and one in ten has a `@Comment`. The bound sees an
orphan only through a live send or a vocabulary call in its body. This test needs neither. It is
still a sample, with one casing per tag and a small pool. It shows no difference on the lists it
draws, not that none exists.

Measured 2026-10-02 at the repaired head. The battery holds 8,083 shapes, 627 of them fixed seeds,
and the amendment changes 761. The repair added 115 seeds. Each row puts part of the repair back
and counts the lists that fail. "Head alone" changes the head only, which the
head-equals-baseline check sees. "Both" changes the head and the baseline copy alike, which that
check cannot see. The shape test is counted on the battery and on its 4,000 raw lists.

| What is put back | Head alone | Both: the bound | Both: shape, battery | Both: shape, raw |
|---|---|---|---|---|
| the whole repair, so the rule at `880f431d94` | 121 | 52 | 53 | 178 |
| a sibling adoption sees a marker as a step | 70 | 70 | 70 | 5 |
| the same, and a wrapper moves its marker one step back (round 2) | 86 | 43 | 43 | 0 |
| a branch marker holding a label marker opens no branch | 4 | 1 | 4 | 7 |
| the branch-group test reads the rendered kind | 12 | 12 | 12 | 13 |
| a send label nests its body | 2 | 2 | 2 | 169 |
| a demoted send label no longer selects the `sends` list | 2 | 2 | 0 | 0 |
| a `<Call>` carrying a statement stays a call | 23 | 0 | 0 | 0 |

With the repair in place every count is zero. Two rows show what each check cannot see. A send
label that drops the `sends` list changes no shape, so the shape test cannot see it. The bound
sees it, on the two seeds written for it, and so does the unit test
`test_demoting_a_handlers_only_visible_send_adds_no_trailing_send`. *Corrected 2026-10-02 (the
Lander's second hold):* this said only the bound saw it. A Call that stays a call changes no
shape and adds no live code on these lists: with the kind remembered, it only counts a label as
a mapped call, so only the head-equals-baseline check and a unit test see it. Both are readings
of this battery, not proofs about the change.

The two rows about a send label were measured before the second repair, when a send off a
`<Line>` was a label. It is a refused send now, so neither mutation exists as written.

Measured 2026-10-02 at the second repair. The battery holds 8,095 shapes. Twelve are new seeds,
on a `<Block>` and on a `<Call>`: a send off a `<Line>` that main refuses, alone, beside another
send and in a `Try` with a Catch; a send naming no destination, with role markup and without;
and a send main delivers, in a `Try` with a Catch. The amendment changes 773 battery shapes and
2,929 of the 4,000 raw lists. "Put back" restores the
earlier rule, a send off a `<Line>` rendered as a label and a marker, in the head and in the
baseline copy alike.

| | Battery, of 8,095 | Raw lists, of 4,000 |
|---|---|---|
| The bound is red, with the earlier rule put back | 22 | 429 |
| The same, counting refusals alone and not sends | 8 | 128 |
| The bound is red, with the repair in place | 0 | 0 |

The second row is the first cut of this check, which counted only the refusals, over the ten
seeds it then had. All 8 of its battery shapes are new seeds. So a lost refusal could not show on
the 8,083 older shapes by any check, and it showed on the raw lists once the bound read them.
Counting sends too adds ten older seeds, where main delivers the send and the earlier rule left
a comment. Of the 22, twelve are new seeds and ten are older. This is still a sample. It shows
no quieter list among those it draws, not that none exists.

The measurement below is older. It was taken the same day at `880f431d94`, before the repair, and
was not run again. The battery then held 7,968 shapes, 512 of them fixed seeds. The 181 seeds new
at that head put a statement on each of the seven container tags, an unmodelled tag and a list
wrapper: a clone, a write, a send, a styled verb outside the table, and each of the seven verbs
with no markup in two casings. The amendment changed 646 shapes, marked a live statement in 623
and dropped a live send in 513. The head equalled the amended baseline on every shape. Each
mutation arm of the head failed the guard, counted in shapes. The row "a wrapper's marker sits
where the wrapper sat" was the first cut put back, where the adoption saw the marker. The marker
does sit there now, and the adoption never sees it.

| Mutation of the head | Shapes failing |
|---|---|
| no rule at all | 646 |
| the scan ignores the rule, so the render marks only | 557 |
| the render ignores the rule, so the scan holds nothing and nothing is marked | 646 |
| a construct drops its marker | 90 |
| a `<Block>` or a `<Call>` drops its marker | 511 |
| a list wrapper drops its marker | 27 |
| a wrapper's marker sits where the wrapper sat | 8 |
| an unmodelled tag does not name the statement | 18 |
| the rule reaches the seven container tags only | 45 |
| a send in a `<Block>` or a `<Call>` stays a live send | 6 |
| a `<Call>` carrying a send still renders as a call | 3 |
| the table loses `msgtreecopy` | 230 |
| the table loses `msgcreate` | 18 |
| the verb is matched in its usual case only | 91 |
| the keyword reading is dropped | 2 |
| the keyword reading is a `<Block>`'s alone | 1 |
| the keyword reading reaches every element | 7 |
| the keyword need not lead the `@Data` | 1 |
| the marker leaves the statement out | 623 |
| the gate admits a `<Block>` with a label | 248 |

### (c) Unmapped actions are never silently dropped (count-and-log)

An action whose `class` has no v1 mapping emits, **in place**, an
`# TODO: Corepoint <ActionClass> — hand-finish` marker plus a best-effort field-preserving
`msg.set(<target>, msg.field(<target>) or "")` passthrough stub when a target field is recoverable.
The import summary counts mapped vs. unmapped actions per channel (the count-and-log ethos, CLAUDE.md
§1). In the lens round-trip the stub degrades to a single in-place `code` row — never a whole-file
refusal.

**(c″) AMENDMENT 2026-09-16 — the passthrough stub is withdrawn; an unmapped action emits NO live
code (BACKLOG #1681).** The paragraph above is kept as written, because the stub shipped and a reader
needs to recognise the line in a module generated before this date. Two sentences of it no longer
describe the code: the `msg.set(<target>, msg.field(<target>) or "")` stub is gone from every input
layer, and with it the `code` row it contributed (the bare marker still classifies as one, so AC-4 is
unchanged).

The stub was not the inert passthrough its name claimed. `Message.set` **raises `KeyError`** on an
absent segment, and on a present segment with an absent field it **materialises** that field and its
empty components on the wire — so a line whose only job was to stay visible could dead-letter the
message or change it. A generated handler carrying one would, on first deployment, dead-letter every
message lacking the target segment and pad the segment of every message that has it. The validated
role-parsed path (`_decline`) had already withdrawn it on those grounds; this amendment finishes the
job on the two paths that had not — `_map_action` (the superseded JSON layer, §2(a)) and
`_map_statement` (the fallback for an export whose `@Data` carries no span markup).

**The recovered target is not lost — it rides into the marker text** as `; intended target <path>`, so
the hand-finish still sees which field the source action meant. That move is what makes the value a
*comment* problem rather than a *literal* problem, and the two escapes are not interchangeable: a
`_lit` literal contains a newline by escaping it, while a comment simply ends at one. So on the JSON
layer both the action class and the recovered target — neither of which has been through any grammar —
are flattened through `_comment_text` before they enter the marker (BACKLOG #1683), which also deletes
the control characters that would otherwise make the module uncompilable.

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
  `# TODO: Corepoint …` marker naming the intended target field when one is recoverable, SHALL emit no
  live code for it (amendment (c″)), and SHALL count it — never drop it silently.
  → `tests/test_corepoint_import.py::test_unmapped_action_is_marked_not_dropped`
- **AC-3 (check gate)** — the emitted modules SHALL pass `messagefoundry check` (validate leg).
  → `tests/test_corepoint_import.py::test_generated_module_passes_check`
- **AC-4 (lens round-trip)** — every emitted `@handler` SHALL classify through `lens parse` into typed
  rows with no whole-file refusal; mapped calls become `action`/`lookup` rows, the `return` a `send` row.
  → `tests/test_lens_parse.py::test_generated_handler_round_trips_through_lens`
- **AC-5 (untrusted input)** — a hostile value (quotes/newlines/backslashes) SHALL ride across as an
  inert literal, never injected code; a hostile value bound for a **comment** SHALL be flattened to one
  line with its non-whitespace control characters deleted; a value JSON can render but Python cannot
  read back (`null`/`true`/`false`, a non-finite number, an unpaired surrogate) SHALL raise
  `CorepointImportError` rather than be written into a module that fails at import or at encode
  (amendment (c″), BACKLOG #1683); a malformed export SHALL raise `CorepointImportError`, not a
  traceback. → `tests/test_corepoint_import.py::test_hostile_values_are_escaped_not_injected`,
  `::test_an_unmapped_actions_recovered_target_cannot_escape_its_comment`,
  `::test_a_nul_in_an_action_class_cannot_make_the_module_uncompilable`,
  `::test_a_json_scalar_python_cannot_read_is_refused_not_rendered`,
  `::test_an_unpaired_surrogate_is_refused_before_it_reaches_the_file`,
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
- **AC-6g (a statement off a `<Line>`, amendment 2026-10-02)** — an element other than a `<Line>`
  whose `@Data` is a statement (§2(b.4)) SHALL emit a counted TODO naming it, SHALL emit no
  write and no delivery for it, and its list SHALL hold no handle as `msg`; a prose label SHALL
  stay a comment. A `MsgSend` in a Block's or a Call's `@Data` SHALL be a refused send, which
  raises. The marker SHALL NOT
  change the shape of the tree: which construct holds which branch. The head SHALL be no quieter
  than main on any list: no refusal, marked ending, unmapped count or TODO main has SHALL go.
  → `::test_a_clone_where_a_label_belongs_is_marked_and_its_send_is_judged_on_the_marker`,
  `::test_a_send_in_a_block_label_is_never_a_delivery`,
  `::test_a_send_off_a_line_is_refused_aloud_and_never_filters_in_silence`,
  `::test_a_send_off_a_line_naming_no_destination_keeps_mains_loud_ending`,
  `::test_a_catch_never_swallows_the_refusal_of_a_send_off_a_line`,
  `::test_a_prose_block_label_stays_a_label`, `::test_the_scan_and_the_render_ask_one_rule`,
  `::test_a_wrappers_marker_never_orphans_a_sibling_branch`,
  `::test_a_marker_at_the_end_of_any_flattened_body_never_orphans_a_branch`,
  `::test_a_branch_marker_holding_only_a_marked_wrapper_still_opens_its_branch`,
  `::test_a_demoted_label_changes_no_shape_around_it`

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
