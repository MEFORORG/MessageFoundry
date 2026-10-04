# 0206 -- An HL7 write or re-encode never lets data become structure

- **Status:** Accepted (2026-10-02, on build; decision delegated by the owner under the driver rule and taken by the batch 186 Manager; the owner may overrule at review)
- **Date:** 2026-10-02
- **Related:** vault BACKLOG #2558 (a decoded leaf copied into a whole field), #2559 (the outbound
  delimiter override), #2560 (a second `MSH` in one body), #2557 and
  [ADR 0205](0205-an-outbound-frame-holds-exactly-one-message.md) (the same family, for frame bytes),
  [ADR 0204](0204-a-delivery-the-message-itself-makes-impossible-uses-the-permanent-failure-class.md) (the permanent failure class), [ADR 0054](0054-low-allocation-builtins-hl7-parser.md)
  (the built-in tolerant parser), [ADR 0076](0076-typed-action-vocabulary-action-list-lens.md) (the
  typed action vocabulary), [ADR 0089](0089-recognition-first-lens-native-idioms.md) (the lens's
  native idioms), [ADR 0144](0144-security-lint-gate-over-admin-authored-router-handler-config.md) (the advisory handler-security lint),
  CLAUDE.md section 2 (the count-and-log invariant)

Built with the change, in the same pull request. The engine repository is public, and this record
describes defects in the shipped code, so it lands with its fix rather than ahead of it. With zero
deployments (CLAUDE.md section 0), nothing below is a live exposure: each defect is what a deploying
site would have hit.

---

## Context

The injection audit of 2026-10-01 found three paths by which a value the sender wrote would become
structure a downstream receiver parses. Its probes P5, P3 and P6 reproduce them.

1. **A decoded leaf copied into a whole field (#2558).** `copy_field` read with `msg.field(src)`,
   which unescapes a component or subcomponent, and wrote with `msg.set(dst, ...)`. A whole-field
   `set` takes its text as the caller's structure. So escaped component, repetition and
   subcomponent separators in the source became live ones: P5's copy to `PV1-19` gave two
   repetitions and a second component. The function's docstring said the write escapes.
   `split_field` had the same branch, and a Handler writing `msg.set(field, msg.field(leaf))` by
   hand has it too.
2. **The outbound delimiter override (#2559).** `encode_with_separators` mapped the source
   separators to an MLLP outbound's `encoding_characters` and carried a target delimiter that sat
   literally in a leaf as it was. The sender chooses the source separators, so it can make any target
   delimiter plain data on the way in. P3 declared `#` as the field separator and put a literal `|`
   in a name: the engine saw one `PID-5`, and the downstream parse gave three fields.
3. **A second `MSH` in one body (#2560).** `parse` accepts a later `MSH` line. On a source that
   hands one body over as one message, the Router sees one message with one control id, and a
   receiver that splits on `MSH` would see two. P6 parsed one body as `MSH, PID, MSH, PID` with
   control id `CTRL1`.

`Message.set` is correct by its own contract. The fault is in callers that pass a decoded leaf as if
it were authored structure, and in a re-encode and an intake that never asked whether a character was
data. The invariant at stake, from [CLAUDE.md](../../CLAUDE.md) section 2, verbatim:

> **Count-and-log invariant (do not break):** **every received message is persisted before the ACK**
> (status `RECEIVED` at the ingress stage), so inbound counts still reflect the true received volume
> and nothing is accepted-and-dropped.

A second message inside one body has no disposition of its own; the first two paths let a sender set
fields the Router and Handler never saw.

## Decision

**A value read from a message stays data wherever it is written or re-encoded, and one body is one
message on a source that does not split.** Five rules, as the accepted draft wrote them, with its
open points settled below.

1. **A decoded leaf is data at every destination level.** `Message` gains `set_data(path, value)`,
   the write that says the caller means data. At a whole-field path it escapes the value as one leaf
   (the separators, the escape character, and the control characters ADR 0205 rule 2 names) and then
   writes it, so it lands as the first component and reads back unchanged. At a component or
   subcomponent path it is exactly `set`. `copy_field` and `split_field` use `set_data` when the
   source path is a component or subcomponent, and `set` when it is a whole field.
2. **A whole-field `set` with author-supplied text keeps today's meaning.** `msg.set("PV1-19", "A^B")`
   still writes two components. A whole-field copy of a whole field still copies raw text, structure
   and all.
3. **The hand-written form is named as unsafe.** The user guide's *The `Message` operations you'll
   use* section says to write a value read from a message with `set_data`, and why. The advisory
   handler-security lint (`_check_handler_security` in `messagefoundry/checks.py`, ADR 0144) gains a
   sixth rule, `leaf-to-whole-field`. It flags a `<name>.set("<field>", v)` call or a
   `<name>["<field>"] = v` assignment whose value a `<name>.field("<leaf>")` call or a
   `<name>["<leaf>"]` read flows into, directly or through a name bound in the same scope. Both paths
   must be string literals for the AST to know their level. It is advisory, as the lint is.
4. **`encode_with_separators` keeps every leaf reading the same under the target set.** A target
   delimiter sitting literally in a leaf is escaped with the target escape character: the target
   field, component, repetition, subcomponent and escape characters become `F`, `S`, `R`, `T` and
   `E` escapes. A separator escape (`F`, `S`, `R`, `T`, `E`) is decoded against the source set and
   re-escaped against the target set, because its letter names a different character there. An
   escape character nothing closes is data, as the parser reads it, so it and the text after it are
   written as data under the target set. Any other escape sequence keeps its text under the target
   escape character. Two values the target set cannot represent raise `DelimiterRewriteRefused`: an
   escape sequence other than the five separator escapes whose text holds a target delimiter, and a
   segment id holding the target field separator. The MLLP override raises it as
   `NegativeAckError(permanent=True)`, code `reencode`, so the delivery fails at once.
5. **A source that does not split refuses a body with more than one `MSH`.** The check sits in
   `check_decoded`, the shared post-decode guard, as `IngressMultipleMessagesRejected`, an
   `IngressBodyRejected` like ADR 0205's frame-byte refusal. The MLLP, TCP and HTTP listeners record
   `ERROR`; a listener with an ACK channel answers `AR` with MSA-3 `more than one MSH in body`. The
   dry-run runs the same guard, so it refuses the same body. The resubmission paths run it whenever
   they know the inbound connection. `admit_resubmitted_body` with no connection (`ic=None`: the
   edit-resend direct path, or a re-route whose inbound is gone) runs only the engine-wide NUL and
   size rules, so it does not refuse a second `MSH`; ADR 0205 documents the same skip for its frame
   bytes. The loopback re-ingress of a captured reply (`_process_response_item` in
   `messagefoundry/pipeline/wiring_runner.py`) does not run `check_decoded` either. It checks the
   size ceiling and peeks the reply, so a reply holding a second `MSH` is ingested as one message,
   and an ADR 0205 frame byte in it is not refused. Both skips stay open. The guard counts `MSH` the way the parser does: every line whose first three characters are
   `MSH`, after the whitespace around the body is stripped. The File and remote-file sources split a
   file first, so each message reaches the guard alone.

### The open points, settled

- **The explicit write's shape (rule 1).** A new method, `set_data`, rather than a keyword on `set`.
  A keyword defaulting to today's behaviour would leave the safe form the one a reader has to know
  to ask for, and the method name says at the call site which meaning the caller chose. `set` and
  `set_data` agree at a leaf, so a caller unsure of the level loses nothing by choosing `set_data`
  for a value it read. *Added in the final repair round:* the two are one implementation, so
  `set_data` checks the same things in the same order as `set` and raises the same exception type
  for the same arguments. Before, a message with no `MSH` and an absent segment raised `ValueError`
  from `set_data` where `set` raised `KeyError`. `MSH-1` and `MSH-2` hold the delimiters themselves
  and have no escaped form, so `set_data` writes them as `set` does. A dry-run trace records a
  `set_data` write with the value the Handler passed, which is what it records for `set`, and not
  the escaped text the write stores.
- **The lens's Copy Field.** The Steps view inserts Copy Field in the native idiom (ADR 0089), which
  was the very shape rule 3 names. Its insert now emits `msg.set_data(...)` when the source is a
  literal component or subcomponent path, and the recognizer reads both `msg.set` and `msg.set_data`
  copies back as `copy_field`. A source given as an expression cannot be classified there and keeps
  `msg.set`; the lint cannot see that one either. A `msg.set_data` call that is not a copy reads as a
  `code` row, because `set_field` means `set`, except for the Set Field template described at the
  end of this point. An edit of a copy row's `src` or `dst` re-picks the
  write the same way, so a source edited from a leaf to a whole field goes back to `set`, and one
  edited the other way goes to `set_data`. At a literal leaf destination the two writes are the same,
  so there the method is left as written. A re-pick that would push the line past the column limit
  is refused, since the lens never wraps a line itself. ADR 0106's palette table still shows the old shape as
  the record of that decision; `docs/STEPS-PALETTE.md` shows the new one. *Added in the final repair
  round:* a native Set Field whose value is a template is picked the same way. The write is
  `msg.set_data` when three things hold. Every read in the template is a literal component or
  subcomponent path. Its own text holds none of the HL7 component, repetition, subcomponent and
  escape characters `^ ~ & \`. *(Changed by the amendment of 2026-10-04 below: this set also held
  the X12 `:` and `>` (component) and `*` (element).)* Its destination is not a literal leaf. The
  pick runs on insert and on an edit of the value or the path. The recognizer reads such a `msg.set_data` back as
  `set_field`. At a literal leaf destination it reads any `msg.set_data` that is not a copy back
  as `set_field`, whatever the value, because there the two writes are the same. An edit that
  moves a Set Field's path off a literal leaf into a whole field and keeps its value is refused
  when the lens would write `msg.set` there and the value is not plain text, whichever write the
  line was spelled with. Plain text is a string literal holding none of those separators and no
  `|`. At the leaf either write escaped the value, so it was data, and
  `msg.set` would make its separators structure. Whether the value was kept is read from the
  arguments, so naming it unchanged in the same edit is refused too. A `msg.set_data` into a whole
  field whose template text holds one of those separators, such as `A^`, reads as a `code`
  row, because the lens never writes that line. A whole-field read is raw text with its
  structure, so it keeps `msg.set`. Text holding one of those separators is structure the
  author wrote, so it keeps `msg.set` too, and the lint still flags a leaf it copies. A field
  separator in the text does not keep `msg.set`. `set` refuses one in a whole field, so it can only
  mean data. At a literal leaf destination the lens writes `msg.set`. An edit that changes no
  argument leaves the write as written, even when it respells a string's quotes or drops a `u`
  prefix. The lens cannot know a message's own separators, and it cannot tell an X12 handler from
  an HL7 one, so it tests the separators of HL7, the default format, and adds no X12-only one. An
  X12 composite path with a three-character segment id, such as `CLM-05.1`, reads as a leaf, so a Set Field template over one
  is written `msg.set_data`. One with a two-character id, such as `N4-01.1`, does not match the
  HL7 path grammar the lens uses, so it keeps `msg.set`. The X12
  message gained a `set_data` for that line, which raised `AttributeError` before. It is the X12
  `set`, except that a whole element also refuses the component separator. X12 has no escape, so
  refusing is how the value stays data. `set_data` receives the value already built, so it cannot
  tell a separator the author typed from one a read returned. So on an X12 message a template
  whose text holds the component separator raises under `set_data`. *(Changed by the amendment of
  2026-10-04 below: the lens kept `set` for a template whose text held `:` or `>`, which cost HL7
  templates their protection.)* A Copy Field on
  X12 still fails, because `X12Message` has no `field` method. That was true before this ADR, and
  it is not changed here. At least four template
  writes into a whole field still take decoded text as structure and are not changed here: the
  wrapper form `set_field(msg, ...)`, and templates into `add_repetition`, `append_to_field` and
  `replace_literal`, each of which writes with `set` or `add_repetition`.
- **The lint's reach (rule 3).** It follows the value's data flow: the written expression, and
  every binding in the write's own scope of a name that flows into it, as `unsafe-db-lookup`
  follows a name (BACKLOG #1658). A conditional's test, a comprehension's filter, a subscript or
  mapping key, a `key=` function, and the argument of a call that returns a length, a truth value
  or a number select or measure the value and are not followed, so `msg.set("PID-3", mr)` in
  `samples/results_relay/results_relay.py`, whose only leaf read is a generator filter, is clean.
  Every binding of a name counts, so it over-reports rather than miss a branch, and the names are
  solved as one fixed point per scope, so a long chain costs a pass per link rather than doubling at
  each. A read from any plain name counts, not only the message the write targets: a decoded leaf
  from another message is as much data. It does not follow a value through a function call into
  another scope, and it does not see a dynamic path. **Known blind spots**, each a shape it does not
  flag: a loop target (`for rep in msg.repetitions(...)`, whose items are then written whole); a
  walrus target bound inside an expression; a value passed by keyword (`msg.set("PV1-19",
  value=v)`); an augmented subscript write (`msg["PV1-19"] += v`); decoded leaves joined into a
  line handed to `add_segment`; a write inside a nested function, which sees the module's bindings
  but not its enclosing function's; and a dict comprehension's keys. It also reads `"~".join(...)` and other method calls by their
  receiver and arguments, so it flags a join of leaves but cannot tell what a join it does not
  follow produced. It is advisory, so these are recorded rather than closed. *Added in the final
  repair round:* the flow walk keeps its own stack instead of recursing. A long `+` chain nests as
  deep as it has terms, and 500 terms used to raise `RecursionError` and crash
  `messagefoundry check`. A write the walk still cannot finish is reported as
  `leaf-to-whole-field-unscanned` and never raised, so strict mode refuses it as it refuses a
  finding, rather than passing code nobody scanned.
- **What a value under the target set becomes (rule 4).** Escaped, not refused. The draft allowed
  either. Escaping keeps the message deliverable and is what the target set's own escape mechanism
  exists for. The test is what the receiver reads: a separator escape keeps its letter only when that
  letter names the same character under both sets, and is otherwise decoded and re-escaped, so
  `SMITH \T\ SONS` sent under a target subcomponent `#` still reads `SMITH & SONS`. Refusal is kept
  for the one leaf value escaping cannot fix: text inside an escape sequence such as `\Z..\` has no
  escape of its own. A segment id is not a leaf and is refused too. A field holding no source escape
  character takes one `str.translate`, whose table maps the separators and escapes each data
  character that needs it. When the target set equals the source set, every field takes the plain
  translate it took before. *Changed in the final repair round:* a field holding an escape sequence
  was walked character by character, on the event loop in MLLP `send()`, which a reviewer measured
  at about 20 times the old cost. It is now split on the escape character: each escape sequence is
  rewritten once per message, up to 64 distinct ones remembered, and the text between sequences
  takes the same single translate. On a
  1 MB `OBX-5` under a target subcomponent `#` (best of three, a loaded machine, so read the ranges
  as rough), a report with a line-break escape every 80 characters took 2 to 3 ms before this ADR,
  100 to 180 ms after the walk, and 15 to 16 ms now; a field with a separator escape every 10
  characters took 2 to 3 ms, 90 to 160 ms, and 57 to 63 ms. A field with no escape is unchanged, at
  2 to 3 ms. The walk survives only for a message whose escape character is also one of its
  separators, where the separator wins, and a test holds the split to the walk's output over 400
  random fields per target set. The send stays on the event loop in this round.
  *Recorded in the final repair round:* a target set may name a letter, such as `E`, as a
  separator. The letters `F`, `S`, `R`, `T` and `E` are what a separator escape is made of, so a
  receiver re-splits the escapes this rewrite writes, and reads something other than what the
  engine read. That is filed separately as vault BACKLOG #2828, the escape-letter separator
  re-split, and is not closed here.
- **Which re-encode failures are permanent.** All of them on the MLLP override, not only rule 4's,
  and the sibling `hl7_raw_separators` re-encode too. A payload that is not parseable HL7 fails
  identically on every retry under either setting, so a retry only holds the lane. That is ADR
  0204's rule: a refusal the payload causes raises the existing permanent class, here with code
  `reencode`. `NegativeAckError` is a `DeliveryError`, so a caller catching the latter is
  unaffected. *Added 2026-10-02, on merging ADR 0205's repair:* MLLP's `send()` and its
  `check_frame` now share one rewrite step, `_rewrite_for_wire`, and the permanent refusal lives
  there. So on a single-row send a simulate (shadow) outbound dead-letters a payload the rewrite
  refuses, as a live send does. ADR 0205's note that shadow completes such a row, while a live
  send retries it, described the retryable refusal this ADR replaced. Two batch gaps stay open.
  A live MLLP batch rewrites the whole envelope in `send()`, so one member the target set cannot
  carry dead-letters every member of that batch at once; before this ADR that member was not
  refused at all, and its text became structure. A shadow batch checks members with
  `rewrite=False` and never rewrites the envelope, so it marks that batch `PROCESSED`. ADR 0205
  dropped a full per-member rewrite for two reasons: it raised a retryable error on a member with
  no `MSH`, re-pending the whole batch, and it stripped a trailing frame byte the envelope still
  carries. A narrower per-member check, for this ADR's refusal alone, is not built and stays open.
- **RemoteFileSource (rule 5): it splits, like the File source.** It reads whole files, as the File
  source does, and a remote drop is where a partner's batch file arrives: several `MSH` messages, with
  or without an `FHS`/`BHS` envelope, the shape `samples/messages/adt_batch.hl7` holds. Refusing would
  turn a conformant batch file into one `ERROR` where the same file dropped locally is N messages, and
  an enveloped batch was already refused there whole, because the listener path does not accept an
  `FHS`/`BHS`-led body. Splitting has no ACK to reinterpret, which is the draft's objection to
  splitting on a listener: a file source answers nobody, and each message gets its own disposition.
  The split goes through a new `split_batch_bytes` in `messagefoundry/parsing/split.py`, which decodes
  with the declared charset, splits with `split_batch`, and re-encodes each message; a single-message
  or undecodable file is handed over as its original bytes, as the File source does. In a charset
  whose ASCII bytes always mean ASCII (UTF-8, ASCII, ISO 8859, Windows-125x), a file with no `MSH`
  after a line break is one message, so it is handed over after one byte scan, with no decode or
  split. The stop is checked before every hand-off, the first included: a stop part-way leaves the
  whole file for the next start, and a store failure on hand-off K leaves it for the next poll; both
  re-emit the first K messages, the at-least-once behaviour the File source already has. The split
  runs in a worker thread, as the poll's other blocking steps do, so a large batch file does not
  hold the event loop; a cancellation at that point hands nothing over. The File
  source keeps its own inline copy of the same logic in this change, because a concurrent pull
  request is editing `transports/file.py`; moving it onto the helper is a follow-up.
- **No leading message is dropped by the split.** `split_batch` used to keep only chunks that began
  with `MSH`, so a file starting with a byte order mark, a space or a tab lost its first message
  when it held three or more, and with two the whole file went over as one `ERROR`. Now the first
  chunk is read past whitespace, a byte order mark (U+FEFF) and its `FHS`/`BHS` envelope header
  lines. What remains is a message when it starts with `MSH`, and is otherwise kept so the parser
  records its `ERROR`. The File source calls `split_batch` too, so it is fixed by the same change.
  The dry-run's `split_messages` splits a latin-1 view of the bytes, where a UTF-8 byte order mark is
  three characters, so it strips that mark first and splits as the live sources do under a UTF-8
  charset. It is not told the connection's charset, so under a single-byte charset, where the live
  sources keep those three bytes and the parser refuses the file, the dry run still reads past them;
  that gap stays open. *Changed in the
  final repair round:* a file holding one message led by a UTF-8 byte order mark, or by an
  `FHS`/`BHS` envelope header, used to be handed over whole, and the parser refused it, while each
  message of a two-message file led the same way was recorded. Now `one_message_bytes` in
  `messagefoundry/parsing/split.py` hands such a file over as the split read it: past the mark or
  the header, with its line ends made CR, as each member of a batch is. The File source, the
  remote-file source and the dry-run's `split_messages` all call it, so one such message gets the
  disposition each member of a batch gets. The mark is read in the decoded text, so under a
  single-byte charset its bytes are three characters, which the batch split keeps too, and a
  `utf-8-sig` or UTF-16 decode drops the mark itself. A one-message file whose decoded text starts
  with `MSH` after whitespace is still handed over as its own bytes. The split drops an envelope's
  header lines but not its `BTS`/`FTS` trailer lines, so the last message of an enveloped file, and
  now its only message, carries them to the Handler; dropping them is not built here.
- **A second-`MSH` counter does not close ADR 0205's route 3.** There the smuggled header follows an
  embedded start byte, so the parser reads a segment whose id begins with that byte, not `MSH`. The
  embedded-byte refusal of ADR 0205 rule 4 runs first in the same guard and is what closes it.

### What `encode_batch` does with a member holding a second `MSH`

The draft read this from a docstring; it was run for this record. `encode_batch` in
`messagefoundry/parsing/split.py` carries each member verbatim and writes the member count into
`BTS-1`. Given two members, the second holding two messages, it wrote `BTS|2` around three `MSH`
lines, and `split_batch` of the envelope gave three. So a receiver that splits on `MSH` would see one
message more than `BTS-1` says.

After rule 5 no such member arrives from a source: the listeners refuse it, and the File and remote
sources split it. What remains is a Handler that builds one itself, by returning text holding two
messages in one `Send`, or a `Message` parsed from such text. That is structure the Handler author
wrote, not data becoming structure, so it is outside this decision. The same payload sent unbatched
over MLLP is one frame holding two messages. Whether a delivery should refuse a payload holding more
than one `MSH` is left to its own item.

## Acceptance Criteria

- **AC-1** -- WHEN `copy_field` copies a component or subcomponent into a whole field, THE SYSTEM
  SHALL write the value as data, so its escaped separators stay escaped and the field holds one
  repetition and one component.
  -> `tests/test_data_never_becomes_structure.py::test_P5_copy_field_from_a_component_to_a_whole_field_stays_one_value`
  -> `tests/test_data_never_becomes_structure.py::test_a_subcomponent_source_is_data_too`
- **AC-2** -- WHEN `split_field` splits a component or subcomponent, THE SYSTEM SHALL write each
  piece as data at every destination level.
  -> `tests/test_data_never_becomes_structure.py::test_split_field_writes_decoded_pieces_as_data`
- **AC-3** -- WHEN a whole field is copied or written through `set` with author-supplied text, THE
  SYSTEM SHALL keep that text's structure.
  -> `tests/test_data_never_becomes_structure.py::test_a_whole_field_copy_still_carries_its_structure`
  -> `tests/test_data_never_becomes_structure.py::test_set_data_escapes_a_whole_field_and_set_keeps_its_meaning`
- **AC-4** -- WHEN `set_data` writes a whole field, THE SYSTEM SHALL escape the value with the
  message's own separators, scope it to one repetition when asked, and still refuse CR and LF;
  it SHALL raise what `set` raises for the same arguments, and a dry-run trace SHALL record the
  value passed, as it does for `set`.
  -> `tests/test_data_never_becomes_structure.py::test_set_data_reads_the_messages_own_separators`
  -> `tests/test_data_never_becomes_structure.py::test_set_data_scopes_to_one_repetition_and_leaves_the_others`
  -> `tests/test_data_never_becomes_structure.py::test_set_data_still_refuses_a_segment_separator`
  -> `tests/test_data_never_becomes_structure.py::test_set_data_fails_exactly_as_set_fails_for_the_same_write`
  -> `tests/test_data_never_becomes_structure.py::test_the_dry_run_trace_records_a_set_data_write_as_set_records_it`
- **AC-5** -- WHERE a config module writes into a literal whole-field path with `set` a value that a
  literal leaf read flows into, THE SYSTEM SHALL report a `leaf-to-whole-field` advisory finding, and
  SHALL NOT report one for `set_data`, a leaf destination, a whole-field source, a dynamic path, or a
  leaf read that only selects or measures the value (a test, a filter, a key, a length). IF the
  lint cannot finish walking a write, THEN THE SYSTEM SHALL report it as
  `leaf-to-whole-field-unscanned` and SHALL NOT crash the check. WHEN it reports either, THE SYSTEM
  SHALL advise `set_data` and SHALL name the X12 case, where `set_data` refuses the component
  separator in a whole element. *(Added by the amendment of 2026-10-04 below.)*
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_flags_a_decoded_leaf_written_to_a_whole_field`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_follows_a_name_bound_in_the_same_scope`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_does_not_flag_safe_or_unknowable_shapes`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_ignores_a_leaf_that_does_not_flow_into_the_value`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_still_flags_a_leaf_that_flows_into_the_value`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_follows_a_name_only_through_its_value`
  -> `tests/test_data_never_becomes_structure.py::test_the_shipped_results_relay_sample_is_clean`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_resolves_a_deep_doubling_chain_quickly`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_walks_a_very_long_concatenation_without_crashing`
  -> `tests/test_data_never_becomes_structure.py::test_a_write_the_lint_cannot_walk_is_noted_and_never_raises`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_advice_names_the_x12_case_where_set_data_raises`
  -> `tests/test_data_never_becomes_structure.py::test_an_unscanned_write_gets_the_same_advice`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_gives_no_leaf_advice_without_a_leaf_finding`
- **AC-6** -- WHEN the Steps view inserts a Copy Field from a literal leaf, THE SYSTEM SHALL emit
  `set_data` and read the line back as the same `copy_field` row; and WHEN an edit moves a copy's
  source or destination across that line, THE SYSTEM SHALL re-pick `set` or `set_data`. WHEN a Set
  Field template reads only literal leaves into a whole field, and its text holds none of
  `^ ~ & \`, THE SYSTEM SHALL write it with `set_data` on insert and on an edit of its value
  or path, and read it back as `set_field`; WHEN its text holds one, THE SYSTEM SHALL keep `set`.
  WHEN a `set_data` call that is not a copy writes a literal leaf, THE SYSTEM SHALL read it back as
  `set_field`, whatever its value. WHEN an edit moves a Set Field's path off a literal leaf into a
  whole field, keeps a value that is not plain text (a string literal holding none of
  `^ ~ & \ |`), and would write it with `set`, THE SYSTEM SHALL refuse the edit, whichever
  write the line was spelled with. WHEN an edit changes no argument, including one that only
  respells quotes or drops a `u` prefix, THE SYSTEM SHALL leave its write alone. WHEN such a
  `set_data` line runs on an X12 message, THE SYSTEM SHALL write the value as `set` writes it, and
  SHALL raise `ValueError` rather than write the component separator into a whole element.
  -> `tests/test_data_never_becomes_structure.py::test_the_lens_inserts_a_copy_from_a_leaf_with_set_data_and_reads_it_back`
  -> `tests/test_data_never_becomes_structure.py::test_the_lens_keeps_set_for_a_whole_field_or_an_expression_source`
  -> `tests/test_data_never_becomes_structure.py::test_a_copy_edited_from_a_leaf_to_a_whole_field_source_writes_with_set`
  -> `tests/test_data_never_becomes_structure.py::test_a_copy_edited_from_a_whole_field_to_a_leaf_source_writes_with_set_data`
  -> `tests/test_data_never_becomes_structure.py::test_a_copy_whose_destination_is_edited_to_a_whole_field_writes_with_set_data`
  -> `tests/test_data_never_becomes_structure.py::test_a_copy_re_pick_that_would_pass_the_column_limit_is_refused`
  -> `tests/test_data_never_becomes_structure.py::test_a_set_field_template_copying_a_leaf_writes_with_set_data_and_reads_back`
  -> `tests/test_data_never_becomes_structure.py::test_a_set_field_template_that_is_not_a_leaf_copy_keeps_set`
  -> `tests/test_data_never_becomes_structure.py::test_an_inserted_set_field_template_copying_a_leaf_writes_with_set_data`
  -> `tests/test_data_never_becomes_structure.py::test_a_set_field_template_into_a_leaf_keeps_set`
  -> `tests/test_data_never_becomes_structure.py::test_a_set_field_template_holding_a_field_separator_writes_with_set_data`
  -> `tests/test_data_never_becomes_structure.py::test_a_set_field_path_edit_re_picks_the_write`
  -> `tests/test_data_never_becomes_structure.py::test_an_edit_that_changes_nothing_leaves_a_hand_written_write_alone`
  -> `tests/test_data_never_becomes_structure.py::test_an_edit_that_only_respells_a_quote_leaves_the_write_alone`
  -> `tests/test_data_never_becomes_structure.py::test_an_edit_that_only_drops_a_u_prefix_leaves_the_write_alone`
  -> `tests/test_data_never_becomes_structure.py::test_a_set_field_template_holding_an_x12_separator_writes_with_set_data`
  -> `tests/test_data_never_becomes_structure.py::test_an_hl7_template_holding_an_x12_separator_keeps_an_escaped_leaf_as_data`
  -> `tests/test_data_never_becomes_structure.py::test_a_set_data_template_into_a_leaf_still_reads_back_as_set_field`
  -> `tests/test_data_never_becomes_structure.py::test_any_set_data_value_into_a_leaf_reads_back_as_set_field`
  -> `tests/test_data_never_becomes_structure.py::test_a_path_edit_never_moves_a_leafs_data_write_into_a_whole_field_as_set`
  -> `tests/test_data_never_becomes_structure.py::test_a_path_edit_that_keeps_the_meaning_is_not_refused`
  -> `tests/test_data_never_becomes_structure.py::test_a_set_data_template_holding_a_colon_reads_back_as_set_field`
  -> `tests/test_data_never_becomes_structure.py::test_the_no_change_test_leaves_the_tree_it_reads_as_it_was`
  -> `tests/test_x12_parsing.py::test_set_data_is_set_on_an_x12_message_and_keeps_one_component`
  -> `tests/test_x12_parsing.py::test_the_lens_set_field_template_line_runs_on_an_x12_message`
  -> `tests/test_x12_parsing.py::test_a_lens_template_whose_text_holds_the_component_separator_raises_on_x12`
  -> `tests/test_x12_parsing.py::test_a_path_edit_writes_set_data_for_a_template_holding_the_component_separator`
- **AC-7** -- WHEN the delimiter override rewrites a message, THE SYSTEM SHALL keep every leaf reading
  the same under the target set: a target delimiter inside a leaf is escaped with the target escape
  character, a separator escape is decoded against the source set and re-escaped against the target
  set, and an escape character nothing closes is carried as data, so the downstream parse reads the
  fields and values the engine saw.
  -> `tests/test_data_never_becomes_structure.py::test_P3_a_literal_target_field_separator_stays_inside_its_field`
  -> `tests/test_data_never_becomes_structure.py::test_every_target_delimiter_found_in_a_leaf_is_escaped`
  -> `tests/test_data_never_becomes_structure.py::test_escapes_and_structure_survive_the_slow_path`
  -> `tests/test_data_never_becomes_structure.py::test_an_override_that_only_renames_separators_takes_the_plain_translate`
  -> `tests/test_data_never_becomes_structure.py::test_a_separator_escape_reads_the_same_after_the_rewrite`
  -> `tests/test_data_never_becomes_structure.py::test_an_escaped_and_a_literal_component_stay_distinct_under_the_target`
  -> `tests/test_data_never_becomes_structure.py::test_an_unclosed_escape_holding_a_target_delimiter_is_carried`
  -> `tests/test_data_never_becomes_structure.py::test_the_split_rewrite_matches_the_character_walk`
  -> `tests/test_data_never_becomes_structure.py::test_a_field_of_many_distinct_escapes_rewrites_past_the_cache_cap`
  -> `tests/test_mllp_encoding_override.py::test_reencode_decodes_separator_escapes_so_they_read_the_same`
- **AC-8** -- IF the target delimiters cannot carry a value as data, THEN THE SYSTEM SHALL refuse the
  rewrite with content-free text, and the MLLP delivery SHALL fail permanently before any dial.
  -> `tests/test_data_never_becomes_structure.py::test_a_value_the_target_set_cannot_carry_is_refused`
  -> `tests/test_data_never_becomes_structure.py::test_the_mllp_override_refusal_is_permanent_and_dials_nothing`
  -> `tests/test_data_never_becomes_structure.py::test_a_non_hl7_payload_under_the_override_is_permanent_too`
  -> `tests/test_data_never_becomes_structure.py::test_a_non_hl7_payload_under_raw_separators_is_permanent_too`
- **AC-9** -- IF an HL7 v2 body reaching a listener holds more than one `MSH` segment, THEN THE
  SYSTEM SHALL record `ERROR`, answer `AR` where it has an ACK channel, and commit nothing to the
  ingress stage.
  -> `tests/test_data_never_becomes_structure.py::test_ingress_refuses_a_second_msh`
  -> `tests/test_data_never_becomes_structure.py::test_P6_the_mllp_listener_naks_and_records_error`
  -> `tests/test_data_never_becomes_structure.py::test_P6_the_http_listener_records_error_and_commits_nothing`
  -> `tests/test_data_never_becomes_structure.py::test_the_dry_run_refuses_what_the_listener_refuses`
- **AC-10** -- THE SYSTEM SHALL admit a body holding one message, `MSH` text inside a field, an
  enveloped single message, and any non-HL7 body.
  -> `tests/test_data_never_becomes_structure.py::test_ingress_admits_one_message`
  -> `tests/test_data_never_becomes_structure.py::test_the_second_msh_refusal_is_hl7v2_only`
- **AC-11** -- WHEN a remote-file source retrieves an HL7 v2 batch file, THE SYSTEM SHALL hand each
  message over on its own, in file order, give each its own disposition, and SHALL leave the file in
  place, handing nothing more over, when a stop arrives before its last message. The split SHALL
  run off the event loop.
  -> `tests/test_data_never_becomes_structure.py::test_the_remote_file_source_splits_a_batch_like_the_file_source`
  -> `tests/test_data_never_becomes_structure.py::test_a_stop_part_way_through_a_remote_batch_leaves_the_file`
  -> `tests/test_data_never_becomes_structure.py::test_a_stop_before_the_first_message_hands_nothing_over_and_still_prunes`
  -> `tests/test_data_never_becomes_structure.py::test_split_batch_bytes_splits_a_batch_and_hands_one_message_over_untouched`
  -> `tests/test_data_never_becomes_structure.py::test_split_batch_bytes_hands_a_single_message_over_without_decoding`
  -> `tests/test_data_never_becomes_structure.py::test_split_batch_bytes_still_splits_an_encoding_the_byte_check_cannot_read`
  -> `tests/test_data_never_becomes_structure.py::test_the_remote_split_runs_off_the_event_loop_and_keeps_file_order`
- **AC-12** -- WHEN a batch file starts with whitespace or a byte order mark, THE SYSTEM SHALL keep its
  first message, on the File and the remote-file source alike, and SHALL otherwise leave the File
  source's batch split unchanged. WHEN a one-message file starts with a UTF-8 byte order mark or an
  `FHS`/`BHS` envelope header before its `MSH`, THE SYSTEM SHALL hand the message over as the split
  read it, so it gets the disposition a batch member gets.
  -> `tests/test_data_never_becomes_structure.py::test_every_message_of_a_noise_led_remote_file_gets_a_disposition`
  -> `tests/test_data_never_becomes_structure.py::test_split_batch_keeps_a_first_message_led_by_noise`
  -> `tests/test_data_never_becomes_structure.py::test_a_first_chunk_that_is_not_an_envelope_is_kept_for_the_parser`
  -> `tests/test_data_never_becomes_structure.py::test_the_file_source_keeps_a_bom_led_first_message`
  -> `tests/test_data_never_becomes_structure.py::test_the_dry_run_split_keeps_a_bom_led_first_message_as_the_live_split_does`
  -> `tests/test_data_never_becomes_structure.py::test_a_bom_led_remote_file_gets_the_same_disposition_per_message`
  -> `tests/test_data_never_becomes_structure.py::test_one_bom_led_message_loses_its_mark_before_hand_off`
  -> `tests/test_data_never_becomes_structure.py::test_the_file_source_hands_one_bom_led_message_over_without_its_mark`
  -> `tests/test_data_never_becomes_structure.py::test_one_enveloped_message_goes_over_as_the_split_reads_it`
  -> `tests/test_data_never_becomes_structure.py::test_one_enveloped_remote_message_is_recorded`
  -> `tests/test_data_never_becomes_structure.py::test_one_bom_led_message_goes_over_as_the_split_reads_it`
  -> `tests/test_data_never_becomes_structure.py::test_the_leading_mark_check_reads_the_whitespace_the_sniff_tolerates`
  -> `tests/test_message_split.py`

## Options considered

1. **An explicit data write, escaping in the re-encode, and a one-message rule at intake.** The
   draft's design, with the points above settled. **CHOSEN.**
2. **Make every whole-field `set` escape.** It breaks every Handler that writes structure on purpose.
   Rejected.
3. **Refuse a mixed-level copy.** Safe and blunt; it turns a common mapping into an error. Rejected
   in favour of the explicit write, and kept as the fallback the draft named.
4. **Mark a decoded read with a `str` subclass that a whole-field `set` escapes.** It would fix the
   hand-written form with no change to Handler code. It is also invisible at the call site, and any
   string operation (`upper()`, slicing, concatenation) returns a plain `str` and drops the mark, so
   it would protect some shapes and silently not others. Rejected.
5. **Pin the accepted inbound separators per connection**, instead of escaping in the override. It
   narrows the input and leaves the encoder wrong. Worth doing as well, not instead; not built here.
6. **Split a second `MSH` on a listener, as the File source does.** It makes the paths consistent,
   and it turns one MLLP ACK into several dispositions, so the ACK would no longer say what happened
   to everything the sender sent. Rejected for the listeners. Taken for `RemoteFileSource`, which has
   no ACK.
7. **Refuse a second `MSH` in `RemoteFileSource`.** Rejected, for the reasons above.

## Consequences

**Positive** -- The `copy_field` docstring is true for every destination. A sender that declares
unusual separators can no longer set a field through the override. A sender that packs two messages
into one MLLP frame or one HTTP request is told so, with an `AR` where it can be. A remote batch file
is processed as the File source processes one, and an enveloped remote batch is no longer one
`ERROR`. A batch file led by whitespace or a byte order mark keeps its first message on both file
sources, and a one-message file led by a byte order mark or an `FHS`/`BHS` envelope header is no
longer an `ERROR`.

**Negative / risks** -- Rule 3 is advisory: a Handler author can still write the unsafe form, and
the lint sees only literal paths and has the blind spots listed above. A partner that reads a
target-set escape it did not expect would see the escape rather than a split field, which is the
point. A Handler can still send two messages in one payload; see the `encode_batch` finding.
`samples/send_mllp.py` sends a whole file as one frame, so `samples/messages/adt_batch.hl7`, five
messages with no envelope, now gets an `AR`; the helper's usage text, `docs/USER-GUIDE.md` and
`docs/CONNECTIONS.md` say so.

**Out of scope** -- A delivery refusing a payload holding more than one `MSH`. Moving the File source
onto `split_batch_bytes`. Pinning inbound separators per connection. The `FHS`/`BHS` header lines
`encode_with_separators` rewrites, which keep their python-hl7-parity shape. The `escape_leaf` defect
with a letter separator, which ADR 0205 fixed and this branch now carries. The escape-letter
separator re-split in the delimiter rewrite, vault BACKLOG #2828. The second-`MSH` refusal on the
loopback re-ingress path. A per-member re-encode check for an MLLP batch.

## Amendment 2026-10-04: the lens protects HL7 and adds no X12-only separator

Vault BACKLOG #2861 and #2862. The owner delegated the decision, and a Manager took it after an
adversarial review.

**The decision.** `_AUTHORED_STRUCTURE` in `messagefoundry/lens.py` drops `*`, `:` and `>`. It now
holds only the HL7 component, repetition, subcomponent and escape characters `^ ~ & \`. Two of
those, `^` and `~`, are also common X12 separators, for a repetition and a segment end, and both
X12 writes refuse them. A Set Field template whose own text holds `*`, `:` or `>` is written with
`msg.set_data` into a whole field, as any other template of literal leaf reads is.

**Why.** The lens cannot tell an HL7 handler from an X12 one. Each character in the set costs HL7
its protection, and the three X12 separators bought X12 little.

- `*`: `X12Message` refuses the element separator under both `set` and `set_data`. Keeping it in
  the set never changed an X12 result. It only took `set_data` away from HL7 templates.
- `:`: the HL7 template `MRN: {PID-3.1}` into `PV1-19`, with `PID-3.1` holding `12\S\34`, kept
  `msg.set`. That wrote `MRN: 12^34` live, so the data became a second component and `PV1-19.2`
  read `34`. `msg.set_data` writes `MRN: 12\S\34`, which is correct.
- `>`: the same as `:`.
- An X12 handler's `msg` is a `RawMessage`, which has no `set` or `set_data`. A Steps-view Set Field
  on X12 runs only after a hand-written `msg = X12Message.parse(...)`, so the X12 need here is small.

**What X12 pays.** An X12 leaf read is split on the component separator, so it can never hold
one. On X12, a component separator in a lens template is always text the author typed. Under
`set_data` that line now raises, whether the author meant a composite such as `11:B:1` or data
such as `12:30`. `set` would write the first and split the second without a word. So the cost is
an X12 composite authored in the Steps view. A hand-written `msg.set` composite line pays it too
once its value or path is edited there. The edit re-picks `set_data`, and the line then raises on
every message. An X12 author who means a composite writes `set` by hand and does not edit it as a
step, or writes each component on its own path. The lens path grammar is HL7's, so this applies
only where the read's segment id has three characters, such as `CLM-05.1`; `HI-01.2` keeps `set`.
Telling the formats apart would remove this cost. That is the per-handler format hint named out
of scope below.

**What else moved.** The path-edit refusal (`_moves_data_off_a_leaf`) reads the same set to decide
what plain text is. A string literal holding an X12 separator is now plain, so moving it off a leaf
into a whole field is no longer refused. Under the default HL7 separators such text is written the
same at a leaf and in a whole field. On X12 the move can turn a line that raised into one that
writes structure: `msg.set_data("CLM-05.1", "A:B")` raises, and its edit to `CLM-05` becomes
`msg.set("CLM-05", "A:B")`, two components. That is author-typed text under `set`, which rule 2
keeps as structure. An HL7 message whose own MSH-2 uses `:`, `>` or `*` as a separator loses this
refusal for such a literal. A Set Field template whose text holds that separator is also written
`set_data` there, which escapes it. Both were already true of any other non-default separator.
The in-body text above, AC-5 and AC-6 now state the new rules and name the changed tests.

**The lint advice (#2862).** Rule 3's `leaf-to-whole-field` finding advises `set_data`. The lint
reads paths, not formats, so it flags an X12 composite such as
`msg.set("CLM-05", f"{msg['CLM-05.1']}:B:1")` too, and there `set_data` raises on the component
separator. A finding now carries advice. On HL7 it says to write a value read from a component
or subcomponent with `set_data`. On X12 it says `set_data` refuses the component separator in a
whole element, and `set` may stay where the text holds one on purpose. It offers `keep set` to
the X12 case only, so an HL7 author is not told to keep the unsafe write. A
`leaf-to-whole-field-unscanned` finding carries the same advice. The row first assumed the lens
kept `set` for an X12 template holding `:`. This amendment removes that premise, so only the
advice half remained. Strict mode is unchanged.

**Out of scope here.** Vault #2863 (the path-plus-value edit gap), #2856 (`X12Message` has no
`field`), and a per-handler format hint for `X12Message.parse`.
