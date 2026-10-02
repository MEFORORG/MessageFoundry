# 0206 -- An HL7 write or re-encode never lets data become structure

- **Status:** Accepted (2026-10-02, on build; decision delegated by the owner under the driver rule and taken by the batch 186 Manager; the owner may overrule at review)
- **Date:** 2026-10-02
- **Related:** vault BACKLOG #2558 (a decoded leaf copied into a whole field), #2559 (the outbound
  delimiter override), #2560 (a second `MSH` in one body), #2557 and
  [ADR 0205](0205-an-outbound-frame-holds-exactly-one-message.md) (the same family, for frame bytes),
  ADR 0204 (the permanent failure class; on its own pull request), [ADR 0054](0054-low-allocation-builtins-hl7-parser.md)
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
   `<name>["<field>"] = v` assignment whose value holds a `<name>.field("<leaf>")` call or a
   `<name>["<leaf>"]` read, directly or through a name bound in the same scope. Both paths must be
   string literals for the AST to know their level. It is advisory, as the lint is.
4. **`encode_with_separators` escapes a target delimiter found in a leaf**, with the target escape
   character: the target field, component, repetition, subcomponent and escape characters become
   `F`, `S`, `R`, `T` and `E` escapes. A value the target set cannot represent raises
   `DelimiterRewriteRefused`: an escape sequence, or an escape character nothing closes, whose text
   holds such a character, and a segment id holding the target field separator. The MLLP override
   raises it as `NegativeAckError(permanent=True)`, code `reencode`, so the delivery fails at once.
5. **A source that does not split refuses a body with more than one `MSH`.** The check sits in
   `check_decoded`, the shared post-decode guard, as `IngressMultipleMessagesRejected`, an
   `IngressBodyRejected` like ADR 0205's frame-byte refusal. The MLLP, TCP and HTTP listeners record
   `ERROR`; a listener with an ACK channel answers `AR` with MSA-3 `more than one MSH in body`. The
   dry-run and the resubmission paths run the same guard, so they refuse the same body. It counts
   `MSH` the way the parser does: every line whose first three characters are `MSH`, after the
   whitespace around the body is stripped. The File source is unchanged: `split_batch` splits it
   first, so each message reaches the guard alone.

### The open points, settled

- **The explicit write's shape (rule 1).** A new method, `set_data`, rather than a keyword on `set`.
  A keyword defaulting to today's behaviour would leave the safe form the one a reader has to know
  to ask for, and the method name says at the call site which meaning the caller chose. `set` and
  `set_data` agree at a leaf, so a caller unsure of the level loses nothing by choosing `set_data`
  for a value it read.
- **The lens's Copy Field.** The Steps view inserts Copy Field in the native idiom (ADR 0089), which
  was the very shape rule 3 names. Its insert now emits `msg.set_data(...)` when the source is a
  literal component or subcomponent path, and the recognizer reads both `msg.set` and `msg.set_data`
  copies back as `copy_field`. A source given as an expression cannot be classified there and keeps
  `msg.set`; the lint cannot see that one either. A `msg.set_data` call that is not a copy reads as a
  `code` row, because `set_field` means `set`. ADR 0106's palette table still shows the old shape as
  the record of that decision; `docs/STEPS-PALETTE.md` shows the new one.
- **The lint's reach (rule 3).** It follows a name through every binding in the write's own scope,
  as `unsafe-db-lookup` does (BACKLOG #1658), and over-reports rather than miss a branch. A read
  from any plain name counts, not only the message the write targets: a decoded leaf from another
  message is as much data. It does not follow a value through a function call into another scope,
  and it does not see a dynamic path.
- **What a target delimiter in a leaf becomes (rule 4).** Escaped, not refused. The draft allowed
  either. Escaping keeps the message deliverable and is what the target set's own escape mechanism
  exists for. Refusal is kept for the values escaping cannot fix: text inside an escape sequence has
  no escape of its own, and a segment id is not a leaf. A field holding no such character takes the
  single `str.translate` it took before, so the common path costs one regular-expression scan more.
- **Which re-encode failures are permanent.** All of them on the MLLP override, not only rule 4's,
  and the sibling `hl7_raw_separators` re-encode too. A payload that is not parseable HL7 fails
  identically on every retry under either setting, so a retry only holds the lane. That is ADR
  0204's rule: a refusal the payload causes raises the existing permanent class, here with code
  `reencode`. `NegativeAckError` is a `DeliveryError`, so a caller catching the latter is
  unaffected.
- **RemoteFileSource (rule 5): it splits, like the File source.** It reads whole files, as the File
  source does, and a remote drop is where a partner's batch file arrives: several `MSH` messages, with
  or without an `FHS`/`BHS` envelope, the shape `samples/messages/adt_batch.hl7` holds. Refusing would
  turn a conformant batch file into one `ERROR` where the same file dropped locally is N messages, and
  an enveloped batch was already refused there whole, because the listener path does not accept an
  `FHS`/`BHS`-led body. Splitting has no ACK to reinterpret, which is the draft's objection to
  splitting on a listener: a file source answers nobody, and each message gets its own disposition.
  The split goes through a new `split_batch_bytes` in `messagefoundry/parsing/split.py`, which decodes
  with the declared charset, splits with `split_batch`, and re-encodes each message; a single-message
  or undecodable file is handed over as its original bytes, as the File source does. A stop part-way
  through a batch leaves the whole file for the next start, and a store failure on hand-off K leaves
  it for the next poll; both re-emit the first K messages, the at-least-once behaviour the File source
  already has. The File source keeps its own inline copy of the same logic in this change, because a
  concurrent pull request is editing `transports/file.py`; moving it onto the helper is a follow-up.
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
  message's own separators, scope it to one repetition when asked, and still refuse CR and LF.
  -> `tests/test_data_never_becomes_structure.py::test_set_data_reads_the_messages_own_separators`
  -> `tests/test_data_never_becomes_structure.py::test_set_data_scopes_to_one_repetition_and_leaves_the_others`
  -> `tests/test_data_never_becomes_structure.py::test_set_data_still_refuses_a_segment_separator`
- **AC-5** -- WHERE a config module writes a literal leaf read into a literal whole-field path with
  `set`, THE SYSTEM SHALL report a `leaf-to-whole-field` advisory finding, and SHALL NOT report one
  for `set_data`, a leaf destination, a whole-field source or a dynamic path.
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_flags_a_decoded_leaf_written_to_a_whole_field`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_follows_a_name_bound_in_the_same_scope`
  -> `tests/test_data_never_becomes_structure.py::test_the_lint_does_not_flag_safe_or_unknowable_shapes`
- **AC-6** -- WHEN the Steps view inserts a Copy Field from a literal leaf, THE SYSTEM SHALL emit
  `set_data` and read the line back as the same `copy_field` row.
  -> `tests/test_data_never_becomes_structure.py::test_the_lens_inserts_a_copy_from_a_leaf_with_set_data_and_reads_it_back`
  -> `tests/test_data_never_becomes_structure.py::test_the_lens_keeps_set_for_a_whole_field_or_an_expression_source`
- **AC-7** -- WHEN the delimiter override meets a target delimiter inside a leaf, THE SYSTEM SHALL
  escape it with the target escape character, so the downstream parse reads the fields the engine
  saw.
  -> `tests/test_data_never_becomes_structure.py::test_P3_a_literal_target_field_separator_stays_inside_its_field`
  -> `tests/test_data_never_becomes_structure.py::test_every_target_delimiter_found_in_a_leaf_is_escaped`
  -> `tests/test_data_never_becomes_structure.py::test_escapes_and_structure_survive_the_slow_path`
  -> `tests/test_data_never_becomes_structure.py::test_an_override_that_only_renames_separators_takes_the_plain_translate`
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
  message over on its own, in file order, and SHALL leave the file in place when a stop arrives
  part-way.
  -> `tests/test_data_never_becomes_structure.py::test_the_remote_file_source_splits_a_batch_like_the_file_source`
  -> `tests/test_data_never_becomes_structure.py::test_a_stop_part_way_through_a_remote_batch_leaves_the_file`
  -> `tests/test_data_never_becomes_structure.py::test_split_batch_bytes_splits_a_batch_and_hands_one_message_over_untouched`
- **AC-12** -- THE SYSTEM SHALL leave the File source's batch split unchanged.
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
`ERROR`.

**Negative / risks** -- Rule 3 is advisory: a Handler author can still write the unsafe form, and
the lint sees only literal paths. A partner that reads a target-set escape it did not expect would see
the escape rather than a split field, which is the point. A Handler can still send two messages in one
payload; see the `encode_batch` finding.

**Out of scope** -- A delivery refusing a payload holding more than one `MSH`. Moving the File source
onto `split_batch_bytes`. Pinning inbound separators per connection. The `FHS`/`BHS` header lines
`encode_with_separators` rewrites, which keep their python-hl7-parity shape. The `escape_leaf` defect
with a letter separator, which is fixed on ADR 0205's branch.
