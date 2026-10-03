# 0205 -- An outbound frame holds exactly one message

- **Status:** Accepted (2026-10-02, on build; decision delegated by the owner under the driver rule and taken by the batch 186 Manager; the owner may overrule at review)
- **Date:** 2026-10-02
- **Related:** vault BACKLOG #2557 (the defect this closes), #2558, #2559 and #2560 (the same family:
  message data becoming structure), #2562 (the permanent failure class), [ADR 0067](0067-persistent-outbound-mllp.md)
  (persistent MLLP), [ADR 0054](0054-low-allocation-builtins-hl7-parser.md) (the built-in tolerant parser),
  [ADR 0124](0124-outbound-mllp-fire-and-forward-no-wait-for-ack-delivery-on-write.md) (no-ack MLLP), CLAUDE.md section 2 (the
  reliability and count-and-log invariants), ASVS chapter 1

Built with the change, in the same pull request. The engine repository is public, and this record
describes a defect in the shipped code, so it lands with its fix rather than ahead of it. With zero
deployments (CLAUDE.md section 0), nothing below is a live exposure: each defect is what a deploying
site would have hit.

---

## Context

`FrameCodec.frame` in `messagefoundry/framing.py` wraps a payload as start byte, payload, end byte.
It does not look inside the payload. Before this change nothing upstream looked either: ingress
refused only NUL, and `Message.set` refused only CR and LF.

The injection audit of 2026-10-01 found three routes that put a frame byte in an outbound payload,
and reproduced each at the parser, the model and the codec.

1. **Across framings.** A body that arrives over the HTTP listener, the File source or a differently
   framed TCP source can hold the raw MLLP end and start bytes. An MLLP outbound would have emitted
   two complete frames. The reverse also held: the STX/ETX bytes in an `hl7v2` body toward an
   `stx_etx` TCP outbound.
2. **A Handler edit.** A body holds HL7 hex escapes for those bytes. `unescape` decodes them, and a
   read-modify-write of that component (`convert_case`, `copy_field`) wrote them back raw. Two
   complete frames. A hex-escaped NUL re-entered past the ingress NUL guard the same way.
3. **Plain pass-through.** An MLLP frame keeps an embedded start byte as data
   (`FrameDecoder.feed`), so a pass-through would have emitted one frame with a second start byte in
   the middle. The engine's own decoder reads one frame there; a receiver that resynchronises on a
   start byte would read a second message.

The invariants this breaks, from [CLAUDE.md](../../CLAUDE.md) section 2, verbatim:

> **Count-and-log invariant (do not break):** **every received message is persisted before the ACK**
> (status `RECEIVED` at the ingress stage), so inbound counts still reflect the true received volume
> and nothing is accepted-and-dropped.

Both it and the reliability invariant assume one outbound row is one delivered message. A forged
second message would have reached the downstream system with no disposition of its own, never
routed, filtered or counted.

## Decision

**One outbound frame holds exactly one message, on every transport that frames.** Five rules, built
as the accepted draft wrote them except where a point below says otherwise.

1. **A delivery never frames a payload that holds the codec's own start or end byte.**
   `frame_for_delivery` in `messagefoundry/transports/framing.py` encodes the payload, checks the
   encoded bytes for the codec's start and end byte, and refuses; it never strips or escapes. It
   holds for every codec, preset or explicit. `FrameCodec.frame` itself is unchanged, because it
   also serves a client (the test harness) that frames hostile bytes on purpose.
   - *Added 2026-10-03 (ASVS 1.1.2).* The judgement itself, which byte, at which position, and the
     refusal's wording, moved to the client-importable leaf as `FrameCodec.find_frame_byte`, with
     `FrameCodec.neutralise` for the reply path below. `check_frame_bytes` and `frame_reply`
     delegate to them with no change in behaviour, so the engine and the test harness hold one
     definition. The harness refuses with `FrameCodec.frame_checked` and neutralises with
     `FrameCodec.frame_neutralised` (MLLP wrappers of both are in `messagefoundry.mllpcodec`). The
     harness modules that still frame with the bare `frame`, on purpose, are named once, in
     `_DELIBERATE` in `tests/test_harness_frame_bytes.py`.
   - *Deviation from the draft, and why.* The draft put the check in a wrapper "that all six send
     paths call". The build frames **once, in `send()`, before any dial**, and passes the framed
     bytes to the six paths (`_send_once`, `_send_once_no_ack`, `_send_persistent`,
     `_send_persistent_no_ack` in `transports/mllp.py`; `_send_once`, `_send_persistent` in
     `transports/tcp.py`), which now only write them. No path can frame on its own, a refused
     payload opens no connection, and a refusal cannot discard a healthy persistent connection,
     which a check inside the persistent path's `try` would have done.
   - The check is on **bytes**, after the encode, because a receiver's decoder scans bytes. For a
     single-byte charset or UTF-8 and the shipped presets that is the same as a character check; for
     an explicit codec byte above `0x7F` it is the only correct one.
   - The encode goes through the existing `encode_wire_body`, so a payload the charset cannot hold
     is the same content-free permanent failure other destinations already raise. Before this change
     it escaped from `frame()` as a bare `UnicodeEncodeError`.
   - *Added 2026-10-02, in review.* The check alone is `check_frame_bytes` in the same module, and
     the MLLP and TCP destinations offer it as `check_frame`, a no-op hook on `DestinationConnector`
     that only they override. The delivery stage calls it where no
     single-payload `send()` runs: on each member of an MLLP batch before the envelope is built,
     and on a simulate (shadow) outbound, which never calls `send()`. `send()` still checks the
     bytes it frames. For a shadow single send, MLLP's `check_frame` judges the payload after the
     same delimiter rewrites `send()` applies (`encoding_characters`, `hl7_raw_separators`),
     which drop a frame byte at either end, and the shadow path re-attaches a detached document
     first, so it sees the bytes a live send would frame. Shadow mirrors rule 1 only: a re-attach
     or rewrite failure there is skipped and the row completes, as before this change, although a
     live send would retry it. A batch member is judged as it sits in the envelope, with no rewrite
     (`rewrite=False`), because `send()` rewrites the whole envelope and the envelope carries each
     member as stored. A member's refusal is dead-lettered only after the rest of the batch is
     resolved, or before a lane stop, so a store fault there cannot reach the clean members. A
     refusal that is not permanent is the whole batch's, as from `send()`.
2. **A leaf write through the HL7 model never emits a raw control character.** On a component or
   subcomponent write, each C0 control character and DEL except TAB is written as an HL7 hex escape
   (`\X0B\`, uppercase digits), so a value that arrived hex-escaped leaves hex-escaped. CR and LF
   keep today's refusal. The one implementation is `escape_leaf` in
   `messagefoundry/parsing/_builtin_hl7.py`: one `str.translate` pass over a table cached per
   separator set, so nothing it inserts is scanned again. *Corrected 2026-10-02 in review:* the
   build first chained one `str.replace` per character. That rescanned its own escapes, so with
   MSH-2 `F~\&` (component separator `F`) a write of `a|b` came out `a\\S\\b` and read back
   `aSb`. One residual stays open: when a separator is a letter or digit an escape is made of,
   the escape that holds it (`\F\` under component separator `F`) is split on re-parse, because
   the parser splits a field on its separators before it unescapes. So a write of `a|b` there
   still changes structure at the receiver. A hex escape of the character, or refusing the write,
   would close it; this build does neither, and MSH-2 is sender-controlled. `Message._escape_leaf` and the DICOM mapper's `_escape_leaf` delegate to it, so
   the three escapers the draft named cannot drift. The alphabet comes from
   `messagefoundry/controlchars.py`, scanned to U+00FF as the log scrub table is, so a deliberate
   widening there reaches this table too.
3. **A whole-field write, `add_repetition` and `add_segment` refuse `0x0B`, `0x1C` and NUL**, with a
   `ValueError`, as they refuse CR and LF. Other C0 characters pass as before.
4. **Ingress refuses an `hl7v2` body that holds `0x0B` or `0x1C` inside the message**, that is,
   anywhere but the whitespace at either end. The refusal is in `check_decoded` in
   `messagefoundry/pipeline/ingress_guards.py`, the guard at least both live listeners, the dry-run
   and the operator resend share. A resend with no inbound to guard for
   (`admit_resubmitted_body(raw, None)`) applies only the engine-wide rules, as it did before, and
   so skips this one. It is `IngressFrameByteRejected`, a sibling
   of the NUL refusal under a new base, `IngressBodyRejected`. A listener with an ACK channel answers
   `AR` with the fixed MSA-3 text `MLLP frame byte in body` and records `ERROR`; a source with no ACK
   channel records `ERROR` alone. With rule 1, this is what closes route 3: a rule about a second
   `MSH` does not, because the parser reads the smuggled header as a segment whose id begins with the
   start byte.
5. **A refusal at rule 1 is a permanent delivery failure**, through the existing class:
   `NegativeAckError(permanent=True)`, with `code="framing"`. The delivery worker dead-letters the
   row at once. A refusal at a model write is a `ValueError`, which the transform records as `ERROR`.

### The three open points, settled

**A frame byte in the whitespace around the message stays tolerated, at either end.** In Python
both `0x0B` and `0x1C` are whitespace. `Peek.parse` skips the leading run with `str.lstrip()`, the
built-in parser strips both ends with `str.strip()`, and neither run is encoded (audit probe P16,
re-measured on this build). So a frame byte there cannot carry a second message and never reaches a
delivery. An MLLP frame saved whole to a file, start byte to trailer, is the realistic shape, and it
is accepted. The two tests that pin the
tolerance keep passing unchanged: `test_guard_admits_what_peek_parse_admits_and_the_sniff_refuses` in
`tests/test_resend_ingress_guards.py` and `test_looks_like_hl7_accepts_valid_headers` in
`tests/test_asvs_phase0.py`. The stored raw does keep a frame byte at either end, because the
listener stores the decoded text as received. That is safe because pass-through sends the encoded
message, not the stored raw. A raw-forwarding path that sent the stored raw of a body ending in
`0x1C` would dead-letter it at rule 1 (2026-10-02, in review:
`test_a_trailing_frame_byte_is_received_and_kept_in_the_stored_raw` pins it).

*Everything inside is refused, blank lines included.* On this build a frame byte on a blank line
between segments survives the encode as data, so the line between tolerated and refused is exactly
the strip the parser applies. The check calls `str.strip()` itself, and only once a frame byte is
known to be present, so a clean body costs two scans and no copy. *Corrected during the build:* a
first cut tolerated the leading run only, on a mistaken reading that a trailing frame byte survives
the encode; the code review measured that it does not.

**The reply path neutralises; it never refuses.** `frame()` also framed listener replies: the
handler-fault NAK and the per-frame reply in `transports/mllp.py`, and the reply write in
`transports/tcp.py`. Every one of those replies is engine-built (`build_ack`); no Handler-supplied
reply body reaches an MLLP or TCP listener today. But `build_ack` echoes header values from the
inbound message with only CR and LF removed, and an inbound MLLP body can hold a raw start byte, so
an echoed control id could have carried a second start byte into the reply. A raise there would come
after the commit and leave the sender with no reply. So all three now frame through `frame_reply`,
which replaces each of the codec's start and end bytes with a space (what the ACK builder already
puts in place of an echoed CR or LF), logs a content-free warning, and frames. The sender still gets
exactly one frame; an echoed control id that held a frame byte simply stops matching.

**The hex escape's meaning.** HL7 v2 section 2.7 defines the syntax of `\Xdddd...\` (pairs of hex
digits, each an 8-bit value) and leaves the interpretation of the data to agreement between the
sending and receiving applications. That was the reviewer's recollection, and it holds. The engine
already fixed its own reading: `unescape` decodes each pair to one character, U+0000 to U+00FF. Rule 2
writes the exact inverse, so a value round-trips through the engine unchanged. The cost falls on a
partner that cannot decode a hex escape: where an edited value used to reach it as a raw control
character, it now sees `\X01\`. For the two frame bytes that is the fix itself, since MLLP cannot
carry them raw. For the other C0 characters it is a behaviour change, accepted on purpose, and the
existing `hl7_raw_separators` escape hatch does not reverse it (it emits only the four structural
separators raw).

## Acceptance Criteria

- **AC-1** -- IF an outbound payload's encoded bytes hold the codec's start or end byte, THEN THE
  SYSTEM SHALL refuse it with `NegativeAckError(permanent=True)` naming the byte and its position
  and no content, for MLLP, STX/ETX and an explicit codec (audit probes P1, P1 reverse, P15).
  -> `tests/test_one_frame_one_message.py::test_a_frame_byte_in_the_payload_is_a_permanent_refusal`
- **AC-2** -- WHEN any of the four MLLP send modes or the two TCP send modes delivers such a payload,
  THE SYSTEM SHALL refuse it before opening a connection.
  -> `tests/test_one_frame_one_message.py::test_all_four_mllp_send_paths_refuse_before_any_dial`,
  `tests/test_one_frame_one_message.py::test_both_tcp_send_paths_refuse_before_any_dial`
- **AC-3** -- WHEN a payload holds no frame byte, THE SYSTEM SHALL frame it byte for byte as before.
  -> `tests/test_one_frame_one_message.py::test_a_clean_payload_frames_exactly_as_before`
- **AC-4** -- IF a payload cannot be encoded in the destination's charset, THEN THE SYSTEM SHALL
  refuse it with the content-free permanent `encoding` failure.
  -> `tests/test_one_frame_one_message.py::test_an_unencodable_payload_is_the_content_free_permanent_refusal`
- **AC-5** -- WHEN a Handler edits a component that arrived holding hex-escaped frame bytes or NUL,
  THE SYSTEM SHALL write them back hex-escaped, and a message so edited SHALL frame as one message
  (audit probes P2 and P10).
  -> `tests/test_one_frame_one_message.py::test_P2_a_hex_escaped_frame_byte_survives_a_component_edit_escaped`,
  `tests/test_one_frame_one_message.py::test_P2_a_hex_escaped_nul_does_not_re_enter_raw`,
  `tests/test_one_frame_one_message.py::test_P10_mllp_in_edit_mllp_out_is_one_frame`
- **AC-6** -- WHEN a leaf write holds a C0 character or DEL other than TAB, THE SYSTEM SHALL write it
  as a hex escape in all three leaf escapers, and SHALL keep refusing CR and LF.
  -> `tests/test_one_frame_one_message.py::test_every_leaf_escaper_hex_escapes_c0_and_del_except_tab`,
  `tests/test_one_frame_one_message.py::test_P2_control_a_decoded_cr_is_still_refused`,
  `tests/test_one_frame_one_message.py::test_the_structural_escapes_are_unchanged`
- **AC-7** -- IF a whole-field write, `add_repetition` or `add_segment` holds `0x0B`, `0x1C` or NUL,
  THEN THE SYSTEM SHALL raise `ValueError` and write nothing.
  -> `tests/test_one_frame_one_message.py::test_writes_that_take_structure_refuse_frame_bytes_and_nul`,
  `tests/test_one_frame_one_message.py::test_other_c0_characters_still_pass_a_whole_field_write`
- **AC-8** -- IF an `hl7v2` body holds `0x0B` or `0x1C` inside the message, THEN THE SYSTEM
  SHALL record `ERROR` with the fixed reason, answer `AR` where it has an ACK channel, and the
  dry-run SHALL preview the same reason (audit probe P15).
  -> `tests/test_one_frame_one_message.py::test_ingress_refuses_an_embedded_frame_byte`,
  `tests/test_one_frame_one_message.py::test_P15_the_listener_naks_and_records_error`,
  `tests/test_ingress_guard_parity.py::test_the_listener_and_the_dry_run_refuse_with_the_same_reason`
- **AC-9** -- WHEN an `hl7v2` body's frame bytes sit only in the whitespace at either end, THE SYSTEM
  SHALL accept it, and the encode SHALL hold no frame byte.
  -> `tests/test_one_frame_one_message.py::test_a_frame_byte_around_the_message_stays_tolerated_and_never_reaches_the_encode`,
  `tests/test_one_frame_one_message.py::test_a_leading_frame_byte_is_still_received`
- **AC-10** -- WHEN a listener's reply holds the codec's start or end byte, THE SYSTEM SHALL send one
  frame with each such byte replaced by a space, and SHALL NOT raise.
  -> `tests/test_one_frame_one_message.py::test_frame_reply_neutralises_a_frame_byte_instead_of_raising`,
  `tests/test_one_frame_one_message.py::test_the_mllp_listener_sends_one_frame_when_its_reply_holds_a_start_byte`,
  `tests/test_one_frame_one_message.py::test_the_mllp_handler_fault_nak_is_one_frame_when_the_header_holds_a_start_byte`,
  `tests/test_one_frame_one_message.py::test_the_tcp_listener_sends_one_frame_when_its_reply_holds_its_start_byte`
- **AC-11** -- WHEN MLLP framing bytes arrive in a body over the File or MLLP inbound of the test
  harness's hostile graph, THE SYSTEM SHALL record `ERROR` (with a NAK over MLLP) and deliver
  nothing. The harness scenario this promotes was a strict known-defect xfail before this change.
  -> `tests/test_harness_scenarios.py::test_every_registered_scenario_passes_against_the_real_graph`
- **AC-12** (*added 2026-10-02, in review*) -- IF one member of an MLLP batch holds the codec's start
  or end byte, THEN THE SYSTEM SHALL dead-letter that member alone, permanently and with
  content-free text, and SHALL send the rest as one envelope.
  -> `tests/test_outbound_batch.py::test_a_member_holding_a_frame_byte_is_dead_lettered_alone`,
  `tests/test_outbound_batch.py::test_a_batch_whose_every_member_holds_a_frame_byte_sends_nothing`
- **AC-13** (*added 2026-10-02, in review*) -- WHEN an MLLP or TCP outbound runs in simulate
  (shadow) mode, THE SYSTEM SHALL record the disposition rule 1 would give a live send.
  -> `tests/test_one_frame_one_message.py::test_a_shadow_outbound_records_what_a_live_send_would`,
  `tests/test_outbound_batch.py::test_a_member_holding_a_frame_byte_is_dead_lettered_alone`

Every criterion's test except AC-3 and the controls failed on the code before this change, measured
by running them against `origin/main` `ed2b60bf89` with the new names stubbed to the old behaviour.
The AC-12 and AC-13 tests, except the clean-payload control, failed on this branch at `94c0daaad9`,
before the review round.

## Options considered

1. **Refuse at delivery, escape at the model write, refuse at ingress, neutralise the reply.**
   **CHOSEN.**
2. **Escape at the framer.** MLLP has no escape mechanism, so the framer cannot make a delimiter byte
   safe. Rejected.
3. **Strip the bytes.** That changes clinical data silently and hides the attempt. Rejected for
   payloads. The reply is the one place bytes are replaced, because the reply is engine-built, goes
   back to the sender and is never stored as the message.
4. **Guard at ingress only.** It does not close the hex-escape route or the reverse direction of
   route 1. Rejected as the sole guard.
5. **Refuse control characters on a leaf write, as CR and LF are refused.** Simpler, and it turns a
   faithful round trip into an `ERROR`. Rejected in favour of the escape.
6. **Also hex-escape CR and LF on a leaf write.** Consistent, but it changes behaviour tests pin.
   Left out on purpose, as the draft said.
7. **Refuse in the reply path.** It would raise after the commit with no reply to the sender, who
   would re-send. Rejected.

## Consequences

**Positive** -- Every frame a delivery writes holds exactly one message, on every transport that
frames. For a single send that frame is one outbound row. For an MLLP batch (ADR 0082) it is one
`BHS` envelope holding N rows, and each member is checked on its own first: a member that holds a
frame byte is dead-lettered alone and the rest batch (*corrected 2026-10-02, in review:* this line
read "one outbound row is one frame holding one message", which a batch never was, and the build
first dead-lettered all N rows on one envelope offset). A shadow outbound records the same
dispositions a live one would. A hex-escaped control character survives a Handler edit unchanged where it used to be silently
decoded. A frame-byte refusal is visible at once in the dead-letter queue. A payload the charset
cannot hold is now a content-free permanent failure on MLLP and TCP too.

**Negative / risks** --

- An inbound `hl7v2` body with an embedded `0x0B` or `0x1C` is refused where it was accepted. With no
  deployments there is no feed to break.
- A raw C0 character other than the two frame bytes still passes through an unedited message. This
  decision does not promise otherwise.
- A whole-field write of a value holding `0x0B`, `0x1C` or NUL now raises, so the transform
  records `ERROR` for that message. It is reachable: `copy_field` from a component to a whole field
  reads the component decoded, so a hex-escaped frame byte in the source, which rule 4 admits,
  reaches the refusal. That is fail-closed, an `ERROR` rather than a forged frame, and it is the
  shape #2558 changes when `copy_field` escapes a decoded leaf (draft 2).
- Rule 4 covers `hl7v2` bodies and MLLP's two bytes only. Rule 1 alone catches the rest, at delivery,
  after the ACK, as a dead-letter: a raw-TCP or X12 body holding the outbound codec's bytes, and an
  `hl7v2` body holding another codec's bytes, such as `0x03 0x02` toward an `stx_etx` outbound.
- A partner that cannot decode a hex escape now sees `\Xhh\` where an edited value once carried a raw
  control character.
- *2026-10-02, in review:* `internal_error = "stop"` no longer halts the lane for an MLLP or TCP
  payload the destination's charset cannot hold. That payload is now a permanent
  `NegativeAckError` with `code="encoding"` and is dead-lettered, as it already was on the other
  connectors that encode through `encode_wire_body`. Before, the bare `UnicodeEncodeError` reached the internal-error
  policy, and its text, with the character that failed, went into `last_error`; that leak is closed.
- *2026-10-02, in review:* the loopback re-ingress of a captured reply
  (`_process_response_item` in `pipeline/wiring_runner.py`) checks only the size, never
  `check_decoded`, so rule 4 does not run there. Rule 1 still blocks the bytes at egress. The same
  gap already held for NUL before this change.
- *2026-10-02, in review:* a direct edit-and-resend with no inbound to guard for
  (`admit_resubmitted_body(raw, None)`) skips rule 4, so a body with an embedded frame byte is
  admitted there and would dead-letter at rule 1 on an MLLP or TCP outbound instead.
- *2026-10-02, in review:* rule 4 refuses any `hl7v2` body with an interior `0x0B`, whatever the
  destination, even a File or database outbound that could carry it. A likely real source is OBX-5
  text pasted from Microsoft Word, whose soft line break (Shift+Enter) is `0x0B`. Such a message is
  `ERROR` at ingress.
- *2026-10-02, in review:* a File capture holding several saved MLLP frames back to back is not split
  into messages: the batch splitter in `parsing/split.py` splits only where a CR is followed by
  `MSH`, and a saved frame puts its start byte between them. Its interior frame bytes then make
  rule 4 refuse it whole. Before this change it was accepted as one
  merged message, silently.

**Out of scope** --

- The dry-run, `messagefoundry check` and the Test Bench do not run `frame_for_delivery`, so a
  payload a live MLLP or TCP outbound would refuse at rule 1 previews as a delivery. Rule 4 means an
  `hl7v2` inbound toward an MLLP outbound that sends the parsed message previews correctly. The gap
  is a non-HL7 payload, another codec's bytes toward a TCP outbound, and (*qualified 2026-10-02, in
  review*) a Handler that sends a `str` or a `RawMessage` it built holding a raw `0x0B` or `0x1C`:
  that previews clean and dead-letters live. Filed as vault #2824.
- *2026-10-02, in review:* a shadow (simulate) outbound and each member of an MLLP batch now run
  rule 1's check too, through the destination's `check_frame` hook, so neither previews
  or batches what a live single send would refuse. That is the delivery stage, not the dry-run, so
  it does not close vault #2824.
- On a persistent connection that a reload is closing, a payload refused at rule 1 dead-letters
  rather than retrying on the replacement connector, because the framing runs before the
  closed-connector check. Only a reload that changes the outbound's charset or framing could make
  the replacement accept it.
- The test harness builds its hostile messages through the model, which no longer writes a raw
  frame byte or NUL, so it now puts those bytes back after the encode, in place of a placeholder.

- The ingress **summary** still decodes a hex-escaped NUL, `0x0B` or `0x1C` to the raw character,
  because `summarize` reads unescaped fields. That is a read-side path into the store, not into a
  frame, and none of the five rules reaches it. It is left for its own item.
- The ACK side on a persistent MLLP connection was not analysed further. Rule 1 means a forged
  second frame never leaves, so it cannot draw a second ACK.
- A second `MSH` inside one message, and data becoming structure through `copy_field` or the
  delimiter override, are #2560, #2558 and #2559.
