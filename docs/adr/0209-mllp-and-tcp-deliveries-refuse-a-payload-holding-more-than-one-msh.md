# 0209 -- MLLP and TCP deliveries refuse a payload holding more than one MSH

- **Status:** Accepted (2026-10-17, on build; decision delegated by the owner under the driver rule and taken by the batch 265 Manager; the owner may overrule at review)
- **Date:** 2026-10-17
- **Related:** vault BACKLOG #2858 (the item this closes), #2560 (the inbound refusal),
  #134 (outbound batch aggregation), [ADR 0206](0206-an-hl7-write-or-re-encode-never-lets-data-become-structure.md)
  (rule 5, the inbound half, which defers this decision), [ADR 0205](0205-an-outbound-frame-holds-exactly-one-message.md)
  (one outbound frame holds one message; the check this one sits beside),
  [ADR 0082](0082-outbound-batch-aggregation.md) (the `BHS` batch envelope),
  [ADR 0204](0204-a-delivery-the-message-itself-makes-impossible-uses-the-permanent-failure-class.md)
  (a delivery the message itself makes impossible is a permanent failure), CLAUDE.md section 2 (the count-and-log invariant)

Built with the change, in the same pull request. With zero deployments (CLAUDE.md section 0),
nothing below is a live exposure: it is what a deploying site would have hit.

---

## Context

ADR 0206 rule 5 makes the MLLP, TCP and HTTP listeners refuse an inbound `hl7v2` body holding more
than one `MSH`, and the File and remote-file sources split one. Its section *What `encode_batch`
does with a member holding a second `MSH`* names what is left: a Handler that returns one `Send`
whose payload holds two messages, as text or as a `Message` parsed from such text. ADR 0206 leaves
whether a delivery refuses that payload to its own item, which is this one.

Before this change nothing on the outbound side looked. `MLLPDestination.send` and
`TcpDestination.send` framed the payload they were given, so two messages went out as one frame
under one acknowledgement. A receiver that splits on `MSH` would read two messages, and the
engine's count of what it sent would be one short: one outbound row, one disposition, two
messages. That breaks the reading of the count-and-log invariant ADR 0205 relies on, that one
outbound row is one delivered message. A Handler bug or a pasted batch is the realistic cause.

## Decision

**An MLLP or TCP delivery refuses a payload whose first segment is `MSH` and that holds a second
`MSH`.**

1. **Which payload.** One that opens with `MSH` after whitespace and any byte order mark
   (U+FEFF), and holds another line that starts with `MSH`. The mark is read past because
   `split_batch` reads past it too, and a receiver that drops it reads the messages behind it,
   although the engine's own parser refuses a body it leads. A line break is a CR or an LF, so a
   payload with LF or CRLF segment ends is read the way a receiver that normalizes them reads it. The reading is ADR 0206's: `_holds_more_than_one_message`, the ingress guard's,
   moved unchanged from `pipeline/ingress_guards.py` to `parsing/split.py` beside `_MSH_BOUNDARY`.
   The delivery's `_sends_more_than_one_message` sits beside it. It is the same reading on a
   payload that is not normalized, with searches that stop at the first hit, and a test holds the
   two to one answer on the normalized text of every shape it tries. The ingress guard reads
   normalized text, so it keeps its CR-only count and pays no LF scan.
2. **The refusal.** `NegativeAckError(permanent=True)` with `code="multiple-messages"`
   (`MULTIPLE_MESSAGES_CODE` in `transports/framing.py`), so the delivery worker dead-letters the
   row at once (ADR 0204). The text names the transport and the rule, never message content.
3. **Where.** In `check_frame_bytes` in `transports/framing.py`, before the encode. The MLLP and
   TCP outbound connections reach it on at least three paths: `send()` through
   `frame_for_delivery`, before any dial, and `check_frame` for each batch member and for a
   shadow (simulate) outbound. So those three give one answer, and a refused payload opens no
   connection. On MLLP it judges the payload after the
   delimiter rewrites `send()` applies, as ADR 0205 rule 1 does. A rewrite keeps each `MSH` line,
   so a two-message payload the rewrite accepts is refused with this code under
   `encoding_characters` and `hl7_raw_separators` too; a test pins both. A payload the rewrite
   itself refuses, such as one whose second message holds a target delimiter as data, keeps the
   rewrite's code, `reencode`, because the rewrite runs first.
4. **Batch members are judged as stored** (`rewrite=False`), before the envelope is built. A
   member holding two messages is dead-lettered alone and the rest batch, so `BTS-1` again counts
   the messages the envelope holds.
5. **No batch-sender opt-out.** On MLLP, batch sending already exists through ADR 0082
   aggregation. Its envelope opens with `BHS`, not `MSH`, so the refusal never reads it. TCP has
   no batch aggregation (wiring refuses `batch` on anything but MLLP), so a TCP partner that takes
   several HL7 messages per frame has no sanctioned path; the one left is a Handler-built envelope,
   under rule 6. That cost is accepted: no such partner is known, and an opt-out would be a second
   batch path with no `BTS-1` count.
6. **Only an `MSH`-led payload is read.** A relayed X12 interchange over TCP, or any other opaque
   payload, is never refused by this rule, whatever lines it carries. So is a Handler-built
   payload that opens with `FHS`, `BHS` or another segment: an envelope is a batch its author
   declared, and this rule does not check its `BTS-1`. That holds for a batch member too, so a
   member led by anything but `MSH` is carried into the envelope whatever it holds.

**Out of scope, on purpose.** HTTP outbounds, which do not frame. An HL7 body holding two messages
POSTed over HTTP still reaches its receiver as one delivery, the count gap this ADR closes for
MLLP and TCP; the engine's own HTTP listener refuses that body (ADR 0206 rule 5). File and
remote-file outbounds, which may legitimately write a batch file.

## Acceptance Criteria

- **AC-1** -- IF an MLLP or TCP delivery's payload opens with `MSH` and holds a second `MSH` line,
  with CR, LF or CRLF line ends, leading whitespace or a leading byte order mark, THEN THE SYSTEM SHALL refuse it before any
  dial, on all four MLLP send paths and both TCP send paths, with `NegativeAckError(permanent=True)`,
  code `multiple-messages`, and text that holds no message content.
  -> `tests/test_one_frame_one_message.py::test_all_four_mllp_send_paths_refuse_two_messages_before_any_dial`,
  `tests/test_one_frame_one_message.py::test_both_tcp_send_paths_refuse_two_messages_before_any_dial`
- **AC-2** -- WHEN the payload holds one message, THE SYSTEM SHALL frame it as before (control).
  -> `tests/test_one_frame_one_message.py::test_the_mllp_send_control_frames_one_message`,
  `tests/test_one_frame_one_message.py::test_the_tcp_send_carries_one_message_and_an_opaque_relay`
- **AC-3** -- WHEN a TCP outbound relays an X12 interchange, or a payload not led by `MSH`, THE
  SYSTEM SHALL send it.
  -> `tests/test_one_frame_one_message.py::test_the_tcp_send_carries_one_message_and_an_opaque_relay`
- **AC-4** -- WHEN `check_frame` judges such a payload, with or without the MLLP rewrite, THE
  SYSTEM SHALL refuse it as `send()` does, and a shadow outbound SHALL dead-letter it.
  -> `tests/test_one_frame_one_message.py::test_check_frame_refuses_two_messages_as_a_send_does`,
  `tests/test_one_frame_one_message.py::test_a_shadow_outbound_records_what_a_live_send_would`
  (its `two-messages` row)
- **AC-5** -- IF one member of an MLLP batch holds two messages, THEN THE SYSTEM SHALL dead-letter
  that member alone with content-free text and send the rest as one envelope, live and in shadow.
  -> `tests/test_outbound_batch.py::test_a_member_holding_two_messages_is_dead_lettered_alone`
- **AC-6** -- WHEN an MLLP batch is sent through the real `send()`, THE SYSTEM SHALL frame its
  `BHS`...`BTS` envelope as one frame.
  -> `tests/test_outbound_batch.py::test_the_batch_envelope_still_goes_out_through_the_real_send`
- **AC-7** -- THE SYSTEM SHALL read an outbound payload as the ingress guard reads its normalized
  text, when it opens with `MSH`.
  -> `tests/test_one_frame_one_message.py::test_the_delivery_reading_is_the_ingress_reading_of_an_msh_led_payload`

The AC-1, AC-4 and AC-5 tests failed on this branch with `transports/framing.py` put back to
`origin/main`; the controls passed.

## Options considered

1. **Refuse an `MSH`-led payload at MLLP and TCP delivery, with no opt-out.** **CHOSEN.**
2. **Allow it where the connection is declared a batch sender.** A second way to send a batch, with
   no envelope and no `BTS-1` count, beside ADR 0082's. Rejected.
3. **Split it into N frames.** One outbound row would become N deliveries under one disposition,
   which is the count problem again, and a retry after a partial send would repeat the first
   messages. Rejected.
4. **Refuse on every outbound.** A File outbound may write a batch file on purpose, and an HTTP
   body is not framed. Rejected.
5. **Check only in `check_frame`.** The live single-row path calls `send()`, not `check_frame`, so
   a live send would still have framed two messages. Rejected for the shared check both reach.

## Consequences

**Positive** -- An `MSH`-led MLLP or TCP payload holding a second `MSH` line is refused on a live
send, a batch member and a shadow outbound alike, and a Handler that returns two messages in one `Send` is visible at once in
the dead-letter queue, with a named code.

**Negative / risks** --

- A Handler that meant to send two messages in one frame now dead-letters every such row. It should
  return two `Send`s, or use ADR 0082 batching.
- The check reads the payload twice more per MLLP or TCP delivery, two C-level `str.find` scans
  and no copy; a clean payload scans to its end both times.
- The dry-run, `messagefoundry check` and the Test Bench do not run `frame_for_delivery`, so such a
  payload previews as a delivery and dead-letters live. That is the gap ADR 0205 names, vault #2824.
- A payload led by `FHS` or `BHS` is never read, so a Handler-built envelope with a wrong `BTS-1`
  goes out as written.
- Only a line whose first three characters are `MSH` counts, the parser's reading. A second
  message behind a CR and another character, such as `0x0B` toward an `stx_etx` TCP outbound, or a
  space, is not refused here. A receiver that trims each line would read it as a message.
- An MLLP or TCP inbound whose `content_type` is not `hl7v2` admits a body holding several
  `MSH`-led messages, because ADR 0206 rule 5 guards `hl7v2` only. A pass-through of it to an MLLP
  or TCP outbound now dead-letters, after the sender was acknowledged. Declare such a feed `hl7v2`,
  so it is refused at the listener.
- The dry-run gap above means the error surfaces at delivery, not at the Handler that caused it.
  Checking where a `Send` becomes an outbox row, for MLLP and TCP outbounds, would move it there;
  that is not built.
