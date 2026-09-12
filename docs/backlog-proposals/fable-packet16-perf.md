# Proposed backlog items from Fable review packet 16 (performance and bounded resources)

**These are proposals, not items.** No number is allocated and nothing here is written into
`docs/BACKLOG.md`. The Manager allocates serially after the packets land (owner instruction relayed
2026-09-12) and files from this list. Each proposal is in the house format minus the heading number,
with the duplicate search recorded. The byte-level reproductions are in the vaulted findings document
`docs/reviews/FABLE-PACKET-16-PERF-2026-09-11-FINDINGS.md` (vault branch `vault/fable-packet16-perf`);
this file names the subject, the mechanism and the fix only.

Engine ref measured: `70063ab55`. Every impact claim is conditional: there are zero deployments
(`CLAUDE.md` section 0).

**Findings deliberately not filed**, with the reason: "retention ships off" (owner-ruled twice, #1212
and #179, and auto-bounded on PHI environments; only the row-count point survives, below); queue depth
without a policy ceiling (design under ADR 0001; #1191's proposed work already names the depth bound);
`FileDestination._write` resolving two paths (9 percent of a 2.31 ms write); the estimator's scan cost
(measured within its docstring); the per-message 4x memory peak (a design cost folded into proposal 2);
`_INTAKE_SUCCESS_KEEP_MAX` being unpinned (capped in code, low value).

---

## Proposal 1. X12 frame reassembler: keep a scan offset so reassembly is linear, not quadratic, in interchange size over chunk size

> Filed 2026-09-12 - not started. Found by Fable review packets 1 (P1-02) and 9 (P9-05), re-measured
> unchanged by packet 16 (P16-01). `parsing/x12/interchange.py` `X12FrameReader._take_one` restarts
> `buf.find(b"IEA", 3)` and the segment-terminator walk from the ISA on every `feed()`, and the
> transports feed it from `reader.read(4096)`, so the chunk size is the sender's. Measured at
> `70063ab55`: 8 MiB in 4 KiB chunks 1.67 s; 512 KiB in 16-byte chunks 1.54 s scanning about 8.6 GB;
> one 16 MiB interchange at 16 bytes per read extrapolates to about 26 minutes of event-loop CPU, per
> connection, with `max_connections` 256 in front of it.

**Cluster:** Transports / bounded resources. **Priority:** P2. **Verdict:** build.
**Severity:** medium. A first deployment exposing an X12 listener would let one slow sender hold a core
for most of an hour per interchange, in short slices, slowing every other connection on that loop in
proportion. No message is lost.

**Mechanism.** Each feed appends to the buffer and rescans it from offset 3; total work is the sum of
the buffer lengths at each feed, quadratic in the interchange size divided by the read size.

**Fix.** Keep a scan offset on the reader and resume both the `IEA` search and the terminator walk
from just before the previously scanned end, rewinding by the terminator length plus three bytes.
Local to `_take_one`. Pin it with a test that feeds a 1 MiB interchange 16 bytes at a time under a
time budget.

**Duplicate search.** No open or closed item names the rescan. Searched both ledgers for `X12` with
`rescan`, `quadratic`, `scan offset`, `_take_one`, `reassembl`: zero hits on the combination. #149
(closed, streaming path) and #1191 (open, MLLP availability bound) are adjacent and do not name it.

---

## Proposal 2. MLLP listener: bound the life of an open frame and the connections per host, because `receive_timeout` is per read and a trickling peer holds a slot and a 16 MiB decoder buffer indefinitely

> Filed 2026-09-12 - not started. Found by Fable review packet 16 (P16-02), sharpening packet 2's
> handoff. `transports/mllp.py` `_on_client` applies `receive_timeout` (60 s default) to each
> `reader.read(4096)`, so it bounds silence between reads and not the time from a frame's start byte to
> its end byte. `transports/framing.py` `FrameDecoder.feed` holds up to `max_frame_bytes` (16 MiB) in
> a `bytearray` until the frame ends or overflows. `max_connections` (256) counts sockets, not hosts.
> Measured at `70063ab55`: a peer sending one byte every 0.2 s against `receive_timeout=0.5` kept its
> slot for 3.1 s and was dropped only after 0.8 s of silence; a frame held open at 16.00 MiB traced
> 16.0 MiB and released to 57 bytes on over-cap. So 256 sockets from one host, each holding a frame one
> byte short of the cap and trickling one byte a minute, hold 4 GiB and every slot of that listener.

**Cluster:** Transports / bounded resources. **Priority:** P2. **Verdict:** build.
**Severity:** medium, with a High argument recorded in the findings document. A first deployment on an
8 GB engine host would let one unauthenticated LAN peer take half its memory and all of one listener's
MLLP capacity without sending a message. Nothing is lost or dropped; the cost is availability. #1249
records `receive_timeout` as a shipped concurrency bound; this narrows what it bounds to idle sockets.
Same family as June's M-14 and packet 2's P2-01, which pin a slot by a non-reading peer.

**Mechanism.** The per-read timeout resets on every byte; the decoder buffer is released only on frame
end or over-cap; the slot cap has no per-host term and the source allowlist ships off.

**Fix.** Add a per-connection frame deadline (start byte to end byte, about 60 s at default) beside
the per-read timeout; add `max_connections_per_host` with a default well under 256; consider a
per-listener in-flight ingress semaphore so the aggregate handling peak (measured 64 MiB traced per
16 MiB message on the pre-ACK path, so 10 to 16 GiB computed across 256 in-flight frames) is a setting
rather than a product of two others. Pin the trickle case with a test that sends one byte per 0.2 s
under a 0.5 s timeout and asserts the drop at the frame deadline.

**Duplicate search.** No item names the per-read timeout or the trickle. #1249 (open) lists
`receive_timeout` among four shipped bounds and is about a documented rate limit; #1191 (open, ASVS
15.2.2) proposes a depth bound, not a frame deadline; #1114 (open, ASVS 2.4.1) is message rate; #159
(open) is a no-framing TCP mode. Searched both ledgers for `receive_timeout`, `slowloris`, `trickl`,
`per-read`, `decoder buffer`, `4 GiB`.

---

## Proposal 3. No backend ever deletes a `messages`, `queue` or `message_events` row, so the console's monitoring queries scale with lifetime volume, and #179's premise holds for bytes but not rows

> Filed 2026-09-12 - not started. Found by Fable review packet 16 (P16-03). `store/store.py`
> `purge_message_bodies` blanks `raw`, `summary`, `metadata` and `error` and never deletes the row;
> `DELETE FROM messages` appears zero times in `store.py`, `sqlserver.py` and `postgres.py`; done
> `queue` rows and `message_events` rows are not deleted either. `connection_metrics` (behind
> `/connections` and `/status`) counts and groups every `messages` row received since
> `Engine.started_at`; `stats()` (behind `/stats` and the per-second `/ws/stats` push, up to 64
> sockets) groups every queue row of a stage; the list view paginates with `OFFSET`. Measured at
> `70063ab55` with 100,002 message rows: `connection_metrics(since=0)` 120.5 ms, `stats()` 10.5 ms,
> both linear in rows. Linear extrapolation, stated as such: 30 million lifetime messages would cost
> about 36 s per `/connections` call and about 3 s per stats push, on a read pool of 4.

**Cluster:** Store / monitoring / bounded resources. **Priority:** P2. **Verdict:** build, after
re-reading #179 with this measurement.
**Severity:** medium. A first deployment at the volumes ADR 0051 targets would see the web console's
connection and status pages and every stats socket slow in proportion to lifetime volume with
retention fully configured, and the read pool would saturate before the write path noticed. The hot
path is unaffected: all 22 distinct per-message statements have index-backed plans and per-message
wall time did not move between an empty store and 100,000 rows.

**Mechanism.** Retention bounds bytes at rest (bodies are blanked) and leaves the row count alone;
three operator-facing reads are O(rows).

**Fix.** Either delete rows past the retention window (the audit chain lives in `audit_log`, not
here) or make the monitoring reads independent of lifetime volume: a bounded `since` window for
`connection_metrics`, a maintained per-stage status counter table for `stats()`, keyset pagination in
place of `OFFSET`. Amend #179's premise line either way.

**Duplicate search.** No item records that rows persist past retention. #179 (declined) rests on the
opposite premise; #1212 (closed) is body retention defaults; #135 (open, demand-gate) is the stats
push interval, not its cost; #1421 (open) is the same shape for `audit_log`, which is keep-forever by
design. Searched both ledgers for `rows are never deleted`, `metadata rows`, `purge_message_bodies`,
`connection_metrics`, `started_at`, `stats()`, `ws/stats`, `OFFSET`, `table size`.

---

## Proposal 4. DICOM SCP: bound the received object before decode, because pynetdicom buffers a whole object of any size and `max_object_bytes` applies only after decode and re-encode

> Filed 2026-09-12 - not started. Found by Fable review packet 16 (P16-04), widening packet 9's
> deflate note. `transports/dicom.py` `_on_c_store` checks `len(object_bytes) > max_object_bytes`
> (128 MiB default) after `event.dataset` decodes and `dataset.save_as` re-encodes the object.
> pynetdicom 3.0.4 `dimse_messages.py` `decode_msg` writes every P-DATA fragment into a `BytesIO` with
> no ceiling; `_config.STORE_RECV_CHUNKED_DATASET` defaults `False` and the engine does not set it;
> `max_pdu_size` bounds a fragment, not the object; `max_associations` defaults 10. Measured at
> `70063ab55` with a synthetic event: a 160 MiB object was refused with `0xA700` after a 320 MiB
> traced peak inside the callback, on top of the 160 MiB pynetdicom had buffered and the decoded
> dataset the event holds, about 4x the wire bytes. The wire half is read from the library, not driven.

**Cluster:** Transports / bounded resources. **Priority:** P2. **Verdict:** build.
**Severity:** medium. A first deployment exposing the SCP would let each of 10 associations push an
object of any size into memory four times over before the cap refused it. The transport is opt-in and
carries optional AE-title and source-IP allowlists.

**Fix.** Set `pynetdicom._config.STORE_RECV_CHUNKED_DATASET = True` at SCP start so the receive spools
to a file, or bound the raw `event.request.DataSet` length against `max_object_bytes` before
`event.dataset` is touched, the way `_deflated_over_cap` already does for the deflated syntax. Pin
with a test that hands `_on_c_store` an over-cap raw data set and asserts refusal before decode.

**Duplicate search.** No item names the receive-side buffer. #1129 (open, ASVS 5.2.3) and #1237
(closed) are the deflate ceiling, already built; #1514 (open) is the association pacer's margin.
Searched both ledgers for `STORE_RECV`, `pynetdicom` with `buffer`, `max_object_bytes` with `after`,
`whole object`.

---

## Proposal 5. Shared frame decoder: replace the per-byte Python loop with `bytes.find`, because every inbound MLLP or TCP byte costs about 59 ms of event-loop CPU per MiB

> Filed 2026-09-12 - not started. Found by Fable review packet 16 (P16-05).
> `transports/framing.py` `FrameDecoder.feed` iterates `for byte in data` and appends one byte at a
> time. Measured at `70063ab55`: one 16 MiB frame in 4,096-byte reads cost 0.951 s of loop CPU, 59 ms
> per MiB; each read's slice is about 0.25 ms so the loop never stalls. That is about 17 MiB/s of
> inbound bytes per process before the store is consulted, and about 4 minutes of loop CPU for 256
> peers each sending one 16 MiB frame.

**Cluster:** Transports / performance. **Priority:** P3. **Verdict:** build.
**Severity:** low. Irrelevant for a 2 KiB ADT (0.1 ms); one message per second per process for a
document-carrying feed at the 16 MiB cap.

**Fix.** Rewrite `feed` around `bytes.find` for the start and end delimiters with `memoryview`
slices, keeping the cap check on slice length and the `in_frame` property. Add a throughput test that
feeds 16 MiB in 4 KiB reads under a time budget. The existing decoder tests (which went red under
packet 16's negative control A) pin the semantics.

**Duplicate search.** No item. #149 and #198 (both closed) mention the decoder in passing for
streaming and zeroization. Searched both ledgers for `FrameDecoder`, `byte-by-byte`, `per-byte`,
`bytearray`, `MLLPDecoder`.

---

## Proposal 6. `stream_inflight_budget_bytes` ships as `0`, which means unlimited, while it is documented as the aggregate guard that replaces the frame cap for streaming inbounds

> Filed 2026-09-12 - not started. Found by Fable review packet 16 (P16-06), correcting a sentence in
> packet 3's findings. `config/settings.py` `stream_inflight_budget_bytes: int = 0` with the docstring
> "0 (the default) = unlimited"; `wiring_runner.py` takes `max(0, ...)`. Streaming is per-inbound and
> off by default, so the shipped path never reaches it; an inbound that opts in gets its raised
> `max_message_bytes` as the only bound, times `max_connections`.

**Cluster:** Config / secure defaults. **Priority:** P3. **Verdict:** build.
**Severity:** low. A guard that ships off protects nobody, and a document that says it is on is the
SDS-3.7 shape. Only a deployment that enables streaming is affected.

**Fix.** Default the budget to a multiple of the largest configured `max_message_bytes` whenever any
inbound enables streaming, or reword the setting and the packet 3 sentence to say the bound is
opt-in; refuse `serve` on a PHI-carrying environment when streaming is enabled and the budget is `0`,
the way the retention windows are auto-bounded there.

**Duplicate search.** #149 (closed) introduced the setting and does not name its default; #1191
(open) mentions the 16 MiB ceiling. Searched both ledgers for `stream_inflight_budget`, `inflight
budget`, `streaming budget`.

---

## Proposal 7. `DatabaseLookupExecutor.query`: charge a row ceiling at the fetch, because `fetchall()` buffers every row of a Handler-authored statement in the transform worker

> Filed 2026-09-12 - not started. Found by Fable review packet 9 (P9-12), measured by packet 16
> (P16-07). `transports/database.py` `DatabaseLookupExecutor.query` runs `list(await cur.fetchall())`
> with no row or byte cap, where the DATABASE source bounds the same driver at
> `fetchmany(poll_max_rows)`. Measured at `70063ab55` through a stub pool: 1,000,000 rows buffered 283
> MiB and took 3.9 s in the worker.

**Cluster:** Transports / bounded resources. **Priority:** P3. **Verdict:** build.
**Severity:** low. The statement is operator-authored and parameterized; a broad predicate with a
message-derived parameter is the realistic trigger, and the cost is one transform worker's memory.

**Fix.** A `max_rows` per `DatabaseLookup` connection, defaulting to the source's `poll_max_rows`
family, charged at the fetch with `fetchmany`, raising `DbLookupError` on overflow so the message
takes the existing ERROR path.

**Duplicate search.** No item. Searched both ledgers for `db_lookup` and `DatabaseLookup` with
`fetchall`, `row cap`, `max_rows`, `result set`, `fetchmany`: zero hits on the combination.

---

## Proposal 8. Connection-event capture: batch the drainer's commits and bound `connection_event_retention_hours`, because each event is a standalone commit and the table keeps forever

> Filed 2026-09-12 - not started. Found by Fable review packet 16 (P16-08). `store/store.py`
> `record_connection_event` is one `INSERT` and one `_commit()`; `config/settings.py` ships
> `connection_events = True` and `connection_event_retention_hours = 0` (keep forever), and the
> setting is outside the PHI windows that `serve` auto-bounds. Measured at `70063ab55`: six messages
> over three TCP connections wrote six `connection_event` rows and cost 9.0 commits per message
> against 7 without connection churn. A sender that opens a connection per message, which many legacy
> MLLP senders do, would pay about 29 percent more commits and grow the table by two rows per message
> for the life of the instance. The in-memory queue is bounded at 10,000 and drops on overflow, so
> memory is not at risk.

**Cluster:** Monitoring / store cost. **Priority:** P3. **Verdict:** build.
**Severity:** low. A cost, not a loss. Same shape as #1421's audit_log costs.

**Fix.** Drain the queue in bursts and commit once per burst; give
`connection_event_retention_hours` a bounded default or add it to the auto-bounded windows.

**Duplicate search.** #46 (closed) built the log; #63 (closed) gated `message_events`, not
connection events; #1421 (open) records the same cost family for `audit_log` and does not name this
table. Searched both ledgers for `connection_event` with `commit`, `retention`, `per connection`.

---

## Proposal 9. Retention strip: size an embedded document from its base64 length instead of decoding it

> Filed 2026-09-12 - not started. Found by Fable review packet 1 (note), measured by packet 16
> (P16-09). `parsing/binary.py` `strip_documents_in_hl7` and `_strip_whole_body_mfb64` call
> `len(_b64decode(...))` to learn a document's size before replacing it with a tombstone. Measured at
> `70063ab55`: 70 ms and a 45 MiB traced peak for one 12 MiB document, of which the decode is 20 ms;
> the arithmetic on the whitespace-stripped length gives the same byte count in 10 us.

**Cluster:** Parsing / retention. **Priority:** P3. **Verdict:** build.
**Severity:** low. The strip runs off the hot path; a retention sweep over thousands of documents
would pay about 2 ms and 3x the document's size per document for a number it can compute.

**Fix.** After validating the alphabet, compute `len(compact) * 3 // 4` minus padding; decode only
when the value is not well-formed. Keep the corrupt-value branch that leaves the value for the operator.

**Duplicate search.** #47 (closed) built the pruning; #94 (closed) is BLOB offload. Neither names the
decode. Searched both ledgers for `strip_documents`, `b64decode`, `base64 length`, `tombstone`.

---

## Proposal 10. Pin the X12 open-interchange cap: both oversize tests stayed green with `_check_cap` disabled

> Filed 2026-09-12 - not started. Found by Fable review packet 16's negative control B (P16-10).
> `tests/test_x12_parsing.py` `test_frame_reader_oversize_raises` and `tests/test_x12_transport.py`
> `test_source_drops_oversize_interchange` both feed a complete interchange, so the refusal they see
> is `_take_one`'s second check on a complete frame. The eager `_check_cap`, the only thing that stops
> a peer that never sends an IEA from buffering without bound, is exercised by nothing. Measured at
> `70063ab55`: with `_check_cap` a no-op an open interchange buffered 1,051,706 bytes past a 65,536-byte
> cap with no raise while both tests passed; restored, the same feed raised at 61,706 bytes.

**Cluster:** Test quality. **Priority:** P2. **Verdict:** build.
**Severity:** medium as a test gap: the bound it leaves unpinned is the one that matters, and a
refactor could drop it with the suite green.

**Fix.** One test that feeds an ISA and then body bytes with no IEA past the cap and asserts
`X12FrameError` within one read of the cap.

**Duplicate search.** No item. #149 (closed) is the only hit on `open interchange`. Searched both
ledgers for `_check_cap`, `open interchange`, `oversize` with `X12`.

---

## Proposal 11. Pin the connection-event overflow drop and its counter

> Filed 2026-09-12 - not started. Found by Fable review packet 16's negative control C (P16-11). With
> `_CONN_EVENT_QUEUE_MAX` set to 1 and the overflow arm changed to re-raise, all 11 tests in
> `test_connection_event_emit.py` and `test_connection_event_outbound.py` passed at `70063ab55`;
> `_conn_events_dropped` is asserted in no test file.

**Cluster:** Test quality. **Priority:** P3. **Verdict:** build.
**Severity:** low. The drop is the memory bound for a connection flood; nothing shows it works.

**Fix.** A test that parks the drainer, fills the queue past its cap from a listener, and asserts the
drop count and that the listener loop did not raise.

**Duplicate search.** No item. Searched both ledgers for `_conn_events_dropped`, `QueueFull`,
`10,000-entry`, `event queue`.

---

## Proposal 12. `test_destination_expect_reply_reads_returned_interchange` asserts nothing

> Filed 2026-09-12 - not started. Found by Fable review packet 16's AST scan and confirmed by reading
> (P16-12). In `tests/test_x12_transport.py` the handler returns an interchange, `send(EDI)` runs with
> `expect_reply=True`, and the test ends without capturing the return. It would pass if the
> destination read nothing, read garbage, or returned `None`.

**Cluster:** Test quality. **Priority:** P3. **Verdict:** build.
**Severity:** low.

**Fix.** Capture the return of `send` and assert it equals the interchange the handler returned.

**Duplicate search.** No item. #117 (closed, fire-and-forward) is the only hit on `expect_reply`.

---

## Proposal 13. Pin the commits-per-message model end to end and state that its `N` counts outbound rows

> Filed 2026-09-12 - not started. Found by Fable review packet 16 (P16-13). ADR 0051 and
> `store/store.py` `_commit` write the durable-write model as `3 + 2H + 2N`. Measured at `70063ab55`
> through a real pooled delivery on the store's own `committed_txns` counter: 7 at one handler and one
> destination, exactly the model; 12, 8 and 14 at (H, N) of (2,1), (1,2), (2,2), where the model gives
> 9, 9, 11 with `N` as destinations and 11, 9, 15 with `N` as outbound rows, batch completion shaving
> one. `tests/test_adr0114_claim_fold.py` pins single handoffs at one or two commits; no test drives a
> message through and asserts the total.

**Cluster:** Test quality / documentation accuracy. **Priority:** P3. **Verdict:** build.
**Severity:** low. The number is load-bearing for every throughput argument in ADRs 0051, 0069 and
0107, and a regression that added a commit per message would pass the suite.

**Fix.** One test through `RegistryRunner` asserting `committed_txns` rises by 7 for the base shape,
and a one-line amendment to the model's comment saying `N` counts outbound rows.

**Duplicate search.** #207 (closed) built the harness counters; #209 (closed) taught the ladder that
routed fan-out differs from delivered; #64 (closed) is the roadmap. None pins the engine number.
Searched both ledgers for `3 + 2H + 2N`, `committed_txns`, `commits per message`, `txn/msg`.
