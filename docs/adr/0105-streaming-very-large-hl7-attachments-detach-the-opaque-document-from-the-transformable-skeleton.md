# 0105 — Streaming very-large HL7 attachments: detach the opaque document from the transformable skeleton

- **Status:** Accepted  <!-- Phase 0 (substrate) + Phase 1a (ingress detach) + Phase 1b (delivery re-attach) + Phase 3a (message->attachment linkage + retention decref) + Phase 4 (SQL Server + Postgres substrate parity, go-live) + Phase 3b (operator read/download surface) built 2026-07-13 — #149 COMPLETE (all three backends, operator read surface) -->
- **Date:** 2026-07-12
- **Related:** BACKLOG #149 · [ADR 0001](0001-staged-pipeline-architecture.md) (staged pipeline) · [ADR 0028](0028-base64-binary-carriage-codec.md) (base64 carriage) · [ADR 0042](#) (pruned-document tombstone, #47) · BACKLOG #94 (BLOB offload) · CLAUDE.md §2 (reliability + count-and-log invariants), §8 (HL7), §9 (PHI)

---

## Context

An adopter must stream a **single very-large HL7 message** into Epic — a base64-encoded PDF sitting
in `OBX-5.5` that pushes the MLLP frame past the store's **16 MiB** cap. Today every body is
materialized **whole** in memory and bounded by that cap, so the message cannot be received at all.
BACKLOG #149 (decline overturned 2026-07-09) tracks lifting that ceiling for monolithic bodies that
neither #94's embedded-document BLOB offload nor `parsing/split.py` batch-splitting can decompose (a
monolithic body is not a batch).

The forcing constraints are the CLAUDE.md invariants this path must **not** break:

- **Count-and-log invariant (§2):** *"every received message is persisted before the ACK … nothing
  is accepted-and-dropped."* A very-large body must be **durably committed to the store before the
  inbound is ACKed**.
- **Reliability / at-least-once (§2):** *"At-least-once now relies on a re-run re-deriving identical
  output, so **routers and transforms must be pure** (message in → message out, no external side
  effects)."* Every stage handoff (ingress→routed→outbound) must re-derive **identical** output on a
  crash re-run, so the stored body is the canonical re-run input.
- **PHI at rest (§9):** the body is PHI — *"Never log full message bodies at INFO or above"* — and a
  streamed document persisted in pieces must be **encrypted at rest** exactly like `queue.payload`,
  with **no orphaned PHI** left behind on a crash.

Six places in the engine materialize a whole body today (the "whole-body materialization points"):
the MLLP **FrameDecoder** (buffers the frame to the 16 MiB cap), the **listener** decode/parse/
strict-validate, `enqueue_ingress` (the raw → ingress row), each **stage handoff** (raw carried
routed→outbound), the **transform** (`Message.parse`/`encode`), and the **delivery** encode back to
the wire. Streaming must relieve the memory pressure of the *opaque document* at these points while
keeping the small transformable HL7 **skeleton** on the existing fast path.

## Decision

**Detach the large opaque document from the small transformable HL7 skeleton.** At ingress, lift the
oversized `OBX-5.5` value out of the message into a **content-addressed, chunked, in-store
attachment** (each chunk AES-GCM-sealed with the existing `mfenc` cipher), leaving a small
`mfdoc:v1:ref:<sha256>:<content_type>` **live handle** in its place. The skeleton — now well under the
cap — rides the existing ingress→routed→outbound stages unchanged; at delivery the handle is
**re-attached** (the exact verbatim attachment bytes are spliced back into `OBX-5.5` — never a
decode/re-encode) and the full frame is streamed to Epic over inline MLLP.

Four **owner rulings** (2026-07-12) fix the shape:

1. **Delivery is inline MLLP MDM.** Epic's MLLP receiver does **not** cap frame size, so the document
   is **re-attached** (the verbatim value spliced back) into `OBX-5.5` and the whole frame is streamed
   as an MDM message. **No FHIR-Binary / DocumentReference path** is needed.
2. **These feeds are pure pass-through.** No transform re-encodes the PDF. **Doc-mutating transforms
   are an explicit non-goal** of the fast path and are **disallowed on streaming feeds** — the
   detached document is opaque to routing and transform.
3. **Approach B — store the `OBX-5.5` value VERBATIM.** The attachment holds the **exact** base64
   string the partner sent, byte-for-byte; re-attach splices the exact string back. There is **no
   decode-then-re-encode**, so the delivered bytes are trivially byte-identical to the wire and a
   crash re-run re-derives identical output (pure) with no codec round-trip to diverge.
4. **3-backend parity before go-live.** Phase 0 ships **SQLite**; SQL Server + Postgres are Phase 4.

The handle is **unified with #94's opaque-pointer contract**: one pointer format
(`mfdoc:v1:ref:<sha256>:<content_type>`) and one deref seam serve both **in-store chunked**
attachments (this ADR) and #94's **external-BLOB** offload. `mfdoc:v1:ref:` is the *live* sibling of
the existing `mfdoc:v1:pruned:` tombstone (#47/ADR 0042): a tombstone is a dead placeholder for an
evicted document; a ref is a live handle that dereferences to real bytes.

**Invariants preserved (and the new hazards they create):**

- **ACK after skeleton commit.** The attachment chunks are committed, then the skeleton (carrying the
  ref) is committed to the ingress stage, and only then is the inbound ACKed — so the whole document
  is durably persisted before the ACK (count-and-log holds). This widens the **ACK latency window**
  by the stream-and-seal time; the deferred-ACK receive-timeout re-tuning is a Phase-1 knob.
- **At-least-once + FIFO.** The stored attachment + skeleton are the canonical re-run inputs; because
  the stored bytes are **verbatim** (Approach B), every stage re-derives identically. FIFO is
  untouched (the skeleton rides the same per-lane ordering).
- **Crash-safety + orphan sweep (NEW).** Chunks are content-addressed and **refcounted** (generalizing
  the `shared_body` store-once model): an attachment is GC'd the moment its refcount hits 0. A crash
  *between* committing chunks and committing/increffing the skeleton would strand refcount-0 (or, for
  a future incremental writer, half-written) chunks. A new **startup orphan/incomplete-attachment
  sweep** — wired where `reset_stale_inflight` runs — reclaims refcount-0 **and** incomplete-write
  attachments so **no orphaned PHI chunk accumulates at rest**.
- **Refcount PHI hazard.** The refcount is the *only* thing keeping a live document's chunks from
  being GC'd; an under-count would delete PHI a delivery still needs, and an over-count would keep PHI
  past its last referrer. Incref/decref are therefore performed **inside the same transaction** as the
  referencing row (Phase 1), exactly as `shared_body` does — never as a detached best-effort step.
- **Key rotation covers attachments.** The `rotate-key` re-encrypt sweep is extended to **re-seal
  every attachment chunk** under the new DEK (chunk-at-a-time, so the whole document is never
  materialized to re-seal it), so a rotation covers attachment PHI like every other cipher column.

## Acceptance Criteria

- **AC-1** — WHEN a document is streamed to `put_attachment` in chunks, THE SYSTEM SHALL store each
  chunk AES-GCM-sealed, content-address the attachment by the sha256 of the **verbatim concatenated
  plaintext**, and `read_attachment` SHALL yield back the **exact** original bytes chunk-by-chunk.
  → `tests/test_attachment_substrate.py::test_put_read_roundtrip_verbatim_chunked`
- **AC-2** — WHEN the identical content is put twice, THE SYSTEM SHALL **dedup** to the same ref and
  store one physical copy. → `tests/test_attachment_substrate.py::test_put_dedups_identical_content`
- **AC-3** — WHILE an attachment's refcount is above 0 it SHALL be retained; WHEN its refcount reaches
  0 THE SYSTEM SHALL GC the attachment **and all its chunks**.
  → `tests/test_attachment_substrate.py::test_incref_decref_gc_at_zero`
- **AC-4** — WHEN the store starts, THE SYSTEM SHALL reclaim **refcount-0** and **incomplete-write**
  (orphaned-chunk) attachments so no PHI chunk is left at rest.
  → `tests/test_attachment_substrate.py::test_startup_sweep_reclaims_orphans_and_incomplete`
- **AC-5** — WHEN the store encryption key is rotated, THE SYSTEM SHALL re-seal every attachment chunk
  under the active key and `read_attachment` SHALL still return the exact bytes.
  → `tests/test_attachment_substrate.py::test_key_rotation_reseals_chunks`
- **AC-6** — THE SYSTEM SHALL round-trip a `mfdoc:v1:ref:<sha256>:<content_type>` handle and
  `is_doc_ref` SHALL distinguish a ref from a `mfdoc:v1:pruned:` tombstone and from a plain value.
  → `tests/test_doc_ref_handle.py::test_doc_ref_roundtrip_and_discrimination`
- **AC-7** — IF a streaming attachment method is called on a backend whose
  `supports_streaming_attachments` is `False`, THEN THE SYSTEM SHALL raise a clear not-supported error
  rather than silently degrade. → `tests/test_attachment_substrate.py::test_capability_flag_gate`

## Options considered

1. **Content-addressed chunked in-store attachment + `mfdoc:v1:ref:` live handle, detach-at-ingress,
   verbatim (Approach B)** — **CHOSEN.** Bounds memory for the pass-through case, reuses the
   `shared_body` refcount/GC and the `mfenc` cipher (no parallel mechanism), unifies with #94's
   pointer contract, and keeps re-run purity trivial (verbatim bytes, no codec round-trip).
2. **Raise the frame cap only** — Rejected: the cap doubles as an **OOM guard**; lifting it without
   detaching the document just moves the whole body through all six materialization points in memory,
   trading a hard cap for an unbounded-memory failure. (The cap becomes a `max_message_bytes` OOM
   guard in Phase 1, not a frame limit.)
3. **External message broker (Kafka/etc.) for large bodies** — Rejected: breaks the core reliability
   invariant (*"at-least-once … **without** a separate broker"*, §2) and adds an operational
   dependency an on-prem healthcare deployment does not want.
4. **Ship C's streaming decoder up-front** — Rejected for Phase 0: a true streaming FrameDecoder
   (never buffering the frame) is a large ingress rework; the substrate + detach must land and be
   proven first. Deferred to Phase 1.
5. **Chunk the body without detaching it** — Rejected: chunking the *whole* message still drags the
   opaque document through route/transform/`Message.parse`, and doc-mutating transforms are a non-goal
   anyway. Detaching the document keeps the skeleton on the existing fast path untouched.

## Consequences

**Positive** — Bounded memory for the pass-through large-document case; the small skeleton rides the
existing staged pipeline with **zero behaviour change for existing messages** (the substrate is
dormant until Phase 1 wires it); attachment PHI is encrypted at rest and covered by key rotation;
one pointer format + one deref seam for both in-store chunks and #94 external BLOBs.

**Negative / risks** — A **transient ingress buffer remains** in Phase 0/1 until the streaming decoder
(C) lands, so peak memory is still bounded by a single document until then. The **refcount is a PHI
hazard** (an under-count deletes live PHI; an over-count retains it) — mitigated by same-transaction
incref/decref and the startup sweep. The **deferred-ACK window** widens ACK latency by the
stream-and-seal time. **Strict hl7apy validation stays whole-body**, so on a streaming inbound it is
**header-only** (the detached document is opaque and not re-validated). The **read surface** (raw view,
content search, retention strip) is not attachment-aware yet — deferred to Phase 3.

**Out of scope** — All **pipeline/ingress/delivery wiring** (the OBX-5 detach at ingress and the
delivery re-attach, the FrameDecoder change) is **Phase 1**, not Phase 0. Phase 0 is the substrate + the
marker + the round-trip helpers only, testable in isolation, with default behaviour byte-identical to
today. **Doc-mutating transforms on streaming feeds** are a permanent non-goal (owner ruling 2).

### Phased plan

- **Phase 0 (this ADR, built 2026-07-12):** the attachment substrate (`attachment` +
  `attachment_chunk` tables, `put_attachment`/`read_attachment`/`attachment_incref`/`attachment_decref`,
  the startup orphan/incomplete sweep, the key-rotation re-seal, the `supports_streaming_attachments`
  capability flag) + the `mfdoc:v1:ref:` marker helpers in `parsing/binary.py`. **SQLite only.**
- **Phase 1a (built 2026-07-12):** the **ingress** wiring — see the dedicated section below. Detach the
  oversized `OBX-5.5` at ingress (via the parsed model), commit chunks then the skeleton, ACK after the
  skeleton+incref commit. The per-inbound `stream_threshold_bytes` / `max_message_bytes` knobs and the
  aggregate in-flight budget land here. **SQLite only.**
- **Phase 1b (built 2026-07-13):** the **delivery** wiring — see the dedicated section below. Re-attach
  the verbatim value at the terminal egress and stream the full frame inline; the outbound MLLP frame is
  uncapped so the large hydrated MDM (and a Handler-built large MDM) send inline.
- **Phase 3a (built 2026-07-13):** the **message→attachment linkage + retention decref** — see the
  dedicated section below. Persist a `message_attachment` join row per detached attachment (atomic with the
  ingress incref) and make `purge_message_bodies` decref + delete those rows in the body-purge transaction,
  **closing the Phase-1b over-retention gap**. **SQLite only.**
- **Phase 4 (built 2026-07-13):** 3-backend parity — the whole substrate on SQL Server + Postgres, flag
  flipped `True`. See the dedicated section below. **Go-live parity met (the production store is SQL
  Server).**
- **Phase 3b (built 2026-07-13):** the **operator read/download surface** — `attachments_for` (all three
  backends), the additive `MessageDetail.attachments` metadata list, the audited, `view_raw`-gated
  `GET /messages/{id}/attachments/{id}` download (channel-scope 404 + linkage check + base64 round-trip),
  and the web-console Attachments panel. See the dedicated section below. **#149 COMPLETE.**

### Phase 1a — ingress detach (built 2026-07-12, BACKLOG #149)

The ingress side of the pipeline wiring. An over-threshold streaming inbound now detaches its oversized
OBX-5 documents into the Phase-0 substrate **before** the ingress commit, so the pipeline carries only
the small skeleton + a `mfdoc:v1:ref:` handle. Delivery re-attach is **Phase 1b** (a detached message is
stored but not yet re-attachable — opt-in, no real feed enabled until 1b).

- **Config / opt-in (per-inbound, HL7v2 only; code-first AND `connections.toml`):**
  `stream_threshold_bytes` (`None` = OFF, byte-identical to today; set = a received body at/above this
  size detaches its OBX-5 ED base64 documents), `max_message_bytes` (`None` = inherit the engine 16 MiB
  ceiling; set = the per-connection **total-body OOM guard** that replaces the frame-cap-as-only-guard — a
  body over it is NAK'd/`ERROR`'d **before** detach), and the service-level
  `[inbound].stream_inflight_budget_bytes` (the **aggregate in-flight DoS guard** — total bytes of
  over-threshold bodies concurrently mid-detach across all inbounds; a detach that would exceed it is
  refused with backpressure). Since the frame cap was the OOM guard, correctness now rests on these caps
  + backpressure.
- **Ingress detach path (over-threshold):** buffer the frame once → PEEK/parse MSH **synchronously**
  (header decode + optional strict-**header** validate + a malformed-header **NAK** still run BEFORE any
  commit, exactly as today) → detach each OBX-5.5 ED value through the parsed `Message` model
  (`iter_obx_documents` + the same replace-in-OBX mechanism as `strip_documents_in_hl7`, but **VERBATIM**:
  the exact base64 string is chunked into `put_attachment`, no decode/encode) → replace OBX-5.5 with the
  `mfdoc:v1:ref:<sha256>:<content_type>` handle → `enqueue_ingress` persists the **skeleton** and increfs
  each attachment ref **in the same transaction** (the **two-object commit**: chunks committed first at
  refcount 0, then the referencing skeleton row + increfs commit together). The ACK fires only after the
  skeleton commits.
- **Deferred-ACK re-tune:** the ACK is deferred until the skeleton (and thus the whole sealed document)
  is durable. The MLLP `receive_timeout` is an **idle-between-reads** guard and the detach+seal runs
  **outside** its `wait_for` window (in the handler, between reads), so it does not clip the seal; a
  streaming inbound's `Mllp()` source should nonetheless raise `receive_timeout` **and** `max_frame_bytes`
  so a slow multi-hundred-MB upload is neither idle-timed-out nor frame-capped. Both are already
  per-source knobs — no new global default is introduced (raising `DEFAULT_RECEIVE_TIMEOUT` would perturb
  every non-streaming feed).
- **Strict-validation policy:** whole-body hl7apy strict validation cannot complete over threshold (it
  would materialize the opaque document), so it is **downgraded to header-only** on a streaming inbound
  over threshold — the MSH structure `Peek.parse` already validated. Not a regression: ED-document feeds
  are not whole-body strict-validated today. Below threshold, full strict validation still runs
  (byte-identical).
- **Compose with copy-on-Send (ADR 0104):** the detach acts on the ingress `Message`; the skeleton is a
  normal `Message` whose OBX-5.5 leaf is the opaque handle, so `Message.copy()` / Send-snapshot semantics
  carry it verbatim, unchanged.
- **Invariants preserved:** *ACK-on-receipt* (deferred until the skeleton commits; a header NAK still
  fires synchronously before any commit). *At-least-once / re-run* (the skeleton is the canonical re-run
  input; the attachment is immutable + content-addressed, so a re-run re-derives identically and does
  **not** double-write — dedup on sha256). *FIFO + count-and-log* (one message = ONE skeleton ingress row
  = one lane position; `RECEIVED` written before the ACK regardless of size; the attachment is a
  finalizer-invisible side table). *Crash-safety* (a crash before the skeleton commit leaves orphan
  chunks at refcount 0 → no ACK → the sender resends → the Phase-0 startup sweep reclaims the orphans).
  **Below-threshold and no-threshold ingress is BYTE-IDENTICAL to today.**
- **Scope:** ingress only, SQLite only. A streaming inbound on SQL Server / Postgres raises the
  `StreamingAttachmentsUnsupported` error at detach (turned into an `ERROR`/NAK) until Phase 4 parity.

### Phase 1b — delivery re-attach (built 2026-07-13, BACKLOG #149)

The delivery side of the pipeline wiring, completing the round-trip. A stored skeleton carrying a
`mfdoc:v1:ref:` handle is now **deliverable**: at the terminal egress the handle is re-materialized into
the full inline document just before it hits the wire, so a partner (Epic's inline MLLP MDM receiver, which
does not cap the frame — owner ruling 1) receives the exact document the sender sent. This validates the
owner's two end-to-end shapes: (A) a doc detached at ingress round-trips **byte-identically** to delivery,
and (B) a Handler that picks up a PDF, base64-encodes it, and builds a large MDM delivers it inline.

- **The pure splice-back helper** `parsing/binary.reattach_documents_in_hl7(text, reader)` — the
  delivery-side inverse of `strip_documents_in_hl7`. It scans each `OBX-5.5`, and for every live
  `mfdoc:v1:ref:` handle it parses the content address, `await`s the injected `reader(sha256)` for the
  stored VERBATIM base64, and splices it back into `OBX-5.5` **byte-for-byte** (Approach B — no
  decode/re-encode). `reader` is an injected async callable so the helper stays **pure** and
  unit-testable; `pipeline/` supplies the async store read. **Fail-loud:** a value that looks like a
  handle but whose `reader` returns `None` / raises (attachment missing or GC'd) raises `DocRefError` — it
  **never** emits the raw `mfdoc:v1:ref:` text. A body with no handle is returned **byte-identical**.
- **The delivery seam** `RegistryRunner._hydrate_payload` runs **before** `connector.send` on both the
  single-item (`_process_delivery_item`) and batch (`_process_delivery_batch`, per member) paths. A single
  `DOC_REF_MARKER` substring check short-circuits the common no-handle case to a **byte-identical**
  passthrough with **no store read** — so below-threshold, no-detach, and Handler-built (never-detached)
  deliveries are unchanged. When a handle is present it hydrates via `reattach_documents_in_hl7` with an
  async reader over `store.read_attachment` (off the event loop, chunk-by-chunk). **Fail-loud:** a missing
  / GC'd attachment (`KeyError`), a malformed handle (`DocRefError`), or an unsupported backend
  (`StreamingAttachmentsUnsupported`) is turned into a retryable `DeliveryError` — exactly like the
  pre-send `encoding_characters` / `hl7_raw_separators` failures — so the row takes the normal
  ERROR/retry/dead-letter path and **the connector never receives an un-hydrated handle** (which would
  deliver `mfdoc:v1:ref:…` into the partner's `OBX-5.5` = silent corruption).
- **Delivery is a pure READ — never a decref.** A message fans out to multiple outbounds and is
  replayable, so each send **reads** the immutable, content-addressed attachment per-send and leaves the
  refcount untouched; the refcount is released **only** at retention/purge (below). This makes retry
  idempotent (a re-hydrate re-derives the identical frame off the immutable attachment) and fan-out safe
  (two outbounds each deliver the full verbatim doc, refcount unchanged).
- **Outbound large frame — no new cap.** The outbound MLLP **send is deliberately uncapped**: `frame()`
  never truncates, so the large hydrated MDM (shape A) and a Handler-built large MDM (shape B) already
  stream inline. `MLLPDestination.max_frame_bytes` (already per-outbound) bounds **only the ACK-read
  decoder** (the reply we read back), never the outgoing frame — so no new knob is introduced and none is
  needed. (The frame cap that mattered for streaming was the **inbound** one, handled in Phase 1a.)
- **Compose with copy-on-Send (ADR 0104):** hydration happens **only at the terminal egress, after
  transform**. Through routing and transform the handle is an opaque `OBX-5.5` leaf carried verbatim by
  `Message.copy()` / the Send snapshot — unaffected.
- **Invariants preserved:** *count-and-log* (the finalizer sees the small skeleton rows; hydration is
  invisible to it — a delivered handle-bearing row finalizes exactly as any other). *At-least-once /
  retry* (hydration is a pure read; a failed send re-hydrates the identical frame). *FIFO* (hydration is
  per-row, in the existing send position). *Below-threshold / no-handle delivery is BYTE-IDENTICAL to
  today* (single substring check, no store read).
- **Scope:** delivery + the two end-to-end worked samples/tests (`samples/config/IB_STREAM_MDM.py` shape A;
  `samples/config/IB_PDF_TO_MDM.py` + `_pdf_mdm_transforms.py` shape B). SQLite only.

#### Known gap carried to Phase 3 — retention/purge does NOT yet decref an attachment — **CLOSED by Phase 3a (2026-07-13)**

`purge_message_bodies` (and `strip_embedded_documents`) null a message's `raw` body — which holds the
skeleton + its `mfdoc:v1:ref:` handle — but do **not** decref the referenced attachment, and the
`messages` table does **not** persist a message's `attachment_refs` (the ingress incref happens in
`enqueue_ingress` but no column records which refs a message holds for a later release). **Consequence:**
when a detached message's body is purged, its attachment's refcount is never decremented, so the
attachment + its chunks are **retained past their last referrer** (a PHI-at-rest over-retention, not a
loss — the ADR "refcount over-count keeps PHI past its last referrer" hazard). This is **not** a
Phase-1b delivery concern (delivery must never decref — see above); it belongs to **Phase 3** (the
read-surface + retention migration), which must persist per-message attachment refs and decref them in the
same transaction as the body purge (mirroring `_release_outbound_body_refs` for `shared_body`). Flagged
here rather than left as a silent leak. Until Phase 3 lands, an operator reclaiming a streaming feed's
storage relies on the startup `sweep_orphan_attachments` (refcount-0 only) — a purged-but-still-referenced
attachment is **not** yet reclaimed.

**→ This gap is CLOSED by Phase 3a (below):** retention now persists the linkage and decrefs on purge.

### Phase 3a — message→attachment linkage + retention decref (built 2026-07-13, BACKLOG #149)

Closes the Phase-1b over-retention gap above. A detached message now durably records **which** attachments
it holds, and retention releases them — so a purged-but-referenced document is reclaimed at its last
referrer instead of over-retaining PHI at rest forever. **The store linkage + SQLite retention decref
only** — the read surfaces (raw view / content search / retention document-strip made attachment-aware)
are **Phase 3b**, and SQL Server / Postgres parity is **Phase 4**.

- **The linkage table** `message_attachment(message_id, attachment_id)` — `PRIMARY KEY(message_id,
  attachment_id)`, one row per (message, DISTINCT attachment) the ingress detach lifted out. It is the
  durable record retention needs to know which attachments a purged message references (the `messages` table
  has no column to release from, and the `mfdoc:v1:ref:` handle lives only in the body being nulled).
  Logical refs (no FK — mirrors `attachment_chunk.attachment_id` / `queue.body_ref`). **SQLite schema only;**
  SS/PG never populate it (they raise `StreamingAttachmentsUnsupported` at ingress), and they don't yet
  carry the `attachment`/`attachment_chunk` tables either, so Phase 4 adds all three together — no orphaned
  DDL lands on the server backends now.
- **Ingress populate (atomic with the incref).** `enqueue_ingress` inserts one `message_attachment` row per
  distinct ref **in the same `_run_grouped` transaction** as the incref + skeleton row — so a crash leaves
  neither or both (invariant a). `refs` is already de-duplicated, so the PK never conflicts and
  `attachment.refcount` stays `== count of live message_attachment rows` referencing it (invariant c).
  Below-/no-threshold ingress writes **no** join rows and is byte-identical.
- **Retention decref (`purge_message_bodies`).** For every eligible purged message, in the **single**
  body-purge transaction, the new `_release_message_attachments` seam (the attachment sibling of
  `_release_outbound_body_refs` for `shared_body`): tallies each distinct attachment the eligible set holds
  via the linkage, **decrefs each by its live-reference count (GC at 0 reclaims chunks + header)**, then
  **DELETEs those join rows** — atomically with nulling the body (invariant b). A public
  `release_message_attachments(message_id)` runs the same seam for one message.
- **The DEAD/replay split (the correction — get it wrong and it is silent DATA LOSS).** A message is
  body-eligible when it has no `pending`/`inflight` row, but that set **includes** a message whose outbound
  rows are all `dead`. A `dead` row stays **replayable** — its `payload` is deliberately kept (`purge_message_-
  bodies` blanks only `done`/`cancelled` payloads; `dead` bodies are deferred to `purge_dead_letters`) and a
  later replay **hydrates** the `mfdoc:v1:ref:` handle from the attachment. Since the linkage is held **once
  per message** (not per row, unlike `shared_body`'s per-row `body_ref`), the attachment must be released only
  when the message's **last replayable row** is blanked — so `_release_message_attachments` is gated on the
  negated **live-holder** predicate (`_attachment_still_referenced_sql`): a message keeps its attachment while
  any row is `pending`/`inflight` **or** is a `dead` row still carrying a `payload` or a live `body_ref`.
  `purge_message_bodies` therefore releases only the all-`done`/`cancelled` case; **`purge_dead_letters`
  releases the attachment when it blanks a message's last replayable `dead` row** — the per-MESSAGE analogue
  of the `shared_body` done/cancelled-vs-dead split, and correct under **either purge order** (a re-run / the
  other purge finds the join rows gone and decrefs nothing). Proven by dead-row regression tests
  (body-purge-keeps, dead-purge-releases, run-dead-purge-first, done+dead fan-out, double-dead-purge
  idempotency).
- **The refcount-underflow hazard (the crux — get it wrong and it is silent DATA LOSS).** A
  content-addressed attachment is **shared** across messages (two messages, same PDF → one attachment,
  refcount 2, two join rows). Purge is **crash-re-runnable**: if a decref committed but its join-row DELETE
  did not, a re-run would **double-decref → refcount underflow → GC an attachment a SIBLING message still
  references**. The decref and the join-row DELETE are therefore **one atomic transaction, ordered so a
  re-run is a no-op** — a re-run finds the join row already gone and decrefs nothing. Proven by a
  double-purge test that asserts a shared sibling's attachment **survives** with the correct refcount.
- **Fan-out (invariant d).** Delivery to N outbounds is a **pure read** (Phase 1b — never an incref/decref),
  so a fanned-out message decrefs its attachment **once** at purge, never per-delivery. Proven by a
  delivered-to-two-outbounds-then-purged test (refcount unchanged through both deliveries, single decref at
  purge).
- **No new age-based delete.** Retention keeps the `messages` row (Mirth Data-Pruner) — there is **no**
  age-based row-DELETE of a message anywhere in the engine, so `purge_message_bodies` (which nulls `raw`,
  removing the handle) is the **sole** path that drops a message's attachment reference. `strip_embedded_-
  documents` replaces `mfb64:`/OBX-5 ED embeds with tombstones but does **not** remove a `mfdoc:v1:ref:`
  handle, so it keeps the reference live and correctly does **not** decref.
- **Scope:** store + retention decref, SQLite only. No read-surface (Phase 3b), no SS/PG (Phase 4). The
  Phase-0 `sweep_orphan_attachments` (refcount-0 reclaim) still runs as the belt-and-suspenders startup net;
  no reconciliation sweep was added (the atomic decref + join-DELETE keeps refcount == linkage-count, so
  there is nothing for one to reconcile).

### Phase 4 — SQL Server + Postgres substrate parity (built 2026-07-13, BACKLOG #149)

3-backend parity, the **go-live gate** (owner ruling 4): the production store is **SQL Server**, so
streaming must work identically there and on Postgres before the feature ships. The whole Phase-0→3a
substrate is now implemented on both server backends **at byte-for-byte behavioral parity** with the
SQLite reference (`store/store.py`), adapting only the SQL dialect and each backend's transaction model —
`supports_streaming_attachments` is flipped `True` on both, so the startup `sweep_orphan_attachments`
(guarded by that flag in `engine.py`) and the ingress detach now run on all three.

- **Schema.** `attachment` / `attachment_chunk` / `message_attachment` are added to each backend's
  `_SCHEMA` in one migration (all three together — no orphaned DDL), matching how each stores its existing
  ciphertext body columns: **SQL Server** `NVARCHAR(MAX)` ciphertext + `NVARCHAR(64)` content-address ids +
  `BIGINT total_bytes` + `INT refcount`; **Postgres** `TEXT` ciphertext + `TEXT` ids + `BIGINT` +
  `INTEGER`. Composite PKs `(attachment_id, seq)` / `(message_id, attachment_id)`. Logical refs (no FK —
  mirrors `queue.body_ref`). The schema-content-hash marker (ADR 0064) picks up the new DDL automatically
  (`test_store_schema_hash.py` is content-derived, not a pinned constant), forcing one full DDL run on the
  next open.
- **Methods.** `put_attachment` (content-addressed sha256 of the verbatim concatenated plaintext, per-chunk
  `mfenc` seal via the store cipher, **dedup** — a re-put of existing content returns the ref and writes
  nothing), `read_attachment` (async chunk iterator, decrypt in `seq` order, `KeyError` on a missing/GC'd
  ref — the connection is released **before** yielding, so partial consumption never pins it),
  `attachment_incref` (`KeyError` on a missing ref), `attachment_decref` + the transaction-participant
  `_decref_attachment` (GC header+chunks at 0 — SQL Server has no scalar `MAX(a,b)`, so a `CASE` clamps to
  0; Postgres uses `GREATEST(0, …)`), `_release_message_attachments` (tally-by-linkage → decref-by-count →
  DELETE join rows, in the caller's transaction), `_attachment_still_referenced_sql` (the dead-row
  live-holder predicate — SQL Server keeps SQLite's `?`/`IN (?, ?)` form, Postgres uses
  `= ANY($n::text[])` numbered placeholders), `release_message_attachments`, and `sweep_orphan_attachments`
  (refcount-0 headers + header-less incomplete-write chunk groups).
- **Ingress two-object commit.** Each backend's existing `enqueue_ingress` now increfs each **distinct**
  ref AND inserts its `message_attachment` join row **in the same transaction** as the skeleton message +
  ingress queue row (SQL Server's `_acquire`/`_cursor`/`_commit`; Postgres's `conn.transaction()`). A
  missing ref fails loud → the whole ingress rolls back → **no ACK** for a body we couldn't reference. The
  earlier "reject any non-empty `attachment_refs`" stub is removed; empty/None is byte-identical to today.
- **Retention decref + the DEAD/replay split.** The linkage release is wired into **both**
  `purge_message_bodies` (all-`done`/`cancelled` case) and `purge_dead_letters` (releases when a message's
  **last replayable `dead` row** is blanked), gated on the negated live-holder predicate — identical to
  SQLite and **correct under either purge order**. On Postgres `purge_dead_letters` was promoted from a bare
  pooled `execute` to a `conn.transaction()` so the payload blank + decref + join-DELETE commit atomically.
  The decref + join-row DELETE are **one transaction, re-run-idempotent** (a re-run finds the join rows gone
  and decrefs nothing) — no double-decref, no refcount underflow, no premature GC of a **shared** attachment
  a sibling message still references (the killer invariant).
- **Key rotation.** Each backend's `reencrypt_to_active` sweep is extended to re-seal `attachment_chunk`
  ciphertext under the active key (SQL Server: a dedicated composite-PK pass mirroring its `state` pass;
  Postgres: the existing `_reencrypt_composite` helper with `value_col="ciphertext"`), one chunk at a time —
  the content-address id is over plaintext, so a re-seal is rotation-stable.
- **Tests.** SS + PG parity suites (`tests/test_sqlserver_store.py`, `tests/test_postgres_store.py`) mirror
  every SQLite attachment/retention/dead-row assertion (round-trip verbatim, dedup, incref/decref/GC,
  ingress two-object commit + rollback on a missing ref, purge decref + join-DELETE, double-purge
  idempotence on a shared attachment, the dead-row keeps/releases split in both purge orders, fan-out single
  decref, below-threshold byte-identical, per-chunk seal at rest + key-rotation re-seal). They follow the
  existing real-backend fixture/skip gate, so they run on the SS/PG CI legs and skip locally without a live
  backend. `test_messagestore_satisfies_store_protocol` and the schema-hash tests stay green; the SQLite
  suites are unchanged (the SQLite implementation was only mirrored, never edited).
- **Scope:** substrate + retention + parity tests. **Not** Phase 3b (operator read/download surfaces —
  backend-agnostic, the only remainder). The SQLite implementation is untouched.

### Phase 3b — operator read/download surface (built 2026-07-13, BACKLOG #149) — **#149 COMPLETE**

The last phase: an operator can now **see that a message carries a detached document and pull the real
bytes**, where before the raw view showed only the opaque `mfdoc:v1:ref:<sha256>:<content-type>` handle
in OBX-5.5. Backend-agnostic, PHI-gated, audited. Owner rulings (2026-07-13): **reuse
`Permission.MESSAGES_VIEW_RAW`** (a detached document is the same PHI as the raw body — no new
permission), and **API + web console only** (the PySide6 desktop console is deprecated — no new surface).

- **Store read method.** `attachments_for(message_id) -> [{attachment_id, content_type, total_bytes}]`
  on the `Store` protocol + all three backends (SQLite/SS/PG) — a `message_attachment` JOIN `attachment`
  read, **metadata only** (never a chunk-ciphertext read/decrypt), so it stays cheap on the message-detail
  path. Returns `[]` for a message with no detached document. SS/PG parity tests on the CI legs.
- **`MessageDetail.attachments`.** An additive `list[AttachmentInfo]` (`id`/`content_type`/`total_bytes`),
  populated by `get_message` via `attachments_for`. Metadata only — it stays on the existing `view_raw`
  gate (no extra PHI exposure), and defaults to `[]` so an older client / a normal message is unchanged.
- **Download endpoint** `GET /messages/{message_id}/attachments/{attachment_id}`
  (`require_phi_read(MESSAGES_VIEW_RAW)`, no step-up — matches the raw view, not the content-search
  step-up). **Security crux — three gates:** the same channel-scope **404-not-403** guard as `get_message`
  (don't reveal a message in another tenant's channel), **plus** a `(message_id, attachment_id)` **linkage
  existence** check (content-addressing shares one physical blob across messages/tenants, so the linkage is
  what scopes access — a guessed content address unlinked to an in-scope message is a 404). Then
  `read_attachment` reconstructs the **verbatim base64** (Approach B — buffer-once, mirroring the delivery
  buffer-once posture) and **base64-decodes once** to the original document bytes (round-trips byte-for-byte
  to what the sender sent). Returns a `Response` with a **validated** `Content-Type` (the stored
  `content_type` only when it is a clean `type/subtype` MIME, else `application/octet-stream` — an
  attacker-influenced OBX-5.2 label can never inject/split the header) + a header-safe
  `Content-Disposition: attachment; filename="attachment-<sha16><ext>"`. Every download is **audited before
  the bytes leave**: `record_view` (the per-message PHI timeline) + a tamper-evident `attachment_download`
  audit row (actor + the id pair, docs/PHI.md §6). **The bytes/base64 are never logged at any level.**
- **Web console.** The message-detail view renders an **Attachments panel** (content type + human size +
  a Download link) only when `MessageDetail.attachments` is non-empty. The link targets a
  `/ui/messages/{id}/attachments/{attachment_id}` route that reuses the engine's audited download handler
  **in-process** (a top-level browser GET carries the session cookie, not the bearer, so the JSON API route
  isn't directly reachable — the `/ui` gate re-asserts `view_raw`, and the engine handler does the same PHI
  audit). No PySide6 surface (deprecated). The seam handshake bumps to **v4** (the additive
  `MessageDetail.attachments` + a `download_attachment` `CoreHandlers` field); `SUPPORTED_ENGINE_SEAMS`
  gains `4` and the seam snapshot + `/ui` route-table goldens are refreshed.
- **Scope:** store read method + API endpoint + web console panel. **No** change to the
  ingest/deliver/retention machinery (Phases 0/1a/1b/3a/4). This closes #149.

## To resolve on acceptance

- [x] Delivery transport for the large frame — **inline MLLP MDM** (owner ruling 1).
- [x] Whether transforms may mutate the detached document — **no, non-goal** (owner ruling 2).
- [x] Store the value verbatim vs decode/re-encode — **verbatim, Approach B** (owner ruling 3).
- [x] Backend parity gate — **SQLite Phase 0; SS+PG Phase 4** (owner ruling 4).
- [x] Phase-1a: `stream_threshold_bytes` / `max_message_bytes` are **per-inbound opt-in** (no built-in
      default — `None` = OFF/inherit), plus the aggregate `[inbound].stream_inflight_budget_bytes` DoS
      guard; the OOM guard is now the per-connection `max_message_bytes` + the budget, not the frame cap.
- [x] Phase-1a: deferred-ACK receive-timeout — the detach+seal runs outside the MLLP idle-timeout window;
      a streaming inbound raises its `Mllp()` `receive_timeout` + `max_frame_bytes` (both existing
      per-source knobs), so no global default change is needed.
- [x] Phase-1b: re-attach is a **pure splice-back** (`reattach_documents_in_hl7`, injected async reader,
      VERBATIM) hydrated at the terminal egress on both the single-item and batch delivery paths; a missing
      attachment / handle is **fail-loud** (retryable `DeliveryError`, never a handle on the wire).
- [x] Phase-1b: the outbound MLLP **send is uncapped** (the large hydrated / Handler-built MDM streams
      inline); `max_frame_bytes` bounds only the ACK read — no new knob.
- [x] Phase-3a (built 2026-07-13): retention/purge now **decrefs** a purged message's attachment refs — a
      `message_attachment` join table persists the linkage (populated atomically with the ingress incref) and
      `purge_message_bodies` decrefs + deletes those rows in the body-purge transaction, ordered so a
      crash-re-run is a no-op (no double-decref / underflow / premature GC of a shared attachment). Closes the
      Phase-1b "Known gap" above. **SQLite only** (SS/PG parity is Phase 4; read surfaces are Phase 3b).
- [x] Phase-3a correction (2026-07-13): the attachment release is gated on **no remaining replayable row**
      (the live-holder predicate), not merely on body-eligibility — a message held only by `dead` rows keeps
      its attachment until `purge_dead_letters` blanks its last replayable `dead` row. Fixes a premature GC
      that would have lost a dead-lettered message's document on replay (fail-loud `DeliveryError`); correct
      under either purge order and store-once `dead` rows.
- [x] Phase-4 (built 2026-07-13): **SQL Server + Postgres substrate parity** — the whole substrate
      (schema, `put`/`read`/`incref`/`decref`/`sweep`, ingress two-object commit, retention decref + the
      dead-row split, key-rotation re-seal) is implemented on both server backends at byte-for-byte
      behavioral parity with the SQLite reference (dialect + txn-model adapted only), `supports_streaming_-
      attachments` flipped `True`, with SS/PG parity tests on the CI legs. **Go-live parity met** (the
      production store is SQL Server). Only Phase 3b (operator read/download surfaces) remains.
- [x] Phase-3b (built 2026-07-13): the **operator read/download surface** — `attachments_for` (all three
      backends), the additive `MessageDetail.attachments` metadata list, and the audited, `view_raw`-gated
      `GET /messages/{id}/attachments/{id}` download (channel-scope 404 + linkage check + base64 round-trip
      to the original bytes) + the web-console Attachments panel. Reuses `MESSAGES_VIEW_RAW` (no new
      permission); API + web console only (no PySide6). **This closes #149** (streaming very-large HL7
      attachments — all three backends + operator read surface).
- [ ] Forward-compat coupling (no action today): the `_attachment_still_referenced_sql` live-holder
      predicate's `body_ref IS NOT NULL` clause is **dead on SS/PG** because store-once (`queue.body_ref`)
      is schema-only there — `body_ref` is always `NULL`, so the predicate reduces to `payload <> ''`,
      matching SQLite behavior. **If store-once is later implemented on SS/PG**, `purge_dead_letters` must
      null `body_ref` (as SQLite's `_release_outbound_body_refs` does) **before** the attachment release,
      or a dead-row-only attachment would over-retain — keep this coupling with the dead-row split.
