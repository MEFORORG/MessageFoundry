# ADR 0042 — Embedded-document (base64 attachment) pruning

- **Status:** Proposed (2026-06-27) — drafted for Multisession Plan 4 (Lane 0 coordinator); owner ratifies
  the **design fork** (build increment (a) now, or defer) before Lane A builds. Number reserved here (next
  free after [0041](0041-load-path-attestation-and-change-attribution.md)).
- **Decision in one line:** add a per-connection **`prune_documents_after`** window (with a size threshold)
  that, on a `RetentionRunner` pass, **rewrites the stored raw in place** to replace each base64 embedded
  document (the generic `mfb64:v1:` carriage marker and HL7 **OBX-5 ED** embeds) with a small
  size/content-type **tombstone** — keeping the surrounding message parseable and the row intact — on all
  three store backends; the ingest-time **offload** half is the deferred (b) increment.
- **Related:** [ADR 0027](0027-per-connection-retention.md) (per-connection retention — the **sibling**
  built in the same Lane-A pass; this reuses its per-connection override **field on the connection spec** (a
  `prune_documents_after` field on `InboundConnection`, the #46 `capture_ack` `bool | None` idiom) + per-connection
  cutoff resolution), [ADR 0028](0028-base64-binary-carriage-codec.md) (the `mfb64:v1:` carriage marker +
  OBX-5 ED embedding this strips; `RawMessage.from_bytes`/`.raw_bytes`), [ADR 0007](0007-gui-manageable-connections-toml.md)
  (connections-as-data overlay), [CLAUDE.md](../../CLAUDE.md) §1 (no grouping unit; connections may be data),
  §2 (count-and-log; never purge an in-flight body), §8 (**never string-slice raw HL7** — edit via the parsed
  model/codec and re-encode), §9 (PHI minimization), [PHI.md](../PHI.md) §8, BACKLOG #47 (distinct from #34),
  Multisession Plan 4.

---

## Context

Large **base64-encoded embedded documents** (PDF reports, CCD/C-CDA, scanned images) ride inline in
messages — in HL7 in **OBX-5** (ED data type), and generically anywhere via the
[ADR 0028](0028-base64-binary-carriage-codec.md) `mfb64:v1:` carriage marker. These blobs are often tens to
hundreds of KB and are stored verbatim in the raw message at **every** persisted stage (`ingress` → `routed`
→ `outbound`), so a chatty document feed bloats the store far out of proportion to its message *count*.

**Gap today.** Retention is all-or-nothing on the whole body: the global `RetentionRunner`
([`pipeline/retention.py`](../../messagefoundry/pipeline/retention.py)) calls `purge_message_bodies`
([`store/store.py`](../../messagefoundry/store/store.py)), which **nulls the entire raw body**
keep-metadata, store-wide, by message age only. There is no way to evict *only the bulky attachment* while
preserving the surrounding HL7 (the segments an operator still wants to see), and no per-connection window
(that broader gap is **#34 / ADR 0027**). Nothing offloads the blob at ingest either — it rides inline.

**What Mirth does.** Two complementary mechanisms: an **Attachment Handler** (offload at ingest — extract
the blob to a separate attachment table, replace inline with a `${ATTACH:...}` token, reattach on the
outbound) and a **Data Pruner** (prune content/metadata on independent per-channel clocks). The user's
literal ask is the **prune-after-a-window** half (Data Pruner, attachment-scoped); the more impactful half is
**offload-at-ingest** (Attachment Handler), which stops the bloat at the source.

Three [CLAUDE.md](../../CLAUDE.md) invariants bound the design:

- **Never string-slice raw HL7** (§8): "Work via the parsed model and re-encode." The strip must edit via the
  codec / parsed model, never by byte/offset surgery on the raw.
- **Count-and-log + reliability** (§2): the row is **never deleted** (counts/disposition/audit intact); the
  strip is null-the-blob-keep-the-message; the per-connection cutoff **AND**s the *never-purge-an-in-flight-body*
  predicate.
- **No grouping unit / connections may be data** (§1): the per-connection window is transport-adjacent
  settings data (a per-connection field on the connection spec / `connections.toml`), not a Router/Handler knob or a built "channel" object.

## Decision

### The design fork (owner ratifies)

**Owner decision (locked 2026-06-27).** Build **increment (a)** now — an **in-place selective strip** of the
embedded document after a per-connection window. **Record (b)** — the ingest-time offload to a separate
attachment store with a placeholder marker (true Mirth Attachment-Handler parity; a larger build touching the
pipeline + a new store table + reattach-on-outbound) — as a **deferred follow-up that gets its own future ADR
if pursued**, not built now. (c) = both, with (a) as the near-term increment. (a) matches the literal request
and is cheaper; its accepted cost is that the blob still bloats the store until the window elapses and is
duplicated across stages meanwhile.

### D1 — A per-connection `prune_documents_after` window (+ size threshold)

A per-connection `prune_documents_after` window with an **embedded-doc size threshold**, layered over a
global default — the same **global-default + per-connection-override** model as FIFO / `RetryPolicy` /
`BuildupThreshold` / ADR 0027. It **reuses ADR 0027's per-connection override field on the connection spec** — a
`prune_documents_after: int | None` field on `InboundConnection` (the #46 `capture_ack` `bool | None` idiom + ADR 0007
`connections.toml` keys) — so it stays hand-/GUI-editable and shares the per-connection cutoff
resolution rather than re-deriving it.

### D2 — An in-place document-strip purge path (codec-driven, three backends)

A new store purge path (sibling to `purge_message_bodies`) that **rewrites the stored raw in place**,
replacing each embedded document with a small **placeholder/tombstone** (size + content-type + a `pruned
<ts>` marker) while leaving the rest of the message **byte-stable and parseable**. It targets **both**
carriage forms — the generic `mfb64:v1:` marker (ADR 0028) and HL7 **OBX-5 ED** embeds — editing via the
parsed model / codec and re-encoding (**never string-slicing raw HL7**, §8). It must land on **all three**
backends (SQLite / Postgres / SQL Server). It is driven from `RetentionRunner.run_once` in the same Lane-A
pass as ADR 0027.

### D3 — One audit row per pass

Each pass that strips documents emits **one** `audit_log` row recording the per-connection window + counts
(documents stripped / bytes reclaimed), **never** any message content — same count-and-log discipline as the
global runner.

### D4 — A distinct disposition flag (pruned vs never-present)

A strip is **irreversible** — the bytes are gone — so an operator viewing a message must be able to tell an
attachment that was **evicted** from one that was **never present**. The strip therefore sets a **distinct
flag on the message** (proposed `documents_pruned` — a boolean/timestamp on the message metadata,
*orthogonal* to the `RECEIVED`/`ROUTED`/`PROCESSED`/`FILTERED`/`ERROR` disposition, which is **unchanged**)
so the console/raw-view renders "[document evicted, pruned <ts>]" rather than silently showing a tombstone
that could be mistaken for an empty field. This is the `documents_pruned` analog of the existing "body
purged" rendering — it introduces **no** new terminal disposition and alters **no** count. The tombstone
itself stays self-describing (size + content-type + `pruned <ts>`); the flag is the message-level signal an
operator reads.

### What this must not break

- **Never string-slice raw HL7 (§8).** The strip goes through the parsed model / ADR 0028 codec and
  re-encodes; the message stays parseable after the strip (a re-parse round-trips).
- **Count-and-log + reliability (§2).** The row is never deleted; metadata/disposition/audit stay intact;
  the per-connection cutoff AND-s the in-flight guard.
- **No grouping unit / code-first logic (§1).** The window is settings data; Router/Handler logic is
  untouched.
- **Disposition unchanged (§2).** The strip sets the orthogonal `documents_pruned` flag (D4); it never
  introduces a new terminal disposition or alters a message's `RECEIVED`/`ROUTED`/`PROCESSED`/`FILTERED`/
  `ERROR` count.
- **Global / no-override deployments.** With no `prune_documents_after` set, no document is stripped.

## Acceptance Criteria

> EARS form; each linked (`→`) to its test. `messagefoundry adr-analyze` checks each `→` resolves.

- **AC-1** — WHERE a connection sets `prune_documents_after`, WHEN a `run_once` pass runs past that window,
  THE SYSTEM SHALL replace each `mfb64:v1:` embedded document above the size threshold with a tombstone
  (size + content-type + `pruned <ts>`) and leave the rest of the raw byte-stable.
  → `tests/test_embedded_document_pruning.py::test_mfb64_blob_stripped_to_tombstone`
- **AC-2** — WHEN an HL7 message carries an OBX-5 ED embedded document, WHEN it is pruned, THE SYSTEM SHALL
  strip the OBX-5 value via the parsed model (never raw string-slicing) and the result SHALL re-parse cleanly.
  → `tests/test_embedded_document_pruning.py::test_obx5_ed_stripped_and_reparses`
- **AC-3** — IF a message body is still in-flight, THEN THE SYSTEM SHALL NOT strip its documents even when the
  per-connection window has elapsed (the cutoff AND-s the in-flight guard).
  → `tests/test_embedded_document_pruning.py::test_in_flight_body_not_stripped`
- **AC-4** — THE SYSTEM SHALL produce identical strip results across the SQLite, Postgres, and SQL Server
  backends.
  → `tests/test_embedded_document_pruning.py::test_three_backend_parity`
- **AC-5** — WHEN a strip pass does work, THE SYSTEM SHALL write exactly one `audit_log` row recording the
  per-connection window + counts (documents stripped / bytes reclaimed) and SHALL NOT record message content.
  → `tests/test_embedded_document_pruning.py::test_audit_records_strip_counts`
- **AC-6** — WHERE no `prune_documents_after` is set, WHEN `run_once` runs, THE SYSTEM SHALL strip no
  documents (back-compat).
  → `tests/test_embedded_document_pruning.py::test_no_window_no_strip`
- **AC-7** — WHEN a message's embedded document is stripped, THE SYSTEM SHALL set the distinct
  `documents_pruned` flag (so an operator sees *evicted* vs *never present*) and SHALL NOT delete the row or
  change its disposition count.
  → `tests/test_embedded_document_pruning.py::test_sets_pruned_flag_disposition_unchanged`

## Options considered

1. **In-place selective strip after a per-connection window — increment (a), CHOSEN now.** Matches the literal
   ask, cheap, reuses ADR 0027's per-connection override field + the runner; codec-driven strip honours §8.
2. **Ingest-time offload to a separate attachment store (Mirth Attachment Handler) — (b), DEFERRED.** Bounds
   growth from the start (the more impactful half) but a far larger build: pipeline edits + a new store table +
   reattach-on-outbound + a token scheme. Revisit on a real high-volume document feed.
3. **Both, (a) near-term — (c).** The eventual target; (a) ships first, (b) follows on a feed trigger.
4. **Whole-body purge only (status quo / #34 alone).** Rejected: an operator wants the segments kept while only
   the bulky attachment is evicted — whole-body null can't do selective.

## Consequences

**Positive** — Bounds store growth for chatty document feeds while preserving the readable message; PHI
minimization scoped to the bulky attachment. Reuses ADR 0027's per-connection override field + the existing runner +
audit discipline — one Lane-A pass covers #34 and #47.

**Negative / risks** — (a) leaves the blob duplicated across stages until the window elapses (accepted). The
codec-driven strip across two carriage forms × three backends is the real cost; a parity test + a re-parse
round-trip test are mandatory. Tombstone shape must stay parseable HL7 / valid `mfb64` placeholder.

**Out of scope** — Ingest-time offload (b), the attachment-token reattach-on-outbound scheme, and any new
attachment store table — all deferred to a future increment on a real feed.

## To resolve on acceptance

- [ ] **Owner fork call.** Confirmed-locked 2026-06-27: build (a) now; (b) ingest-time offload is a deferred
  follow-up with its own future ADR. Leave a final owner ratification of this ADR's *status* flip to Accepted.
- [ ] **Tombstone shape + flag name.** Exact placeholder for `mfb64:v1:` vs OBX-5 ED (must round-trip parse;
  record size + content-type + pruned timestamp without leaking content), and confirm the message-level
  `documents_pruned` flag name (D4) — distinct from the tombstone and orthogonal to the disposition.
- [ ] **Size threshold default + shared override mechanism.** Confirm the threshold and that `prune_documents_after`
  rides ADR 0027's per-connection override mechanism — a field on the connection spec (**one** mechanism, not two) —
  coordinating with the #34/0027 owner so the two windows share one override path.
