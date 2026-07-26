# ADR 0131 — Bulk raw-message-body export from a search result (step-up, audited PHI egress)

- **Status:** Accepted (2026-07-17) — DEMAND-GATE-BACKLOG Wave 3 build (lane `dg-s7b`); pushes/PR owner-approved.
- **Built:** Yes — additive. `GET /messages/export` on [`api/app.py`](../../messagefoundry/api/app.py):
  a **streaming** (NDJSON) bulk export of decrypted message bodies, selected either by an explicit id set
  (save-selected) or by the **basic** `/messages/search` filters (save-all), gated by
  `require_step_up(messages:export, messages:view_raw)` + `enforce_phi_read_hop`, per-row `_scope`
  (`can_access_channel`), and a pre-stream `messages_export` audit counting every selected body. New
  `MESSAGES_EXPORT` permission in [`auth/permissions.py`](../../messagefoundry/auth/permissions.py)
  (OPERATOR + administrator). `app.js` save-selected / save-all with a progress readout + stop control.
- **Related:** [ADR 0046](0046-message-content-search-scan-and-decrypt.md) (the `/messages/search` +
  `search_messages` this reuses for selection), [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
  (the PHI-read hop guard), [ADR 0090](0090-message-resend-edit-resubmit.md) (the `messages:view_raw`
  PHI gate this rides), the `/audit/export` streaming route it mirrors, BACKLOG #124. Companion:
  [ADR 0130](0130-runtime-ephemeral-log-verbosity-control-and-phi-redacted-log-tail-viewer.md) (S7b #171).

## Context

An operator handing a batch of message bodies to a partner or support engineer for offline analysis
today has only **one-at-a-time** `GET /messages/{id}` raw retrievals (each an audited PHI view) after a
`/messages/search` — there is no **batch** export of bodies to a file (BACKLOG #124). This is the
**largest PHI surface** in the S7b cluster: it puts *bulk* raw bodies onto an operator-chosen file. The
build must therefore be maximally conservative about who can do it, over what transport, for which
channels, and that **every** exposed body is accounted for — a scripted "save-all" must not be able to
harvest bodies that never hit the audit trail.

Two hard constraints frame the design: (1) **no store schema change** — this lane must keep
`store_schema` false, so the export must **not** add a 3-backend bulk-body iterator; and (2) the
selection must stay coupled to the **basic** `/messages/search` filters only (a sibling lane later
extends search with layered queries/presets — export-from-a-preset is sequenced after that).

## Decision

### §1 — Selection reuses `/messages/search`; delivery LOOPS `get_message` per id (no bulk iterator)

The route selects the id set two ways: an explicit **`ids`** list (the UI's *save-selected*) or, absent
that, the **basic** `search_messages(spec, channel_id/status/message_type/control_id, limit,
allowed_channels)` result rows (the UI's *save-all* — the same scan-and-decrypt search the console
already exposes, kept to basic filters per the lane scope). It then **loops
`await store.get_message(id)` per id** to fetch + decrypt each body and streams it. Crucially it does
**not** introduce a 3-backend "bulk bodies" store method — reusing the existing single-message
`get_message` (already on every backend) keeps `store_schema` **false** and avoids a cross-backend
migration for a demand-gate export. The per-id loop is off the perf-critical path (an operator export,
not the message path).

### §2 — Gate: step-up + `messages:export` + `messages:view_raw`, and the PHI-read hop guard

Bulk PHI egress demands the **strongest** interactive gate: `require_step_up(MESSAGES_EXPORT,
MESSAGES_VIEW_RAW)` — a fresh re-proof + second factor on top of BOTH the raw-view PHI permission AND a
**dedicated `messages:export` capability** (so "export a batch to a file" is a distinct, separately
grantable privilege from "view one raw message", not implied by it). Like the step-up search route,
`enforce_phi_read_hop` is called **explicitly** (step-up does not fold it): a production-PHI instance
whose API serve hop is not proven secure **refuses** to emit bodies (ADR 0092). `MESSAGES_EXPORT` is
granted to OPERATOR (who already holds `view_raw`) and — implicitly — the administrator.

### §3 — Per-row channel scope on EVERY streamed body

Every candidate id is re-checked with `identity.can_access_channel(row["channel_id"])` as it is fetched.
The search path already filters to `_scope(identity)` in SQL, but the **save-selected** `ids` path takes
attacker-suppliable ids, so the per-row check is **load-bearing** there: an out-of-scope id is **skipped**
(never streamed) and a `auth.channel_denied` audit row is written, mirroring `GET /messages/{id}`. A
channel-scoped operator can only ever export bodies from its own channels.

### §4 — A dedicated `messages_export` audit counts EVERY body, BEFORE it streams

Mirroring `/audit/export`, a single tamper-evident `messages_export` audit row is written **before the
StreamingResponse begins** — actor + the selection mode + the basic filters + the **needle SHAPE**
(via `_search_audit_detail`, never the needle value; an MRN needle is PHI) + the **count of selected
bodies**. Because the stream only ever iterates that selected id set, the audited count is an **upper
bound on** — and covers — every body that can be exposed: a scripted save-all cannot pull a single body
that was not first counted in a durable audit row. Per-row scope denials are separately audited (§3). The
bodies stream as **NDJSON** (one JSON object per line: id/channel/received_at/type/control/status +
`raw`), which `json.dumps` escapes safely (CR-delimited HL7, binary `mfb64:` markers) and which streams
line-by-line without buffering the whole set. The **PHI-safe destination is the operator's
responsibility** (documented) — the engine's job is the gate + the audit.

## Options considered

1. **Reuse `search_messages` for selection + loop `get_message` per id + pre-stream aggregate audit (chosen).**
   No schema change, strongest gate, per-row scope, one durable count-bearing audit before any egress.
2. **Add a 3-backend bulk-body store iterator.** Rejected — flips `store_schema` true (a cross-backend
   migration this lane must not make), for no functional gain over the per-id loop on an export path.
3. **Audit per-body only (N rows), no pre-stream aggregate.** Rejected — N audit rows flood the chain and,
   worse, a client disconnect / crash could leave streamed-but-unaudited bodies; the pre-stream aggregate
   is the harvest-proof guarantee (durable before any body leaves), exactly as `/audit/export` does.
4. **Gate on `messages:view_raw` alone (no `messages:export`).** Rejected — bulk export is a materially
   larger exposure than opening one message; a distinct, separately grantable capability lets an org
   withhold *bulk* export from a role that may still view single messages.
5. **Export a ZIP / raw concatenation.** Rejected for the MVP — NDJSON is self-describing, streamable, and
   safely escapes CR-delimited/binary bodies; a framed/zip variant can follow if a partner needs it.

## Consequences

**Positive** — operators export a batch of bodies to a file behind step-up + a dedicated permission + the
PHI-read hop guard + per-row scope, with a durable audit counting every selected body; no store schema
change (per-id `get_message` loop), streamed without buffering, reuses the existing search + raw-view
seams.

**Negative / residual** — the PHI-safe destination is the operator's responsibility (an export to a
world-readable path is out of the engine's control, documented). The pre-stream audit records the
**selected** count (an upper bound); per-row scope skips / deleted ids make the actually-streamed count
lower (over-count is the safe direction, and denials are separately audited). Selection is **basic**
search filters only — export-from-a-layered-preset is sequenced after the later search work. NDJSON is
the only export shape in the MVP.
