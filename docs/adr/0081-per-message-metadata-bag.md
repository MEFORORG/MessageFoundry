# ADR 0081 — User-writable per-message metadata bag (channelMap / userdata parity)

**Status:** Accepted (2026-07-10) — owner ratified; build to follow (BACKLOG #150)

## Context
Corepoint's `channelMap` / Mirth's `$('key')` userdata lets a transform stamp small key/value
annotations onto a message that ride the pipeline and surface in the message view. The committed
Corepoint cutover needs this (BACKLOG #150; the trigger has fired). Today MessageFoundry has no
such surface:

- `parsing/message.py` `Message` (line 54) exposes HL7 read/mutate/encode only — **no metadata API**.
  `RawMessage` (line 577) likewise has none.
- The API wire contract already **reserves the slot**: `api/models.py:40`
  `metadata: str | None  # code/operator-attached values (mechanism TBD)` — carried on
  `MessageSummary`, so the read-only surface is half-built and waiting for a producer.
- The store already has the column: `messages.metadata TEXT` (`store/store.py:895`), **cipher-encrypted
  at rest** as PHI (EF-3, `store/store.py:1552`), decrypted into list responses at
  `store/store.py:4346`. It is currently used *only* internally for ADR 0013 correlation lineage
  (`{"correlation_id", "correlation_depth"}`, read at `store/store.py:2568`).

The hard constraint: a Handler runs in the **transform** stage (`wiring_runner.py:3459`
`transform_one` → `store.transform_handoff`), which under ADR 0001 is a pure, re-runnable stage.
A metadata write must therefore be **derived from the input message, applied exactly-once inside the
handoff transaction** — never an imperative side effect.

## Decision
Add a declarative **`SetMeta(key, value)`** op, modelled exactly on ADR 0005's `SetState`
(`config/wiring.py:1588`). A Handler returns it alongside its `Send`s:

```python
@handler
def enrich(msg):
    return [Send("OB_ACME", msg), SetMeta("mrn_source", "ACME"), SetMeta("priority", msg["PV1-2"])]
```

- **Where it lives on `Message`:** nowhere mutable. `SetMeta` is a *return value*, not an attribute —
  identical to `SetState`, so the `Message`/`RawMessage` objects stay pure read/mutate views and can't
  smuggle hidden state between handlers. `HandlerFn` (`wiring.py:1628`) widens to accept `SetMeta`.
- **How it persists through the staged handoff:** `transform_one` partitions `SetMeta` ops out
  (like `StateOpPreview`) and the transform worker passes them to `transform_handoff(meta_ops=...)`.
  Inside the **same claim→produce→complete transaction** (`store.py:2553` `_body`), the store does a
  read-modify-write of the row's decrypted `metadata` JSON, merging user keys under a **reserved
  `"user"` sub-key** (`{"correlation_id": ..., "user": {k: v, ...}}`) so it never collides with ADR
  0013 lineage, then re-encrypts. Merge is per-key upsert (last-writer-wins within the message).
- **Read-only PHI-safe surface:** the existing `MessageSummary.metadata` (`api/models.py:40`) is
  populated from the `"user"` sub-key as a JSON string; it is treated as **PHI** (already encrypted at
  rest, already redaction-gated with `summary` in the list/detail views). No write route — the only
  producer is a Handler; operators and the console see it read-only.

## Options considered
1. **Reuse `messages.metadata` under a reserved `"user"` key (chosen).** Zero schema change, inherits
   EF-3 encryption + retention + the reserved API slot. Trade-off: read-modify-write must merge with
   ADR 0013 lineage in-transaction (one extra SELECT on the parent row — already done for `pt_deliveries`).
2. **New `messages.user_metadata` column.** Cleaner separation from lineage, no merge. Trade-off: a
   migration on all three backends (SQLite/Postgres/SQL Server), a new encrypted-column registration in
   three places, and a new API field — cost the audit explicitly said was avoidable by reuse.
3. **Mutable `msg.meta[...]` dict on `Message`.** Best ergonomics, matches Corepoint feel most closely.
   **Rejected:** imperative mutation is an impure side effect — a re-run of a crashed transform could
   observe different external state, and it breaks the "no hidden state between handlers" isolation that
   `transform_one` guarantees by giving each handler its own payload.

## Consequences
- One new public name (`SetMeta`) + docs; `Message` API is unchanged. Symmetric with `SetState`, so
  the mental model is already established.
- `transform_handoff` gains a `meta_ops` param and one merge branch; byte-identical when empty.
- No new column, migration, or encryption registration — the bag is PHI from day one for free.
- A future `meta_get()` read-back (analogous to `state_get`) is a natural follow-up but is **out of
  scope**: #150 asks only to *write* and *surface*, not to read back within the pipeline.

## Invariant preservation
- **At-least-once:** the merge UPDATE is part of the single `transform_handoff` transaction
  (`store.py:2553`). Crash before commit → routed row recovers, transform re-runs; commit → the routed
  row is gone and re-invocation is a no-op. No new commit, no new failure window.
- **FIFO:** `SetMeta` produces no delivery and no wake — it rides the existing transform→outbound
  handoff untouched. Ordering is unaffected.
- **Purity / idempotent re-run:** `value` must be a pure function of the input message (author's
  contract, enforced by the same `to_thread` isolation and no-lookup rule as any transform). A re-run
  re-derives identical `SetMeta` ops → the per-key upsert re-applies the identical merged JSON. The
  write is the deliberate *in-transaction* apply, never a live external effect, so the ADR 0009 purity
  invariant holds exactly as it does for `SetState`.

## Ratified decisions (2026-07-10)

The Proposed open questions are resolved as follows (owner-ratified), favouring Corepoint parity,
simplicity, and consistency with ADR 0005:

1. **Sibling-handler races → last-writer-wins, documented.** A flat per-message bag matches Corepoint's
   `channelMap`, and it inherits ADR 0005 `SetState`'s existing non-linearized caveat rather than adding a
   new one. Two handlers writing the same key on one message is last-writer-wins; documented, not
   namespaced. (A handler-namespaced bag stays a future option if a partner needs order-independence.)
2. **Values are `str`; capped.** Restrict `SetMeta` values to `str` (the reserved `MessageSummary.metadata`
   wire type; simplest, Corepoint-faithful). Enforce a per-message bound — **≤ 32 user keys and ≤ 4 KiB
   total** decoded — to keep the encrypted column small; over-cap raises at transform time (a code error →
   dead-letter, never a silent truncation).
3. **Wire shape stays an opaque JSON string.** Keep `metadata: str | None` on `MessageSummary` (minimal API
   change; the slot is already `str`). A typed `dict[str, str]` console render is a later, additive UI
   enhancement, out of scope here.
4. **No pipeline read-back.** `meta_get()` within the pipeline is **out of scope** for #150 (write + surface
   only). If a transform ever needs to read a sibling's metadata, that is a separate ADR (it would also
   re-open the purity question).

## Acceptance Criteria

- A Handler returning `SetMeta(k, v)` persists `{k: v}` under the row's `metadata.user` sub-key, applied
  **inside** the `transform_handoff` transaction (no separate write, no new commit).
  → `tests/test_metadata_bag.py::test_setmeta_persists_under_user_key`
- Re-running a crashed transform re-applies identical metadata — idempotent and pure.
  → `tests/test_metadata_bag.py::test_setmeta_idempotent_on_rerun`
- ADR 0013 correlation lineage sharing the column is preserved, never clobbered by a user write.
  → `tests/test_metadata_bag.py::test_user_bag_coexists_with_correlation_lineage`
- `MessageSummary.metadata` surfaces the user bag **read-only** and PHI-redacted; there is no write route.
  → `tests/test_metadata_bag.py::test_metadata_surfaced_readonly_phi_safe`
- Values are `str`; the ≤32-key / ≤4 KiB per-message cap is enforced (over-cap dead-letters).
  → `tests/test_metadata_bag.py::test_str_values_and_cap_enforced`

## Amendment (2026-07-12) — egress-time metadata consumer for dynamic outbound HTTP headers (BACKLOG #68)

Decision #4 ("No pipeline read-back") deferred any metadata *read* path to a separate ADR because a
**transform** reading a sibling's metadata would re-open the purity question. BACKLOG #68 (per-message
outbound HTTP headers) adds a read path that is **not** that case, so it is recorded here rather than as a
new ADR:

- **What:** an opt-in **egress-time consumer**. A connector that sets `consumes_metadata` (surfaced as
  `dynamic_headers=True` on `Rest()`/`FHIR()`) reads the delivering row's user metadata bag at **send** time
  via a new read accessor `QueueStore.message_metadata_json` (3 backends), and `DestinationConnector.send()`
  gains a keyword-only `metadata=` param carrying it. A Handler stamps `SetMeta("http.header.<Name>", value)`
  (the existing, unchanged write path); REST/FHIR project the `http.header.*` entries onto the request,
  merged **over** the static headers (per-message wins).
- **Why it does NOT re-open purity:** this is a **delivery-time read at the egress boundary**, which is
  already a side-effecting, non-pure stage — not a transform reading metadata mid-pipeline. The **write**
  side stays `SetMeta`-only and re-run-safe (the bag is committed inside `transform_handoff`), so a re-run
  re-derives identical headers. The transform-purity invariant of #150 is untouched.
- **Default byte-identical:** only a `consumes_metadata` connector performs the extra read; the default
  delivery path and the perf-critical claim SELECT are unchanged.
- **Header safety:** `Authorization` is never per-message-settable; header names are validated to the
  RFC 7230 token grammar (bad names dropped); CR/LF/NUL/control chars are stripped from values (no header
  injection / request splitting).
