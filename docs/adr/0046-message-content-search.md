# ADR 0046 — Message-content search (HL7 field-path / raw-content matching) under at-rest encryption

- **Status:** Accepted (2026-06-27, built — first slice in 0.2.10; keyed-token field-path index deferred)  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-27
- **Related:** BACKLOG #51 · [`store/crypto.py`](../../messagefoundry/store/crypto.py)
  `AesGcmCipher`/`_NONCE_BYTES` (the AES-256-GCM at-rest cipher this collides with) ·
  [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) (the **KeyProvider seam** — where that
  cipher's DEK is sourced: HSM/KMS/Vault/env/dpapi) · [ADR 0001](0001-staged-pipeline-architecture.md)
  (the staged store this searches) · [CLAUDE.md](../../CLAUDE.md) §2 (count-and-log / reliability — search is a
  read, it touches neither), §9 ([PHI.md](../PHI.md) §6/§8 — audited PHI access, PHI-at-rest
  inventory) ·
  [`store/crypto.py`](../../messagefoundry/store/crypto.py) `AesGcmCipher`/`make_cipher`/`Cipher` ·
  [`store/store.py`](../../messagefoundry/store/store.py)
  `list_messages`/`count_messages`/`_message_filter`/`_decode_row`/`_dec`/`_read` ·
  [`api/app.py`](../../messagefoundry/api/app.py) `list_messages` (the `/messages` route) +
  `_SummaryAuditCoalescer` (the coalesced PHI-access audit) ·
  [`api/security.py`](../../messagefoundry/api/security.py) `require_phi_read`/`require_step_up` ·
  [`api/field_authz.py`](../../messagefoundry/api/field_authz.py) (`messages:view_summary` /
  `messages:view_raw` per-property gate) ·
  [`parsing/peek.py`](../../messagefoundry/parsing/peek.py) `Peek.field` (the HL7 field-path resolver)

---

## Context

`/messages` today filters on **indexed metadata columns only** — `channel_id`, `status`,
`message_type`, `control_id` — assembled into a parameterized `WHERE` by
[`_message_filter`](../../messagefoundry/store/store.py) and run by `list_messages` /
`count_messages`. There is **no way to search inside a message**: an operator chasing "every ADT for
MRN 12345" or "any message that quotes accession `A8842`" cannot do it from the Log Search view — they
must already know the `control_id`, or open messages one at a time (each a `record_view` + audited
`message_view`). Mirth's message browser, by contrast, offers a raw/segment content search. BACKLOG
#51 asks for the same: **HL7 field-path (`PID-3`, `OBX-5`) and/or raw-content matching** in Log Search.

The matching surface is exactly the PHI-bearing one. `messages.raw` is the raw HL7 body; `summary`,
`error`, and `metadata` are PHI-bearing text columns. The hard constraint is that **all four are
AES-256-GCM-encrypted at rest** when a key is configured. The store's cipher seam
([`store/crypto.py`](../../messagefoundry/store/crypto.py) `AesGcmCipher`) encrypts each value to a
`mfenc:v1:<key_id>:<base64(nonce ‖ ciphertext ‖ tag)>` marker on write and decrypts on read via
`_dec`; `_decode_row` is where `list_messages` decrypts `error`/`summary`/`metadata` **after** the SQL
returns. The default is the `IdentityCipher` (no key → values stored as-is), but the **moment
encryption is on, the on-disk bytes for `raw`/`summary` are an opaque, per-row, randomly-nonced
ciphertext** — there is no order, no substring, no plaintext to match against in SQL.

This is the crux: **a plain SQL `LIKE '%MRN12345%'` over `messages.raw` is impossible while the cipher
is on.** AES-GCM with a random 96-bit nonce per write (`os.urandom(_NONCE_BYTES)`,
[crypto.py](../../messagefoundry/store/crypto.py)) means the same plaintext encrypts to different bytes
every time and the ciphertext is uncorrelated with the plaintext — by design, that is what makes it
PHI-at-rest protection. A column-level `LIKE` would silently match **nothing** on an encrypted store
and **everything-as-plaintext** on an unencrypted one — a correctness *and* a security trap (it would
appear to "work" in dev with no key, then go blind in any encrypted production deployment).

Two existing invariants bound any answer and **must not** be relaxed:

- **PHI-at-rest must stay encrypted** ([PHI.md](../PHI.md) §8). Whatever makes content searchable must
  not park plaintext PHI on disk outside the cipher. The whole point of `AesGcmCipher` is that a stolen
  database file yields no PHI; a search index that re-exposes `PID-3` in cleartext would undo that for
  the indexed fields.
- **Every PHI read is gated + audited** ([PHI.md](../PHI.md) §6, [SECURITY.md](../SECURITY.md)).
  `/messages` already runs behind `require_phi_read(MESSAGES_READ)`, redacts `summary`/`error` per the
  `messages:view_summary` gate ([field_authz.py](../../messagefoundry/api/field_authz.py)), and
  coalesces a `summary_access` audit row per actor/hour through `_SummaryAuditCoalescer`
  ([api/app.py](../../messagefoundry/api/app.py)). A content search that returns matched bodies is a
  **higher-PHI-exposure** operation than a metadata list and must inherit *at least* that posture.

## Decision

**Ship message-content search as a bounded SCAN-AND-DECRYPT-PER-ROW first slice — the only mechanism
that works while the store is encrypted — behind the existing `messages:view_*` gate + step-up + a
dedicated audit row, with a hard row/result cap and the decrypt run off the event loop. Defer the
structured HL7-field-path index, and decline the plaintext key-field index outright.**

### D1 — Scan-and-decrypt-per-row is the search mechanism (the first slice, the only one that works encrypted)

Content matching cannot happen *in SQL* once the cipher is on, so it happens **in Python, after
decrypt**, over a **bounded** candidate set:

1. **Pre-filter in SQL on the indexed metadata first.** The existing `_message_filter`
   (`channel_id` / `status` / `message_type` / `control_id` + the per-channel RBAC
   `_append_channel_scope`) narrows the candidate rows **before** any decrypt — so an operator who can
   give a date window / channel / type never scans the whole store. The content predicate is layered
   **on top of** that metadata `WHERE`, never instead of it.
2. **Decrypt and match per row, off the event loop.** For each candidate row, decrypt `raw` (and/or
   `summary`) via the store cipher (`_dec`) and test the operator's needle against the plaintext —
   either a raw substring/`re` match or, for a field-path query, the `Peek.field("PID-3")` resolver
   from [`parsing/peek.py`](../../messagefoundry/parsing/peek.py) (already the tolerant routing peek).
   Because decrypt is CPU work (AES-GCM) and `Peek` parses HL7, the scan runs **off the asyncio event
   loop** via `asyncio.to_thread` (the `db_lookup` / `WebhookTransport` off-loop pattern), so a long
   search never stalls the listener/router/transform tasks ([CLAUDE.md](../../CLAUDE.md) §6).
3. **A hard candidate-and-result cap — non-negotiable.** The scan is bounded by **both** a maximum
   number of rows decrypted (`scan_limit`, e.g. a few thousand) **and** a maximum number of matches
   returned (the existing `limit`, capped like `/messages`' `le=500`). When the scan hits `scan_limit`
   before exhausting the candidate set, the response says so (a `truncated`/`scanned` field), so an
   under-specified search degrades to "narrow your filters" rather than to a full-store table scan that
   decrypts every body. This is the cost ceiling that makes a slow-by-construction operation safe to
   expose.
4. **Same gate + step-up + per-property redaction as `/messages`, plus a dedicated audit row.** The
   search route runs behind `require_phi_read(MESSAGES_READ)` exactly like `list_messages`; results are
   redacted through `redact_unauthorized` so `summary`/`error` only render with `messages:view_summary`
   and any returned **raw body excerpt** is gated on `messages:view_raw`
   ([field_authz.py](../../messagefoundry/api/field_authz.py)). Because scanning decrypts bodies the
   caller never explicitly "opened," the search additionally requires **step-up** (`require_step_up`,
   [security.py](../../messagefoundry/api/security.py)) — it is a bulk-PHI operation, like replay — and
   writes a **dedicated `message_search` audit row** (actor + the metadata filters + the **needle's
   shape, never the needle value if it could itself be PHI like an MRN**, + rows scanned + matches
   returned), on top of the coalesced `summary_access` audit the redaction path already emits. An MRN
   needle is PHI; the audit records *that a content search ran and how much it touched*, not the search
   term verbatim.

This delivers #51's operator value — "find messages by what's *in* them" — while the store stays
encrypted, because matching is on the **decrypted-in-memory** plaintext, never on disk.

### D2 — The structured HL7-field-path index is a deferred second slice

A faster **field-path** experience (jump straight to "every message where `PID-3.1 = 12345`" without
decrypting non-candidates) wants a real index. The honest version of that index is one that **stays
inside the cipher**: e.g. a **deterministic, keyed token** of selected routing fields (an HMAC of the
normalized field value under the store key) so equality search is an indexed lookup of the token —
**never the cleartext field**. That is real design work (which fields; keyed-hash vs searchable
encryption; rebuild-on-rotation; the migration to backfill existing rows; equality-only vs
substring) and it **collides directly with the store-writer / pool-prewarm work** (§"To resolve").
So it is **explicitly deferred to a second slice** — D1's scan-and-decrypt is the shippable first
slice that needs no schema change and no new at-rest material, and it is *sufficient* for the
metadata-pre-filtered case that covers most operator searches.

### D3 — The plaintext key-field index is declined (PHI-at-rest exposure)

The tempting fast path — extract `PID-3` / `PID-5` / accession into **plaintext indexed columns** on
write so a normal SQL `LIKE`/`=` works — is **declined**. It would store the most-identifying HL7
fields **outside the AES-GCM cipher**, in cleartext, on disk: a stolen database file would then yield
those fields directly, **defeating the at-rest encryption for exactly the PHI an attacker most wants**
([PHI.md](../PHI.md) §8, [`store/crypto.py`](../../messagefoundry/store/crypto.py) `AesGcmCipher` — the
DEK keyed via the [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) KeyProvider seam). It is faster, but it is a
PHI-at-rest regression an encrypted-store deployment cannot accept. (If a future slice needs an index,
D2's *keyed-token* form is the route — fast **and** inside the cipher — not cleartext columns.)

### What this must not break

- **PHI-at-rest stays encrypted.** D1 matches on **in-memory** plaintext only; nothing new is written
  to disk, no plaintext PHI column is added (D3 declined). The `mfenc:` ciphertext on disk is unchanged.
- **Audited, gated PHI access.** Search inherits `require_phi_read` + the `view_summary`/`view_raw`
  per-property redaction, adds step-up + a `message_search` audit row — strictly **more** controlled
  than `/messages`, never less. No PHI needle value is logged.
- **Count-and-log / reliability (§2, ADR 0001).** Search is a **read** on the dedicated read-only WAL
  pool (`_read`); it never writes a `messages`/`queue` row, never touches dispositions, never blocks
  intake (the off-loop scan keeps the event loop free).
- **Unencrypted stores behave identically.** With the `IdentityCipher`, `_dec` is the identity, so
  scan-and-decrypt is just scan-and-match — same results, same caps; the search does not branch on
  whether a key is configured (it always matches post-`_dec`).

## Acceptance Criteria

> EARS form; each linked (`→`) to its test/fixture. `messagefoundry adr-analyze` checks each `→` resolves.

- **AC-1** — WHEN a content search is issued against an **encrypted** store, THE SYSTEM SHALL return
  the messages whose decrypted `raw` (and/or `summary`) matches the needle — i.e. it SHALL match on
  plaintext even though the at-rest bytes are `mfenc:` ciphertext (a plain SQL `LIKE` would match none).
  → `tests/test_message_search.py::test_content_match_on_encrypted_store`
- **AC-2** — WHERE the operator supplies a metadata filter (channel/type/status/control_id), THE SYSTEM
  SHALL apply it as the SQL pre-filter so only those rows are decrypted (the candidate set is narrowed
  before any decrypt).
  → `tests/test_message_search.py::test_metadata_prefilter_bounds_scan`
- **AC-3** — WHEN the candidate set exceeds `scan_limit`, THE SYSTEM SHALL stop after `scan_limit`
  decrypts and report the result as truncated rather than scanning the whole store.
  → `tests/test_message_search.py::test_scan_cap_truncates`
- **AC-4** — WHERE a field-path needle (`PID-3`) is given, THE SYSTEM SHALL resolve it via the HL7
  `Peek.field` path resolver against each decrypted candidate, returning only rows whose field matches.
  → `tests/test_message_search.py::test_field_path_match`
- **AC-5** — THE SYSTEM SHALL gate the route on `require_phi_read(MESSAGES_READ)` + step-up, redact
  `summary`/`error` for a caller lacking `messages:view_summary`, and gate any returned raw excerpt on
  `messages:view_raw` (identical per-property posture to `/messages`).
  → `tests/test_message_search.py::test_search_gated_and_redacted`
- **AC-6** — WHEN a content search runs, THE SYSTEM SHALL write a `message_search` audit row recording
  the actor + metadata filters + rows-scanned + matches, and SHALL NOT record the needle value when it
  could itself be PHI (no MRN-in-the-audit).
  → `tests/test_message_search.py::test_search_audited_without_phi_needle`
- **AC-7** — THE SYSTEM SHALL run the decrypt-and-match scan off the asyncio event loop, so a large
  search does not block the listener/router/transform tasks.
  → `tests/test_message_search.py::test_scan_runs_off_event_loop`
- **AC-8** — THE SYSTEM SHALL NOT introduce any plaintext PHI column or on-disk index of a PHI field
  (D3 declined): the at-rest schema/bytes are unchanged and `mfenc:` coverage of `raw`/`summary`/
  `error`/`metadata` is intact.
  → `tests/test_message_search.py::test_no_plaintext_phi_index_added`

## Options considered

1. **Plain SQL `LIKE` over `messages.raw` (the obvious first instinct).** Rejected outright: with the
   cipher on, `raw` is per-row random-nonced AES-GCM ciphertext (`crypto.py`) — a `LIKE` matches
   nothing and silently misleads. It only "works" on an unencrypted dev store, making it a correctness
   *and* security trap. This is the whole reason the ADR exists.
2. **Scan-and-decrypt-per-row, metadata-pre-filtered, bounded, off-loop, gated + audited — CHOSEN
   (first slice).** The only mechanism that works **while encrypted**, because it matches on
   decrypted-in-memory plaintext. Slow by construction, so it is bounded by a hard `scan_limit` + result
   cap and narrowed by the existing metadata `WHERE`, run off the event loop, and held to a *higher*
   PHI bar (step-up + dedicated audit) than `/messages`. No schema change, no new at-rest material —
   shippable now.
3. **Plaintext key-field index (extract `PID-3`/`PID-5` into cleartext columns for a fast `LIKE`/`=`).**
   Rejected (D3): fast, but stores the most-identifying HL7 fields **outside the cipher** in cleartext
   on disk — a direct PHI-at-rest regression that defeats `AesGcmCipher` for exactly the fields an
   attacker wants ([PHI.md](../PHI.md) §8). A stolen DB would leak them.
4. **Keyed-token / searchable-encryption field index (HMAC of the normalized field under the store key,
   indexed) — deferred (D2 second slice).** The honest fast index: equality search becomes an indexed
   token lookup, **inside the cipher** (never cleartext). But it is real design work (field selection,
   rebuild-on-rotation, backfill migration, equality-vs-substring) and **collides with the store-writer
   / pool-prewarm refactor**, so it is sequenced after the D1 slice rather than built first.
5. **Status quo (metadata filters only).** Rejected: leaves the operator unable to search by message
   content — the explicit #51 gap and the Mirth message-browser parity ask.

## Consequences

**Positive** — Operators get content search ("find by what's *in* the message") **with the store still
encrypted**, because matching is on decrypted-in-memory plaintext, not on disk. No new at-rest material
and no schema change (D3 declined, D2 deferred), so the first slice is small and additive. It reuses the
existing read pool, the `Peek.field` resolver, the `require_phi_read` + `view_summary`/`view_raw`
redaction, and the audit coalescer — and tightens the bar (step-up + a dedicated `message_search`
audit) for a bulk-PHI read. Unencrypted and encrypted stores return identical results.

**Negative / risks** — The scan is **slow by construction** on a poorly-filtered query (it decrypts +
parses per candidate row); the hard `scan_limit` + result cap turn that into a bounded, truncate-and-
tell operation rather than a full-store scan, but an operator with no metadata filter gets a
deliberately-narrow result and a "narrow your search" signal, not a global match. The off-loop scan
consumes a worker thread for its duration. Per-row decrypt makes content search markedly heavier than
the metadata `/messages` list — appropriate, since it is a higher-PHI operation. The keyed-token index
(D2) remains owed for any deployment that needs sub-second field-path search at scale.

**Out of scope / deferred** — The structured HL7-field-path **index** (D2 keyed-token form) is a second
slice. The **plaintext** key-field index (D3) is **declined**, not deferred — if an index ships it must
be the in-cipher keyed-token form, never cleartext PHI columns. Cross-message / full-text relevance
ranking, regex over `metadata`/`detail` beyond `raw`/`summary`, and a search UI in the IDE are not part
of this ADR.

## To resolve on acceptance

- [ ] **Confirm the ADR number is 0046** and that the coordinator adds the `Proposed` row to
  [docs/adr/README.md](README.md) (this worker does not touch the registry).
- [ ] **Pick the `scan_limit` default + result cap** and the truncated-response shape
  (`scanned` / `truncated` fields) — the cost ceiling that keeps the scan safe to expose.
- [ ] **Confirm the needle-redaction rule for the `message_search` audit** — record filter shape +
  counts, never an MRN-shaped needle verbatim ([PHI.md](../PHI.md) §6). Decide whether step-up is
  required for *all* content searches or only those that decrypt `raw` (vs `summary`-only).
- [ ] **Confirm the route surface** — extend `/messages` with a `content`/`field_path` query param vs a
  dedicated `/messages/search` — and that it reuses `_message_filter` + `_scope` for the pre-filter and
  `_SummaryAuditCoalescer` for the summary-exposure audit.
- [ ] **Land-order with the store refactor (the hard collision).** This is the **hardest store-read
  collision with the pool-prewarm sibling** — the per-row decrypt scan reads through `_read` / the
  shared read-only pool, so its candidate-iteration path must rebase cleanly onto the pool-prewarm /
  shared-read-pool store change. Coordinate the merge order so neither clobbers the other's `_read` /
  `list_messages` path before the scan loop lands.
- [ ] **Decide the D2 second-slice trigger** — which routing fields a future keyed-token index would
  cover, and the rotation/backfill story (an index keyed under the store key must rebuild on
  `rotate-key`, like the cipher's re-encrypt pass).
