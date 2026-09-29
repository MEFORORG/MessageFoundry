# 0202 — A Handler receives the whole decrypted message, so ASVS 11.7.2 is recorded as partial

- **Status:** Proposed
- **Date:** 2026-09-29
- **Related:** BACKLOG #1174 (ASVS 11.7.2), #1185 (ASVS 14.2.2) · [ADR 0005](0005-transform-accessible-state.md) ·
  [ADR 0105](0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md) · CLAUDE.md §1, §2, §9 · [`docs/PHI.md`](../PHI.md) §2

---

## Context

ASVS 5.0 requirement 11.7.2 reads: *"Verify that data minimization ensures the minimal amount of
data is exposed during processing, and ensure that data is encrypted immediately after use or as
soon as feasible."*

BACKLOG #1174 researched whether the engine can honestly pass it. Its finding, and the owner-ruled
ceiling, is that it cannot, and that the honest terminal state is a recorded partial. The row owes
one thing this ADR supplies: **the written decision on the Handler boundary.**

The boundary is the product. [`CLAUDE.md`](../../CLAUDE.md) §1 defines a Handler this way:

> **Handler** — a **code-first Python script** that takes a message from a Router, **filters →
> transforms**, then hands it to one or more *outbound* connections.

And §4 says what a Handler does with it: it "filters → transforms (via
[`Message`](messagefoundry/parsing/message.py)) → returns `Send`s to outbound connections." A Handler
is arbitrary Python written by the site. It may read any field, rebuild any segment, and send any
part of the message anywhere. A transform that could see only some fields would be a different
product.

The #1174 research also names what would **not** be an honest pass. Narrowing the Handler contract
is one. Counting the zeroization of the cipher's own buffers as "encrypted after use" is another.

## Decision

**A Handler receives the whole decrypted message, by design. The engine does not narrow it, and
ASVS 11.7.2 is recorded as partial on that ground.** Minimization is enforced at the surfaces
listed below, which sit outside the Handler.

### What a Handler receives

The transform worker decrypts a routed row and hands the Handler the whole body as a parsed
`Message` (HL7) or a `RawMessage` (other formats). No setting narrows it. The body's plaintext
lives in engine memory, as immutable Python strings and in every copy the Handler's own code makes,
for as long as that code and the garbage collector keep it. The persisted copy is re-encrypted by
the store cipher on every write (`store/crypto.py`).

### Where minimization is enforced

Each of these was read against the tree on 2026-09-29, at engine `origin/main` `8d389ad7b`. The list is
at least these; it is not complete.

1. **The router hot path reads named fields only.** Routing reads fields through the tolerant peek
   (`parsing/peek.py`) rather than building the full object model. The strict `hl7apy` model is
   opt-in per connection (`docs/PHI.md` §3, "Peek, not full-parse, on the hot path").
2. **PHI in API responses is withheld by default.** `api/phi_gate.py` defines `PhiGatedModel`. A
   gated property serializes as `null` until something explicitly releases it for that instance,
   and the release set defaults empty. `redact_unauthorized` in `api/field_authz.py` is what
   releases it, and only what the caller holds.
3. **`dryrun` redacts bodies unless asked.** `--show-phi` is off by default (`__main__.py`,
   the `dryrun` parser). Without it the CLI prints `<redacted N chars; pass --show-phi>` in place of
   each body. The trace (`pipeline/dryrun_trace.py`, `_safe_value`) turns every assigned local and
   message write into `"REDACTED"` under the same gate. The IDE mirrors it: `ide/src/stepsModel.ts`
   shows live values redacted by default.
4. **PHI-bearing API responses are not cached.** `api/app.py` serves `Cache-Control: no-store` on
   the `/ui` pages and on every route in `_NO_STORE_PREFIXES` and `_NO_STORE_ROUTE_PATHS`.
5. **The staged queue drops each row at handoff.** Each stage's row is consumed in the same
   transaction that writes the next stage's rows (CLAUDE.md §2), so the queue does not keep a
   message open between stages.

One more surface exists and is deliberately **not** counted here. An inbound's
`stream_threshold_bytes` detaches an over-threshold document into the encrypted attachment store
before the ingress commit, and re-attaches it only at the outbound. That is a real field-scoped view,
and the Handler still receives the message with the reference in it. It ships off by default
(`config/wiring.py`, `stream_threshold_bytes: None`), and it answers a different requirement, so it
must not be re-badged onto 11.7.2.

### Why 11.7.2 cannot pass on this ground

Three grounds. Any one is enough.

1. **The verb asks for encryption after use.** Every mechanism available to a CPython process is
   destruction at best, such as overwriting a buffer. Destruction is not encryption. OWASP removed the
   overwrite-sensitive-memory requirement in the 4.x to 5.0 cull and kept this one.
2. **The engine cannot list the copies.** A Handler is the site's own Python. Every split, slice,
   regex group and f-string it writes makes a new immutable object the engine never sees. A control
   that cannot list what it covers cannot claim to cover it.
3. **"As soon as feasible" changes when, not whether.** The in-process body is never re-encrypted.
   "Never" is not a point on that timeline.

These grounds do not rest on CPython having no way to wipe a `str`. #1174 measured that such a
way exists; it fails grounds 1 and 2 all the same.

### What this must not break

The Handler contract, the purity rule for Routers and Handlers (CLAUDE.md §2), and the
count-and-log invariant. This ADR changes no code.

## Acceptance Criteria

The decision is to leave the Handler boundary as it is, so these criteria pin the minimization
surfaces this ADR relies on. Each links to an existing test that already guards it.

- **AC-1** — THE SYSTEM SHALL serialize every PHI-gated response property as `null` until the
  route releases it for a caller who holds the permission.
  → `tests/test_field_authz_fail_closed.py`
- **AC-2** — WHEN `dryrun` runs without `--show-phi`, THE SYSTEM SHALL print no message body.
  → `tests/test_cli.py`
- **AC-3** — THE SYSTEM SHALL serve every PHI-bearing API response with `Cache-Control: no-store`.
  → `tests/test_no_store_phi_coverage.py`

## Options considered

1. **Keep the whole-message Handler, enforce minimization outside it, record 11.7.2 as partial.**
   It matches the product and makes no claim the code cannot back. **CHOSEN.**
2. **Hand a Handler only the fields it declares.** Rejected: it narrows the product's core contract,
   and #1174 names it as the move that would not be an honest pass.
3. **Wipe plaintext `str` objects after each transform.** Rejected: it is destruction, not
   encryption (ground 1); it cannot reach the Handler's own copies (ground 2); and a wiped string
   still matches its old `hash()`, which corrupts any dict holding it.
4. **Re-score 11.7.2 on the strength of a nearby control** (the no-store directive, the retention
   purge, the detach seam, or the sealed read-through caches of BACKLOG #1174 part C). Rejected:
   none of them is the clinical body in engine memory, which is the verb's subject.

## Consequences

**Positive** — The record states one reason for the partial, and the reason matches the code. No
reader has to wonder whether a narrower Handler contract was ever on the table.

**Negative / risks** — On a first deployment, the decrypted body of every message a Handler
processes would live in engine memory until garbage collection. Reading it needs access to the
engine process's memory: a core dump, a debugger, unencrypted swap, or a local administrator. That
exposure is the in-use residual `docs/PHI.md` §3 describes, which §10 carries as a stated
deployment requirement.

**Out of scope** — The ASVS record's own wording (the vault scorecard cell, a record act); the
decrypted in-process caches (BACKLOG #1185, and #1174 part C, which seals them); host-level memory
protection.

## To resolve on acceptance

- [ ] The owner confirms the Handler boundary stated here, which #1174 says is theirs to bless.
