# 0150. Client address on audit entries

Date: 2026-07-22

## Status

Accepted (2026-07-22) — built; pushes/PR owner-approved.

## Context

An `audit_log` row named **who** (`actor`) and **what** (`action`, `detail`) but never **where
from**. After an incident that is the question that matters: *which host pulled that bulk PHI
export?* The trail could say "alice ran `messages.export` at 03:14" and nothing more — so a
compromised workstation, a stolen token used from elsewhere, and alice at her desk were
indistinguishable in the record.

Two things look like they already answer this. Neither does.

**The one address-bearing audit event cannot reach the PHI routes.** WP-L3-13 emits
`auth.admin_action_new_ip` carrying `known_ip`/`seen_ip`, but `AuthService.flag_new_client_ip` is
called from exactly four places — `require_step_up`, `require_reauth_only`,
`require_step_up_action`, `require_reauth_only_action` — and:

- the single-message raw-PHI view (`GET /messages/{message_id}`) is gated by **`require_phi_read`**,
  which never calls it at all;
- even on `/messages/export` (which *is* `require_step_up`), the signal returns `False` immediately
  unless `[auth].admin_new_ip_step_up` is on — it is **off by default** — and then only fires when
  the address **differs** from the session baseline, deduped per `(session, address)`.

So on a default deployment it never fires; on an enabled one it fires only on a *change*, and it
writes its own `auth.*` row rather than attributing the export row.

**The session record is actively misleading, not merely lossy.** `sessions.client` is captured at
**login**. On a replayed token it therefore holds the **original victim's** address, so joining an
audit row to its session to recover "where from" produces a confident, wrong answer that points at
the victim's host instead of the attacker's. A missing field is a gap; this is a false lead.

The address must therefore live on the audit row itself, stamped at write time.

## Decision

**1. A nullable `client` column on `audit_log`, on all three backends.** SQLite `TEXT`, Postgres
`TEXT`, SQL Server `NVARCHAR(256)` — matching `sessions.client` so the two attribution columns share
one width. Each backend uses its own established additive-migration idiom (SQLite
`PRAGMA table_info` + `ALTER TABLE ADD COLUMN`; Postgres `ADD COLUMN IF NOT EXISTS` in the idempotent
DDL list; SQL Server `IF COL_LENGTH(...) IS NULL ALTER TABLE ... ADD`).

**2. The address is folded into the CHAINED payload, as a conditional trailing element.** This is the
load-bearing decision, and it has two halves.

*Why chained at all.* The obvious cheap option — an unchained sibling column — was rejected.
`row_hash` is what makes the log tamper-evident; a `client` outside it could be rewritten by anyone
who can write the table without breaking verification. Attribution an attacker can silently edit is
**worse than no attribution**, because it invites reliance.

*Why conditional.* `audit_row_hash` canonicalizes as
`json.dumps([prev_hash, ts, actor, action, channel_id, detail], sort_keys=True, default=str)`. An
**unconditional** 7th element would append `null` to the payload of every row written before the
column existed, changing their digests and breaking verification at the **first legacy row** — on
every existing deployment, at upgrade. So the element is appended **only when `client is not None`**:

```python
fields = [prev_hash, ts, actor, action, channel_id, detail]
if client is not None:
    fields.append(client)
```

A row with no client hashes over the same 6-element list as before and its stored `row_hash` still
verifies **byte-identically**. One chain therefore spans pre- and post-upgrade rows, and the frozen
keyless-digest fixture (the pre-#190 compatibility gate) is untouched.

This composes with the existing #190 keyed-chain watermark without interacting with it: keying
chooses SHA-256 vs HMAC over the canonical bytes, this decision chooses what those bytes contain. A
store can have a keyless legacy prefix, a keyed suffix, and old- and new-format rows interleaved
throughout, and all of it verifies.

*Ambiguity.* The encoding stays injective across the two shapes because JSON is uniquely decodable: a
6- and a 7-element list can never render to the same bytes, and string values are escaped, so no
crafted `detail` can forge the trailing `, "<client>"` of the longer form. Pinned by test.

**3. The address is threaded EXPLICITLY, never carried ambiently.** A `ContextVar` was considered and
**rejected**: it leaks across `asyncio.create_task` boundaries, so a background worker spawned during
a request would inherit the live operator's address and stamp it onto unrelated `system` rows —
corrupting the audit record rather than improving it. `record_audit` takes `client=`, API callers
pass `client_ip(request)`, and engine-internal writers pass nothing.

**4. `NULL` means "no client was in scope" — never "unknown", never inherited.** Three places keep
NULL deliberately, because a plausible-looking address there would be a *false* attribution:

- `_SummaryAuditCoalescer._emit` — one `summary_access` row coalesces many requests across an hour
  window and is also flushed at engine shutdown; no single address describes it;
- the **dual-control** `config_reload` executor — the row's `actor` is the original *requester* while
  the request in flight belongs to the *approver*, so stamping it would attribute one person's action
  to another person's host;
- `_audit_channel_denied` when handed to the console seam as a bare callback, which has no request.

**5. One extraction path.** `api/security.py::_client_ip` becomes public `client_ip` and is reused
verbatim. A second extractor would eventually disagree with the first about proxy handling — it
already resolves `X-Forwarded-For` via uvicorn's `forwarded_allow_ips = [api].trusted_proxies` — and
then the audit trail would contradict the new-client-IP risk signal that reads the same value.

**6. The address travels off-box and is readable.** `emit_audit_tee` forwards it as a **discrete**
field so a SIEM can index it without parsing the redacted `detail`; it is an infrastructure
identifier, not message content, so it is **not** run through `safe_text`. `AuditEntry` gains
`client`, so `GET /audit`, the webconsole audit page, and the `audit:export` CSV all carry it.

## Consequences

**Attribution now exists where it was needed.** The raw-PHI view, the bulk export, the admin actions,
the RBAC denials, and both halves of every dual-control ceremony record the host. 30 of the 55 auth
audit sites had an address genuinely in scope (login, MFA, reauth, credential flows — they already
received it for `sessions.client` and the out-of-band notice) and now record the *same* address the
session does, so the two can no longer disagree.

**Existing stores upgrade silently and keep verifying.** The migration is a nullable `ADD COLUMN`; no
existing `row_hash` is recomputed or rewritten. `verify_audit_chain` passes over a store containing
both formats — proven by test, including the real upgrade path (open a DB whose `audit_log` predates
the column).

**Privacy.** An IP is personal data under our PHI posture, but it is **not PHI** — it identifies a
host, not a patient, and it is exactly the datum HIPAA §164.312(b) audit controls exist to capture.
It stays **plaintext at rest**, on the same footing as `audit_log.detail` and `sessions.client`:

- it must be greppable/indexable for incident response, which is the whole point of recording it;
- it is already stored in the clear in `sessions.client`, so encrypting it here would buy nothing
  while making the two columns inconsistent;
- it is now *inside* the hash chain, so it carries **integrity** protection (tamper-evident) even
  though it has no confidentiality protection — which is the property that matters for an audit
  field.

The residual is that it widens what a store-file compromise reveals, from "who did what" to "who did
what from where". That is judged acceptable and is the intended trade: it is the same exposure the
off-box SIEM copy already carries, and the volume-encryption + owner-only-ACL guidance in
[PHI.md §10](../PHI.md) is the control. Recorded in the at-rest inventory rather than hidden.

**Not done.** 25 auth audit sites are token-only or engine-internal and stay NULL; there is no
retention/minimization policy specific to the address (it ages out with the row); and no operator
setting exists to suppress it (an on-prem engine on a hospital private network has no plausible need
to, and suppressing it would defeat the control).
