# ADR 0085 — Direct-Project S/MIME-over-SMTP outbound connector (DIRECT-HISP, PR1)

*(final ADR number assigned at merge — placeholder to avoid multisession churn)*

- **Status:** Accepted (2026-07-10) — PR1 outbound-only; later phases deferred
- **Date:** 2026-07-10
- **Related:** [ADR 0029](0029-email-smtp-destination.md) (SMTP EMAIL destination — the STARTTLS/cleartext
  posture reused here) · [ADR 0003](0003-non-hl7-transports.md)/[ADR 0004](0004-payload-agnostic-ingress.md)
  (pluggable transports + payload-agnostic bodies) · CLAUDE.md §2 (reliability/purity invariants) · §7
  (no ad-hoc deps) · §9 (PHI rules) · BACKLOG #157

---

## Context

The Direct Project is the national standard for point-to-point exchange of clinical content between
trusted correspondents (HISPs). A Direct message is an **S/MIME message carried over SMTP**: the payload
is **signed** with the sender's certificate (authenticity + integrity) and **encrypted** to the
recipient's certificate (confidentiality), so PHI is protected end-to-end **independent of the transport
TLS**. Adopters migrating off Corepoint have Direct outbound feeds, so MessageFoundry needs a Direct
destination.

Two CLAUDE.md invariants bound the design:

- §7 — *"Verify a dependency exists … No ad-hoc installs — add deps to `pyproject.toml`."* A Direct
  connector must not pull a new crypto dependency if the core stack already covers it.
- §9 — *"Never log full message bodies at INFO or above."* / *"no PHI leaves the local environment
  without explicit, reviewed configuration."* The connector encrypts PHI to a partner and must be
  fail-closed on both the certificate trust chain and the egress host.

The pipeline's reliability model (§2) also applies: delivery is **at-least-once**, so a retry re-sends;
the transport must be side-effect-idempotent-tolerant (a duplicate is accepted, a drop is not).

## Decision

Ship a **`DirectDestination`** (`transports/direct.py`), registered as a new
`ConnectorType.DIRECT`, that in `send()` **SIGNs then ENCRYPTs** the Handler-produced body and submits
it as an `application/pkcs7-mime; smime-type=enveloped-data` message over STARTTLS SMTP, off the event
loop via `asyncio.to_thread`. Authored code-first via a `Direct()` factory in `config/wiring.py`.

Scope for **PR1 = outbound send only**. The following are **deferred** (named, not built):

- **inbound** Direct mail source (IMAP/POP read + S/MIME decrypt/verify),
- **MDN** (Message Disposition Notification) processed/dispatched receipts,
- **DNS CERT / LDAP** certificate discovery (`dnspython` deferred — the recipient cert + trust anchor
  are operator-supplied files here),
- **IHE XDR/XDM** document-exchange bindings.

**Crypto = core `cryptography` (`serialization.pkcs7`), no new dependency.** SIGN via
`PKCS7SignatureBuilder` (SHA-256, signer cert attached, `Binary` option so the body is byte-exact);
ENCRYPT via `PKCS7EnvelopeBuilder().add_recipient(recipient_cert)`. `endesive` was evaluated and
**rejected** (an avoidable dependency for what pkcs7 already does). SMTP is stdlib `smtplib`, reusing the
EMAIL destination's STARTTLS-by-default + `refuse_cleartext_credentials` posture verbatim.

**All cert/key material is loaded and cross-validated at construction** (fail loud, the `RestDestination`
pattern): signing key↔cert public-key match, recipient cert chains to the supplied trust anchor
(one-level `verify_directly_issued_by`; multi-level path building deferred), and a cleartext-credential
misconfig all raise at `check`/dry-run/start — never as a wire-time surprise.

**Egress gate = a new `[egress].allowed_direct` list** (fail-closed, `deny_by_default`-aware), kept
**separate** from `allowed_smtp` so an operator can permit a Direct HISP relay without opening generic
email egress — a distinct trust relationship carrying encrypted PHI. (Owner decision; the alternative of
reusing `allowed_smtp` was considered and rejected for that granularity.)

**What it must not break:** the reliability/purity invariants (transport is a pure sink; at-least-once
retry re-sends, duplicate accepted), the one-way dependency rule (`transports/` never imports
`pipeline/`), and the PHI-safe logging rule (error text names only host + failure class, never the body,
recipients, key material, or password).

## Acceptance Criteria

- **AC-1** — WHEN a Handler sends a payload to a DIRECT destination, THE SYSTEM SHALL sign it with the
  sender key+cert then encrypt it to the recipient cert, producing an S/MIME message a holder of the
  recipient private key can DECRYPT and whose signature VERIFYs against the signer cert.
  → `tests/test_direct_transport.py::test_sign_then_encrypt_round_trip`
- **AC-2** — IF the signing key does not match the signing cert, OR the recipient cert does not chain to
  the trust anchor, OR a required cert/key file is missing/malformed, THEN THE SYSTEM SHALL raise at
  construction (fail-closed, never accept-and-drop at wire time).
  → `tests/test_direct_transport.py::test_key_cert_mismatch_refused`,
  `::test_untrusted_recipient_refused`, `::test_missing_material_refused`
- **AC-3** — IF `use_tls=false` without the dev escape, OR SMTP AUTH credentials would cross cleartext,
  THEN THE SYSTEM SHALL refuse at construction.
  → `tests/test_direct_transport.py::test_cleartext_refusals`
- **AC-4** — WHEN a DIRECT host is not in `[egress].allowed_direct` (or the list is empty under
  `deny_by_default`), THE SYSTEM SHALL refuse the destination at load.
  → `tests/test_direct_transport.py::test_egress_allow_and_deny`

## Options considered

1. **pkcs7 sign-then-encrypt over stdlib SMTP, operator-supplied certs, outbound-only.** **CHOSEN.**
   No new dependency, reuses the EMAIL posture, ships the highest-value slice (outbound) first.
2. **`endesive` for S/MIME.** Rejected: a new dependency for functionality core `cryptography` already
   provides (§7).
3. **DNS-CERT discovery now (`dnspython`).** Rejected/deferred: adds a dependency + a network lookup on
   the delivery path; operator-supplied certs cover PR1.
4. **Reuse `[egress].allowed_smtp` for the host gate.** Rejected: conflates a Direct HISP relay with
   generic mail egress; a separate `allowed_direct` gives independent, honest fail-closed control.

## Consequences

**Positive** — Direct outbound feeds are supported with zero new dependencies; PHI is end-to-end
protected independent of transport TLS; misconfigured certs fail at `check`, not in production.

**Negative / risks** — One-level trust-anchor validation only (a multi-level chain must present the
issuing CA directly as the anchor); a single recipient cert per destination (no per-recipient cert map);
no MDN, so delivery confirmation relies on the at-least-once queue + AlertSink, not a Direct receipt.
All are documented and slated for later phases.

**Out of scope** — inbound Direct, MDN, DNS-CERT/LDAP discovery, IHE XDR/XDM, pixel/large-attachment
handling. Also deferred: **CMS signed attributes** required by the Direct implementation guide
(`signingTime`, `ESSCertIDv2`/`signingCertificate`) — PR1 signs with `NoAttributes | Binary` (the
signature is over the content directly, so authenticity + integrity hold and a plain
signature-over-content verification succeeds); the signed-attribute refinement is a later phase.
Both the sign and the **envelope encrypt** use `PKCS7Options.Binary` so binary bodies (and the signed
DER itself) are carried byte-exact — without it `cryptography` text-canonicalizes (lone LF → CRLF) and
corrupts a binary HL7/DICOM payload.

## To resolve on acceptance

- [x] Egress list: dedicated `allowed_direct` (owner-ratified).
- [x] Crypto library: core `cryptography` pkcs7 (endesive rejected, dnspython deferred).
- [x] Scope: outbound-only PR1; later phases named above.
