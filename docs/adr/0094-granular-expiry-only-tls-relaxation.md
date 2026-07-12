# 0094 — Granular expiry-only TLS relaxation per connection

- **Status:** Accepted (2026-07-12) — built (#129)
- **Date:** 2026-07-12
- **Related:** [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) (WP-13b MLLP-over-TLS) · [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) (posture-keyed hop refusal) · [ADR 0093](0093-pinned-internal-ca-trust-anchor.md) (pinned internal-CA trust anchor) · CLAUDE.md §2 (on-prem, offline-by-default) · CLAUDE.md §8 (ACK/NAK, transport security) · BACKLOG #129

---

## Context

Real hospital estates routinely present a partner **server certificate whose validity period has
lapsed** (`notAfter` in the past) — an internal PKI that missed a renewal, a long-lived integration
whose cert nobody re-issued. Today the only per-connection lever for such a hop is the blunt
`tls_verify=false`, which builds a `CERT_NONE` / `check_hostname=False` context: it drops **chain,
hostname, AND expiry together**, turning a merely-expired-cert hop into a fully **MITM-able** one. It is
also (correctly) refused off a trusted network unless `MEFOR_ALLOW_INSECURE_TLS`, and — per
[ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) — **refused outright
on a production-PHI instance**. So an operator whose partner's cert simply expired has no proportionate
option: they must either fix the far-end cert (often not in their control) or open the full MITM hole.

The forcing constraint is a Python-stdlib limitation the CLAUDE.md invariant "be **explicit about HL7
version**… don't rely on silent autodetection" mirrors in spirit for TLS: **stdlib `ssl` has no named
lever to ignore only the validity-period check.** `ssl.VerifyFlags` exposes `VERIFY_X509_STRICT`,
CRL-check, partial-chain, trusted-first, allow-proxy — but **no** `NO_CHECK_TIME`. Any relaxation must
therefore be built deliberately, and must **not** weaken the [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
cleartext/verify-off refusals or the reliability invariants.

## Decision

Add a per-connection opt-in **`tls_allow_expired`** (default `False` = byte-identical) that relaxes
**only** the certificate validity-period check on an **outbound verifying** TLS context, while the chain,
hostname, key-usage/EKU, and RFC 5280 strict path validation all **still apply**.

**Mechanism — the OpenSSL `X509_V_FLAG_NO_CHECK_TIME` verify flag, not `CERT_NONE`.** Although
`ssl.VerifyFlags` does not *name* it, `SSLContext.verify_flags` accepts a raw `int` OR, and OpenSSL's
`X509_V_FLAG_NO_CHECK_TIME` (`0x200000`, `openssl/x509_vfy.h` — a stable public constant, unchanged since
OpenSSL 1.0.2 through 3.5) disables **exactly** the `notBefore`/`notAfter` check during chain
verification and nothing else. A single shared helper — `config/tls_policy.py:relax_verify_expiry(ctx, *,
host)` — ORs that bit onto an already-**verifying** context (`CERT_REQUIRED`; it is a guarded no-op on a
`CERT_NONE` context so a caller bug can never be amplified into a silent downgrade) and logs a
construction-time WARN (`host` only — never a credential or a body).

The helper is threaded into every transport that builds an outbound verifying `SSLContext`, keyed on a
`tls_allow_expired` connector setting, on the **verify path only** (never the `tls_verify=false` /
`CERT_NONE` branch): `transports/mllp.py` (`_mllp_ssl_context`), `transports/remotefile.py`
(`_ftps_ssl_context`), `transports/dicom.py` (`_client_ssl_context`), and the urllib-opener HTTP family
`transports/rest.py` (`_expiry_relaxed_opener`, reused by `transports/soap.py` — incl. its mTLS opener —
and `transports/fhir.py`). Code-first factories (`MLLP`/`Rest`/`FHIR`/`Soap`/`DICOM`/`Ftp`) expose the
flag; `connections.toml` carries it as a plain setting.

**What it must NOT break.** (1) It **never** disables verification, so it composes with — and can never
bypass — the fail-closed no-CA / `tls_verify=false` refusals or the
[ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) posture-keyed
cleartext/verify-off hop refusal. Those predicates key on `tls_verify=false` / cleartext; because
`tls_allow_expired` leaves TLS on and verifying, an expiry-relaxed hop is **not** an insecure hop in the
#200 sense and is not refused (confirmed by test). (2) Default `False` is byte-identical (no flag ORed,
no opener change). (3) It composes with the [ADR 0093](0093-pinned-internal-ca-trust-anchor.md)
trust-anchor plumbing — a connection's own `tls_ca_file`, or the internal-CA anchor, still selects which
roots verify the peer; expiry relaxation only removes the time check from that verification.

### Config surface — reconciliation with "add it in config/models.py"

Every existing per-connection TLS knob (`tls_verify`, `tls_ca_file`, `tls_check_hostname`,
`tls_key_password`, …) lives in the connector's free-form `settings` mapping (`Source.settings` /
`Destination.settings` in `config/models.py`), **not** as a typed model field, and is read directly by
the connector's context builder. `tls_allow_expired` follows that exact convention (read via
`settings.get("tls_allow_expired")`) rather than introducing a one-off typed field that would need
separate threading through `_dest_config`. This is the faithful realization of "a per-connection opt-in
flag in `config/models.py`": it is a recognized key of the models' `settings` dict, surfaced by the
code-first factories.

## Acceptance Criteria

- **AC-1** — WHERE `tls_allow_expired=true` on an outbound TLS connection, WHEN the peer presents a cert
  whose `notAfter` has passed but whose chain and hostname are valid, THE SYSTEM SHALL complete the
  handshake and deliver.
  → `tests/test_tls_expiry_relaxation.py::test_expired_cert_accepted_only_with_flag`
- **AC-2** — WHILE `tls_allow_expired=true`, IF the peer cert's hostname does not match, THEN THE SYSTEM
  SHALL still reject the handshake.
  → `tests/test_tls_expiry_relaxation.py::test_wrong_hostname_still_rejected_with_flag`
- **AC-3** — WHILE `tls_allow_expired=true`, IF the peer cert chains to an untrusted anchor, THEN THE
  SYSTEM SHALL still reject the handshake.
  → `tests/test_tls_expiry_relaxation.py::test_broken_chain_still_rejected_with_flag`
- **AC-4** — WHERE `tls_allow_expired` is unset (default), WHEN the peer presents an expired cert, THE
  SYSTEM SHALL reject it (byte-identical to today).
  → `tests/test_tls_expiry_relaxation.py::test_expired_cert_accepted_only_with_flag`
- **AC-5** — WHEN the relaxation is enabled, THE SYSTEM SHALL emit a PHI-free WARNING naming the hop.
  → `tests/test_tls_expiry_relaxation.py::test_relax_sets_no_check_time_bit_and_warns`
- **AC-6** — IF `tls_verify=false` is also set, THEN THE SYSTEM SHALL NOT apply the expiry relaxation to
  that (already `CERT_NONE`) context, and the #200 refusal SHALL be unaffected.
  → `tests/test_tls_expiry_relaxation.py::test_verify_off_path_ignores_allow_expired`,
  `::test_allow_expired_is_not_a_refused_insecure_hop`

## Options considered

1. **OpenSSL `X509_V_FLAG_NO_CHECK_TIME` verify flag on the verifying context — CHOSEN.** One
   context-level primitive that OpenSSL applies **inside** the handshake, so it works **uniformly** for
   every transport that funnels through an `SSLContext` — asyncio (`open_connection`), `ftplib`,
   `pynetdicom`, and urllib HTTPS openers — with **no per-transport post-handshake re-verification** and
   no restructuring of dial paths. It keeps `CERT_REQUIRED` + `check_hostname`, so chain and hostname
   verification are demonstrably intact (tested). Downside: it relaxes **both** bounds of the validity
   period (`notBefore` as well as `notAfter`), i.e. a not-yet-valid cert is also accepted — see
   Consequences. The constant is a stable public OpenSSL value; if a future build ignored it the failure
   mode is **fail-closed** (the expired cert is simply rejected), never a silent broadening.
2. **Post-handshake verification with `cryptography.x509.verification`** (`PolicyBuilder().store(...)
   .time(<instant inside the cert window>).build_server_verifier(DNSName(host)).verify(...)`). The
   library and `.time()` **are** available (cryptography 49.0 in the lock), and this *can* ignore only
   `notAfter` by pinning the verification instant. **Rejected** as the primary mechanism: it operates on
   parsed certs **after** the TLS handshake, so it requires handshaking with verification **off**
   (`CERT_NONE`) and then re-verifying the peer chain — which is only cleanly reachable for the asyncio
   MLLP path (`ssl_object.get_unverified_chain()`), **not** for `ftplib` / `pynetdicom` / urllib openers,
   where we hand OpenSSL a context and never see the post-handshake socket. Adopting it would mean two
   different mechanisms across the five transports and a `CERT_NONE`-then-reverify window on each — more
   surface, more risk, for no additional safety over option 1. (It also cannot express "ignore only
   `notAfter`" any more *safely* than option 1 in practice: pinning the instant to the leaf's
   `notBefore` — the only instant guaranteed inside the whole chain's overlap — likewise accepts a
   not-yet-valid leaf.)
3. **Keep only `tls_verify=false`.** Rejected: it is the disproportionate, MITM-able lever this ADR
   exists to replace, and it is (rightly) refused on production PHI — leaving the expired-partner-cert
   case with no proportionate answer.

## Consequences

**Positive** — An operator can honour a lapsed-but-otherwise-valid partner cert **without** dropping
chain or hostname verification and without opening the `tls_verify=false` MITM hole; the relaxed hop stays
a *verified* hop, so the #200 production-PHI refusal does not fire and the operator is not forced onto the
blunt escape. Uniform, one-line application across MLLP / FTPS / DICOM-SCU / REST / SOAP / FHIR. Default
off = byte-identical.

**Negative / risks** — (1) `NO_CHECK_TIME` relaxes the **entire** validity-period check, so a
**not-yet-valid** cert (`notBefore` in the future — usually clock skew) is also accepted on a relaxed
hop; this is an accepted, documented trade-off (the alternative mechanisms share it) and is far narrower
than `tls_verify=false`. (2) The WARN fires at **construction** (the relaxation is enabled), once per
connector build — it does not fire per-accepted-cert, because the context-level OpenSSL flag does not
surface *which* presented certs were expired without extra post-handshake inspection we deliberately do
not add. Operators rely on the construction WARN + the deliberate config opt-in for visibility. (3) A
relaxed hop no longer alerts on an expired cert via a handshake failure — the operator has explicitly
accepted that; it remains their responsibility to restore a valid cert.

**Out of scope** — Inbound/mTLS **client**-cert expiry relaxation (the API server context verifying
client certs, ADR 0083) — a different trust role, not requested. Revocation (delegated per ADR 0002/0078,
unchanged). An audit-sink hook at context construction: these builders have no reachable `AlertSink`
(the established pattern — like the `tls_verify=false` warning — is the WARN log), so visibility is the
log line, not a structured audit event.

## To resolve on acceptance

- [x] Confirm the chosen mechanism keeps chain + hostname enforced (tested — AC-2/AC-3).
- [x] Confirm no interaction with the #200 posture-keyed refusal (tested — AC-6).
