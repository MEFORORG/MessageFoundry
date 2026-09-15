# 0188 — Per-connection `tls_ciphers` on the MLLP and DICOM connectors

- **Status:** Accepted (2026-09-14) — built
- **Date:** 2026-09-14
- **Related:** [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) (WP-13b MLLP-over-TLS) · [ADR 0025](0025-dicom-codec-store-connectors.md) (DICOM C-STORE connectors) · [ADR 0094](0094-granular-expiry-only-tls-relaxation.md) (the per-connection TLS opt-in this copies) · [ADR 0172](0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md) (the engine always serves TLS) · CLAUDE.md §9 (PHI on the wire)

---

## Context

The engine has a strict positive cipher allow-list, `_APPROVED_TLS_SUITES` in
`config/tls_policy.py`, and it governs exactly **one** operator setting: `[api].tls_ciphers`, wired by
a field validator in `config/settings.py`. That setting configures the engine's own API listener — the
hop a browser uses to reach the web console.

Every **partner-facing** hop had no cipher lever at all. The MLLP listener and destination
(`transports/mllp.py`) and the DICOM SCP listener and SCU destination (`transports/dicom.py`) each
build an `SSLContext` and inherit whatever suite list the interpreter's OpenSSL configures. They call
`harden_cipher_suites`, which **asserts** four properties on that inherited list — forward secrecy,
encryption, peer authentication, a 128-bit floor — and deliberately does **not** apply the allow-list.

So an operator who needed a narrower suite set toward one hospital peer had nowhere to say so. The
knob existed for the engine's own console and not for the hops that carry PHI between organisations,
which is the inversion this ADR closes.

**What the allow-list must NOT be extended to, and why.** `harden_cipher_suites` skips it on purpose,
and the reason is recorded in that function: the shipped inherited default carries **six CBC-SHA2
suites** (`ECDHE-{ECDSA,RSA}-AES{256,128}-SHA{384,256}` and the two `DHE-RSA-AES*-SHA256`) that the
AEAD-only allow-list excludes, so applying the list to an inherited context would refuse every current
configuration. A ruling was taken and it stands: **the allow-list governs what an operator may
CONFIGURE, never what a default may contain**, and the six are **not retired**. Third-party hospital
TLS stacks are not MessageFoundry users, and **no census exists** showing they can do without CBC.
Retiring those six is gated on running that census — not on an argument, and not on this ADR.

## Decision

Add a per-connection **opt-in** `tls_ciphers` to the `MLLP()` and `DICOM()` factories, covering both
directions on each — MLLP listener, MLLP destination, DICOM SCP listener, DICOM SCU destination.

**Unset is the default and it changes nothing.** A connection that does not set it builds exactly the
context it builds today: no `set_ciphers` call, the interpreter's inherited suite list, **the six
CBC-SHA2 suites still negotiable**. This is the hard boundary of the change, and it is proven rather
than asserted — see AC-4 and AC-5.

**Set runs the same policy as the API knob.** The string goes through `validate_tls_ciphers` with
`require_approved_suites=True` — the identical function the `[api].tls_ciphers` field validator calls,
not a second copy — so an operator cannot put a NULL, anonymous, non-forward-secret or under-strength
suite on a hop carrying PHI. Opting in therefore **narrows** that one hop to AEAD. It is the operator
asking for the stricter list; it is not the engine imposing it on anyone who says nothing.

**One helper, not four threaded copies.** `tls_policy.harden_connection_cipher_suites(ctx, settings, *,
connector)` replaces the `harden_cipher_suites(ctx, connector=...)` call at each of the four seams. It
reads the setting, validates and applies it when present, and then runs the existing assertion. The
four seams were already identical in shape, so this is the whole change at each of them.

The **order** is why it is one helper. The assertion has to run on the context the connector will
actually use, which is the post-`set_ciphers` one; threading an option into four builders would let
that order drift on one of them, and a suite list asserted before it is replaced is an assertion of
nothing. Here the order cannot drift.

The setting name lives once, in `CONNECTION_TLS_CIPHERS_SETTING`, so four seams cannot spell it
differently — a misspelled key would read as "the operator set nothing" and would never fail.

**Config surface.** It follows [ADR 0094](0094-granular-expiry-only-tls-relaxation.md) §"Config surface"
exactly: a recognised key of the connector's free-form `settings` mapping, read by the context builder
via `settings.get(...)`, surfaced by the code-first factory — **not** a typed model field. Because
`connections.toml` desugars `[settings]` straight through the same factory ("the factory IS the
schema", `config/connections_file.py`), adding the factory parameter reaches the data surface too,
with no second schema to keep in step.

## Acceptance Criteria

- **AC-1** — WHERE `tls_ciphers` is set on an MLLP inbound, WHEN the listener context is built, THE
  SYSTEM SHALL negotiate exactly the suites that string resolves to.
  → `tests/test_connection_tls_ciphers.py::test_opt_in_applies_the_operator_suite_list`
- **AC-2** — Same for the MLLP outbound, the DICOM SCP inbound, and the DICOM SCU outbound (all four
  seams).
  → `tests/test_connection_tls_ciphers.py::test_opt_in_applies_the_operator_suite_list`
- **AC-3** — IF `tls_ciphers` names a suite the shared policy refuses (NULL, anonymous,
  non-forward-secret, under-strength, or simply not on the approved list), THEN THE SYSTEM SHALL raise
  at construction, naming the connector.
  → `tests/test_connection_tls_ciphers.py::test_a_suite_the_shared_policy_refuses_is_refused_here`
- **AC-4** — WHERE `tls_ciphers` is unset, WHEN any of the four contexts is built, THE SYSTEM SHALL
  resolve the **same** suite list as the untouched reference construction for that context shape.
  → `tests/test_connection_tls_ciphers.py::test_unset_leaves_the_inherited_suite_list_untouched`
- **AC-5** — WHERE `tls_ciphers` is unset, THE SYSTEM SHALL call `set_ciphers` **not at all** on any of
  the four contexts.
  → `tests/test_connection_tls_ciphers.py::test_unset_never_calls_set_ciphers`
- **AC-6** — WHERE `tls_ciphers` is unset, THE SYSTEM SHALL still offer the CBC-SHA2 suites the
  approved list excludes, wherever the local OpenSSL enables any.
  → `tests/test_connection_tls_ciphers.py::test_unset_still_offers_the_suites_the_allow_list_excludes`

## Options considered

1. **Per-connection opt-in validated by the existing allow-list — CHOSEN.** It gives the operator the
   lever that was missing, reuses one policy, and costs nothing to a connection that says nothing.
2. **Extend `_APPROVED_TLS_SUITES` to the inherited defaults** (make `harden_cipher_suites` apply the
   list). **Rejected**, and it is the one failure mode this work had: it would retire the six CBC-SHA2
   suites for every deployment at once, on an interop premise nobody has measured. `harden_cipher_suites`
   records that premise as unmeasured in its own comment. A census first, then a decision.
3. **Ship a narrower inherited default** (`set_ciphers` with an AEAD preference string when the
   operator sets nothing). **Rejected** for the same reason as 2, plus a measured second one already
   recorded in `harden_cipher_suites`: against the shipped default that string also *adds* two DSS
   suites the default did not enable, so it is not the tightening it looks like.
4. **A typed field in `config/models.py`.** **Rejected** — it would be the only typed per-connection
   TLS knob among a dozen untyped ones, needing its own threading through `_dest_config`, for no gain.
   ADR 0094 settled this shape.

## Consequences

**Positive** — A deploying site can pin one partner hop to AEAD suites without touching any other hop
and without a code change to the allow-list. The policy that guards the console hop now reaches the
hops that carry PHI between organisations. Default unset is unchanged, so no configuration that works
today stops working.

**Negative / risks** — (1) An operator can narrow a hop until a partner cannot negotiate with it; the
symptom is a handshake failure at that connection only, and the fix is to remove the setting. This is
the cost of any suite pin and it is why the default stays off. (2) The setting is a **tightening**, so
it is deliberately absent from `security_loosenings()`; `tests/test_security_posture_defaults.py`
records that classification with its reason, so a future TLS-shaped parameter cannot join it silently.
(3) `DICOM()` remains code-first only — it has no `connections.toml` transport name — so the DICOM half
of the setting is reachable from the factory and not from TOML. That is a pre-existing property of the
DICOM connector, unchanged here.

**Out of scope** — The other verifying TLS hops (REST / SOAP / FHIR / FTPS / DICOMweb / SMTP / LDAPS /
the database hops). Several of them assert through a library's own context (`build_asserted_https_handler`,
`assert_ldap3_tls_suites`) where applying an operator string is a different problem with its own
traps — `ldap3` in particular **swallows** an invalid `ciphers=` string, which `assert_ldap3_tls_suites`
already refuses to go near. Retiring the six CBC-SHA2 suites from the inherited default: still gated on
the peer census.

## To resolve on acceptance

- [x] Confirm the unset path performs no `set_ciphers` and resolves the reference suite list (AC-4, AC-5).
- [x] Confirm the opt-in path runs the same validator as `[api].tls_ciphers`, allow-list included (AC-3).
