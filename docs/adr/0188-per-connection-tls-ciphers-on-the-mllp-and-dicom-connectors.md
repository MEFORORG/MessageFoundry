# 0188 — Per-connection `tls_ciphers` on the MLLP and DICOM connectors

- **Status:** Accepted (2026-09-14) — built. **Amended 2026-09-23 (BACKLOG #300):** unset now narrows to the
  approved suites on all four seams, and the approved list is the default on every context the engine
  builds, with recorded exceptions. See the amendment at the end; it supersedes AC-4, AC-5 and AC-6 below.
  **Amended 2026-09-26 (BACKLOG #2042, owner ruling R4):** the three AES-128-GCM suites leave the
  approved list, and TLS 1.3's `TLS_AES_128_GCM_SHA256` goes wherever the interpreter can remove it.
  See the second amendment at the end.
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

**One helper for the narrowing, and the assertion stays at the seam.** `tls_policy.apply_connection_tls_ciphers(ctx,
settings, *, connector)` reads the setting, validates it and applies it when present, and returns what
it applied. It is added *above* the existing `harden_cipher_suites(ctx, connector=...)` call at each of
the four seams, which stays exactly where it was. The four seams were already identical in shape, so
this is the whole change at each of them:

```python
harden_kex_groups(ctx)                                      # pin ECDHE groups (ASVS 11.6.2)
apply_connection_tls_ciphers(ctx, s, connector="<seam>")    # opt-in per-hop suite list (this ADR)
harden_cipher_suites(ctx, connector="<seam>")               # assert forward secrecy (ASVS 12.1.2)
```

**The assertion may not be folded into the helper, and that is a correctness constraint rather than a
style choice.** The ASVS 12.1.2 call-site guard
(`tests/test_tls_policy.py::test_every_context_that_pins_kex_groups_also_asserts_forward_secrecy`)
reads every context builder for `harden_cipher_suites` **by name**, so that a new seam cannot ship a
context nothing checked. A first draft of this ADR folded the two together behind one wrapper; the
guard went red on all four seams, which is the guard working. Its call-site half is the only
instrument that can see a seam with no assertion at all — the function-level tests exercise the
function, not its wiring.

**On order.** The seams narrow first and assert last, on the post-`set_ciphers` context the connector
will actually use. An earlier draft claimed the single helper was needed because a drifted order would
be unsafe. **That claim was wrong and is withdrawn here rather than quietly dropped**:
`validate_tls_ciphers` runs on the *string*, independently of `ctx`, and it is strictly stronger than
the assertion (allow-list included), so a seam that asserted before applying would still refuse every
string the policy refuses. What the trailing assertion genuinely adds is a check on the **real context
shape** — the validator probes a `PROTOCOL_TLS_SERVER` context, and a client context could in
principle resolve the same string differently. The order is therefore checked rather than structurally
guaranteed: `test_the_assertion_runs_on_the_post_set_ciphers_context` runs per seam, and swapping the
two calls on one seam reds that seam alone.

The setting name lives once, in `CONNECTION_TLS_CIPHERS_SETTING`, so four seams cannot spell it
differently — a misspelled key would read as "the operator set nothing" and would never fail.

**Config surface.** It follows [ADR 0094](0094-granular-expiry-only-tls-relaxation.md) §"Config surface"
exactly: a recognised key of the connector's free-form `settings` mapping, read by the context builder
via `settings.get(...)`, surfaced by the code-first factory — **not** a typed model field. Because
`connections.toml` desugars `[settings]` straight through the same factory ("the factory IS the
schema", `config/connections_file.py`), adding the factory parameter reaches the data surface too,
with no second schema to keep in step. Both surfaces are checked, not reasoned about:
`test_the_code_first_factories_carry_the_setting` and
`test_tls_ciphers_reaches_the_mllp_connector_from_connections_toml`. The DICOM half is factory-only
(see Consequences 3), and `test_dicom_is_still_absent_from_the_toml_transport_table` pins that so the
sentence above cannot quietly become half-false.

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

**AC-4, AC-5 and AC-6 are three independent instruments on one boundary, and they are
mutation-proven.** Making the unset path apply `ECDHE+AESGCM:ECDHE+CHACHA20` turns all twelve cases
red — four seams by three instruments — so none of them is a guard that cannot fail. They are kept
separate because they make different claims: AC-4 compares the resulting suite *set*, AC-5 forbids the
`set_ciphers` *call* (a call resolving back to today's default would satisfy AC-4 and still freeze the
list against a future interpreter), and AC-6 names the six suites the boundary exists to keep. AC-5
carries its own positive control — a class-level patch on a stdlib method is the kind that silently
misses its target, so the opt-in arm must record a call or the zero means nothing.

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
- [x] Confirm the ASVS 12.1.2 call-site guard still sees the assertion at all four seams.
      It did not, on the first draft, and that is why the assertion is not folded into the helper.

---

## Amendment (2026-09-23): the approved suites become the default (BACKLOG #300)

**The approved AEAD suites are now the default TLS 1.2 list on every context the engine builds, MLLP
and DICOM included, with the exceptions recorded in the table below.** This reverses the boundary the Decision above called hard. Two owner rulings
allow it, one for each half, and this section is the in-repo record of both.

### What changed

A new function, `tls_policy.narrow_to_approved_suites(ctx)`, calls `set_ciphers` with the eight
(five since the 2026-09-26 amendment below) TLS 1.2 names in `APPROVED_TLS12_SUITES`, in order. Every engine-built seam calls it before its
`harden_cipher_suites` assertion. On the four seams this ADR covers, `apply_connection_tls_ciphers`
calls it when `tls_ciphers` is unset, so those seams still read as the three calls shown above.

| Hop | Default before | Default now |
|---|---|---|
| MLLP listener and destination, DICOM SCP and SCU, the HTTP listener (it reuses the MLLP builder) | interpreter list, 6 CBC-SHA2 suites included | approved list |
| API / UI listener, apiclient, IDE extension client | interpreter list | approved list |
| REST, FHIR, DICOMweb, SOAP, SMART and OAuth2 token endpoints, `fhir_lookup`, alert webhook | interpreter list | approved list |
| SMTP (EMAIL, DIRECT transport, alert email), syslog forwarder, FTPS, OIDC IdP, Postgres store (pinned-CA and verify-off branches), `verify` smoke | interpreter list | approved list |
| Postgres store, default verifying branch | asyncpg's own context | **unchanged**: the engine passes `ssl=True` and asyncpg builds the context, the residual `store/postgres.py` already records |
| Windows tray `/health` probe (`tray/probe.py`) | `truststore` context | **unchanged**: a separate stdlib-plus-httpx package (ADR 0113); it talks only to the local engine, which now serves the approved list |
| At least: LDAPS (`ldap3`), Vault (`hvac`), the SQL Server store, the DATABASE connector and `db_lookup` (ODBC drivers) | library's list | **unchanged**: the library builds the context, as BACKLOG #1170's third category records |

A configured `tls_ciphers` or `[api].tls_ciphers` still wins over the default, and still runs the
same allow-list, which refuses CBC.

**The two properties that could have gone wrong, and were checked.** The narrowing uses the suite
NAMES, never a preference string, because option 3 below measured that a preference string adds two
DSS suites. And it writes the context's existing security level back in front of the names, so the
level is stated rather than left to the build. On OpenSSL 3.5.7 a bare string was measured to keep
the level anyway, so this is a guard, not a fix. It neither raises nor
lowers the level; raising it is a separate, counterparty-facing decision this amendment does not make.

### Why hops outside MLLP and DICOM could narrow

**Owner ruling 2026-08-22, recorded in BACKLOG #1170:** the interop rationale reaches only TLS on
MLLP and DICOM. The Context above and option 2 argued from hospital peers, and that ruling scopes the
argument to those two connectors. No other hop has a named peer class that needs CBC. So option 3's
rejection never reached the other hops, and narrowing them contradicts nothing this ADR decided.

### Why MLLP and DICOM narrowed too

**Owner ruling 2026-09-23, relayed on BACKLOG #300:** remove the six CBC-SHA2 suites from the MLLP
and DICOM TLS 1.2 defaults. State the risk plainly, because this ADR said the opposite:

- **No peer census was run.** The Context above gated retirement on one. The owner decided not to
  wait for it and accepted the interop risk. The premise that hospital peers still need CBC is still
  unmeasured in either direction.
- **A legacy CBC-only peer is served only by a reviewed code change to `_APPROVED_TLS_SUITES`.**
  There is no per-connection CBC override and no new loosening setting. `tls_ciphers` cannot reopen
  CBC, because the allow-list it runs refuses it (AC-3). This keeps the 2026-08-22 strict-allow-list
  ruling (BACKLOG #1317) intact.
- A peer that offers only CBC-SHA2 suites now fails the TLS 1.2 handshake at that one connection.

### Superseded acceptance criteria

AC-4, AC-5 and AC-6 asserted that unset changed nothing. Each keeps its instrument and flips its
claim, in `tests/test_connection_tls_ciphers.py`:

- **AC-4 (amended)** — WHERE `tls_ciphers` is unset, THE SYSTEM SHALL offer exactly
  `APPROVED_TLS12_SUITES` at TLS 1.2, in order.
  → `test_unset_resolves_the_approved_suite_list_in_order`
- **AC-5 (amended)** — WHERE `tls_ciphers` is unset, THE SYSTEM SHALL call `set_ciphers` exactly once,
  naming the approved list.
  → `test_unset_narrows_through_one_set_ciphers_call`
- **AC-6 (amended)** — WHERE `tls_ciphers` is unset, THE SYSTEM SHALL offer none of the six CBC-SHA2
  suites. → `test_unset_offers_none_of_the_six_cbc_sha2_suites`

And for the engine-wide default, in `tests/test_tls_default_suites.py`:

- **AC-7** — WHEN any engine-built hop meets a TLS 1.2 peer offering only a CBC-SHA2 suite, THE
  SYSTEM SHALL fail the handshake; WHEN the peer offers an AEAD suite, it SHALL complete. A stock
  context of the same shape completes against the same CBC-only peer, as the control.
  → `test_client_hop_refuses_a_cbc_only_server`, `test_server_hop_refuses_a_cbc_only_client` and
  their `accepts` pairs
- **AC-8** — Every engine-built hop SHALL offer `APPROVED_TLS12_SUITES` in order, and that order SHALL
  follow the stated rule: ECDHE before DHE, then AES-256-GCM, ChaCha20. (It read "AES-256-GCM,
  AES-128-GCM, ChaCha20" until the 2026-09-26 amendment below removed AES-128-GCM.)
  → `test_every_hop_offers_the_approved_list_in_order`, `test_the_approved_order_follows_the_stated_rule`
- **AC-9** — Every engine module other than `tls_policy.py` that calls `harden_cipher_suites` SHALL
  make at least as many narrowing calls. This is a per-module count: it cannot see a narrowing placed
  after the assertion or in an unrelated function, which the handshake tests catch for listed hops.
  → `test_every_module_that_asserts_a_suite_list_also_narrows_one`

### What this amendment does not change

The separation above stands: `harden_cipher_suites` asserts and never narrows, and the ASVS 12.1.2
call-site guard still sees it by name at every seam. It also asserts on library-built contexts that
the engine cannot narrow, which is why it must not apply the list itself. Key-exchange groups are not
touched: Python 3.14 cannot set them, so every hop still inherits OpenSSL's group list, which accepts
`ffdhe2048` (see `harden_kex_groups`). Counterparty key floors and the OpenSSL security level are out of scope.

---

## Amendment (2026-09-26): no AES-128 suite by default (BACKLOG #2042, owner ruling R4)

**The approved list no longer holds any AES-128 suite at TLS 1.2, and TLS 1.3 drops
`TLS_AES_128_GCM_SHA256` wherever the interpreter can.** The owner ruled option A of BACKLOG #2042
on 2026-09-26, on an adversarial review's recommendation, and did not ratify the alternative D1.

### What changed

`APPROVED_TLS12_SUITES` loses three suites: `ECDHE-ECDSA-AES128-GCM-SHA256`,
`ECDHE-RSA-AES128-GCM-SHA256` and `DHE-RSA-AES128-GCM-SHA256`. Five remain, in the interpreter's own
order. The apiclient and IDE copies lose the same three.

TLS 1.3 is out of reach of `set_ciphers`. A new `tls_policy.narrow_tls13_suites(ctx)` calls
`SSLContext.set_ciphersuites` with `APPROVED_TLS13_SUITES` where the method exists, and returns
whether it did. `narrow_to_approved_suites` calls it, and so does each branch that applies an
operator `tls_ciphers` string.

| Where | TLS 1.2 | TLS 1.3 |
|---|---|---|
| Every engine-built hop in the first amendment's table, and the apiclient | 5 suites, no AES-128 | CPython 3.14: all three suites, `TLS_AES_128_GCM_SHA256` included. **A recorded gap, not an override.** CPython 3.15: 2 suites, with no code change |
| IDE extension client (Node) | 5 suites, no AES-128 | 2 suites now: Node's `ciphers` option reaches TLS 1.3 |
| The library-built hops the first amendment lists as unchanged | unchanged | unchanged |

**The CPython 3.14 residual is recorded, not accepted by override.** CPython 3.14 has no
`set_ciphersuites`, so no engine code can remove the TLS 1.3 AES-128 suite there. The allow-list
admits `TLS_AES_128_GCM_SHA256` only on an interpreter without that method, because a string the
operator cannot change must not fail validation. On 3.15 the admission and the suite leave together.

**A legacy peer that needs AES-128 is served by a reviewed change that widens the allow-list**, as
the 2026-09-23 CBC ruling already provides. There is no setting. `tls_ciphers` cannot select an
AES-128 suite, because the allow-list refuses it, so an operator string such as `ECDHE+AESGCM` now
refuses at load. `ECDHE+AESGCM+AES256:ECDHE+CHACHA20` is the equivalent that passes.

The same ruling covers `aes128-gcm@openssh.com` on SFTP and `aes128-gcm96` on Vault Transit. Those
are separate changes and are not recorded here.

### Acceptance criteria

In `tests/test_tls_default_suites.py`:

- **AC-10** -- WHEN any engine-built hop meets a TLS 1.2 peer offering only
  `ECDHE-ECDSA-AES128-GCM-SHA256`, THE SYSTEM SHALL fail the handshake. A stock context of the same
  shape completes against the same peer, as the control.
  -> `test_client_hop_refuses_an_aes128_gcm_only_server`,
  `test_server_hop_refuses_an_aes128_gcm_only_client` and the two `test_control_a_stock_*_aes128_*`
- **AC-11** -- WHERE the context has `set_ciphersuites`, THE SYSTEM SHALL set it to
  `APPROVED_TLS13_SUITES`; WHERE it does not, the call SHALL report that it did nothing.
  -> `test_narrow_tls13_suites_applies_the_approved_tls13_list_where_the_method_exists`,
  `test_narrow_tls13_suites_reports_nothing_done_without_the_method`,
  `test_the_tls13_aes128_residual_is_measured_as_the_recorded_gap`
- **AC-12** -- Every branch that applies an operator `tls_ciphers` string SHALL also narrow TLS 1.3.
  -> `test_every_operator_cipher_branch_narrows_tls13_too`
