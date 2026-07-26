# ADR 0120 — FIPS-provider mode attestation (report-only on /security/posture)

- **Status:** Accepted (2026-07-17) — owner-directed (demand-gated, BACKLOG #73); report-only, enforces
  nothing.
- **Deciders:** owner (the demand-gate trigger fired: a compliance/procurement requirement asked for a
  FIPS attestation) + a code-fact verification pass over the `ssl` / `_hashlib` primitives and the
  `/security/posture` seam.
- **Related:** [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) (the in-transit-TLS +
  revocation-delegation posture this reports alongside — **not** amended: this ADR adds no governance, only
  a read-out) · `config/tls_policy.py` (the pure `ssl`-policy home this helper joins) ·
  M5 `GET /security/posture` (the authenticated, `MONITORING_READ`-gated, audited posture route this extends)
  · BACKLOG **#73** (this build) · CLAUDE.md §9 (SECRET-1 — no key material leaves the box).

---

## Context

BACKLOG #73 is a **demand-gate** item: numbered for tracking, built only when a procurement / compliance
requirement demands a FIPS attestation. That trigger has now fired.

MessageFoundry owns **no cryptographic primitives** of its own. At-rest encryption is `pyca/cryptography`;
in-transit TLS is stdlib `ssl` over the interpreter's linked OpenSSL. Whether that OpenSSL is running its
**FIPS provider** (OpenSSL 3.x `fips` provider active, i.e. `EVP_default_properties_is_fips_enabled`) is a
property of the **operator's OS build**, not of anything this engine configures. A compliance buyer who has
deployed on a FIPS-validated OpenSSL wants to *see*, in the running instance, that the FIPS provider is in
force — today the only artifact is a FIPS-**permitted-curve** comment in `tls_policy.py`, which attests a
policy choice, not the runtime provider state.

CPython exposes the provider state directly: `_hashlib.get_fips_mode()` returns the OpenSSL library-context
FIPS flag as an `int` (`1` = FIPS provider active, `0` = not), and `ssl.OPENSSL_VERSION` is the linked
OpenSSL version string. Both are **stdlib, no new dependency**, and neither is secret material — a boolean
and a version string are metadata (SECRET-1 respected; unlike `key_id`, there is nothing one-way to hash
because there is no secret here at all).

### The scope trap this ADR names on the record

`_hashlib.get_fips_mode()` and `ssl.OPENSSL_VERSION` attest **the CPython interpreter's linked OpenSSL** —
the one `ssl` (TLS in transit) and `hashlib`/`hmac` use. They do **NOT** attest the *separately linked*
OpenSSL that lives **inside the `pyca/cryptography` wheel**, which is what actually encrypts PHI **at rest**
(ADR 0109 / the store cipher). On a manylinux `cryptography` wheel those are two different OpenSSL builds,
and only one of them may be FIPS. Reporting `fips_mode` as an unqualified "this instance is FIPS" would be a
**false attestation** about the at-rest path. So the field and every UI/doc string are scoped to *"the
interpreter's `ssl`/`_hashlib` OpenSSL"* and worded as **reported**, never *"FIPS-140 certified"*. Attesting
`cryptography`'s backend is a possible future extension (its `backend.openssl_version_text()` is available),
called out under "Out of scope".

## Decision

**Report the interpreter's OpenSSL FIPS-provider state on `GET /security/posture`; enforce nothing.**

1. A pure helper `fips_attestation()` in `config/tls_policy.py` returns `(fips_mode: bool | None,
   openssl_version: str)`:
   - `fips_mode` is `_hashlib.get_fips_mode() != 0` when the primitive is present, else **`None`** =
     *undeterminable* (an alternative / non-OpenSSL build with no `get_fips_mode`). The `getattr` guard is a
     **runtime** guard for that case, **not** a typing crutch — this repo's typeshed declares
     `_hashlib.get_fips_mode() -> int`, so it type-checks clean with **no** `type: ignore`.
   - `openssl_version` is `ssl.OPENSSL_VERSION` (always a string).
2. Two **additive, report-only** fields on `SecurityPosture`: `fips_mode: bool | None = None` and
   `openssl_version: str | None = None`. The `/security/posture` route populates them; the existing
   `MONITORING_READ` gate + `security.posture_view` audit already cover the read.
3. A metadata-only attestation row on the web console **Status** page's posture table, worded *"OpenSSL FIPS
   mode (ssl/_hashlib): reported / undeterminable"* with the version — never *"certified"*.

The engine **changes no behaviour on the value**: it does not refuse to start, does not warn, does not
select ciphers differently. FIPS enforcement is the OS OpenSSL build's job; this is a **read-out** so an
operator/auditor can confirm the deployment they intended. That is why this is a **decision note** that adds
a report to ADR 0002's posture surface rather than an **amendment** to ADR 0002's governance — no policy
changes, so ADR 0002's decisions stand untouched.

## Acceptance Criteria

- **AC-1** — `tls_policy.fips_attestation()` SHALL return `(bool, str)` on an OpenSSL build exposing
  `_hashlib.get_fips_mode`, and `(None, str)` when the primitive is absent; it SHALL never raise.
  → `tests/test_tls_policy_fips.py`
- **AC-2** — `GET /security/posture` SHALL include `fips_mode` (the interpreter OpenSSL's provider state,
  `null` when undeterminable) and `openssl_version`, both report-only. → `tests/test_security_posture_fips.py`
- **AC-3** — The read SHALL stay `MONITORING_READ`-gated and audited (`security.posture_view`), byte-identical
  to before; no new route, no enforcement. → `tests/test_security_posture_fips.py`
- **AC-4** — Neither field SHALL carry secret material (a boolean + a public version string only) — SECRET-1.
  → `tests/test_security_posture_fips.py`
- **AC-5** — The web console posture table SHALL render a report-only FIPS row worded "reported", never
  "certified". → `tests/test_webconsole_pages.py` (or the monitoring page test).

## Options considered

1. **Report-only `fips_mode` + `openssl_version` on the existing posture route, no enforcement** —
   **CHOSEN.** Smallest surface that satisfies the compliance-visibility trigger; reuses an already
   authenticated + audited route; adds no dependency and no behaviour change.
2. **Enforce FIPS (refuse to start when `get_fips_mode()==0`)** — rejected. MeFor owns none of the crypto;
   refusing to start over the OS OpenSSL's provider state would break every non-FIPS deployment for a
   property the engine neither sets nor can fix, and #73 is explicitly *attestation*, not enforcement.
3. **A dedicated `GET /security/fips` route** — rejected. It duplicates the posture route's auth + audit for
   one boolean; the FIPS state is exactly "effective security posture", which `/security/posture` already is.
4. **Report an unqualified "FIPS: yes/no" spanning at-rest too** — rejected as a false attestation: the
   interpreter's OpenSSL is not `cryptography`'s linked OpenSSL (the at-rest path). Scope the wording to the
   `ssl`/`_hashlib` OpenSSL instead.

## Consequences

**Positive**

- A compliance buyer can confirm, in the running instance, that the interpreter's TLS/hash OpenSSL is in
  FIPS-provider mode — through an already authenticated, permission-gated, audited surface.
- Zero new dependency (stdlib `ssl` + `_hashlib`), zero behaviour change, no store/schema edit.
- The scope caveat is on the record: the report is honest about *which* OpenSSL it attests.

**Negative / risks**

- **Partial attestation.** It does not cover `cryptography`'s at-rest OpenSSL. Mitigated by explicit wording
  ("ssl/_hashlib OpenSSL", "reported") and the future-extension note; an operator who needs the at-rest
  backend attested reads the caveat and knows to verify it separately.
- **`None` is a third state to render.** The console renders it as "undeterminable" (an alt/non-OpenSSL
  build); dashboards that consume the JSON gain a nullable field.

**Out of scope / NOT built here**

- **Attesting `cryptography`'s backend OpenSSL** (the at-rest path) via `backend.openssl_version_text()` /
  its FIPS state — a possible follow-up if a buyer requires the at-rest primitive attested too.
- **Any enforcement** — no serve refusal, no cipher change, no warning keyed on the value. FIPS enforcement
  stays the OS OpenSSL build's responsibility.
- **Formal FIPS governance in ADR 0002.** Left as-is; ratify an ADR 0002 amendment only if the owner later
  wants FIPS a governed requirement rather than a reported fact.
