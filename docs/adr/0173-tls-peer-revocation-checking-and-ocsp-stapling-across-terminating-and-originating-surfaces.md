<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors -->

# ADR 0173 — TLS peer revocation checking and OCSP stapling across terminating and originating surfaces

- **Status:** **Accepted (2026-08-23; the accept half ratified by the owner 2026-09-22).** The original
  change carried no code. The §4.3 build rider, tracked by BACKLOG **#1498**, is **PARTLY BUILT** as of
  2026-09-22: the SMART token endpoint and the syslog TLS forwarder are guarded; **the OIDC token and
  JWKS legs are not** (AC-4 carries the recipe and the reason). **Three of this document's own premises
  moved under that build and are corrected in place rather than rewritten** — see §4.3's amendment and
  the notice in §1.4. One of them reached a *decision* and not only evidence: §2.1 declined a
  direction-2 file CRL that BACKLOG #299 has since built. **Settled by the owner 2026-09-22. §2.1's
  amendment is the record, it is the only place this file states it, and it leaves reason 2 open.**
- **Date:** 2026-08-23 (ratified 2026-09-22)
- **Deciders:** owner (ratified the accept half 2026-09-22, owner ruling) · security working group
- **Related:** **extends [ADR 0078](0078-certificate-revocation-posture.md)** (Accepted 2026-07-10,
  owner-ratified — that ADR made the `[api]` in-process delegation an *enforced* start-time refusal;
  this one grades the two remaining directions and records why one of them is unbuildable) ·
  [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) §"Certificate revocation (12.1.4)"
  (the original documented residual) · [ADR 0023](0023-inbound-http-listener.md) (the inbound HTTP
  listener, which inherits the MLLP builder) · [ADR 0024](0024-smart-backend-services-token-provider.md) (the
  SMART token provider) · [ADR 0025](0025-dicom-codec-store-connectors.md) (DICOM SCP/SCU) ·
  [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) (the
  posture-keyed cleartext/verify-off refusals this composes with) · [ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (the
  posture the gates key on) · BACKLOG **#201**, **#1005** · **ASVS 12.1.4 (L3)** ·
  [CLAUDE.md](../../CLAUDE.md) §0 (not-deployed beta), §2 (on-premises, offline by default), §11
  (SDS-3.5 to SDS-3.8 — reviewing security prose)
- **Code references** are this worktree at `3f18051b`. `e52055c7` was cited while drafting and is no longer an ancestor of HEAD; `git diff e52055c7 HEAD -- messagefoundry/` is EMPTY, so every code line below is byte-identical either way. The revocation code cited
  below is byte-for-byte present on `origin/main` at `06ef8ec8` at the **same line numbers**
  (`harden_crl_check` at `tls_policy.py:215`, its three call sites at `api/tls.py:69`,
  `mllp.py:558`, `dicom.py:150`, and `check_inbound_revocation` in `wiring_runner.py`), verified with
  `git grep` against `origin/main`. Line numbers drift; locate exactly at implementation time.

---

## 1. Context

### 1.1 What ASVS 12.1.4 asks, and the reading this ADR applies to it

The requirement is **one sentence**, graded Level 3. Quoted exactly from the ASVS 5.0.0 source the
vault tracks (`docs/security/asvs-5.0.0-source/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv`,
line 254):

> Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP)
> Stapling, is enabled and configured.

**An earlier revision of this ADR misquoted that sentence** -- as "proper *certificate* revocation,
such as OCSP stapling" -- and asserted it "covers two independent behaviours". Corrected 2026-08-24
against the primary source. Two things follow, and **neither moves the verdict**:

* **The sentence names one behaviour and one example.** It contains no "client", no "peer" and no
  "server". ASVS uses the same `such as` construction one row up (12.1.1, "such as TLS 1.2 and TLS
  1.3") for a plainly non-exhaustive example, which is internal evidence that the operative noun is
  *proper certification revocation*. The client-side duty lives in a **different** requirement --
  12.3.2, Level 2 -- and that one is about *validation*, not revocation.
* **So the split into directions below is THIS ADR's reading, not the requirement's structure.** It
  is kept, because it is how the engine's surfaces genuinely differ and the two have different
  remedies. It is now labelled an interpretation rather than presented as the standard's wording.
  Whether the reasoning resting on it is amended is an **open owner decision**; the `fail` verdict
  stands either way, because a contested reading resolves to the worse verdict.

| # | Direction (this ADR's axes, not the requirement's) | The engine's role | The question it answers |
|---|---|---|---|
| **1** | **Staple my own status** | **terminating** (the engine is the TLS server) | can a client learn, from my handshake, that my certificate is still good, without fetching from my issuer? |
| **2** | **Check the peer's status** | **originating** (the engine is the TLS client) | is the certificate this partner just presented revoked? |

Neither is built. The rest of this section separates *why* per direction, because the two answers do
not share a fix.

### 1.2 THE RUNTIME CANNOT STAPLE, IN EITHER DIRECTION — and that is the first fact, not a footnote

Direction 1 is **unbuildable on every interpreter this project builds against**, not merely unbuilt. **THERE IS NO PINNED RUNTIME AND THIS ADR MUST NOT IMPLY ONE** -- corrected 2026-08-23 after the sibling ADR was refuted on exactly that phrase. `pyproject.toml:28` is `requires-python = ">=3.14"`, a FLOOR with no implementation constraint; there is no `.python-version`, `.tool-versions` or `runtime.txt`, and no OpenSSL pin anywhere. What is true is narrower and sufficient: CI exercises CPython 3.14 and the free-threaded 3.14t through `actions/setup-python`, no code branches on `sys.implementation` (zero occurrences), and the stapling surface is absent from the `ssl` module API that every conforming implementation shadows. The distinction decides
everything downstream: "nobody built it" opens a build item, "the runtime exposes no hook" does not.

Measured on this worktree, CPython 3.14.6 (`tags/v3.14.6:c63aec6`, Jun 10 2026) / OpenSSL 3.5.7
(9 Jun 2026):

```
sorted(a for a in dir(ssl.SSLContext) if any(k in a.lower() for k in ('ocsp','staple','status')))  ->  []
sorted(a for a in dir(ssl.SSLSocket)  if ...same filter...)                                        ->  []
sorted(a for a in dir(ssl.SSLObject)  if ...same filter...)                                        ->  []
```

**Positive controls, same `dir()` technique, so an empty list means absence rather than a dead
probe:** filter `verify` on `SSLContext` returns `['load_verify_locations',
'set_default_verify_paths', 'verify_flags', 'verify_mode']`; filter `cert` on `SSLSocket` returns
`['getpeercert']`. The instrument returns real attributes when they exist.

There is no `set_ocsp_server_callback` equivalent, no `status_request` extension surface, and no way
to attach a cached OCSP response to a stdlib handshake. **This is not a configuration the engine
failed to set. There is no configuration.**

Module-level `ssl` exposes exactly three names matching `crl|ocsp|staple`:
`VERIFY_CRL_CHECK_CHAIN`, `VERIFY_CRL_CHECK_LEAF`, and `enum_crls`. The first two check a CRL that
was **already loaded from a file** into the trust store. `enum_crls` is Windows-only and returns raw
bytes out of the OS certificate store; nothing in `messagefoundry/` calls it. **There is no fetch of
any kind**, so direction 2 is partly blocked too: the engine cannot request or read a stapled
response, and cannot do an OCSP or CRL-distribution-point fetch. What it *can* do is check a CRL an
operator placed on disk.

So the single revocation mechanism this runtime offers is a file-loaded CRL, and §1.4 shows the
engine built exactly that — on a third combination that neither graded direction covers.

### 1.3 What exists today on the two graded directions: nothing

**Four terminating surfaces. Zero stapling calls.** Each builds a `PROTOCOL_TLS_SERVER` context,
loads a chain, hardens key exchange, cipher suites and verify flags, and stops:

| Terminating surface | Context built at | Hardening | Stapling |
|---|---|---|---|
| Engine API, `/ui`, `/ws/stats` | `messagefoundry/api/tls.py:43` | `:49-53` chain, `:56` kex, `:57` suites, `:58` verify flags | none |
| MLLP inbound listener | `messagefoundry/transports/mllp.py:545` | `:549` chain, `:559-561` | none |
| Inbound HTTP/1.1 listener (ADR 0023) | `messagefoundry/transports/http_listener.py:419` | inherits the MLLP builder verbatim (`_mllp_ssl_context(s, server=True)`) | none |
| DICOM C-STORE SCP | `messagefoundry/transports/dicom.py:131` | `:142` chain, `:151-153` | none |

A repository-wide grep for `stapl` across `messagefoundry/` returns **six hits and every one is
prose** — a docstring or an operator-facing error string: `config/tls_policy.py:18`, `:203`, `:332`;
`pipeline/wiring_runner.py:6793`; `__main__.py:1716`, `:1734`. Zero code. Positive control on the
same path and technique: `harden_verify_flags` returns hits in seven files.

**Thirteen originating hops. None checks revocation.** Every one builds a verifying client context
and gets `harden_verify_flags` at most, which ORs only `ssl.VERIFY_X509_STRICT`
(`config/tls_policy.py:209-212`). Its own docstring states the limit: *"This is **strict validation,
not revocation checking**"* (`:202`).

| Originating hop | Context built at | What it carries |
|---|---|---|
| MLLP outbound | `transports/mllp.py:583`, `:585`; flags `:601` | HL7 message bodies |
| DICOM C-STORE SCU | `transports/dicom.py:454`, `:457`; flags `:471` | imaging headers |
| FTPS | `transports/remotefile.py:228`; flags `:253` | message files |
| REST / FHIR / DICOMweb / SOAP | `transports/soap.py:202`; the HTTP family rides urllib's own context via `_NO_REDIRECT_OPENER` (`transports/rest.py:267`) and builds none of its own -- `rest.py:275` and `:296` are the dev-escape openers, not this path | message bodies |
| SMTP and alerting egress | `config/tls_policy.py:1216`; flags `:1235` | alerts, Direct payloads |
| Shared pinned-anchor client builder | `config/tls_policy.py:1172`, `:1178` | anchors only; never touches `verify_flags` |
| Engine-to-store (asyncpg) | `store/postgres.py:752`, and `:760` where asyncpg builds it (`:729` is the `trust_server_certificate` escape, `CERT_NONE` at `:731`) | the whole PHI store |
| Syslog / SIEM forwarder (RFC 5425) | `logging_setup.py:310` | audit records |
| OIDC / IdP token and JWKS legs | `auth/oidc_http.py:99-101` | the client secret, the authorization code |
| SMART Backend Services token endpoint | **GUARDED 2026-09-22 (BACKLOG #1498) -- and this row's withdrawal was over-applied; see §4.3 correction 1.** The `ssl`-usage measurement stands: `transports/smart.py` contains ZERO `ssl` usage (`create_default_context`, `SSLContext`, `ssl.` all absent; control: 153 hits package-wide), `:183-184` is an opener and redirect handler, and it rides urllib's own context. **That makes it no member of the `harden_verify_flags` population and does NOT make it a non-hop**: the guard takes a scheme and a url. | the signed `client_assertion` |
| Shared engine-API client | `apiclient/client.py:214`, `:222` | session credentials |
| Windows tray probe | `tray/probe.py:123` | health only |
| TLS version prober | `config/tls_probe.py:97` | nothing; it scopes itself out at `:32` |

Two of these say so in their own shipped prose, which is the posture this ADR preserves:
`transports/rest.py:663` — the hop verifies the chain "(+ strict RFC 5280) but performs NO OCSP/CRL,
so a revoked-but-unexpired server cert is still accepted" — and `store/postgres.py:737`, the same
sentence for asyncpg.

### 1.4 ABSENT versus PRESENT-BUT-ORTHOGONAL — the one thing a reader will get wrong

**The engine DOES ship revocation checking. It is on neither graded direction.** Anyone who greps for
CRL code, finds `harden_crl_check`, and concludes 12.1.4 is partly satisfied has read the wrong axis.
Two axes, not one:

| | **terminating** (engine is the server) | **originating** (engine is the client) |
|---|---|---|
| **check MY OWN status** | **Direction 1. ABSENT — unbuildable (§1.2).** No stapling hook exists. | not a thing |
| **check the PEER's status** | **Direction 3. PRESENT, opt-in, default off.** `harden_crl_check` on a partner's *client* certificate. **Neither graded direction.** | **Direction 2. ABSENT.** Every client context gets strict path validation only. |

**Direction 3 is genuine revocation checking and it moves neither cell.** It is the same verb as
direction 2 — check the peer — performed in the **server** role, against a partner's client
certificate under mTLS. It staples nothing, so direction 1 is untouched. It never runs on an
originating context, so direction 2 is untouched.

> **THE MEASUREMENT BELOW IS FALSE AT HEAD, AND SO IS THIS SECTION'S CONCLUSION ABOUT DIRECTION 2.
> BACKLOG #299 IS WHY. Recorded 2026-09-22 with the #1498 build; nothing here was reversed by that
> build, which added no `harden_crl_check` call site.** #299 limb A (`3aa07e5d5`, *"outbound CRL
> revocation checking and the blanket-attestation clamp"*) landed **after** this ADR was drafted.
>
> Re-measured at HEAD, same instrument (`grep -rn '^\s*harden_crl_check('` over `messagefoundry/`):
> **seven call sites, not three, and four of the seven are CLIENT contexts** — `auth/oidc_http.py`,
> `logging_setup.py`, and `config/tls_policy.py` inside `build_verifying_client_context` and
> `build_anchored_https_handler`. The three original server-side sites are unchanged and still
> mTLS-only. Positive control on the same read: `harden_verify_flags` returns **eight** files (the
> ADR's seven plus `verify/smoke.py`), so the grep and the path are live.
>
> **What that costs this section:** its table cell *"Direction 2. ABSENT"* and its sentence *"It never
> runs on an originating context, so direction 2 is untouched"* no longer hold. Direction 2 now has a
> real, **opt-in, default-off** in-engine file CRL on originating hops. The two-axis framing this
> section exists to teach is unaffected and still correct — what moved is which cell is empty.
>
> **And it reaches the DECISION, not only the evidence: §2.1's *"Direction 2's buildable half is
> declined for now, on cost rather than on principle"* describes a build that has since happened.**
> #299 built the file-CRL-on-originating-hops that §2.1 declined, anchor-keyed, which is §2.1's own
> reason 1 accepted rather than avoided. **This notice does not reverse anything and no seat should
> read it as doing so** — it records that the accept half was ratified over a decline the tree had
> already overtaken. **The owner has since settled it; §2.1's amendment is the whole record and this
> notice does not restate it.** Direction 3's *"must not be
> counted toward either graded direction"* is untouched: that is still the terminating axis.

The measurement, with a positive control:

- **`ssl.VERIFY_CRL_CHECK` appears EXACTLY ONCE in all of `messagefoundry/`:**
  `config/tls_policy.py:276`, inside `harden_crl_check` (defined `:215-276`).
  Positive control for that search: the same grep over the same path returns `harden_verify_flags` in
  seven files, so the pattern and the path were live.
- **Exactly three call sites, and all three are `PROTOCOL_TLS_SERVER` contexts inside an
  mTLS-only branch:** `api/tls.py:69` (nested in `if client_ca is not None:` at `:60`),
  `transports/mllp.py:558` (nested in `if ca:` at `:550`), `transports/dicom.py:150` (nested in
  `if ca:` at `:143`). The inbound HTTP listener is a fourth beneficiary for free, because
  `http_listener.py:419` reuses the MLLP server builder.
- **The helper is careful, and each refusal is a measured failure mode**
  (`tls_policy.py:222-247` records them): it refuses a missing file (`:251-255`), refuses a CRL past
  `nextUpdate` (`:261-266`, because an expired CRL refuses *every* client rather than only revoked
  ones), loads through `cafile=` only, and asserts `cert_store_stats()["crl"] >= 1` (`:269-275`)
  because `cadata=` loads zero CRLs from the same bytes while still setting the flag.
- **Every default is off.** `config/settings.py:779` (`tls_client_crl_file: str | None = None`) and
  `config/wiring.py:1071` (MLLP), `:1356` (Http), `:2200` (DICOM) — all `None`.

So: the one mechanism the runtime offers is the one the engine built, and it built it on the axis
12.1.4's two graded directions do not name.

### 1.5 What the engine does instead: four enforced refusals and an attestation escape

The engine does not accept the gap quietly. It converts it into refusals that **admit the engine
performs no revocation** rather than claiming it does, which is what keeps them clear of SDS-3.7's
false-premise defect:

1. **Originating hops — `RevocationHopGuard`.** Refuses an off-loopback production-PHI verifying hop
   unless revocation is proven in front or attested. Disposition at `config/tls_policy.py:963-973`;
   the operator-facing detail at `:1032-1038`; `enforce_construction` at `:1040`. Wired at
   `transports/mllp.py:751-752`, `rest.py:1347`, `soap.py:403`, `fhir.py:370`, `dicomweb.py:261`,
   `email.py:239`, and `store/postgres.py:745` via `_refuse_store_revocation` (`:763`).
   **Nine sites since BACKLOG #1498 (2026-09-22), not seven** — `transports/smart.py` (the SMART
   token endpoint) and `logging_setup.py:_refuse_forward_revocation` (the syslog forwarder) joined
   under §4.3. Read the list as *"at least these"* and locate each by symbol: these line numbers were
   written in August and the §4.3 build moved several of them.
2. **Terminating `[api]` TLS — `in_process_tls_revocation_refused`** (`config/tls_policy.py:344`),
   wired at `__main__.py:1722`. `serve` refuses an in-process off-loopback `[api]` TLS bind unless a
   declared TLS-terminating reverse proxy (WP-15) or `MEFOR_TLS_REVOCATION_ATTESTED` proves
   revocation in front. Loopback and proxy-terminated binds never trip it.
3. **Terminating mTLS listeners — `check_inbound_revocation`** (`pipeline/wiring_runner.py:6779`,
   body `:6800-6826`). Refuses an mTLS listener that verifies client certificates with no
   `tls_crl_file`, on an enforcing production-PHI instance.
4. **Attestation escape, both directions.** `Source.tls_revocation_attested`
   (`config/models.py:269`, default `False`), `Destination.tls_revocation_attested`
   (`models.py:655`), and the blanket env read at `tls_policy.py:327-335`
   (`MEFOR_TLS_REVOCATION_ATTESTED`, constant at `:53`). An attestation that suppresses a would-be
   production-PHI refusal is **audited** at `tls_policy.py:1051-1060`.
5. **CRL expiry monitoring**, because an expired CRL refuses every client rather than only revoked
   ones: `MonitoredCert(kind="crl")` at `pipeline/cert_expiry.py:64`, inbound enrolment `:136-138`,
   dispatch `:261-271`, facts `:293-300`; the sink method at `pipeline/alerts.py:101` and the
   expired case logged at ERROR at `:317-331`.

**Rider 3 makes the load-bearing point in shipped code** (`wiring_runner.py:6791-6795`):
`harden_verify_flags` delegates live revocation to a proxy plus the OS trust store, which is credible
for the API and UI surface, but **an HTTP proxy can terminate neither MLLP framing nor DIMSE**. For
those two listeners the documented delegation does not reach, so the gate raises rather than resting a
control on a premise that is false for that transport.

### 1.6 Three hops cross with no signal at all

**TWO CONFIRMED originating hops** have **no guard of any kind** — no refusal, no warning, no audit line — **and the true population is larger and UNGRADED; the count and its correction live in §4.3 and nowhere else.** Two
of the three carry authentication material:

| Hop | Site | Crosses with |
|---|---|---|
| SMART Backend Services token endpoint | **GUARDED 2026-09-22 (BACKLOG #1498).** No `ssl` usage in the file at all, which is why the row was withdrawn -- over-applied, see §4.3 correction 1. | the signed `client_assertion` |
| OIDC / IdP token and JWKS legs | `auth/oidc_http.py:99-101` | the client secret, the authorization code, the identity assertion (its own comment, `:105-107`) |
| Syslog / SIEM TLS forwarder | `logging_setup.py`, `_build_tls_context` | audit records. **GUARDED 2026-09-22 (BACKLOG #1498)**, and it now calls `harden_verify_flags` -- which per §4.3 correction 2 asserts a flag `create_default_context` had already set, so read the "no `harden_verify_flags` either" clause this cell used to carry as a grep fact and not as a gap |

Measured: a grep for `revocation` in `transports/smart.py` returns **zero**. Positive control on the
same file, same technique: `refuse_cleartext_credential_hop` is imported at `:61` and called at
`:143`, so the file already reaches into `rest.py`'s refusal helpers and the grep was live.

The SMART module's trust argument (`smart.py:23-28`) does not cover this. It says `token_url` is
operator-pinned with no `.well-known` discovery and gated by `[egress].allowed_http`. **Pinning the
name does not check the certificate's status**, which is the whole point of revocation.

### 1.7 Beta framing (CLAUDE.md §0)

**Nothing above is a live exposure. There are zero deployments.** Stated conditionally: on first
deployment, a partner client certificate revoked this morning **would** keep authenticating to an
mTLS MLLP, HTTP or DIMSE listener until its `notAfter` unless the site sets `tls_crl_file` or
attests; a revoked peer server certificate **would** be accepted on every originating hop; and a
peer that requires a stapled response from an engine-terminated listener **would** fail the
handshake. There is likewise **no migration cost** to anything decided here — nothing to break and
nobody to notify. This never relaxes a control.

## 2. Decision

**Accept the ASVS 12.1.4 gap on both graded directions as a documented, enforced delegation — with
one build rider that the accept reasoning does not reach.**

- **Direction 1 (staple my own status while terminating): ACCEPT, and record it as RUNTIME-BLOCKED.**
  It is not implementable at any effort level on any interpreter this project builds against (§1.2, and see the scoping note there -- there is no pin, only a `>=3.14` floor). This closes it to build
  items until the runtime or the dependency set changes (§6).
- **Direction 2 (check the peer's status while originating): ACCEPT, delegated and enforced.** The
  only mechanism the stdlib offers a client is a file-loaded CRL with no fetch, and where the engine
  can enforce a decision it already refuses the hop rather than crossing it quietly (§1.5).
- **Direction 3 (the shipped opt-in client-certificate CRL): unchanged, and it does not count toward
  either graded direction.** It stays opt-in and default-off. The record must not cite it as partial
  12.1.4 coverage.
- **The unguarded hops in §1.6 are NOT accepted** (count and scope: §4.3). Accepting the *mechanism* is not accepting
  *silence*. Closing them needs no new dependency, no new control and no stapling, so the reasoning
  that justifies the rest does not apply to them. See §4.3.

### 2.1 Why accept rather than build

**Direction 1 has no build to authorize.** The one library that exposes OCSP handshake callbacks is
pyOpenSSL, and it is deliberately excluded from core: `pyproject.toml:160-161` records it as
"maintenance-mode upstream; hard-caps cryptography<51 — kept OUT of core so repo-wide cryptography
upgrades stay uncoupled". It resolves only transitively through the optional `webauthn` extra
(`requirements.lock:738`, `pyproject.toml:169`), and nothing under `messagefoundry/` imports
`OpenSSL.SSL`. Building direction 1 means reversing a recorded dependency decision, then adding a
fetch-and-refresh daemon with a cache, a refresh timer and a fail-open-or-closed ruling — an outbound
network dependency that contradicts the offline-by-default premise stated at `tls_policy.py:18` and
`__main__.py:1713-1716`.

**Honest limit on that claim:** pyOpenSSL is not importable in this venv (`ModuleNotFoundError: No
module named 'OpenSSL'`), so `set_ocsp_server_callback` was not `hasattr`-verified on 26.4.0 and is
not asserted here. The cost above is a floor, not a ceiling.

**And stapling protects the peer, not the engine.** A server that staples gains nothing itself; the
benefit accrues to the client, which is spared a fetch. Without the RFC 7633 must-staple extension on
the certificate, stapling is **soft-fail by design** — a client receiving no stapled response simply
continues. So the engine could staple flawlessly on all four surfaces and the observable delta could
be zero, because the property that makes it load-bearing lives in the peer's configuration, which the
engine cannot see, cannot enforce and gets no signal about. On MLLP and DIMSE those peers are partner
interface engines and modality gateways. Asserting that they consume stapled responses would be a
compensating control resting on an unverified assumption about third-party software, which SDS-3.7
forbids.

> **AMENDMENT 2026-09-22 — BACKLOG #299 BUILT THE CONTROL THE PARAGRAPH BELOW DECLINES. Read this
> before quoting that paragraph or any of its three reasons.** **Reason 1 fell. The cost framing did
> not.** One of the three cost reasons is false at HEAD, so the decline no longer rests on what it was
> written on — but reasons 2 and 3 still carry real cost, so *"on cost rather than on principle"*
> remains the right shape for what is left. **The accept in §2 is unchanged and this amendment reverses
> nothing** — the owner ratified the accept half on 2026-09-22 and chose to restate reason 1 rather than
> reopen the decision. The accept stands on its other legs: direction 1 is RUNTIME-BLOCKED (§1.2), and
> the delegation-and-enforcement reasoning (§1.5) is untouched.
>
> **Every *"at HEAD"* in this amendment was measured at `d3a7ef505`. Re-measure rather than trust it**,
> and note that this document's `3f18051b` code-reference baseline predates #299, so the line numbers
> in the original text below resolve against a tree that no longer exists. Locate by symbol.
>
> **Reason 1's stated limit is false at HEAD, and the shipped prose is where it says so.** The reason
> claims a file CRL *"reaches only hops with a pinned per-connection anchor"* and *"cannot reach the
> HTTP family"*. Neither holds. `resolve_trust_anchor`'s docstring records that the policy CRL *"rides
> along on every non-loopback arm, including the per-connection-CA arm and the `system` default
> (BACKLOG #299)"*. The HTTP family's single opener construction goes through
> `build_anchored_https_handler`, which loads the CRL onto urllib's own context. `[tls].crl_file`'s own
> comment states the rule plainly: every hop that resolves a trust anchor loads the CRL onto its own
> context. So #299 did not merely accept reason 1's narrower coverage — it reached past the limit the
> reason states. Locate each of these by symbol. §1.4's notice carries the call-site reading and this
> amendment does not restate it.
>
> **Two hops carry their own CRL key, because no trust anchor resolves for them:** the OIDC token and
> JWKS legs (`[auth].oidc_tls_crl_file`) and the syslog forwarder (`[logging].forward_tls_crl_file`).
> Read that as *"at least these"*. **The SMART token endpoint is NOT one of them** — it resolves an
> anchor against its own `token_url` and takes the instance-wide key, so it has no CRL setting of its
> own for a reader to go looking for (§4.3 correction 1).
>
> **What remains declined, which is the half still worth having a reason for.** The control is opt-in
> and default-off, so the **default** posture is what §2 accepts and what §7 grades as a delegated
> residual. No fetch of any kind is in scope in either direction (§5). Reason 3's publication-latency
> bound therefore stands, and so does its live-expiry hazard. That hazard is in fact **worse on this
> axis than on the terminating one**: `harden_crl_check` catches a stale CRL only at construction, and
> §1.5 rider 5's expiry monitoring enrols **inbound** CRLs only, so an originating CRL ships with no
> expiry alarm at all. The `capath=` refreshable drop that would answer this is still out (§5). And the
> CRL reaches a hop only where engine code can reach the context. A context engine code never touches
> at all never sees the policy — an `ldap3.Tls` or a `truststore` context, **not** urllib's, which
> `build_anchored_https_handler` does reach and load the CRL onto. And the requests-based client's CRL
> refusal is **pre-armed rather than active**: its own docstring records it as unreachable while those
> callers pass a default policy. So grade a hop by asking its context, not by reading a setting, which
> is what `context_checks_revocation` exists for.
>
> **Reason 2's premise is CONFIRMED, not moved — and reason 2 is NOT amended here.** #299 shipped the
> CRL-plus-system-roots combination reason 2 said would need a hard refusal, and shipped it without
> that refusal. `[tls].crl_file`'s own WARNING carries the premise live: `VERIFY_CRL_CHECK_LEAF`
> refuses a peer whose issuer has no CRL in the store, not only a revoked one. What changed is the
> remedy rather than the hazard — a documented warning, fail-closed, opt-in, loopback exempt. Whether
> reason 2 should say so in its own text is an open owner question this amendment does not settle.
>
> **What this amendment deliberately leaves alone — read it as *"at least these"*.** Reason 2's text
> and reason 3's text, both left standing unedited. And §6 rider 4, whose first trigger, *"the
> HTTP-family hops gain a pinned per-connection trust anchor"*, has already fired at HEAD — so the
> section a reader consults for *when do we revisit this* still reads as pending where it is not.

**Direction 2's buildable half is declined for now, on cost rather than on principle.** ADR 0078's
rejection of an in-engine client attacked **fetching**, and that reasoning does not reach a CRL an
operator drops on disk. A file-based CRL on originating hops is implementable today with the existing
`harden_crl_check`, unchanged. It is declined here for three reasons, and the third is the strongest:

1. **Coverage is narrower than the delegation it would sit beside.** File CRL reaches only hops with a
   pinned per-connection anchor. It cannot reach the HTTP family (REST, FHIR, DICOMweb, SOAP), which
   rides urllib's own context on the OS trust store — the largest group of originating hops. A site
   that terminates outbound at a revocation-checking egress proxy covers all of them. *(Overtaken
   2026-09-22: BACKLOG #299 built this, and wider than the limit stated here — see the amendment
   above. The egress-proxy sentence is unaffected and still true.)*
2. **It is unusable on the default trust posture.** `build_verifying_client_context`
   (`tls_policy.py:1171-1178`) loads the OS roots on the `system` and `augment` postures. With the
   check flag set and a CRL loaded for one CA only, a peer chaining to any other trusted CA is refused
   with `unable to get certificate CRL`. So the build would need a hard refusal of CRL-plus-system-
   roots, which narrows it further. *(Premise CONFIRMED and still live as of 2026-09-22 — but #299
   shipped this combination WITHOUT that hard refusal, so the conclusion in the last sentence no longer
   describes the tree. See the amendment above; this reason is not amended here.)*
3. **It converts a confidentiality gap into an availability hazard on the delivery path.** The engine
   already says so at `tls_policy.py:231-233`: an expired CRL refuses every peer. `harden_crl_check`
   catches a stale file **at construction**, where `check` and dry-run see it — but not the live case,
   where a CRL passes `nextUpdate` while the engine runs and every outbound delivery on that
   connection begins failing at once. The staged pipeline retries and dead-letters rather than losing
   messages, so it is a stall and a growing backlog, not data loss. It is still an outage caused by a
   control the operator installed. Against that, the security gain is bounded by publication latency:
   a CRL is a snapshot, so the revocation window stays days wide.

**This decline is a cost judgment on a currently-buildable control, not an impossibility finding.**
Do not restate it as one. §6 names what would flip it.

## 3. Acceptance Criteria

> Behavioural criteria in EARS form. Criteria 1 to 3 describe **shipped** behaviour this ADR ratifies
> rather than commissions, and link to the tests that already hold it. Criteria 4 and 5 are the §4.3
> build rider and carry no test ref until it lands.

- **AC-1** — WHERE an mTLS listener requires and verifies a client certificate and no `tls_crl_file`
  is configured, on an enforcing production-PHI instance, THE SYSTEM SHALL refuse the wiring rather
  than start
  → `tests/test_hop_refusal_wiring.py::test_mtls_without_a_crl_is_refused_on_an_enforcing_phi_instance`,
  `::test_a_configured_crl_passes`, `::test_tls_without_mtls_is_not_a_revocation_gap`.
- **AC-2** — WHEN a CRL is configured on an mTLS listener, THE SYSTEM SHALL refuse a revoked client
  and SHALL accept a good one, and WITHOUT the CRL SHALL accept the same revoked client
  → `tests/test_tls_policy.py::test_a_revoked_client_is_refused_by_a_crl_checked_context`,
  `::test_a_good_client_is_accepted_by_the_same_context`,
  `::test_without_the_crl_the_revoked_client_gets_in`. **The third is the untouched baseline and is
  the load-bearing one**: without it the pair cannot distinguish enforcement from blanket refusal.
- **AC-3** — IF a configured CRL file is missing, carries no CRL, or is already past `nextUpdate`,
  THEN THE SYSTEM SHALL raise at context construction rather than advertise revocation checking and
  perform none
  → `tests/test_tls_policy.py::test_harden_crl_check_refuses_a_missing_file`,
  `::test_harden_crl_check_refuses_a_file_carrying_no_crl`,
  `::test_harden_crl_check_refuses_an_already_expired_crl`.
- **AC-4** — WHERE an originating hop carries authentication material or audit records over verified
  TLS to a non-loopback host, THE SYSTEM SHALL apply the same posture-keyed revocation disposition the
  other verifying hops apply, and SHALL NOT cross with no refusal, no warning and no audit entry
  → all in `tests/test_hop_refusal_revocation.py`, beside the #201 and #299 arms for the same guard.
  **The SMART token endpoint**:
  `::test_the_smart_token_hop_is_refused_when_it_checks_no_revocation`,
  `::test_the_smart_token_hop_on_loopback_still_crosses`,
  `::test_the_smart_token_hop_crosses_on_a_per_connection_revocation_attestation`,
  `::test_a_cleartext_smart_token_hop_is_the_200_gates_refusal_not_this_one`,
  `::test_the_smart_revocation_attestation_comes_from_its_own_settings_key`.
  **The `[logging]` syslog TLS forwarder**:
  `::test_the_syslog_tls_forwarder_is_refused_when_it_checks_no_revocation`,
  `::test_the_syslog_tls_forwarder_on_loopback_still_crosses`,
  `::test_the_syslog_tls_forwarder_crosses_on_a_crl_that_really_loaded`,
  `::test_a_verify_off_syslog_forwarder_takes_no_revocation_guard`,
  `::test_a_syslog_forwarder_with_no_posture_is_unchanged`,
  `::test_the_forwarder_refusal_names_a_lever_that_exists_for_it`.
  **The not-refused arms are the load-bearing ones**, for the same reason AC-2's untouched baseline
  is: a guard that refuses everything passes a refusal arm on its own, and the CRL arm is the only one
  that proves the finished context reached the guard rather than a setting being read.

  **AC-4 IS PARTIAL: TWO HOPS OF THE THREE. THE OIDC TOKEN AND JWKS LEGS ARE NOT BUILT.** The wording
  above deliberately stopped enumerating the three hops, because a criterion that names a hop is read
  as covering it, which is the SDS-3.6 defect this ADR was careful about elsewhere. What remains is
  small and fully specified: `auth/oidc_http.py:build_idp_opener` builds the context both legs share,
  so the guard belongs there with `context=` (its `[auth].oidc_tls_crl_file` must relax it), and the
  posture has to be **threaded** rather than read ambiently because `AuthService` is constructed in
  the API lifespan, outside the `active_hop_posture` scope — the position `auth/ldap.py` and
  `store/postgres.py` are already in. `RevocationHopGuard.capture` now takes `posture=` and
  `ways_across=` (added by #1498) so that hop needs no new mechanism, only its call. Guard the two
  legs **separately**: they may be different hosts with different loopback status, so one guard keyed
  on the token host alone would let an off-box JWKS cross.
  *It was held out of #1498 for a coordination reason and not a technical one* — the caller change
  lands in `auth/service.py`, which another session held at the time. Recorded plainly because a
  dormant guard plus a caveat in an operator-facing security page is worse than an honest gap.
- **AC-5** — THE SYSTEM SHALL NOT assert in code, docstring, error text or documentation that it
  performs certificate revocation checking on either graded direction, and any prose naming the
  shipped client-certificate CRL SHALL state that it is the peer's certificate on a terminating
  listener → review gate; no test. **Re-checked against the #1498 build:** each new guard's
  `description` says the hop "performs no certificate revocation checking", which is the admission
  every sibling makes rather than a claim, and the new `harden_verify_flags` call sites are commented
  as strict validation and explicitly *not* revocation checking. No new prose asserts a check.

## 4. What this decides, hop by hop

### 4.1 Accepted with an enforced refusal in front

The `[api]` in-process bind (`__main__.py:1722`), the mTLS listeners (`wiring_runner.py:6779`), and
the seven guarded originating hops listed at §1.5 rider 1. On a named environment these refuse rather
than warn: `config/settings.py:2338-2342` derives `DataClass.PHI` for `dev`, `staging` **and** `prod`,
and `settings.py:3675` defaults enforcement to `SecurityEnforcement.ENFORCE`. The disposition ladder
at `tls_policy.py:963-973` has no global audited-opt-out arm (`:958-960`), so the only relaxations are
loopback, a proven terminator, an attestation, or a non-PHI posture.

**One caveat, stated so nobody reads more coverage into it than exists:**
`RevocationHopGuard.enforce_construction` **no-ops when the posture is unstamped** (`tls_policy.py:1044-1046`)
— a live serve build after the pre-flight, or a direct test or embedding. The `build_check` gate is
the authority there, by design. A configuration that names no environment and declares no data class
lands on the not-PHI ALLOW arm and gets nothing.

### 4.2 Accepted with no risk to accept

- **The default `[api]` bind** — `config/settings.py:726` (`host: str = "127.0.0.1"  # Phase 1 =
  localhost only`). Loopback short-circuits the refusal. No TLS terminated, no peer certificate,
  nothing to revoke. The web console is same-origin behind it.
- **Any inbound without mTLS** — `wiring_runner.py:6805-6806` returns early. No client certificate is
  requested, so none can be revoked.
- **Raw TCP and X12 inbound** — `wiring_runner.py:6797-6799` records that they have no TLS option.
- **The TLS version prober** — `config/tls_probe.py:97`, which scopes itself out at `:32`: verifying
  real traffic "is a different control (12.1.4 / `harden_verify_flags`)".

### 4.3 NOT accepted — the build rider

> **PARTLY BUILT 2026-09-22 under BACKLOG #1498, and this section's own premises moved under it. Read
> the amendment below before quoting anything in the original text that follows it.** Two of the three
> hops are now guarded — the SMART token endpoint and the syslog forwarder. **The OIDC token and JWKS
> legs are NOT**, and AC-4 carries the recipe and the reason. **The rider's number is #1498, not a
> fresh allocation** — the text below says to allocate one when the build starts, and it predates
> #1498, which was filed to be this rider's tracking item.
>
> **Correction 1 — the SMART hop was withdrawn on a ground that does not reach it.** §1.3, §1.6 and §7
> withdrew the SMART row because `transports/smart.py` contains **zero `ssl` usage**. That measurement
> is TRUE and it was over-applied. It removes the file from the `harden_verify_flags` population,
> which is what it was taken for; it does **not** remove the hop, because
> `refuse_unrevoked_verified_hop` takes a **scheme and a url and never a context** — exactly for hops
> that ride urllib's shared opener and build no context of their own, which is the whole HTTP family.
> The hop is real and separately addressable: #1660 resolves this hop's trust anchor against
> `token_url` precisely because *"the authorization server is frequently a different host from the
> FHIR/REST endpoint"*, so the sibling guard on the REST/FHIR destination keys on a different host and
> cannot answer for it. It is now guarded in `SmartBackendTokenProvider.__init__`, one statement,
> beside the cleartext refusal already there.
>
> **Correction 2 — the `harden_verify_flags` half of this section is an ASSERTION, not a gap, and the
> inference below does not follow.** The grep is right: the call was absent from `logging_setup.py`
> and `auth/oidc_http.py`. The conclusion drawn from it is wrong. Measured 2026-09-22 on CPython
> 3.14.6 / OpenSSL 3.5.7, two arms: `ssl.create_default_context()` sets `VERIFY_X509_STRICT`
> **itself**, while a raw `ssl.SSLContext(...)` does **not**. Both unguarded hops build their context
> through `create_default_context`, so both already had strict path validation; the seven control
> files build raw contexts, where the call is load-bearing. The call #1498 added to the forwarder
> makes the property explicit and survives a future switch to a raw context — it closed nothing, and
> **this correction is the reason no such call was added to `auth/oidc_http.py`**, which would have
> been pure churn in a file with no other change. Both arms are pinned at
> `tests/test_hop_refusal_revocation.py::test_a_default_context_already_carries_the_strict_flag_a_raw_one_does_not`.
>
> **Correction 3 — "no signal at all" was already stale when this was ratified, and BACKLOG #299 is
> why.** #299 limb A landed after this ADR was drafted and gave both remaining hops a real, opt-in,
> in-engine CRL (`[auth].oidc_tls_crl_file`, `[logging].forward_tls_crl_file`), plus
> `context_checks_revocation` and the guard's `crl_checked` relaxation. So the honest statement of the
> gap at ratification was narrower than the one below: an operator had a way to close it and **nothing
> asked them to**, which is what #1498 fixed. §1.3's *"Thirteen originating hops. None checks
> revocation"* and §1.4's *"exactly three call sites, all `PROTOCOL_TLS_SERVER`"* are both false at
> HEAD for the same reason — see the note in §1.4.

The three hops at §1.6 get the same posture-keyed treatment their siblings already have. The helper
exists and the call is one statement: `refuse_unrevoked_verified_hop(scheme, url, connector=,
revocation_attested=)` at `transports/rest.py:656-679`, called in exactly that shape by five
siblings (`fhir.py:370`, `dicomweb.py:261`, `rest.py:1347`, `soap.py:403`, and `email.py:239` via
`RevocationHopGuard.capture`). **The unguarded hops also lack `harden_verify_flags`** -- measured at HEAD, it occurs zero times in `logging_setup.py`, `auth/oidc_http.py` and `transports/rest.py` alike, against a positive control of seven files that do carry it. *(Stale two ways as of 2026-09-22: `logging_setup.py` now carries the call, and **correction 2 above retracts the inference** -- these builders use `create_default_context`, which sets the flag itself. The control is also eight files now, not seven.)* (`transports/smart.py` was in this measured list and is REMOVED: it has no `ssl` usage at all, so it is not a member of the population -- see the withdrawal in §4.3.) An earlier draft of this ADR presented the omission as peculiar to syslog; it is not, and the corrected reading strengthens the rider rather than weakening it -- the gap spans the group.

**Filed by subject, deliberately unallocated** (CLAUDE.md §"Never CITE a `#N` you have not
allocated"): *revocation-guard parity for the SMART token endpoint, the OIDC token and JWKS legs, and
the syslog forwarder*. Allocate a number when the build starts.

**Why this is not folded into the accept.** The accept rests on "the mechanism cannot be built without
reversing a dependency decision". That reasoning does not touch these three at all — the guard is
already written and already wired six times. Leaving them out would also harden a count into the
record: `transports/direct.py:250-253` shows, in a shipped comment, that DIRECT declined a
`RevocationHopGuard` partly because adding it "would make the enumerated count eight and force four
'seven verifying hops' docs to change". That comment gives a real second reason and records the
choice honestly, which is the right instinct. But SDS-3.6 says a completeness claim is a liability,
and an accept-and-document ruling that left the unguarded credential hops outside the count would
write a number a reader treats as coverage.

## 5. Consequences

**Positive**

- The 12.1.4 record stops oscillating between "unbuilt" and "impossible" for direction 1. The runtime
  probe in §1.2 is reproducible in under a second, with no engine tree, corpus or network.
- Direction 3 stops being miscounted as partial coverage of directions 1 or 2.
- The unguarded credential hops are named and owned (§4.3) instead of being invisible inside an
  enumeration.
- Nothing in the tree claims a revocation check it does not perform. The refusals name the missing
  check and the two ways to prove it in front (`tls_policy.py:1033-1037`, `__main__.py:1729-1736`).

**Negative and residual**

- **ASVS 12.1.4 stays delegated.** The engine performs no revocation on either graded direction, and
  any scorecard reasoning has to keep saying so.
- **The blanket attestation is coarser than the problem.** `tls_policy.py:327-335` reads one env var
  and `capture` ORs it into every hop (`:1018`), plus the in-process `[api]` listener and every
  inbound mTLS gate. Per-connection flags exist and default `False` (`models.py:269`, `:655`), but the
  env var is the easier reach and both refusal texts offer it by name. The crossing is audited
  (`tls_policy.py:1051-1060`); nothing stops a one-hop need becoming an instance-wide posture.
- **The refusals are a real operator cost, not a free control.** Because all three named environments
  derive PHI and enforcement defaults to ENFORCE, a first deployment wiring any off-loopback partner
  hop hits a construction-time refusal and must either terminate at a revocation-checking egress proxy
  or attest. Some sites will attest without a revocation-checking PKI behind the claim, because
  attesting is one environment variable and standing up a proxy is a project. The control is honest by
  construction — the flag is named an attestation and its use is audited — but the residual risk moves
  into a claim the engine cannot check.
- **Direction 3 remains opt-in and default-off**, so a site that configures nothing gets no
  client-certificate revocation and, on an enforcing PHI posture, a start-time refusal telling it so.
- **An operator who enables direction 3 takes on CRL refresh.** The engine alarms on expiry
  (`cert_expiry.py:261-271`, ERROR at `alerts.py:317-331`) but cannot fetch a replacement.

**Out of scope**

- Any AIA or CRL-distribution-point fetch, in either direction. ADR 0078's offline-by-default
  reasoning holds here with full force and is not reopened.
- `VERIFY_CRL_CHECK_CHAIN` and `capath=` hashed-directory CRL loading. `harden_crl_check`'s own
  docstring (`tls_policy.py:237-247`) records that `capath=` was measured working while
  `cert_store_stats()["crl"]` reports zero for it, so the helper's liveness assertion would reject a
  working configuration. Anyone adding it needs a different proof.
- Any change to `apiclient/client.py:222` or `tray/probe.py:123`, which delegate chain building to the
  OS verifier through `truststore`. Whatever the OS does there, the engine neither configures nor
  observes it.

## 6. What would trigger revisiting

Any one of these reopens the corresponding direction. None of them is speculative housekeeping; each
names a fact that is checkable.

1. **Any conforming interpreter or its OpenSSL grows a stapling surface.** Re-run the §1.2 probe with its positive controls. The trigger is deliberately not keyed to CPython: the project constrains the Python VERSION, not the implementation.
   A non-empty result on `SSLContext` or `SSLSocket` retires the runtime-blocked finding for
   direction 1 and turns it back into a build question. **Do not retire it on a release note; retire
   it on the probe.**
2. **pyOpenSSL, or an equivalent exposing OCSP handshake callbacks, becomes a declared core
   dependency for an unrelated reason.** The dependency argument in §2.1 is the larger half of the
   direction 1 cost; if something else pays it, only the soft-fail argument remains, and that one is
   about peer behaviour rather than about us.
3. **A deploying site reports a peer that requires a stapled response**, or a partner issues
   must-staple certificates to this engine. That converts the soft-fail objection into a concrete
   interoperability failure and makes an RFC 7633 must-staple **refusal** worth building: it depends
   on no peer behaviour, it needs no network, and `cryptography` is already core
   (`pyproject.toml:64`, resolved 50.0.0, `x509.TLSFeature` and `TLSFeatureType` verified present at
   OID 1.3.6.1.5.5.7.1.24). Note the ordering scar first: `api/tls.py:64-67` warns that a check
   placed beside `harden_verify_flags`, before the CA load, yields a context that refuses every
   client.
4. **The HTTP-family hops gain a pinned per-connection trust anchor**, or the availability objection
   in §2.1 is answered by an in-engine CRL refresh that does not fetch. Either removes a reason
   direction 2's file-CRL build was declined.
5. **A first deployment happens.** CLAUDE.md §0's beta framing is a stated fact with a stated
   expiry. Every conditional in §1.7 becomes a present-tense claim the day an adopter goes live, and
   this ADR must be re-read before that.

## 7. ASVS linkage

**Requirement: ASVS 12.1.4 (L3), *certification* revocation** -- the standard's noun, quoted in full
at §1.1. A scorecard cell for 12.1.4 may cite this ADR as the reasoning for both graded directions,
provided it carries §1.1's caveat that those directions are this ADR's axes rather than the
requirement's. The vocabulary CLAUDE.md fixes applies: the subject is the engine, the record lives
elsewhere, and this ADR is neither.

What a cell may take from here:

- **Direction 1** is **runtime-blocked**, evidenced by the §1.2 probe with its positive controls, not
  by an absence of code.
- **Direction 2** is a **delegated residual with an enforced construction-time refusal**, evidenced at
  `config/tls_policy.py:963-973` and `:1040`, wired at **at least nine** sites (§1.5 rider 1; seven
  until BACKLOG #1498). A cell citing this **must also carry the §1.4 correction**: direction 2 is no
  longer *absent* in-engine, because BACKLOG #299 added an opt-in, default-off file CRL on originating
  hops. *Delegated residual* remains the right grade for the **default** posture; *absent* is not.
- **Direction 3** is **present and must not be counted toward either**, evidenced at
  `config/tls_policy.py:215-276`. **Its "exactly three call sites, all `PROTOCOL_TLS_SERVER`" evidence
  is stale** — seven at HEAD, four of them client contexts (§1.4). The three terminating sites that
  make direction 3 what it is are unchanged and still mTLS-only; cite those three by symbol, and do
  not cite the total.
- **The unguarded-hop population is LARGER THAN TWO AND UNGRADED** -- corrected 2026-08-23. Two hops are confirmed and evidenced below. A third citation, `transports/smart.py:183-184`, is **WITHDRAWN as a `ssl`-usage citation: that file has no `ssl` usage at all.** *The clause that used to follow — "and cannot carry a guard" — is RETRACTED, 2026-09-22.* It does not follow from the measurement and it was wrong: `refuse_unrevoked_verified_hop` takes a scheme and a url, never a context, so a hop riding urllib's shared opener carries the guard exactly as the four HTTP-family cells do. That hop **is** guarded as of BACKLOG #1498 (§4.3, correction 1). What the zero-`ssl` measurement correctly establishes is only that the file is not in the `harden_verify_flags` population. Separately, at least six further unguarded context constructions exist (`apiclient/client.py:214`, `store/postgres.py:729`, `rest.py:275`, `:296`, `soap.py:202`, `tls_policy.py:1218`) and **NONE of them has been graded** -- several are outbound client contexts where the answer may differ. **Do not scope this rider as a well-specified three-hop job.** The confirmed two were at
  `auth/oidc_http.py` and `logging_setup.py`; the build rider is §4.3.
  **Of that confirmed pair, the syslog forwarder is now GUARDED (BACKLOG #1498) and the OIDC legs are
  not** — so a cell citing this bullet must say *one confirmed hop remains ungraded-and-unguarded*,
  not two. The six further ungraded constructions are untouched and still ungraded; #1498 graded none
  of them.

Anchor these to code, not to this ADR's line numbers. **This document is prose and will be edited;
the code is the evidence.** Nothing in this section is scorecard content, and nothing from the
scorecard is reproduced here.

## 8. Sources that are stale, and must not be cited as current

Recorded so the next reader does not re-derive a refuted premise, and so nobody edits these files as
a side effect of reading this ADR.

- **`docs/adr/0078-certificate-revocation-posture.md:30`** — "A grep across the whole tree confirms
  there is **zero OCSP/CRL code anywhere**." **False at `origin/main`.** `harden_crl_check` is at
  `config/tls_policy.py:215` on `origin/main` at `06ef8ec8`, with three call sites. That premise was
  true when ADR 0078 was accepted (2026-07-10) and the #1005 build retired it. ADR 0078's *decision*
  stands; only that one premise line is stale. Correcting it is an ADR 0078 amendment, not an edit
  made in passing.
- **`docs/BACKLOG.md:231`** (repeated verbatim at `:3889`) — "No client-certificate revocation code
  exists anywhere under `messagefoundry/`". **False at `origin/main`**, same evidence.
  **DO NOT edit `docs/BACKLOG.md` from this ADR.** The item's own status is the backlog's business.

## 9. Not addressed

- **Whether any partner actually consumes a stapled response.** That is a question about someone
  else's software and the engine gets no signal about it. The accept in §2 does not depend on the
  answer; the trigger in §6 rider 3 is what would surface one.
- **The `truststore`-backed hops** (`apiclient/client.py:222`, `tray/probe.py:123`). Chain building
  goes to the OS verifier, which may or may not consult revocation depending on the host. **Neither
  half of that is asserted here**, because engine code neither configures nor observes it.
- **`enum_crls`.** Windows-only, returns raw CRL bytes from the OS certificate store, and has zero
  call sites in `messagefoundry/`. Whether it could back a Windows-specific path is not evaluated.
- **A count of "verifying hops".** §1.3's table lists thirteen originating sites and §4.3 explains why
  a fixed count is a liability. Read it as "at least these", per SDS-3.6.
