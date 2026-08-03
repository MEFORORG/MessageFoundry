<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0155 — DAST: dynamic security testing of the running engine

- **Status:** Accepted (2026-07-31) — increment 1 built; advisory, not a required context
- **Date:** 2026-07-31
- **Related:** BACKLOG #318; [Secure_Development_Standards](../Secure_Development_Standards.md) §6.1, §A.6; [Secure_Build_Standards](../Secure_Build_Standards.md) signal 10

---

## Context

Every security test this project runs today is **static or in-process**: SAST, SCA, secret scanning,
and a large pytest suite that exercises the API through ASGI transports and direct function calls.
**No DAST has ever run against this project** — nothing has ever driven the engine's HTTP surface
over a real socket, with real credentials, and asked whether the deny-by-default authorization model
actually holds on the wire. [`Secure_Development_Standards`](../Secure_Development_Standards.md) §6.1
names that tier explicitly (`Dynamic | DAST / authenticated testing of the running app | Per release
and periodically`) and it has been empty since the row was written.

Two [CLAUDE.md](../../CLAUDE.md) invariants bound how it may be filled.

§9, verbatim:

> **Never log full message bodies at INFO or above.** Full payloads go only to the secured
> store, never to the general log.

A scanner's artifacts travel — they are uploaded from CI, attached to tickets, and read by people who
were not present when the scan ran. A receipt that carries request or response bodies is a log of
message bodies with extra steps, so the receipt records **method, path template, status code, counts
and the scanned posture, and nothing else**.

§5, verbatim:

> **Verify a dependency exists** (real, reputable, the intended name) **before adding it**, then put
> it in `pyproject.toml` and re-lock — never an ad-hoc install (§7). AI-suggested packages are often
> hallucinated.

Every candidate scanner in this space is a new dependency, a new lock artifact, or a container image
on a mutable tag. The rule above is why *Options considered* records what each one drags in rather
than what its README claims — and it is why increment 1 adds **no new dependency at all**.

**The measured shape of the target** (this worktree, 2026-07-31, against an unchanged app): the live
route table carries **105 rows**; **100** are gated by a `require*()` dependency; **87** of those
carry at least one named permission; and exactly **5** are anonymous by design — `GET /auth/providers`,
`POST /auth/login`, `POST /auth/negotiate`, `GET /health`, `GET /ai/policy`. One of the 100 gated rows
is the `/ws/stats` WebSocket, which authorizes inside its own body rather than through a dependency,
leaving **99 gated HTTP rows** to probe.

The hazard specific to this target is that a deny-by-default API rewards a lazy scanner. Point an
unauthenticated crawler at it and every route answers 401; the run exits 0 and reads as *all endpoints
protected* having proved nothing about authorization. That is the same shape as the measurement-gate
failures this repo has already catalogued, so the design below is organised around **not producing
one**.

## Decision

Build a **self-run, authenticated, deterministic authorization sweep** against a real HTTP listener,
in one process, with no new dependency.

1. **A real loopback listener, not an in-process transport.** `uvicorn` binds `127.0.0.1:0` on the
   same event loop, in front of a real `Engine` and a real `AuthService`. Both identities
   (administrator, viewer) are minted **over the wire** through `POST /auth/login`. An in-process
   ASGI transport would bypass uvicorn's HTTP parser, leave `request.client` unset so every
   IP-keyed control degenerates, and could not emit the framings the app guards against; a real
   listener costs about a second and recovers those.
2. **The authorization expectation is derived, never hand-kept.**
   [`scripts/security/route_gates.py`](../../scripts/security/route_gates.py) walks each route's
   `require*()` closure and reports its gate and permissions from the **live** app. That single
   implementation is shared with the existing security doc-drift guard, so there is exactly one
   derivation of "is this route gated" in the tree, and a route that lands tomorrow is covered the
   day it lands.
3. **Three passes.** *Negative* — every gated HTTP row is sent twice, with no credential and with an
   invalid bearer; anything but 401 is a finding. *Authorized reach* — every gated `GET` row is sent
   with the administrator bearer, and the run counts how many answered **outside** `{401, 403, 429}`;
   this is the number that makes a wall of 401s impossible to mistake for coverage. *BFLA* — every
   gated `GET` row whose permission set is not a subset of the viewer role's is sent with the viewer
   bearer; anything but a refusal, **including 404**, is a finding, because a 404 on a matched path
   template means the caller got past authorization into resource lookup.
4. **A receipt with floors that fail closed.** Every count is computed by the runner from its own
   request log and the live route table — never parsed out of another tool's summary. Floors are
   minimums with headroom under the measured values; a run that falls below one exits **2 (could not
   measure)**, never 0. Findings exit 1. Clean *and* above every floor exits 0.
5. **Two canaries built from supported configuration.** One disables authentication at the target;
   one over-grants the low-privilege identity while the expectation set stays the viewer's. Both are
   produced by configuration and provisioning that the engine already supports — **no source patch**,
   so there is nothing anchored to line numbers and nothing to re-anchor after a refactor. CI runs
   both **before** the real scan and requires each to exit exactly **1** (findings) with a receipt on
   disk; any other code fails the job and the real scan never runs.
6. **The probe's ability to fail is merge-blocking; the probe run is advisory.** The sweep and both
   canaries run as ordinary pytest inside the **existing required** test legs, so a change that blinds
   the detector reds a pull request. The nightly workflow re-runs the same shipped code and is
   deliberately **not** a required context — it has no `pull_request` trigger, so it cannot report on
   a PR at all. Advisory here means *not in branch protection*; it does **not** mean
   `continue-on-error`, and the job carries none.

## Scope boundary

Self-run automated DAST of the authenticated HTTP API plane only. It fills PART of the Secure_Development_Standards §6.1 "Dynamic" tier row — DAST / authenticated testing of the running app — and nothing else; at least the unauthenticated MLLP/TCP/X12/DICOM ingress plane, the /ui console plane and TLS are outside what it scans, and controls including MFA, the rate limiters, lockout and step-up freshness are relaxed in the scanned posture (ADR 0155, "What this does NOT give us"). It does NOT satisfy Secure_Build_Standards signal 10, "Independent external verification" (third-party source review + penetration test + DAST), which requires INDEPENDENCE, not automation: an internally-run pass is the substitute that rubric explicitly exists to grade past. The independent engagement has not been performed and its dated risk acceptance remains in force; Secure_Development_Standards §A.6 is the single source of record for that status.

The **verbatim** text above lives in exactly two carriers: this section, and the
`INDEPENDENCE_NOTICE` constant in
[`scripts/security/dast_auth_sweep.py`](../../scripts/security/dast_auth_sweep.py). The second copy
is justified because the receipt is an uploaded CI artifact that travels outside the repository, and
a number circulating without its boundary is worse than no number.
`tests/test_dast_claims.py::test_independence_notice_is_byte_identical` pins the two byte-identical,
so they cannot drift apart, and `::test_the_notice_has_exactly_two_copies` refuses a third carrier.

Everywhere else carries a **bare pointer to this section and no independence wording of its own** —
at least BACKLOG #318, [`docs/adr/README.md`](README.md), [`docs/CI.md`](../CI.md) and
[`.github/workflows/dast.yml`](../../.github/workflows/dast.yml). That is not an assertion of good
manners: `tests/test_dast_claims.py::test_no_stray_paraphrase_of_the_boundary` reads each of those
passages plus the two implementation modules and reds on independence-boundary language in any of
them. The rule earns its keep the day this wording is sharpened — a paraphrase left behind becomes a
second, stale, contradictory answer to *has anything independent run?*, and nothing would have gone
red.

[`docs/FEATURE-MAP.md`](../FEATURE-MAP.md) is deliberately **outside** that sweep and is the one
place a reader should expect independence language beside this work. Its ASVS row makes a claim about
the **project's** assessment posture, not about this ADR's scope, it predates this change, and it is
pinned by `tests/test_feature_map_claims.py` — including the phrase *"no independent dynamic (DAST)
testing"*, which this change added to that pin precisely because it was unguarded. Folding it into
the paraphrase sweep would red honest, already-guarded prose.

This ADR deliberately does **not** restate the status of the independent engagement itself. §A.6 is
the source of record; a copy here would survive the next revision of that standard and become a
second, contradictory answer to the question *has anything independent run?*

## Acceptance Criteria

- **AC-1** — WHEN the sweep runs against the shipped app, THEN THE SYSTEM SHALL refuse every gated
  operation with 401 for both a no-credential and an invalid-credential request.
  → `tests/test_dast_auth_sweep.py::test_sweep_is_clean_against_the_real_app`
- **AC-2** — WHEN the administrator token is used, THEN THE SYSTEM SHALL report at least 40 gated
  `GET` operations answering outside `{401, 403, 429}`, and shall name in the receipt how many
  operations it examined.
  → `tests/test_dast_auth_sweep.py::test_receipt_names_what_it_examined`
- **AC-3** — IF authentication is disabled at the target, THEN THE SYSTEM SHALL exit 1 with at least
  50 negative findings.
  → `tests/test_dast_auth_sweep.py::test_canary_open_auth_is_detected`
- **AC-4** — IF the low-privilege identity is over-granted, THEN THE SYSTEM SHALL exit 1 with at
  least 5 BFLA violations.
  → `tests/test_dast_auth_sweep.py::test_canary_bfla_is_detected`
- **AC-5** — IF no gated operation can be derived, THEN THE SYSTEM SHALL exit 2 (could not measure),
  never 0.
  → `tests/test_dast_auth_sweep.py::test_zero_gated_operations_exits_2`
- **AC-6** — WHILE the set of ungated routes differs from the documented anonymous allow-list, THE
  SYSTEM SHALL fail the run rather than treat the difference as background.
  → `tests/test_dast_auth_sweep.py::test_ungated_routes_are_exactly_the_documented_anonymous_set`
- **AC-7** — WHEN the boundary text above is edited in one place and not the other, THE SYSTEM SHALL
  fail the required test legs.
  → `tests/test_dast_claims.py::test_independence_notice_is_byte_identical`
- **AC-8** — WHILE a canary run exits with anything other than 1 (findings), THE SYSTEM SHALL fail
  the CI job before the real scan runs, because neither 0 (blind) nor 2 (could not measure)
  demonstrates detection.
  → `tests/test_dast_auth_sweep.py::test_the_canary_step_demands_exit_code_1_specifically`
- **AC-9** — IF the sweep cannot complete a probe against the target, THEN THE SYSTEM SHALL exit 2
  (could not measure) rather than 1, and SHALL write no receipt.
  → `tests/test_dast_auth_sweep.py::test_a_target_that_dies_mid_scan_exits_2`
- **AC-10** — WHEN the live app carries a route class the gate walk does not understand, THE SYSTEM
  SHALL report it as an ungated row rather than drop it.
  → `tests/test_dast_auth_sweep.py::test_no_route_falls_off_the_end_of_the_walk`
- **AC-11** — WHILE a passage outside the two permitted carriers restates the scope boundary, THE
  SYSTEM SHALL fail the required test legs.
  → `tests/test_dast_claims.py::test_no_stray_paraphrase_of_the_boundary`

## Options considered

1. **Loopback uvicorn + a derived route table + three passes, no new dependency** — **CHOSEN.** Runs
   in about two and a half seconds, adds no dependency, no new required context, and produces a
   receipt whose central number (`authorized reach`) cannot be satisfied by a wall of refusals.

2. **Schemathesis** (schema-driven property testing, incl. its `ignored_auth` check) — **deferred to
   increment 2**, not rejected. Two blockers. First, it would be measuring nothing today: the shipped
   OpenAPI document declares **no `components.securitySchemes` and no per-operation `security`**, so
   `ignored_auth` has nothing to key on and would pass on every operation having probed none of them.
   Making it meaningful needs an out-of-band security overlay injected into the schema, plus proof
   that the overlay actually marks the operations before any result is credited. Second, it is not
   installed here, so adopting it means a non-default dependency group, a fifth committed dependency
   lock, and a new export/diff path in the DEP-1 step — over a closure of roughly thirty
   distributions including `starlette`, `anyio`, `click`, `requests` and `hypothesis`. This repo
   already carries a **measured, bisected** instance of exactly that mechanism silently downgrading a
   shipped runtime package across all four lock artifacts (recorded in-tree at `pyproject.toml`), and
   `starlette` here carries a CVE-motivated version floor. Paying that risk for an advisory scanner
   in increment 1 is a bad trade.

3. **OWASP ZAP** — rejected. Pinning the GitHub Action by commit SHA does not pin the scanner: the
   action pulls a container on a **mutable `:stable` tag**, which would open a fresh unpinned-
   dependency finding on a repository already carrying two. Its one high-value surface here is the
   browser console, and the published images do not install the web console package at all. Revisit
   only alongside the `/ui` plane.

4. **Nuclei** — rejected. It is a CVE and misconfiguration **template matcher**; this target is a
   bespoke FastAPI application with no matching template surface. Also a live instance of the
   hallucinated-package trap §5 warns about: `pip install nuclei` resolves to an abandoned 2018
   package unrelated to the scanner.

5. **Dredd** — rejected: archived by its maintainers in 2024. **RESTler** — rejected: heavyweight
   stateful fuzzing whose grammar compilation is its own project. **CATS** — rejected: a JVM tool,
   a new runtime in CI for this repository. **`schemathesis/action`** — rejected: no licence field.

6. **In-process ASGI transport instead of a listener** — rejected. It bypasses uvicorn's HTTP parser,
   leaves `request.client` unset so every IP-keyed control degenerates into a no-op, and cannot
   produce the request framings the app guards. A real loopback listener costs roughly a second and
   recovers those; a probe against the guarded framing returned a genuine 400 over the socket during
   design, which the in-process transport structurally cannot do.

7. **Source-patch canaries** (apply a `.patch` against the auth dependency to inject the defect) —
   rejected for **patch rot**. Anchoring a canary to exact source lines guarantees a recurring
   re-anchoring chore and a failure mode where the canary quietly stops applying and the run keeps
   reporting green. Both injected defect classes are reachable through supported configuration and
   provisioning instead, so they survive any refactor of the gate's body.

8. **A black-box target over real TLS, driven by a spawned `serve`** — deferred to increment 2. It is
   the only way to observe the https-gated controls (see below), but its bring-up is large, and it
   cannot land in the same change as the sweep it would host.

## What this does NOT give us

Stated once, here, because a scanner's value is bounded by what it touched and every consumer of the
receipt needs the same boundary.

**Surfaces not scanned.** At least:

- **The unauthenticated ingress plane** — MLLP, raw TCP, X12 and DICOM listeners take bytes from
  partner systems by protocol design and are the surface a hostile input would actually arrive on.
  Nothing in increment 1 reaches them; the sweep binds only the API port. Worth recording for whoever
  picks this up: BACKLOG #89 refers to *"the ADR 0054 adversarial audit harness"*, but
  [ADR 0054](0054-low-allocation-builtins-hl7-parser.md) is the low-allocation HL7 parser — **there
  is no such harness, and no mutator or generator to extend**. Deferred on size, not on value: the
  hard part is the oracle, since a listener that catches broad exceptions makes "no crash" vacuous.
- **The `/ui` console plane.** It needs a second credential type (the session cookie jar) plus
  same-origin request headers; a naive scanner trips the same-origin assertion on every write and
  reports a working control as a finding. It is also the only surface where a DOM/CSP scanner would
  mean anything, which is why it and any ZAP revisit belong in the same later increment.
- **TLS and the https-gated controls.** The `__Host-` cookie prefix, the `Secure` flag, HSTS, the
  effective-https response-header bundle for `/ui`, and the configured TLS floor are all keyed on a
  real https origin and are structurally unobservable over a cleartext loopback target.
- **Non-`GET` reach and non-`GET` BFLA.** A reach or BFLA probe carries a **valid** token and would
  actually execute a mutating endpoint, so extending past `GET` needs a per-probe store reset. The
  receipt therefore prints its BFLA ratio (19 of about 60 candidate rows) rather than implying full
  BFLA coverage.

**Controls relaxed in the scanned posture, and what does exercise them.** To make the sweep
deterministic the target runs with MFA off, the four rate limiters off, lockout effectively disabled
and step-up freshness widened. So this run says nothing about whether those controls fire. The
receipt **prints every relaxation** so no reader can mistake the scanned posture for the shipped
default, and `tests/test_mfa_access_gate.py` and `tests/test_step_up.py` are what exercise the MFA
access gate and step-up freshness today. A probe asserting each control fires **on the wire** is
increment 2.

**Defect classes a scanner of this shape does not find.** It compares an observed status code against
an expectation derived from the route table. It therefore says nothing about whether a *reached*
endpoint returns the right rows for the caller (object-level authorization / IDOR), nothing about
business-logic flaws, nothing about injection into SQL or HL7 or a filesystem path, nothing about
what a response *body* leaks, nothing about cryptographic strength or key handling, nothing about
race conditions or ordering, and nothing about the correctness of the permission-to-route assignment
itself — a route mapped to the wrong permission is consistent with both the derivation and the probe.
Those remain the property of the unit and integration suites, the static gates, and the engagement
named in *Scope boundary*.

**A blind spot in the type checking.** CI runs `mypy` over the engine and the web console only;
`scripts/` is outside that scope. The new modules under `scripts/security/` are therefore
type-checked **locally, by hand**, and a type error in them will not red CI. The invocation matters:
`scripts/` has no `__init__.py`, and `dast_auth_sweep.py` imports its siblings as
`scripts.security.*`, so checking the three files together with a bare `mypy --strict` aborts with
*"Source file found twice under different module names"* before checking anything — a compensating
control that produces zero coverage while looking like it ran. Use:

```
mypy --strict --explicit-package-bases --namespace-packages \
  scripts/security/route_gates.py scripts/security/dast_target.py scripts/security/dast_auth_sweep.py
```

**Independence.** See *Scope boundary* above and
[Secure_Development_Standards §A.6](../Secure_Development_Standards.md). Nothing in this ADR changes
that status, and this tier must not be cited as if it did.

## Consequences

**Positive**

- The §6.1 Dynamic tier row is no longer empty, and what fills it is reproducible in about two and a
  half seconds by anyone with the repository checked out.
- The single riskiest way this class of gate lies — *green because nothing was scanned* — is
  answered by a positive number the run must produce: how many operations a **privileged** token got
  past authentication and authorization on. If an MFA wall, a step-up wall or a limiter silently
  re-arms, that number collapses and the run reds instead of quietly reporting a clean wall of
  refusals.
- The authorization expectation is derived from the live app by the **same** implementation the
  existing doc-drift guard uses, so the two cannot disagree, and a newly landed gated route is probed
  without anyone updating a list.
- A newly **ungated** route reds the run rather than joining the background, because the ungated set
  is asserted equal to the documented anonymous allow-list.
- No new dependency, no new required context, no new lock artifact, and no scanner installed in CI.

**Negative / risks**

- **The scanned posture is not the shipped posture.** Five controls are relaxed to make the run
  deterministic. Mitigated by printing every relaxation into the receipt, never by implying the app
  as shipped was scanned.
- **A status code is a weak oracle.** The passes above establish that a caller was refused or
  admitted, not that what came back was correct. See *What this does NOT give us*.
- **The floors are hand-chosen minimums.** They sit with headroom under values measured on
  2026-07-31; a large, legitimate reduction in the route table would trip them and require a
  deliberate, reviewed edit. That is the intended cost of failing closed.
- **Canary rot is reduced, not eliminated.** The canaries survive refactors of the gate's body
  because they are built from configuration, but a change to what that configuration *means* could
  still neuter them. The compensating control is that CI requires each canary run to exit **1**
  (findings) *and* to have written its receipt: a **0** (blind), a **2** (could not measure — the
  shape a neutered canary actually produces) or any other code fails the job before the real scan
  runs. Stated as an exact code deliberately: an earlier revision tested "did it succeed?", and since
  a canary run can never exit 0, that test was dead code which accepted exit 2 as proof.
- **An advisory job can be ignored, and today nothing pages on it.** `nightly-notice.yml` opens an
  issue only for the workflow named `CI`, so a red DAST nightly surfaces in the Actions tab and
  nowhere else; the workflow has no `pull_request` arm and is not a required context, so nothing on a
  PR reflects it either. That is a known, accepted gap for increment 1, recorded here rather than
  left to be discovered — widening the notice workflow is a follow-up, not part of this change. The
  compensating design is that the half which must not rot — the detector's ability to fail — lives in
  the required test legs, not in the nightly.

**Out of scope**

Named in full in *What this does NOT give us* above; in short, at least the unauthenticated
MLLP/TCP/X12/DICOM ingress plane, the `/ui` console plane, TLS and the https-gated controls, non-`GET`
reach and non-`GET` BFLA, and the relaxed posture.

## PHI

The runner creates an **empty store in a temporary directory** and never seeds a message into it, and
the receipt records only method, path template, status code, counts and the scanned posture — no
request or response body, no header value, no token, and never the store file. That, not the bind
address, is what keeps PHI out of the artifact: the loopback bind governs who can reach the listener,
not what the receipt contains, and a compensating control resting on a false premise is worse than
none.
