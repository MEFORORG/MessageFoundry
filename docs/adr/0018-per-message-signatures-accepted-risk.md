# ADR 0018 — Per-message digital signatures (ASVS 4.1.5): accepted risk / deferred-by-design

- **Status:** **Accepted (2026-06-16).** Records a deliberate accepted-risk / deferral decision. No build
  is authorized by this ADR — the control is built only when a trigger below fires. Recorded as a dated
  deviation in the Secure Development Standards [Appendix A.6](../Secure_Development_Standards.md).
- **Requirement:** OWASP ASVS 5.0 **4.1.5** (V4.1 Generic Web Service Security, **Level 3**) — *"Verify
  that per-message digital signatures are used to provide additional assurance on top of transport
  protections for requests or transactions which are highly sensitive or which traverse a number of
  systems."*

## Context

- MessageFoundry is a healthcare integration engine: it carries **PHI** ("highly sensitive") and, as
  middleware, a message **traverses a number of systems** (sender → MF → outbound → partner, often
  further downstream). Both triggers in 4.1.5 are satisfied by the OR, so the requirement is
  **applicable** — it is **not** Not-Applicable. (Marking it N/A would be score-optimization; "the
  industry doesn't do it" is a *practice* observation, not an applicability test.)
- 4.1.5 asks for a message-level signature **on top of** transport protection — valuable specifically
  when a message can be tampered with at an **intermediary hop**.
- Realities for the supported deployment model:
  - The data plane is already protected by **TLS** (1.2+ floor; API/WSS + MLLP-over-TLS, [ADR 0002](0002-phase2-transport-security-and-strong-auth.md)).
  - The supported model is **on-prem, single-tenant, point-to-point**, with **no untrusted intermediary**.
  - **Industry practice:** HL7 v2 interchange relies on transport/network security; per-message digital
    signatures are rare, and **no known partner system requires or supports** receiving a per-message
    signature on these feeds. A signature only has value if the receiver verifies it, and both parties
    must agree on the format and keys.
  - The local console → API call is explicitly **out of scope** of the requirement (a local call, not a
    sensitive multi-hop transaction).

## Decision

**Accept the risk and defer by design.** Do not build per-message signing now; record the compensating
controls and the build triggers, and revisit when a trigger fires.

- **Compensating controls:** TLS-protected data plane + a trusted single-tenant on-prem network (no
  untrusted intermediary); the count-and-log / per-message disposition record gives an integrity and
  audit trail of what was received and sent.
- **Build triggers (any one):**
  1. A **partner contract** that mandates (or offers to verify) a message-level signature.
  2. An **off-prem / cloud / shared-tenant** deployment, or any path through an **untrusted intermediary**.
- **When triggered, the implementation path is already scoped:** SOAP **XML-DSig** / WS-Security on the
  outbound SOAP connector ([ADR 0015](0015-ws-soap-outbound-mtls-wssecurity.md) §4a), or a **detached
  JWS** over the message body for HL7/JSON. `cryptography` is already a core dependency.

## Consequences

- ASVS **4.1.5 remains a Fail** on the scorecard — an *accepted* Fail is governed, not re-scored to Pass
  or N/A. It is recorded as a dated deviation in [SDS Appendix A.6](../Secure_Development_Standards.md)
  and tracked in [ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md).
- **Residual risk:** a compromised hop inside MF or on the (trusted) network could alter a message with
  no per-message signature to detect it; mitigated by the on-prem trust boundary, TLS, restricted service
  accounts, and the audit trail. Accepted while the supported model holds.
- Closing 4.1.5 is **not required** for the loopback-default posture and does not block v0.1.
- **Review:** at each release and on any trigger above. This ADR is superseded by the build decision when
  the signature path is implemented.

**Cross-references:** [ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md) (4.1.5 verdict) ·
[ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md) ·
[Secure_Development_Standards.md](../Secure_Development_Standards.md) §A.6 · [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) · [ADR 0015](0015-ws-soap-outbound-mtls-wssecurity.md).
