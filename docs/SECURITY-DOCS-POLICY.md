# Security documentation — what is public, what is not, and how to ask

MessageFoundry's security-posture document set — the threat model, the OWASP ASVS assessments and
their remediation plans, the risk-acceptance register, and the internal review reports — is
maintained privately and is **not in this repository**. Where these docs cite a `docs/security/` or
`docs/reviews/` path, that names a real maintainer-internal document: it is cited for **provenance**,
and it will not resolve here. This page states the rule that decides which side a document lands on,
what is public, and what you can ask for.

**Keeping the withheld set out of this repository rests on a client-side hook, not on a server
control.** [`SECURITY.md`](SECURITY.md) records that posture and its limits, under *Supply-chain &
CI security*. Read it before assuming the separation is enforced.

## The rule

A document is withheld only if it does one of two things:

- it describes an **open, un-remediated weakness in enough detail to act on**, or
- it **names a customer, site, or deployment**.

Everything else is publishable. A **closed** finding is transparency, not an attacker roadmap: once a
weakness is fixed and shipped, writing it down is what lets a reviewer trust the engine and stops the
next contributor reintroducing it. That is why the
[remediation ledger](SECURITY-REMEDIATION-LEDGER.md) is public with its findings named and its method
described, while an assessment still being worked is not.

The rule moves documents **into** the open, not just out of it: the
[Secure Development Standards](Secure_Development_Standards.md) were withheld until 2026-07-29 and
are now published, because nothing in them met either test.

Two neighbouring paths are held back for their own reasons, neither of them a security posture claim:
`docs/reviews/` is point-in-time review findings, withheld on the same open-weakness test as above;
`docs/marketing/` is local competitor- and market-research notes, which are working material rather
than a project artifact.

## What is public

| Document | What it covers |
|---|---|
| [`SECURITY.md`](SECURITY.md) | Authentication, RBAC, the audit trail, and the trust boundary |
| [`PHI.md`](PHI.md) | Where PHI lives, how it is protected, what is built and what is planned |
| [`SECURITY-REMEDIATION-LEDGER.md`](SECURITY-REMEDIATION-LEDGER.md) | An audit wave end to end — findings, lanes, and how each was closed |
| [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) | SBOM, VEX, signing and provenance: what ships per release and how to verify it |
| [`../.github/SECURITY.md`](../.github/SECURITY.md) | Reporting a vulnerability, and our response and remediation targets |
| [Architecture Decision Records](adr/README.md) | Every significant security decision, with its context and consequences |

## What you can request

Adopters, evaluators and security reviewers can ask for the withheld material — including the threat
model and the current ASVS assessment — which is made available to evaluators under NDA. Requests are
answered case by case.

Use the contact route already documented in [`.github/SECURITY.md`](../.github/SECURITY.md): open a
[GitHub private security advisory](https://github.com/MEFORORG/MessageFoundry/security/advisories/new),
which is always available and stays private to the maintainers, or email the maintainer at the address
on the GitHub profile. If you cannot reach a maintainer privately within a few business days, that
page's documented fallback applies — a **non-detail** public issue, title only (for example,
"requesting a private security contact"). Never put vulnerability detail, reproduction steps, or any
message content in a public issue.
