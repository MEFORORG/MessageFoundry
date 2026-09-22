# Security Policy

MessageFoundry is an HL7 v2.x integration engine that handles **PHI**. We take security
reports seriously and appreciate responsible disclosure.

## Supported versions

The project is pre-1.0 and evolving rapidly; only the latest `main` is supported. Please
verify a report against current `main` before filing.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Instead, report it privately:

- **Preferred (always available, fully private):** open a [GitHub private security advisory](https://github.com/MEFORORG/MessageFoundry/security/advisories/new)
  ("Report a vulnerability") — GitHub keeps it private to the maintainers until coordinated disclosure.
  This is the recommended channel.
- **No GitHub account?** Email **<security@messagefoundry.org>** — it reaches the maintainers
  directly. Ordinary email is not end-to-end encrypted, so the advisory above is still preferred for a
  detailed report; if you only have email, send a short notice and we will open a private channel.
  Please do **not** use the website contact form for vulnerability details — it is routed through a
  third-party form service.

If you cannot reach a maintainer privately within a few business days, you may request a contact via a
**non-detail** public issue (title only, e.g. "requesting a private security contact") — **never** put
vulnerability details, reproduction steps, or any message content in a public issue.

Please include: affected component (e.g. MLLP/file transport, store, API/auth, console),
a description and impact, and reproduction steps or a proof of concept. Do **not** include
real PHI — use synthetic HL7 (the `messagefoundry generate` corpus is ideal).

We aim to acknowledge within a few business days and credit reporters who wish to be named once a
fix is released.

**Machine-readable contact.** The channels above are also published as
[`.well-known/security.txt`](../.well-known/security.txt), per
[RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).

## Authorization and safe harbor for good-faith research

**You are authorized to test.** MessageFoundry adopts the authorization wording recommended by
CISA, the US Cybersecurity and Infrastructure Security Agency, in its
[Vulnerability Disclosure Policy template](https://www.cisa.gov/vulnerability-disclosure-policy-template):

> If you make a good faith effort to comply with this policy during your security research, we
> will consider your research to be authorized, we will work with you to understand and resolve
> the issue quickly, and MessageFoundry Foundation, LLC will not recommend or pursue legal action
> related to your research. Should legal action be initiated by a third party against you for
> activities that were conducted in accordance with this policy, we will make this authorization
> known.

The wording is CISA's, changed in two ways only: the template's `AGENCY NAME` placeholder is
filled with this project's legal entity, and the template's bold and italic emphasis is dropped.

### What is in scope: the software, and your own installation of it

In scope is **this repository's source** and **an installation you run yourself**. Install
MessageFoundry from source or from PyPI, run it on hardware you control, and attack that. There is
no MessageFoundry-operated service hosting the engine, so there is no instance of ours to point a
scanner at.

The engine's default network posture is in **Scope notes** below. Read it there rather than
assuming it, because an operator can change it.

**Out of scope, and the authorization above does not reach them:**

- **A third party's installation.** A site running this engine has not consented to your testing,
  and their permission is theirs alone to give.
- **The project website and any third-party services we use**, including the website contact form
  mentioned above and our hosting, email and package-index providers. They are not ours to
  authorize testing against. If you believe you have found something affecting one of them, report
  it through a channel above and we will route it.

Ask first if you want something outside this list covered. We would rather widen the scope in
writing than have you guess.

### What a good-faith effort means here

At least the following. This names the cases with a real chance of arising rather than claiming to
be a closed list.

1. Report through a channel above, and honor the coordinated-disclosure ask in **Response &
   remediation timeline** below. That section asks for a reasonable window rather than naming a
   fixed number of days, and says we will agree the timing with you, so agree it with us there
   rather than reading a deadline into this list.
2. Stop at proof. Once you can show the vulnerability exists, stop, rather than pivoting further
   or running the exploit wider than a demonstration needs.
3. Use synthetic HL7 only, as **Reporting a vulnerability** above already requires of a report.
   The same rule governs the testing that produced it.
4. Leave service intact. No denial-of-service or load testing against anything you do not own,
   and no destructive actions.
5. Do not access, change, or keep data that is not yours. If you reach such data, stop and tell
   us what you reached.
6. Attack the software, not the people or the accounts. No social engineering, no physical
   attacks, and no attacks on maintainer accounts or project infrastructure.

Ask first through a reporting channel above if you are unsure whether something is in scope.
Asking never counts against you.

## Response & remediation timeline

After we acknowledge a report, we triage it by severity and target these remediation windows
(measured from triage; fixes are verified before a report is closed):

| Severity | Target to remediate |
|---|---|
| Critical | ≤ 7 days |
| High | ≤ 30 days |
| Medium | ≤ 90 days |
| Low | Best-effort |

**Coordinated disclosure.** We practice coordinated disclosure: we ask that you give us a reasonable
window to ship a fix before any public detail, and we publish details (and credit, if wanted) **once
a fix is available**. We'll keep you updated on progress and agree the disclosure timing with you.
These windows trace to the project's [Secure Development Standards](../docs/Secure_Development_Standards.md) (§4.4 RV.2, Appendix A.5).

## Dependency (third-party) vulnerabilities

The table above is for vulnerabilities in **MessageFoundry's own code**, clocked from our triage. A
vulnerability in a **third-party dependency** is a different clock and a different priority signal, so
it has its own targets (this is deliberately distinct — the dependency fast lane below is ≤72h, which
is *not* a contradiction of the ≤7-day own-code window above):

- **Clock starts at upstream-fix availability**, not our triage — we generally cannot patch someone
  else's library, so the SLA measures how fast we adopt the fix once it exists.
- **Exploitation pressure sets priority, not CVSS alone.** We triage **KEV-first** (on CISA's
  Known-Exploited-Vulnerabilities list → patch now), then **EPSS** (≥ 0.7 = imminent), with **CVSS only
  as a tiebreaker**, and we weigh **reachability** — is the package installed in a shipped profile,
  wired into a running graph, and egress-reachable? The procedure behind that judgement is
  `docs/security/SOUP-DEPENDENCY-HANDLING.md`, a maintainer-internal document;
  [`docs/SECURITY-DOCS-POLICY.md`](../docs/SECURITY-DOCS-POLICY.md) explains why it is not published
  here and what you can request.

| Class | Trigger | Target (from upstream-fix availability) |
|---|---|---|
| **Tier-0 fast lane** | CISA **KEV** *or* **EPSS ≥ 0.7**, and reachable in a shipped profile | **≤ 72 hours** |
| Critical | CVSS critical, reachable | ≤ 14 days |
| High | CVSS high, reachable | ≤ 30 days |
| Medium | CVSS medium | ≤ 60–90 days |
| Low / unreachable | — | Best-effort; recorded with rationale |

**No upstream fix yet?** We apply a documented **compensating control** — pin the transitive dep out,
leave the affected extra uninstalled, or tighten the egress allow-list — and track to the fix. Detection
feeds this lane automatically: blocking `pip-audit`/`npm-audit` against the hash-locked tree, a **daily**
`security.yml` cron (a CVE against an unchanged pin is caught in ~24h), and grouped Dependabot security
PRs. The step-by-step response is `docs/security/DEP-CVE-RUNBOOK.md`, also maintainer-internal —
see [`docs/SECURITY-DOCS-POLICY.md`](../docs/SECURITY-DOCS-POLICY.md).

## Scope notes

- The engine binds `127.0.0.1` by default and requires authentication; the documented threat
  model and current posture live in [`docs/SECURITY.md`](../docs/SECURITY.md). Findings are
  rated both for today's localhost posture and for a future network-exposed deployment.
- Configuration is **executed Python** (Routers/Handlers) from an admin-owned config directory;
  the ability of a config author to run code in-process is by design, not a vulnerability — see
  `docs/SECURITY.md` and `docs/SERVICE.md` for the trust boundary and required directory ACLs.
- The engine's other deliberately-powerful surfaces — native calls, process starts, thread
  impersonation, plug-in dispatch and the hostile-input parsers — are listed in
  [`docs/DANGEROUS-FUNCTIONALITY.md`](../docs/DANGEROUS-FUNCTIONALITY.md), with what constrains each one.
