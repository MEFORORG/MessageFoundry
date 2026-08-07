# Secure Development Standards

| | |
|---|---|
| **Document** | Secure Development Standards |
| **Applies to** | Any application developed under this standard. **MessageFoundry (MEFOR)** is the reference implementation (Appendix A). |
| **Maintained by** | Project maintainers (open-source). Each deploying organization assigns its own local owner. |
| **Status** | Published — adopter-facing |
| **Version** | 2.2 |
| **Date** | July 30, 2026 |
| **License** | Publishable under the project's open-source license; intended to be shared with adopters and reused across projects. |
| **Review cadence** | At least annually, and on any material architecture or threat change |
| **Aligns to** | NIST SP 800-218 (SSDF) · NIST SP 800-115 · NIST SP 800-66 Rev. 2 (HIPAA Security Rule) · OWASP ASVS 5.0 Level 3. Its Spec-Driven Development practices (§5) are a distilled synthesis by this document — not an external standard or certification. |

---

## How to read the rules

Each requirement in this standard is one testable statement carrying a stable identifier and the
evidence that settles it. Cite the identifier — in a documented deviation (A.6), in a review, in a
companion standard — so that the citation and the requirement it names stay the same sentence.

| Element | What it means |
|---|---|
| `SDS-<section>.<n>` | A stable identifier. It survives rewording of the text around it |
| **MUST**, **MUST NOT** | Absolute. Not meeting one is a deviation recorded in A.6, never a judgment call |
| **SHOULD**, **SHOULD NOT** | Depart from it only for a stated reason you have weighed |
| **MAY** | A free choice. Conforming either way |
| Evidence | What a reviewer looks at. A requirement with no checkable evidence is an aspiration |

Those words carry that meaning **only in capitals**; the same words in lowercase prose do not.

**An identifier is a permanent name, never a position.** A new rule takes the next free number in its
section and is **appended** — inserting one must never renumber those after it, because a citation
written against the old number would then resolve silently to a different requirement. Reword a rule
freely under the same identifier. Change *what it demands* and the identifier is retired and a new one
allocated; [Retired rules](#retired-rules) keeps the tombstone, so a citation that outlives its rule
lands on a record of what happened rather than on somebody else's requirement.

**The numeric part resembles a section number because of where the rule was first written, not because
it is a lookup.** An identifier is a name. If the surrounding section is ever renumbered the identifier
does not move, and that is the property that makes it worth citing: this document has been renumbered
once already (§5–§9 became §6–§10 when Spec-Driven Development was inserted; see Version history), and
citations written against the old numbers are still resolving to the wrong requirements today.

**Not every statement here is a rule.** The NIST and HIPAA crosswalks (§3, §7.2), the spec-stack and
EARS tables (§5.1, §5.2), the control-area inventory (§7.1), the reference list (§10) and the
Applicability Profile (Appendix A) describe, map or record; they carry no identifiers and nothing
conforms *to* them. A.6 is the register that **cites** rules — it does not state them.

---

## 1. Purpose and scope

This is the secure development standard for an **open-source software project intended for use in regulated environments, including healthcare** (handling of protected health information, PHI).

It is written to serve three audiences:

1. **The development team** — a consistent engineering bar to build to, across this and future projects.
2. **Deploying organizations** — both the maintainer's own organization and any other organization that adopts the open-source software, who need evidence that it was built and tested securely.
3. **Future projects** — this standard is **project-agnostic**; any new application can be developed under it without rewriting it.

**How the standard is structured.** The body (§2–§10) states requirements that apply to *any* application built under this standard. Each application records its own specifics — technology stack, applicable verification scope, the interface mechanisms it implements — in a **per-project Applicability Profile**. MEFOR's profile is Appendix A; future projects add their own (Appendix B, C, …).

**Companion standards.** Two companions extend this baseline. The [Secure AI-Assisted Development Standards](Secure_AI_Development_Standards.md) governs *building with an AI coding assistant* (risk tiers, provenance, guardrails). The [Code Quality & Anti-Slop Standards](Code_Quality_Standards.md) governs *judging whether the resulting code is good, not "AI slop"* — an evidence-based rubric aligned to ISO/IEC 25010. This document states the security baseline both build on; the three are complementary (process → build → outcome).

**Open-source note.** The software is developed in the open. This standard, and the project's security attestations, are publishable so that adopters can rely on them or extend them for their own environment.

---

## 2. Shared responsibility

Because the software is built by one party and deployed by others, responsibilities split cleanly. Stating the split prevents either side from assuming the other has it covered.

| The **project** is responsible for | The **deploying organization** is responsible for |
|---|---|
| Secure development practices (§4) | Its own environment, host, and network security |
| Secure-by-default configuration | Identity, credential, and key management in its environment |
| Security testing and attestation of the software (§6) | Backups, disaster recovery, and availability |
| Vulnerability response and disclosure (§8) | Its own compliance program — HIPAA Security Rule obligations, risk assessments of the deployment, and Business Associate Agreements where applicable |
| Documentation and evidence (§9) | Operational monitoring, patching, and incident response |

**No certification or agreement is conferred by the software itself.** A deploying organization operates the software under *its own* programs; an attestation that the software was built securely is evidence for that organization's assessment, not a substitute for it.

---

## 3. How this maps to NIST (overview)

Three NIST publications cover three different questions. Together they form the standard:

| Question | NIST publication | Section |
|---|---|---|
| **How is the software built?** (secure development process) | SP 800-218 (SSDF) | §4 |
| **How is it tested?** (security testing methodology) | SP 800-115 | §6 |
| **What controls does it implement?** (security/privacy controls + HIPAA safeguards) | SP 800-66 Rev. 2 | §7 |

These are complementary to the **OWASP ASVS 5.0 Level 3** verification (source-assisted and hands-on; performed internally today, with an independent assessment as a best-practice pre-production add-on — ASVS itself does not require independence): ASVS verifies that the built application is secure; SSDF attests to how it was built; 800-66 maps the HIPAA safeguards.

### A note on claims and wording (read before publishing any claim)

NIST does **not** issue certificates for these frameworks. The project may **display alignment claims**, but words them honestly and backs them with evidence:

- **Use:** "Built to NIST SP 800-218 (SSDF)," "NIST SSDF–aligned," "tested per NIST SP 800-115," "controls mapped to NIST SP 800-66 Rev. 2," "HIPAA-compliant deployment supported."
- **Do not use:** "NIST certified" or any phrasing implying a certificate exists.
- **Back every claim** with the implemented practice and its evidence (this standard, test reports, the ASVS attestation, the applicability profile). A self-attestation is a formal, legally significant declaration — only make it if it is true.
- A third-party assessor may **validate** an attestation; that raises its weight but is still not a NIST certificate.

#### Reviewing security prose: ask what a reader would DO with it

**Review security prose by asking what a reader would DO with it, not whether it is accurate.** This is
the governing instruction; the three rules below are instances of it.

It matters because the expensive failures are not false statements. A correctness review terminates at
"yes, that sentence is accurate" — and every finding in the 2026-07-30 documentation audit passed that
test. Each was **true about the mechanism and misleading about the posture**: a sentence that survives
every spot-check while pointing the reader somewhere they cannot go. Six such findings were caught by
asking what happens to someone who acts on the sentence; **none** was caught by accuracy checking.

- **State a load-bearing fact ONCE, and link to it; never restate it.** A repo that states a fact twice
  will eventually state it two ways, and the stale copy is the one that gets cited — a reader who finds
  *a* statement stops looking for the other. Three instances in a single day: `harden_kex_groups`
  described as pinning key-exchange groups across **five** live documents, when `SSLContext.set_groups`
  is a Python 3.15 API that pins nothing; a superseded "Transit degrades to an unkeyed audit chain on
  SQL Server/PostgreSQL" claim left in `PHI.md` after the code closed it, from where it propagated into
  a public web page *and* an internal security review; and `PHI.md` §5 asserting "no PHI is placed in a
  URL" while §7 documented the exact query parameters that carry it. In every case the repo held
  **both** the right and the wrong version. The mitigation is structural, not diligence: pick the source
  of record, link to it, and let the copy die.
- **A completeness claim is a liability.** "Two configurations do X, and a reviewer should hear both"
  invites the check and then survives it, because a reader who confirms the named case stops looking.
  Twice this documentation set shipped such a sentence wrong in *both* directions at once — naming a
  case that no longer existed while omitting one that did. Where you cannot enumerate exhaustively, say
  "at least", name the case that matters, and point at the reference.
- **A compensating control must not rest on a false premise.** A `Referrer-Policy` relaxation was
  justified on the grounds that console URLs "carry opaque ids only (never PHI)" — untrue of the
  console's own search route. The control itself was sound; the stated reason was not, and the next
  person to touch it reasons from the comment. A wrong justification is worse than none.

- **Confirm your instrument answers the question you asked, not one adjacent to it.** The rules above
  catch prose that is true and misleading; this one catches a claim that is **false when written, while
  feeling measured**. The rule is the question — ***does my instrument answer the question I asked, or
  one adjacent to it?*** — and it outlives every example below. **The pairs are dated illustrations, not
  the rule:** `--is-ancestor` misleads here only because this repository squash-merges, and any of them
  may stop being true without the question changing at all. On 2026-08-02 four parallel sessions
  retracted eleven claims in a single night and every one traced to an instrument answering in adjacent
  terms: `git diff` on a **staged** file (returns
  *"is there an unstaged delta"*; the question was *"is the tree dirty"*); `merge-base --is-ancestor`
  (*"is this an ancestor"* vs *"did this work land"* — **squash-merge makes the answer always no**); a
  hash **inequality** (*"are these different"* vs *"is the installed copy **worse**"*); a session-start
  **banner** (*"who was live when it printed"* vs *"who is live now"*); `grep -c $'\r$'` over `git diff`
  output (*"does the diff **render** a CR"* vs *"does the file contain CRLF"* — it reported a
  byte-perfect file as mangled); `$?` after `cmd | tail` (*"did `tail` succeed"*); the Actions
  `?filter=latest` view (*"what did the **latest attempt** do"* vs *"what did the suite ever do"*); and a
  **job** conclusion answering a **step** question, which drops the tightest samples by construction.
  **Re-reading caught none of the eleven; a check that could fail caught one immediately.** Nor were
  these facts that expired — "#119 never merged (it died on a CI timeout)" was never true at any instant:
  that pull request's timeline carries exactly one `closed` event, simultaneous with `merged`. Dating a
  claim does not protect against this class; only re-deriving it does. So before publishing a measured
  claim, write down the question and write down what the instrument returns, and check that they are the
  same sentence.

*Provenance (the evidence is the point):* the completeness-claim and false-premise rules, and the
governing instruction above, came out of the 2026-07-30 public-documentation audit; the
state-it-once rule was named by the parallel ASVS review session, which also supplied the
`harden_kex_groups` and `PHI.md` §5/§7 instances. The instrument rule came out of the 2026-08-02
parallel-session cluster — four sessions, eleven retractions, none caught by its own author — and was
named by the repo-security-review session after applying it to its own four and finding four for four;
the remaining instances were contributed by the ci-margin-correction, announce-hook, sandbox-codec and
ADR 0154 sessions, each of which had made one. `CLAUDE.md` §11 carries these as bare one-line
imperatives — deliberately duplicated, because an instruction that short cannot meaningfully drift and
a pointer nobody follows mid-task changes no behaviour. **This section is the source of record for the
reasoning, the evidence and the dates.**

---

## 4. Secure software development — NIST SP 800-218 (SSDF)

SSDF organizes secure development into four practice groups: **Prepare the Organization (PO)**, **Protect the Software (PS)**, **Produce Well-Secured Software (PW)**, and **Respond to Vulnerabilities (RV)**. Requirements below apply to every project; project-specific tooling is recorded in the applicability profile.

### 4.1 Prepare the Organization (PO.1–PO.5)

| ID | Requirement | Evidence |
|---|---|---|
| SDS-4.1.1 | **MUST** document the project's security requirements — this standard plus the project's standing contract — and treat them as first-class alongside functional requirements. **(PO.1)** | This standard, and the standing contract file it names |
| SDS-4.1.2 | **SHOULD** capture those requirements as first-class specs that drive design and tests (§5). **(PO.1)** | A spec artifact per requirement, linked to its design and tests |
| SDS-4.1.3 | **MUST** define maintainer and reviewer roles, with security ownership stated explicitly rather than assumed. **(PO.2)** | The written role assignment, naming who owns security |
| SDS-4.1.4 | **MUST** include secure-development orientation in onboarding. **(PO.2)** | The onboarding material |
| SDS-4.1.5 | **MUST** hold all source in version control. **(PO.3)** | The repository |
| SDS-4.1.6 | **MUST** run automated security checks in CI on every change (§6.2). **(PO.3)** | The CI workflow definition and a run of it |
| SDS-4.1.7 | **MUST** run dependency scanning and secret scanning. **(PO.3)** | The scanner jobs and their most recent results |
| SDS-4.1.8 | **MUST** pin dependencies and verify their integrity. **(PO.3)** | A hash-locked dependency file, checked in CI for drift |
| SDS-4.1.9 | **MUST** define pass/fail release gates (§6.4). **(PO.4)** | The documented gate list |
| SDS-4.1.10 | **MUST NOT** ship a release carrying unresolved high or critical findings. **(PO.4)** | The gate result for the released commit |
| SDS-4.1.11 | **MUST** require disk encryption on developer machines. **(PO.5)** | A stated and reviewed environment baseline |
| SDS-4.1.12 | **MUST NOT** use real PHI in development or test. Synthetic or de-identified data only. **(PO.5)** | The test corpus, and the de-identification path that produced it |
| SDS-4.1.13 | **MUST** grant least-privilege access to repositories and environments. **(PO.5)** | A dated access review |

### 4.2 Protect the Software (PS.1–PS.3)

| ID | Requirement | Evidence |
|---|---|---|
| SDS-4.2.1 | **MUST** enforce branch protection and required reviews on the trunk. **(PS.1)** | The protection settings, and a rejected direct push |
| SDS-4.2.2 | **MUST NOT** permit direct commits to the main branch. **(PS.1)** | The protection settings |
| SDS-4.2.3 | **SHOULD** sign commits where the platform supports it. **(PS.1)** | Signature status on trunk commits |
| SDS-4.2.4 | **MUST** version releases and make them integrity-verifiable by checksum or signature. **(PS.2)** | The published checksums or signatures |
| SDS-4.2.5 | **MUST** generate a software bill of materials per release. **(PS.2)** | The SBOM attached to the release |
| SDS-4.2.6 | **MUST** archive each released version, its build inputs and its SBOM, so an incident can be analysed against what actually shipped. **(PS.3)** | The retained archive, and a retrieval of one past release |

### 4.3 Produce Well-Secured Software (PW.1, PW.2, PW.4–PW.9)

**Secure design and threat modeling (PW.1–PW.2).** The reviewed design artifact and its acceptance criteria are the spec; §5 describes the recommended clarify/analyze gates applied before build.

| ID | Requirement | Evidence |
|---|---|---|
| SDS-4.3.1 | **MUST** threat-model each interface and component. **(PW.1–PW.2)** | A written threat model per interface, dated |
| SDS-4.3.2 | **MUST** identify and document trust boundaries. **(PW.1–PW.2)** | The boundary list in the threat model |
| SDS-4.3.3 | **MUST** review a design against the security requirements **before** build. **(PW.1–PW.2)** | The review record, dated earlier than the implementation |
| SDS-4.3.4 | **SHOULD** apply the clarify and analyze gates of §5 before build. **(PW.1–PW.2)** | Resolved clarifications on the design record |

**Reuse well-secured components (PW.4).**

| ID | Requirement | Evidence |
|---|---|---|
| SDS-4.3.5 | **SHOULD** prefer a vetted library over a new implementation. **(PW.4)** | The dependency's provenance, recorded when it was added |
| SDS-4.3.6 | **MUST NOT** implement custom cryptography. **(PW.4)** | Absence of hand-rolled primitives; a named library for each |

**Secure coding practices (PW.5).** Every rule below is mandatory unless it says otherwise.

| ID | Requirement | Evidence |
|---|---|---|
| SDS-4.3.7 | **MUST** validate structure and content at every ingress. | The validator, and a test per ingress that rejects malformed input |
| SDS-4.3.8 | **MUST** reject or quarantine malformed input rather than processing it. | The error/dead-letter path, and its disposition record |
| SDS-4.3.9 | **MUST NOT** build SQL by string concatenation. Parameterized statements or an ORM throughout. | A source scan showing no string-built statements |
| SDS-4.3.10 | **MUST** enforce authentication and authorization on every action (§7.4). | A route-to-permission map covering every action |
| SDS-4.3.11 | **MUST** deny by default. | The default-deny path, and a test that an unmapped action is refused |
| SDS-4.3.12 | **MUST** authenticate every web-service endpoint. | The endpoint inventory, each with its mechanism |
| SDS-4.3.13 | **MUST** validate and size-limit payloads against a schema. | The schema, and the configured limit |
| SDS-4.3.14 | **MUST** disable external-entity resolution and DTD processing for SOAP/XML. | The parser configuration, and an XXE regression test |
| SDS-4.3.15 | **MUST** apply rate limiting and timeouts. | The configured values |
| SDS-4.3.16 | **MUST NOT** expose stack traces or sensitive data in fault responses. | A fault-response test asserting the redacted shape |
| SDS-4.3.17 | **MUST** confine file reads and writes to configured directories, canonicalizing paths and rejecting traversal and symlink escapes. | The canonicalization, and traversal/symlink regression tests |
| SDS-4.3.18 | **MUST** validate file type and size by content, not by extension. | The content-sniffing check |
| SDS-4.3.19 | **MUST** write files atomically (write-then-rename) so a partial file is never processed. | The write path |
| SDS-4.3.20 | **MUST NOT** store handled files in an executable or web-served path. | The configured storage location |
| SDS-4.3.21 | **MUST NOT** execute file contents. | Absence of any execution path from handled content |
| SDS-4.3.22 | **SHOULD** scan inbound files for malware where feasible. | The scanner, or a stated reason it is not feasible |
| SDS-4.3.23 | **MUST** encrypt sensitive files at rest and securely delete them after processing, per the retention policy. | The encryption setting and the deletion step |
| SDS-4.3.24 | **MUST** use TLS for all network communication. | The TLS configuration and its minimum version floor |
| SDS-4.3.25 | **MUST** encrypt sensitive data at rest. | The at-rest encryption setting |
| SDS-4.3.26 | **MUST** use approved algorithms and libraries. | The cryptographic inventory |
| SDS-4.3.27 | **MUST** use FIPS-validated cryptography where a deployment requires it. | The deployment's validated-module configuration |
| SDS-4.3.28 | **MUST NOT** place secrets in code, in prompts, or in commit history. | A clean secret-scan over the full history |
| SDS-4.3.29 | **MUST** source secrets from the environment or a secret store. | The configuration surface, carrying no literal secret |
| SDS-4.3.30 | **MUST** enforce the two rules above by pre-commit and CI secret scanning. | The pre-commit hook and the CI job, each observed to fail on a planted secret |
| SDS-4.3.31 | **MUST** fail closed. | A test per control asserting the closed outcome on error |
| SDS-4.3.32 | **MUST NOT** log secrets or sensitive data. | A redaction test over the log surface |
| SDS-4.3.33 | **MUST** produce a tamper-resistant, timestamped audit log. | The log's integrity mechanism, and a detected-tamper test |

**Build, review, test and defaults (PW.6–PW.9).**

| ID | Requirement | Evidence |
|---|---|---|
| SDS-4.3.34 | **MUST** make builds reproducible. **(PW.6)** | Two builds of one commit producing the same artifact |
| SDS-4.3.35 | **MUST** fix security-relevant build, interpreter and dependency settings in the pipeline rather than on a developer machine. **(PW.6)** | The pipeline definition |
| SDS-4.3.36 | **MUST** peer-review every change. Where a project cannot staff a human second reviewer, the deviation and its compensating controls are recorded in A.6. **(PW.7)** | The review record per change, or the A.6 entry |
| SDS-4.3.37 | **MUST** run static analysis and software composition analysis in CI (§6.2). **(PW.7)** | The SAST and SCA jobs, and their results for the released commit |
| SDS-4.3.38 | **SHOULD** confirm in review that a change conforms to its spec's acceptance criteria (§5). **(PW.7)** | The criteria, checked off in the review |
| SDS-4.3.39 | **MUST** maintain an automated test suite that runs on every change. **(PW.8)** | The suite, and its run on the change |
| SDS-4.3.40 | **MUST** include security test cases in that suite. **(PW.8)** | The security tests, named |
| SDS-4.3.41 | **SHOULD** trace tests to the spec's acceptance criteria so coverage is mechanical rather than prose (§5). **(PW.8)** | A criterion-to-test link per criterion |
| SDS-4.3.42 | **MUST** judge test *quality*, not merely presence, per the [Code Quality & Anti-Slop Standards](Code_Quality_Standards.md) — behavior-verifying assertions over mock choreography, with mutation testing as guidance. **(PW.8)** | The quality review against that rubric |
| SDS-4.3.43 | **MUST NOT** gate quality on line-coverage percentage alone; it is a gameable single scoreboard. Measure structure and behavior. **(PW.8)** | The gate definition, showing no coverage-only threshold |
| SDS-4.3.44 | **MUST** ship secure-by-default: transport encryption on, at-rest encryption on, least-privilege accounts, audit logging on. **(PW.9)** | The shipped default configuration |
| SDS-4.3.45 | **MUST** require an explicit, documented opt-in for any insecure option. **(PW.9)** | The opt-in setting and the documentation stating its risk |

### 4.4 Respond to Vulnerabilities (RV.1–RV.3)

| ID | Requirement | Evidence |
|---|---|---|
| SDS-4.4.1 | **MUST** monitor dependencies continuously. **(RV.1)** | The monitoring job and its most recent run |
| SDS-4.4.2 | **MUST** publish a defined intake channel for internally and externally reported issues (§8). **(RV.1)** | The published channel |
| SDS-4.4.3 | **MUST** triage findings by severity against target remediation timelines set in the applicability profile. **(RV.2)** | The triage record, with dates against the profile's targets |
| SDS-4.4.4 | **MUST** verify a fix before closing the finding. **(RV.2)** | The verifying test or check, referenced from the closure |
| SDS-4.4.5 | **MUST** perform a root-cause review of a significant vulnerability. **(RV.3)** | The root-cause record |
| SDS-4.4.6 | **MUST** feed systemic causes back into this standard. **(RV.3)** | The resulting change to this document, in Version history |

---

## 5. Spec-Driven Development

The practices in this section are a **distilled synthesis** drawn from GitHub Spec Kit, AWS Kiro, and BDD / Specification-by-Example — **not adoption of any external tool or standard, and not a certification.** They formalize habits the reference project already practices. **They are recommended (SHOULD), adopted incrementally**; they add no new blocking release gate, and they do not weaken or replace any security requirement in §4 or §6. Where a practice maps to an SSDF practice, that mapping is noted.

### 5.1 The spec stack (constitution → decisions → requirements → tasks → verification)

Spec-driven development treats the artifacts that describe *what* a change must do and *why* as first-class, versioned, and connected — so design, build, and verification trace back to an agreed specification rather than to memory. The recommended structure is five layers, each mapping to an SSDF practice. The framing here is generic; the concrete MEFOR artifacts that fill each layer are recorded in Appendix A.7.

| Layer | What it holds | Maps to |
|---|---|---|
| **Constitution** | The standing, versioned contract of invariants + vocabulary every later artifact honors. | PO.1 |
| **Decisions** | Architecture decision records with a build-gating lifecycle (proposed → accepted → superseded/rejected). | PW.1–PW.2 |
| **Requirements / sequencing** | Numbered, ID'd requirement items, cross-referenced by decisions. | PO.1 |
| **Tasks** | Decomposition of decisions/requirements into work items / lanes / gates. | PW.1–PW.2 |
| **Verification** | Automated checks + human conformance reviews that test/inspect against the spec. | PW.7 (review), PW.8 (test) |

A project SHOULD keep these five layers present and connected; the recommended connections are described in §5.3–§5.5.

### 5.2 EARS acceptance criteria

A change's behavioral acceptance criteria SHOULD be written in **EARS (Easy Approach to Requirements Syntax)** — a small, constrained grammar that turns prose requirements into testable, unambiguous statements. EARS offers five templates:

| Template | Form |
|---|---|
| Ubiquitous (always-on) | THE SYSTEM SHALL `<response>` |
| Event-driven | WHEN `<trigger>` THE SYSTEM SHALL `<response>` |
| State-driven | WHILE `<state>` THE SYSTEM SHALL `<response>` |
| Unwanted behavior | IF `<condition>` THEN THE SYSTEM SHALL `<response>` |
| Optional feature | WHERE `<feature>` THE SYSTEM SHALL `<response>` |

> **Example (event-driven).** WHEN a message fails strict validation, THE SYSTEM SHALL NAK (AR/AE) and record `ERROR` before any ingress row.

This fits the project's existing posture: the standing contract's invariants already read as SHALL-style statements, and each ASVS "Verify that X" requirement restates as an underlying "the system SHALL X" that EARS can express. EARS also maps cleanly onto the *technical* HIPAA safeguards (access control, audit, integrity, transmission security) the software implements — the administrative safeguards (§7.2) are organizational obligations, not behavioral system triggers, so they fall outside EARS's WHEN/WHILE/IF grammar. *(Lineage: AWS Kiro `requirements.md`; distilled, not adopted.)*

### 5.3 Requirement → design → tasks → test traceability

Each acceptance criterion SHOULD carry an **ID** linked to the test or fixture that exercises it, so coverage is **mechanical, not prose** — "which criteria are untested" becomes computable rather than a judgment call. The reference project already owns the pieces — decisions in ADRs, requirement IDs in the backlog, tasks in release/multisession plans — and the recommendation is to **connect** them: criterion ID → test/fixture link. *(Lineage: AWS Kiro requirements/design/tasks triad; distilled.)*

### 5.4 Clarify and analyze (lightweight, advisory)

Two lightweight checks are recommended, both explicitly **advisory, not hard gates**:

- **Clarify** — force ambiguity resolution before build, surfacing and answering open questions while they are still cheap to change. The project already has an informal version: the ADR **"To resolve on acceptance"** block.
- **Analyze** — automated cross-artifact consistency/coverage: does every acceptance criterion have a task and a test? does any artifact contradict the constitution's invariants?

These SHOULD be run as lightweight advisory checks. They introduce no new blocking release gate (cf. §6.4). *(Lineage: GitHub Spec Kit `specify → clarify → plan → tasks → analyze → implement`; distilled.)*

### 5.5 Executable acceptance criteria (living documentation)

BDD / Specification-by-Example expresses acceptance criteria as Given/When/Then scenarios with concrete `(input → expected outcome)` example tables that **execute** as tests — so specification and verification cannot silently drift, and the spec doubles as living documentation. This fits naturally with EARS's WHEN/THEN phrasing, and the HL7 domain (well-defined inputs, well-defined dispositions) is well suited to example-driven verification. The concrete reference-project opportunity (detailed as R2 in Appendix A.7):

> A project's dry-run gate that already replays fixtures through the real graph but asserts only "didn't error" **SHOULD** be upgraded to assert an **expected disposition per fixture** (e.g. `PROCESSED` / `UNROUTED` / `FILTERED` / `ERROR`), turning it into an executable acceptance-criteria check.

*(Lineage: BDD / Specification-by-Example; distilled, not BDD-tool adoption.)*

### 5.6 Constitution as a first-class versioned artifact

A standing, versioned ruleset that all downstream artifacts respect is sound practice — it gives design, decisions, and verification a single source of invariants and vocabulary to honor. The reference project already has it: the project's standing contract / constitution ([`../CLAUDE.md`](../CLAUDE.md)). The only addition is that the **analyze** check (§5.4) can verify no artifact violates the constitution's invariants. *(Validates existing practice; nothing external adopted.)*

> **Recommendation pointer.** For the reference project's existing spec stack and three concrete, recommended improvements (R1–R3), see Appendix A.7.

---

## 6. Security testing and assessment — NIST SP 800-115

Testing follows the methodology of NIST SP 800-115 (*Technical Guide to Information Security Testing and Assessment*): review techniques, target identification and analysis, and target vulnerability validation.

### 6.1 Testing tiers

| Tier | What | Cadence |
|---|---|---|
| Automated (in CI/CD) | SAST, SCA/dependency scan, secret scanning, unit/integration security tests | Every commit / build |
| Dynamic | DAST / authenticated testing of the running app | Per release and periodically |
| Independent review | Third-party source-code review + penetration test per 800-115 — the project's own pre-production gate (§6.3), **not** an ASVS mandate. It covers the **OWASP ASVS 5.0 Level 3** verification, which is source-assisted/hands-on and may be performed internally; the external engagement adds independence + credibility. | Before a production release; after major change; periodically thereafter |

### 6.2 Internal testing (continuous)

- SAST and SCA run automatically; builds fail on new high/critical findings.
- Secret scanning runs pre-commit and in CI; the full git history is kept clean of secrets, credentials, keys, and any sensitive data.
- Security-focused test cases (authn/authz, input validation, error handling) are part of the standard suite.

### 6.3 OWASP ASVS 5.0 Level 3 — scope

The independent review is scoped to **OWASP ASVS version 5.0.0** (released May 2025), **Level 3**:

- **Version-pinned citation.** Requirements are cited as `v5.0.0-<chapter>.<section>.<requirement>`; identifiers changed substantially from 4.0.x, so the version is always stated.
- **Scale and level model.** ~350 requirements across **17 chapters**. Levels are **cumulative** — L3 includes all of L1 and L2. **MessageFoundry targets Level 3** (defence-in-depth for the highest-assurance contexts), chosen above the usual L2 norm because the engine carries PHI; L1 and L2 form the cumulative baseline and are assessed first.
- **Access required for L3.** L3 is a white-box / hybrid review: the assessor needs source code, developer access, documentation, and an authenticated test instance running **synthetic, non-PHI** data.
- **Documented Security Decisions (new in 5.0).** Each chapter opens with a requirement to document *how* its controls are applied and *why*. This standard, the per-interface threat models (PW.1), and the secure-default baseline (PW.9) serve as that documentation. **Each project documents which chapters are in scope and records exclusions with justification** — see the applicability profile. (Documenting exclusions is itself an ASVS practice.)
- **5.0 modernizations to honor.** Cryptography (V11) reflects current guidance, including post-quantum considerations; authentication and password rules (V6) align with NIST SP 800-63; ASVS 5.0 scopes to **applications and APIs** (host/network infrastructure is the deployer's responsibility, §2).

**The 17 chapters (v5.0.0):** V1 Encoding and Sanitization · V2 Validation and Business Logic · V3 Web Frontend Security · V4 API and Web Service · V5 File Handling · V6 Authentication · V7 Session Management · V8 Authorization · V9 Self-contained Tokens · V10 OAuth and OIDC · V11 Cryptography · V12 Secure Communication · V13 Configuration · V14 Data Protection · V15 Secure Coding and Architecture · V16 Security Logging and Error Handling · V17 WebRTC.

*Per-project chapter applicability (in scope / excluded with justification) is recorded in the applicability profile.*

### 6.4 Release gates

A production release requires: passing automated checks, no unresolved high/critical findings, current independent-review status (or a documented risk acceptance), and updated evidence (§9).

---

## 7. Security/privacy controls and HIPAA safeguards — NIST SP 800-66 Rev. 2

For deployments that handle PHI, the software implements security and privacy controls — verified against **OWASP ASVS 5.0** (§6.3) — and maps them to the HIPAA Security Rule using NIST SP 800-66 Rev. 2 (*Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide*). *(A non-PHI deployment may scope the HIPAA mapping out; the control areas still apply.)*

### 7.1 Applied control areas

These control areas summarize the software's security posture. Each is verified through the OWASP ASVS 5.0 chapter(s) noted (§6.3) and produced by the secure-development practices of §4.

| Control area | Applied to the software | ASVS 5.0 chapter |
|---|---|---|
| **Access control** | Least-privilege, role-based access; deny by default | V8 Authorization |
| **Authentication** | Authenticated access enforced on every action; strong credential handling; interface mechanisms per §7.4 | V6 Authentication (V9/V10 when tokens/OAuth are introduced) |
| **Audit & accountability** | Tamper-resistant, timestamped audit logging; no sensitive data in logs | V16 Security Logging and Error Handling |
| **Communications & data protection** | TLS in transit; encryption at rest; trust-boundary enforcement | V11 Cryptography; V12 Secure Communication; V14 Data Protection |
| **System & information integrity** | Input validation; flaw remediation (RV); message/data integrity and durability | V1/V2 Validation; V15 Secure Coding and Architecture |
| **Configuration management** | Version control, reviewed changes, secure-default configuration, SBOM | V13 Configuration |
| **Contingency** | Backup/restore and replay capability *(deployer operates DR in their environment, §2)* | — *(operational; deployer)* |
| **Risk assessment** | Vulnerability assessment by the project; deployment risk assessment by the deployer | §4.4 (RV); §7.3 |
| **Secure acquisition** | Secure development practices (§4) and vetted third-party components | V15; §4 |

### 7.2 HIPAA Security Rule safeguard mapping (via 800-66 Rev. 2)

| HIPAA safeguard | Representative requirement | Software implementation | ASVS 5.0 |
|---|---|---|---|
| **Administrative** | Security management, risk analysis, workforce/access management | This standard; least-privilege access; *deployer's risk analysis* | V8, V15 |
| **Physical** | Facility and device controls | *Deployer's environment* | (Deployer) |
| **Technical — Access Control** | Unique user ID, authentication, automatic logoff | Authenticated, role-based access; session controls | V6, V7, V8 |
| **Technical — Audit Controls** | Record and examine activity | Tamper-resistant, timestamped audit log | V16 |
| **Technical — Integrity** | Protect data from improper alteration/destruction | Input validation; durable, ordered processing | V1, V2 |
| **Technical — Transmission Security** | Protect data in transit | TLS for all sensitive transport | V12 |
| **(Addressable) Encryption** | Encrypt sensitive data at rest and in transit | Encryption at rest and in transit | V11, V14 |

### 7.3 Deployment risk assessment

Each deploying organization conducts its own HIPAA Security Risk Assessment of the deployment (mapped to 800-66 Rev. 2). The project supplies evidence (§9) to support it; it does not replace it.

### 7.4 Interface authentication standard

Integration software authenticates **systems, not people**, on its interfaces. Each connection uses the strongest mechanism the partner system supports, drawn from the hierarchy below; the mechanism, scope, and credential reference for every connection are recorded in its connection definition. (Maps to ASVS V6/V9/V10/V12; HIPAA person-or-entity authentication and transmission security.) *Which mechanisms a given project implements is recorded in its profile.*

**Preferred — system-to-system:**

- **Mutual TLS (mTLS).** Client-certificate authentication over **TLS 1.2+ (prefer 1.3)** with strong cipher suites; validate the full chain to a trusted CA, check revocation (OCSP/CRL), rotate certificates before expiry. Where tokens are also used, prefer **sender-constrained (mTLS-bound) access tokens** (ASVS 5.0 V10).
- **OAuth 2.0 client-credentials grant.** The default for machine-to-machine API auth. Prefer **asymmetric client authentication (`private_key_jwt`)** over shared secrets; issue short-lived, per-connection scoped tokens; validate issuer, audience, expiry, and scope on every request.
- **SMART on FHIR (Backend Services).** For any FHIR REST interface, authenticate using the SMART **Backend Services** profile — OAuth 2.0 client-credentials with a **signed JWT client assertion** and `system/` scopes; validate granted scopes against the requested operation.

**Directory / enterprise integration (e.g., Active Directory):**

- **Run under a least-privilege service account — preferably a group-Managed Service Account (gMSA)** on Windows/AD — so the password is auto-rotated and never stored in configuration.
- **Use Kerberos / Integrated Windows Authentication**; prefer Kerberos over NTLM (disable NTLM where feasible) with correct SPNs.
- **Authenticate to databases with integrated authentication** (the service account) rather than a stored database password, where supported.
- **Perform directory lookups over LDAPS (LDAP over TLS) only** — never cleartext LDAP; bind with a least-privilege account.
- **Map roles to directory security groups** for centralized RBAC; if human operators authenticate, **federate to the enterprise identity provider (AD FS / Entra ID) via OIDC or SAML** rather than a local user store.

**Legacy / interoperability tier** *(supported, least-preferred, documented per connection):* HTTP Basic over TLS, per-connection API keys, or SOAP **WS-Security** (UsernameToken or, preferably, X.509 certificate tokens with message-level signing). Always over TLS; credentials vaulted, scoped per connection, and rotated. Used only when a partner system cannot support a preferred mechanism, with the exception recorded.

**Across all mechanisms:** TLS everywhere (no cleartext sensitive transport); credentials and keys in a secret store, never in code or config; per-connection least privilege; and per-connection IP allowlisting / network segmentation as defense-in-depth.

---

## 8. Open-source project security

Because the software is developed in the open and adopted by others, the project also maintains:

- **Repository hygiene.** No secrets or sensitive data ever committed; the full history is scanned and kept clean. A clear `LICENSE`.
- **Coordinated vulnerability disclosure.** A published `SECURITY.md` with a private reporting channel and a disclosure timeline; reported issues feed the RV process (§4.4).
- **Signed, verifiable releases.** Release artifacts are signed and accompanied by an SBOM (PS.2), so adopters can verify provenance and integrity.
- **Contribution review.** All external contributions are security-reviewed before merge; signed commits / DCO required; maintainers gate merges; dependency provenance is checked.
- **Adopter guidance.** A deployment/hardening guide so adopters can stand the software up securely and meet their §2 responsibilities.

---

## 9. Evidence and attestation

The project maintains a current evidence set so any claim is backed:

- This **Secure Development Standards** document and each project's standing contract.
- **SSDF practice evidence** (toolchain configuration, review records, SBOMs, secure-default settings).
- **Test results** — CI security-scan history; the independent **OWASP ASVS 5.0 Level 3** report and re-test results.
- **Per-project applicability profile** (Appendix A and onward).
- A **claims register** recording each published claim, its wording, and the evidence behind it.

**Attestation posture.** The software is self-attested as NIST SSDF–aligned, tested per NIST SP 800-115, **assessed against** OWASP ASVS 5.0 **using Level 3 as the target** — an assessment **in progress**, not a completed verification — and built to support HIPAA-compliant deployment (controls mapped to NIST SP 800-66 Rev. 2). Third-party validation of the SSDF attestation and of the ASVS assessment raises the weight of these claims.

> **The ASVS wording above changed on 2026-08-02, and the previous wording was wrong.** It read *"verified against OWASP ASVS 5.0 Level 3."* Three facts make that unsupportable, and they are stated here rather than quietly corrected because the claim was **published**:
> 1. **The survey is incomplete.** A minority of the 345 requirements have been read against the ASVS text at a known commit; the remainder are recorded as *unverified*, which is explicitly **not** a pass. "Verified" asserted a completed verification that had not occurred.
> 2. **Open requirements exist**, including at Level 2 — so the claim was not rescuable by narrowing it to a lower level.
> 3. **At least one Level 3 requirement is scoped out** as a hosting-platform property outside the assessed software. Under ASVS 5.0 that does **not** preserve a Level 3 claim: 4.0's "may still claim full ASVS compliance" clause was **dropped** in 5.0, and OWASP retains normative authority over which requirements sit at which level. A Level 3 claim omitting a Level 3 requirement is non-conformant on OWASP's own terms.
>
> **No accredited Level 3 pathway exists to appeal to.** OWASP certifies no vendor or software and states that any trust mark claiming ASVS compliance is not officially endorsed by it; the one ASVS-based accreditation scheme accredits testing *firms*, and its published scope is Levels 1–2. So "self-attested" is the only honest register available here, and this section now uses it.
>
> Current status is held in the project's private assessment record, which is the count of record; **no figure is restated here**, deliberately, so this page cannot go stale against it. **Attestations are published with releases** so adopters can rely on them; each adopter still performs its own deployment risk assessment (§7.3). None of these is a NIST certificate; displayable certificates (SOC 2, ISO 27001, HITRUST) are a separate, organization-level track.

**What the SSDF attestation is answerable to — and it is nothing, today.** The alignment above is **voluntary evidence for adopters, not a regulatory obligation**. CISA's *Secure Software Development Attestation Form* does not require an attestation for software that is **freely obtained and publicly available**, nor for open-source software an agency obtains directly, nor for third-party open-source components incorporated into an end product — so a project distributed as free open source sits outside its scope entirely. **The exemption is a property of the distribution model, not of the software:** a paid or hosted offering of this same code would fall inside the form's scope, and this sentence is the only thing that will make that visible when it happens. Recorded because silence here invites the error in **both** directions — claiming a compliance standing the project does not hold, or inheriting an obligation it does not have.

**The SSDF version is pinned deliberately; do not re-map to the draft.** §4 maps **SP 800-218 v1.1** (February 2022), which is the current **final** version — the mapping is current, not lagging. **SP 800-218r1 (SSDF 1.2) is an Initial Public Draft**: published 2025-12-17, comments closed 2026-01-30, no announced finalisation date. This document is **not** re-mapped until r1 is Final, and not incrementally as the draft moves. When it does land, the re-map is a **per-ID re-resolution, never a find-and-replace** — 1.2 renumbers and adds practices, so a citation that still resolves to a real practice but a *different* one is the failure that looks like success, and nothing in CI can see it. The single-maintainer PW.7 deviation must be re-justified against 1.2's own text rather than carried across.

---

## 10. References

- NIST SP 800-218, *Secure Software Development Framework (SSDF) v1.1*
- NIST SP 800-115, *Technical Guide to Information Security Testing and Assessment*
- NIST SP 800-66 Rev. 2, *Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide*
- OWASP Application Security Verification Standard (ASVS) v5.0.0 (May 2025), Level 3

---

## Appendix A — Applicability Profile: MessageFoundry (MEFOR)

*The first project under this standard. Future projects add their own profile (Appendix B, C, …) using the same headings.*

### A.1 Project summary

MessageFoundry (MEFOR) is an open-source **HL7 v2.x integration engine** — a candidate alternative to commercial engines (Corepoint, Mirth Connect, Rhapsody, Cloverleaf). It routes and transforms clinical messages between systems.

**Technology stack:** Python 3.14+, FastAPI/uvicorn, aiosqlite/SQLite (WAL), `python-hl7`/`hl7apy`, PySide6 (desktop UI), Windows/PowerShell deployment; MLLP transport with native MLLP-over-TLS (opt-in via cert config — ADR 0002); application-layer AES-256-GCM encryption at rest (database-native where the backend provides it). Durable message store with FIFO/per-key ordering and dead-letter handling.

### A.2 Interfaces and surfaces

- **HL7 v2.x over MLLP** (inbound/outbound). **MLLP-over-TLS is built** (opt-in via per-connection cert config; optional client-cert **mTLS** via a trust anchor), with an off-loopback bind guard and a certificate-expiry monitor — ADR 0002 / WP-13b. Loopback-bound by default; IP allowlisting as additional defense-in-depth.
- **REST and SOAP** web-service interfaces — **outbound destinations built** (per-connection bearer / Basic-over-TLS; SOAP WS-Security + XML-DSig per ADR 0015). A **generic inbound HTTP listener is built** (ADR 0023) as the substrate REST/SOAP-in ride on; ADR 0003/0004 framed the original non-HL7 transport + payload-agnostic ingress design.
- **Database** source (inbound poll) and destination — ADR 0003.
- **File-handler interface** (file-drop pickup / output).
- **PySide6 desktop client**, plus an **opt-in read-only web ops dashboard** served under `/ui`
  (`[api].serve_ui`, off by default — [ADR 0065](adr/0065-web-ops-dashboard.md)).

### A.3 OWASP ASVS 5.0 Level 3 — chapter applicability

| # | Chapter (v5.0.0) | In scope | Notes |
|---|---|---|---|
| V1 | Encoding and Sanitization | Yes | HL7 input validation, output encoding, parameterized SQL |
| V2 | Validation and Business Logic | Yes | HL7 structural/content validation; routing/business-rule checks |
| V3 | Web Frontend Security | Yes | **Core surface** — the browser operator console at `/ui`, the sole operator UI since the PySide6 desktop client was retired (BACKLOG #103, 2026-07-13). Security headers, CSP, COOP/CORP and clickjacking defenses apply |
| V4 | API and Web Service | Yes | **Core surface** — the localhost engine API: authn/authz per endpoint, payload size limits, WS-Origin checks. REST/SOAP outbound destinations plus a **generic inbound HTTP listener** (ADR 0023); **XXE/DTD defenses apply when inbound XML / SOAP-IN body parsing is added** — no inbound XML attack surface yet |
| V5 | File Handling | Yes | File-handler interface: path confinement, content validation, atomic write-then-rename, malware scan, encryption at rest |
| V6 | Authentication | Yes | Per §7.4; align to NIST SP 800-63 |
| V7 | Session Management | Yes | API/UI session controls, timeout/logout |
| V8 | Authorization | Yes | Role-based, least-privilege, deny-by-default |
| V9 | Self-contained Tokens | **In scope when introduced; currently N/A** | No JWT/JOSE today — sessions are opaque, server-side, revocable tokens. Applies if/when JWT access tokens are added |
| V10 | OAuth and OIDC | **Partly active** | **Outbound** OAuth 2.0 client-credentials + SMART on FHIR Backend Services and a FHIR REST connector are built (ADR 0024/0043 — `transports/smart.py`/`fhir.py`). **Inbound** OAuth/OIDC (engine as OAuth resource server) remains N/A |
| V11 | Cryptography | Yes | At-rest encryption via **application-layer AES-256-GCM on PHI columns** (database-native where the backend provides it); argon2id passwords; approved algorithms; post-quantum awareness |
| V12 | Secure Communication | Yes | TLS / MLLP-over-TLS; mTLS for system-to-system |
| V13 | Configuration | Yes | Secure-by-default; secrets management; SBOM |
| V14 | Data Protection | Yes | PHI minimization, encryption, no PHI in logs |
| V15 | Secure Coding and Architecture | Yes | Threat modeling, secure design, vetted components |
| V16 | Security Logging and Error Handling | Yes | Tamper-resistant audit log; fail-closed errors; no PHI/secrets in logs |
| V17 | WebRTC | **No** | Not applicable — no WebRTC; documented exclusion |

*In scope: 14 chapters active today (V1–V8, V11–V16). V10 (OAuth/OIDC) is now **partly active** — outbound OAuth 2.0 client-credentials / SMART on FHIR are built (ADR 0024); inbound OAuth/OIDC remains N/A. V9 (JWT) is in scope when JWT is introduced — currently N/A. Documented exclusion: V17.*

### A.4 Interface authentication mechanisms

Recorded honestly against what is **built today** vs **designed-but-deferred** vs **aspirational/
planned** (§9: every claim is backed by evidence). The §7.4 hierarchy is the target; this is MEFOR's
current position on it.

**Built (in code today):**

- **System-to-system (data plane):** per-connection **HTTP Basic over TLS** and **bearer token / API
  key** (env-vaulted) on REST and SOAP **destinations**; **database** authentication via SQL login,
  **Windows Integrated (Trusted Connection)**, or **Microsoft Entra**, over an encrypted connection.
- **Outbound machine-to-service auth:** **OAuth 2.0 client-credentials** with a **signed-JWT client
  assertion** and the **SMART on FHIR Backend Services** profile (ADR 0024, `transports/smart.py`); a
  **FHIR REST connector** (`transports/fhir.py`, plus the read-only Handler `fhir_lookup` — ADR 0043);
  and **SOAP WS-Security** on the SOAP destination — `<wsse:UsernameToken>` + WS-Addressing/Timestamp
  and **XML-DSig X.509** signing over the WS-*-wrapped envelope (ADR 0015).
- **Transport TLS:** native **API HTTPS/WSS** and **MLLP-over-TLS** (TLS 1.2+, opt-in via cert config),
  with optional client-certificate **mTLS** (API `tls_client_ca_file`; MLLP `tls_ca_file`), an
  off-loopback bind guard, and a certificate-expiry monitor — ADR 0002 / WP-13a/13b.
- **Operator strong-auth (control plane):** native **RFC 6238 TOTP MFA** for **local** accounts
  (ADR 0002 WP-14, built 2026-06-17) — enrolled per user, enforced for the Administrator role via
  `[auth].require_mfa` and re-verified at the sensitive-operation step-up boundary; AD/Entra users'
  MFA is delegated to the IdP. Recovery codes are argon2id-hashed; the TOTP secret is store-cipher
  protected.
- **Operator / directory (control plane, not interface auth):** **LDAPS** directory bind
  (certificate-validated; cleartext `ldap://` refused fail-closed), **Kerberos / SPNEGO** Windows SSO,
  and **AD security-group → role** mapping for RBAC. These authenticate **human operators** to the
  console/API, not data-plane systems.

**Designed but deferred (ADR 0002 — build before off-loopback exposure):**

- **Federated SSO for operators (OAuth 2.0 / OIDC / SAML via Entra)** — gets a dedicated federated-SSO
  ADR when 0.2 design begins; today's operator directory auth is direct LDAPS bind + Kerberos SSO, not
  federation. (Native TOTP MFA, transport TLS, MLLP-over-TLS, and client-cert mTLS are all **built** —
  see above.)

**Aspirational / planned (not built, no ADR yet):**

- *None outstanding.* The items previously listed here — **OAuth 2.0 client-credentials**, **SMART on
  FHIR (Backend Services)**, and **SOAP WS-Security (UsernameToken / X.509)** — have since been **built**
  (ADR 0024 / ADR 0015; see the **Built** tier above). Inbound OAuth/OIDC with the engine as a resource
  server remains out of scope until a JWT/OIDC-bearer inbound is introduced.

> **gMSA** is a **deployment posture** (run the Windows service under a group-Managed Service Account),
> not an engine protocol — see `docs/SERVICE.md`. It is recommended, not enforced in code.

### A.5 Project-specific parameters

- **Remediation SLA windows** (RV.2) — **confirmed 2026-06-12: Critical ≤ 7 days, High ≤ 30 days,
  Medium ≤ 90 days** (Low: best-effort). Measured from triage; fixes verified before closure;
  coordinated disclosure after a fix is available. Published in [`.github/SECURITY.md`](../.github/SECURITY.md).
- **Applicable control set** — the tailored control baseline is confirmed per deployment with the
  deploying organization's security lead (the §7.1 control areas apply; deployment-specific tailoring
  is the deployer's, §2/§7.3).

### A.6 Documented deviations

Honest record of where MEFOR's *current* practice differs from the body of the standard, with the
compensating control (the standard requires exclusions/deviations be documented, §6.3).

- **Single-maintainer development (PO.2 / PW.7).** The project is solo-maintained today, so the
  standard's "every change is peer-reviewed" cannot mean a *human second reviewer*. Compensating
  controls: blocking automated review (bandit/semgrep SAST, pip-audit SCA, gitleaks), AI-assisted
  review, branch protection + required CI checks, and no direct pushes to `main`. Revisit when a
  second maintainer joins. **Detailed record:** the AI-assisted-review compensating control — and the
  full risk-tiered discipline for building with Claude Code — is operationalized in
  [`Secure_AI_Development_Standards.md`](Secure_AI_Development_Standards.md), the companion standard
  that owns and expands this deviation.
- **Independent ASVS-L3 review & DAST (§6.3 / §6.4).** Not yet performed; a **dated risk acceptance**
  is in force pre-1.0. An independent engagement is planned — it is a **$25,000–$50,000** commitment
  that the project intends to fund through a grant or sponsorship rather than licence revenue.
  MessageFoundry is **self-hosted**, so the decision to deploy it beyond loopback, and the assessment
  that justifies that decision, rest with the **implementing organization**: this standard states what
  has and has not been independently verified, and does not gate your deployment on it.
- **Federated operator SSO (§7.4).** API/WSS/MLLP **TLS and client-cert mTLS are built** (opt-in via
  cert config) and **native TOTP MFA for local accounts is built** (ADR 0002 WP-14); the remaining
  deferred operator-auth item is **federated SSO (OIDC/SAML via Entra)**, held safe by the fail-closed
  `127.0.0.1` bind guard. Federation gets a dedicated ADR before off-loopback exposure.
- **Mechanical requirement→test traceability (§5.3, recommended).** Not yet enforced: acceptance
  criteria are not uniformly ID'd and linked to tests, and the dry-run gate asserts only "didn't error"
  (R2). This is **not a deviation from a hard requirement** — §5 traceability is **recommended (SHOULD)**,
  adopted incrementally — but it is recorded here for honesty. Tracked as R1–R3 in §A.7.

**ASVS 5.0 L3 deferred items — accepted / deferred** (risk accepted **2026-06-16**, refreshed after
MFA + admin-defense landed **2026-06-17**; owner: project maintainer). Each is deferred-by-design behind
the fail-closed bind guard or off-loopback-conditional, with the compensating controls below. Detail +
build triggers: `security/ASVS-FAILS-REMEDIATION-PLAN.md`;
per-requirement verdicts: `security/ASVS-L3-ASSESSMENT.md`. Reviewed at
each release and on any trigger below. Those are maintainer-internal documents;
[`SECURITY-DOCS-POLICY.md`](SECURITY-DOCS-POLICY.md) explains what is withheld and what you can request.

- **6.3.3 — multi-factor authentication.** **Satisfied for local accounts** — native RFC 6238 TOTP MFA
  is **built** (ADR 0002 WP-14, 2026-06-17), enforced for the Administrator role via `[auth].require_mfa`
  at the step-up boundary; **AD/Entra-account MFA is delegated to the IdP** (the supported enterprise
  path). No longer a deferred Fail. *(Hardware/WebAuthn second factors are now **built** — browser
  WebAuthn passkeys as the phishing-resistant second factor at the step-up boundary, ADR 0068 / WP-14b,
  behind the `[webauthn]` extra.)*
- **4.1.5 — per-message digital signatures on the PHI data plane.** Deferred-by-design. Transport-level
  security (TLS 1.2+ floor) over a single-tenant on-prem network is the de-facto standard for HL7 v2
  interchange; per-message signing is rare in practice and reserved for partners that contractually
  require it. *Compensating controls:* TLS + trusted on-prem network, no untrusted intermediary on the
  supported model. *Build trigger:* a partner contract mandating a message-level signature, or an
  off-prem / shared-tenant / untrusted-intermediary deployment (SOAP XML-DSig per ADR 0015 §4a, or a
  detached JWS for HL7/JSON). *Design record:* [ADR 0018](adr/0018-per-message-signatures-accepted-risk.md).
- **8.4.2 — multi-layer administrative-interface defense.** **Built (2026-06-17, ADR 0002)** — WP-14 MFA
  is wired as a genuine second factor at the step-up boundary, plus a **new-client-IP contextual-risk
  signal** (`[auth].admin_new_ip_step_up`, default off) layered over deny-by-default RBAC and the
  fail-closed `127.0.0.1` bind guard. *Residual (delegated):* device-posture assessment is delegated to
  the deployment (a managed/attested host + an mTLS client cert terminated at the WP-15 reverse proxy),
  not done in-process.
- **12.1.4 — TLS certificate revocation (OCSP/CRL).** Off-loopback-conditional. *Compensating controls:*
  native API/WSS + MLLP TLS built with a pinned 1.2+ floor + a cert-expiry monitor; loopback default.
  *Build trigger:* off-loopback exposure → OCSP-must-staple / CRL, or documented delegation to the org
  PKI / TLS terminator (ADR 0002).
- **13.3.3 — key material in an HSM/vault.** Deferred-by-design. The store data key is loaded into engine
  memory for AES-256-GCM; an attacker able to read process memory already implies host compromise on a
  single-tenant box. *Compensating controls:* machine-bound DPAPI at rest, restricted service account,
  on-prem network, host volume encryption. *Build trigger:* off-prem / cloud / shared-tenant or a
  PHI-critical posture/mandate → the pluggable KeyProvider seam (KMS/Vault/HSM envelope decryption,
  BEYOND WP-BL3-04).
- **16.4.3 — off-box log / audit shipping.** Off-loopback-conditional. *Compensating controls:* the local
  `audit_log` is append-only, SHA-256 hash-chained, and read-gated; restricted host. *Build trigger:*
  off-loopback exposure → structured JSON logging + syslog/SIEM forwarding (BEYOND WP-BL3-20).

### A.7 Spec-driven development — existing stack and recommendations

MEFOR already operates the five-layer spec stack of §5; the layers exist but are not yet mechanically
connected. Recorded honestly below, with three recommended (SHOULD) improvements.

#### A.7.1 Existing spec stack (state accurately)

| Layer | MEFOR artifact | Notes | SSDF |
|---|---|---|---|
| Constitution | [`../CLAUDE.md`](../CLAUDE.md) | Always-loaded standing contract of invariants + vocabulary. | PO.1 |
| Decisions | [`adr/`](adr/) (`docs/adr/*.md`) | Build-gating lifecycle (`README.md`: Proposed = drafted, no code → Accepted = ratified, build may start → Superseded/Rejected; plus `Reserved` number-allocations and `Dropped`). **ADRs numbered through 0105; some numbers are Reserved/Dropped.** The house pattern includes Context / Decision / Options considered / Consequences / "To resolve on acceptance". | PW.1–PW.2 |
| Requirements / sequencing | [`BACKLOG.md`](BACKLOG.md) + [`FEATURE-MAP.md`](FEATURE-MAP.md) | Numbered requirement IDs (e.g. #20, #26, #34), cross-referenced by ADRs; each item names its originating review finding. | PO.1 |
| Tasks | `docs/releases/*-PLAN.md`, `docs/releases/MULTISESSION-PLAN-11.md` (current) | Decompose ADRs/backlog into per-worktree lanes, gates, per-window quartet re-check. | PW.1–PW.2 |
| Verification | `messagefoundry check` ([`../messagefoundry/checks.py`](../messagefoundry/checks.py)) + conformance reviews under `security/` | `validate` (required) + `dryrun` (required when `*.hl7` fixtures exist) + advisory ruff/mypy; reviews: `SDS-CONFORMANCE-REVIEW-*.md`, `ASVS-L3-ASSESSMENT.md`. | PW.8 (test); reviews → PW.7 |

PW.8 (test executable code) is the home of `messagefoundry check` (validate + dryrun); PW.7 (review/analyze) is the home of the conformance reviews and code review — do not collapse the two. The SDS conformance review already cites SSDF practice IDs natively (PS.2, PO.4, PW.1–PW.2), so this mapping is not a retrofit.

#### A.7.2 Recommendations (all **recommended / SHOULD**, advisory)

- **R1 — EARS "Acceptance Criteria" block on the ADR template.** Each ADR **SHOULD** carry an EARS "Acceptance Criteria" block, each criterion bearing an ID linked to its test or fixture. Doc-only, zero-code; formalizes the existing SHALL-style house register. *(Lineage: AWS Kiro requirements.md; distilled.)*
- **R2 — Make the dry-run gate executable-spec.** `messagefoundry/checks.py` **SHOULD** read an **expected disposition per fixture** (`PROCESSED` / `UNROUTED` / `FILTERED` / `ERROR`) and assert it, upgrading today's "didn't error" dry-run (`_check_dryrun` asserts only not-`ERROR`) into an executable acceptance-criteria check. **Backward-compatible:** a fixture with no declared expectation keeps today's not-`ERROR` semantics. *(Lineage: BDD / Specification-by-Example; distilled.)*
- **R3 — Promote clarify, add analyze.** The ADR **"To resolve on acceptance"** block **SHOULD** be promoted into an explicit **clarify** step (resolve ambiguity before `Accepted`), and an **analyze**-style advisory coverage check **SHOULD** verify that every **Accepted** ADR's acceptance criteria has a linked test, and that no artifact contradicts a `CLAUDE.md` invariant. **Advisory, not a hard gate** — it belongs in the advisory tier alongside `ruff`/`mypy`, not the required `validate`/`dryrun` tier. *(Lineage: GitHub Spec Kit pipeline; distilled.)*

---

## Retired rules

A retired identifier is **never reissued**. A rule is retired when *what it demands* changes; a rule
whose wording changes keeps its identifier and does not appear here. A citation that outlives its rule
resolves to a row below rather than to whatever requirement later took the number.

| Retired ID | Retired in | What it required | Why, and what replaced it |
|---|---|---|---|
| — | — | *No rule has been retired yet.* | — |

---

## Version history

| Version | Date | Change |
|---|---|---|
| 2.2 | July 30, 2026 | **Independent-review deviation reframed.** The independent ASVS-L3 review & DAST is no longer stated as a precondition for off-loopback/production exposure. MessageFoundry is self-hosted, so the deployment decision — and the assessment supporting it — belong to the implementing organization; this standard records what has and has not been independently verified rather than gating deployment on it. The engagement remains planned, at an estimated $25,000–$50,000, intended to be grant- or sponsor-funded. Also drops a dangling citation to `security/RELEASE-GATE.md`, which is not present in this repository. No change to the SSDF / ASVS / HIPAA mappings. |
| 2.1 | July 29, 2026 | **Code-quality companion added.** Cross-linked the new [Code Quality & Anti-Slop Standards](Code_Quality_Standards.md) (evidence-based anti-slop rubric, ISO/IEC 25010): a companion-standards pointer in §1 and a test-*quality* + anti-metric note at PW.8. No change to the SSDF / ASVS / HIPAA mappings or Appendix A. |
| 2.0 | June 24, 2026 | Restructured baseline around SSDF, spec-driven development, NIST SP 800-115 testing tiers and SP 800-66 Rev. 2 safeguards. Content carried forward unchanged at this baseline. The full prior changelog — MEFOR-specific drafts → genericization (project-agnostic, with an Appendix A applicability profile) → OWASP ASVS 5.0 Level 3 re-target → NIST SP 800-53 removal → §5 Spec-Driven Development addition and the §5–§9 → §6–§10 renumbering — is preserved in git history. |
