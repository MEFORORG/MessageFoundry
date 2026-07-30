# Secure Build Standards — An Evidence-Based Rubric for Judging Whether a Build Is Actually Secure

*Companion to the [Secure Development Standards](Secure_Development_Standards.md) (SDS), the [Secure AI-Assisted Development Standards](Secure_AI_Development_Standards.md) (the AI-build companion), and the [Code Quality & Anti-Slop Standards](Code_Quality_Standards.md) (the sibling outcome rubric). The SDS says what a secure build must satisfy. The AI companion says how to build it with an AI assistant. Code Quality judges whether the code is good. This document is the fourth leg: it defines how to judge whether a build is actually secure rather than security theater, using signals the evidence supports. Each project records its graded result in a separate scorecard — see the [MessageFoundry Secure Build Scorecard](Secure_Build_Scorecard_MEFOR.md) for the reference implementation.*

> **Scope boundary — read this first.** This is a measurement rubric, not the security standard itself. The standard is the SDS. This rubric does not re-derive any per-requirement finding. It grades on top of a project's existing security evidence base — its ASVS assessment, conformance review, threat model, and risk-acceptance register — which remain the single source of truth. A scorecard built from this rubric cites those; it does not re-adjudicate them or fork a second scorecard. Its value-add is a layer none of them carry: an evidence-graded, anti-scoreboard, composite letter grade. That grade separates a genuinely secure build from a well-instrumented one that only looks secure, the way [Code Quality](Code_Quality_Standards.md) sits on top of the SDS.

| | |
|---|---|
| **Document** | Secure Build Standards — Evidence-Based Rubric |
| **Applies to** | Any project developed under the SDS. Each project records its graded result in its own scorecard; MessageFoundry (MEFOR) is the reference implementation ([Secure Build Scorecard](Secure_Build_Scorecard_MEFOR.md)). |
| **Maintained by** | Project maintainers (open-source). Each deploying organization assigns its own local security owner. |
| **Status** | Draft for review |
| **Version** | 0.5 |
| **Date** | July 14, 2026 |
| **License** | Publishable under the project's open-source license; intended to be shared with adopters and reused across projects. |
| **Review cadence** | At least annually, and on any material change to the evidence base behind the rubric (new metric studies, a new framework version, a change to the enforcement model). |
| **Aligns to** | NIST SP 800-218 (SSDF) producer practices · SP 800-115 (technical security testing) · SP 800-66 Rev. 2 (HIPAA Security Rule) · OWASP ASVS 5.0 Level 3. Companion to the SDS, the [AI-build companion](Secure_AI_Development_Standards.md), and [Code Quality](Code_Quality_Standards.md). Confers no certification — NIST and OWASP issue no certificate, and a self-assessment is not one. |

---

## Executive summary

No single number certifies that a build is secure. This is the security twin of the code-quality thesis. Every scoreboard people reach for first is theater or gameable.

Take the four most common. A scanner inventory counts tools, not enforcement; advisory or cron-only jobs that never redden a pull request inflate the count without adding a gate. A zero-findings SAST/SCA run is a start condition for red-on-regression enforcement, not a certificate; zero findings on a weak ruleset proves nothing. A single ASVS %-pass headline hides the composite, especially when a rosier count rests on a non-standard "conditional Pass" verdict the canonical assessment discards. And "NIST/HIPAA/ASVS-L3 certified" phrasing describes a certificate that does not exist. Each is an anti-metric this rubric forbids gating on (§4.1).

What survives is a composite, not a count. The composite is the product of four things no single figure captures: deterministic enforcement, a written threat model, independent external verification, and evidence-backed honest claims. It plays out in three layers. First, deterministic blocking enforcement: SAST, SCA, and secret-scan gates that fail on any new finding from a clean baseline, verified in the workflow file rather than the tool list. Second, the structural controls: a written per-interface threat model, supply-chain integrity, fail-closed defaults, interface authentication with TLS everywhere, and a tamper-evident audit log. Third, the controls a scoreboard can never supply: independent external verification and evidence-backed honest claims. A green CI checkmark from a gate you ran on yourself does not substitute for an adversary who did not.

This document is a measurement rubric, not another process gate. It gives three things. Twelve signals separate a secure build from theater, split into a machine-enforced layer (signals 1–8) and a thinner process/attestation layer (9–12). An anti-metric list names what never to gate on. And a placement model maps each signal to a project's enforcement points. Each project applies the rubric and records its graded result in its own scorecard.

---

## 1. Purpose, scope, and the lens

This standard answers one question: is a build actually secure, or is it security theater? For a codebase built largely with an AI assistant across many parallel sessions, a green checkmark and a long tool inventory are cheap. A genuinely defended trust boundary is not.

It serves three audiences. Maintainers get a standing rubric to re-run each release, so the posture is re-graded rather than assumed to hold. Adopters and auditors get evidence that a build is judged against consensus frameworks and its own conformance record, not a badge. Future projects inherit the rubric and add their own scorecard.

**This is a rubric, not a re-derivation.** It sits on top of the SDS (the requirement spine) and on each project's own security evidence base — its conformance review and its ASVS assessment with a risk-acceptance register. Those documents remain the single source of truth for per-requirement verdicts. A scorecard built from this rubric cites them and does not restate them. Its value-add is the same layer [Code Quality](Code_Quality_Standards.md) adds on the SDS for the quality outcome: an evidence-graded, anti-scoreboard, composite letter grade for the security outcome. The SDS governs the process. The [AI companion](Secure_AI_Development_Standards.md) governs how the build is done with an AI assistant. This rubric governs whether the resulting build is actually defended, and whether the claims about that defense are honest.

**The lens is composite defense over scoreboards.** A single security number invites optimization of the number. A scanner count, an ASVS percent-pass, a green CI run, or a self-issued "L3 verified" each collapses a multi-dimensional posture into one gameable figure. So the verdict is composite and structural. It explicitly forbids grading security on any one row (§4.1). This mirrors the SDS discipline of writing deterministic checks and never asking the model to be secure. Here: grade the composite of enforced controls and verified claims, and never trust a scoreboard.

Two consequences are load-bearing, and the rubric surfaces both. First, built is not on-by-default is not independently verified. A control can be coded, ship off, and never have been challenged by an outside adversary. These are three states the rubric grades separately. Second, the honesty layer is itself a graded signal (§11). A rosy in-tree scorecard that survives beside the canonical verdict-of-record is a live defect, not a presentation nit, and it costs the grade.

---

## 2. The evidence — real signal vs. security theater

Read this before crediting any control.

Unlike the peer-reviewed metric-validity studies behind the [Code Quality rubric](Code_Quality_Standards.md#2-the-evidence--validated-vs-gameable-read-before-setting-any-gate), there is no body of academic studies that certifies "secure." Being honest about that is the point. The anchor here is the industry-consensus secure-build frameworks — NIST SSDF (SP 800-218) and OWASP ASVS L3 — plus the SDS discipline that NIST and OWASP issue no certificate, so every claim needs evidence and every unverified item must be named (SDS §3, §9). Consensus frameworks tell you which controls a mature build carries. The evidence discipline tells you how to prove a given build carries them. Neither issues a passing score, and this rubric never pretends otherwise.

So the discriminator is not which controls are named. It is which observable artifact indicates a defended build versus the gameable proxy that only looks like one. Each row pairs the real signal with the theater that impersonates it. A scorecard's job is to credit the real signal and grade past the proxy.

| # | Real signal | Gameable proxy / theater |
|---|---|---|
| 1 | Blocking SAST/SCA/secret-scan gates that fail on **new** findings from a clean baseline, verified in the workflow file | "N security scanners" / a long tool inventory — advisory or cron-only jobs never gate a PR |
| 2 | The canonical verdicts read as a composite (Pass / Partial / Fail, residuals owned) | A single ASVS %-pass headline, or "zero open Fails" reached via a non-standard "conditional Pass" |
| 3 | Dated, signed risk acceptances, each with a re-score-voiding trigger | "A risk-acceptance register exists" — an unsigned register is not governance |
| 4 | Encryption or hardening that is on-by-default or fail-closed, verified at the code path | A capability claim ("AES-256-GCM at rest") that says nothing about the default posture |
| 5 | Control-parity: every sibling ingress/publish path carries the control as one deterministic check | "Control X is built" on the one path that happened to be prompted |
| 6 | Independent third-party source review + penetration test + DAST | An internal "L3 verified" / self-assessment pass |
| 7 | Release-time blocking SBOM + signing + provenance at tag | "SBOM generated in CI" — an advisory CI job that never gates |
| 8 | A single canonical verdict-of-record with stale findings reconciled to current code | Whatever the most-optimistic in-tree doc says |

Read the table as a crediting rule. A control earns credit only for the real-signal cell — the enforced, verified, parity-checked, HEAD-current form — never for the proxy that shares its name. The proxies are not strawmen. Each is quotable from a real artifact: a tool count, a rosy status doc, an unsigned register, a capability claim, a green CI job. That is why the grade is a composite and why §11 grades the honesty layer directly. The theater lives inside the evidence base, so the rubric's job is to grade past it.

> **Honesty note on the anchor.** This is the load-bearing caveat for the whole rubric. The security anchor is weaker than the code-quality rubric's peer-reviewed metric studies, and this document says so. SSDF and ASVS are consensus control catalogs, not validated predictors of breach-resistance, and the SDS discipline they pair with issues no certificate. A grade from this rubric reflects control presence plus honesty posture. It does not reflect runtime efficacy or an outside adversarial challenge, because the control that would supply that — independent verification, §10 — is by definition external. Read the letter grade as directional and project-set, never as evidence-certified security.

---

## 3. Insecure-build failure modes and the control that neutralizes each

A secure-build posture rarely degrades from a missing control. It degrades from a control that reads as present but is inert, scoped to the wrong path, or attested by the same author who wrote it. AI-assisted authorship sharpens each case. A model will happily document a control it did not build, wire a guard onto the one listener it was prompted about, or add a plausible dependency that does not exist.

Each failure mode maps to a numbered signal in [§4](#4-the-rubric--the-12-signals-that-separate-a-secure-build-from-security-theater), so the failure mode and its scorecard row stay in lockstep. The AI-specific rows draw from [`Secure_AI_Development_Standards.md`](Secure_AI_Development_Standards.md) §3 and §6.

| Failure mode | Control + owner |
|---|---|
| **Doc optimism / self-certification-by-prompt** — a control documented as "implemented" before the code exists; the model attests its own output. | **Signal 11** — a claims register with the Built / designed-but-deferred / aspirational taxonomy plus per-claim evidence citations (SDS §9; AI companion §8). No claim ships without a code pointer a grader can open. |
| **Point-in-time scorecard read as current posture** — a dated snapshot quoted as if it describes HEAD. | **Signal 11** — dated snapshots, supersede notes, and a single canonical verdict-of-record. |
| **Conflicting sources of truth** — a rosier scorecard survives beside the canonical one. | **Signal 11** — reconcile to the sole verdict-of-record; retire or annotate superseded docs so only one composite can be cited. |
| **Control-parity gap** — a guard covers the prompted path and silently misses its sibling. | **Signals 3 & 6** — enumerate sibling ingress/publish paths and encode the control as one deterministic check shared across them (AI companion §3, control-asymmetry rule). |
| **Insecure code + author overconfidence under solo self-review** — the maintainer reviews their own AI-authored code and waves it through. | **Signal 3** + SDS PW.7 — blocking SAST/SCA that cannot be waived, with AI-assisted review as a compensating control, never the primary one. (Stanford CCS'23: overconfidence bites hardest when the author reviews their own model output.) |
| **Hallucinated / typosquatted dependencies (slopsquatting)** — a model suggests a plausible package that is malicious or nonexistent. | **Signal 4** — dependency and supply-chain integrity: a hash-locked lockfile, `--require-hashes` install, and a verify-before-add provenance gate (AI companion §6.4). |
| **Advisory-scanner theater — scoped-green is not the gate** — counting non-blocking jobs as coverage. | **Signal 3** — distinguish blocking from advisory jobs; the verdict rests only on blocking-from-clean-baseline gates (AI companion §3, scoped-green rule). |
| **Deferred-control drift** — an off-by-default control read as active, or (the inverse trap) a fail-closed control mis-read as inert. | **Signal 6** — a secure-default audit that scores "built" separately from "on-by-default", and "off" separately from "fail-closed". |

---

## 4. The rubric — the 12 signals that separate a secure build from security theater

Each signal is a risk, a control, and a measure. It is tagged by gate type and by the document that owns it. Gate types: deterministic (machine-checked, red-on-regression), advisory (a human arbitrates the finding), and process (an exercised program, not a file). A scorecard built from this rubric only checks that a control is present and honestly claimed. It cites the SDS and the project's conformance and ASVS evidence for per-requirement verdicts rather than re-deriving them.

The signals fall into two layers, and the split is the whole point.

**Durable layer — signals 1–8: the machine-enforced controls.** These are structural, deterministic properties enforced on every push by a scanner, a bind guard, a hash-lock, or a hash-chain. A secure posture here is hard to fake because the evidence is a green CI leg, not a claim. This layer carries most of the weight.

| # | Signal | What "good" looks like | Gate type | Owner |
|---|---|---|---|---|
| 1 | **Per-interface threat model & secure design** (SSDF PW.1–2 / ASVS V15) | A written per-interface STRIDE-lite threat model enumerating every trust boundary, reviewed before build. Each ingress has a named mitigation; each dangerous-functionality and third-party-component item has a constraining control. | Advisory + artifact-checked | SDS PW.1–2 |
| 2 | **Secure coding practices enforced** (PW.5 / ASVS V1,V2,V5) | Structure and content input validation at every ingress; parameterized SQL only (no string-built SQL); path confinement with traversal/symlink rejection; XXE/DTD disabled; vetted crypto; no custom crypto. | Deterministic | SDS PW.5 |
| 3 | **Blocking security gates in CI, red-on-regression** (PW.7, PO.4 / ASVS V14) | SAST/SCA/secret-scan gates that block from a clean baseline and fail on any new finding. Not advisory, `continue-on-error`, or cron-only. Blocking and advisory jobs are distinguished, and only the blocking set carries the verdict. | Deterministic | SDS PW.7 / [AI companion](Secure_AI_Development_Standards.md) (checked here) |
| 4 | **Dependency & supply-chain integrity** (PS.2, PW.4, RV.1 / ASVS V15) | Hash-locked lockfile with in-sync enforcement and `--require-hashes` install; verify-before-add provenance gate; SBOM + signing + build-provenance at release; automated CVE surveillance with fast-response SLAs. | Deterministic | SDS PS.2/PW.4 + [AI companion §6.4](Secure_AI_Development_Standards.md) |
| 5 | **Secrets hygiene** (PW.5 / ASVS V13,V16) | No secrets, keys, or PHI in code or full git history; fail-closed secret-scan and forbidden-content scan pre-commit and in CI, shared as one source of truth across publish/pre-commit/CI; deny-list on secret/key/db reads. | Deterministic | SDS PW.5 |
| 6 | **Secure-by-default, fail-closed configuration** (PW.9 / ASVS V13) | TLS/encryption/least-privilege on by default; any insecure posture is an explicit, named, audited opt-in behind a fail-closed guard; off-by-default controls do not read as active. | Deterministic | SDS PW.9 |
| 7 | **Interface & transport authentication** (SDS §7.4 / ASVS V6,V9,V10,V12) | Strongest per-connection mechanism the partner supports (mTLS / OAuth2 client-credentials / SMART Backend Services / WS-Security); TLS everywhere (no cleartext sensitive transport); credentials vaulted, per-connection least-privilege. | Deterministic + advisory | SDS §7.4 |
| 8 | **Audit & tamper-evident logging** (PW.5 / ASVS V16) | Append-only, timestamped, user-attributed audit log with a hash chain; no PHI or secrets at INFO+; off-box forwarding available over TLS when exposed. | Deterministic | SDS PW.5 / ASVS V16 |

**Process / attestation / verification layer — signals 9–12: the thinner, harder-to-automate half.** These are exercised programs, independent challenges, and honest bookkeeping: vulnerability response run end-to-end, an external adversary, a single canonical verdict-of-record, and a release gate that does not lean on an unsigned acceptance. A control here cannot be discharged by a passing scanner. It needs a rehearsal, a signature, or an outside party. This is where the defects a scorecard exists to catch tend to concentrate.

| # | Signal | What "good" looks like | Gate type | Owner |
|---|---|---|---|---|
| 9 | **Vulnerability response & disclosure** (RV.1–3) | Defined private intake channel; triaged remediation SLA windows (Crit/High/Med) clocked from upstream-fix; RCA process; coordinated disclosure; the SLA machinery exercised end-to-end (tabletop/dry-run), not just written. | Process | SDS §4.4/§8 |
| 10 | **Independent external verification** (SDS §6.3 / ASVS L3) | Third-party source review + penetration test + DAST before production or off-loopback. Where deferred, a dated, signed risk acceptance is in force with a re-score trigger. | Process | SDS §6.3 |
| 11 | **Evidence & attestation honesty** (SDS §9) | A claims register with a Built / designed-but-deferred / aspirational taxonomy; documented ASVS exclusions; a single canonical verdict-of-record with no conflicting in-tree scorecards; no "certified" phrasing; stale findings reconciled to current code. | Advisory | SDS §9 / [AI companion §8](Secure_AI_Development_Standards.md) |
| 12 | **Release-gate integrity** (SDS §6.4) | Codified pass/fail gate: no unresolved high/critical, current independent-review status or a signed risk acceptance, updated evidence and a signed/SBOM'd tag; the gate does not lean on an unsigned acceptance. | Deterministic + advisory | SDS §6.4 |

> **The composite certifies "secure-enough," never a single row.** The verdict is the composite defined in the Executive summary. A perfect durable layer with no external challenge (signal 10) and conflicting in-tree scorecards (signal 11) is not an A. The process layer is not optional weight. No green scanner count, ASVS %-pass, or self-assessment substitutes for the rows a solo project finds hardest to supply. This is the security-side analogue of the [Code Quality rubric's](Code_Quality_Standards.md) "structure over scoreboards."

### 4.1 The anti-metric rule (hard)

Do not certify a build as secure, or pass a release, on any single one of these. Each is a badge that looks like security and is not.

- **Number of security scanners** is a badge count. Advisory or cron-only jobs never gate a PR. Count coverage by blocking jobs run on the PR, not by tool inventory.
- **SAST/SCA finding-count hitting zero** is a start condition, not a certificate. A clean baseline sets up red-on-regression enforcement. Zero findings on a weak ruleset proves nothing.
- **A single ASVS %-pass number** hides the composite, especially when a rosier count rests on a non-standard "conditional Pass" the canonical assessment discards. A pass-rate hides the Partial and Fail verdicts-of-record.
- **"NIST certified" / "HIPAA certified" / "ASVS L3 certified" phrasing** describes a certificate that does not exist. NIST and OWASP issue none, and a self-assessment is not a certification. Use "built to", "aligned", or "self-assessed against", backed by evidence.
- **Count of controls or ADRs marked "Built"** conflates states. Built is not on-by-default is not fail-closed is not independently verified. A control can ship disabled, and a control read as "off" may actually be fail-closed. Score these as distinct states.
- **A green CI checkmark or passing self-assessment alone** is one input, not the verdict. The verdict is the composite. No self-run gate substitutes for the missing external review.
- **"A risk register exists" as a checkbox** is not governance. Only dated, signed acceptances are. An unsigned acceptance is an un-accepted open gap.

These may be surfaced as advisory context. They must never be the pass/fail decision. This mirrors the SDS rule that gates are deterministic checks and you never ask the model to be secure. Here: a scoreboard is never the verdict.

### 4.2 No validated single threshold (honest)

There is no validated single-metric threshold for "secure." Neither NIST SSDF nor OWASP ASVS supplies a numeric cutoff — a blocking-scanner count, an ASVS pass-rate, an MTTR floor — that certifies a build safe. Each is directional at best and gameable at worst (§4.1).

The composite letter grade a project records is therefore project-set and directional, not evidence-certified. It is the security-side analogue of the SDS's "NIST issues no certificate" and the [Code Quality rubric's §4.2](Code_Quality_Standards.md). Where a scorecard names a target such as an SLA window or a "zero unresolved high/critical" release bar, it is a project-chosen line reviewed as evidence accumulates. It is never a universal constant, and never sufficient on its own to gate a release. No single row of the rubric is a release gate; only the composite is.

---

## 5. Placement (local vs CI)

Every signal is owned by the SDS, the [AI-build companion](Secure_AI_Development_Standards.md), or a project's ASVS assessment. A scorecard records where each control actually fires across a project's enforcement points. Most projects have three: a **pre-commit hook** (local, fast feedback), a **local + CI check command**, and **CI** (the authoritative gate) — the same three the AI companion and the [Code Quality rubric §5](Code_Quality_Standards.md) name.

Two distinctions keep a placement table honest.

- **Mechanism vs. point.** A control can be present without being enforced at a PR-time gate. A runtime fail-closed guard (signal 6) or a release-time job (signal 12) is enforced, just not at any PR-time point. A placement table separates the enforcement *mechanism* from the enforcement *point*.
- **Which points are authoritative.** The durable-layer verdict rests only on the blocking CI gates and the tag-time release gate — the points where a regression turns the tree red from a clean baseline. Runtime and process controls (signals 6–11) are carried by dated artifacts and the scorecard, not a checkmark. Signal 10 is enforced at no PR-time point at all; it is held only by the release-gate trigger and a signed risk acceptance, which is why it caps the composite grade.

Per the anti-metric rule, a green CI run is one input to the verdict, never the verdict. A project's filled-in placement table — mapping each signal to its pre-commit / check / CI points and its Built/deferred taxonomy — lives in that project's scorecard.

---

## 6. How this maps to the companion standards

A scorecard built from this rubric does not restate a single per-requirement verdict. Each signal points at the SSDF practice, ASVS chapter, and AI-companion section that own it. The Ownership column marks whether the control is owned-elsewhere-and-checked-here (the scorecard verifies presence and honesty and folds it into the composite) or new-here (the evidence-graded, anti-scoreboard layer this rubric adds, as [Code Quality §6](Code_Quality_Standards.md) adds its measurement gates on top of the SDS).

| # | Rubric signal | SDS practice (SSDF) | ASVS chapter | AI-companion anchor | Ownership |
|---|---|---|---|---|---|
| 1 | Threat model & secure design | PW.1–PW.2 | V15 (V1 architecture) | §6.5–6.6 | Owned there; checked here |
| 2 | Secure coding practices | PW.5 | V1, V2, V5 | §6.5 | Owned there; checked here |
| 3 | Blocking security gates in CI | PW.7, PO.4 | V14 | §6.5 (gates are deterministic checks) | Owned there; verdict-anchored here |
| 4 | Dependency & supply-chain integrity | PS.2, PW.4, RV.1 | V15 | §6.4 / §9 | Owned there; checked here |
| 5 | Secrets hygiene | PW.5 | V13, V16 | §9 | Owned there; checked here |
| 6 | Secure-by-default configuration | PW.9 | V13 | §5 (fail-closed defaults) | Owned there; checked here |
| 7 | Interface & transport authentication | SDS §7.4 | V6, V9, V10, V12 | — | Owned by SDS §7.4; checked here |
| 8 | Audit & tamper-evident logging | PW.5 | V16 | — | Owned there; checked here |
| 9 | Vulnerability response & disclosure | RV.1–RV.3 (§4.4/§8) | (process — no ASVS row) | — | Owned by SDS; checked here |
| 10 | Independent external verification | SDS §6.3 | ASVS L3 verification mandate | — | Owned by SDS §6.3; surfaced here as the capping gap |
| 11 | Evidence & attestation honesty | SDS §9 | (ASVS exclusions V3/V17) | §8 / §9 (tooling-honesty register) | New — this rubric (the anti-scoreboard layer) |
| 12 | Release-gate integrity | SDS §6.4 | — | §9 | Owned there; checked here |
| — | The composite letter grade + anti-metric rule (§4.1) | — | — | Analogue of AI companion §5 and [Code Quality §4.1](Code_Quality_Standards.md) | New — this rubric |

**Reading the Ownership column.** Ten of the twelve signals are owned-elsewhere-and-checked-here. The SDS and the ASVS assessment carry the requirement and the verdict-of-record; a scorecard only confirms the control is present, grades its evidence honesty, and folds it into a composite. It does not fork a second source of truth; if those docs update, re-grade.

Two things are new here. Signal 11 is the claims-register and single-verdict-of-record discipline the rubric exists to enforce — it is what catches conflicting scorecards and an unsigned register. The composite letter grade itself is the other, which no companion issues. That new layer is the entire value-add. It is deliberately directional and project-set, not evidence-certified — the same posture the SDS takes toward "NIST issues no certificate" and [Code Quality §4.2](Code_Quality_Standards.md) takes toward its single-threshold caveat. Never gate a release on any single row of this map; the release gate (signal 12) reads the composite, not one cell.

---

## 7. Evidence caveats (carry these into every use)

1. **The frameworks this rubric rides on are consensus practice, not empirical breach-predictors.** NIST SP 800-218 (SSDF), SP 800-115, SP 800-66 Rev. 2, and OWASP ASVS 5.0 are expert-consensus catalogs of what ought to reduce risk. None is a validated statistical model that predicts incidents from a score. A high conformance count means the recognized controls are present and honestly evidenced, not that a given deployment will not be breached. Grade control presence and honesty, never runtime efficacy.

2. **A scorecard is layered on existing sources of truth; it does not re-derive them.** Every row cites the SDS and the project's conformance and ASVS evidence. It adds the evidence-graded, anti-scoreboard, composite-grade layer and nothing else, as [`Code_Quality_Standards.md`](Code_Quality_Standards.md) sits on the SDS. If those docs update, re-grade. Do not treat a scorecard as an independent second verdict.

3. **A self-assessment carries real but bounded weight.** When the underlying ASVS result is an AI-assisted, point-in-time self-assessment, it is the assessor evaluating their own — often AI-authored — code, the exact configuration the Stanford CCS'23 overconfidence finding warns about. Until an external engagement lands (signal 10), read every grade as self-attested, and hold the deferral open under a dated, signed risk acceptance. An unsigned register would be an un-accepted gap, not governance.

4. **ASVS %-pass is not a validated threshold, and the rosiest in-tree number is not the verdict-of-record.** There is no evidence-certified pass-rate at which software becomes "secure." The composite letter grade is directional and project-set (§4.2). Grade off the canonical assessment, not a superseded status doc reached via a "conditional Pass" the canonical doc discards. Never gate a release on any single row.

5. **"No unresolved high/critical" is only as honest as the scanner baselines behind it.** The release-gate claim rests on blocking jobs firing red-on-regression from a clean baseline. It says nothing if the baseline was set on a weak ruleset, or if advisory `continue-on-error`/cron-only jobs are miscounted as gating coverage. Verify enforcement by the blocking job list in the workflow file, not by tool inventory or a green checkmark.

6. **AI-failure-mode evidence is model-era-specific; re-baseline periodically.** The overconfidence and package-hallucination findings that motivate signals 3–5 skew to 2022–2023-era models; frontier models plausibly behave differently. The controls stay valid regardless. The magnitude of the threat they answer should be re-checked, not quoted as fixed.

7. **A wrongly-pessimistic grade is as much a defect as a wrongly-optimistic one.** The rubric grades past optimistic theater, but it must also grade past pessimistic mis-reads — a control scored "off" that is actually fail-closed, a Fail that is stale against HEAD. Re-verify against the current code before crediting or docking a signal.

---

## 8. References

**Framework spine (consensus standards — see caveat §7.1):**
- NIST SP 800-218 — *Secure Software Development Framework (SSDF) v1.1* (PO/PS/PW/RV practices; the requirement spine).
- NIST SP 800-115 — *Technical Guide to Information Security Testing and Assessment* (independent review + pentest methodology; signal 10).
- NIST SP 800-66 Rev. 2 — *Implementing the HIPAA Security Rule* (safeguard mapping for PHI deployments).
- OWASP ASVS v5.0.0 (May 2025), Level 3 — the application/API verification standard a project's assessment is scoped to.

**The parent standards this rubric mirrors and extends:**
- **Secure Development Standards** — the requirement spine (§4 SSDF, §5 spec-driven, §6 testing + ASVS L3, §7 controls/HIPAA + §7.4 interface auth, §9 evidence).
- [**Secure AI-Assisted Development Standards**](Secure_AI_Development_Standards.md) — the AI-build companion (blocking gates §6.4, supply-chain integrity, evidence honesty §8).
- [**Code Quality & Anti-Slop Standards**](Code_Quality_Standards.md) — the sibling outcome rubric whose structure and voice this document mirrors.

**Per-project scorecards** apply this rubric and cite their own security evidence base (ASVS assessment, conformance review, threat model, risk-acceptance register) and enforcement artifacts. The reference implementation is the [**MessageFoundry Secure Build Scorecard**](Secure_Build_Scorecard_MEFOR.md).

---

## Version history

| Version | Date | Notes |
| --- | --- | --- |
| 0.5 | July 14, 2026 | **Split into a reusable standard + a per-project scorecard.** This document is now the project-agnostic rubric; MEFOR's graded result moved to the separate [Secure Build Scorecard](Secure_Build_Scorecard_MEFOR.md). All MEFOR-specific content (the placement table, evidence citations, verdict, ranked gaps, grade history) lives there. No change to the twelve signals, the anti-metric rule, or the companion mapping. |
| 0.1–0.4 | July 14, 2026 | Developed as a single combined document (rubric + MEFOR scorecard). Full history is retained in the [Secure Build Scorecard](Secure_Build_Scorecard_MEFOR.md) version table, which carried the B+ → A- grade progression. |
