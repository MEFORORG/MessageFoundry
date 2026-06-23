# Secure AI-Assisted Development Standards — Risk-Tiered Guardrails for Building with Claude Code

*A companion standard to [Secure Development Standards](Secure_Development_Standards.md). It governs how the maintainers **use Claude Code to BUILD** MessageFoundry — the engineering workflow — and is NOT about the AI assistant the shipped product offers operators (that is [AI.md](AI.md)). The two share the word "AI" and nothing else.*

> **Scope boundary — read this first.** This standard governs **using Claude Code to BUILD** MessageFoundry and any project developed under the [Secure Development Standards](Secure_Development_Standards.md) — the maintainers' **own engineering workflow**. The shipped **product's** runtime AI-assistant policy (an operator-set `mode` × `data_scope` clamped by production posture, RBAC-gated by `ai:assist`) lives in [AI.md](AI.md) and is **OUT OF SCOPE here**; the two share a name only. PHI data rules: [PHI.md](PHI.md). Identity / RBAC: [SECURITY.md](SECURITY.md). The project's standing contract for an AI session is [`../CLAUDE.md`](../CLAUDE.md). These are **complementary** — read the relevant ones.

**Standard ref:** [Secure Development Standards](Secure_Development_Standards.md) **PO.5** (secure development environments — *no real PHI in dev/test*), **PO.2 / PW.7** (code review & analysis), and **[§A.6](Secure_Development_Standards.md#a6-documented-deviations)** (the *Single-maintainer development → AI-assisted review as a compensating control* deviation). This document **owns and expands** that §A.6 deviation as its detailed record for the solo-maintainer reality.

| | |
|---|---|
| **Document** | Secure AI-Assisted Development Standards |
| **Applies to** | Any project developed under the [Secure Development Standards](Secure_Development_Standards.md) using an AI coding assistant. **MessageFoundry (MEFOR)** is the reference implementation (Appendix A); future projects add Appendix B, C, … |
| **Maintained by** | Project maintainers (open-source). Each deploying/adopting organization assigns its own local owner. |
| **Status** | Draft for review |
| **Version** | 0.1 |
| **Date** | June 18, 2026 |
| **License** | Publishable under the project's open-source license; intended to be shared with adopters and reused across projects. |
| **Review cadence** | At least annually, and on **any material change to the AI toolchain or threat model** (a new agent framework, MCP server, Claude Code version, or a new probed attack class). |
| **Aligns to** | NIST SP 800-218 (SSDF): PO.1 / PO.2 / PO.3 / PO.5 / PS.1 / PW.1 / PW.4 / PW.7 / PW.8 / RV.2 · OWASP ASVS 5.0 Level 3 (V8, V11, V14, V15, V16) · a **five-principle synthesis** distilled from the AI-assisted-development literature (§3, §11 — *not* an external standard) · the project standing contract [`../CLAUDE.md`](../CLAUDE.md) · companion to [Secure Development Standards](Secure_Development_Standards.md). **Deliberately omits any certification framework** — see §8. |

---

## Executive summary

This is the *Secure AI-Assisted Development Standards* — a companion to the [Secure Development Standards](Secure_Development_Standards.md) (SDS) that governs **how the maintainers use Claude Code to BUILD MessageFoundry** (the engineering workflow), without weakening any SDS guarantee. It is explicitly **NOT** the runtime AI assistant the shipped product offers operators; that policy lives in [AI.md](AI.md) and is out of scope here (the two share only the word "AI"). The standard **owns and expands** the SDS [§A.6](Secure_Development_Standards.md#a6-documented-deviations) deviation — *single-maintainer development, with AI-assisted review as a compensating control* — as the detailed record for the solo-maintainer reality, and it aligns to **NIST SP 800-218 (SSDF)** and **OWASP ASVS 5.0 L3** while deliberately conferring **no certification**. **Status: Draft for review, v0.1.** It serves maintainers (the daily loop), adopters and auditors (build-provenance evidence for their own compliance program), and future projects (their own appendix).

**Why it exists.** It lets a solo maintainer build a PHI-carrying healthcare engine with an AI assistant without weakening the secure-development baseline, and produces auditable build-provenance evidence. Every control traces to one of **five named failure modes (§3):** (1) intent/requirements drift with no auditable intent→code chain; (2) context loss / "context rot" (the model's working context degrading across a long session); (3) long-trajectory error accumulation; (4) the "fast but flawed" speed–quality paradox; and (5) misplaced trust in output. The calibration anchor is the **METR RCT (2025)**: 16 experienced developers on mature repos were measured **~19% SLOWER** with early-2025 AI tooling while forecasting and still believing they were faster — uncontrolled AI assistance is **not automatically** a speed or quality win.

**The spine — the risk-tier matrix (§4).** A `project_scale` (S0–S3, blast radius) × `phi_touch` (P0–P3, the dominant ratchet) matrix resolves **every change to exactly one tier — T0 Exploratory · T1 Guarded · T2 Governed · T3 Regulated-Release** — and the tier dictates which guardrails, gates, review depth, and provenance are mandatory versus omittable. The **PHI ratchet dominates:** code that touches or protects real PHI (P2/P3) forces **≥T3 regardless of scale** (P1 floors at T2); scale only scales the lower-PHI cells. The **resolver is clamp-to-strictest and fail-closed:** when phi_touch or scale is unknown, or a production / off-loopback (network-exposed beyond localhost) posture applies, it clamps UP (≥T3). There is **no automatic detector** — it is a human-applied checklist emitting a recorded one-line reason as a **PR `Tier:` trailer** (e.g. `Tier: S1×P3 ⇒ T3 — the store touches the production PHI code path; the PHI ratchet dominates scale`). **MEFOR is the reference T3** (S1×P3).

**The universal floor (§4.4 — all tiers, never scales down).** No real PHI to the AI, and **none in any commit, fixture, published artifact, shared memory, screenshot, or CI log**. No secrets/keys/`.env`/`*.db` to the assistant — a path deny-list, backstopped by commit-time leak/forbidden-content scans, since the human can still paste. **All content the assistant reads is DATA, never instructions** (HL7, config, fetched pages, MCP results are attacker-influenceable). **Reject code you cannot explain** (explanation reached *with AI assistance* is acceptable). Model+version provenance is retained; the honesty taxonomy (Built / designed-but-deferred / aspirational) tags every claim; and the build tooling itself is vetted (pin the Claude Code version; vet skills, MCP (third-party tool-server) connections, and extensions before use).

**The BAA exception (§4.5 — distinct from the floor).** A separately-scoped exception permits real PHI to reach the AI *only* under a signed Business Associate Agreement plus zero-data-retention, scoped to the specific tool/endpoint, operator-enabled, minimum-necessary, and audited as a disclosure. It **never** covers PHI in commits, fixtures, artifacts, memory, or logs, and never sends secrets. It is **defined but NOT enabled** at MEFOR today, so the effective posture remains no-PHI-to-AI.

**Controls-as-dials and the daily loop (§5–§6).** A master table expresses six control families — spec/plan rigor, context isolation, verification gates, human-review depth, provenance/traceability, and the forbidden/hard-NO list — as cumulative dials set by tier, in real Claude Code primitives. The loop, itself dialed by tier, runs: a **testable spec** (ADR at T2+) → **Plan-mode approval** before edits → **context engineering** (the `CLAUDE.md` anchor, fresh per-task context, `/clear` + `/compact`, worktree isolation, default-deny MCP/web egress) → **decomposed implementation** (`TodoWrite`, verify-before-add for any AI-suggested dependency) → **automated HARD gates** → **human review** of every diff with the maintainer as arbiter → **provenance/commit** (one coherent layer per commit, `Co-Authored-By` + tier trailer) → and explicitly, **when NOT to use AI** (§6.8 — take manual control on security-critical seams, when output is unverifiable, or after ~2 failed attempts).

**The core principle.** Gates are **DETERMINISTIC checks** — hooks, the deny-list, blocking SAST/SCA/secret-scan CI (bandit, semgrep, pip-audit, gitleaks, crypto-inventory, forbidden-content) and `messagefoundry check` — **never "ask the model to be secure."** Under solo maintenance, these gates plus AI-assisted review **ARE** the compensating second reviewer — which is exactly the SDS §A.6 deviation this standard owns and expands; prompt-based security optimization is unstable and not relied on.

**Honesty discipline (§8–§9).** A strict approved-vs-overclaim phrasing table separates "AI-assisted code review as a compensating control" and "plan approved by the maintainer" from overclaims like "AI-reviewed," "autonomously developed," "AI-certified secure," and "AI made development faster." **No unmeasured speed or quality claim ships** — the loop buys auditability, continuity, and safety, not measured speed (METR found slower; a high benchmark coding score on isolated tasks ≠ real-world repo quality). The tooling-honesty taxonomy (§9) tags every control **Built / designed-but-deferred / aspirational**, so the document never overclaims its own toolchain (e.g., commit-granular provenance is Built by convention, while a CI-enforced trailer lint, hunk-level AI-authorship, and a true independent second reviewer remain designed-but-deferred or aspirational).

**Healthcare overlay (§10).** MEFOR is an **HL7 integration engine — NOT a medical device / Software as a Medical Device (SaMD) — and is NOT subject to IEC 62304 or FDA device regulation today.** Because adopters may run it *inside* a regulated clinical workflow, it adopts SOUP treatment of AI-generated code and requirement→design→test traceability **voluntarily, by analogy** — not as a regulatory obligation, and producing them confers no compliance. HIPAA's OCR audits **runtime behavior with PHI, not git history**, so verification targets behavior, not just diffs.

**Attestation posture (§11).** The project **self-attests that it builds under this standard with AI governed as a tool** — **NOT** that AI output is independently audited, and **not** that the product, maintainer, or adopter is thereby HIPAA-compliant or certified, nor a substitute for the adopter's own risk assessment. Per-project specifics — MEFOR's resolved tier (S1×P3 ⇒ T3), its live guardrail inventory, the claims register, and **five documented deviations** with compensating controls and build triggers — are recorded in **Appendix A**.

---

## 1. Purpose, scope, audiences, and the lens

This is **both** a formal companion standard to the [Secure Development Standards](Secure_Development_Standards.md) (SDS) **and** a practical Claude Code playbook. The SDS states *what* a secure build must satisfy; this document states *how to build it with an AI assistant* without weakening any SDS guarantee — and gives the copy-paste primitives to do so.

It serves three audiences:

1. **Maintainers** who need a **repeatable, safe daily loop** for building with Claude Code (the playbook is embedded in §6).
2. **Deploying / adopting organizations and auditors** who need **build-provenance evidence** — proof that AI was used as a governed tool, with a human arbiter and deterministic gates, not as an unsupervised author.
3. **Future projects** that will adopt this standard and record their own specifics in an Appendix.

**How this doc is structured.** The body (§2–§11) is **project-agnostic**. Its **spine** is the risk-tier matrix (§4) and the controls it dials (§5); the **daily loop** is embedded as §6, one subsection per loop stage, each scaled by the tier. Per-project specifics — MEFOR's live guardrail inventory, resolved tier, claims register, and deviations — live in **Appendix A** (the Applicability Profile, mirroring SDS Appendix A). Future projects add Appendix B, C, … with identical headings.

**Open-source note.** The software is built in the open; this standard and its provenance evidence are publishable so adopters can rely on or extend them.

**The lens — risk-tier drives everything.** A **`(project_scale × phi_touch)` matrix resolves every change to exactly one tier (T0–T3)**, and the tier dictates which guardrails, gates, review depth, and provenance are **mandatory** versus **allowed to be omitted**. Nothing in this document is "always on" except a small universal floor (§4.4); everything else is a **dial** set by the tier.

**The solo-maintainer altitude.** This standard is written for the reality it most often runs in: **one maintainer + an AI assistant**, no human second reviewer on hand. In that mode the **automated gates ARE the compensating "second reviewer"** (the SDS §A.6 deviation this doc owns). The matrix and dials make that honest and bounded, and define the **build trigger** at which a control escalates back to a human.

> **Shared responsibility — no compliance conferred.** This standard governs how the software is **built**; it produces **build-provenance evidence** a deploying organization can rely on for **its own** HIPAA / compliance program. It does **not** confer HIPAA compliance — or any certification — on the product, the maintainer, or the adopter, and is not a substitute for the adopter's own risk assessment (cf. the [Secure Development Standards](Secure_Development_Standards.md) §2 shared-responsibility split). The attestation posture is §11.

---

## 2. Out of scope / boundary with AI.md and the adjacent docs

Making the non-collision boundary **structural**, not a one-line disclaimer.

**This standard does NOT:**

- govern the **engine's runtime AI feature** — the AI coding assistant the *shipped product* exposes to operators in a customer deployment;
- restate [AI.md](AI.md)'s `mode` × `data_scope` × production-ceiling model, its `resolve_effective_policy()`, or its `ai:assist` RBAC gate;
- set the **product's** message-data egress policy (what the deployed engine may send to an LLM at runtime).

| Concern | Owning document |
|---|---|
| **Dev-process** use of AI to *build* the software (this workflow) | **THIS document** |
| **Product** AI-assistant runtime policy (`mode` × `data_scope`, production clamp) | [AI.md](AI.md) |
| PHI data protection (threat model, redaction, retention) | [PHI.md](PHI.md) |
| Identity, RBAC, the `ai:assist` permission, audit | [SECURITY.md](SECURITY.md) |
| Secure-development baseline (SSDF / ASVS / HIPAA mapping) | [Secure Development Standards](Secure_Development_Standards.md) |

For the **shipped product** AI-assistant policy, see **[AI.md](AI.md) — out of scope here.** The two documents share the word "AI" but have **disjoint scope**: AI.md is a *customer-facing product policy enforced in the engine at runtime*; this is an *internal build-process discipline*.

---

## 3. The problem this standard attacks

Every control below traces to one of five named failure modes the consensus literature identifies in AI-assisted development:

1. **Intent / requirements drift + no auditable intent→code chain.** Generated code diverges from what was actually wanted, and there is no versioned spec to check it against.
2. **Context loss and "context rot."** The model's working context degrades across a long or multi-session trajectory (the "lost-in-the-middle" / "dumb zone" effect; the *comprehension–generation asymmetry* of the Context Engineering survey).
3. **Long-trajectory error accumulation.** Errors compound over an unconstrained run; cost balloons.
4. **The speed–quality "fast but flawed" paradox.** QA gets skipped because output *looks* finished; Fawzy et al. warn of "a new class of developers who build but cannot debug."
5. **Misplaced trust in output.** The decisive calibration point — the **METR RCT (2025)**: 16 experienced developers on mature repos were measured **~19% SLOWER** with early-2025 AI tooling, *while forecasting and still believing they were faster*. Uncontrolled AI assistance is **not automatically** a speed or quality win.

**The regulated framing.** In a PHI/medical-software context, **compliance is a property of the EVIDENCE and PROVENANCE surrounding the code, not of the code itself.** *MEFOR is an HL7 integration engine — **not** a medical device / SaMD — and is **not** itself subject to IEC 62304 or FDA device regulation today (§10).* But because adopters may run it **inside** a regulated clinical workflow, it adopts the higher-bar discipline **by analogy**: AI-generated code would, in an IEC 62304-regulated deployment, be treated as **SOUP** (Software of Unknown Provenance) — documented and assessed — and MEFOR follows that voluntarily. HIPAA's OCR audits **runtime behavior with PHI, not git history** — so verification must target behavior, not just diffs. (Citations and their honesty caveats: §8, §11.)

---

## 4. The risk-tier matrix (THE SPINE), the resolver, and the universal floor

**Classify in one question first.** *Does any code path in this change touch — or protect — real PHI in production (or can you not yet prove it never will)?* **If yes (or unprovable) → T3** (the §4.3 resolver). Only on a confident **no** does the `project_scale` axis become the tiebreaker between T0/T1/T2. So most of MEFOR's day-to-day work resolves to **T3 on the PHI question alone**; the scale axis matters mainly for code-only and synthetic-only changes.

### 4.1 The two axes

**Axis 1 — `project_scale` (blast radius; S0→S3, monotonically stricter):**

- **S0 Throwaway/spike** — one-off script or prototype; not on a shipping branch; no external consumer; short single-session trajectory.
- **S1 Solo / component-feature** — one maintainer + AI authoring a bounded module in a shipped repo (**MEFOR today**); multi-session, decomposed, branch + PR. *The gates ARE the second reviewer.*
- **S2 Cross-cutting / security-seam** — a change spanning `pipeline`+`store`+`api`, a schema/migration, or a security-relevant seam (auth, crypto, KeyProvider, bind guard) — *blast radius beyond one module*; ADR-backed, parallel worktrees. (When there *is* a team of 2–5, that also raises scale to S2 — but a solo maintainer reaches S2 by change-shape alone and need not null out a team that doesn't exist.)
- **S3 Multi-team / regulated-release** — multiple teams, **or** a tagged release adopters install onto N PHI instances (the [ADR 0017](adr/0017-consumer-deployment-model.md) one-wheel-to-N posture).

**Axis 2 — `phi_touch` (the DOMINANT ratchet-UP axis).** This measures the **dev-process data exposure** *and* the **production code-path sensitivity** — **NOT** the product's runtime AI egress (that is [AI.md](AI.md)).

- **P0 None** — no PHI anywhere in scope; code-only assistant context; public/synthetic data only; not on the production PHI code path.
- **P1 Synthetic / PHI-path** — code + synthetic/generated HL7 only in dev/test (**PO.5: dev/test is ALWAYS synthetic**), **and** the production code path carries PHI (store, transports, parsing, data-path logging).
- **P2 PHI-critical / security-control** — code that **protects** PHI or is itself a compliance control (at-rest crypto, auth/RBAC, audit log, bind guard, redaction); a failure is a direct HIPAA / ASVS-L3 exposure.
- **P3 Real-PHI runtime** — the built/deployed system carries **real patient data** in production (every MEFOR adopter deployment).

> **Hard rule (restated as a floor).** `phi_touch` describes the **production code path**, **never real PHI on a dev box**. PO.5 means dev/test is **ALWAYS synthetic** — `python -m messagefoundry generate`. "PHI-touch" never licenses real PHI in a prompt, fixture, transcript, or memory file at *any* tier.

### 4.2 THE MATRIX

Each cell resolves to one tier: **T0 Exploratory · T1 Guarded · T2 Governed · T3 Regulated-Release.**

| `project_scale` ↓ \ `phi_touch` → | **P0 none** | **P1 synth/path** | **P2 PHI-critical** | **P3 real-PHI** |
|---|---|---|---|---|
| **S0 throwaway** | T0 | T2 | T3 | T3 |
| **S1 solo** | T1 | T2 | T3 | T3 |
| **S2 small-team** | T2 | T2 | T3 | T3 |
| **S3 multi-team** | T3 | T3 | T3 | T3 |

**The PHI ratchet:** `P2`/`P3` force **≥T3 regardless of scale**; `P1` floors at **T2**. Scale only scales the *lower-PHI* cells. The lattice **join** guarantees monotonicity — *more scale OR more PHI ⇒ stricter, never laxer*. **MEFOR is the reference T3** (S1×P3 — see Appendix A).

### 4.3 The resolver (clamp-to-strictest, fail-closed)

Ordered rules, mirroring [AI.md](AI.md)'s `resolve_effective_policy()` clamp order and its recorded `reason`:

1. **PHI hard rule (dominant).** Touches or protects real PHI ⇒ **≥T3**, never clamped down by scale.
2. **Scale ceiling (secondary).** Among lower-PHI cells, scale sets the floor: S0→S3 ⇒ T0→T3.
3. **Fail-closed default.** When `phi_touch` or scale is **UNKNOWN/unresolvable** (new repo, unclear data flow, "might touch PHI later"), or an **off-loopback / production posture applies** (the maintainer judges the change touches a production / off-loopback path — there is **no automatic detector**; the resolver is a human-applied checklist that produces the PR `Tier:` trailer), **clamp UP** to the strictest applicable tier (**≥T3 under any production posture**).
4. **Recorded reason.** Every resolution emits a one-line human-readable reason, surfaced as a **PR tier-declaration trailer** — the dev-process analogue of AI.md's recorded clamp `reason`, and the **evidence line** in the deviations register:

   ```
   Tier: S1×P3 ⇒ T3 — store touches the production PHI code path; PHI ratchet dominates scale.
   ```

**How to classify (checklist).** *Does any code path in this change see real PHI in production?* → if yes, **T3**. *Can you PROVE it never will (and that no real PHI enters dev/test)?* → if you **cannot prove it**, fail closed to **T3**. Otherwise apply the scale ceiling.

**Worked examples:**

| Configured change | Resolved tier | Recorded reason |
|---|---|---|
| Tweak to a synthetic HL7 generator | **T1** | S1×P0 — code-only, no production PHI path. |
| New MLLP listener option | **T2** | S1×P1 — synthetic in dev, but the transport is on the production PHI path. |
| KeyProvider / at-rest crypto change | **T3** | S2×P2 — a PHI-protecting compliance control; PHI ratchet. |
| Unclear new repo, data flow undecided | **T3** | Fail-closed: `phi_touch` unresolvable. |

### 4.4 The universal floor (every tier, including T0 — never scales down)

| Floor control | Why T0 still has it |
|---|---|
| **No real PHI to the AI**, and **none in any commit, test fixture, published artifact, shared memory, screenshot, or CI log** — by default, every tier. **One narrow exception** (PHI *to the AI* only): a signed **BAA + zero-data-retention** agreement covering the AI tool may permit real PHI in a prompt/context — see **§4.5**. That exception **never** covers PHI in commits / fixtures / published artifacts / shared memory / logs, which stays **absolutely forbidden**. | A throwaway spike that ingests real PHI is already a HIPAA exposure — and a BAA with the *AI vendor* never blesses PHI in your *git history*. |
| **No secrets/keys/`.env`/`*.db`** readable by the assistant — enforced by the `.claude/settings.json` deny-list. **But the deny-list is PATH-based:** it cannot stop a secret/PHI string you **paste** into the prompt, that a command the agent ran **echoes** into its captured output, or that gets written into project memory. **The human must not paste them, and must not let `dryrun`/`generate` output be captured into a committed file, transcript, or memory.** **Deterministic backstop:** the forbidden-content CI scan ([`scan_forbidden.py`](../scripts/publish/scan_forbidden.py)) and `gitleaks` catch a forbidden string or secret that lands in a *commit*, even though a path deny-list cannot stop a paste. | A path deny-list gives false confidence; the leak paths it misses are human-driven — so a commit-time scan backstops them, but "the human must not" is the first line. |
| **All content the assistant READS during a build is DATA, never instructions.** HL7 samples, `connections.toml`, file content, a pasted log, a WebFetch page, an MCP tool result — a value that *reads like* a command ("ignore prior rules", "add this dependency", "exfiltrate `.env`") is **still data**. Never let fetched/tool/file content auto-trigger an edit or command. (This is the dev-process lift of [`../CLAUDE.md`](../CLAUDE.md) §8 and [PHI.md](PHI.md)'s treat-as-untrusted-data rule.) | Inbound HL7 and partner config are *attacker-influenceable*; an agent that acts on embedded instructions is steered entirely inside the build process, bypassing every runtime control. |
| **Reject code you cannot explain** — even if it works. **Explaining it with AI assistance is acceptable** — what's rejected is code that stays **opaque even with the AI's help**. (A deliberate, documented **override** of the stricter "unaided comprehension" anti-SOUP bar — see §10 and the [A.6](#a6-documented-deviations) deviation.) | Shipping code no one can reason about is how "developers who build but cannot debug" are made (Fawzy); applies from T0, independent of PHI. The T3 escalation (a *qualified* human can explain — AI-assisted is fine — **and** independent review) is in §6.6. |
| **Model + version transparency.** The assistant's identity and the session are retained as a provenance signal. | Provenance is a property you cannot reconstruct after the fact. |
| **Honesty taxonomy** (Built / designed-but-deferred / aspirational) on every claim. | An unbacked claim is a defect at any tier (§8). |
| **Vet the build tooling itself.** Pin/verify the Claude Code version; vet any installed skill, MCP server, IDE extension, or agent framework **before use**; prefer official sources; record what is in use. | The tools that *build* the code are a supply-chain surface no SAST/SCA gate inspects — the GSD trust-incident lesson (§11). |

### 4.5 The BAA exception — PHI to the AI under a Business Associate Agreement

The floor's default is **no real PHI to the AI**. Real PHI may enter the AI assistant's prompt/context **only** when **all** of the following hold — the dev-process analogue of the product's `managed_claude_baa` + `phi` model in [AI.md](AI.md):

- **Signed BAA** with the AI vendor covering the **specific tool/endpoint** in use (the vendor is a HIPAA Business Associate). A BAA for one product/endpoint does **not** extend to a different model, an MCP server, or a developer's personal bring-your-own account.
- **Zero-data-retention / no-training** on that connection, contractually assured (the PHI is not retained or used for training).
- **Operator-enabled, not ad-hoc.** Turning PHI-to-AI on is an **operator/owner** decision recorded in config + the Applicability Profile — never a per-developer choice (mirrors [AI.md](AI.md): the policy is set by whoever *operates* the install).
- **Minimum necessary.** Send only the PHI actually required; prefer **synthetic** or **de-identified** data wherever it suffices (de-id is roadmap — [PHI.md](PHI.md)). Routine dev/test stays **synthetic-only** (PO.5) — this exception is for legitimate PHI-handling work (e.g., diagnosing a production incident on real data), **not** everyday development.
- **Audited as a disclosure.** PHI sent to the AI is logged as a PHI **disclosure to a Business Associate** (acting user, what, when), per the audit substrate.
- **Scope stays narrow.** The exception covers **transmission to the BAA-covered AI only.** It does **not** relax any other floor: PHI must **never** land in a commit, test fixture, the published mirror, shared project memory, a screenshot, or a CI log; **secrets/keys are never sent to the AI**, BAA or not.

Absent **all** of the above, the default holds: **no PHI to the AI.** Today MEFOR asserts **no such BAA-covered AI connection** — the exception is **defined but not enabled** (Appendix A.5), so the effective posture remains no-PHI-to-AI.

---

## 5. Controls-as-dials — the master table

Every control is a **dial** set by tier, expressed in real Claude Code primitives. Each row is the index into its §6 loop-stage subsection (where the checklist + snippet live). A control is **cumulative**: a "+" means *in addition to the tier(s) to its left*.

| Control family | **T0 Exploratory** | **T1 Guarded** | **T2 Governed** | **T3 Regulated-Release** |
|---|---|---|---|---|
| **Spec / plan rigor** (§6.1–6.2) | Inline intent in the prompt; Plan mode optional | **Written plan via Plan mode, approved before edits** | + **ADR** ([`docs/adr/NNNN`](adr/README.md)) for any hard-to-reverse decision **before** build + a threat-model note (PW.1) | + **requirement→design→test traceability** — *solo obligation today:* each change's **test name/docstring cites its ADR # / requirement id** + the Plan artifact + PR tier-declaration (honor-system, unenforced). The *automated* matrix mirroring the IEC 62304 B/C posture *by analogy* (§10) is **aspirational** (§9); the manual links are the standing [A.6](#a6-documented-deviations) posture |
| **Context isolation / engineering** (§6.3) | Single session | Curated `CLAUDE.md` + **fresh per-task context** + `TodoWrite` decomposition + `/clear` after ~2 failed attempts | + **SessionStart worktree hook** + **separate git worktree per parallel session** + single-writer memory coordination; **default-deny MCP / no web egress of identifying strings** | Same, mandatory; **memory files / committed context NEVER carry PHI or secrets** (floor); live PHI in a prompt only under the **§4.5 BAA exception** |
| **Verification gates** (§6.5) | `messagefoundry check` advisory; lint if convenient | **Full local gate MUST pass** (`ruff check` + `ruff format --check` + `mypy` strict + `pytest`, offscreen-Qt for console) + **new behavior gets a test** + **verify-before-add** any new dependency | + **bandit / semgrep / pip-audit / gitleaks / crypto-inventory / forbidden-content BLOCKING** in CI + the **advisory** `/security-review` skill on the diff (human arbitrates — not a CI gate) | + **sink-aware project semgrep rules** (the injection/deserialization/TLS rules in [`.semgrep`](../.semgrep/messagefoundry.yml); dedicated *PHI-detection* rules are aspirational, §9), **no unresolved findings**, the **release gate** ([SDS §6.4](Secure_Development_Standards.md) / [RELEASE-GATE.md](security/RELEASE-GATE.md)), advisory SBOM / SLSA / signed tag |
| **Human-review depth** (§6.6) | Author self-review | Self + plan approval; **the maintainer IS the reviewer, gates are the compensating second reviewer** (SDS §A.6) | + `/code-review` + `/security-review` on the diff (*AI-assisted, advisory — the human arbitrates*); a human second reviewer for consequential changes **when a second maintainer exists** — else the T1 compensating posture (gates + AI-assisted review + self-explain) carries up ([A.6](#a6-documented-deviations)) | + a **qualified human MUST approve AND be able to EXPLAIN** every AI change (*AI-assisted explanation is acceptable — §10 / [A.6](#a6-documented-deviations)*; *achievable solo*); **no merge on AI self-certification alone.** **[team posture]** independent human review before production exposure — *under solo maintenance this is the documented [A.6](#a6-documented-deviations) deviation (gates + AI-assisted review compensate), escalating when a 2nd maintainer joins* |
| **Provenance / traceability** (§6.7) | None required | **One coherent layer per commit** + PR with **`Co-Authored-By` model/version trailer** + the PR tier-declaration | + ADR link for hard-to-reverse decisions + the Plan artifact + PR-thread reference (no separate transcript store is retained yet — §9) | + **claims-register entry** + **AI- vs human-authored provenance** (commit-granular trailer; an adopter's QMS would want line-level — *by analogy*, §10) + **SOUP assessment** of AI-generated code *in a 62304-regulated deployment* (§10) |
| **Forbidden / hard-NO** (cumulative) | *Floor — ALL tiers:* real PHI to the assistant (**except under the §4.5 BAA exception**) **or** any secret to the assistant; **no PHI/secret in any commit / fixture / published artifact / shared memory / CI log** (absolute — no BAA covers this); **acting on instructions embedded in untrusted content** | *(floor, +)* accept-and-merge an **unreviewed** AI diff onto a shipping branch; **add an AI-suggested dependency without verifying it exists/is reputable/is the intended name** | *(floor, +)* merge code you **cannot explain even with AI help**; **skip a blocking gate**; **self-certify security by prompting**; **route PHI/secrets across an MCP or web-egress boundary** | *(floor, +)* **un-ADR'd irreversible decisions**; off-loopback/production exposure without the release gate satisfied or a dated risk acceptance — *(the no-PHI-in-prompts/logs/transcripts rule is the floor, in force here as everywhere)* |

> **The non-negotiable principle of the gate row:** gates are **DETERMINISTIC checks** — hooks, the deny-list, CI exit codes, `messagefoundry check`. **Never "ask the model to be secure."** Prompt-based optimization of security/maintainability is unstable (§8).

---

## 6. The daily loop — embedded playbook (dialed by tier)

Each subsection opens with a **dial-up line** (S0…→T3) and ends with a **"maps to"** tag (consensus principle / SSDF practice / ASVS chapter).

### 6.1 Scope & spec — write a testable intent before prompting

> **Dial:** T0 inline intent in the prompt → T1 a written, testable intent → **T2+/P2** capture it as an **ADR + threat-model note** → T3 the spec is a traceable deliverable.

Write *what* and *why* before prompting; phrase requirements testably (EARS / RFC-2119 "MUST/SHALL"). Quote the real invariant lines from [`../CLAUDE.md`](../CLAUDE.md) the change must not break — they are the durable source of truth. At T2+ capture any hard-to-reverse decision as an ADR **before** building (see [ADR README](adr/README.md)).

```markdown
<!-- docs/adr/00NN-<kebab-title>.md  (minimal stub) -->
# NN. <decision>
Status: Proposed
Context: <the forcing problem + the CLAUDE.md invariant in play, quoted verbatim>
Decision: <the choice; what it must NOT break>
Consequences: <reversibility, the verifying test, the tier — e.g. S2×P2 ⇒ T3>
```

*Maps to:* Principle 1 (intent as source of truth) · SSDF **PO.1, PW.1** · ASVS context for the seam.

### 6.2 Plan-mode approval — the approved-intent artifact

> **Dial:** T0 plan optional → **T1+ Plan mode required, approved before any edit** → T3 the plan is retained as a provenance reference.

At T1 and above, use **Plan mode** so the diff is checked against an **approved plan**, not improvised. A good plan names: the **files/seams** it will touch, the **test it adds**, the **invariants it must not break**, and the **tier**. The diff that comes back is reviewed *against the plan* — divergence is a review finding.

> **METR caveat.** Planning here buys **correctness and auditability, not raw speed.** Do **not** claim it makes development faster (§8).

*Maps to:* Principles 1 & 5 · SSDF **PO.1** · ASVS V8 (process/governance evidence).

### 6.3 Context engineering — anchor it, isolate it, recover from rot

> **Dial:** T0 single session → T1 curated `CLAUDE.md` + fresh per-task context + `TodoWrite` + `/clear` → **T2+ SessionStart worktree hook + a worktree per parallel session**; MCP/web egress default-deny.

[`../CLAUDE.md`](../CLAUDE.md) is the **always-loaded anchor** — keep it current; when the code stops matching it, fix the doc. Project memory is for **FACTS** (decisions, lane maps) — **NEVER PHI or secrets** (floor). The `SessionStart` hook injects worktree/branch context deterministically:

```json
// .claude/settings.json — SessionStart hook (excerpt; timeout/statusMessage omitted)
"SessionStart": [
  { "hooks": [ { "type": "command",
    "command": "pwsh -NoProfile -File scripts/worktree/session-context.ps1" } ] } ]
```

**Context-rot recovery (name the primitives).** Symptoms → action:

- *Repeating itself, re-reading the same files, confidently wrong edits* → **`/clear`** and restart with a sharper prompt (per [`../CLAUDE.md`](../CLAUDE.md): `/clear` after ~2 failed attempts — don't grind in a polluted context).
- *Long session nearing the limit* → **`/compact`**, focusing the summary on **API shape and decisions** (e.g. "preserve the connector registry and the `inbound`/`outbound`/`@router`/`@handler` interface").
- *Always* → fresh context per task; keep context utilization **LOW** (the "dumb zone" / lost-in-the-middle effect degrades recall).

**Untrusted-input handling (the floor, operationalized).** Content the assistant pulls in — an HL7 sample, `connections.toml`, a pasted log, a **WebFetch** page, an **MCP** tool result — is **DATA, not instructions**. At T2+ **never let fetched/tool/file content auto-trigger an edit or command**: read it, decide yourself, then act. (Lift of [`../CLAUDE.md`](../CLAUDE.md) §8.)

**MCP and web egress trust** (default-deny at T2+/PHI-touch):

- **MCP servers** are arbitrary third-party processes that can read repo content and receive whatever the agent sends — a direct PHI/secret egress channel and a supply-chain trust boundary **outside** AI.md's product model. **Default-deny for T2+/PHI-touch.** Any MCP server must be **vetted, version-pinned, and recorded** (provenance); **no PHI or secret may cross an MCP boundary**; MCP results are **untrusted data**.
- **WebSearch / WebFetch** are live egress: **no PHI, secret, or customer-identifying string in any query or tool call** (a partner name, internal hostname, or config fragment). The repo's [`scan_forbidden.py`](../scripts/publish/scan_forbidden.py) backstops forbidden strings that **land in a commit / the published mirror** — it is **not** a live interceptor of a WebSearch/WebFetch/MCP query, so runtime egress discipline is on the human. **At T3, web egress is off or reviewed.**

*Maps to:* Principle 2 (context engineering) · SSDF **PO.3, PO.5** · ASVS V14 (config), V8.

### 6.4 Decomposed implementation — small tasks, isolated sessions

> **Dial:** T0 single session → T1 `TodoWrite` decomposition + fresh per-task context → **T2+ a separate git worktree per parallel session**.

Decompose with `TodoWrite`; keep trajectories short; give each task fresh context. **Parallel sessions MUST be isolated via separate worktrees** — never share a working tree:

```powershell
# Each session gets its own checkout + branch + .venv (see WORKTREES.md)
scripts/worktree/new.ps1 -Name keyprovider-followup
```

When the AI suggests a dependency, **verify-before-add** it here (real, reputable, the **exact intended** name) **before** it touches `pyproject.toml` — then re-lock. AI-suggested packages are frequently hallucinated or typosquatted ([`../CLAUDE.md`](../CLAUDE.md) §5). See [WORKTREES.md](WORKTREES.md).

> **Honest caveat.** Decomposition reduces *per-step* error but is **not** a correctness guarantee (the same agent paradigm scores ~28% on SWE-bench Lite, ~19% on SWE-bench-Live). Pair it with §6.5.

*Maps to:* Principle 3 (decomposition) · SSDF **PW.4** · ASVS V8.

### 6.5 Automated verification as HARD gates — the core compensating control

> **Dial:** T0 advisory → **T1 the full local gate MUST pass + new behavior gets a test + verify-before-add** → **T2 blocking SAST/SCA/secret-scan in CI + the advisory `/security-review` skill** → T3 + sink-aware project semgrep rules (PHI-detection rules aspirational), no unresolved findings, the release gate.

**The local gate** (run, in order):

```powershell
$env:QT_QPA_PLATFORM="offscreen"
.venv\Scripts\ruff.exe check messagefoundry tests
.venv\Scripts\ruff.exe format --check messagefoundry tests
.venv\Scripts\mypy.exe messagefoundry
.venv\Scripts\python.exe -m pytest -q
python -m messagefoundry check   # exit-coded validate + dryrun, reused by git-hook + CI + IDE
```

**Deterministic guardrails the model cannot bypass** — the `.claude/settings.json` deny-list and the PreToolUse hook:

```json
// .claude/settings.json — deny-list + PreToolUse wiring (excerpt — abridged; the real file has more denies + timeout/statusMessage)
"deny": [
  "Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)",
  "Read(./*.key)", "Read(./*.pem)", "Read(./*.pfx)", "Read(./*.db)",
  "Edit(./secrets/**)", "Write(./secrets/**)",
  "Bash(rm -rf:*)", "Bash(git push --force:*)", "Bash(git reset --hard:*)"
],
"PreToolUse": [
  { "matcher": "Bash",       "hooks": [ { "type": "command", "if": "Bash(git *)",
    "command": "pwsh -NoProfile -File scripts/hooks/block-blanket-git-stage.ps1" } ] },
  { "matcher": "PowerShell", "hooks": [ { "type": "command", "if": "PowerShell(git *)",
    "command": "pwsh -NoProfile -File scripts/hooks/block-blanket-git-stage.ps1" } ] }
]
```

> **Transferable principle — fail-OPEN by design.** The git-staging guard blocks *blanket* staging (`git add -A`/`.`) so the human curates each commit; if the guard itself errors it lets the command **through** (fail-open) rather than wedging the workflow — a deliberate tradeoff for a *workflow* guard. (Contrast the engine's *fail-closed* bind guard for a *security* boundary.)

**The blocking security CI** ([`.github/workflows/security.yml`](../.github/workflows/security.yml)) — **bandit** (SAST), **pip-audit** (SCA, hash-locked), **gitleaks** (secret scan), **semgrep** (project rules, [`.semgrep/messagefoundry.yml`](../.semgrep/messagefoundry.yml)), **crypto-inventory**, and **forbidden-content** — is **BLOCKING**: bandit/gitleaks/semgrep/pip-audit started from a clean baseline so a regression turns CI **red**, and crypto-inventory/forbidden-content fail the build on any inventory drift or forbidden-string hit. The CycloneDX **SBOM** job is **advisory** (`continue-on-error: true` — it fails only if the bill of materials cannot render), not a blocking gate. Separately, the maintainer runs the **`/security-review`** and **`/code-review`** Claude Code skills on the diff as **advisory** reviews — local, human-invoked AI reviews the human arbitrates, **never** a deterministic CI gate (§7).

> **CRITICAL.** Gates are **deterministic checks**, never "ask the model to be secure." The model must **not** self-certify security or maintainability by prompting alone.

*Maps to:* Principle 4 (verification as hard gates) · SSDF **PW.7, PW.8** · ASVS V14 (config), V15 (secure coding), V16 (logging).

### 6.6 Human review of every diff — the maintainer is the arbiter

> **Dial:** T0 self-review → **T1 self + plan approval; the maintainer IS the reviewer, gates are the compensating second reviewer** → T2 + `/code-review` + `/security-review` (advisory, human arbitrates); a second human for consequential changes when one exists (else the T1 posture carries up) → **T3 a qualified human MUST approve AND be able to explain (AI-assisted is acceptable — §10) (achievable solo); no merge on AI self-certification. [team posture] independent review before production exposure — solo: the [A.6](#a6-documented-deviations) deviation, escalating when a 2nd maintainer joins.**

The maintainer reviews **every** diff against the §6.2 plan. **Reject code you cannot explain — even if it works** (the floor, §4.4) — explaining it **with AI assistance is acceptable** (a deliberate override of the stricter "unaided comprehension" anti-SOUP bar; see §10), and what's rejected is code that stays **opaque even with the AI's help**. This is the SDS **§A.6** deviation this document owns: under solo maintenance, AI-assisted review + the blocking gates are the **compensating** second reviewer, **not** an independent audit (§8 wording rules). **Your live T3-solo obligation** is concrete and achievable: the full local + blocking-CI gate green, `/code-review` + `/security-review` run and triaged, and every change **explained-or-discarded** (with AI help if needed — but you must **engage with and stand behind** the explanation, not rubber-stamp it) — the *independent human* review is the deferred [A.6](#a6-documented-deviations) escalation, not a control you can satisfy alone today.

> **QMS-gap warning.** A process that does not distinguish AI- from human-authored code has *its first gap*. **HIPAA framing:** OCR audits **runtime behavior with PHI**, not git history — verification (§6.5) must target behavior, not just the diff.

*Maps to:* Principle 5 (human-in-the-loop + auditability) · SSDF **PO.2, PW.7, RV.2** · ASVS V8.

### 6.7 Commit / PR with provenance

> **Dial:** T0 none → **T1 one coherent layer per commit + PR + `Co-Authored-By` + tier-declaration** → T2 + ADR link + Plan artifact + PR-thread reference → T3 + claims-register entry + AI-vs-human provenance + SOUP assessment (by analogy, §10).

Work on a feature branch and open a PR (**direct `main` pushes are blocked**). One coherent layer per commit. Record provenance in the trailer:

```
<subject — one coherent layer>

Tier: S1×P3 ⇒ T3 — <recorded reason>

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

The human-gate stack: [CODEOWNERS](../.github/CODEOWNERS) + branch protection + required CI checks + the [PR template](../.github/PULL_REQUEST_TEMPLATE.md) + the CLA bot ([`cla.yml`](../.github/workflows/cla.yml)). For the **tag-time** bar (SBOM / signed tag / SLSA), see [RELEASE-GATE.md](security/RELEASE-GATE.md).

> **Provenance honesty (read with §9).** The `Co-Authored-By` trailer is **Built (by convention)** and records model/version at **commit granularity** — it is **not** enforced by CI and does **not** mark which *lines/hunks* are AI- vs human-authored. The line-level distinction a QMS actually wants is **designed-but-deferred** (§9). Do not claim more than the trailer delivers (§8; Appendix A.6 deviation).

*Maps to:* Principle 5 · SSDF **RV.2** · ASVS V8.

### 6.8 When NOT to use AI / taking manual control back

The other side of every dial: a maintainer must know **when to stop and code by hand**. This is Sarkar & Drosos's core finding — expertise is redistributed to *knowing when to take manual control back* — and the practical reading of the METR result (§3, §8). **Take manual control when:**

- the change is a **security-critical seam you must fully own** (auth, crypto, a bind guard) and you want every line by hand;
- you **cannot yet verify** the output (no test, no spec you trust) — write the test/spec first, or write the code;
- you've hit **~2 failed attempts** on the same problem → `/clear` and reconsider, or switch to manual ([`../CLAUDE.md`](../CLAUDE.md));
- the result is anything you **could not explain even with the AI's help** under review (the floor) — discard it and author it yourself.

This standard governs *how* to use AI at each tier; it **does not mandate** using AI for every task. For a solo maintainer on a mature PHI repo (precisely the METR cohort), manual authoring is sometimes the correct, faster, safer choice. *Maps to:* Principle 5 · SSDF **PO.2**.

---

## 7. Cross-walk: loop stages → 5 principles → NIST SSDF → OWASP ASVS

| Loop stage / principle | NIST SSDF | ASVS 5.0 L3 | Claude Code primitive(s) |
|---|---|---|---|
| §6.1 Spec / **P1 intent-as-truth** | PO.1, PW.1 | V8 | `CLAUDE.md`, ADR, EARS/RFC-2119 intent |
| §6.2 Plan approval / **P1 & P5** | PO.1 | V8 | Plan mode (EnterPlanMode/ExitPlanMode) |
| §6.3 Context / **P2 context-engineering** | PO.3, PO.5 | V14, V8 | `CLAUDE.md`, project memory, SessionStart hook, `/clear` + `/compact`, worktrees |
| §6.4 Decomposition / **P3** | PW.4 | V8 | `TodoWrite`, subagents, worktrees |
| §6.5 Verification / **P4** | PW.7, PW.8 | V14, V15, V16 | local gate, `messagefoundry check`, blocking CI (bandit/semgrep/pip-audit/gitleaks), deny-list + PreToolUse hook, `/security-review`, `/code-review` |
| §6.6 Human review / **P5** | PO.2, PW.7, RV.2 | V8 | PR review, CODEOWNERS, `/code-review` |
| §6.7 Provenance / **P5** | RV.2 | V8 | `Co-Authored-By` trailer, tier-declaration, transcript |
| §6.8 Manual control / **P5** | PO.2 | — | `/clear`; deliberate non-use of AI |

**Primitive → control → guardrail-type** (with the live MEFOR file):

| Claude Code primitive | Control it implements | Guardrail type | Live MEFOR file |
|---|---|---|---|
| `.claude/settings.json` deny-list | No secrets/keys/`*.db`/`.env` to the assistant | **Deterministic gate** | [`.claude/settings.json`](../.claude/settings.json) |
| PreToolUse hook | Block blanket git staging (fail-open) | **Deterministic gate** | [`scripts/hooks/block-blanket-git-stage.ps1`](../scripts/hooks/block-blanket-git-stage.ps1) |
| SessionStart hook | Inject worktree/branch context | **Context** | [`scripts/worktree/session-context.ps1`](../scripts/worktree/session-context.ps1) |
| Blocking security CI | SAST/SCA/secret-scan/forbidden-content | **Deterministic gate** | [`.github/workflows/security.yml`](../.github/workflows/security.yml) |
| `messagefoundry check` | Validate + dryrun, exit-coded | **Deterministic gate** | [`messagefoundry/checks.py`](../messagefoundry/checks.py) |
| `CLAUDE.md` | Standing contract / invariants | **Context** | [`../CLAUDE.md`](../CLAUDE.md) |
| Plan mode, `/code-review`, `/security-review` | Plan approval, diff review | **Advisory** (human arbitrates) | — (Claude Code feature) |

This document **owns and expands** the [SDS §A.6](Secure_Development_Standards.md#a6-documented-deviations) line — *"AI-assisted review as a compensating control"* — for the solo-maintainer **PO.2 / PW.7** deviation. The detailed record is Appendix A.6.

---

## 8. A note on claims and wording (read before publishing any claim)

Mirror the SDS claims discipline. **Back every claim with evidence.**

| **Use:** (approved phrasing) | **Do not use:** (overclaim) |
|---|---|
| "AI-assisted code review as a **compensating control**" | "AI-**reviewed**" implying an independent audit |
| "Plan **approved by the maintainer** before implementation" | "**autonomously** developed" |
| "Gates **enforce intent deterministically**" | "**AI-certified**" / "AI-certified secure" |
| "**Built with AI assistance** under this standard" | "AI **made development faster**" (unmeasured — METR found 19% **slower**) |
| "Provenance recorded at **commit granularity** by convention" | "AI-generated code is **verified secure by the model**" |

**The METR honesty point.** Do **not** claim a productivity or quality gain that has not been **measured for THIS context**. The loop + gates buy **auditability, continuity, and safety** — **not** guaranteed speed. **Benchmark pass@1 ≠ real quality:** HumanEval/MBPP scores say nothing about repo-scale correctness, security, or maintainability (SWE-bench-Live best resolution ~19%; ~40% of "executable" agent code fails to match expected output).

Every AI-build-process claim is logged in the **claims register** (Appendix A.4) with its exact wording and evidence — no unbacked claim ships.

---

## 9. Tooling honesty — built / designed-but-deferred / aspirational

The repo's tiered-honesty taxonomy, applied to the **dev-process tooling itself**, so this document never overclaims its own toolchain.

**Built (in code today):**

- PreToolUse [`block-blanket-git-stage.ps1`](../scripts/hooks/block-blanket-git-stage.ps1) (Bash + PowerShell, fail-open).
- [`.claude/settings.json`](../.claude/settings.json) secrets/keys/`*.db` **path-based** deny-list + destructive-command denies.
- Blocking security CI: bandit, semgrep ([`.semgrep/messagefoundry.yml`](../.semgrep/messagefoundry.yml)), pip-audit, gitleaks, crypto-inventory, forbidden-content ([`scripts/publish/scan_forbidden.py`](../scripts/publish/scan_forbidden.py)). The CycloneDX **SBOM** job is **advisory** (`continue-on-error`), not blocking.
- [`messagefoundry check`](../messagefoundry/checks.py) exit-coded validate + dryrun gate.
- SessionStart worktree-context hook; worktree scripts ([`new.ps1`/`remove.ps1`](../scripts/worktree/)); shared AI project memory (facts only); synthetic generators; the dependency-boundary test ([`tests/test_dependency_boundaries.py`](../tests/test_dependency_boundaries.py)).
- `Co-Authored-By` provenance trailer — **by convention** (model/version, commit granularity).
- `/code-review` + `/security-review` skills.

**Designed but deferred (Build trigger + Design record):**

- **A dedicated SPDX-header CI test — *highest-priority deferred gate*.** SPDX-header presence is today enforced only by **convention** — there is no test asserting it. ("AI memory" is **not** a control: it fails silently the moment context rots, §6.3.) *Interim compensating control:* a manual checklist item in the [PR template](../.github/PULL_REQUEST_TEMPLATE.md) (add if absent) — a deterministic-ish artifact, **not** "AI memory" — plus the leak/forbidden scan. *Build trigger (cheap — do this first):* a trivial pytest walking first-party `.py` files. *Design record:* Appendix A.6.
- **A new-dependency-introduction check — *highest-priority deferred gate*.** `pip-audit` finds CVEs in *already-pinned* packages — it does **not** flag a freshly **hallucinated/typosquatted** name with no advisory. Verify-before-add (§6.4) is today enforced only by the human remembering — exactly the cheap deterministic gate that should stand in for the absent second reviewer. *Interim compensating control:* a manual verify-before-add line in the [PR template](../.github/PULL_REQUEST_TEMPLATE.md) (add if absent). *Build trigger (cheap — do this first):* a pytest/CI step diffing `pyproject` deps against the prior commit and requiring a recorded justification. *Design record:* Appendix A.6.
- **A `Co-Authored-By` trailer-format CI check** (presence/format) **and** a **line/hunk-level** AI-authorship record. *Build trigger:* a commit-msg lint; a hunk-attribution mechanism. *Design record:* Appendix A.6.
- **A retained-transcript provenance store** (PHI/secret-free, access-controlled).

**Aspirational / planned (no ADR yet):**

- Cross-artifact spec-consistency analysis.
- An **automated requirement→design→test traceability matrix** (today: ADR ↔ test-name ↔ requirement by convention — see §10/Appendix A.6).
- A **true second human reviewer** (*build trigger:* a second maintainer joins).
- **Dedicated PHI-detection semgrep rules** (today's [`.semgrep`](../.semgrep/messagefoundry.yml) rules target injection/deserialization/TLS sinks, *not* PHI strings).

> The **fail-OPEN** design of the git-staging guard is recorded as a transferable principle (§6.5): a *workflow* guard fails open so it never wedges work; a *security boundary* (the engine bind guard) fails closed.

---

## 10. Healthcare / regulated overlay (the T3 layer)

Extra obligations that attach at the PHI/regulated tier — **without overreaching**.

> **Scoping (read first).** MEFOR is an **HL7 integration engine, not a medical device / SaMD**, and is **not itself subject to IEC 62304 or FDA device regulation** today; no other project doc claims otherwise. The IEC 62304 / SOUP / traceability practices below are **adopted by analogy** as a defensible higher-bar posture, because an adopter may run MEFOR **inside** a regulated clinical workflow. They are voluntary discipline, **not** a regulatory obligation on MEFOR — and producing them does not make MEFOR (or its adopter) compliant (see the shared-responsibility callout in §1).

- **Traceability at T3.** A full **bidirectional requirement→design→test** traceability matrix *mirrors* the IEC 62304 Class B/C posture (*"the deliverable auditors check first"*) — but MEFOR is **not** a medical device and **not** subject to IEC 62304 (scoping note above); it adopts the discipline **voluntarily, by analogy**. The *automated* matrix is **aspirational** (§9). **The standing T3 obligation MEFOR meets today** is the manual compensating control: a change's **test name or docstring cites the ADR # / requirement id** it verifies, plus the Plan artifact + the PR tier-declaration — **unenforced (honor-system, no CI check yet)**, recorded as a dated deviation (Appendix A.6). The standard does **not** claim an automated matrix it has not built.
- **AI-generated code as SOUP (by analogy).** In a 62304-regulated deployment, AI-generated code would be treated as SOUP — documented and assessed — and an adopter's **QMS would need to distinguish AI- from human-authored code**. MEFOR has **no QMS of its own** (it is an OSS engine, not a device manufacturer); it **voluntarily** offers commit-granular provenance toward that via the `Co-Authored-By` trailer (§6.7, §9). Line/hunk-level attribution is aspirational — recorded as a deviation (Appendix A.6).
- **"Explain it with AI help" — a deliberate override of the strict anti-SOUP bar.** The strongest guard against **SOUP** (*Software of Unknown Provenance*) is the *strict* reading of *reject what you can't explain*: a human understands every line **unaided**, so nothing is of unknown provenance. This standard **consciously relaxes** that to *explainable **with AI assistance***, because it governs a **solo maintainer who builds with AI** — requiring unaided comprehension of every AI-written line would bar the very workflow it exists to support. The residual SOUP risk is **accepted and bounded**: the maintainer must still **produce, verify, and stand behind** an explanation (rubber-stamping is forbidden — code opaque *even with AI help* is still rejected); the deterministic gates (tests + blocking SAST/SCA) still apply; and at T3 the explanation is **captured durably** (comment / PR / ADR / test) so provenance is recorded, not ephemeral. Recorded as a dated deviation (Appendix A.6). **Build trigger:** a regulated-device / formal-IEC-62304 deployment requiring documented SOUP assessment or unaided comprehension ⇒ the strict bar is reinstated.
- **HIPAA.** OCR audits **runtime behavior with PHI, not git history** — verification targets behavior (§6.5). **PO.5 reiterated:** routine dev/test uses synthetic data, never real PHI.
- **PHI to the AI under a BAA (§4.5).** Real PHI reaches the AI assistant **only** under a signed **BAA + zero-data-retention** agreement covering the tool — operator-enabled, minimum-necessary, and audited as a disclosure (the dev-process analogue of [AI.md](AI.md)'s `managed_claude_baa` / `phi` model). It **never** licenses PHI in commits, fixtures, the published mirror, or shared memory. Default and current MEFOR posture: **no BAA-covered AI connection → no PHI to the AI** (Appendix A.5).
- **FDA draft "AI-Enabled Device Software Functions"** (Jan 2025, Docket FDA-2024-D-4488, **DRAFT**) — cited **informative only**: it governs AI *in* the device, but its total-product-lifecycle risk posture informs how AI-*built* software should be controlled.

PHI data detail routes to [PHI.md](PHI.md); the **product** egress policy routes to [AI.md](AI.md) (out of scope).

---

## 11. Evidence, attestation, and references

**Evidence set.** *Retained, auditable evidence:* this standard + [`../CLAUDE.md`](../CLAUDE.md); the [`.claude/settings.json`](../.claude/settings.json) hook/deny-list config; the security-CI scan history; the `Co-Authored-By` model/version trailers (commit granularity); PR/commit history; the **claims register** (A.4); the **deviations register** (A.6). *Ephemeral (not retained today):* the live session transcript — there is **no** retained-transcript store yet (§9), so it is not a standing archive; the PR thread + commit trailer are the durable provenance until that store is built.

> **Provenance retention constraint.** Any **retained transcript or memory** used as a provenance record **MUST be free of PHI and secrets and access-controlled** — it is otherwise a long-lived PHI/secret store and a HIPAA exposure. A retained-transcript store is **designed-but-deferred** (§9); until then, provenance is the trailer + CI history + the PR thread, not a persisted transcript archive.

**Attestation posture.** The project **self-attests** that it builds under this standard with **AI governed as a tool** — **NOT** that AI output is independently audited (§8 wording rules).

**References** (each flagged where it is vision-not-validated or popularity-not-quality):

- **NIST SP 800-218 (SSDF)** and **OWASP ASVS 5.0 L3** — the binding external standards this doc aligns to. **IEC 62304** (medical-device software lifecycle) and the **FDA draft "AI-Enabled Device Software Functions"** (Jan 2025 — DRAFT) — **informative only, not binding on MEFOR** (§10 scoping); the IEC 62304 specifics here are from reputable secondary sources, not the paywalled standard text.
- **METR RCT** (arXiv 2507.09089) — experienced devs **19% slower**; the calibration anchor.
- **Sarkar & Drosos** (PPIG 2025) — expertise redistributed to *knowing when to take manual control back*.
- **Context Engineering survey** (arXiv 2507.13334) — comprehension–generation asymmetry.
- **Ge et al., "A Survey of Vibe Coding with LLMs"** (arXiv 2510.12399) — five development models.
- **Fawzy et al.** (arXiv 2510.00328) — "fast but flawed"; "build but cannot debug." *Grey-lit review.*
- **"Good Vibrations?"** (arXiv 2509.12491) — trust as a delegation regulator.
- Benchmark-validated systems (AgentCoder, MapCoder, Reflexion, MASAI) — *pass@1 is HumanEval/MBPP; does NOT translate to repo/security/maintainability (SWE-bench-Live ~19%).*
- SDD frameworks (**Spec Kit, Kiro, OpenSpec**) and **12-Factor Agents** — *practitioner, largely un-peer-reviewed; popularity ≠ quality; the field moves monthly.*
- **GSD / Ralph Loop** — *cited as a supply-chain/governance **cautionary tale*** (governance moved to "open-gsd" after a trust incident).

**Cross-links:** [Secure Development Standards](Secure_Development_Standards.md) · [AI.md](AI.md) · [PHI.md](PHI.md) · [`../CLAUDE.md`](../CLAUDE.md) · [WORKTREES.md](WORKTREES.md) · [security/RELEASE-GATE.md](security/RELEASE-GATE.md) · [docs/adr/README.md](adr/README.md).

---

## Appendix A — Applicability Profile: MessageFoundry (MEFOR)

Per-project specifics, so the body stays project-agnostic. Future projects add Appendix B, C, … with identical headings.

### A.1 Project summary + resolved tier

MEFOR is an open-source HL7 v2.x integration engine (Python; FastAPI; SQLite/WAL; PySide6 console). It is **solo-maintained** and its production code path **carries real PHI** at every adopter deployment.

**Resolved tier: S1×P3 ⇒ T3.** *Recorded reason:* `Tier: S1×P3 ⇒ T3 — the store/transports/parsing path carries real patient data in production; the PHI ratchet dominates the solo (S1) scale.`

### A.2 Live guardrail inventory (each tagged **Built**)

| Guardrail | File | Tag |
|---|---|---|
| Secrets/keys/`*.db` deny-list + destructive-cmd denies; PreToolUse + SessionStart hooks | [`.claude/settings.json`](../.claude/settings.json) | Built |
| Blanket-git-stage guard (fail-open) | [`scripts/hooks/block-blanket-git-stage.ps1`](../scripts/hooks/block-blanket-git-stage.ps1) | Built |
| Worktree context + isolation | [`scripts/worktree/session-context.ps1`](../scripts/worktree/session-context.ps1), [`new.ps1`/`remove.ps1`](../scripts/worktree/) | Built |
| Exit-coded validate + dryrun gate | [`messagefoundry/checks.py`](../messagefoundry/checks.py) | Built |
| Blocking SAST/SCA/secret-scan/crypto-inventory/forbidden-content (+ advisory SBOM) | [`.github/workflows/security.yml`](../.github/workflows/security.yml) | Built |
| Lint/format/type/test + cross-DB store suites | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | Built |
| Project SAST rules | [`.semgrep/messagefoundry.yml`](../.semgrep/messagefoundry.yml) | Built |
| Customer/PHI leak guard | [`scripts/publish/scan_forbidden.py`](../scripts/publish/scan_forbidden.py) | Built |
| Human-gate stack | [PR template](../.github/PULL_REQUEST_TEMPLATE.md), [CODEOWNERS](../.github/CODEOWNERS), [`cla.yml`](../.github/workflows/cla.yml) | Built |
| Engine-boundary import test (depends-on integrity) | [`tests/test_dependency_boundaries.py`](../tests/test_dependency_boundaries.py) | Built |

### A.3 Tier examples + control applicability

| Real MEFOR work | Resolved tier |
|---|---|
| KeyProvider / at-rest crypto ([ADR 0019](adr/0019-pluggable-keyprovider-hsm-kms-vault.md)) | **S2×P2 ⇒ T3** |
| New MLLP listener option | **S1×P1 ⇒ T2** |
| Synthetic-generator tweak | **S1×P0 ⇒ T1** |

| Control family | Status at MEFOR |
|---|---|
| Spec/plan rigor | In scope (T3) — ADR + Plan mode |
| Context isolation | In scope — CLAUDE.md + worktrees + SessionStart hook |
| Verification gates | In scope — full local + blocking CI |
| Human-review depth | **Deviation** (A.6 — solo maintainer) |
| Provenance/traceability | **Partial / deviation** (A.6 — commit-granular; manual traceability) |

*Summary:* 3 in-scope as built; 2 carry documented deviations (A.6).

### A.4 Claims register (AI-build-process)

| Claim (approved wording) | Evidence |
|---|---|
| "Built with AI assistance under the Secure AI-Assisted Development Standards." | This doc; `Co-Authored-By` trailers; CI history. |
| "AI-assisted code review as a compensating control for the solo-maintainer review deviation." | A.6; SDS §A.6; `/code-review` + `/security-review`; blocking CI. |
| "Gates enforce intent deterministically." | `.claude/settings.json`; PreToolUse hook; `security.yml`; `messagefoundry check`. |
| "Provenance recorded at commit granularity by convention." | `Co-Authored-By` trailer; **not** CI-enforced (A.6). |

*Not claimed:* "AI-reviewed = independently audited"; "AI made development faster"; "AI-certified secure."

### A.5 Project-specific parameters

- **Verification order:** `ruff check` → `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console) → `messagefoundry check`.
- **Commits:** one coherent layer per commit; branch + PR (direct `main` blocked).
- **Trailer format:** `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` + the `Tier:` line.
- **Clamp posture:** fail-closed to the strictest applicable tier when `phi_touch`/scale is unknown or off-loopback.
- **Parallel sessions:** one worktree each; **shared AI memory is single-writer** — coordinate memory writes across sessions ([WORKTREES.md](WORKTREES.md)).
- **PHI-to-AI exception (§4.5):** **not enabled** — MEFOR asserts no BAA-covered, zero-data-retention AI connection for the dev tooling today, so the effective posture is **no PHI to the AI**. To enable, an operator records the signed **BAA + zero-data-retention** reference (vendor, tool/endpoint, date) here; routine dev/test stays synthetic-only (PO.5) regardless.

### A.6 Documented deviations

The standard requires deviations be documented with a compensating control (SDS §6.3 pattern).

- **Single-maintainer review (PO.2 / PW.7) — the canonical deviation this doc owns.** *First accepted 2026-06-16 in [SDS §A.6](Secure_Development_Standards.md#a6-documented-deviations); expanded here 2026-06-18; owner: project maintainer.* The T3 "human second reviewer" control cannot mean an independent human today. **Compensating controls:** blocking SAST/SCA/secret-scan (bandit/semgrep/pip-audit/gitleaks), AI-assisted review (`/code-review`, `/security-review`), branch protection + required CI checks, no direct `main` pushes. **Build trigger:** *a second human maintainer joins ⇒ T3 review escalates to a true human second reviewer.* **Design record:** [SDS §A.6](Secure_Development_Standards.md#a6-documented-deviations) + this section (+ an ADR if cut). *Honesty:* wording forbids "AI-reviewed = independently audited" (§8).
- **"Explain it with AI help" accepted in lieu of unaided comprehension — the anti-SOUP override.** *Risk accepted 2026-06-18; owner: project maintainer.* The floor's *reject code you cannot explain* (§4.4) is satisfied by an explanation reached **with AI assistance** — a deliberate relaxation of the stricter "the human understands it unaided" reading that most directly prevents **SOUP** (Software of Unknown Provenance, §10). **Why override:** the standard governs a solo maintainer who builds with AI; an unaided-comprehension bar would bar that workflow. **Compensating controls:** the maintainer must produce, verify, and **stand behind** the explanation (code opaque *even with AI help* is still rejected; rubber-stamping forbidden); the deterministic gates (tests + blocking SAST/SCA) still apply; at T3 the explanation is captured durably (comment/PR/ADR/test). **Build trigger:** a regulated-device / formal-IEC-62304 deployment requiring documented SOUP assessment or unaided comprehension ⇒ reinstate the strict bar. **Design record:** §4.4, §6.6, §10.
- **AI-authorship recorded at commit granularity by convention.** *Risk accepted 2026-06-18; owner: project maintainer.* The AI-vs-human distinction is commit-level via `Co-Authored-By`, not line/hunk-level, and not CI-enforced (MEFOR has no QMS of its own — §10). **Compensating controls:** the trailer + the PR thread + the PR tier-declaration. **Build trigger:** a trailer-format CI lint and a hunk-attribution mechanism (§9). **Design record:** §6.7, §9.
- **Automated requirement→design→test traceability not built (T3).** *Risk accepted 2026-06-18; owner: project maintainer.* **Compensating controls:** ADR ↔ test-name ↔ requirement links + the Plan artifact + the tier-declaration. **Build trigger:** the first regulated-release / adopter audit. **Design record:** §10, §9 (+ an ADR if cut).
- **SPDX-header enforcement by convention.** *Risk accepted 2026-06-18; owner: project maintainer.* No dedicated test asserts header presence. **Compensating controls:** convention + AI memory + the leak/forbidden scan. **Build trigger:** a trivial pytest walking first-party `.py`. **Design record:** §9.

---

## Cross-references & back-links

**Links out** (this doc → the docs graph): [`../CLAUDE.md`](../CLAUDE.md) (the operationalized standing contract) · [Secure Development Standards §A.6](Secure_Development_Standards.md#a6-documented-deviations), [PO.5](Secure_Development_Standards.md), [PW.7](Secure_Development_Standards.md) (bound via the **Standard ref** above) · [AI.md](AI.md) (out-of-scope product policy) · [PHI.md](PHI.md) (PO.5 no-real-PHI + treat-HL7-as-untrusted-data) · [WORKTREES.md](WORKTREES.md) · [security/RELEASE-GATE.md](security/RELEASE-GATE.md) (tag-time gate) · [docs/adr/README.md](adr/README.md).

**Back-link stubs to add** (reciprocal wiring): **FROM** [SDS §A.6](Secure_Development_Standards.md#a6-documented-deviations) — a pointer from the *Single-maintainer development* deviation to **this doc** as its detailed record; **FROM** [AI.md](AI.md) top / Future-direction — a one-line *"for the dev-process use of AI to BUILD MessageFoundry, see [Secure_AI_Development_Standards.md](Secure_AI_Development_Standards.md) — distinct from this product policy"*; a [docs/adr/README.md](adr/README.md) row if an ADR is cut; an entry in [FEATURE-MAP.md](FEATURE-MAP.md) if it enumerates security docs.

---

## Version history

| Version | Date | Change |
|---|---|---|
| 0.1 | June 18, 2026 | **Initial companion standard** — the `(project_scale × phi_touch)` **risk-tier matrix as the spine** (§4), the env-clamp **fail-closed tier resolver** with a recorded reason / PR tier-declaration, the **controls-as-dials master table** (§5), and the **embedded daily-loop Claude Code playbook** (§6, incl. *when NOT to use AI*, §6.8, and MCP/web-egress trust, §6.3). **Owns and expands the [SDS §A.6](Secure_Development_Standards.md#a6-documented-deviations) AI-assisted-review compensating-control deviation** (Appendix A.6). Honesty taxonomy applied to the dev-process toolchain (§9), including the SPDX-enforcement-by-convention and commit-granular-provenance gaps. |
