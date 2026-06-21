# Counsel Engagement Brief — Dual-Licensing & "Config-as-Separate-Work" Review (Backlog #13)

> **INTERNAL ENGAGEMENT-SCOPING ARTIFACT — NOT LEGAL ADVICE.** This document is prepared by the
> MessageFoundry project to scope and open a review with outside counsel. It states the project's
> own positions, drafts, and open questions; it is **not** a legal opinion, does not establish an
> attorney-client relationship by itself, and must not be relied on as legal advice. Nothing herein
> resolves any of the open questions it raises.
>
> - **Engagement opened:** 2026-06-19 (coordinator)
> - **Status:** **OPEN — awaiting counsel**
> - **Type:** doc-only (no code change). This brief only **opens** the engagement; recording
>   counsel's answers and flipping the posture out of "pending legal review" is a separate, later
>   close-out task (see §6).
> - **Cross-references:** [DUAL_LICENSING_PLAN.md](DUAL_LICENSING_PLAN.md) ·
>   [../CLA.md](../CLA.md) · [../COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md) ·
>   [ADR 0017 §6](adr/0017-consumer-deployment-model.md) ·
>   [BACKLOG.md #13](BACKLOG.md#13-licensing-posture--config-as-separate-work--commercial-edition-counsel-review-deferred-to-v02--accepted-risk)

---

## 1. Purpose & urgency

MessageFoundry ships open source under **AGPL-3.0-or-later** as an open-core project, with a planned
separate **commercial license** for organizations whose use falls outside the AGPL's terms. That
dual-licensing model rests on three legal positions the project has drafted but **never had reviewed
by counsel**: (a) the **CLA relicensing grant** that lets the steward offer commercial terms; (b) the
**commercial-license posture** itself; and (c) the **"config is a separate work"** position in
[ADR 0017 §6](adr/0017-consumer-deployment-model.md). This engagement asks counsel to review and
either ratify or revise all three, plus the supporting instruments.

The review is urgent for three reasons, and the timeline raises the stakes:

1. **It was a dated accepted risk, deferred from v0.1.** The formal counsel review was originally
   gated to precede publication. On **2026-06-17** the project owner recorded an **accepted-risk**
   decision deferring the review to the **v0.2** cycle and explicitly **not** gating v0.1.0 on it
   (ADR 0017 §6, "owner accepted-risk" note). This brief discharges that deferred obligation.

2. **It gates any commercial offering.** [COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md) is a
   posture/intent statement with **no binding terms** — grant scope, fees, support, and usage
   thresholds are all marked "not finalized." No commercial license can be offered until counsel has
   reviewed the grant scope and the relicensing chain that supplies the rights to grant.

3. **The posture is already public, precedent-setting, and effectively irreversible.** On
   **2026-06-18**, v0.1.0 was cut and **published** on the drafted AGPL-3.0-or-later posture
   (NOTICE, per-file SPDX, [CLA.md](../CLA.md), [COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md);
   landed in PR #350) **without** counsel sign-off. Publishing the release and reserving the package
   name is effectively irreversible, and it sets the licensing precedent adopters build on. Counsel
   is therefore **not** reviewing a pre-publication draft — counsel is reviewing an **already-public,
   precedent-setting** posture, which raises the cost of any required revision and makes a clear,
   prompt opinion more valuable.

---

## 2. Background — the engine's licensing posture

**Open core under AGPL-3.0-or-later.** The engine is distributed open source under
AGPL-3.0-or-later. Running the **unmodified** engine internally triggers no source-disclosure
obligation. The copyleft lever is **AGPL §13** (the network clause): an organization that **modifies**
the engine and then **network-operates** that modified version, or **redistributes** it, owes a
source offer to the users it interacts with over the network.

**The commercial edition rationale.** The §13 obligation is the basis for a separate **commercial
license**: an organization that wants to modify + network-operate or redistribute a modified engine
**without** satisfying the §13 source-offer, or wants to embed the engine in a proprietary product,
takes a commercial license instead of complying with AGPL §13. This is the standard open-core /
dual-licensing pattern. The current consumer-facing statement of who needs a commercial license is
[COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md); its binding terms are TBD (see §3).

**The CLA makes dual-licensing possible.** Dual-licensing only works if the steward holds the rights
to relicense **all** contributions — including ones it didn't author. The **CLA** ([CLA.md](../CLA.md))
supplies this: each contributor grants the steward a perpetual, irrevocable copyright license **plus**
an explicit right to **license and relicense** the contribution under any terms (including commercial),
while the contributor **retains** their own copyright. Without an enforceable relicensing grant from
every contributor (and every contributor's employer, where IP is employer-owned), the commercial
edition cannot lawfully include those contributions.

**The steward entity.** The licensor/steward is **"MessageFoundry Organization"**. The **name** is
decided (project decision of record). Its **registered legal form is not yet decided and is pending
counsel's input** — it is one of the open questions below, and it interacts with the CLA's
governing-law clause (§4, Q1 and Q5).

---

## 3. The artifact package counsel must review

All four artifacts have been read and digested. The table below states each artifact's path, its
current drafting state, and what specifically needs counsel's review.

| # | Artifact | Path | Current state | What needs review |
|---|----------|------|---------------|-------------------|
| A | Contributor License Agreement | [`CLA.md`](../CLA.md) | **Full template drafted; self-flagged as not legal advice.** 7 sections (Definitions, Copyright Grant §2, Patent Grant §3, Representations §4, No Obligation §5, Notice §6, Governing Law §7) + a sign-by-PR-comment mechanism. Adapted from the Apache Individual CLA with a **relicensing grant added**. | The whole instrument is unfinalized. Specifically: the §2 **relicensing grant** wording; the §3 **patent grant + defensive-termination** clause; the §7 **Iowa governing-law** choice; the **sign-by-comment** assent mechanism's enforceability; and the absence of any **Corporate CLA** for employer-owned IP. (See Q4, Q7, Q8, Q9, Q10.) |
| B | Commercial license posture | [`COMMERCIAL-LICENSE.md`](../COMMERCIAL-LICENSE.md) | **Posture/intent statement only; no binding terms.** States who does/doesn't need a commercial license and how to inquire. Banner + "What it would cover" mark **grant scope, fees, support, usage thresholds as not finalized**; "Nothing here is an offer, a contract, or legal advice." Carries the CLA and config-as-separate-work positions **by reference** as themselves pending. Dedicated contact channel TBD. | The **terms themselves** (grant scope, fees/support model, usage thresholds, warranty/indemnity), and confirmation that the open-core carve-out cleanly relieves the steward of its **own** AGPL §13 obligations when it operates a commercial/hosted modified engine. (See Q3, Q6, Q11.) |
| C | Deployment/ownership ADR — Decision #6 | [`docs/adr/0017-consumer-deployment-model.md`](adr/0017-consumer-deployment-model.md) | **Decision ratified 2026-06-16 as a project position; legal validation deferred to v0.2 under owner accepted-risk (2026-06-17).** Adopts the written position that Routers/Handlers loaded via `--config` are a **separate work**, not a derivative of the AGPL engine, backed by a **packaging boundary** (engine = non-editable pinned wheel; `--config` = separate tree the engine *loads but does not incorporate*). | The **central question of this engagement**: does the separate-work-vs-derivative determination hold, is the **packaging boundary** an adequate *legal* basis for it, and how should the position be **phrased for publication**? (See Q2.) |
| D | Dual-licensing plan + open-questions list | [`DUAL_LICENSING_PLAN.md`](DUAL_LICENSING_PLAN.md) | **Plan of record; enumerates six open legal questions.** | Source of the six questions in §4 (Q1, Q3, Q4, Q5, Q6, and the config question Q2). **Live inconsistency to resolve:** the plan's §Status still says "The public `0.1.0` release is **gated on counsel sign-off** of this posture," which **contradicts** ADR 0017 §6's 2026-06-17 accepted-risk note (review deferred to v0.2; v0.1.0 shipped **without** sign-off). The plan doc is **stale** relative to the ratified ADR; counsel need not opine on this, but it is flagged so the close-out (§6) reconciles the two. |

---

## 4. Questions for counsel

Each question is numbered, specific, and answerable, with the context counsel needs. Q1–Q6 restate
(in substance) the six open questions already enumerated in
[DUAL_LICENSING_PLAN.md](DUAL_LICENSING_PLAN.md); **Q2** is the central config-as-separate-work
question; **Q7–Q11** are additional items surfaced while assembling this package.

### The six questions from DUAL_LICENSING_PLAN.md

**Q1 — Registered legal form of the steward.**
The licensor/steward name "MessageFoundry Organization" is decided, but its **registered legal form
is not**. What entity form (e.g., a specific LLC, nonprofit, foundation, or fiscal-sponsorship
arrangement) should hold the copyright, receive the CLA grants, and offer the commercial license, and
in **which jurisdiction** should it be formed? The answer drives Q5 (governing-law alignment) and the
NOTICE/copyright attribution.

**Q2 — Does the "config is a separate work" position hold, and how should it be phrased for
publication?**
ADR 0017 §6 adopts the position that an adopter's Connections/Routers/Handlers loaded via `--config`
are a **separate work**, not a **derivative work** of the AGPL engine — so authoring **private**
integration logic in `--config` does **not** trigger AGPL copyleft on that config. The asserted basis
is a **packaging boundary**: the engine ships as a **non-editable, pinned wheel**, and the `--config`
repo is a separate, separately-versioned tree the engine **loads but does not incorporate** into its
own distribution. ADR 0017 itself records that this separate-work-vs-derivative determination is
**"legally undefined."** Counsel is asked to:
  - (a) assess whether, under AGPL-3.0 and applicable derivative-work doctrine, config authored
    against the engine's documented extension surface (the `inbound`/`outbound`/`@router`/`@handler`/
    `Send`/`Message` API) and **loaded at runtime** by a pinned, non-editable wheel is more
    persuasively a **separate work** or a **derivative work**;
  - (b) opine on whether the **packaging boundary** (non-editable wheel + loaded-not-incorporated
    config) is a sufficient *legal* basis for the separate-work claim, or whether it is merely a
    technical arrangement that does not by itself control the legal characterization;
  - (c) provide **publishable phrasing** for the position that the project can put in adopter-facing
    docs without overclaiming, including any conditions or caveats that should accompany it.

**Q3 — Commercial-license terms.**
[COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md) intentionally leaves the terms open. What should the
commercial license's **grant scope** be (what it permits beyond AGPL — e.g., modify + network-operate
without §13 source-offer, redistribution, proprietary embedding), and what is counsel's guidance on
the **fee/support structure, any usage thresholds** that trigger the requirement, and the
**warranty/indemnity** posture appropriate for a healthcare-integration engine carrying PHI?

**Q4 — Review and finalization of the CLA text.**
Is the CLA ([CLA.md](../CLA.md)), as a whole, sound and enforceable as drafted? The instrument is
adapted from the Apache Individual CLA with an **added relicensing grant** (§2) and is self-flagged as
an unreviewed template. Counsel is asked to confirm or revise the full text and identify any clause
that should be added, removed, or rewritten before the project relies on it.

**Q5 — Governing-law / jurisdiction alignment.**
CLA §7 names **"the State of Iowa, United States of America"** as governing law. Does that choice
align with the steward entity's **actual formation** (Q1)? If the entity is formed elsewhere, should
the CLA's governing-law and any forum/venue provisions be changed to match, and is Iowa an appropriate
choice for the contributor-facing agreement regardless of the entity's formation state?

**Q6 — Dedicated commercial-licensing contact channel.**
[COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md) currently routes inquiries to a maintainer handle
and says a "dedicated commercial-licensing contact address will be published when the offering is
finalized." What contact channel (and any associated intake/record-keeping for license inquiries and
executed agreements) does counsel recommend establishing before the offering goes live?

### The additional questions surfaced while assembling this package

**Q7 — No Corporate/Entity CLA exists; the employer-IP chain is incomplete.**
CLA §4.3 contemplates that an employer "has executed a **separate Corporate CLA** with the Project,"
but **no Corporate CLA (CCLA) artifact exists** in the repository. Many anticipated contributors are
employed by healthcare organizations where contributions are **employer-owned IP**. Without a CCLA,
is the §2 relicensing grant from an individual contributor actually **enforceable against
employer-owned** contributions, and does the project need a CCLA instrument (and an intake process for
it) to make the dual-licensing rights chain complete? Counsel is asked to advise whether to draft a
CCLA and what it must contain.

**Q8 — Enforceability of the sign-by-PR-comment acceptance mechanism.**
CLA §"How to sign" binds a contributor by a **GitHub pull-request comment** ("I have read the CLA and
I agree to its terms"). Independent of the **text** (Q4), does a GitHub-comment assent form an
**enforceable agreement** that actually transfers the §2 relicensing rights — considering
contract-formation requirements such as identity verification, the signer's capacity/authority,
consideration, and durable record-keeping of who agreed to which version when? If not sufficient,
what mechanism does counsel recommend (e.g., a CLA bot with versioned records, a signed instrument for
significant contributors)?

**Q9 — Patent grant scope and defensive-termination clause (unreviewed).**
CLA §3 grants a patent license and includes a **defensive-termination** trigger ("If any entity
institutes patent litigation … any patent licenses granted under this Agreement for that Contribution
terminate"). The plan's six questions never address the patent grant. Counsel is asked to review §3's
**scope** and its termination trigger, and to confirm its interaction with **AGPL-3.0's own patent
provisions** and with the **commercial edition** (i.e., whether the commercial license needs its own
patent grant or relies on §3).

**Q10 — The steward's own AGPL §13 obligations under the commercial/open-core model.**
ADR 0017 §6 and [COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md) frame AGPL §13 only from the
**adopter's** side. If **MessageFoundry Organization** itself operates a **hosted or commercial**
offering of a **modified** engine, does the steward satisfy **its own** §13 source-offer, and does the
open-core structure (steward holds all relicensing rights via the CLA) cleanly relieve the steward of
the §13 obligation the AGPL would otherwise impose on it? Counsel is asked to confirm the steward's
own compliance posture in the open-core model.

**Q11 — Inbound-dependency license compatibility with both outbound licenses *(flag; confirm if in
scope)*.**
An AGPL distribution that **also** offers a proprietary/commercial edition needs every bundled
third-party dependency to be license-compatible with **both** outbound licenses (AGPL **and**
commercial). This is not raised in the four artifacts and may be out of scope for this engagement.
Counsel is asked to **confirm whether** a dependency-stack (SOUP) license-compatibility review is
within scope; if so, it should be handled as a separate, defined deliverable.

---

## 5. Scope & deliverable

**In scope — what counsel returns.** A **written opinion** that, for each of Q1–Q11 (Q11 only if
counsel confirms it in scope), either **ratifies** the project's current position or **revises** it
with the corrected position and the reasoning. The opinion must be specific enough that the project
can:

- finalize or revise the **CLA** text, its **patent** and **governing-law** clauses, and its
  **acceptance mechanism** (Q4, Q9, Q5, Q8), and decide whether a **Corporate CLA** is required (Q7);
- state a defensible, **publishable** "config is a separate work" position with agreed phrasing and
  caveats (Q2);
- establish the steward's **registered legal form** and reconcile it with governing law (Q1, Q5);
- set the **commercial-license terms** (grant scope, fee/support model, usage thresholds,
  warranty/indemnity) and the steward's **own §13** posture (Q3, Q10), and stand up the
  **contact/intake** channel (Q6);
- and thereby **flip** [ADR 0017 §6](adr/0017-consumer-deployment-model.md) and
  [DUAL_LICENSING_PLAN.md](DUAL_LICENSING_PLAN.md) out of **"pending legal review."**

**Out of scope.**

- **Implementing** the answers — drafting the final commercial-license contract, forming the entity,
  rewriting the CLA, or building any intake tooling. Counsel's deliverable is the **opinion + revised
  language**; the project performs the close-out (§6).
- Anything **beyond licensing**: corporate formation mechanics, tax, employment, HIPAA/PHI compliance,
  trademark, and export are **not** part of this engagement except where they directly bear on a
  numbered question (e.g., entity form in Q1).
- The **dependency-stack license review (Q11)** unless counsel affirmatively brings it in scope; by
  default it is a separate engagement.
- This brief takes **no code change** and makes **no commitment** to launch the commercial offering;
  that decision is part of the close-out (§6).

---

## 6. What changes after counsel responds (close-out — a later Lane L task, **not** this brief)

This brief **only opens** the engagement. Recording counsel's answers and acting on them is a
**separate, later** task (Lane L). For clarity, the artifacts that would move in that close-out are:

- [`DUAL_LICENSING_PLAN.md`](DUAL_LICENSING_PLAN.md) — record each answer; remove the
  "pending legal review" status; and **reconcile the stale §Status line** that still says v0.1.0 is
  "gated on counsel sign-off" with the 2026-06-17 accepted-risk reality (review deferred to v0.2,
  v0.1.0 shipped without sign-off).
- [`docs/adr/0017-consumer-deployment-model.md`](adr/0017-consumer-deployment-model.md) §6 — replace
  the accepted-risk/deferred note with counsel's ratified or revised determination on the
  config-as-separate-work position, plus the agreed publishable phrasing.
- [`CLA.md`](../CLA.md) — apply any revisions to the relicensing grant (§2), patent clause (§3),
  governing law (§7), and the acceptance mechanism; add a **Corporate CLA** instrument if counsel
  directs (Q7); and remove the "not yet reviewed" banner once finalized.
- [`COMMERCIAL-LICENSE.md`](../COMMERCIAL-LICENSE.md) — replace the TBD terms with the
  counsel-reviewed grant scope, fee/support model, usage thresholds, and warranty/indemnity; publish
  the dedicated contact channel.
- [`BACKLOG.md` #13](BACKLOG.md#13-licensing-posture--config-as-separate-work--commercial-edition-counsel-review-deferred-to-v02--accepted-risk) —
  close out the item once the above land.
- **A go/no-go decision on launching the commercial offering** — made by the owner on the basis of
  counsel's opinion; recorded wherever commercial-offering decisions live.

None of the above happens in this brief. This document's only effect is to **open** the engagement.

---

## 7. Engagement log

| Date | Event | Actor |
|------|-------|-------|
| 2026-06-19 | Engagement opened / brief authored | coordinator |
