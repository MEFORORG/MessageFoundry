# Contributor Program — decision record & community plan

> **Status: Decision made (2026-07).** `MEFORORG/MessageFoundry` is the **single active development
> repository**. The former one-way publish pipeline is **retired**, and the previously-private
> `wshallwshall/MessageFoundry` is retained only as an **inactive, read-only archive** (never deleted;
> it holds the full history and internal-only material). This document records that decision and the
> community/governance plan that follows from it. Community go-live is still sequenced against the
> **v0.1 "enterprise-ready" milestone** (see the v0.1 release plan and
> [`EARLY-ADOPTER-GUIDE.md`](EARLY-ADOPTER-GUIDE.md)).

---

## 0. The question this answers

> "How do we go beyond one solo developer — let other people file issues, propose changes, and
> eventually co-maintain MessageFoundry — **without** leaking PHI/customer data, without diluting the
> architecture, and without creating maintainer work a single person can't sustain?"

Three forces pull against each other and shape every decision below:

1. **PHI/healthcare safety.** This engine carries PHI. Outside contributors must *never* be able to see
   real PHI or customer connection data. The repository is PHI-clean **by construction** — real
   migration/customer data lives in a *separate, git-ignored* location and is never tracked here.
2. **Architectural integrity.** The "no channel object", code-first Router/Handler model, the
   reliability invariants, and the PHI guardrails are easy to erode with well-meaning PRs. Contribution
   is gated on understanding, not just green CI.
3. **Solo-maintainer bandwidth.** One person cannot absorb unbounded triage, review, and community
   management. Every process below is runnable by **one** maintainer and *scales down* gracefully, then
   adds a second maintainer deliberately.

---

## 1. The repository model (decided)

Development happens **in the open** on `MEFORORG/MessageFoundry`. Outside PRs are ordinary GitHub PRs
against `main`; there is no snapshot/mirror boundary to bridge and no SHA divergence. The whole PHI
air-gap therefore rests on the always-on leak gate holding **100% of the time**: the
`forbidden-content` scan (with `gitleaks`) runs as a **required PR check** and on `main`, fail-closed,
so an inbound PR carrying a secret, routable IP, or customer string fails *before* a human reads it.
Treat any bypass of that gate as a Sev-1.

This is the only model with a *standard, sustainable* contribution flow — full Issues / PRs /
Discussions / Projects on one repo, no per-PR replay cost. The tradeoff (no snapshot "air gap") is
accepted and mitigated by the required leak gate above and the PHI rules in §5.

---

## 2. Where we are today (inventory)

**Already built — reuse, don't recreate:**

| Area | Status | File |
|---|---|---|
| License | ✅ AGPL-3.0-or-later (network/§13 copyleft) | [`LICENSE`](../LICENSE) |
| Contributing guide | ✅ license, CLA, dev workflow, PHI rules, conventions | [`CONTRIBUTING.md`](../CONTRIBUTING.md) |
| CLA (individual) | ⚠️ template, **needs lawyer review**; enables open-core relicensing | [`CLA.md`](../CLA.md) |
| CLA enforcement | ✅ CLA Assistant bot wired | `.github/workflows/cla.yml` |
| Security policy | ✅ private disclosure + remediation SLAs | `.github/SECURITY.md` |
| Issue templates | ✅ bug / feature / config | `.github/ISSUE_TEMPLATE/` |
| CI / security gates | ✅ tests/lint/types + bandit/semgrep/gitleaks + required leak gate | `.github/workflows/{ci,security}.yml`, [`docs/CI.md`](CI.md) |
| Dependabot | ✅ | `.github/dependabot.yml` |
| Code of Conduct | ✅ Contributor Covenant | [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) |

**Missing — the governance & community layer this plan tracks:**

- `GOVERNANCE.md` — who decides, how, and the maintainer ladder (§3).
- `MAINTAINERS.md` / `CODEOWNERS` — who owns which subsystem; bus-factor plan.
- `.github/PULL_REQUEST_TEMPLATE.md` — the contributor's pre-merge checklist.
- A public **roadmap** + curated **`good first issue` / `help wanted`** on-ramp.
- A **support/discussion** channel (GitHub Discussions) distinct from the issue tracker.
- A **triage cadence** and labeling scheme.
- Contributor **recognition** (CONTRIBUTORS file / all-contributors).

---

## 3. Governance model

A solo project needs an *honest* governance doc, not a pretend committee. Proposed `GOVERNANCE.md`:

- **Model: BDFL / single steward, explicitly.** The owner is the sole maintainer and final
  decision-maker today. Say so plainly.
- **Decision-making:** *lazy consensus* on issues/PRs (silence = assent after a stated window); the
  steward breaks ties. **Architectural changes go through an ADR** (`docs/adr/`) — ADR-or-it-didn't-
  happen for anything touching the invariants.
- **The maintainer ladder** (how trust is earned, so the bus factor can grow deliberately):
  1. **Contributor** — anyone with a merged PR.
  2. **Triager** — issue/PR labeling + triage rights, earned by sustained accurate triage help.
  3. **Maintainer (committer)** — merge rights to a subsystem via `CODEOWNERS`, earned by a track
     record of high-quality PRs *and* good review judgment; requires the steward's invitation.
  4. **Steward** — the owner; holds admin, release, security-advisory, and tie-break authority.
- **Bus factor is a named risk.** A single steward is a single point of failure for security advisories
  and releases. Goal: recruit **one** trusted second maintainer before review volume makes solo review
  the bottleneck. Track this as an explicit milestone.
- **Scope boundaries for contributions:**
  - **Welcome:** bug fixes w/ tests, new **Connections/transports** (registry-pluggable by design),
    docs, example Routers/Handlers, generators, test coverage, perf with benchmarks.
  - **Discuss-first (ADR/issue before code):** anything touching the reliability invariants, the
    store/queue, auth/RBAC, the staged pipeline, or the "no channel object" model.
  - **Out of scope:** re-introducing a declarative "channel"/"route" element; YAML-for-logic; Black;
    PyQt; GUI imports in the engine; anything that weakens PHI guardrails.

---

## 4. The contributor experience (artifacts to create)

Each is small; none is engine code:

1. **`GOVERNANCE.md`** — §3 above.
2. **`MAINTAINERS.md` + `.github/CODEOWNERS`** — start with the steward owning everything; pre-mark the
   *sensitive* paths (`messagefoundry/auth/`, `store/`, `transports/`, `api/security*`, the security
   policy, and `scripts/security/`) so that when a 2nd maintainer joins, sensitive review still routes
   to the steward.
3. **`.github/PULL_REQUEST_TEMPLATE.md`** — checklist: *tests added; gates green
   (`python -m messagefoundry check`); no real PHI; CLA agreed; docs/ADR updated if
   behavior/architecture changed; uses Connection/Router/Handler vocabulary; no new
   declarative-channel / GUI-in-engine / Black.*
4. **Labels + on-ramp** — `good first issue`, `help wanted`, `needs triage`, `discuss-first`,
   `area:*` (transport/store/api/console/parsing/auth/docs). Curate **5–10 genuinely small** first
   issues before announcing — an empty on-ramp kills momentum.
5. **Public roadmap** — largely in place (the README roadmap, [`FEATURE-MAP.md`](FEATURE-MAP.md), and
   the built-vs-experimental map in [`EARLY-ADOPTER-GUIDE.md`](EARLY-ADOPTER-GUIDE.md)); optionally add
   a GitHub Projects board.
6. **GitHub Discussions** — enable as the Q&A/design forum, distinct from Issues (bugs/features) and
   Security advisories (vulns). Keep everything on GitHub for auditability; defer chat.
7. **Contributor recognition** — a `CONTRIBUTORS` file or the all-contributors bot; credit security
   reporters per the existing security policy.
8. **Refresh `CONTRIBUTING.md`** — the `python -m messagefoundry check` gate, the triage/label legend,
   a pointer to GOVERNANCE / Code of Conduct / [`docs/CI.md`](CI.md), and the "discuss-first" scope
   boundaries from §3.

---

## 5. PHI / security guardrails for outside contributors (non-negotiable)

This is a healthcare engine; these are hard gates, not nice-to-haves.

- **Contributors only ever touch the PHI-clean repo.** The repository contains zero PHI/customer data
  *by construction* (migration artifacts stay in a separate git-ignored location). Reaffirm this in
  CONTRIBUTING + Code of Conduct: **no real PHI or customer data in issues, PRs, tests, fixtures, or
  screenshots — synthetic HL7 only** (`messagefoundry generate`).
- **The forbidden-content scan is required CI on inbound PRs.** `scan_forbidden.py` + `gitleaks` run as
  **required PR checks** (and on `main`), fail-closed, so an outside PR carrying a secret/IP/customer
  string fails *before* a human reads it. Fork PRs run with minimal token scope so they can't exfiltrate
  secrets; the real token list is never committed (it loads from a git-ignored local file plus an
  Actions secret).
- **Executed-Python config is a trust boundary.** Routers/Handlers are *code that runs in-process*.
  Example-config contributions get read with that in mind; never auto-execute untrusted contributed
  config in CI without sandboxing. Document this in the PR review checklist.
- **Security disclosure stays private** (existing `.github/SECURITY.md`). Do **not** route vulns through
  public issues/Discussions. The advisory team must reach **≥2 people** once a second maintainer exists
  (today: steward only — a known single-point risk).
- **CLA before first merge** (already enforced by the bot). **Gate:** the CLA and the entity it names
  should get a **lawyer review** before the program is announced.
- **Branch protection, contributor-mode.** Today protections are tuned for a solo dev (CI-gated, no
  required human review — a solo dev can't self-approve). When contributions open: require **≥1
  maintainer approval on external PRs**, keep all CI checks + CLA required, require **CODEOWNERS review
  on sensitive paths**, keep "no direct push to `main`", and retain a **logged** admin-bypass for solo
  emergencies.

---

## 6. Triage & sustainability (so one person can run this)

- **Weekly triage pass**, time-boxed: label new issues, close stale/dupes, tag `good first issue`.
- **Response SLA you can actually keep:** acknowledge new issues/PRs within ~1 week; be explicit that
  this is a small project so reviews may take time. Under-promise.
- **Bots do the toil:** CLA Assistant (have), Dependabot (have); add **stale-bot** for abandoned
  issues/PRs and optionally triage/label automation.
- **"Discuss-first" deflects expensive PRs early** — the label + scope boundaries in §3 stop a
  contributor spending a weekend on something that will be declined on principle.
- **ADR discipline scales review:** if the rationale is written down, you re-explain it by linking, not
  retyping.

---

## 7. Community rollout (sequenced against v0.1)

**Phase 0 — Foundation.** Create the *paper* governance layer: `GOVERNANCE.md`, `MAINTAINERS.md`,
`CODEOWNERS`, `PULL_REQUEST_TEMPLATE.md`, refreshed `CONTRIBUTING.md`. Get the **CLA lawyer-reviewed**.
*Exit gate:* docs merged; CLA legally cleared.

**Phase 1 — Open the front door (issues/discussions).** Enable **Discussions** + public **issue**
intake; publish the roadmap; curate the first `good first issue` set. This builds signal and surfaces a
possible second maintainer at near-zero risk.
*Exit gate:* v0.1 GA tagged; the v0.1 hard gates (PHI log redaction, no "experimental" backends,
published throughput baseline, off-loopback/TLS) met per the v0.1 release plan.

**Phase 2 — Open code contribution.** Apply contributor-mode branch protection (§5); announce "open for
contributions".
*Exit gate:* `scan_forbidden`/gitleaks green as required PR checks; contributor-mode protections live;
first external PR merged end-to-end as a dry run.

**Phase 3 — Grow the bus factor.** Identify and invite a **second maintainer**; populate
`CODEOWNERS`/`MAINTAINERS.md`; bring them onto the security-advisory team. Revisit governance (BDFL →
small maintainer team) only if/when volume warrants.
*Exit gate:* a second maintainer has merge rights and advisory access.

---

## 8. Owner decisions still open

1. **CLA lawyer review** — clear the [`CLA.md`](../CLA.md) template and confirm the entity it names,
   **before** the program is publicly announced. (Not a blocker for merging the Phase 0 governance docs.)
2. **Communication surface** — GitHub Discussions only (recommended) vs. add chat now.
3. **Second maintainer** — identify a candidate to begin Phase 3.

---

## 9. Open questions / risks

- **AGPL + open-core friction.** The AGPL §13 + relicensing CLA is a deliberate open-core posture; some
  contributors decline CLAs on principle. Accept a (likely small) contributor-pool cost.
- **Single security-advisory contact** is a real single point of failure until Phase 3.
- **The PHI air-gap rests entirely on the CI leak gate** holding 100% of the time. The gate is
  fail-closed; treat any bypass as a Sev-1.
- **Contributions vs. the fork-based component SDK vision:** the long-term model is a read-only SDK
  users *fork to customize*. Clarify for contributors what belongs **upstream** (core engine,
  transports, fixes) vs. what is a **downstream fork** (their site-specific Routers/Handlers).
