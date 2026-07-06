# Contributor Program Plan — from solo developer to an open contributor community

> **Status: Draft for owner review.** This is a *plan*, not an implementation. No governance
> files, workflow changes, or repo settings are created until the owner says "go". Authored in the
> `planning-contributors` worktree (branch `planning-contributors`).
>
> **As-of:** authored against `main` @ `9866a97` (2026-06-14); `main` has since advanced. Contributor
> go-live is sequenced against the **v0.1 "enterprise-ready" milestone** (see the
> [v0.1 release plan](releases/v0.1-PLAN.md) and [`EARLY-ADOPTER-GUIDE.md`](EARLY-ADOPTER-GUIDE.md)).

---

## 0. The question this answers

> "How do we go beyond one solo developer — let other people file issues, propose changes, and
> eventually co-maintain MessageFoundry — **without** leaking PHI/customer data, without diluting the
> architecture, and without creating maintainer work a single person can't sustain?"

Three forces pull against each other and shape every decision below:

1. **PHI/healthcare safety.** This engine carries PHI. The private repo was made private on
   2026-06-10 after customer data once leaked into a public repo. Outside contributors must
   *never* be able to see real PHI or customer connection data.
2. **Architectural integrity.** The "no channel object", code-first Router/Handler model, the
   reliability invariants, and the PHI guardrails are easy to erode with well-meaning PRs. Contribution
   has to be gated on understanding, not just green CI.
3. **Solo-maintainer bandwidth.** One person cannot absorb unbounded triage, review, and community
   management. Every process below is designed to be runnable by **one** maintainer and to *scale down*
   gracefully, then add a second maintainer deliberately.

---

## 1. Where we are today (inventory)

**Already built — reuse, don't recreate:**

| Area | Status | File |
|---|---|---|
| License | ✅ AGPL-3.0-or-later (network/§13 copyleft) | [`LICENSE`](../LICENSE) |
| Contributing guide | ✅ license, CLA, dev workflow, PHI rules, conventions | [`CONTRIBUTING.md`](../CONTRIBUTING.md) |
| CLA (individual) | ⚠️ template, **needs lawyer review**; enables open-core relicensing | [`CLA.md`](../CLA.md) |
| CLA enforcement | ✅ CLA Assistant bot wired | `.github/workflows/cla.yml` |
| Security policy | ✅ private disclosure + remediation SLAs | `.github/SECURITY.md` |
| Issue templates | ✅ bug / feature / config | `.github/ISSUE_TEMPLATE/` |
| CI / security gates | ✅ quartet (ruff/format/mypy/pytest) + bandit/gitleaks | `.github/workflows/{ci,security}.yml` |
| Dependabot | ✅ | `.github/dependabot.yml` |
| Public OSS mirror | ✅ one-way curated snapshot, fail-closed scan gate | `scripts/publish/` |

**Missing — the governance & community layer this plan adds:**

- ❌ `CODE_OF_CONDUCT.md` (table stakes for any public project; GitHub surfaces its absence)
- ❌ `GOVERNANCE.md` — who decides, how, and the maintainer ladder
- ❌ `MAINTAINERS.md` / `CODEOWNERS` — who owns which subsystem; bus-factor plan
- ❌ `.github/PULL_REQUEST_TEMPLATE.md` — the contributor's pre-merge checklist
- ❌ A public **roadmap** + curated **`good first issue` / `help wanted`** on-ramp
- ❌ A **support/discussion** channel (GitHub Discussions) distinct from the issue tracker
- ❌ A **triage cadence** and labeling scheme
- ❌ Contributor **recognition** (CONTRIBUTORS file / all-contributors)
- ❌ **The defined inbound path** for outside PRs (see §2 — the crux)

---

## 2. The crux: the repo model (owner decision #1)

This is the **single most important decision** and everything downstream depends on it.

Today the topology is **private-primary + one-way public mirror**:

- `MEFORORG/MessageFoundry` (**private**) is the source of truth.
- `MEFORORG/MessageFoundry` (**public**) is a *history-free, curated snapshot* produced by
  `scripts/publish/publish.ps1` — it shares **no SHAs** with the private repo and is **publish-only**.

**The problem:** there is **no inbound path**. A contributor can only see and PR the *public mirror*,
but the mirror is regenerated wholesale on each publish — an outside PR against it has nowhere to go
and would be obliterated on the next snapshot. You cannot run a contributor program on a publish-only
mirror. One of three models must be chosen:

### Option A — Flip to public-primary *(recommended, at the v0.1 tag)*
Make `MEFORORG/MessageFoundry` the **real development repo**. The owner develops in the open; outside
PRs are ordinary GitHub PRs. Retire the one-way publish flow for OSS dev; keep a *private* repo only
for commercial/customer-specific artifacts if any exist.

- **Why it works here:** the repo is already **PHI-clean by construction** — real migration/customer
  data lives in the *separate* git-ignored `migration-local/` repo, never in the engine repo. The
  `publish.ps1` curation (deny-list, slug rewrite) is a small, one-time fold-in.
- **Pro:** the only model with a *standard, sustainable* contribution flow. No bridge to maintain, no
  SHA divergence, full issue/PR/Discussions/Projects on one repo.
- **Con:** loses the snapshot "air gap"; discipline (the `scan_forbidden.py` + gitleaks pre-push gate,
  now run as required CI) must hold permanently. Mitigated — see §5.
- **Recommended timing:** flip **at the v0.1 GA tag**, not before (see §7). Pre-v0.1, solo velocity
  matters more than openness.

### Option B — Keep dual-repo, build an inbound bridge
Contributors PR the public mirror; a defined process replays accepted public PRs onto private `main`,
then re-publishes.
- **Pro:** preserves the snapshot air gap.
- **Con:** every accepted PR is hand-replayed across a SHA boundary (contributor loses authorship
  continuity, `git blame` fractures, attribution is manual). **High per-PR maintainer cost** — the
  opposite of what a solo maintainer needs. Not recommended.

### Option C — Stay private-primary, closed to outside code (status quo+)
Accept *issues and discussions* publicly but keep code contribution closed until later.
- **Pro:** zero new risk; lets you build community/feedback before opening code.
- **Con:** not actually a contributor program for *code*; defers the real decision.
- **Use as:** the **interim** state between now and the Option-A flip (see §7, Phase 0–1).

> **Recommendation:** **C now → A at v0.1.** Open *issues/discussions* immediately (low risk, builds
> signal), and **flip to public-primary at the v0.1 tag** so code contribution opens on a sustainable
> topology. Reject Option B — the bridge cost is unsustainable for a solo maintainer.

---

## 3. Governance model (owner decision #2)

A solo project needs an *honest* governance doc, not a pretend committee. Proposed `GOVERNANCE.md`:

- **Model: BDFL / single steward, explicitly.** The owner is the sole maintainer and final
  decision-maker today. Say so plainly — pretending otherwise erodes trust faster than honesty.
- **Decision-making:** *lazy consensus* on issues/PRs (silence = assent after a stated window); the
  steward breaks ties. **Architectural changes go through an ADR** (the project already uses
  `docs/adr/` — make ADR-or-it-didn't-happen the rule for anything touching the invariants).
- **The maintainer ladder** (how trust is earned, so the bus factor can grow deliberately):
  1. **Contributor** — anyone with a merged PR.
  2. **Triager** — issue/PR labeling + triage rights. Earned by sustained, accurate triage help.
  3. **Maintainer (committer)** — merge rights to a subsystem via `CODEOWNERS`. Earned by a track
     record of high-quality PRs *and* good review judgment. Requires the steward's invitation.
  4. **Steward** — the owner; holds admin, release, security-advisory, and tie-break authority.
- **Bus factor is a named risk.** A single steward means a single point of failure for security
  advisories and releases. Goal: recruit **one** trusted second maintainer before contribution volume
  makes solo review the bottleneck — *and* before relying on the security-advisory process (a private
  advisory team of one is fragile). Track this as an explicit milestone, not a someday.
- **Scope boundaries for contributions** (set expectations up front to avoid heartbreak PRs):
  - **Welcome:** bug fixes w/ tests, new **Connections/transports** (registry-pluggable by design),
    docs, example Routers/Handlers, generators, test coverage, perf with benchmarks.
  - **Discuss-first (ADR/issue before code):** anything touching the reliability invariants, the
    store/queue, auth/RBAC, the staged pipeline, or the "no channel object" model.
  - **Out of scope:** re-introducing a declarative "channel"/"route" element; YAML-for-logic; Black;
    PyQt; GUI imports in the engine; anything that weakens PHI guardrails.

---

## 4. The contributor experience (artifacts to create)

On "go", create these (each is small; none is engine code):

1. **`CODE_OF_CONDUCT.md`** — adopt **Contributor Covenant v2.1** verbatim; enforcement contact =
   the steward's security/abuse email. (Lowest-effort, highest-signal community artifact.)
2. **`GOVERNANCE.md`** — §3 above.
3. **`MAINTAINERS.md` + `.github/CODEOWNERS`** — start with the steward owning everything; pre-mark
   the *sensitive* paths (`messagefoundry/auth/`, `store/`, `transports/`, `api/security*`,
   `docs/SECURITY.md`, `docs/Secure_Development_Standards.md`, `scripts/publish/`) so that when a 2nd
   maintainer joins, sensitive review still routes to the steward.
4. **`.github/PULL_REQUEST_TEMPLATE.md`** — checklist: *tests added; quartet green
   (`messagefoundry check`); no real PHI; CLA agreed; docs/ADR updated if behavior/architecture
   changed; uses Connection/Router/Handler vocabulary; no new declarative-channel/GUI-in-engine/Black*.
5. **Labels + on-ramp** — `good first issue`, `help wanted`, `needs triage`, `discuss-first`,
   `area:*` (transport/store/api/console/parsing/auth/docs). Curate **5–10 genuinely small**
   first issues before announcing — an empty on-ramp kills momentum.
6. **Public roadmap** — largely in place already (the README roadmap, [`FEATURE-MAP.md`](FEATURE-MAP.md),
   and the built-vs-experimental map in [`EARLY-ADOPTER-GUIDE.md`](EARLY-ADOPTER-GUIDE.md)); optionally
   add a GitHub Projects board so contributors can see what's actively being worked on.
7. **GitHub Discussions** — enable as the Q&A/design forum, distinct from Issues (bugs/features) and
   Security advisories (vulns). Keep everything on GitHub for auditability; defer chat (Discord/Slack).
8. **Contributor recognition** — a `CONTRIBUTORS` file or the all-contributors bot; credit security
   reporters per the existing SECURITY.md.
9. **Refresh `CONTRIBUTING.md`** — add: the `python -m messagefoundry check` gate (already mentioned),
   the worktree workflow ([`WORKTREES.md`](WORKTREES.md)) for parallel work, the triage/label legend,
   a pointer to GOVERNANCE/Code of Conduct, and the "discuss-first" scope boundaries from §3.

---

## 5. PHI / security guardrails for outside contributors (non-negotiable)

This is a healthcare engine; these are hard gates, not nice-to-haves.

- **Contributors only ever touch the PHI-clean repo.** Under Option A the public repo contains zero
  PHI/customer data *by construction* (migration artifacts stay in the separate git-ignored repo).
  Reaffirm this boundary in CONTRIBUTING + Code of Conduct: **no real PHI or customer data in issues,
  PRs, tests, fixtures, or screenshots — synthetic HL7 only** (`messagefoundry generate`).
- **The forbidden-content scan becomes required CI on inbound PRs.** Today `scan_forbidden.py` +
  gitleaks run as a *pre-publish* gate. Re-wire them as a **required PR check** (and on `main`) so an
  outside PR carrying a secret/IP/customer string fails closed *before* a human reads it. Run untrusted
  PRs with `pull_request_target` hardening / minimal token scope so fork PRs can't exfiltrate secrets.
- **Executed-Python config is a trust boundary.** Routers/Handlers are *code that runs in-process*.
  Example-config contributions get read with that in mind; never auto-execute untrusted contributed
  config in CI without sandboxing. Document this in the PR review checklist.
- **Security disclosure stays private** (existing SECURITY.md). Do **not** route vulns through public
  issues/Discussions. The advisory team must reach **≥2 people** once a second maintainer exists
  (today: steward only — note it as a known single-point risk).
- **CLA before first merge** (already enforced by the bot). **Gate:** the CLA + the "MessageFoundry
  Organization" entity it names should get a **lawyer review** before the program is announced (the
  CLA.md template already flags this). Tie this to the open-core/commercial intent.
- **Branch protection, contributor-mode.** Today protections are tuned for a solo dev (CI-gated, no
  required human review — a solo dev can't self-approve). When contributions open: require **≥1
  maintainer approval on external PRs**, keep all CI checks + CLA required, require **CODEOWNERS review
  on sensitive paths**, keep "no direct push to `main`", and retain a **logged** admin-bypass for
  solo emergencies. (See [[mf-solo-developer]] memory — this supersedes the "no required reviews"
  guidance *once there is someone other than the owner to review*.)

---

## 6. Triage & sustainability (so one person can run this)

- **Weekly triage pass**, time-boxed: label new issues, close stale/dupes, tag `good first issue`.
- **Response SLA you can actually keep:** acknowledge new issues/PRs within ~1 week; be explicit in
  CONTRIBUTING that this is a small project so reviews may take time. Under-promise.
- **Bots do the toil:** CLA Assistant (have), Dependabot (have); add **stale-bot** for abandoned
  issues/PRs and optionally a triage/label automation. Every bot added is maintainer time returned.
- **"Discuss-first" deflects expensive PRs early** — the label + scope boundaries in §3 stop a
  contributor from spending a weekend on something that will be declined on principle.
- **ADR discipline scales review:** if the architecture rationale is written down, you re-explain it
  by linking, not retyping.

---

## 7. Phased rollout (sequenced against v0.1)

Each phase has an explicit entry gate. **Nothing starts until the owner says "go" on Phase 0.**

**Phase 0 — Foundation (pre-v0.1, low risk, while still private-primary).**
Create the *paper* governance layer with no topology change: `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`,
`MAINTAINERS.md`, `CODEOWNERS`, `PULL_REQUEST_TEMPLATE.md`, refreshed `CONTRIBUTING.md`. Get the **CLA
lawyer-reviewed**. These can land on private `main` and ride the next publish to the mirror.
*Exit gate:* docs merged; CLA legally cleared.

**Phase 1 — Open the front door (issues/discussions only; Option C).**
Enable **Discussions** + public **issue** intake on the mirror; publish the roadmap; curate the first
`good first issue` set. *Still no outside code merges yet* (the mirror is publish-only). This builds
signal and surfaces a possible second maintainer at near-zero risk.
*Exit gate:* v0.1 GA tagged; the four v0.1 hard gates (PHI log redaction, no "experimental" backends,
published throughput baseline, off-loopback/TLS) met per the [v0.1 release plan](releases/v0.1-PLAN.md).

**Phase 2 — Flip to public-primary (Option A) and open code contribution.**
Fold `publish.ps1`'s curation into the public repo as required CI; make `MEFORORG/MessageFoundry` the
dev repo; apply contributor-mode branch protection (§5); announce "open for contributions".
*Exit gate:* `scan_forbidden`/gitleaks green as required PR checks; contributor-mode protections live;
first external PR merged end-to-end as a dry run.

**Phase 3 — Grow the bus factor.**
Identify and invite a **second maintainer**; populate `CODEOWNERS`/`MAINTAINERS.md`; bring them onto
the security-advisory team. Revisit governance (BDFL → small maintainer team) only if/when volume
warrants — not before.
*Exit gate:* a second maintainer has merge rights and advisory access.

---

## 8. Owner decisions needed before Phase 0 starts

1. **Repo model & timing** (§2) — confirm **C-now → A-at-v0.1**, or choose B / a different timing.
2. **Governance model** (§3) — confirm **BDFL/single-steward, documented honestly**, with the ladder.
3. **CLA path** (§5) — ✅ **DECIDED 2026-06-14: keep the open-core CLA** (not DCO), preserving the
   dual-license/commercial-edition path. Remaining action (owner): lawyer-review the
   [`CLA.md`](../CLA.md) template and confirm the "MessageFoundry Organization" entity it names,
   **before** the program is publicly announced. Not a blocker for merging the Phase 0 governance docs.
4. **Code of Conduct** — Contributor Covenant v2.1 (recommended) vs. another.
5. **Communication surface** — GitHub Discussions only (recommended) vs. add chat now.
6. **The "MessageFoundry Organization"** — is this a formed legal entity, or does the CLA wording need
   adjusting to the actual owner/entity? (Affects the CLA lawyer review.)

---

## 9. Open questions / risks

- **AGPL + open-core friction.** The AGPL §13 + relicensing CLA is a deliberate open-core posture, but
  some contributors decline CLAs on principle. Accept a (likely small) contributor-pool cost; this is
  a values call the owner has already leaned into.
- **Single security-advisory contact** is a real single point of failure until Phase 3.
- **Mirror-flip discipline** (Option A) puts the whole PHI air-gap on the CI scan gate holding 100% of
  the time. The gate is fail-closed today; treat any bypass as a Sev-1.
- **Contributions vs. the fork-based component SDK vision** ([[mf-vision-and-plan]]): the long-term
  model is a read-only SDK users *fork to customize*. Clarify for contributors what belongs **upstream**
  (core engine, transports, fixes) vs. what is a **downstream fork** (their site-specific
  Routers/Handlers) — so the contribution funnel points at the right target.

---

## 10. What happens on "go"

On an explicit "go" for **Phase 0**, the work is: author the six governance/community files in §4 (1–4,
9) on this `planning-contributors` branch, open a PR, and run the quartet. Phases 1–3 each get their own
"go" gated on the exits above. No repo settings, no announcements, and no CLA reliance happen without
the corresponding decision in §8 being made first.
