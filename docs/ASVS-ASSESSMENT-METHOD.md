# ASVS assessment method

| | |
|---|---|
| **Standard** | OWASP ASVS **5.0.0**, pinned to release tag `v5.0.0_release` |
| **Target level** | **Level 3** (cumulative — L1 + L2 + L3) |
| **Nature** | Point-in-time, **AI-assisted self-assessment by source review.** Not a certification, accreditation, passed audit, or penetration test. OWASP certifies nobody. |
| **Scope** | Declared positively in §2 |
| **Status** | Method of record from 2026-08-01 (ADR 0156) |

> **Why this document exists.** ASVS 5.0's assessment chapter is *"deliberately not prescriptive"* and
> supplies **no verdict rubric**. What it does supply is a stability mechanism: disclose a repeatable
> method, declare scope positively, report **every requirement checked rather than exceptions only**,
> and give a written rationale for anything non-applicable or unimplemented.
>
> This document is that disclosure. It exists because the absence of a written rubric measurably cost
> us: three cells (11.7.1, 3.7.3, 5.4.3) changed verdict in one day purely because two assessors
> applied different unwritten rules to the same code.

---

## 1. Verdicts

**ASVS 5.0 defines three verdicts: verified, exception, and non-applicable-with-rationale.** The
strings *"partially implemented"* and *"not implemented"* appear nowhere in it. Everything below
beyond those three is **our local extension**, and is defined here precisely because the standard
does not define it — an undefined grade is one two assessors will apply differently.

| Verdict | Meaning | ASVS-native? |
|---|---|---|
| `pass` | The requirement's **verb** is satisfied by a **shipped default**, or by a gate that **refuses to start** when the precondition is absent | yes (*verified*) |
| `fail` | **No implementing control exists in any configuration** | yes (*exception*) |
| `na` | The requirement does not apply to this product on the declared scope. **A written rationale is mandatory** | yes — and the rationale is the one **"must"** in ASVS's assessment chapter |
| `partial` | A control exists but ships off, warns instead of refusing, or covers only part of the in-scope surface | **local extension** — see §1.1 |
| `needs-review` | Examined, but the verdict is genuinely contested or blocked on a decision | **local extension** |
| `unverified` | **Not re-verified against the requirement text.** The cell carries a verdict from an earlier assessment that reasoned from the verb *as paraphrased in our own scorecards*, never from the pinned text at a known commit | **local extension** |

### 1.1 The decision procedure — apply in order

Ambiguity is resolved by taking the **first** rule that matches, not by judgement.

1. **Does the requirement apply to this product on the declared scope (§2)?**
   No → **`na`**, and write the rationale. No rationale, no `na`.
2. **Has this cell been read against the ASVS requirement text at a known commit?**
   No → **`unverified`**. *This is not a Pass.* ⚠️ It is also **not** "nobody looked" — the earlier
   lineage graded these cells. What it graded them against was a paraphrase, because the ASVS 5.0.0
   text was not held anywhere in the project until 2026-07-31. So an inherited verdict is a verdict
   about a restatement of the requirement, which is why it has to be re-derived rather than trusted —
   and why re-verification moves some of them.
3. **Does code implementing the requirement's verb exist anywhere in the tree, reachable by any
   configuration?**
   No → **`fail`**.
4. **Is the verb satisfied by a shipped default, or by a gate that refuses to start when the
   precondition is absent?**
   Yes → **`pass`**. *"It can be configured" is never a pass. A signed relaxation is never a pass.*
5. **Otherwise** → **`partial`**: the control exists, but it ships off, warns rather than refuses, or
   covers part of the surface.
6. **If two assessors following 1–5 disagree** → **`needs-review`**, with the disagreement recorded.
   Forcing a premature verdict is what produces flip-flop; parking it is cheaper and honest.

### 1.1a An off-by-default control cannot reach a `pass` — owner ruling, 2026-08-16

**Rule 4 stands exactly as written, and it is strict.** Asked directly whether the rubric should be
relaxed, the project owner ruled on **2026-08-16** that it should not: *"it can be configured" is never
a pass*, and an off-by-default control can **never** be graded `pass`. The §1.3 tie-breaker stands with
it. The ruling was applied to the record on the same date, and the owner accepted the consequence in
advance — that applying it moves at least one cell **down**, which is a §2.2 cause-4 movement and not a
regression.

This subsection exists because rule 4 was being read correctly and then argued around. Three arguments
recur; all three are now settled.

1. **"The feature ships off, but every control inside it is unconditional."** That is **rule 5**, not
   rule 4 — first ruled on 2026-08-05 and re-affirmed by the 2026-08-16 ruling. A control whose internal
   quality is beyond reproach still does not run on a shipped default, and rule 4 asks about the
   default. The implementation's quality belongs in the residual; it does not move the verdict.
2. **"On the default there is no exposure, because the risk and the control appear and disappear
   together — so a `partial` grades a harm that cannot occur."** Rejected. This is the **vacuity
   argument**, and accepting it would make rule 4's first limb unfalsifiable: *every* off-by-default
   control removes its own trigger, so the argument is available to all of them and discriminates
   between none of them. A property predicated of an object the shipped default never creates is not
   *satisfied*.
3. **"No code change could improve the cell, so a `partial` manufactures a phantom remediation item."**
   Rejected as a ground, and usually **false on the facts** as well. Before offering it, name the change
   that would make the verb hold on a stock install and say why it is impossible. Flipping a default,
   moving an optional dependency into the base dependency set, and adding a gate that refuses to start
   are all bounded, ordinary product work — and where such a change exists the remediation is real, so
   the item filed against it is not phantom.

**What rule 4's second limb actually requires.** It is *"a gate that refuses to start when the
precondition is absent"* — a **startup** refusal, of the whole instance. Two near-misses do not qualify,
and both have been argued here:

- **A warning is not a refusal.** Logging loudly at startup and then continuing is rule 5's second limb
  *verbatim* ("warns rather than refusing"), so a cell whose only startup-time response to the missing
  precondition is a log line lands **on** rule 5 rather than merely failing to earn rule 4.
- **A request-time error on a registered route is not a startup gate.** A route that exists and answers
  `400` or `503` because a component is missing describes a **feature being absent**, which is precisely
  the state rule 5 grades. Rule 4's limb is about an instance declining to run at all.

**Two consequences for how this is written down.** First, the owner also directed that the
off-by-default defaults themselves be changed, filed as ordinary product work in the ledger and
described as product changes rather than as assessment findings. Second, **this document records the
rule and deliberately not a list of the cells it moves**: an enumeration of affected requirements over a
closed, published requirement set hands out the complement by subtraction, so the rule is public and the
per-requirement verdicts stay in the record of record.

### 1.2 Worked examples — the ones that actually broke

These are the real disputes. They are here so the next assessor reaches the same answer.

| Cell | Verdict | Which rule, and why |
|---|---|---|
| **5.4.3** | `na` | **Rule 1, and it moved for the same reason 11.7.1 did.** Antivirus scanning of inbound content is an **enterprise-provided** control — the deploying organisation's AV/EDR/ICAP stack over the drop directory, the SFTP landing zone and the upload path — so the verb's subject is outside the declared scope of §2. ⚠️ Previously scored `fail` under rule 3 and cited here as the worked example of one, on the reasoning that *a scan hook exists but its only shipped implementation is `_no_scan` and there is no configuration key at all, so an operator must author the scanner*. **That reasoning is still true of the code** — it simply answers rule 3's question, and rule 1 runs first. ⛔ **This `na` is WEAKER than 11.7.1's and its rationale says so on the cell:** the engine *does* ship a scan seam, so this is a control the product **could** implement, which makes the verdict conditional on the enterprise actually covering those paths. It therefore carries a **deployment requirement**, and a consult to test that premise on outbound-initiated SFTP pulls is filed in the ledger. **CLOSED by owner decision (2026-08-02); do not re-derive it.** |
| **15.2.5** | `partial` | Rule 5, **not** rule 3. `[sandbox].mode` ships `off`, but `subprocess` mode is real and was verified by executing it. A working control that ships off. |
| **11.7.1** | `na` | **Rule 1 — the hardest call in this table, and it moved.** The verb is *"full memory encryption is in use"*: a property of the **CPU, firmware and hypervisor**, not of the three software artifacts in §2. Outside the declared scope, so rule 1 fires before rule 3 is ever reached. **The objection this has to answer, because it is a good one:** ADR 0152's rungs 1–2 *do* ship in-engine, so the engine is not silent on this cell. But that code **reports on and gates against** the platform property — it never provides it. Reporting is not implementing (§2's first guard). ⚠️ Previously scored `fail` under rule 3 and cited here as the worked example of one. That reading was not wrong on its own terms; it answered *"does code implement the verb"* without first asking *"is the verb's subject in scope"*, and rule 1 runs first. **This cell has moved four times in eighteen days — it is CLOSED by owner decision (2026-08-02); do not re-derive it.** ⛔ It buys **no** Level 3 claim: see §2.1. |
| **3.7.3** | `pass` | **Rule 4 — and this row is CORRECTED 2026-08-16.** It stood here as the table's worked example of a rule-3 `fail`, on the reasoning that there was *one off-site navigation, a bare 303, no interstitial and no cancel*. That described the code accurately when it was written. The interstitial was then **built**, and the record has carried this cell as `pass` since 2026-08-03 while this row went on saying `fail` — a worked example teaching the wrong answer for thirteen days. `[security].external_link_interstitial` ships `True` and `[security].organization_domains` ships **empty**, which is the strict position, so every absolute off-site destination is interstitialed out of the box and the verb is satisfied by a shipped default (`messagefoundry/config/settings.py:3743,3746`). **No live worked example of rule 3 remains in this table** — 5.4.3 and 11.7.1 both left it under rule 1 — and that is said plainly rather than patched with a substitute, because a stale example is worse than a missing one. |
| **10.5.5** | `na` | Rule 1. The requirement is conditional — *"**when using** OIDC back-channel logout"* — and the precondition is false and unreachable by configuration. **Building it would create applicability.** |
| **12.2.2** | `na` | Rule 1. No external-facing services on the declared scope. *Also a scoping error worth remembering: this row spent months scoring 12.3.1's verb.* |
| **12.3.1** | `partial` | Rule 5. Raw TCP and X12 cannot speak TLS in any configuration — but a substantial control exists elsewhere (TLS-by-default store hop with a refusing gate), so partial coverage, not rule 3. |

### 1.3 Standing tie-breakers

- **Default to the worse verdict** when uncertain. An unearned pass is the failure this method exists
  to prevent.
- **A verdict is only as good as its anchor.** No `pass`, `partial` or `fail` without evidence (§3).
- **Never reason from a paraphrase.** Quote the requirement's `req_description` from the pinned
  corpus before judging. Scoring a cell against a remembered or restated verb produced three wrong
  verdicts, one of which had stood for three assessment cycles against a requirement ASVS **deleted**.

---

## 2. Scope, declared positively

Per ASVS's guidance, stated as what **is** included rather than what is excluded.

**Included:** the MessageFoundry engine, the web console, and the IDE extension, assessed as source,
at a named commit, against **all 345 ASVS 5.0.0 requirements** at **Level 3**.

**The boundary that phrase implies, stated explicitly because it decides verdicts.** The subject of
this assessment is those three **software artifacts**. It is not the host, the hypervisor, the CPU, the
firmware, or the network the operator deploys onto. Where a requirement's **verb** names a property of
that substrate rather than of the software, the requirement is outside the declared scope and takes
`na` under rule 1 — with the rationale written, as always.

**This is ASVS's own principle, not a local invention.** Verbatim from `0x03-What-is-the-ASVS.md` at the
`v5.0.0` tag:

> "Conversely, ASVS generally excludes requirements that are not directly relevant to the application or
> **where configuration is outside the application's responsibility**. For example, DNS issues are
> typically managed by a separate team or function."

⚠️ **Do not over-read that, and do not reach for the fork clause to do this job.** The same chapter says
organizations are *"strongly encouraged to create an organization- or domain-specific fork that adjusts
requirements"* — but its worked examples of omission are **technology-not-used** (*"omitting irrelevant
sections (e.g., GraphQL, WebSockets, SOAP, if unused)"*), which is the functionality-based shape, and
**forking changes what you are claiming conformance TO**: your tailored ASVS, not stock ASVS 5.0. This
project does **not** fork. It applies rule 1 against a positively-declared scope, which is narrower,
cheaper to defend, and leaves the conformance target unchanged.

Two guards on that boundary, because it is exactly the kind of clause that grows to swallow
inconvenient cells:

* **Shipping code that *reports on* a platform property is not the same as *providing* it, and neither
  direction is decisive on its own.** A cell does not become in-scope merely because the engine
  observes the substrate; nor does it leave scope merely because the substrate is involved. Ask what
  the **verb** requires to be true, and of what.
* ⛔ **This boundary does not shrink the conformance claim's denominator.** A requirement excluded here
  is still a requirement OWASP assigns to Level 3. See §2.1.

### 2.1 What an out-of-scope cell does NOT buy

**It does not preserve an unqualified Level 3 claim.** Two facts, both from ASVS 5.0.0 itself:

* **4.0's clause that an organization excluding requirements "may still claim full ASVS compliance"
  was DROPPED in 5.0.** The 5.0 text says only that non-applicability must be noted in the report.
  There is no longer any standard text saying a documented exclusion preserves a compliance claim, and
  a rationale that cites the older wording is citing a superseded standard.
* **OWASP does not certify anyone — but it does retain normative authority over the requirement SET.**
  It assigns each requirement to a level. So a Level 3 claim that silently omits a requirement OWASP
  places at Level 3 is non-conformant **on OWASP's own terms**, regardless of how well-argued the
  exclusion is.

**Therefore:** scoping a cell out is a statement about *what was assessed*, never a statement that the
level was achieved anyway. Any published attestation must say which requirements were excluded, or say
something weaker than "verified at Level 3". Writing `na` in the record and "Level 3 verified" in a
brochure is the failure mode this section exists to prevent.

### 2.1a ⛔ The pinned corpus cannot settle a question about ASVS's *prose*

**A corpus that cannot express a class of claim cannot refute one.** `[scorecard].corpus_sha256` pins
the ASVS **requirements** — `req_id`, text, level. It carries **no chapter prose**: no assessment
guidance, no scoping discussion, no definitions. So a claim about *what the standard says* outside a
requirement's own text is **structurally uncheckable** against it, and every check will come back clean.

This is not hypothetical. A false statement — *"ASVS reserves non-applicable for functionality-based
exclusions"* — survived **two independent assessors** and reached a signed-adjacent risk-acceptance
block, because every one of them verified against the corpus and the corpus had nothing to say. What
`0x03` actually says is the opposite: it excludes requirements *"where configuration is outside the
application's responsibility."* One fetch of the chapter settled it; no amount of corpus checking could
have.

**So: to cite ASVS prose, fetch the chapter at the `v5.0.0` tag and quote it verbatim.** Never
paraphrase it from memory, from an earlier assessment, or from another agent — and never treat a green
corpus check as evidence about a claim the corpus cannot represent.

### 2.1b "Approved", in a V11 cryptography verb, means Appendix C status A — not the NIST list

**This is the standing definition. State it here and cite this section; do not restate it.** It is an
instance of §2.1a: which list "approved" binds to is a claim about chapter prose, so the pinned corpus
cannot settle it and every corpus check comes back clean.

The V11 chapter says so in its own words, fetched at the `v5.0.0` tag and quoted verbatim:

> "provides more in-depth technical information about the requirements in Appendix C ... includ[ing]
> algorithms and modes that are considered 'approved' for the purposes of the requirements in this
> chapter."

**Read the appendix's status column, and read the Restrictions cell beside it.** Status **A** is
approved; **L** is legacy, restricted by the text in its own row; **D** is disallowed for any
cryptographic purpose. A row's restriction binds only where the row says so, so an **L** mechanism is
not automatically out of every use.

**Substituting the NIST list is a live error with a measured cost.** It graded a keyed BLAKE2b
de-identification seed as unapproved through three successive assessment passes. BLAKE2b is status
**A** in the appendix's general-use hash table with an empty Restrictions cell. The corroborating
consequence: the same appendix approves argon2id for password storage, and argon2's core permutation
**is** BLAKE2b, so a NIST-only reading has the standard mandating a KDF built on a primitive it
disapproves. The measurement, and the wrong fix it nearly bought, are recorded once at BACKLOG #1171.

### 2.2 A count movement is not a posture movement — read the counts accordingly

**The single most misreadable thing this method produces is a change in the bucket totals.** Counts move
for four different reasons, and only one of them means the software got better:

| The count moved because… | Did the posture improve? | What actually happened |
|---|---|---|
| A control was **built or turned on by default** | **Yes** | The verb is now satisfied by shipped code |
| A cell was **re-verified against the requirement text** for the first time (`unverified` → anything) | **No** | The survey advanced. A cell moving `unverified` → `pass` is a *discovery* — or a paraphrase-based grade being corrected — never an improvement |
| A **scope boundary was stated** (→ `na`) | **No** | The requirement left the denominator. Identical code, smaller question |
| A **rule was applied more carefully** (re-grade in either direction) | **No** | The assessment got more accurate. Some of these move *down* |
| **The standard moved** (a new ASVS release changes requirement text, levels, or the requirement count) | **No** | The denominator changed. Zero code changed and zero assessment work happened — and this is the cause most easily mistaken for the survey advancing |

**The worked example, and it is recent.** On 2026-08-02 the fail count went **3 → 2** when 11.7.1 was
scoped out under rule 1. **Zero lines of engine code changed.** A reader comparing only the fail counts
across those two days would conclude a defect was fixed; nothing was. The rationale is on the cell and
the boundary is in §2, but neither is visible to someone reading a total.

**⛔ And the converse is true, and worse: a posture movement with NO count movement.** Everything above
teaches you to interrogate a number that *moved*. The more dangerous class **hides in stillness** — code
changes, an evidence anchor drifts off the line it was pinned to, and the recorded verdict quietly stops
describing the code. **The total does not move at all.** Stability reads as "nothing to see."

This is not hypothetical and it is not cause 4. Cause 4 is a deliberate act — someone re-read a cell and
graded it better. This is an evidence pointer breaking **on its own**, while every reader sees a total
that looks fine. Measured on this project on 2026-08-02: **seven anchors across six cells had drifted**,
and not one bucket total moved. Nobody could have caught it from a number. You catch it **only** if a
gate is watching, which is the entire reason the drift gate exists (ADR 0156).

**Three obligations follow, and they are cheap:**

1. **Never report a bucket total as a trend without naming which cause moved it.** "Fails went from 3
   to 2" is not a finding. "One cell was scoped out; no code changed" is.
2. **When a count improves, state what would have had to happen for it to mean an improvement, and
   whether that happened.** Same discipline as a negative control: a number that can only go one way is
   not measuring anything.
3. **A stable count is not evidence of a stable posture unless the anchors were re-verified in the same
   pass.** Report the drift check alongside the total, or you are publishing the freshness of the last
   check rather than of the software. ⚠️ **Always state the pinned ASVS version with any total**, so a
   denominator change shows up as a version change instead of as progress — the corpus is pinned by
   digest in `[scorecard]`, and a 5.0.x patch release would move requirement text and counts on its own.

⚠️ **This cuts against us more often than for us, which is why it is written down.** The survey is
incomplete, so most future movement will come from cause 2 — cells being re-verified against the
requirement text for the first time — and the aggregate will get *worse* before it gets better as
`unverified` cells resolve into real verdicts. **That is the survey working, not a regression**, and it
should be reported as such rather than defended against.

⚠️ **And state the debt in the right words.** `unverified` measures **re-verification debt**, not
unassessed surface. Describing those cells as "never examined" or "nobody has looked at them"
overstates the deficit and misdescribes the lineage: they were graded, repeatedly, against a
paraphrase. The honest phrasing is *"N of 345 verified against the pinned requirement text; M carry
verdicts not yet re-verified against it."*

**The configuration assessed** — one posture, not a matrix:

> On-premises single hospital · private network, never internet-facing · SQL Server store · operator
> console behind a TLS-terminating reverse proxy on the hospital LAN · `data_class = phi` under
> `[security].enforcement = enforce` · authentication on · RBAC deny-by-default · data plane bound to
> a NIC so partners can send HL7.

**One posture column only.** A previous two-posture (A/B) split was retired because cells were scored
under one frame and carried into another, leaving at least one cell's bucket **unrecoverable from the
record**. Where a verdict would differ under a documented opt-in, the default is scored and the delta
is recorded in the cell's residual — never as a second column.

**What that posture says about OPTIONAL COMPONENTS, written down because it was being left to
inference.** The posture names components that a default install does **not** carry — *"SQL Server
store"* needs the `sqlserver` packaging extra, so the assessed configuration is demonstrably not a bare
`pip install messagefoundry`. Read the posture as exhaustive **in both directions**: an optional
component the posture **names** is present, and one it does **not** name is at its default, which for a
packaging extra means **absent**. Without that rule an assessor may silently assume whichever install
set makes a cell easier to grade, and the two readings disagree about exactly the cells §1.1a governs.

---

## 3. Evidence

ASVS expects per-requirement, artifact-backed evidence, and states that merely running an
off-the-shelf tool is insufficient. It equally endorses **purpose-written tests** — *"testable using
automation ≠ running an off the shelf tool"* — so the anchors below are squarely within its intent.

**Every non-`unverified` cell carries at least one anchor**, machine-verified on every commit
(ADR 0156):

- **Presence anchor** — `path` + `line` + an `expect` **token** that must still resolve. A token
  rather than a bare line number, so ordinary edits above it do not thrash every anchor.
- **Absence claim** — a `pattern` that must return nothing **plus a `positive_control` that must
  still match.** A grep naming the wrong token returns zero and reads exactly like proof; five
  residuals of record died that way, and two of my own greps did in a single day. **An absence claim
  without a live positive control is void**, regardless of what the pattern returns.

**`reviewed_by` and `reviewed_at`** are recorded on every verdict, so staleness is visible and a
verdict can be traced to the pass that set it.

---

## 4. Reporting

- **Every requirement is reported, not exceptions only** — including `unverified`. ASVS asks for a
  summary of all requirements checked; a report that shows only failures hides how much was examined.
- **No document states a count.** The count is **computed** from the scorecard, and prose renders it.
  Five documents once asserted three different counts.
- **`unverified` is reported separately from `pass`.** A headline that merges them is not a
  measurement — it is an average over verdicts reached against a paraphrase. Publish
  *verified / not-yet-re-verified*, not a single total, until the baseline sweep completes.

---

## 5. Pinning

- The corpus is the **official `v5.0.0_release` asset**, recorded with its **SHA-256**, not a fetch
  from `master`. Master is the bleeding-edge branch and a rolling *"latest"* release carries identical
  filenames — an unpinned fetch silently moves versions.
- The scorecard records `asvs_version`. **ASVS requirement IDs are not stable across versions** —
  bare `1.2.5` is *Architecture* in 4.0.3 and *Encoding and Sanitization* in 5.0.0 — and OWASP's
  referencing guidance prefers `v<version>-<chapter>.<section>.<requirement>`. A document-level
  version field satisfies that pinning.

---

## 6. What this method is not

- **Not a certification.** OWASP certifies nobody, and its assessment guidance is written for a
  third-party certifying organisation producing a certification report. Applying it to an in-repo
  self-assessment is a defensible extension, not a mandate — *"insufficient for certification"* is
  not the same as *"insufficient for a self-assessment"*.
- **Not externally validated.** No independent ASVS review, penetration test, or DAST has assessed
  this scorecard.
- **Not a guarantee of correctness.** This method makes verdicts *consistent, derived and
  drift-detecting*. A wrong verdict recorded carefully is still wrong; adversarial verification
  remains the only cure for that.
- **Not prior art.** No open-source project was found maintaining per-requirement ASVS verdicts with
  git-versioned evidence anchors — the one comparable tool keeps verdicts in a gitignored database.
  Every choice here is justified from the ASVS text directly, because there is no convention to adopt.
