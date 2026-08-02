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
| `unverified` | **Never examined.** Inherited from an earlier assessment and never read against the requirement text | **local extension** |

### 1.1 The decision procedure — apply in order

Ambiguity is resolved by taking the **first** rule that matches, not by judgement.

1. **Does the requirement apply to this product on the declared scope (§2)?**
   No → **`na`**, and write the rationale. No rationale, no `na`.
2. **Has this cell been read against the ASVS requirement text at a known commit?**
   No → **`unverified`**. *This is not a Pass.* An inherited verdict is a guess.
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

### 1.2 Worked examples — the ones that actually broke

These are the real disputes. They are here so the next assessor reaches the same answer.

| Cell | Verdict | Which rule, and why |
|---|---|---|
| **5.4.3** | `fail` | Rule 3. A scan *hook* exists but its only shipped implementation is `_no_scan`, and there is **no configuration key at all** — an operator must **author** the scanner. Supplying a control is not configuring one. |
| **15.2.5** | `partial` | Rule 5, **not** rule 3. `[sandbox].mode` ships `off`, but `subprocess` mode is real and was verified by executing it. A working control that ships off. |
| **11.7.1** | `fail` | Rule 3. The read-out is all-`None` off Linux and the only refusing branch keys on a **TOML declaration**, never on the measured property. Zero percent of the verb is satisfied by shipped code. |
| **3.7.3** | `fail` | Rule 3. One off-site navigation, a bare 303, no interstitial and no cancel. `oidc_enabled=False` removes the **trigger**, not a control. |
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

**The configuration assessed** — one posture, not a matrix:

> On-premises single hospital · private network, never internet-facing · SQL Server store · operator
> console behind a TLS-terminating reverse proxy on the hospital LAN · `data_class = phi` under
> `[security].enforcement = enforce` · authentication on · RBAC deny-by-default · data plane bound to
> a NIC so partners can send HL7.

**One posture column only.** A previous two-posture (A/B) split was retired because cells were scored
under one frame and carried into another, leaving at least one cell's bucket **unrecoverable from the
record**. Where a verdict would differ under a documented opt-in, the default is scored and the delta
is recorded in the cell's residual — never as a second column.

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
  measurement — it is an average over guesses. Publish *verified / unexamined*, not a single total,
  until the baseline sweep completes.

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
