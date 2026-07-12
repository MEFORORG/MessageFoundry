# 0101 — Pre-registered falsifier discipline for performance measurement

- **Status:** **Accepted (2026-07-12)** — it has been in force since the C4 handoff and is the reason C5/C6/C7 held up.
  This ADR moves it **into version control**, where it belongs.
- **Date:** 2026-07-12
- **Related:** [ADR 0098](0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md)
  (the result this discipline produced) ·
  [ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md) (the next build, which must carry a
  falsifier) · [ADR 0051](0051-corepoint-throughput-parity-strategy.md) (*measure-first*) ·
  `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` §5 ("Why the measurement programme kept failing")

---

## Context

**This project has published performance results and then retracted them. Twice.** The status doc carries a whole
section (§5) titled *"Why the measurement programme kept failing."* The failures were never bad instruments — they were
**bad inference**: a number was produced, a story was fitted to it after the fact, and the story shipped.

The recurring error has a shape. Every instance is a variant of **naming a cause from an adjacency**:

- **C2** named the wall from a wait's **rank** (`PAGELATCH` was #1) — **retracted.**
- **C4** named the CPU consumer from a **share** (`list_fifo_lanes` 47.5%) without a reconciliation that cleared its
  own pre-gate — **WITHHELD**, and its "72% off-CPU WAIT" reframe turned out to be a **collapse-tail artifact**.
- **C5's handback** named a *"write-path signature"* from `LOGMGR_QUEUE` + `CHECKPOINT_QUEUE` — which are **idle
  background waits**, sitting in a cluster of threads asleep for the entire 800 s window. **Corrected in review.**
- **The reviewer of C5** then claimed `WRITELOG` was *absent* — inferring absence from a **truncated top-14** whose
  noise floor was ~792,000 ms. `WRITELOG` was there all along, and is in fact **rank-1 on the perfectly healthy,
  100 %-delivered N=4 arm**. **Self-retracted.**
- **C7's hypothesis** (parallelism, from `CXSYNC_PORT`'s 34× growth) — **refuted by its own falsifier.**

**Five instances. Four different people/agents. One error class.** The lesson is not "try harder": it is that on a
**collapsing system almost everything grows**, so *rank*, *share*, and *growth rate* are all worthless as causal
evidence, and a post-hoc story will always be available. **The only defence is to fix the decision rule before seeing
the number.**

The discipline that finally worked exists — but **only in handoff documents on an operator's OneDrive, outside the
repository.** Losing them loses the method, and the next measurement programme repeats §5.

## Decision

**Every performance investigation that will inform a build decision SHALL be pre-registered as a falsifier.** A run
that cannot come back "no" is not an experiment; it is a search for confirmation, and its output is not admissible.

**The protocol — all seven are mandatory:**

1. **A pre-registered decision rule.** The verdict table, and every threshold in it, is **fixed in the handoff before
   the run starts**. Thresholds are never widened after seeing a number, and never narrowed to manufacture a signal.
   *(C5 pre-registered `R < 3.62 ⇒ INSUFFICIENT`; C7 pre-registered its null band at 45–57 % delivered / +95…+125
   slope.)*
2. **A stated null band — and a null is a SUCCESSFUL run.** The handoff must say what "no effect" looks like
   *numerically*, and must say in terms that a null result closes the question. *(C7's handoff: "A null result is a
   successful run. Do not go looking for a signal." It then returned a refutation.)*
3. **A manipulation check.** Prove the intervention actually took effect, independently of the outcome. If it did not,
   the run is **VOID — not a null.** *(C7: `CXSYNC_PORT` had to fall to ≈0 under `MAXDOP=1`; it fell to exactly 0. A
   forgotten `CLEAR PROCEDURE_CACHE` would otherwise have produced a null that meant only "I forgot".)*
4. **A same-session control.** A/B against a control run **in the same session on the same rig**, never against a
   historical number. *(This arc's N=8 backlog slope is genuinely run-to-run variable **+4…+13**; N=16 delivered 9.4 %
   in C3/C4 and 26.2 % in C6. Historical baselines here are noise.)*
5. **A mechanism is named ONLY by a convoy, never by rank, share, or growth.** For a store wall, that means **≥5
   sessions suspended on ONE shared `resource_description`** (or a blocking chain ≥2 deep) in ≥50 % of samples, **AND
   absent in the matched PASS control.** Nothing else names a wall. *(C6: 0 of 288 samples met the floor → it correctly
   named **nothing**.)*
6. **A matched PASS control, and the anti-adjacency guard.** The clinching evidence is a signal **present in the FAIL
   arm and absent in a healthy one**. `WRITELOG` is **rank-1 on the 100 %-delivered N=4 arm** — the cleanest available
   proof that rank is not causation. **If a signal appears when the system is healthy, it cannot name the wall when it
   collapses.**
7. **Reproduce before claiming.** A positive result is reproduced **before** it is reported. A negative needs no
   reproduction. *(C7's rep arm was mandatory only ahead of a positive claim; C5's collapse was reproduced 3-for-3.)*

**Instrument rules that are equally binding** (each cost a real defect):

- **Gate on the harness `result` field — NEVER `exit_code`.** Every collapsed arm in C1–C3 serialized `exit_code = 0`.
- **Apply the benign-exclusion set + capture-session fence to every wait report.** An unfiltered top-N by
  `wait_time_ms` puts **idle** waits on top (`SOS_WORK_DISPATCHER` at 74–92M ms; `LOGMGR_QUEUE`/`CHECKPOINT_QUEUE`
  asleep for the whole window) and **is not a result**.
- **Never quote `ceiling.sustained_events_per_s` from a COLLAPSED arm.** It is populated even on a 27 %-delivered arm
  (reads 145.359 on `c3-16`). It is a trap.
- **Pin the engine build**, and state it in the handback. A silent `git pull` invalidates every cross-run comparison.
- **Distinguish RAW capability from PUBLISHABLE** (the Phase-5 **D4** rule: publish at ≤50 % of the measured ceiling).
- **Report a co-constraint carve-out honestly.** If the *rig* (engine box, load-gen) is the saturated resource rather
  than the system under test, the verdict is a **lower bound, DEFERRED** — not a design verdict.

**Where it lives:** the handoff/handback pair is the unit. A **HANDOFF** carries the pre-registered rule *before* the
run; a **HANDBACK** reports against it; an independent **REVIEW** adversarially audits the handback. All three are
retained with the raw artifacts.

**This decision must not break:** nothing — it constrains *how we conclude*, not what the engine does. It authorizes no
code.

## Options considered

1. **Pre-registered falsifier discipline, recorded in-repo. CHOSEN.** It is the only thing that has demonstrably
   worked, and this ADR fixes the fact that it was living outside version control.
2. **Rely on careful analysis and code review.** Rejected — **empirically insufficient.** Five instances of the same
   error class got past careful, motivated, numerate reviewers. The C5 handback passed its *own* adversarial gate with
   the misread intact.
3. **Only pre-register the "important" runs.** Rejected: importance is judged *after* the number arrives, which is
   exactly when the bias operates. Cheap runs are also where the discipline is cheapest.
4. **Require a convoy-grade mechanism for every claim, even directional ones.** Rejected as too strict — it would
   forbid honest *hypotheses* (C7's `CXSYNC_PORT` guess was well-formed and worth ~3 arms to kill). **Hypotheses are
   allowed and encouraged; they just may never be reported as findings, and must be given a kill-criterion.**

## Consequences

**Positive**
- **The store-side search was closed without building the wrong thing.** ADR 0098 exists because C5/C6/C7 could each
  come back "no" — and two of them did.
- **A dead hypothesis becomes a cheap, valuable outcome** rather than an embarrassment. C7 cost three arms and
  permanently removed a thread that would otherwise have hung over every future store result.
- **The method survives the operator.** It is in the repo now, not on a desktop.

**Negative / risks**
- **It is slower and more expensive** — a same-session control and a reproduction arm are real rig time. The C5–C7 arc
  spent perhaps a third of its runs on controls. **This is the price, and §5 is what it buys.**
- **It can feel like ceremony on a "cheap look".** It is not: C7 *was* the cheap look, and it inverted.
- **Discipline decays.** Every handoff must re-carry the rules; a *Do NOT* list in each handoff is the enforcement.

**Out of scope**
- Functional correctness testing (pytest, the FIFO/no-loss gates) — a different regime with different rules.
- The rig's own operations (provisioning, instance lifecycle). Note only: **tearing down the AWS rig is the owner's
  call, never the operator's** — an unsanctioned STOP wipes the instance-store store volume.

## To resolve on acceptance

- [ ] Should the handoff/handback/review artifacts themselves be committed to the repo (redacted of hostnames/IPs), or
      is the discipline-in-ADR enough with artifacts kept on the operator's drive? **Owner's call.** The
      argument for committing: the C5–C7 handbacks are the only record of *how* the numbers were obtained, and
      `docs/benchmarks/` already carries the conclusions without the method.
