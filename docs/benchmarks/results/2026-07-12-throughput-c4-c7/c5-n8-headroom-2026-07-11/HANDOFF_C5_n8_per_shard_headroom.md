# HANDOFF — **C5: what is the per-shard ceiling at N=8, latch-free?** (the falsifier the capacity frontier hangs on)

**Date:** 2026-07-11 · **Continues C3** · **Runs AFTER C4, ideally in the SAME rig session** (both need the same
feature ON — see §1). **Cheap:** one N, a short per-shard ladder, no full sweep.

---

## ⚠️ AMENDMENT 2026-07-12 (v2.1) — READ THIS FIRST: one NEW blocking pre-flight, one prerequisite now CLEARED

**If you have already read v2, these are the only two changes. Nothing else in the doc moves.**

1. **NEW PRE-FLIGHT — pin the engine build to `98bec81` (now §1.5).** v2 said only *"everything else identical to
   C2/C3"* and **never pinned the engine commit** — an omission, not a choice. The C6 handoff pins it (*"a different
   commit makes the profile non-comparable to C4"*); C5 needs the same pin, because `R` is scored against the C1–C3
   ladder and C5-a is sanity-checked against `c3-8`. **Confirm `98bec81` (mirror snapshot from `954bd22`, 2026-07-10)
   before the first arm; do NOT `git pull`.** State the build in the handback (§8 item 1). **See §1.5 for what the
   real exposure is — and, importantly, what it is NOT.**
2. **PREREQUISITE CLEARED — the m7i.4xlarge engine upsize is DONE** (owner, 2026-07-12). The *"still-open
   provisioning prerequisite"* in the rig-review block below is **RESOLVED**: the engine box is now the 16-vCPU
   m7i.4xlarge that §1.3 requires. **C5 is therefore decisive** — an INSUFFICIENT verdict at C5-c or above is **no
   longer auto-deferred** as a box artifact. The §3.2 carve-out stays in force as the **backstop**, unchanged.

**Two things to RE-VERIFY rather than assume** — the rig sat idle and the engine box was just *replaced*:

- `SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized')` = **1**. A store restart is exactly when this silently
  reverts. **Feature OFF ⇒ VOID** (§1.2) — you would be measuring C2's retracted tempdb-catalog latch, not C3's residual.
- The **store box is still the unchanged i4i.2xlarge**. Only the **engine** box was resized.

---

## REVISION 2026-07-11 (per bench review — supersedes v1)

This is **v2**. Run this file, not v1. The bench verifier's review
(`C5_review_run-as-written_2026-07-11.md`) flagged four items; the coordinator has ruled on all four and
this revision applies those rulings. What changed and why:

- **① Engine-box co-constraint (Decision B).** C5-c (261 ev/s) and up sit near the 8-vCPU engine box's own
  ~88% CPU wall, so an `R` capped there could be a **rig** artifact misread as a **design** verdict. Fix:
  **run ALL of C5 on the m7i.4xlarge (16-vCPU) engine box** the throughput doc's Phase-5 already prescribes
  for N≤8 (the i4i.2xlarge **store** box is unchanged). Added a **pre-registered carve-out** to §3: a rung
  that fails with the **engine** box saturated (`max_core%` ≥ ~85%) **while the store is not** saturated is an
  engine-box co-constraint → `R` below it is a **lower bound**, any INSUFFICIENT verdict is **deferred** pending
  a re-run on a still-larger engine box. See §1/§2/§3/§5.
- **② Control rung & `R`'s definition (Decision A).** The feature was already ON at C3's N=8 and *still* showed
  the +4.04 growing backlog slope, so latch-free does **not** flatten it — treating a growing slope as a
  *disqualifier* would leave `R` **undefined** (even the lightest rung is marginal). Fix: **`R` is redefined as
  the highest per-shard rate that meets the store-truth PASS bar** (delivered ~100% within hold+drain, drained
  within `--drain-timeout 150`, stranded 0, dead 0, no lane inversions/repeats) — well-defined even when the
  control is marginal. The `in_pipeline` backlog **slope is now a MARGINALITY ANNOTATION on `R`, not a gate**.
  **C5-a is now an explicit DRIFT CHECK** (must reproduce `c3-8`'s numbers incl. slope ≈ +4), **not** a
  sustain/PASS gate. See §3/§4/§6/§8.
- **③ Two minors (Decision D).** (a) Added the **raw-vs-publishable** cross-reference: `R` thresholds are raw
  capability; any *published* N-sizing claim carries the Phase-5 **D4 0.5 derate**, so publishable-at-N=16 needs
  `R ≈ 7.24` — which (exactly) equals C5's raw N=8 threshold (`16×9×0.5 = 72 = 8×9`), so the whole
  "potentially sufficient" band lies **below** the publishable-at-N=16 line. (b) **Trimmed** the "retires
  open-question #2 for free" over-claim — C5 is pooled at fixed N=8, so it answers neither OQ#2 (per_lane
  ceiling) nor the vary-N Phase-5 question; it feeds **one input rung** into Phase-5. See §3/§4.
- **④ / label fixes (Decisions C & D).** C4 returned **WITHHELD** (non-CONFIRM; the claim-rewrite path is
  separately weakened — `list_fifo_lanes` is raw-CPU #1 at N=16, ~72% of the wall is off-CPU WAIT), so §3's
  verdicts are reworded from "REWRITE sufficient/insufficient" to "**N-SIZING** sufficient/insufficient
  (independent of any claim rewrite)": `R` is a latch-free per-shard **N-sizing** ceiling measured as the code
  ships. Corrected the units-bug label: it is **B10** (throughput doc Phase 0), **not #861** (#861 is the
  per-PID CPU-collector fix). See §0/§3/§4/§5/§8.

**⚠️ CORRECTION 2026-07-11 (C4 clean recapture) — the drift anchor is REMOVED, not just re-based.** An earlier
adversarial-verify pass anchored C5-a's drift check on C3's `c3-8` slope (+4.04) and treated the c4-8 +7.48 as an
*apparatus* effect of C4's heavy capture. **The clean recapture refuted the apparatus story:** capture weight
does not move the slope — the *lighter* c4-8 ran **+13.0** (stranded 3,175), so the N=8/2-shard slope is genuinely
run-to-run variable **+4…+13** at this marginal point and is **not a reproducible drift anchor.** → **C5-a is now
a LOOSE setup sanity check** (shape/feature/delivery/store-CPU-band), **NOT** a slope- or outcome-match gate; a
slope in +4…+13 is normal variance, not drift. `R` keys on the delivery/drain PASS bar across the climbing rungs.
See §2 (C5-a row), §5 (the correction note), §8 item 5.

**Post-revision adversarial verify (2 lenses, 2026-07-11) — fixes applied on top of v2:**
- **Drift anchor (superseded by the correction above).** §5 originally re-based C5-a's anchor to c3-8's +4.04
  "because C5 runs light" — now REMOVED: the recapture showed light ran +13, so slope is not an anchor at all.
- **Pass bar made binary (was a fuzzy "~100%").** §3.1 now keys on the harness `result=PASS` (`drained ∧
  stranded=0 ∧ dead=0 ∧ FIFO`); delivered=100% is a *consequence*, not a threshold; `offered` is defined. No 99.x%
  grey zone for two operators to split `R` on.
- **Carve-out co-limited seam closed.** §3.2: if a fail rung has both boxes within ~5 pts of their bars, DEFER.
- **Numeral.** §3.4 `7.24 → 7.23` (both are the single value `520.83/72`).

**Rig v2-prereq review (2026-07-11) — one seam closed:**
- **Symmetric LOAD-GEN carve-out added (§3.2 / §3.3).** The engine box had a co-constraint carve-out; the load-gen
  did not — a real seam at C5-e (58/s fleet, far beyond C2/C3). Now a fail with the **load-gen saturated while the
  store is not** also → `R` lower bound, verdict DEFERRED. (`loadgen_cpu_soak.csv` already captured — a rule, not new
  instrumentation.)
- **~~Still-open provisioning prerequisite~~ → ✅ RESOLVED 2026-07-12 (owner):** §1.3's **m7i.4xlarge engine upsize**
  was a real EC2 resize (rig engine had been m7i.2xlarge / 8-vCPU). **It has been done** — the engine box is now the
  16-vCPU m7i.4xlarge, so a **decisive** C5 is possible and C5-c+ INSUFFICIENT verdicts are **no longer auto-DEFERRED**
  as a box artifact. The §3.2 carve-out remains the backstop. (See the v2.1 amendment at the top.)

**Preserved unchanged:** the ×9 total-events arithmetic (no units bug), C4-sequencing + `TEMPDB_METADATA=ON`
pre-flight (feature-OFF = void), the one-sided-falsifier design, `--drain-timeout 150`, gate on `result`, no
`per_lane`, don't quote a collapsed arm's ceiling.

---

## 0. Why this run exists — read this even if you skip the rest

C1/C2/C3 all scaled **shard count `N`** at a *fixed, deliberately light* **2 ingress/s per shard**. Not one of them
ever asked the other question: **how hard can a single shard be driven when `N` is large and the tempdb latch is
gone?** That number has never been measured, and the entire capacity story now hangs on it.

Here is the arithmetic that makes it decisive (`total events = ingress × (1 + dests)`, `dests=8` → ×9):

| what you'd need | per-shard ingress required to hit 520.83 events/s |
|---|---:|
| at **N=8** | **7.23 /s** |
| at **N=16** | **3.62 /s** |

And here is everything we currently know about per-shard headroom — **all of it from N=4 on the pooled default**:

- **2.5 /shard sustains** (10 ingress/s fleet, 900 s, drained clean)
- **3.0 /shard fails to drain** (12 ingress/s, `in_pipeline_final` 825, slope +12.17)
- C1's matched-load penalty **worsens monotonically** with per-shard load (1.01× @2/sh → 1.53× @6 → 3.12× @10;
  collapse @12). *Direction firm, magnitudes SOFT — both C1 soaks collapsed.*

So on the shipped default at N=4, the per-shard ceiling sits **between 2.5 and 3.0** — and the target needs **3.62
at N=16**. If the latch-free ceiling at N=8 is in that same 2–3 band, then **even a fully cleared N=16 would still
miss 520.83** — because clearing N=16 *at the 2/shard probe load* only delivers 288 events/s (1.81× short). C5
measures a **latch-free per-shard N-sizing ceiling as the code ships today** — an N-sizing quantity, not a rewrite
quantity — so it answers **"is the N-sizing PATH alive?"**, full stop.

**C4 returned WITHHELD** (non-CONFIRM). That handback separately weakened the claim-rewrite story — at N=16 the
raw-CPU #1 store consumer is `list_fifo_lanes` (the dispatcher's read-only ready-lane discovery scan), **not** the
claim, and ~72% of the N=16 claim wall is off-CPU lock/latch WAIT — so a claim-only rewrite would not clear the
wall. That makes C5's question sharper, not moot: independent of any rewrite, **can N-sizing alone (latch-free,
pooled) reach the per-shard rate the target needs?** C4 asked whether a specific rewrite targets the right thing;
C5 asks whether the N-sizing path could ever be enough. Different questions; this one is cheaper.

**C5 is NOT** a shard sweep, a fix, or a C4 substitute. It changes no engine code.

> **Units label.** The `45,000,000 / 86,400 = 520.83` events/s figure and the `ingress × (1+dests) = ×9`
> total-events arithmetic are the **B10** units fix (throughput doc Phase 0) — **not #861** (#861 is the per-PID
> CPU-collector fix cited in §5).

---

## 1. PRE-FLIGHT (blocking)

1. **Run C4 first, and do not disturb it.** C4 forbids changing any pipeline variable; C5 deliberately changes one
   (the per-shard rate). Finish C4, bank its handback, *then* start C5. (C4 is banked: **WITHHELD** — see §0.)
2. **Feature must be ON:** `MEMORY_OPTIMIZED TEMPDB_METADATA = ON` (two keywords, a SPACE), same enable+verify
   sequence as C3/C4 — RG pool `tempdb_xtp` @25%, restart, then confirm
   `SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized')` = **1** and the ERRORLOG line. **If C4 left it on,
   leave it on — that is the whole point of running these back to back.** A C5 run with the latch present measures
   C2's wall, not C3's residual, and is void.
3. **Run C5 on the m7i.4xlarge (16-vCPU) engine box** — the upsize the throughput doc's Phase-5 already prescribes
   for N≤8. The 8-vCPU box's own ~88% CPU wall sits right under the decision rung (C5-c = 261 ev/s), so an `R`
   capped there would be a **rig** artifact misread as a **design** verdict. The **store box is unchanged**
   (i4i.2xlarge). If for any reason C5 must run on the 8-vCPU engine box, the §3 carve-out applies and every
   INSUFFICIENT verdict at/above C5-c is a **deferred lower bound**, not a design verdict.
4. Everything else identical to C2/C3: `dests=8`, pooled, `--drain-timeout 150` (**do not raise it — 300 s re-arms
   B7**), 900 s soaks.
5. **Engine build pinned to `98bec81`** — the same build C3 and C4 ran (**added in the v2.1 amendment; v2 omitted this**).
   Mirror snapshot `98bec81`, published from private `954bd22` on 2026-07-10. **Confirm before the first arm; do NOT
   `git pull`.** (C6 pins the same commit.) `R` is scored against the C1–C3 ladder and C5-a is sanity-checked against
   `c3-8`, so the build must not move under the run.

   **Scoped honestly — what the exposure is, and what it is NOT** (verified against the mirror 2026-07-12):

   - **The mirror HEAD has already moved one snapshot past the pin**, to `dd701b2`. So a `git pull` is **not** a no-op
     — it does move the build. That is why the pin exists.
   - **But that particular drift is INERT for the bench, and does not void a run.** `98bec81 → dd701b2` is 5 commits,
     4 of them docs, and **exactly 4 lines of engine code**: an opt-in `MultiSubnetFailover=Yes` ODBC keyword in
     `store/sqlserver.py`, gated on a `multi_subnet_failover` setting that **defaults to `False`**. **If the rig is
     already on `dd701b2`, C3/C4 comparability HOLDS — record the build and proceed; do not void the run.**
   - **The REAL exposure the pin guards against is a FUTURE publish.** The private repo is ~94 commits and ~6,500
     lines of engine change ahead of the pinned snapshot — **including the `accepts=` Router-stage seam (#952), which
     changes the very routing path C5 measures.** **None of that is on the mirror yet.** The moment anyone runs
     `publish.ps1`, a `git pull` mid-arc would swallow all of it and silently invalidate `R`. **So: do not pull, and
     if the build is anything other than `98bec81` or `dd701b2`, STOP and report it before running an arm.**

   *(Correction, 2026-07-12: an earlier draft of this item claimed a fresh pull would pick up the `accepts=` seam
   today. It would not — that seam is private-only and unpublished. The pin stands; the stated reason was wrong and
   is fixed above.)*

## 2. THE RUN — N=8 fixed, walk the per-shard rate up until it breaks

**`N = 8` in every arm. Engine box = m7i.4xlarge (16 vCPU); store box = i4i.2xlarge (unchanged) — see §1.3.**
The only variable is per-shard offered ingress.

| arm | per-shard ingress | fleet ingress | fleet events/s | why this rung |
|---|---:|---:|---:|---|
| **C5-a** | **2** | 16 | 144 | **LOOSE SETUP SANITY CHECK (not a sustain gate, not a slope-match).** Confirm the shape built (N=8, 2/shard, feature ON), high delivery, store CPU in a plausible band. **Do NOT gate on the backlog slope** — it is run-to-run variable **+4…+13** at this marginal point (§5 correction); a slope in that band or a small stranded count is normal variance, not drift. Stop only on a *catastrophic* divergence (delivery far below ~C3 / store CPU wildly off / build mismatch). It is *not* the R ladder — R is measured across the climbing rungs (C5-b+). |
| **C5-b** | **3** | 24 | 216 | First R rung. The rate that already **failed to drain at N=4** on the default config. Does latch-free N=8 hold it? |
| **C5-c** | **3.62** | 29 | 261 | ⭐ **THE DECISION RUNG.** This is the per-shard rate a cleared N=16 would need to reach 520.83. Capture engine `max_core%` on **both** boxes + store CPU% here (§3 carve-out). |
| **C5-d** | **5** | 40 | 360 | Only if C5-c meets the pass bar. Starts bracketing the real ceiling. |
| **C5-e** | **7.23** | 58 | 521 | Only if C5-d meets the pass bar. This is target-at-N=8 — i.e. N=8 alone is sufficient. Would be a very big result. |

**`R` is the highest R rung (C5-b or above) that meets the store-truth PASS bar (§3).** Stop at the first rung that
fails the bar; `R` is the last rung that met it. Ladder down by 0.5/shard between the last PASS and the first
failure if you want a tighter bracket and the time is cheap — but the bracket matters far less than which side of
**3.62** `R` lands on. **Annotate `R` with its `in_pipeline` slope** (a growing slope = "`R` is near the edge"); the
slope is a marginality note on `R`, **not** a gate that can move it (§3).

## 3. DECISION RULE (pre-registered — fixed before the run)

### 3.1 `R` — the store-truth PASS bar

Let **`R`** = the highest per-shard ingress rate at N=8 (across the climbing R rungs C5-b+) that meets the
**store-truth PASS bar** — the harness's own `result = PASS`, which is **binary**, not a fuzzy percentage:

- **drained** — `in_pipeline → 0` within `--drain-timeout 150` (`drained: true`; "within" = before the 150 s
  timeout fired, not a wall-clock stopwatch bound)
- `stranded: 0` **and** `dead: 0`
- **no lane inversions / repeats** (FIFO intact)

**`drained ∧ stranded=0` already forces delivered = offered (100%)** — every offered message left the pipeline —
so "~100% delivered" is a *consequence* of the bar, not a separate threshold to argue over. Define the denominator
once for the record: **`offered = per-shard rate × N × hold_seconds`** (drain-window arrivals excluded), read
phase-matched to the same soak. A rung that leaves *any* row stranded at the drain deadline **fails** — there is no
99.x% grey zone, because `stranded > 0` is a clean FAIL. (If a future run wants a soft floor, pre-register the exact
percentage and the `offered` field *before* the run; do not choose it to fit a result.)

`R` is **where delivery/drain BREAKS** — the last rung meeting the bar before the first rung that fails it. This is
well-defined **even when the control is marginal**: it does not depend on the backlog slope.

**The `in_pipeline` backlog slope is a MARGINALITY ANNOTATION on `R`, not a gate.** C3's `c3-8` cleared delivery but
carried a **+4.04 rows/s** backlog slope (*"GROWING, slow saturation"*). Crucially, **the latch-free feature was
already ON at C3's N=8 and the +4.04 slope persisted** — so latch-free does **not** flatten it, and treating a
growing slope as a *disqualifier* would leave `R` **undefined** before the ladder even starts (even the lightest
rung is marginal). So: **report the slope at every rung.** A growing slope means `R` **is near the edge** — surface
it as "`R = x /shard`, marginal (backlog slope +y)"; it does **not** move `R`. That marginality signal is the
durability half of what C5 exists to settle — this re-check is the whole reason to revisit N=8 — but it is a
*qualifier on `R`*, not a second pass/fail axis.

*(This supersedes v1's rule that "a rung with a growing backlog slope is NOT a sustain, even if it drains." That
rule made `R` undefined; it is removed.)*

### 3.2 Engine-box co-constraint carve-out (pre-registered)

At every rung, capture `max_core%` on **all three boxes** (engine, store, **and load-gen**) **and** store CPU% (§5).
Read them together and **judge** which resource bound first — this is a human read of reported numbers, **not** an
auto-gate:

- A rung that **fails the pass bar with the ENGINE box saturated** (`max_core%` ≥ ~85% — a *reported-and-judged*
  reading, not a computed trigger) **while the STORE is NOT saturated** (store CPU well below the C3-16 92–93%
  mark) is an **engine-box co-constraint, NOT a store/design verdict.** In that case the `R` below it is a **LOWER
  BOUND**, and any "N-SIZING INSUFFICIENT" verdict is **DEFERRED** pending a re-run on a still-larger engine box.
  (This mirrors the R≥7.23 re-run discipline in the table below. The bench box is a plausible **co-constraint** at
  C5-c+, never "the box will be the wall.")
- **Symmetrically, a LOAD-GEN co-constraint (pre-registered).** A rung that **fails with the LOAD-GEN box saturated**
  (`max_core%` ≥ ~85%, reported-and-judged) **while the STORE is NOT saturated** is a **load-gen co-constraint, NOT
  an N-sizing verdict** → `R` is a **LOWER BOUND**, verdict **DEFERRED** pending a re-run with a larger/split
  load-gen. This closes the exact "you may be measuring the load-gen's ceiling, not the engine's" risk §5 names —
  acute at **C5-e (58/s fleet)**, far above anything C2/C3 drove, and the same class as the throughput doc's caution
  that the `per_lane` ~28/s ceiling "may have been the bench box." (`loadgen_cpu_soak.csv` is already captured, §5 —
  this is a rule, not new instrumentation.) A DEFER holds if **either** the engine **or** the load-gen is the
  saturated non-store resource; only a **store-saturated** or **all-boxes-clearly-cool** fail is a clean N-sizing
  verdict.
- A rung that fails **with the STORE saturated** (like C3's N=16 at 92–93%), **or with NEITHER box saturated**, is a
  **legitimate design verdict** — read the table straight. **One seam to pre-register:** if a fail rung has neither
  box across its bar but **both are within ~5 points of it** (engine `max_core%` ~80% *and* store CPU ~87–90%, say —
  co-limited, neither cleanly the wall), treat it as an engine-box **co-constraint → DEFER**, not a clean design
  verdict. Only a fail where the store is *clearly* the sole saturated resource (or both are *clearly* cool) reads
  straight. This closes the one gap where the binary read would force a verdict on an ambiguous, co-limited rig.

Running C5 on the m7i.4xlarge (§1.3) is the mitigation that makes an engine-box co-constraint *unlikely* at these
rungs; the carve-out is the backstop if it hits anyway.

### 3.3 The verdict table (N-sizing, independent of any claim rewrite)

`R` is a **latch-free per-shard N-sizing ceiling measured as the code ships today.** It is an **N-sizing** quantity,
not a rewrite quantity — so these verdicts are phrased in N-sizing terms and hold **regardless of any claim
rewrite.** (C4 returned **WITHHELD**, so there is no CONFIRMED rewrite to lean on anyway; C5 answers "is the
N-sizing PATH alive," full stop — see §0.)

| `R` lands | verdict | what you do next |
|---|---|---|
| **`R` < 3.62** | **N-SIZING INSUFFICIENT** (independent of any claim rewrite) | Even a fully cleared N=16 would **still miss 520.83**, so N-sizing is dead as a standalone path. The `txn/event` levers (Phase 3 `accepts=`, Phase 4 group-commit) stop being follow-ons and become **mandatory co-requisites**. Re-plan before building. **Carve-out (Decision B):** if this fail rung had **either the engine OR the load-gen box saturated while the store was not** (§3.2), `R` is a **lower bound** and this verdict is **DEFERRED** pending a re-run on larger iron (engine upsize, or a larger/split load-gen) — it is a box co-constraint, not an N-sizing verdict. |
| **`3.62 ≤ R < 7.23`** | **N-SIZING POTENTIALLY SUFFICIENT** (independent of any claim rewrite) | A cleared N=16 at rate `R` reaches `16 × R × 9 ≥ 521` **raw** events/s. This is **raw latch-free capability** (go/no-go on whether the N-sizing path is alive), **not** a publishable claim — see §3.4. To make it real you still need N=16 to actually clear at rate `R`; then re-run the C2/C3 sweep to show sufficiency. Separate claims; do not collapse them. |
| **`R` ≥ 7.23** | **N=8 ALONE HITS TARGET (raw)** | Extraordinary — and *suspect*. Before publishing: confirm the load-gen was not the limiter (§5), re-check `max_core%` on **both** boxes, and re-run the arm. A result this good against everything C1/C2/C3 measured is more likely an instrument fault than a win. Publishing still carries the §3.4 D4 derate. |

**Do not soften an `R < 3.62` result** (absent the §3.2 engine-box carve-out). The temptation will be "but a rewrite
would raise `R` too." It might! That is a *hypothesis*, and C5 does not test it — C5 measures `R` **as the code ships
today, latch-free**. Pinning value on an unmeasured `R` improvement is the same adjacency inference that got C2
retracted.

### 3.4 Raw capability vs publishable rate (Decision D — a cross-reference, not an arithmetic fix)

`R`'s thresholds (3.62/shard @N=16, 7.23/shard @N=8) are **raw** — `ingress × N × 9 = 520.83`, **no derate**. They
are a go/no-go on whether the N-sizing **path** is alive. Any **published** N-sizing claim carries the throughput
doc's **Phase-5 D4 rule: publish at ≤50% of the measured ceiling** (`N × per-shard × 0.5`). So a *publishable*
45M/day claim at N=16 needs `R ≈ 7.23` — which is the **same threshold** as C5's raw N=8 go/no-go, because both
are `520.83 / 72`: `16 × 9 × 0.5 = 72 = 8 × 9`. (Both round to 7.23/shard; they are one number, `520.83/72 =
7.234…`, not two.) Consequence: **the entire "potentially sufficient" band (3.62 ≤ `R` < 7.23) lies below
the publishable-at-N=16 line.** A raw `R` just over 3.62 earns "potentially sufficient" but its D4-publishable rate
is half of raw — not a certifiable 45M/day claim. Keep raw and publishable distinct in the handback.

## 4. WHAT ELSE THIS RUN FEEDS

- **The N=8 durability re-check.** C3's N=8 clear was explicitly *marginal*, not comfortable — backlog slope +4.04
  rows/s, store CPU climbing 40→60% through the soak, and ingress never driven above 16/s so headroom was
  uncharacterized. C5-a **reproduces** it as a drift check (§2) and C5-b/c/… characterize the headroom, surfacing
  the backlog slope as `R`'s marginality annotation (§3.1). The durability signal — the whole reason to revisit N=8
  — is preserved.
- **One input rung into Phase-5.** C5 feeds a **pooled per-shard `R` at fixed N=8** into the throughput doc's
  Phase-5 analysis (`docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md`). **It does NOT retire open-question #2** —
  OQ#2 is *per_lane*'s real ceiling at a 900 s hold, and C5 runs **pooled** (forbids `per_lane`, §6) at **fixed
  N=8**, so it answers neither OQ#2 nor the vary-N Phase-5 flatness question. It contributes exactly one rung; do
  not over-claim it as retiring either.

## 5. CAPTURE (the LIGHT C2/C3 instrument set — NOT C4's heavy per-query capture)

> **Run C5 at the C2/C3 apparatus level, deliberately WITHOUT C4's per-query `sys.dm_exec_query_stats` / XTP
> capture worker.** C5 measures per-shard headroom (`R`) — it needs delivered / drain / backlog-slope +
> `max_core%` + store CPU%, none of which require per-query CPU attribution.
>
> **⚠️ CORRECTION 2026-07-11 (clean recapture) — do NOT use the N=8 backlog SLOPE as a drift anchor.** An earlier
> draft anchored C5-a's drift check on reproducing `c3-8`'s slope (≈ +4), on the theory that C4's heavier capture
> had inflated it to +7.48. **The recapture refuted that:** capture weight does **not** drive the slope — the
> *lighter* c4-8 arm ran **+13.0** (stranded 3,175), *worse* than the heavy +7.48 and far from c3-8's +4.04. So the
> N=8/2-shard backlog slope is **genuinely run-to-run variable (+4 … +13) at this marginal operating point**, and it
> is **not a reproducible drift anchor.** → **C5-a is a LOOSE setup sanity check, not a slope/outcome-match gate:**
> confirm the shape built (N=8, 2/shard, feature ON verified §1.3), store CPU in a plausible band, and delivery
> high — a slope anywhere in **+4…+13** or a small stranded count is **normal marginal-point variance, NOT rig
> drift.** Only a *catastrophic* divergence (e.g. delivered % far below ~C3, store CPU wildly off, or a build/port
> mismatch) means "stop." `R` is measured on the delivery/drain PASS bar (§3.1) across the **climbing** rungs
> (C5-b+); it does not depend on C5-a reproducing any slope.

Per arm: the report JSON, `claim_phase_soak.txt`, `cpu_soak.csv` + `loadgen_cpu_soak.csv`, `storedmv_soak.txt`,
`storepage_soak.txt`. Plus:

- **`in_pipeline` slope for every arm** — it is the **marginality annotation on `R`** (§3.1): report it at every
  rung and attach it to `R` as "near the edge / comfortable." It does **not** gate `R` and is not a second pass/fail
  axis; it is not a footnote either.
- **Whole-box + per-core CPU on BOTH boxes** (`max_core%` — the validated substitute; the per-PID collector's
  `0.00` was diagnosed and fixed in **#861**, but shardcert still has no in-harness per-PID sampler, so `max_core%`
  remains what you read). Engine box is the **m7i.4xlarge** (§1.3); capture `max_core%` on the engine box **and** the
  store box every arm — the §3.2 carve-out reads both. *(#861 = the per-PID CPU-collector fix; the units-bug fix is
  **B10**, §0 — do not conflate them.)*
- **Load-gen CPU.** At the higher rungs (C5-d/e) the load-gen box is being asked to drive 40–58 msg/s, far above
  anything C2/C3 asked of it. **If load-gen CPU climbs, the ceiling you measure may be the load-gen's, not the
  store's** — this is the single most likely way C5 produces a wrong answer. Report it explicitly and, if it is
  non-trivial, say so rather than reporting `R` as an engine result.
- **Store CPU%** — at the rung that fails, is the store CPU-saturated (like C3's N=16 at 92–93%) or is it something
  else? This is the input to the **§3.2 carve-out**: store-saturated fail = a legitimate design verdict; engine-box
  saturated with the store *not* saturated = an engine-box co-constraint, `R` is a lower bound, verdict deferred.
  It is also the one place C5 can cheaply corroborate C4.

## 6. Do NOT

- Do not run C5 with the latch present (feature OFF) — void.
- **Do not `git pull` the engine build** (§1.5). Run on `98bec81`. `dd701b2` (the current mirror HEAD) is **also
  acceptable and NOT a void** — its only engine delta is an opt-in setting that defaults off. **Any other build ⇒ STOP
  and report before running an arm** — a future `publish.ps1` would bring the unpublished `accepts=` seam onto the
  mirror and silently invalidate `R`.
- Do not flip `claim_mode` to `per_lane`.
- Do not raise `--drain-timeout` past ~300 s (re-arms B7). Keep **150**.
- Do not read `exit_code` as a verdict — gate on **`result`**. (Every collapsed arm in C1/C2/C3 serialized
  `exit_code = 0`.)
- Do not quote `ceiling.sustained_events_per_s` from a **collapsed** arm — that key is populated even when
  `result = SOAK_NOT_SUSTAINED` (it reads 145.359 on `c3-16`, an arm that delivered 27.9%). It is a trap.
- Do not treat a **growing backlog slope** as a disqualifier that moves `R` — under v2 it is a **marginality
  annotation** on `R`, not a pass/fail gate (§3.1). (This reverses v1.)
- Do not read an engine-box-saturated fail (engine `max_core%` ≥ ~85%, store **not** saturated) as an N-sizing
  verdict — that is an engine-box **co-constraint**; `R` is a lower bound and the verdict is deferred (§3.2).

## 7. TEARDOWN

Only after **both** C4 and C5 are banked:

```sql
ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = OFF;   -- two keywords, space
-- RESTART SQL Server (disable also requires a restart).
-- optionally:  DROP RESOURCE POOL tempdb_xtp;   (after restart)
```

## 8. What to send back (`HANDBACK_C5_<date>.md`)

1. Proof the feature was active (`IsTempdbMetadataMemoryOptimized` = 1) — else void. Also state the **engine build**
   (`98bec81` expected; `dd701b2` acceptable — anything else, report it, §1.5), the **engine box** used (m7i.4xlarge
   expected, §1.3), and that the **store box** was i4i.2xlarge.
2. Per-arm table: per-shard rate, fleet ingress, `result`, delivered %, stranded, dead, **`in_pipeline` slope**,
   claim_mean, store CPU%, engine `max_core%` (**both boxes**), **load-gen CPU**.
3. **`R`** — the highest per-shard rate at N=8 (C5-b+) that meets the **store-truth PASS bar** (§3.1: ~100%
   delivered, drained ≤150 s, stranded 0, dead 0, FIFO intact), **annotated with its `in_pipeline` slope** as a
   marginality note (`R` is "comfortable" vs "near the edge" — the slope does **not** move `R`).
4. **The §3.3 verdict: N-SIZING INSUFFICIENT / N-SIZING POTENTIALLY SUFFICIENT / N=8 ALONE HITS TARGET (raw)** —
   phrased in N-sizing terms, independent of any claim rewrite (C4 = WITHHELD). If the fail rung was **engine-box
   saturated with the store not saturated**, say so and mark the verdict **DEFERRED** with `R` as a lower bound
   (§3.2). Report `R` **raw** and note the D4-publishable rate is `N × R × 0.5` (§3.4).
5. Did C5-a pass its **loose setup sanity check** (shape built, feature ON, high delivery, store CPU plausible)?
   **Do NOT report a slope-match verdict** — the N=8/2-shard slope is run-to-run variable +4…+13 (§5 correction).
   Only a *catastrophic* divergence means the rig drifted; say so **first** if so.
6. One-line read: **is the N-sizing PATH alive** — can latch-free pooled N-sizing (as the code ships, no rewrite)
   reach the per-shard rate the target needs at N=16, or does the target need the `txn/event` levers too? (C4 is
   WITHHELD, so this is the standing question C5 answers.)

## 9. Sources

- Capacity frontier + the 3.62/shard threshold: `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` §8 (which now
  contains the **"The capacity frontier"** subsection as of PR #928), §9 open question #2.
- **Phase-5 sizing + the D4 0.5 publish derate + the m7i.4xlarge N≤8 upsize:** same status doc, Phase-5 (D4 rule
  `publish N × per-shard × 0.5`; rig-inadequate-for-N≤8 sizing note).
- N=4 headroom points (2.5 sustains / 3.0 fails to drain): status doc §3 Trustworthy.
- C3's marginal N=8 clear (+4.04 rows/s slope, 40→60% store CPU): `HANDBACK_C3_memopt_tempdb_metadata_2026-07-10.md` §1.
- C4 = **WITHHELD** (`list_fifo_lanes` raw-CPU #1 at N=16; ~72% of the wall off-CPU WAIT): `HANDBACK_C4_2026-07-11.md`.
- Units-bug fix label: **B10** (throughput doc Phase 0). #861 = the per-PID CPU-collector fix.
- Read-only DMVs / public catalog names only. No secrets, hostnames, IPs, ports, or customer identifiers.
