# REVIEW — proposed corrections to the C6 handoff (from the C4 clean-recapture)

**Date:** 2026-07-11 · **From:** AWS bench (relayed via operator) · **Re:** `HANDOFF_C6_n16_wait_decomposition.md` (updated)
**Basis:** the C4 clean-recapture, which post-dates the C6 draft. Public source/DMV/catalog names only; no secrets/IPs/PHI.

The updated C6 is strong — the collapse-tail-vs-plateau correction and elevating the `list_fifo_lanes` coupling question to a first-class §3d output are both right, and the coupling point correctly downgrades the C4 "claim-only insufficient" conclusion to **unproven, not disproven**. Two corrections below come from a clean recapture run *after* the C4 handback, plus one efficiency note.

## 1. The apparatus premise (§5 and §9) is now empirically wrong — please reframe
C6 rests on *"C4's in-store capture made c4-16 run +68% claim_mean (93.4 vs 55.7 ms) and flipped c4-8 sustained→not."* All three arms were re-run with a **~6× lighter capture** (TopRows 5000→800, NOLOCK queue scan dropped). Result:
- **claim_mean did not move: heavy 93.4 ms vs light 92.6 ms**, and c4-8 tipped **worse**, not better (backlog slope 13.0 vs 7.5, stranded 3,175 vs 0).
- Store CPU and the N=16 family split reproduced heavy↔light to the decimal.

So the capture *weight* does not drive claim_mean; the +68% vs C3 is **run-to-run variance / C3-vs-C4 drift, not the instrument**. Consequence: keep the `c6-16-nocap` control (the wait cross-check is still worth it), but set its expectation to **~93 ms, not a recovery to C3's 55 ms**, and drop the framing that the capture is a perturbation to be removed.

## 2. "At the sustained plateau the wall looks CPU-bound (0.93)" reads the N=4 value as an N=16 plateau — N=16 has no such plateau
From the c4-16 per-snapshot data: the store sits at **93–94% CPU while the queue grows monotonically, 415 → 11,934 → … → 230,394**, with no flat-backlog window anywhere. The `cpu/elapsed` 0.93→0.70→0.28 progression is **across arms** (N=4 / N=8 / N=16-collapse), so **0.93 is the N=4 arm, not an N=16 plateau**.
- Net: N=16 is a plateau-less collapse; C6's own §3a plateau-existence gate will route it to **AMBIGUOUS-STRUCTURAL by construction**.
- Suggest stating that as the *expected* N=16 outcome up front: C6-16 will most likely **not** name a single wall wait; the usable signal is the N=8 trend + §3d + the reconciliation.

## 3. Efficiency: §3c and §3d don't need a fresh N=16 run
Both are computable from the existing C4 3-arm CSVs.
- **§3c is already in hand:** on the honest phase-matched denominator (plateau **93.3%**, C3-consistent), N=16 reconciliation = **64.4% → the ≤66% AMBIGUOUS band** (vs C4's idle-diluted 70.68%).
- **§3d (the `list_fifo_lanes` coupling answer)** is likewise computable on the existing data with the analyzer's shape-matched machinery — being computed now, so the coupling decision (backlog-effect vs intrinsic → is "claim-only insufficient" proven or unproven) doesn't gate on a C6 run.

None of this blocks C6 — it tightens the priors and sets a realistic N=16 expectation.

## 4. §3d computed on the existing data — the coupling answer
Ran the scan-confound control for `list_fifo_lanes` on the clean light arms, reusing the analyzer's shape-matched sub-interval-summation machinery (method guarded: it reproduces the authoritative claim growth 7.978×).

| metric (N=4 → N=8 → N=16) | value | N=4→16 |
|---|---|---|
| cpu/exec (µs) | 2,926 → 6,596 → 15,633 | 5.34× |
| reads/exec | 283 → 465 → 732 | 2.59× |
| **cpu/read (control)** | **10.34 → 14.18 → 21.34** | **2.06× — RISING** |

**The control is NOT flat → `list_fifo_lanes` is not a pure backlog-scan effect.** It carries a real per-call cost beyond read-depth (`DISTINCT` hash-aggregate + `ORDER BY` sort per page). Corroborated by the analyzer's native coupling test (decoupled, rel 0.52 ≫ 0.15 tol). **Consequence: the "collapse-effect, claim-fix-clears-it" hypothesis fails → "claim-only rewrite insufficient" HOLDS** — the fix must address the whole lane-servicing path, not the claim alone.

**Honest nuance:** a rising cpu/read rules out pure read-depth, but doesn't fully separate *intrinsic* per-page cost from *collapse-induced* per-read inflation (a `DISTINCT` over the 208k pending set could spill). What tips it toward intrinsic: cpu/read already rises at **N=8 (delivers 100%, pre-deep-collapse)** — before the 208k backlog exists. The intrinsic-vs-spill split *at N=16* is the residual §3d can't close, and is exactly what C6's live §3b wait sample would settle (a spill surfaces as a memory-grant / tempdb wait).
