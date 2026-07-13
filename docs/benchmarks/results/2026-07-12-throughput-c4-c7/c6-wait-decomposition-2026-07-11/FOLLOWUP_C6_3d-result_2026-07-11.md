# FOLLOW-UP — the §3d value is in (fold into the revised C6)

**Date:** 2026-07-11 · **From:** AWS bench (relayed via operator) · **Re:** revised `HANDOFF_C6_n16_wait_decomposition.md`
The revision looks right — both recapture corrections landed, and re-scoping the no-capture control to the wait-contamination reason (not the disproven throughput perturbation) is the correct call. One item your REVISION block flagged as *"being computed off-line"* — §3d — is now done, on the existing clean 3-arm data.

## §3d result: `list_fifo_lanes` is INTRINSIC, not a pure backlog-scan effect
| N=4 → N=8 → N=16 | value | ×(N=4→16) |
|---|---|---|
| cpu/exec (µs) | 2,926 → 6,596 → 15,633 | 5.34× |
| reads/exec | 283 → 465 → 732 | 2.59× |
| **cpu/read (your control)** | **10.34 → 14.18 → 21.34** | **2.06× — RISING** |

Under your §3(d) reading, **rising cpu/read ⇒ intrinsic per-call cost**, not the deflatable deeper-scan. Method guard: it reproduces the authoritative `claim_fifo_heads` growth (**7.978×**) as a cross-check, and the analyzer's native scan-confound test agrees (decoupled, rel 0.52 ≫ 0.15 tol).

## Where it lands in your doc
- **§0 coupling paragraph / the "claim-only insufficient: unproven vs disproven" call →** it moves to **PROVEN**: `list_fifo_lanes` carries a real per-call cost beyond read-depth, so a claim fix that merely prevents collapse would **not** clear it. **Next build = whole pooled-`StageDispatcher` lane-servicing path, not claim-scoped.**
- **§3(d) deliverable (§8 item 5) →** fill in: EFFECT vs intrinsic = **intrinsic**.

## Honest residual (for your live §3b to close)
A *rising* cpu/read cleanly rules out "pure read-depth," but it doesn't fully separate **intrinsic per-page cost** from **collapse-induced per-read inflation** (a `DISTINCT` over the 208k-row pending set could spill/pressure cache — itself a collapse effect). What tips it toward genuine intrinsic: **cpu/read already rises at N=8, which delivers 100%** (pre-deep-collapse), before the 208k backlog exists. The intrinsic-vs-spill split *at N=16* is the one thing §3d can't fully close — and it's exactly what C6's live §3b sample would settle (a spill surfaces as a memory-grant / tempdb wait).

Full working: `REVIEW_C6_recapture-corrections_2026-07-11.md` §4 (this folder). Public source/DMV names only; no secrets/IPs/PHI.
