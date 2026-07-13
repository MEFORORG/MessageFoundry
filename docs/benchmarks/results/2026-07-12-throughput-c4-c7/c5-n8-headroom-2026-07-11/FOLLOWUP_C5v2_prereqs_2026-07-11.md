# FOLLOW-UP — C5 v2 review: one prerequisite + one seam

**Date:** 2026-07-11 · **From:** AWS bench (relayed via operator) · **Re:** `HANDOFF_C5_n8_per_shard_headroom.md` (v2)

v2 is a clean, thorough revision — all four review items ruled on and applied correctly, the recapture correction folded in (C5-a → loose setup sanity check; N=8/2-shard slope is genuinely +4…+13 run-to-run, not a drift anchor), and the further 2-lens pass (binary `result=PASS` bar, co-limited-seam DEFER, 7.24→7.23) tightens it further. Two things before a run:

## 1. The m7i.4xlarge engine box (§1.3) is a real infra prerequisite — the gating decision
Decision B upsizes the engine box to **m7i.4xlarge (16-vCPU)**. The current rig engine box is **m7i.2xlarge (8-vCPU)** — so this is an actual provisioning step (resize/replace the engine EC2 instance; the i4i.2xlarge **store** box stays as-is, feature ON). It is the gating item for a **decisive** C5: without it, C5 runs on the 8-vCPU box, the §3.2 carve-out fires at the decision rung and up, and **every C5-c+ INSUFFICIENT verdict comes back DEFERRED (lower bound), not a clean N-sizing verdict.** So the run buys much less on the 8-vCPU box. Recommend deciding the upsize **before** starting — it's the one prerequisite the other runs (C4/C6, which use the existing rig at 2/shard) don't have.

## 2. The load-gen lacks the carve-out the engine box got (a seam)
§3.2 gives the *engine* box a pre-registered co-constraint carve-out, and §5 flags load-gen CPU — but there is **no symmetric carve-out for a load-gen-saturated fail.** At C5-e (58/s fleet) the load-gen drives far beyond anything C2/C3 exercised, and the throughput doc already noted the per_lane ~28/s ceiling "may have been the bench box." Suggest a **parallel pre-registered rule:** a fail rung with the **load-gen box saturated (`max_core%` ≥ ~85%) while the store is not** is a load-gen co-constraint → `R` is a lower bound, verdict DEFERRED — same logic as the engine-box carve-out. §5 already captures `loadgen_cpu_soak.csv`, so it's a wording add, not new instrumentation. (This is the exact "you may be measuring the load-gen's ceiling" risk §5 names; giving it a carve-out closes the seam the way §3.2 closed the engine one.)

Neither blocks the design — #1 is a provisioning call, #2 is a one-rule add. Public source/DMV names only; no secrets/IPs/PHI.
