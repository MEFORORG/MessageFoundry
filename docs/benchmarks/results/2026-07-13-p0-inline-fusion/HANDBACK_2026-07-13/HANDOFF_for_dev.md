# HANDOFF for dev — P0 (inline stage-fusion) + where the C5→C6→C7→P0 arc lands

**Date:** 2026-07-13 · **From:** AWS bench (route onward via operator) · **Run:** p0-inline-fusion
**Engine build:** `28f860e` (pinned — carries the `committed_txns` instrumentation `98bec81` lacked; a
deliberate, documented deviation for P0 only — C5/C6/C7 stay `98bec81`). **No engine code changed** — P0's
harness patch is 3 files / ~150 lines, all `harness/config`/`harness/load`, zero production code.

## Verdict: ABANDON THE ANGLE — the Phase-4 premise is dead
Inline stage-fusion **cuts committed transactions substantially** (2.99 absolute / 28.5% relative per
message — a large, clean, reproducible effect; fusion converges almost exactly to the theoretical minimum
transaction count) but **does not move sustained throughput** (B vs A = **−0.56%**, inside the
pre-registered NULL band, smaller than either arm's own run-to-run noise). **The wall is per-message, not
per-transaction.** Corroborated two more ways: A and B's sustaining ceilings tie exactly on a climb probe
(no lift), and a zero-code H-sweep (1→2→4→8 handlers) shows throughput barely moves (−11.7%) even though
the modelled transaction cost per message *triples* over the same sweep — far too weak a relationship to
support the premise.

**Actionable: do not build F2/F3** (the group-commit / batch-fusion program). **F1 may still ship on its
own narrow merit** (one pure-overhead transaction off the ACK critical path) — this verdict doesn't touch
that; it just means it's not part of a bigger throughput-motivated build.

## Where the whole C5→C6→C7→P0 arc lands
Four falsifiers, four kills, each closing off a cheaper hope before the next was tested:
- **C5:** more sharding alone isn't enough (N-sizing insufficient, `R<3.62`).
- **C6:** the collapse isn't a nameable lock/latch/spill convoy.
- **C7:** it isn't self-inflicted store-side parallelism (forcing serial made it *worse*).
- **P0:** it isn't per-message transaction count either — cutting transactions substantially bought nothing.

Every cheaper, more mechanical fix has now been measured and ruled out. **Recommend: the ADR closing
Phase 4 should also step back and ask whether the constraint is structural/architectural** (batching at a
different layer, a topology change, something outside the txn/event framing this whole arc has been
testing) **rather than searching for a fifth variant of the same class of fix.**

## Methods note (transparency)
Getting a trustworthy two-box measurement here required finding and fixing 3 infrastructure bugs — the
load-gen box runs its own, independently-drifting checkout of the harness, which silently swallowed the
new instrumentation across the first several calibration attempts before it was caught and fixed
non-destructively (a new, additive checkout, not a reset of the existing one). Full detail in the
handback §3, flagged in case it's relevant to how future two-box P-series runs get scoped.

## Package contents
- `HANDBACK_P0_2026-07-13.md` — full handback (manipulation check + units-ambiguity resolution, per-arm
  tables, ceiling-vs-ceiling, arm E sweep, the §7 verdict, methods notes).
- `p0-a-r1/2/3`, `p0-b-r1/2/3` — the primary A-vs-B contrast, 3×900s replicates each.
- `p0-cal-a5`, `p0-cal-b` — the calibration/ceiling climbs for both arms.
- `p0-e-h1/2/4/8-r1/2` — the arm-E premise-check sweep, 2×300s replicates per H value.

Read-only DMV / public catalog names only; no secrets, IPs, hostnames, ports, or PHI.
