# ShardCert two-box SIZING ceiling ladder (PR-C2)

The **turnkey** automation of the manual per-rung ceiling hunt (`C1-MANUAL-LADDER-runbook.md`). It pins
the post-#842 delivered-throughput ceiling of the N-active engine-shard fleet against the 45M-messages/day
target, then feeds the `SYSTEM-REQUIREMENTS.md §8` N-active decision. **This bench reports numbers; it does
not flip §8 or grade its own fix** (the two-box governance rule — an operator/owner reviews the result).

It is a pair of looping subcommands, one per box, that iterate the **same** fixed rung plan in lockstep and
reuse the already-merged C1 primitives (`shardcert-engine` / `shardcert-drive`) unchanged:

- `python -m harness shardcert-engine-ladder …` (engine box)
- `python -m harness shardcert-drive-ladder …` (load-gen box)

## What it adds over a single rung

1. **A rate ladder** that climbs past the known floor until a rung is not sustained, with an early-stop
   signal (the drive posts `LADDER_STOP`; the engine skips the rest — best-effort, degrades to the bounded
   plan on a lost signal, never a hang).
2. **A post-hold drain window** — the drive tallies its sinks only after the engine's *reliable store-truth*
   drain gate (`ENGINE_DRAINED`), so a teardown-frozen in-flight tail is absorbed rather than mis-read as
   loss. This is what lets the classifier tell a true congestion-collapse (the engine could not clear the
   backlog) from a latency tail (the engine drained clean but the sink came up short).
3. **A soak** (≥5 min) at the pinned sustainable rate that asserts lossless + a bounded/draining
   `in_pipeline` slope (the sustainable-vs-slow-saturation discriminator).
4. **One consolidated report** (JSON + human-readable): a per-rung table, the pinned ceiling in **both**
   ingress-msg/s and outbound-deliveries/s, the soak slope, and the per-shard `send_ack`/`mark_done` split.

## Verdict authorities (the only two gated on)

- **Drive sink socket-truth:** `S == A*dests ∧ A>0 ∧ S>0 ∧ Σinversions==0 ∧ Σrepeats==0 ∧ lanes_observed≥2`.
- **Engine store-truth (direct store read):** `drained ∧ stranded==0 ∧ dead_total==0`.

The remote `/stats` poller stays **advisory** (unreliable on a unified store — 4× shard-API overcount /
zeroes under load, #841) and is **never** an input to any gate. Per-rung classification:

| verdict | meaning | climb |
|---|---|---|
| `SUSTAINED` | engine drained clean **and** drive lossless — the pinned-ceiling candidate | continues |
| `COLLAPSED` | engine did **not** drain clean (stranded/dead/backlog remained) — the real ceiling | **stops** |
| `FROZEN_TAIL` | engine drained clean but the sink tally came up short with no ordering/dup break — a latency tail, **not** the ceiling (re-run with a longer drain) | continues |
| `CORRECTNESS_FAIL` | a per-lane FIFO inversion or duplicate — fails the ladder verdict | **stops** |

## Target framing (read this before quoting a number)

45M messages/day = `45_000_000 / 86_400 ≈ 520.83 msg/s` of **INGRESS**. Every accepted message fans out to
`dests` destinations, so `delivered = ingress × dests`. The report states **both** figures and is explicit
that 521/s is measured against **ingress**, not the outbound delivery rate. At `dests=8` a modest ingress
rate is a large outbound (sink-tier) load — watch the runbook's sink-tier-wall caveat and lower `dests` to a
realistic fan-out (1–few) if the sink tier saturates first; do not publish a sink-tier ceiling as an engine
ceiling.

## Running it (two-box rig)

Both boxes share a coord dir (a mount/synced folder) and use the **same** `--rate-ladder` and `--run-id`.
Restart + store rebuild first (`RESTART-AND-SIZING-runbook.md` STEP 1–2), and set
`MEFOR_DELIVERY_PHASE_TIMING=1` on the **engine** box for the `send_ack`/`mark_done` split.

```pwsh
# ENGINE box (MEFOR_STORE_* + the escapes per the restart runbook; phase timing on):
$env:MEFOR_DELIVERY_PHASE_TIMING = "1"
python -m harness shardcert-engine-ladder --shards a,b,c,d --dests 8 --sink-ports 8 `
  --sink-host <LOADGEN_IP> --sink-port 3700 --inbound-bind-host 0.0.0.0 `
  --lanes-per-shard 4 --persistent --claim-mode pooled `
  --rate-ladder 20:64:4 --hold-seconds 60 --drain-timeout 150 `
  --soak-hold-seconds 300 --keep-logs-dir C:\srv\mefor\nodelogs `
  --coord-dir <SHARED> --run-id ladder1

# LOAD-GEN box (K | shards*lanes, M | dests, --insecure for the http engine):
python -m harness shardcert-drive-ladder --engine-host <ENGINE_IP> `
  --rate-ladder 20:64:4 --hold-seconds 60 --drain-timeout 150 `
  --soak-hold-seconds 300 --driver-count 4 --sink-count 8 --sink-host 0.0.0.0 --insecure `
  --coord-dir <SHARED> --run-id ladder1 --report-json ladder1.json
```

The `--rate-ladder`, `--hold-seconds`, `--drain-timeout`, and `--run-id` **must match** on both boxes (both
halves derive the identical rung plan and per-rung `run_id`). The drive box emits the consolidated report
(`ladder1.json` + stdout) and exits `0` (correctness held) / `1` (a correctness break) / `2` (setup/timeout).
Then **stop the instances** (a stopped instance loses the ephemeral store on restart anyway).

## Reading the result

- `ceiling.pinned_ingress_rate` / `pinned_outbound_rate` — the highest sustained rung (a **floor** if the
  climb never collapsed → raise the ladder); `first_collapse_ingress_rate` brackets it from above.
- `ceiling.clears_target_ingress` — whether the pinned **ingress** rate clears ~521/s. This is the number
  the §8 decision keys off, but the bench only reports it.
- `soak_ok` — the soak held (SUSTAINED + a flat/draining `in_pipeline` slope).
- `climb[].phase_timing` / `soak.phase_timing` — the `send_ack` vs `mark_done` split (needs
  `MEFOR_DELIVERY_PHASE_TIMING=1`).

Per the D4 publish rule, publish an operating point at **≤50% of the measured ceiling**, and keep the
"supported" wording attribution-conditional (engine-CPU-bound vs store-claim-bound vs sink-tier-bound — see
the restart runbook STEP 4/5). Adversarially review the verdict before calling it.
