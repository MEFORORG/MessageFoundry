# ShardCert two-box SIZING ceiling ladder (PR-C2)

> ## ⚠️ Measurement caveats — read before trusting any number this emits
>
> Originally written 2026-07-09 against the first full run. **Re-verified 2026-07-10 against the code:
> caveats 1, 2 and 3 are now FIXED and must NOT be re-applied by hand — doing so double-corrects an
> already-corrected number.** The errata below say what changed. The pass/fail **verdicts** were always
> sound (they are store-truth driven).
>
> 1. **The climb is a volume test, not a rate test.** `offered = ingress_rate × hold_seconds`, and the
>    rung then gets a fixed `hold + drain` budget to drain it. A rung passes iff
>    `offered × delivering ≤ drain_capacity × (hold + drain)` (the produced deliveries key on the
>    **`delivering`** fan-out, not `dests` — BACKLOG #209). The raw **offered** `ingress_rate` therefore
>    overstates the true sustainable ingress by exactly `(hold + drain) / hold`.
>    > **✅ FIXED — do not re-apply the 3.5× discount.** `ceiling.pinned_ingress_rate` is now the **D1
>    > drain-discounted honest rate** (`RungOutcome.sustainable_ingress_rate` = `ingress × hold /
>    > (hold + drain)`, using the *measured* engine drain, never the drain *timeout*), and
>    > `clears_target_events` keys off it. Multiplying by `(hold+drain)/hold` again **double-discounts**.
>    >
>    > **Read the honest series, not just the pin.** It *declines* as the offer rises — the fleet is not
>    > gaining headroom, it is absorbing a larger burst and draining it afterwards. On the pooled ceiling
>    > re-run: offered `16→36/s` gave honest `13.05 → 10.93/s`, so the pin (`max`) was the **lowest** rung,
>    > and the top rung was the **worst** estimator. Treat the pin as the optimistic end of a bracket and
>    > let a long soak settle the real sustained point.
> 2. **`--soak-drain-timeout` used to default to 300 s**, separate from `--drain-timeout`, so a soak could
>    pass by draining a growing backlog for minutes.
>    > **✅ FIXED.** It now defaults to `None` ⇒ **coupled to `--drain-timeout`** (D2), giving the soak the
>    > same bounded tail-absorption window as a climb rung. Pass it explicitly only to override.
> 3. **`in_pipeline` used to be N× overcounted** — the advisory `/stats` poller sums the whole unified
>    store once per shard API.
>    > **✅ FIXED for the consolidated report.** `engine.in_pipeline_final` is de-duped to a single store
>    > view (`// len(ids)`, D4 / #841 — `shardcert.py`), and the peak sampler divides by `n_shards`.
>    > **Do NOT re-apply `/4`** to the reported value. (The advisory drive-side cross-checks are still
>    > left at N× on purpose; they are not verdict inputs.)
> 4. **Delivered rate uses the wrong denominator.** Deliveries span `hold + drain`, not `hold`. Recover
>    the true span from the phase-timing lines: `span ≈ (windows / shards) × 5 s`. *(Still true.)*
> 5. **Soak rate auto-pick was dishonest before 2026-07-10 (B8).** `pick_soak_rate` selected the top
>    sustained rung's **offered** rate while `pinned_ingress_rate` published the **honest** one — so the
>    soak ran at `(hold+drain)/hold` times the ceiling the very same report printed, and collapsed by
>    construction. **✅ FIXED:** it now selects `max(sustainable_ingress_rate)` over the sustained rungs,
>    i.e. exactly `pinned_ingress_rate`. **Reading an older report JSON: check whether its `soak.ingress_rate`
>    is far above its `ceiling.pinned_ingress_rate` — if so, that soak's collapse is an artifact.**
>
> **⛔ The old "workaround until fixed" recipe is now HARMFUL — do not use it.** It read
> `--rate-ladder 4 --hold-seconds 60 --drain-timeout 150 --soak-hold-seconds 300 --soak-drain-timeout 30`.
> Its premise (caveats 1–3) is fixed, and the explicit **`--soak-drain-timeout 30`** now *undercuts* the
> coupled climb tail: the soak gets a 30 s window to absorb a tail sized for 150 s, so the sinks can tally
> early and a healthy soak renders a **false `FROZEN_TAIL`**.
>
> **Current recipe for a real sustained number** — leave `--soak-drain-timeout` unset (it couples), and
> **bracket** the ceiling with two long soaks around `pinned_ingress_rate` using `--soak-rate <N>` on the
> **drive box** (it overrides the auto-pick, and still runs the soak even if nothing sustained). Judge on
> the soak's store-truth (`drained ∧ stranded==0 ∧ dead_total==0`) + the sink socket-truth.
>
> **⚠️ A collapsed soak still exits `0`** (B9 — corrects an earlier claim in this box that it exits `1`).
> `exit_code` encodes **correctness only**: `0` correctness held · `1` FIFO inversion/duplicate · `2` setup
> degradation. A throughput ceiling is a *measurement*, not a correctness verdict, so a 900 s soak that
> saturated exits `0`. **Never gate automation on the exit code alone** — read `result`
> (`SOAK_NOT_SUSTAINED`) or `soak_ok` / `soak_not_sustained`. And when a soak did not hold, **do not quote
> that run's `pinned_ingress_rate`**: it is derived from the 60 s climb, which the soak just disproved.
>
> **Harness reliability fixes (2026-07-10)** — a `≥900 s` soak is now trustworthy: the sink's
> `DRIVE_COMPLETE` bound is derived rather than a fixed 600 s (**B6** — it used to truncate every sink's
> tally mid-soak and fabricate a collapse with no abort marker), and the `ENGINE_DRAINED` gate wait is
> derived from `--drain-timeout` rather than a fixed 300 s (**B7** — a raised drain window silently
> outgrew it; missing the gate is a *false negative*, never a fabricated collapse).
>
> What the ceiling actually is, and why `mark_done` was the wrong suspect:
> [`outbound-claim-wall.md`](outbound-claim-wall.md).

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

- **Drive sink socket-truth:** `S == A*delivering ∧ A>0 ∧ S>0 ∧ Σinversions==0 ∧ Σrepeats==0 ∧ lanes_observed≥2`.
  The fan-out is `delivering` (D), **not** `dests` (BACKLOG #209): `dests` is now the count of destination
  CONNECTIONS (the sink port-band width), while `delivering` is how many an accepted message delivers to.
  They coincide at the default `H = D = dests`; at `H != D` keying this on `dests` reads LOSS on every
  healthy rung.
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

45M messages/day = `45_000_000 / 86_400 ≈ 520.83 msg/s` of **INGRESS**. An accepted message DELIVERS to
`delivering` (D) destinations, so `delivered = ingress × delivering` — **never `× dests`** (BACKLOG #209:
`dests` is the count of destination CONNECTIONS, `delivering` is the fan-out; a connection no handler sends
to carries no deliveries). The report states **both** figures and is explicit that 521/s is measured against
**ingress**, not the outbound delivery rate. If the sink tier saturates first, lower **`--delivering`** (the
fan-out) — **not** `--dests`: the sink port-band width is derived from `--dests`, so lowering `--dests`
narrows the band and can make the drive fail to tile its sinks. Do not publish a sink-tier ceiling as an
engine ceiling. To model the reference `H=20, D=4` ADT hub, pass `--handlers 20 --delivering 4` (never raise
`--dests` to 20 — that builds 20 connections and 20 delivered copies, a 4.2× overstatement of the headline).

## Running it (two-box rig)

Both boxes share a coord dir (a mount/synced folder) and use the **same** `--rate-ladder` and `--run-id`.
Restart + store rebuild first (`RESTART-AND-SIZING-runbook.md` STEP 1–2), and set
`MEFOR_DELIVERY_PHASE_TIMING=1` on the **engine** box for the `send_ack`/`mark_done` split.

```pwsh
# ENGINE box (MEFOR_STORE_* + the escapes per the restart runbook; phase timing on):
$env:MEFOR_DELIVERY_PHASE_TIMING = "1"
# --dests is TOPOLOGY (destination CONNECTIONS = sink port-band width). --sink-ports defaults to --dests.
# To model an H!=D hub add --handlers 20 --delivering 4 (both default to --dests ⇒ the H=D=dests graph).
python -m harness shardcert-engine-ladder --shards a,b,c,d --dests 8 `
  --sink-host <LOADGEN_IP> --sink-port 3700 --inbound-bind-host 0.0.0.0 `
  --lanes-per-shard 4 --persistent --claim-mode pooled `
  --rate-ladder 20:64:4 --hold-seconds 60 --drain-timeout 150 `
  --soak-hold-seconds 300 --keep-logs-dir C:\srv\mefor\nodelogs `
  --coord-dir <SHARED> --run-id ladder1

# LOAD-GEN box (the drive learns the shape from SHARDS_READY — it has NO --dests/--handlers/--delivering).
# --sink-count defaults to the engine's advertised band width (min(8, sink_ports)); pass it only to override.
python -m harness shardcert-drive-ladder --engine-host <ENGINE_IP> `
  --rate-ladder 20:64:4 --hold-seconds 60 --drain-timeout 150 `
  --soak-hold-seconds 300 --driver-count 4 --sink-host 0.0.0.0 --insecure `
  --coord-dir <SHARED> --run-id ladder1 --report-json ladder1.json
```

The `--rate-ladder`, `--hold-seconds`, `--drain-timeout`, and `--run-id` **must match** on both boxes (both
halves derive the identical rung plan and per-rung `run_id`). The drive box emits the consolidated report
(`ladder1.json` + stdout) and exits `0` (correctness held) / `1` (a correctness break) / `2` (setup/timeout).
**The exit code says nothing about whether the soak sustained** — a saturating soak exits `0`. Read the
`result` field instead: `PASS` · `SOAK_NOT_SUSTAINED` · `FAIL` · `SETUP_DEGRADED`.
Then **stop the instances** (a stopped instance loses the ephemeral store on restart anyway).

## Reading the result

- `ceiling.pinned_ingress_rate` / `pinned_outbound_rate` — the highest sustained rung (a **floor** if the
  climb never collapsed → raise the ladder); `first_collapse_ingress_rate` brackets it from above.
- `ceiling.sustained_events_per_s` — the pinned rate in **total message events/s**
  (`pinned_ingress_rate × (1 + delivering)`, **not** `× (1 + dests)` — BACKLOG #209), the currency the
  45M/day budget is denominated in.
- `ceiling.clears_target_events` — whether that **total-events** rate clears ~521/s. This is the number
  the §8 decision keys off, but the bench only reports it.
  > **B10 (schema_version 3, 2026-07-10).** This was `clears_target_ingress`, and it compared a pure
  > *ingress* rate against the *total-events* budget — a units defect that made the gate `(1 + dests)`×
  > too strict (**9×** at the bench default `dests=8`). Every "52× short" figure published before that
  > date carries the inflation; the honest pooled gap is **5.79×**. The old keys `clears_target_ingress`
  > and `target_ingress_per_s` were **removed rather than redefined**, so a stale consumer raises
  > `KeyError` instead of silently branching on a boolean whose meaning flipped.
  > **schema_version 4 (BACKLOG #209)** adds `topology.handlers`/`topology.delivering` (the report now
  > emits `schema_version: 4`); every delivery figure — `sustained_events_per_s`, each rung's
  > `outbound_expected` — keys off `delivering`, not `dests`.
- `soak_ok` — the soak held: its verdict is **SUSTAINED**, and that alone. B5 removed the `in_pipeline`
  slope from this gate (the de-inflated slope proved sign-unstable across rates); the slope is still
  *printed* as advisory context. Saturation is caught by SUSTAINED requiring the backlog to drain inside
  the bounded soak window. Do not read the printed flat/GROWING label as pass/fail.
- `climb[].phase_timing` / `soak.phase_timing` — the `send_ack` vs `mark_done` split (needs
  `MEFOR_DELIVERY_PHASE_TIMING=1`).

Per the D4 publish rule, publish an operating point at **≤50% of the measured ceiling**, and keep the
"supported" wording attribution-conditional (engine-CPU-bound vs store-claim-bound vs sink-tier-bound — see
the restart runbook STEP 4/5). Adversarially review the verdict before calling it.
