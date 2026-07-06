# ADR 0071 B5 — thread-hop fusion A/B (the throughput promote gate) — 2026-07-06

## Bottom line: **NO-GO** → bank nothing, keep `fuse_thread_hops` **default-OFF**, **escalate to free-threading (ADR 0053)**

Thread-hop fusion **works and gives a real, statistically-significant lift that grows with concurrency — but only
~6–10%**, an order of magnitude short of the projected ~160–200 msg/s. Per ADR 0071 §6.4(b), a modest/sub-threshold
SQL-Server result banks nothing → escalate to ADR 0053. This is an **expected, honest, non-failure outcome** (the run
itself is `PASS`/exit 0: zero-loss held in every arm, no missing arms — the NO-GO is the *throughput* decision, which
is orthogonal to run correctness).

**Verdict independently confirmed** by a 4-lens adversarial pass (ultracode) — unanimous NO-GO.

## The result (SQL Server, pooled, 400 msg/s offered, 60 s warm hold, **3 trials/arm**)

| N | B0 ceiling (fuse off) | B1 ceiling (fuse on) | lift | >2σ? | gate outcome |
|---|---|---|---|---|---|
| 256 | 114.77 msg/s | 122.18 msg/s | **+6.45%** | yes | **NO-GO** — lift < 10% |
| 512 | 110.41 msg/s | 120.65 msg/s | **+9.27%** | yes | **NO-GO** — lift < 10% |
| 1024 | 106.83 msg/s | 117.52 msg/s | **+10.01%** | yes | **NO-GO** as reported (see nuance) |

`delivered/offered = 1.00` and **zero-loss held** in all 18 trials (sink_received == sent ≈ 24 000, backlog drained).
Trials were tight (sd 0.5–1.5 msg/s), so the lifts are cleanly significant — the effect is real, just small.

## Precise reading (what the adversarial pass sharpened)

- **The overall NO-GO is robust, but it rests on N=256 (+6.45%) and N=512 (+9.27%) being genuinely below the 10% bar
  on the lift clause alone** — no artifact argument touches those two. The conjunctive gate (ALL cells must GO) fails there.
- **The "in_pipeline grew" NO-GO reasons at N=256 and N=1024 are a poller measurement artifact, not a real backlog.**
  B0's `in_pipeline_peak` is severely under-sampled by the `/stats` poller under overload (N=1024 B0 trials read
  **1369 / 7801 / 9316**; one trial's executor gauge collapsed too), while B1 is a steady ~21 k. Three independent checks
  confirm it's an artifact: (1) **B1 drains *faster*** than B0 at every count (142.8 s vs 158.1 s @1024) — a real larger
  backlog drains *slower*; (2) the **independent sink counter** shows `sink_received == sent`, `backlog = 0`, zero-loss in
  every trial of both arms; (3) **Little's law direction** — B0 has the *lower* intake at the same 400/s offered, so it
  accumulates queue *faster* and should read *equal-or-higher* in_pipeline, never lower. So B0 < B1 is physically backwards.
- **Consequently N=1024's *stated* NO-GO reason is invalid** — corrected, that cell is a **GO**, but a *threshold-touching*
  one: lift = 10.0069 % (margin **+0.007 pt**; dropping any single trial swings it 9.68 %–10.27 %). A lone, marginal cell
  under a conjunctive all-cells gate provides **no** counterweight — overall stays NO-GO.
- **Fusion genuinely engaged** in all 9 B1 arms (not a silent async fallback): a uniform operational signature — ACK p50
  ~7–10× lower (≈200 ms vs ≈1.4–2.2 s), pool-wait p95 5× lower — appears in every B1 trial and never in B0, and the B1/B0
  `read/s` distributions are **fully separated** (min B1 116.95 > max B0 115.34). The lift is a true fusion effect.

## Why so small? (context, not excuses)

- **Inter-box store RTT ≈ 11 ms** (TCP-connect, engine→SQL box; min 10.1 / med 11.4 / max 24.0, n=12) — high for
  same-VPC EC2 (usually sub-ms). At ~4–5 store round-trips per message, this network latency is a real co-bottleneck on
  the **absolute** ~107 msg/s ceiling that **fusion does not address** (fusion cuts executor→loop marshaling crossings,
  not network hops). It does **not** bias the A/B (both arms share the link, so the *lift* is clean), but it plausibly
  dilutes the fusion payoff. This matches ADR 0071's own medium-confidence caveat that "the residual marshaling floor could
  dominate."
- The best B1 ceiling (122.9 msg/s) is ~62–77 % short of the 160–200 projection.

## Recommendation

1. **NO-GO on B5 throughput** — do **not** flip `fuse_thread_hops` to default-on. Keep the flagged, default-off machinery
   (it's correct — zero-loss held, fusion is a provable no-op on PG/SQLite).
2. **Escalate to free-threading (ADR 0053)** as the throughput lever; keep the cp314t canary current.
3. **Record in ADR 0071 §6.4(b):** "a modest/sub-threshold SQL-Server result banks nothing" — with the measured
   +6.5 / +9.3 / +10.0 % concurrency-growing lift as evidence.

## Follow-ups worth RECORDING (not acting on now; none change this NO-GO)

- The **lift grows monotonically with concurrency** (+6.5 → +9.3 → +10.0 %). It *might* clear 10 % robustly at **C > 1024** —
  a targeted higher-concurrency (and/or **lower-RTT same-AZ**) re-bench would settle whether fusion is a real win in a
  network regime where the marshaling wall dominates. This is a *record-and-maybe-later*, not a reason to ship.
- **Harness bug:** the `in_pipeline` guard compares the **poller-sampled peak**, which under-samples under overload and
  fires false NO-GOs. It should read the authoritative sink/drain signal (which exonerates B1) instead. Fixing it would
  flip N=1024 to GO but would **not** change the overall NO-GO (256/512 fail on lift regardless).

## Provenance & integrity

- Branch `feat/adr0071-pr5-trials` @ `8bab40e2` (PR4 #777 fuse_ab profile + PR5 #780 trials field; PR1–3 fusion
  machinery in history). **Merge-to-`main` could not be confirmed from the bench** (git over the `\\tsclient` share
  hangs) — the PR5 branch tip is the authoritative PR4+PR5 code regardless; the gate owner should confirm the SHA matches
  merged `main`.
- Synthetic HL7 only, no PHI. RCSI ON. No durability relaxation. Nothing committed/pushed from the bench. Artifacts
  screened for store IP / login / password / message bodies (only a loopback engine URL remains). SQLite/Postgres are
  **not** valid throughput proxies (fusion is a no-op there by construction) — SQL Server is the sole valid leg.
- 4-lens ultracode adversarial verification: unanimous NO-GO; it corrected two framing points (the NO-GO rests on
  256/512 lift, not on the in_pipeline guard; N=1024's in_pipeline reason is a poller artifact) without changing the verdict.
- Details: `fuse_ab.txt` (rendered table + verdict), `fuse_ab.json` (authoritative records + comparison),
  `fuse_ab_console.txt` (per-arm rows), `environment.txt` (rig, RTT, escapes, SHA).
