# Throughput bench record — C4 / C5 / C6 / C7 (2026-07-11 → 2026-07-12)

The raw rig record behind the store-side-search conclusion. Committed so three verdicts and two Accepted ADRs
([0098](../../../adr/0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md),
[0101](../../../adr/0101-pre-registered-falsifier-discipline-for-performance-measurement.md)) no longer rest on files
held only on an operator's local drive. This is the audit trail; the conclusions live in
[`../../THROUGHPUT-STATUS-2026-07-10.md`](../../THROUGHPUT-STATUS-2026-07-10.md) §3/§8.

Each run folder carries the **handoff** (pre-registered rules, written *before* the run), the **handback** (results),
an independent coordinator **review** (adversarial audit), and the raw per-arm telemetry (report JSON + convoy JSON +
`cpu_soak.csv` / `loadgen_cpu_soak.csv` / `storedmv_soak.txt`). This handoff/handback/review triple is the unit the
[ADR 0101](../../../adr/0101-pre-registered-falsifier-discipline-for-performance-measurement.md) discipline mandates.

| run | question | verdict |
|---|---|---|
| **C4** | per-query CPU attribution of the N=16 wall | **WITHHELD.** ⚠️ ran 16 shard processes on an 8-vCPU box (invalid config) and handed back **no JSON** — two `.md` files only. Numbers **inadmissible**; retained for the record. |
| **C5** | per-shard ceiling `R` at N=8, latch-free | **`R ∈ [2,3)`** → N-sizing insufficient alone. Decisive (engine peaked 59.7% max_core). |
| **C6** | is the collapse a resource convoy? | **AMBIGUOUS-STRUCTURAL** — convoy floor met in 0/288 samples. No single blocker. |
| **C7** | is the ceiling a parallelism config default? | **Refuted — parallelism is load-bearing.** `MAXDOP=1` made it worse and broke a healthy rung. |

**Next run:** [`../../HANDOFF_P0_inline_fusion_measurement.md`](../../HANDOFF_P0_inline_fusion_measurement.md) — measures
whether the one surviving lever (inline stage-fusion) moves throughput, and tests the Phase-4 premise itself.

**Provenance:** synthetic-load rig only (AWS m7i.4xlarge engine / i4i.2xlarge SQL Server store). No customer data, PHI,
IPs, hostnames, or partner identifiers — public DMV/catalog names only. Scanned before commit.
