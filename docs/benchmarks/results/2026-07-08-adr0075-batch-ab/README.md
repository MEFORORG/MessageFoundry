# ADR 0075 — per-hop statement batching A/B (the promote gate) — 2026-07-08

## Bottom line: **GO → promote `batch_handoff_statements` default-ON**, flag retained only as an emergency off-switch

Per-hop SQL statement batching is a **distance-insurance** lever, not a raw speed lever ([ADR 0075](../../../adr/0075-per-hop-sql-statement-batching.md) Amendment 2026-07-07): its value is proportional to the engine↔store round-trip time (RTT). The reframed promote criterion — **harmless-near AND helps-far**, over a **green SQL Server correctness precondition** — is met, so the default flips to **ON**. The flag stays as an emergency off-switch (`set false` to disable); it is never an operational control operators normally touch.

## Mechanism (why this is distance insurance)

Batching folds the per-hop SQL round-trips **within one message's handoff** into the fewest `pyodbc.execute()` T-SQL batches (the `_SQL_APPLOCK` precedent) — same ordered `(sql, params)` sequence, still committing **exactly once per hop**. It cuts **network round-trips, not transactions**: `commits/msg = 2.000` (route_handoff + transform_handoff) holds identically in **both** arms — this is per-message statement folding, **not** cross-message commit accumulation, so no commit boundary moves and the ADR 0069 fence is not hit. Value scales with RTT: near-zero on the wire when the store is co-located, meaningful when each round-trip is expensive (the DR-failover "engine failed over, the store did not" case).

- **SQL-Server-only**, fail-closed on an applock timeout; Postgres (asyncpg loop-native) and SQLite (loop-affine single writer) have no batched path and run byte-identically.

## Method

Single-box in-process A/B: `python -m harness --connscale batch_ab` over loopback, SQL Server store, `fuse_thread_hops` **OFF** (the two levers do not compose — batching is measured on the default async path). Far RTTs were introduced by **WinDivert latency injection on the engine→store link** (the two-box drive was a dead-end; single-box in-process + injected latency is the sustainable rig). Both arms: zero-loss, full delivery, drained backlog.

## HARMLESS NEAR (co-located ~0.28 ms RTT, 100 msg/s, N = 256 / 512 / 1024)

Batch **ON vs OFF within ±0.4% throughput** (none statistically significant), **zero-loss**, `delivered/offered = 1.00`. ⇒ **no regression** at the normal co-located placement. (Batching also cuts internal executor→loop crossings, so near is expected neutral-to-slightly-positive, never negative — confirmed.)

## HELPS FAR (injected engine→store RTT, sustainable offered-bound rate, 3 trials/arm)

Both arms zero-loss, full delivery, drained.

| injected RTT | offered | ACK p99 — OFF | ACK p99 — ON | Δ p99 |
|---|---|---:|---:|---:|
| +20 ms | 6 msg/s | 475 ms | 391 ms | **−18% (−84 ms)** |
| +50 ms | 3 msg/s | 1168 ms | 956 ms | **−18% (−212 ms)** |

A **constant ~−18% ACK-p99**, with the **absolute saving widening with RTT** (−84 → −212 ms) — the distance-insurance curve: the further the store, the more round-trip folding pays. Drain time is **not** the signal here (an apparent +20 ms drain delta was a warm-up outlier; drain was flat at +50 ms) — ACK-p99 is the clean, monotone signal.

## Correctness precondition — GREEN

`tests/test_adr0075_batch_sqlserver.py` = **9 passed** on real SQL Server: fail-closed on a real applock timeout, concurrent-finalizer serialization, and ON/OFF **disposition parity**. This is the hard gate; the harmless-near + helps-far result is the promote decision on top of it.

## Promote decision

near-harmless (no regression at the co-located baseline) **+** far-helps (a real, monotone ACK-p99 win that grows with RTT) **+** green SS correctness precondition ⇒ **default-ON**. The flag is kept **only as an emergency off-switch** for a hypothetical future workload that ever regresses. A manual opt-in is the wrong design for a DR lever (an automatic failover never stops to flip a throughput flag), which is precisely why the default flips rather than staying an operator toggle.

## Provenance & integrity

- Synthetic HL7 only, **no PHI**. No real estate/site identifiers, IPs, ports, logins, or message bodies in this record. RCSI ON; no durability relaxation. Nothing pushed from the rig.
- `commits/msg = 2.000` verified in both arms (the covert-transaction-fusion identity guard).
- SQLite/Postgres are **not** valid throughput proxies for this lever (no batched path there by construction) — SQL Server is the sole valid leg; the correctness precondition runs on the CI SQL-Server leg.
