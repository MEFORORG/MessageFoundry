# ADR 0066 Wave-2 — py-spy profile: the ~150 msg/s/engine wall, NAMED

**Date:** 2026-07-04 · **From:** engine box (m7i.2xlarge, Python 3.14.6, **ProactorEventLoop**) · Synthetic HL7, no PHI.
**Gate result:** the per-engine wall is **per-message async-execution overhead — executor→loop future-completion
marshaling + the Windows Proactor self-pipe wakeup on the ~5 off-loop store round-trips per message.** Not the
HL7/pipeline logic, not the store, not the claimer.

## Regime the profile was taken in (anchor)
Single engine, `claim_mode=pooled`, clean/idle store, driven at **128/s offered — at the ceiling**. During the 90 s
flame capture: achieved **127/s** intake, delivered **~94/s**, **ACK p50/p99 = 5.4 s / 44 s**, backlog building
(`in_pipeline` ~2,600), engine **~2.0 of 8 cores**, **max single thread ~0.60 core** (K-sweep per-thread sampler),
store idle (~1 of 40 pool conns active, WRITELOG-waiters <1). → the wall regime, with idle CPU + idle store.

## Dominant cost (flamegraph, fully resolved — 91 `.py` frames, 0 native/unknown)
**Pipeline/HL7 logic is ~2% total:** `_on_client`(mllp) 1.1%, `on_message` 1.1%, `_delivery_worker` 0.6%,
`_process_*_item`/`_router_worker` ~0.2% each. Parse/route/transform/HL7 never appear hot.

**The wall is the async machinery around the off-loop store calls:**
| frame | % | what it is |
|---|---|---|
| `_worker` (concurrent/futures/thread.py:119) | 81.5 | executor threads **parked/idle** (pool NOT saturated) |
| `set_result` (_base.py:549) | 9.5 | executor future completion |
| `_invoke_callbacks` (_base.py:335) | 9.5 | future done-callbacks |
| `_call_set_state` (asyncio/futures.py:409) | 9.4 | future state → asyncio |
| `call_soon_threadsafe` (base_events.py:881) | 9.1 | cross-thread hand-back to loop |
| **`_write_to_self` (proactor_events.py:829)** | **9.1** | **Proactor self-pipe SOCKET wakeup of the IOCP loop** |
| `_run_once` + IOCP (`_poll`/`_loop_self_reading`/`select`/`recv`) | ~9 | loop iteration + Windows IOCP machinery |

**Mechanism:** each message does ~5 durable store round-trips (ingress commit-before-ACK · claim · 2 stage-handoffs ·
delivery-complete). Each is a `run_in_executor` whose completion marshals back to the loop:
`set_result → _invoke_callbacks → _call_set_state → call_soon_threadsafe → _write_to_self` (a socket send that wakes
the Proactor IOCP loop). At ~5 round-trips × ~100 msg/s ≈ **500 completions/s**, this per-completion marshaling +
self-wakeup — **all GIL-serialized on the single loop thread** — is the throughput governor. Executor threads and 6
box cores sit idle, so it is a **per-completion overhead/latency wall on the loop, not CPU saturation.** This is
K-independent (claimers funnel through the one loop), store-independent (store idle), and engine-count-scaling
(each engine has its own loop) — consistent with every K-sweep/N=2 finding.

## Named hypothesis → Wave-2 lever
**Dominant cost = per-store-round-trip executor→loop future-completion marshaling + Proactor self-pipe wakeup
(~18% of active samples; `_write_to_self` alone ~9%).**
→ **Wave-2 = B5: cut executor round-trips per message** — batch the store ops per stage-hop (fewer `run_in_executor`
calls / message) and/or a cheaper loop wakeup (the Proactor self-pipe socket send is a Windows-specific tax; batch
wakeups or a selector loop where viable). **Free-threading is secondary** (parallelizes the marshaling across cores,
but the primary win is fewer completions/message). **NOT** the shared per-stage claimer (K refuted), **NOT**
store-sharding (store idle), **NOT** pool-size.

## Integrity / caveats
- **py-spy 0.4.2 has partial CPython 3.14 support:** the flamegraph works fully; `dump`, `record --gil`,
  `--format raw` **consistently fail** ("Failed to find python version"). The decisive `--gil` view could not be
  captured. GIL-boundedness is inferred from (a) the flame — the marshaling/wakeup chain is on the single loop
  thread — and (b) per-thread CPU (max thread 0.60 core, engine 2.0 cores → **not** a single-core-pinned loop, so
  the wall is per-completion *overhead*, not raw loop CPU saturation).
- py-spy fell ~1–3 s behind at 250 Hz (busy target): valid distribution over ~40k samples, not perfectly real-time.
- A benign asyncio `AssertionError` (Proactor `_attach` during serving-socket setup, proactor_events.py:841) fired
  at startup on 3.14 — a startup race; reports unaffected. Flagged as a possible 3.14/Proactor robustness item.

## Deliverables (this folder)
`engine_flame.svg` (resolved flamegraph) · this findings doc · `profile_run.json` (anchor regime).
(`engine_gil.svg` / thread dump not captured — see caveat.)
