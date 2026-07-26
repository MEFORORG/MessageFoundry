# DEMAND-GATE-BACKLOG · S5 · Outbound keep-alive (Tcp/X12 persistent) + MLLP no-wait ACK

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S5` |
| **Wave** | 2 |
| **Status** | **○ Not started** |
| **Effort** | M |
| **Backlog items** | #117 · #97 |
| **Build order** | #117 → #97 |
| **ADR(s)** | NEW — Outbound MLLP fire-and-forward (no-wait-for-ACK) — opt-in per-connection delivery-on-write; amend ADR 0067 — ADR 0067 amendment — extend persistent outbound to Tcp()/X12() destinations (resolves §8) |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | No |
| **Branch** | `feat/s5-outbound-keepalive-nowait-ack` |
| **Depends on** | None |

## Items

| Item | Title | Status |
|---|---|---|
| #117 | Sender no-wait-for-ACK (fire-and-forward) option | ○ open |
| #97 | Keep-alive / persistent outbound connections | ○ open |

## Owned files / seams

- `messagefoundry/transports/mllp.py (no-ack branch in _send_once/_send_persistent; reference persistent impl) — HOTSPOT shared with S8a #136 (different waves: S5 wave 2, S8a wave 6)`
- `messagefoundry/transports/tcp.py, x12.py (add persistent cache + _stale_reason + _close_bounded + aclose; exactly-one reconnect-before-first-byte, NO internal backoff loop; X12 TA1 leftover/desync guard)`
- `messagefoundry/config/wiring.py (MLLP() no-ack kwarg + reject no-ack+capture_response AFTER the reingress_to→capture_response desugar at 3022; Tcp()/X12() persistent kwargs at the 3025-3040 validation choke)`

## Notes, PHI & gotchas

No new PHI surface. Reconnect/stale logs carry socket/OS metadata only (errno/winerror), never frame bytes. #117 changes the delivery-CONFIRMATION contract: no NAK/timeout retry, PROCESSED on TCP-write drain (at-most-once-confirmation for a silent/NAK peer) — document loudly; default stays ACK-waiting. #97: follow ADR 0067's exactly-one-reconnect model, NOT backlog #97's 'reconnect-with-backoff' wording. VERIFIER deltas to call out in the amendment: persistent=false path gains a BOUNDED _close_bounded (vs legacy unbounded) and the _sending serial assert; decide TCP_NODELAY parity. #117 × #136 INTERACTION (decided): in no-ack mode there is NO ACK read, so #136's (S8a) 'waiting-for-reply' display window has nothing to attach to and is INAPPLICABLE — #136 must render the waiting state only on ACK-waiting outbounds and treat a no-ack MLLP outbound as never-waiting. mllp.py is a cross-session HOTSPOT with S8a: they are in different waves (2 vs 6); if ever built concurrently, serialize on send()/_send_once/_send_persistent. Both S5 items edit wiring.py (different factories) → sequential in one session.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s5\`, branch \`feat/s5-outbound-keepalive-nowait-ack\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
