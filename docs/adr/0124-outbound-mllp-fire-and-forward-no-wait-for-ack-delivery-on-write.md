# ADR 0124 — Outbound MLLP fire-and-forward (no-wait-for-ACK) — delivery-on-write

**Status:** Accepted · **Date:** 2026-07-17
**Relates-to:** ADR 0001 (staged pipeline — the per-outbound delivery worker this rides on; disposition is finalized from the delivery result), ADR 0013 (`capture_response` — the ACK read this mode *skips*, so the two are mutually exclusive), ADR 0021 (inbound ACK vocabulary — the ACK this mode does not read), ADR 0067 (persistent outbound MLLP — no-ack composes with `persistent=true`), BACKLOG #117 (this item), BACKLOG #82.1 (the ACK-waiting default that stays the charter posture), BACKLOG #136 (S8a console waiting-state — inapplicable in no-ack mode), CLAUDE.md §2 ("Reliability invariant" — at-least-once, outbounds idempotent) + §8 (ACK/NAK conventions).
**Code references** are `origin/main @ 9abecc59`; line numbers are approximate — locate exactly at implementation time.

---

## 1. Context

`MLLPDestination.send()` always **frames one message, writes it, drains, reads exactly one ACK, and validates MSA-1** (`_read_ack` → `_check_ack`, `transports/mllp.py`). A non-`AA`/`CA` ACK is a `NegativeAckError` (dead-letter on `AR`/`CR`, retry on `AE`/`CE`); a missing/timed-out ACK is a charged `DeliveryError` → `mark_failed` → backoff → **retry**. Per-lane delivery is strictly serial (one delivery worker per outbound, ADR 0001/0067), so the next message never sends until the prior ACK is read. There is **no per-connection toggle to skip the ACK**.

The only fire-and-forget MessageFoundry ships today is `expect_reply=false` on the **generic** `Tcp()`/`X12()` connectors (`transports/tcp.py`, `transports/x12.py`) — which do not frame/parse HL7. For an HL7/MLLP feed whose downstream peer **does not acknowledge** (a display board, a one-way archival tap, a broadcast relay), or where the per-message ACK round-trip is the measured throughput ceiling on a lane, the operator must either bolt on a byte-identical `Tcp(framing="vt_fs")` workaround (losing the MLLP identity + TLS + encoding-override knobs) or accept the ACK wait.

**Demand-gate, decline overturned (BACKLOG #117, 2026-07-09).** A prior pass recommended DECLINE citing purity; that reason was **invalid** — purity binds `@router`/`@handler`, **not connectors** (CLAUDE.md §8: "side effects belong in connections/transports"). This is an unfired demand-gate, not an architectural impossibility. Build when a downstream peer does not acknowledge and the ACK wait becomes the throughput bottleneck.

## 2. Decision

**Add an opt-in per-outbound `no_ack: bool = False` knob to the MLLP destination.** When `true`, `send()` frames the message, writes it, drains the socket, and completes the delivery **on successful TCP write** — it does **not** read or validate an ACK, so there is **no NAK-driven and no ACK-timeout-driven retry** in this mode. The default `false` is **byte-identical to today** (read one ACK, validate MSA-1) — existing feeds are unchanged.

**Delivery-confirmation contract (document loudly).** In no-ack mode, delivery is **confirmed on write, not on a positive MSA-1 ACK** — *at-most-once-confirmation*. A message the peer silently dropped or would have NAK'd is still finalized `PROCESSED` (the write succeeded), because the connector never learns the peer's disposition. This is the deliberate trade the operator opts into: it buys throughput (no round-trip, no head-of-line ACK wait) at the cost of transport-level delivery assurance. The ACK-waiting default (`no_ack=false`) stays the charter posture (BACKLOG #82.1) and the recommendation for any feed that needs delivery confirmation.

**What no-ack does NOT change:**

- **At-least-once for the WRITE.** A connect failure or a drain failure is still a **charged** `DeliveryError` → `mark_failed` → backoff → retry (with `_describe_error` detail). Only the *read* is removed; the write path's failure handling is unchanged. A retry can therefore still **duplicate** (a drain that failed after bytes reached the peer) — the receiver **must stay idempotent** (CLAUDE.md §2), exactly as in ACK-waiting mode.
- **Count-and-log.** The message is recorded with its disposition as always (`PROCESSED` on write success, `ERROR`/dead-letter on a charged write failure) — nothing is accepted-and-dropped.
- **Per-lane FIFO.** The delivery worker remains the lane's single serial sender; no-ack does not pipeline or reorder within a lane (the `_sending` fail-loud serial assert applies, ADR 0067 §2.5).
- **The ingress/inbound side.** This is an *outbound* knob only; `AckMode`, `build_ack`, and NAK-synchronous inbound semantics are untouched.

**Composition with `persistent` (ADR 0067).** No-ack composes with `persistent=true`: a persistent no-ack outbound reuses one cached connection, applies the same **reconnect-before-first-byte** liveness check (`_stale_reason` — `is_closing`/buffered-unsolicited-bytes/`at_eof`/idle/age, all I/O-free), writes + drains, and re-caches on drain success. It is *simpler* than the ACK-waiting persistent path — there is no ACK frame to read and no desync/leftover guard to run, because **no reply is expected**; any bytes a misbehaving peer sends are caught as "unsolicited bytes" by the reuse-time `_stale_reason` veto and cost a reconnect, never a mis-parse. This is the maximum-throughput posture (no handshake **and** no ACK wait) for a genuinely non-acking high-rate peer.

**Mutually exclusive with `capture_response`/`reingress_to` (rejected at wiring).** `capture_response` (ADR 0013) and `reingress_to` capture the application ACK the peer returns; no-ack never reads it, so `no_ack=true` + `capture_response=true` (or `reingress_to=…`, which desugars to `capture_response=true`) is a **`WiringError` at `check`/dry-run time** — a configuration that can never do what it asks, caught before any store or socket. **MLLP-only:** `no_ack` is a knob on `MLLP()`; a `no_ack` setting on a non-MLLP outbound (via the `connections.toml` desugar) is a `WiringError` (the generic `Tcp()`/`X12()` fire-and-forget is `expect_reply=false`).

**Console waiting-state interaction (BACKLOG #136, S8a).** In no-ack mode there is no ACK read, so the "waiting-for-reply" display window has nothing to attach to — #136 must render the waiting state **only on ACK-waiting outbounds** and treat a no-ack MLLP outbound as never-waiting (recorded here; enforced when #136 lands).

## 3. Acceptance Criteria (EARS)

> Tests land in the implementation PR under `tests/test_mllp_no_ack.py` (loopback `asyncio.start_server` peers, as the existing MLLP tests do).

- **AC-1** — WHEN `no_ack=false` (default), THE ENGINE SHALL behave byte-identically to today: read one ACK, validate MSA-1, apply the `NegativeAckError`/timeout policy unchanged.
  → the existing MLLP suites stay green; `tests/test_mllp_no_ack.py::test_default_still_waits_for_ack`
- **AC-2** — WHEN `no_ack=true` and the write + drain succeed, THE ENGINE SHALL finalize the delivery `PROCESSED` **without reading any ACK**, even if the peer sends a NAK or nothing at all.
  → `::test_no_ack_delivers_on_write_ignoring_nak`, `::test_no_ack_delivers_when_peer_silent`
- **AC-3** — WHEN `no_ack=true` and the **connect** fails, THE ENGINE SHALL raise a charged `DeliveryError` (normal retry, `_describe_error` detail) — the write path's at-least-once handling is unchanged.
  → `::test_no_ack_connect_failure_charged`
- **AC-4** — WHEN `no_ack=true` and the **drain** fails after bytes were written, THE ENGINE SHALL raise a charged `DeliveryError` (retry per policy — the at-least-once duplicate window), never a silent success.
  → `::test_no_ack_drain_failure_charged`
- **AC-5** — IF `no_ack=true` is combined with `capture_response=true` (or `reingress_to=…`), THEN wiring SHALL raise a `WiringError` at `check`/dry-run (no ACK is read, so there is nothing to capture).
  → `::test_no_ack_with_capture_response_rejected`, `::test_no_ack_with_reingress_rejected`
- **AC-6** — IF a `no_ack` setting is placed on a non-MLLP outbound, THEN wiring SHALL raise a `WiringError` (the knob is MLLP-only; generic fire-and-forget is `expect_reply=false`).
  → `::test_no_ack_on_tcp_rejected`
- **AC-7** — WHERE `no_ack=true` AND `persistent=true`, THE ENGINE SHALL reuse one connection across deliveries, redial-before-first-byte on a stale socket (uncharged), and cache on drain success — with no ACK read.
  → `::test_no_ack_persistent_reuses_connection`, `::test_no_ack_persistent_reconnects_before_first_byte`
- **AC-8** — WHILE `no_ack=true`, THE ENGINE SHALL preserve per-lane FIFO order (single serial sender) and the fail-loud concurrent-`send()` assert (ADR 0067 §2.5).
  → `::test_no_ack_preserves_send_order`, `::test_no_ack_concurrent_send_raises`

## 4. Options considered

1. **Per-outbound `no_ack` knob on `MLLP()`, default off, delivery-on-write. CHOSEN.** Contained connector change; the ACK-waiting default is untouched; composes with `persistent` for the maximum-throughput non-acking case; the confirmation-contract change is explicit and wiring-guarded against the capture footgun.
2. **Tell operators to use `Tcp(framing="vt_fs")`.** Rejected as the end state (though it ships today): it loses the MLLP identity, per-connection TLS (WP-13b), the `encoding_characters`/`hl7_raw_separators` overrides, and MLLP-specific observability — a non-acking MLLP feed should stay an MLLP outbound.
3. **Pipelined ACK (send N, reconcile ACKs asynchronously).** Rejected: it needs MSA-2↔MSH-10 correlation (BACKLOG #82, deliberately demand-gated — some peers echo empty/wrong MSA-2) and a per-lane in-flight window, breaking the one-serial-sender model. No-ack is the honest primitive for a peer that *does not ACK at all*; correlated pipelining is a separate, larger item.
4. **`no_ack` implies connect-per-message (reject `persistent`+`no_ack`).** Rejected: the persistent no-ack path is *simpler* than the ACK-waiting one (no ACK read, no desync guard) and delivers the throughput the item targets; forbidding the combination would leave per-message handshake cost on exactly the high-rate non-acking lane that most wants both.

## 5. Consequences

**Positive** (realized only when an outbound opts in with `no_ack=true`) — the ACK round-trip and its head-of-line wait are removed from the delivery path; combined with `persistent=true`, a non-acking high-rate lane pays neither a per-message handshake nor an ACK wait. A genuinely one-way MLLP feed (display/broadcast/archival tap) is expressible as a first-class MLLP outbound instead of a `Tcp()` workaround.

**Negative / risks** — the delivery-confirmation contract weakens to *at-most-once-confirmation*: a silently-dropped or would-be-NAK'd message is finalized `PROCESSED` and **not** retried, because no ACK is read. This is opt-in and loudly documented; the ACK-waiting default stays the recommendation for any feed needing confirmation. A drain-phase failure can still duplicate on retry (unchanged from today) — receiver idempotency still governs. No new PHI surface: reconnect/failure logs carry socket/OS metadata (`_describe_error`) only, never frame bytes.

**Out of scope** — MSA-2↔MSH-10 correlated pipelining (BACKLOG #82); `ack_after=delivered` (planned, not built); the generic `Tcp()`/`X12()` connectors (already have `expect_reply=false`); any inbound ACK-mode change.

## 6. Reliability-invariant checklist

- [x] **At-least-once (write)** — a connect/drain failure is still `DeliveryError` → `mark_failed` → backoff → retry; only the ACK *read* is removed. A crash mid-send leaves the row in-flight for `reset_stale_inflight` exactly as today. The *confirmation* weakening (no NAK/timeout retry) is the documented, opt-in trade — not a silent regression of the default.
- [x] **Idempotent-receiver invariant governs duplicates** — the drain-failure retry window is unchanged in kind; receivers must stay idempotent (CLAUDE.md §2).
- [x] **Count-and-log** — every message is finalized with a disposition (`PROCESSED` on write / `ERROR` on a charged failure); nothing is accepted-and-dropped.
- [x] **Per-lane FIFO** — same single serial worker; no-ack does not pipeline or reorder; the `_sending` assert holds.
- [x] **ACK-on-receipt untouched** — outbound-only; the inbound listener, `build_ack`, and NAK-synchronous semantics are unmodified.
- [x] **Finalizer sole disposition authority** — untouched; only the transport's read behavior changes.
- [x] **No event-loop blocking** — asyncio streams; the write/drain path is bounded by `timeout_seconds`, the close is the ADR 0067 `_close_bounded` (#55) pattern.
- [x] **Purity** — `no_ack` is a connector setting; `@router`/`@handler` purity is unaffected (CLAUDE.md §8).
- [x] **PHI** — no new durable storage; logs carry OS/socket metadata only.

## 7. Residual risks

- **Silent-loss surprise.** An operator who sets `no_ack=true` on a peer that *does* NAK (misconfiguration) loses the NAK signal — the message reads `PROCESSED`. Mitigation: loud CONNECTIONS.md documentation ("delivery confirmed on write, not on ACK; no NAK/timeout retry"), the default stays ACK-waiting, and the wiring reject of `no_ack`+`capture_response` blocks the most likely incoherent combination.
- **Persistent no-ack liveness is best-effort** (inherited from ADR 0067 §7): `at_eof`/`is_closing`/buffered-bytes catch a peer FIN or unsolicited bytes, not a silently dead path; a write into a dead path surfaces as a charged drain `DeliveryError` → retry. `idle_timeout_seconds` bounds staleness.
- **#136 coupling.** The console waiting-state (S8a, wave 6) must treat a no-ack outbound as never-waiting; recorded in §2 and cross-referenced in the #136 work.
