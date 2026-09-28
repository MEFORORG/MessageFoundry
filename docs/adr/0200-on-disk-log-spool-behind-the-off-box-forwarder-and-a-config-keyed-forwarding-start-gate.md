# 0200 -- On-disk log spool behind the off-box forwarder, and a config-keyed forwarding start gate

- **Status:** **Accepted -- 2026-09-27, as the build of owner ruling R4 (a) of 2026-09-24.** The
  owner approved the gate and its order (spool first, then a configuration-keyed refusal) on
  2026-09-24, answer *"Yes, both, as scoped (Recommended)"*. Vault
  `docs/security/ASVS-OWNER-RULINGS-2026-09-24-BATCH128.md`, section R4, is the record. The spool's
  file format, rotation and replay order below are the Builder's design choices inside that ruling,
  not owner rulings. The ruling does not grade the gate: whether a config-keyed gate earns a pass on
  ASVS 16.4.3 is the re-score's question, and G15's *"a gate whose predicate is a config key rather
  than the verb is not rule 4"* is the objection it must answer.
- **Date:** 2026-09-27
- **Related:** BACKLOG #1966 (this build) and #1199 (the 16.4.3 research that named the spool as the
  missing durability half) · [ADR 0080](0080-offbox-forwarding-tls-defaults.md) (native TLS-syslog) ·
  [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) (the per-hop posture the `forward_hop_disposition` gate uses) ·
  [`docs/PHI.md`](../PHI.md) section 2 (the spool's row) ·
  [`docs/CONFIGURATION.md`](../CONFIGURATION.md) `[logging]`

---

## Context

The off-box forwarder hands each record, already rendered and redacted on the caller's thread, to a
bounded in-memory queue drained by one listener thread. Before this ADR a record was lost in three
cases: the queue was full, the process exited with records queued, or the collector was down when
the listener tried to send. A TCP or TLS collector down at start also cost the process its
forwarder for its whole life. The forwarder docstring said so: there was no on-disk spool.

Owner ruling R4 (a) lets a PHI instance under `[security].enforcement = "enforce"` refuse to start
without verified-TLS forwarding to a non-loopback collector, but only once a spool exists, and only
keyed on configuration. A gate that dialled the collector at start would wait out the TCP timeout and
could stop a clinical message path from starting over a network fault.

## Decision

### 1. A bounded on-disk spool sits behind the hand-off queue

`messagefoundry/log_spool.py` holds the spool. The forwarder's listener thread owns it alone.

- **Input.** Only what the hand-off queue holds: text the PHI, credential and control-character
  filters already processed on the caller's thread. The spool never sees a raw record, so it cannot
  hold one unredacted. A test plants a PHI-shaped value and proves the spool file holds only its
  redacted form, with a control that the value was present before the filters.
- **File format, version 1.** A directory of segment files named `spool-<12-digit sequence>.jsonl`.
  Each line is one UTF-8 JSON object, `{"v": 1, "level": "<levelname>", "line": "<rendered text>"}`.
  JSON escaping keeps one entry on one physical line. A reader skips a line of any other version, or
  a torn line, and counts it.
- **Rotation and bound.** Appends go to the newest segment until it reaches one eighth of the cap,
  then a new segment starts. The directory is capped at `[logging].forward_spool_max_bytes`. An
  append that would cross the cap is dropped and counted, newest first, which keeps the oldest
  evidence; the drop is reported at most once a minute. A segment is deleted once every entry in it
  has been sent, so a drained spool holds no segment files.
- **Replay order.** Strictly first in, first out. While anything is spooled, new records are appended
  behind it rather than sent live, so nothing overtakes older evidence.
- **Delivery: best effort, not at least once.** Three limits are real and stated here so no control
  rests on the stronger claim:
  - **A peer reset can lose a record.** After a TCP or TLS collector restarts, the first `sendall` on
    the dead connection can succeed into the local kernel buffer. The entry is then marked sent and
    deleted, though the collector never got it. The next send fails and reconnects.
  - **A restart can resend up to one segment.** The read position lives in memory, so after a
    restart the oldest segment replays from its start. A segment is one eighth of the cap, so at the
    default 100 MB cap a collector can see up to 12.5 MB of entries twice.
  - **UDP detects nothing.** A connectionless send reports success whatever happens to the datagram,
    so with `forward_protocol = "udp"` the spool only keeps what is queued at shutdown or waiting
    behind older entries. The engine does not claim detection it lacks there.
  - **A send error that is not a network error is never counted as sent.** On TCP and TLS it is
    dropped as undeliverable, counted, and reported at ERROR. It is not retried, because a
    deterministic failure retried at the head of a FIFO spool would hold every later entry for good.
- **Permanent connect failures are not deferred.** A collector certificate that fails verification,
  or a host name that does not resolve, is reported at ERROR as permanent and the process runs
  without the forwarder, spool or not. Only a transient failure (refused, timed out, unreachable)
  is deferred as "not reachable yet".
  After a restart, appends start a new segment and never extend a file whose tail may be torn.
- **Backoff.** A failed send waits 1 second before the next try, doubling to 60 seconds. While
  waiting, records go to the spool without touching the network. The listener also wakes once a
  second on an idle queue, so a backlog drains on a quiet engine.
- **Start.** A TCP or TLS collector that is down at start no longer removes the forwarder. With a
  spool, the handler starts unconnected and records spool until the collector answers. A failed TLS
  handshake clears the connected plain socket, so nothing is ever sent over it in cleartext.
- **Shutdown.** Records still queued past the drain deadline go to the spool, not the floor.
- **One process per directory.** The spool takes a non-blocking OS lock on `spool.lock`. A second
  process on the same directory runs without a spool and says so. The default directory is
  `log-spool/<engine or shard id>` beside `[store].path`, so each engine shard gets its own.
- **PHI at rest.** The same class as the application log file: redacted but best-effort, so PL-1,
  plaintext, with no app-level cipher. The directory is created owner-only where the platform honours
  a mode; on Windows it inherits its parent's ACL. The cap bounds it, and a delivered entry is deleted
  with its segment. `[logging].forward_spool_max_bytes = 0` turns the spool off.

### 2. A configuration-keyed start gate

In `serve`, beside the #1967 retention gate: on a PHI instance, forwarding must be configured with
`forward_protocol = "tls"`, `forward_tls_verify = true`, and a `forward_host` that is not loopback.
Under `enforce` a start that fails this refuses with exit 2 and names what is missing. Under `warn` it
warns. The gate reads settings only and opens no connection, so a down collector never blocks start.
Loopback does not pass: the separation limb of 16.4.3 asks for a logically separate system, and a
local agent on 127.0.0.1 is the same host. `forward_hop_attested` does not pass it either; it attests
a hop, and this gate asks whether verified TLS is configured at all.

## Consequences

- On a first deployment a collector outage would no longer lose redacted log evidence up to the cap.
- A PHI instance under `enforce` would need a TLS collector configured before it starts. That is an
  availability trade the owner accepted in R4.
- The start-time cost of the gate is a settings read. It is unmeasured as a duration, and G15's
  2-second figure was costed against something else and does not apply to it.
- Not built here: the shard supervisor and the sandbox child still have no forwarder path, and the
  collector-separation probe (every resolved address is this host's) stays unbuilt. #1199 names them.
