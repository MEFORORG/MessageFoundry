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
a hop, and this gate asks whether verified TLS is configured at all. A host name that resolves to
loopback does pass, because the check never resolves DNS; that residual is #1199's
collector-separation probe.

The gate keys on forwarding configuration only, as the ruling words it, and does not also require
the spool: `[logging].forward_spool_max_bytes = 0` turns off loss protection but not this gate.

**Wired in `serve` (BACKLOG #1966).** Test fixtures and the enforcing hosted serve legs satisfy it
with `forward_host = "siem.invalid"`, TLS, and a synthetic CA plus revocation list: the name never
resolves, the forwarder reports that at ERROR as permanent, and the start still succeeds, which is
the gate being keyed on configuration and not on the collector.

## Consequences

- On a first deployment a collector outage would no longer lose redacted log evidence up to the cap.
- A PHI instance under `enforce` would need a TLS collector configured before it starts. That is an
  availability trade the owner accepted in R4.
- The start-time cost of the gate is a settings read. It is unmeasured as a duration, and G15's
  2-second figure was costed against something else and does not apply to it.
- Not built here: the shard supervisor and the sandbox child still have no forwarder path, and the
  collector-separation probe (every resolved address is this host's) stays unbuilt. #1199 names them.

## Follow-ups (BACKLOG #2278, #2279), 2026-10-08

The two review rounds of the build left findings open. This section records what each became. It
changes no decision above.

**Built.**

- **A read fault is reported as a read fault (#2278).** A spool read that fails for a reason other
  than a missing file keeps every segment, as before. The listener now logs a WARNING naming the
  directory and the count, at most once a minute. The "spool is full" warning says when a
  standing read fault may be what filled the spool. No unreadable segment is retired: that would
  delete undelivered records. While the fault stands, newer records are sent ahead of the
  unreadable ones, so replay order is not kept across a read fault.
- **Entries are written as UTF-8.** The default JSON escaping wrote six bytes for each non-ASCII
  character, which filled the cap early. The format version is unchanged, because a version 1
  reader already decodes both forms. An entry holding a lone surrogate keeps the escaped form.
- **A sent segment whose delete failed stays counted against the cap.** The listener tries the
  delete again after 1 second, doubling to 60 seconds, and `close` tries once more. The "spool is
  full" warning names such segments, and so does a WARNING at close when one remains. One still on
  disk at the next start is replayed whole, because nothing on disk marks it as sent. So the
  "up to one segment twice" limit above is a floor for a spool whose deletes fail.
- **A full disk leaves no empty segments.** A failed write removes the empty segment it started and
  hands its sequence number back.
- **A start whose forwarder cannot be built removes the directories and lock file that start
  created.** It never removes a directory that was already there, or one holding a segment, and
  it logs a WARNING naming segments an earlier run left. A spool that cannot be opened, other
  than one another process holds, names them too.
- **A spool that is turned off warns once at start when old segments remain.** It never deletes
  them: they are undelivered evidence, and a delete cannot be undone.
- **Records still queued at the drain deadline and moved to the spool are reported once**, at
  INFO, with their count.

**Stands by design.**

- **A TLS handshake failure that is not a failed certificate check is deferred to the spool.** Only
  a failed verification is certain to be a configuration fault. A "not yet valid" certificate is
  what a host sees before its clock syncs at boot, and a reset or timed-out handshake is what a
  collector that is restarting looks like. Treating either as permanent would turn the forwarder
  off for the life of the process over a fault that clears on its own. The cost is that a
  permanent fault of an unlisted kind is retried with backoff and never reported at ERROR.
- **The spool lock is held if the listener thread outlives its join.** The thread owns the spool,
  so closing the spool under a thread that may still append would race. The thread is a daemon and
  the operating system releases the lock when the process exits. Until then a second
  `configure_logging` in the same process runs without a spool and says so.

**Still open on #2279.**

- Tests resolve `siem.invalid` over live DNS. A process-wide stub cannot reach the serve
  subprocesses those tests start.
- The lock helper is duplicated in four modules. `log_spool.py` is in the start-up import budget,
  so sharing it is a design question.
- A lone surrogate can still be lost at send time by a caller that puts raw text into `LogSpool`.
  The engine's own path spells it as text before the queue, so it does not arise there.

## Amendment A (2026-10-08, PROPOSED) -- the gate also refuses this host's own name and addresses (vault BACKLOG #2375)

**Status: built, and not yet ruled on by the owner.** Owner ruling R4 (a) keyed the gate on
forwarding configuration. This amendment makes it read local host state as well, which is a
Builder's design inside that ruling and not part of it. The fail-open choice below is an open
owner question.

Decision 2 refused loopback only. A `forward_host` set to the engine's own LAN address passed,
although it is no more a separate system than 127.0.0.1 is.

The gate now also refuses a `forward_host` that is:

- this host's OS name, or that name's first label; or
- an IP literal that is one of this host's own addresses.

**What moved in decision 2's wording.** It said the gate "reads settings only". It now also reads
local host state: the OS host name, and, for an IP literal, the source address the routing table
gives for it. That read is a UDP socket connected and closed with nothing sent. The property the
ruling asked for is unchanged: the gate sends no packet, resolves no name and opens no connection
to the collector, so a down collector or a slow DNS server still cannot block a start.

**A failed read passes the gate, and logs a WARNING.** If the OS gives no name or no source
address, the gate decides as it did before this amendment. The same config can therefore pass
before an interface is up and refuse at the next start; the WARNING is the record of which.
The gate runs before logging is configured, so `serve` writes that line twice: to stderr where
the gate runs, and again through the configured log handlers once they exist. A caller other
than `serve` gets it on its own logger only. A refusal resting on a failed probe would be the kind of fault
R4 (a) keyed the gate on configuration to avoid. Whether it should refuse instead is an open
question for the owner.

**Still not caught, at least:** an alias that resolves to this host, and the fully qualified name
on a host whose OS name is short. On Linux both need a lookup, so they stay with the
collector-separation probe that #1199 names. On Windows the OS holds the qualified name locally;
reading it there is owed work.

**It can refuse a collector that is separate.** The address test asks the routing table, and the
routing table calls an address local when it is bound on this host, even if another system
answers on it. A virtual address bound on every node is the known case: a Kubernetes Service
address under kube-proxy's IPVS mode, read from the node's own network namespace, or a
direct-server-return address held on `lo`. This is reasoned, not measured. A DNS name for that
collector passes. Use one only when another system really answers on the address. The refusal
text points here and does not give that step itself, because the same step would let a collector
that is this host through.

**The Consequences line on start-time cost moved too.** It called the gate "a settings read". For
an IP-literal collector it is now also one local socket call, measured at well under a
millisecond on a Windows host. For a name it is one `gethostname` call.
