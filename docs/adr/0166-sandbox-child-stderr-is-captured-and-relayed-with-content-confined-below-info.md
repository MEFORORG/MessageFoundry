# ADR 0166 — Sandbox child stderr is captured and relayed, with content confined below INFO

- **Status:** **Proposed (2026-08-14)** — records the design decision for BACKLOG #343. The engine
  change is being built against it; this file is the *why*, which the diff cannot carry.
  <!-- Proposed (no code yet) -> Accepted (build may start) -> Superseded by NNNN / Rejected -->
- **Date:** 2026-08-14
- **Supersedes nothing.** Extends the fd-discipline established for the sandbox IPC channel in
  [ADR 0087](0087-sandbox-subprocess-isolation.md) to the one file descriptor that decision left
  undisciplined.

## Context

**fd 1 is strictly framed. fd 2 has no discipline at all.** The sandbox worker was spawned in
[`pipeline/sandbox.py`](../../messagefoundry/pipeline/sandbox.py) (`SandboxSession._spawn`) with
`stdout=PIPE` and `stderr=None`. The `None` was load-bearing and deliberate — its comment reads *"let the child's
stderr (logging) pass through to the engine's stderr"* — but the consequence is that the child's
stderr **is** the engine's own stderr, inherited raw. Admin-authored Handler code therefore writes
directly into the engine's log stream, unframed and unattributed.

**Two problems live in that one fact, and they have different severities and different fixes.**

**(a) Attribution.** A line emitted by a sandboxed Handler is byte-indistinguishable from a line
emitted by the engine. An operator reading the log cannot tell which inbound produced it, and a
Handler can therefore forge engine log lines, emit ANSI control sequences, or write content that
breaks whatever consumes the log. The service runs under NSSM, which captures stdout and stderr to
files ([docs/SERVICE.md](../SERVICE.md)), so the forged line lands in the operator's log of record.

**(b) PHI, and this is the half that matters.** A Handler that calls `print()` on a message body
writes a **full payload** into the general log at whatever level the operator is running.
[CLAUDE.md](../../CLAUDE.md) section 9 forbids logging full message bodies at INFO or above. Nothing
in the current path can prevent this, because there is no path — the bytes are not passing through
any code the engine controls.

**Both are conditional, not live.** MessageFoundry has zero deployments
([CLAUDE.md](../../CLAUDE.md) section 0), so nothing is exposing anything today. The correct framing
is that a deploying site **would** inherit both on first deployment. That changes the wording of the
finding and not one thing about the fix: these rules exist so the first deployment is safe.

**An adjacent defect shares the root and is closed here rather than left.** A Handler that `print()`s
to **stdout** lands in the interpreter's `TextIOWrapper` buffer, while the IPC frames are written
through the underlying `BufferedWriter`. The two do not currently interleave badly, so frames are not
corrupted today. **That is luck, not design** — it depends on buffering behaviour nobody chose and
nothing pins. Leaving it is leaving a latent frame corruption behind a coincidence.

## Decision

**D1 — Capture the child's stderr and relay it through the engine's stdlib logger.** Spawn with
`stderr=subprocess.PIPE` and drain it on a dedicated reader thread, mirroring the existing stdout
frame reader at [`sandbox.py`](../../messagefoundry/pipeline/sandbox.py) (`_reader_loop`). Every
relayed line is attributed to the inbound, the child pid and a per-session **worker generation**
counter — a pid alone is not a unique identity, because an OS recycles pids and a stale generation's
relay can still be draining a killed child while the live one runs. Control bytes are neutralised by
`logging_setup.scrub_control_chars`, the **one** definition `ControlCharScrubFilter` already applies to
every record, called here at the point a byte stream is assembled into a record rather than
reimplemented beside it. Lines are rate-limited, with the suppression count reported rather than
silently dropped.

**One bound in D1 must not be confused with the byte cap rejected below.** A child can write megabytes
with no newline, and an unbounded carry would let it size the parent's heap, so the drain splits a run
that reaches a fixed length into several records. That is a **memory** bound on the parent and it
**discards nothing** — every byte is still relayed, across more records. The rejected cap discards, and
discards the wrong end.

PHI redaction is deliberately **not** a second call site here: it is a property of the engine's log
handlers, which this parent-side relay rides like any other record.

**D2 — Content is relayed at DEBUG only. At INFO and above, the engine emits an attributed,
rate-limited NOTICE carrying the identity and a count, and no content.** This is the load-bearing
clause. It satisfies section 9 **by construction** rather than by operator discipline: there is no
configuration, no verbosity setting and no error path by which child stderr content reaches a log
record at INFO or above, because no such call site exists. An operator running at INFO still learns
*that* a given inbound's Handler is writing to stderr, and how much, which is the operationally
actionable part.

**Built with two independent mechanisms, and the redundancy was measured rather than assumed.** The
sole content call site is `log.debug`, and it additionally sits behind an `isEnabledFor(DEBUG)` guard so
the bytes are never even decoded below that level. Breaking *either* alone still keeps a printed message
body off an INFO log; only breaking both puts one there. That is why the guard is worth its line despite
looking redundant next to a `log.debug`: it is what makes the property survive a later edit that raises
the call site, which is the realistic way this regresses.

**The notice level is `WARNING`, not `INFO`.** An operator running `[logging].level = WARNING` would
never see an INFO notice, and a printing Handler would be entirely invisible — the accept-and-drop shape
the count-and-log invariant forbids, reintroduced by the fix for it. Cry-wolf is answered by the
throttle rather than by the level.

**D3 — The worker rebinds `sys.stdout` to stderr at bootstrap, so the text layer cannot reach fd 1.**
Sequenced after the frame writer captures its raw handle and before `load_config()` runs any
admin-authored code — which the job-assignment comment in
[`sandbox.py`](../../messagefoundry/pipeline/sandbox.py) already identifies as the earliest untrusted
code and the first opportunity to spawn a grandchild.

**This is design intent, not an enforced invariant, and the difference matters (SDS-3.7).** Rebinding
the *name* `sys.stdout` does not make fd 1 frames-only: `sys.__stdout__.buffer`, `os.write(1, ...)` and
`open(1, "wb")` all still reach the raw descriptor. What keeps a raw writer harmless is unchanged — the
closed-tag codec and the parent's unsolicited-frame check. Claiming the rebind seals fd 1 would be a
compensating control resting on a false premise; what it actually buys is that the *accidental* case
(`print()` in a Handler) can no longer sit one buffering change away from corrupting a frame.

## Alternatives rejected

**Relay at INFO with a per-line byte cap — rejected, and the reason generalises.** This is the
obvious compromise: keep the diagnostics visible at normal verbosity, bound the leak with a
truncation. It fails on the specific shape of this payload. **Truncating an HL7 v2 message to its
first N bytes keeps MSH and PID** — the message header and the patient identifying segment — and
discards the clinically bulky remainder. A byte cap therefore preserves *precisely* the most
identifying part of the record and throws away the least sensitive. It is the **worst available
redaction for this format**, not merely a weak one, and it would put a section 9 violation inside the
fix for the defect that violation is about. A truncated body is still PHI.

**`stderr=subprocess.DEVNULL` — rejected.** It closes both problems completely and costs the
operator every Handler traceback. A sandboxed Handler that crashes would fail silently, which trades
a log-integrity defect for a diagnosability one.

**Leave `stderr=None` and document the hazard — rejected.** The threat model is admin-authored
config, which is the same trust boundary ADR 0087 built the sandbox to contain. A control that exists
only as prose in a document is the compensating-control-on-a-false-premise shape that
[CLAUDE.md](../../CLAUDE.md) section 11 (SDS-3.7) forbids.

## Consequences

**A deadlock hazard is CREATED by this change and must be closed in the same commit.** With
`stderr=None` a flooding child is harmless, because the bytes go straight to the inherited descriptor.
With `stderr=PIPE` and nobody draining, a child that fills the pipe buffer **blocks**. The window that
matters is bootstrap: `load_config()` runs untrusted admin code before the boot reply is read, so a
child that writes enough to stderr during config load would hang until `startup_seconds` expires. The
stderr reader must therefore start in the same window the stdout reader does — before the boot frame
write — and no spawn or error path may leave a `PIPE` undrained. **This hazard did not exist before
this decision.**

*Measured while building it* (1 MiB written from config module scope, `startup_seconds = 10`): the
spawn wedges for the full startup budget when the drain starts after the boot **reply** is read, and
does **not** wedge when it starts immediately after the boot frame **write**, because the parent then
blocks on the reply while the drain is already running. The rule above is stated at the stricter of the
two on purpose — the safe boundary is cheap, the failure is a startup timeout that names the wrong
cause, and the margin is whatever a future edit inserts between the two points.

**Attribution requires plumbing the engine does not have today.** `SandboxSession` holds its policy,
config directory and environment, but no inbound name. Attributing a relayed line to an inbound
therefore widens the change beyond `sandbox.py` into the sole production construction site,
`RegistryRunner._sandbox_for` in `pipeline/wiring_runner.py` — **not** `engine.py`, which builds only
the policy and the config source. That cost is accepted: an unattributed relay closes (b) and leaves
(a) open, and (a) is the forgery half. The parameter is **required and keyword-only**, so a future
caller that forgets it fails at type-check time rather than silently reinstating an unattributed relay.

**A second drain thread is a second teardown obligation, and it is EOF-driven rather than
cooperatively stopped.** There is no stop flag to set: the drain is blocked in `read()` on the child's
pipe, and what ends it is the pipe reaching EOF when `_kill` reaps the whole process tree — the same
reap that already EOFs fd 1. Neither pipe is closed to force it, because closing a file object under a
mid-read thread raises `ValueError`, which neither drain's `except OSError` catches, so it would escape
into `threading.excepthook`. The respawn path therefore does **not** join: a surviving grandchild holds
both pipes, and waiting on it under the session lock would wedge the feed. `close()` is the one
exception and takes a **bounded** join, because this drain — unlike the frame reader, which only
enqueues — calls into `logging`, and a daemon thread inside a handler's `emit` when `logging.shutdown`
runs at exit either writes to a closed stream or holds a lock the atexit hook then blocks on.

**The relay is the sole drainer, so a slow log handler becomes back-pressure on the child.** A stalled
`[logging].forward_*` TCP/TLS collector makes each relayed record block for the forward timeout; a
blocked relay stops draining; a full pipe blocks the child mid-dispatch until `wall_seconds` fires and
the message dead-letters. This is back-pressure and not loss, and it only arises at `DEBUG`, where
content is being relayed at all — but it is a coupling that `stderr=None` did not have, and it belongs
here rather than in an incident.

**Operators running at INFO lose Handler stdout and stderr content.** This is the deliberate cost of
D2 and is stated in [docs/CONFIGURATION.md](../CONFIGURATION.md) rather than left to be discovered.
The notice tells them the content exists and at which level to find it. One caveat travels with that
instruction: `configure_stderr_logging` pins the **child's** root logger at `WARNING` for the worker's
whole life, and raising the parent's level does not reach it, so `DEBUG` yields every `print` and raw
write plus the child's `WARNING`+ records, and never the child's own `DEBUG`/`INFO` records — which the
child never emitted. Plumbing a level into the boot frame would add a wire field and is left as an
unfiled follow-up, named by subject because no number is allocated for it.

## References

- BACKLOG #343 — the filed defect, from an adversarial review of the ADR 0087 sandbox codec.
- [ADR 0087](0087-sandbox-subprocess-isolation.md) — the sandbox and its fd 1 framing contract.
- [CLAUDE.md](../../CLAUDE.md) section 9 and [docs/PHI.md](../PHI.md) — the PHI logging rule this
  decision satisfies by construction.
- [CLAUDE.md](../../CLAUDE.md) section 0 — why the finding is written conditionally.
- [docs/SERVICE.md](../SERVICE.md) — NSSM capturing stdout and stderr to the operator's log files.
