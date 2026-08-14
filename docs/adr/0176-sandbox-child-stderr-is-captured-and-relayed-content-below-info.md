# ADR 0176 — Sandbox child stderr is captured and relayed, with content confined below INFO

- **Status:** **Proposed (2026-08-14)** — records the design decision for BACKLOG #343. The engine
  change is being built against it; this file is the *why*, which the diff cannot carry.
  <!-- Proposed (no code yet) -> Accepted (build may start) -> Superseded by NNNN / Rejected -->
- **Date:** 2026-08-14
- **Supersedes nothing.** Extends the fd-discipline established for the sandbox IPC channel in
  [ADR 0087](0087-sandbox-subprocess-isolation.md) to the one file descriptor that decision left
  undisciplined.

## Context

**fd 1 is strictly framed. fd 2 has no discipline at all.** The sandbox worker is spawned at
[`pipeline/sandbox.py:442-450`](../../messagefoundry/pipeline/sandbox.py) with `stdout=PIPE` and
`stderr=None`. The `None` is load-bearing and was deliberate — its comment reads *"let the child's
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
frame reader at [`sandbox.py:495`](../../messagefoundry/pipeline/sandbox.py). Every relayed line is
attributed to the inbound and worker that produced it, sanitised of ANSI and other control bytes, and
rate-limited, with the suppression count reported rather than silently dropped.

**D2 — Content is relayed at DEBUG only. At INFO and above, the engine emits an attributed,
rate-limited NOTICE carrying the identity and a count, and no content.** This is the load-bearing
clause. It satisfies section 9 **by construction** rather than by operator discipline: there is no
configuration, no verbosity setting and no error path by which child stderr content reaches a log
record at INFO or above, because no such call site exists. An operator running at INFO still learns
*that* a given inbound's Handler is writing to stderr, and how much, which is the operationally
actionable part.

**D3 — The worker rebinds `sys.stdout` to fd 2 at bootstrap, leaving raw fd 1 exclusively for
frames.** Sequenced after the frame writer captures its raw handle and before `load_config()` runs
any admin-authored code — which the comment at
[`sandbox.py:452-455`](../../messagefoundry/pipeline/sandbox.py) already identifies as the earliest
untrusted code and the first opportunity to spawn a grandchild.

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

**Attribution requires plumbing the engine does not have today.** `SandboxRunner` holds its policy,
config directory and environment, but no inbound name. Attributing a relayed line to an inbound
therefore widens the change beyond `sandbox.py` into the construction site in `engine.py`. That cost
is accepted: an unattributed relay closes (b) and leaves (a) open, and (a) is the forgery half.

**A second reader thread is a second teardown obligation.** It must be daemonised, cooperatively
stopped, and torn down on respawn and on close alongside the existing reader, or a killed worker
generation leaks a thread holding a dead pipe.

**Operators running at INFO lose Handler stdout and stderr content.** This is the deliberate cost of
D2 and should be stated in the operator documentation rather than discovered. The notice tells them
the content exists and at which level to find it.

## References

- BACKLOG #343 — the filed defect, from an adversarial review of the ADR 0087 sandbox codec.
- [ADR 0087](0087-sandbox-subprocess-isolation.md) — the sandbox and its fd 1 framing contract.
- [CLAUDE.md](../../CLAUDE.md) section 9 and [docs/PHI.md](../PHI.md) — the PHI logging rule this
  decision satisfies by construction.
- [CLAUDE.md](../../CLAUDE.md) section 0 — why the finding is written conditionally.
- [docs/SERVICE.md](../SERVICE.md) — NSSM capturing stdout and stderr to the operator's log files.
