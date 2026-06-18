# Test harness

A standalone PySide6 tool to exercise **everything the engine can do** with synthetic, PHI-free
traffic — send and receive HL7 v2 over MLLP and file, send malformed messages, inject delivery
faults, and watch what a running engine actually did with each message.

```powershell
python -m harness                      # launch the GUI
python -m harness --list-scenarios     # list headless scenarios
python -m harness --scenario processed # run one scenario in CI (exit 0 pass / 1 fail)
python -m harness --list-profiles      # list headless load profiles
python -m harness --load smoke         # run a load profile (exit 0 SLOs met / 1 violation / 2 setup)
```

It reuses the engine's own MLLP framing + ACK builder (`messagefoundry.transports.mllp`), message
generators (`messagefoundry/generators`), and API client (`messagefoundry.console.client`), so it
frames, acknowledges, and reads engine state exactly as the real components do. New message types
light up automatically as they're added to `messagefoundry/generators/all_types.py`.

## GUI tabs

- **Send** — pick a message type/trigger (or "random across all"), a count, target `host:port`,
  and an optional rate; fire them and watch per-message ACK code / latency / errors. Sending runs
  on a worker thread so the UI stays responsive.
- **Receive** — start a localhost MLLP listener and reply with a configurable mode. Beyond
  **AA / AE / AR / none**, the reply can inject faults to drive the engine's *outbound* retry /
  dead-letter / independent-draining behavior: **delay then AA** (set the delay past the engine's
  timeout to force a retry), **close (no reply)**, and **fail N then AA** (reject the first N
  deliveries of a control id, then accept). Repeated control ids — the engine's at-least-once
  retries — are counted and highlighted.
- **File** — *Drop* generated messages into the engine's File-inbound directory (atomic writes,
  so the engine never polls a half-written file), and *Watch* its File-outbound directory, parsing
  and displaying each file that appears. Defaults match `harness/config`.
- **Compose** — send an arbitrary, hand-edited message (preset seeds: valid, no-MSH,
  wrong-version) over MLLP with an explicit **ACK expectation** (Accept / Reject / No ACK), flagged
  against the actual reply — or drop it as a file. This reaches the ERROR / AR / AE / strict-
  validation paths the generators can't.
- **Monitor** — connect to a running engine's API (reusing the console's sign-in) and observe what
  it did: live outbox stats + a connections table (polled off the UI thread), the message store
  with per-message disposition and full delivery/audit trail, the dead-letter queue with scoped +
  bulk replay, and a config-reload button. Connection start/stop/restart/purge controls included.

## Driving a complete engine

`harness/config` is a self-contained config graph wired to produce **every** disposition
and delivery path (see its docstring). Serve it, then drive it from the tabs above:

```powershell
python -m messagefoundry serve --config harness/config --db ./messagefoundry.db --env dev
```

| Send (Send/Compose tab → 127.0.0.1:2575) | Disposition (Monitor tab) |
|------------------------------------------|---------------------------|
| ADT^A01 / A04 / A08                      | PROCESSED (fan-out: MLLP echo + file) |
| any other ADT trigger                    | PROCESSED (file archive) |
| ADT^A02                                  | FILTERED |
| ADT^A03                                  | ERROR (AE NAK) |
| any non-ADT type                         | UNROUTED |
| malformed / wrong version (→ 2577)       | ERROR (AE NAK) |

To see retries → dead-letter → replay: leave the Receive tab **not** listening on 2576 (or set it
to *fail N then AA* / *close*), send an ADT^A01, and watch the echo delivery dead-letter in the
Monitor's Dead Letters tab — the file archive for the same message still succeeds (independent
draining). Then replay it from there.

## Headless scenarios (CI)

The scenario runner generates traffic, sends it, and asserts the engine's resulting disposition
(or dead-lettering) over the API — Qt-free, so it runs on a display-less runner. Built-in
scenarios target `harness/config`; serve it, then:

```powershell
python -m harness --scenario processed   # ADT^A05 → file → PROCESSED
python -m harness --scenario filtered     # ADT^A02 → FILTERED
python -m harness --scenario unrouted      # ORU → UNROUTED
python -m harness --scenario error         # ADT^A03 → ERROR
python -m harness --scenario dead_letter   # ADT^A01 echo with nothing on 2576
```

Pass `--engine <url>` for a non-default API address and `--token <t>` for an auth-enabled engine.

## Load testing (headless)

A separate, **Qt-free** asyncio load engine (`harness/load/`) drives the engine under heavy MLLP
traffic and measures it — the GUI's single-thread sender can't saturate it. A pool of **persistent,
pipelined** connections offers a data-driven [load profile](load/profiles/) (warmup → ramp →
sustained → spike → soak); a fast **correlation sink** absorbs the engine's outbound fan-out and
times every message end-to-end; an engine poller samples the API for throughput, backlog, DB growth,
and post-load drain. The run ends in an SLO verdict + a no-loss reconciliation and a JSON/CSV report.

Serve the synthetic high-fan-out [system-under-test](config/load/) (separate from `harness/config`),
then run a profile:

```powershell
$env:MEFOR_LOAD_FANOUT=20; $env:MEFOR_LOAD_TRANSFORM="edit"; $env:MEFOR_LOAD_SINK_PORT=2700
python -m messagefoundry serve --config harness/config/load --db ./load.db   # swap --db for backends
python -m harness --load fanout-baseline --engine URL --token T --report-json out/load/run.json
```

Full guide — profile schema, the env knobs, reading the report/SLOs, exit codes, baseline
comparison, and the backend-comparison recipe — is in [docs/LOAD-TESTING.md](../docs/LOAD-TESTING.md).
