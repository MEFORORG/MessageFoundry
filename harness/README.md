# Test harness

A standalone PySide6 tool to exercise **everything the engine can do** with synthetic, PHI-free
traffic — send and receive HL7 v2 over MLLP and file, send malformed messages, inject delivery
faults, and watch what a running engine actually did with each message.

```powershell
python -m harness                      # launch the GUI
python -m harness --list-scenarios     # list headless scenarios
python -m harness --scenario processed # run one scenario in CI (exit 0 pass / 1 fail)
python -m harness --coverage           # connector kinds by direction vs the scenarios covering them
python -m harness --list-profiles      # list headless load profiles
python -m harness --load smoke         # run a load profile (exit 0 SLOs met / 1 violation / 2 setup)
```

It reuses the engine's own MLLP framing + ACK builder (`messagefoundry.mllpcodec`), message
generators (`messagefoundry/generators`), and API client (`messagefoundry.apiclient`), so it
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

The scenario runner injects traffic, then asserts what the engine did with it -- Qt-free, so it
runs on a display-less runner. Built-in scenarios target `harness/config`; serve it, then:

```powershell
python -m harness --list-scenarios
python -m harness --scenario processed            # ADT^A05 -> file -> PROCESSED
python -m harness --scenario filtered             # ADT^A02 -> FILTERED
python -m harness --scenario unrouted             # ORU -> UNROUTED
python -m harness --scenario error                # ADT^A03 -> ERROR
python -m harness --scenario dead_letter          # ADT^A01 echo with nothing on 2576
python -m harness --scenario mllp_echo_delivered  # the echo copy arrives at a harness MLLP sink
python -m harness --scenario file_roundtrip       # file in -> PROCESSED -> file out
python -m harness --coverage                      # which connector kinds the scenarios cover
```

Pass `--engine <url>` for a non-default API address, `--token <t>` for an auth-enabled engine, and
`--cacert <pem>` to trust the engine's minted certificate. A malformed endpoint, or a sink that cannot bind its port (the GUI
Receive tab already listening on 2576, say), exits 2 as a setup error; a scenario verdict is 0 or 1.

### Drivers, sinks and endpoints

A scenario is three parts, each one module per transport family and each discovered rather than
listed, so a new family is a new file and never an edit to a shared table:

- **Driver** (`harness/drivers/<family>.py`) -- injects payloads into one kind of engine
  *inbound* (MLLP, File, ...). It reports a failed send instead of raising.
- **Sink** (`harness/sinks/<family>.py`) -- stands up the peer an engine *outbound* delivers to
  and records what arrived, byte for byte. Every sink binds loopback, records in memory, and never
  logs a payload.
- **Endpoints** (`harness/endpoints/<family>.py`) -- the ports and directories a graph under
  `harness/config/` binds. The graph reads each one through the engine's own `env("harness_<key>",
  default=...)` and imports nothing from the harness; the harness resolves the same name as
  `--endpoint KEY=VALUE`, then the `MEFOR_VALUE_HARNESS_<KEY>` environment variable, then the
  documented default (`mllp_in` is 2575, `file_in` is `./harness_io/in`, and so on). A test holds
  every graph default equal to its endpoint default. The engine applies `MEFOR_VALUE_*` only with an
  environment active, so serve with `--env dev` when you move an endpoint. The tests serve the real
  graph with every port ephemeral and every directory temporary. Relative directories resolve
  against each process's own working directory, so run the engine and the harness from the same
  directory, or pass absolute paths to both.
- Every sink binds 127.0.0.1 only. The `host` endpoint is what drivers and engine outbounds DIAL.

Scenarios live in `harness/scenarios/<family>.py`, each module exporting a `SCENARIOS` tuple; a
name claimed twice is an error. A scenario declares the (connector kind, direction) pairs it
covers: it covers an inbound kind by injecting through it, and an outbound kind only by asserting
what a sink of that kind received -- a disposition alone does not say what left the engine. Every
run sends fresh `uuid4` control ids, so a long-lived store cannot satisfy it with a previous run's
rows.

### Connector coverage

`python -m harness --coverage` prints every connector kind the engine registers, by direction,
against the scenarios that cover it. It reads the engine's live connector registries, not a list
kept here, and flags a scenario that claims a kind the engine does not register. It needs no
running engine. `harness/coverage.py` is the one harness module allowed to import
`messagefoundry.transports` (read-only; `_CLIENT_ALLOWED` in `tests/test_dependency_boundaries.py`
names it), because the registries have no public listing.

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

## Transport families and hostile content

### Hostile content (MLLP and File)

`harness/scenarios/hostile.py` sends WELL-FORMED HL7 whose field values are hostile to a downstream
sink: path traversal in the field the File outbound names its file from, SQL and spreadsheet-formula
metacharacters, markup, raw HL7 escapes, redefined MSH-1/MSH-2 delimiters, MLLP framing bytes, bare
line breaks, an oversize field and non-ASCII text under MSH-18. The values are data in
`harness/scenarios/hostile_values.toml`; each is placed with the `Message` API, never by slicing raw
HL7, and a report names a value by its label, never its content.

Each `hostile_<class>` scenario injects through the MLLP and File drivers (framing bytes through MLLP
only) into the pass-through graph `harness/config/hostile.py` (ports 2628/2629,
`./harness_io/hostile_*`). It asserts the disposition; the bytes the MLLP and File sinks received
(identical to what was sent, except where the engine documents a change: line endings normalized to
CR, and an MLLP frame ending at its first 0x1C); that every written file is a single name inside its
directory, with nothing where an unconfined `{MSH-10}.hl7` would have landed outside it; and that
`/health` answers with every hostile connection still running. A NUL, or a body that does not decode
on the connection's charset, is a documented ERROR.

`KNOWN_DEFECTS` holds the scenarios an engine defect fails today, outside the registry (so not
reachable from `--scenario`); `tests/test_harness_hostile.py` runs each as a strict xfail on the
defect's own signature. Today that is MLLP framing bytes carried in by File and forwarded over
MLLP, which the peer receives truncated at the end block, with any later start block read as a
second message.

### Fuzzing a live engine

`python -m harness --fuzz` fuzzes a RUNNING engine in pure Python, so it runs on Windows too (the
repo-root `fuzz/` package is the in-process Atheris parser fuzzer; this one is `harness/fuzz/`). It
takes the generators' synthetic HL7, applies seeded mutations at three layers -- bytes, fields
(through the parsed `Message` model) and MLLP frames -- and sends each case through a harness
driver. After every `--fuzz-batch` cases it checks that `/health` answers `ok`; that every
positive ACK (AA/CA) names, in MSA-2, a control id the store holds with a disposition; that the
store grew across the batch by at least the number of ACKs and NAKs sent (a NAK's row often has no
control id, so it is counted, not matched); that every complete frame sent got exactly one reply,
each a well-formed ACK or NAK, followed by a clean close; and that no API call answered 5xx. `harness/fuzz/invariants.py` says why
each holds.

```powershell
python -m messagefoundry serve --config harness/config --db ./fuzz.db
python -m harness --fuzz --engine URL --cacert PEM --token T --fuzz-seed 7 --fuzz-iterations 100000 --fuzz-seconds 300
python -m harness --fuzz-replay <path printed by the failure> --engine URL --cacert PEM --token T
```

`--fuzz-driver KIND` and `--fuzz-endpoint KEY` pick the driver and the endpoint (`mllp` defaults to
`mllp_in`; any other driver must name one). Only `mllp` carries the frame layer and counts replies
per frame; through another driver a send error or a reply that is not an ACK still fails the case,
but nothing is matched to the store. Point the mllp driver at an inbound that answers in HL7: one
with `ack_mode = "none"` never replies, and every case would fail the reply rule. The store checks read
`GET /messages` about twice per case, so on an auth-enabled engine the per-user read limit (120 a
minute by default) sets the pace: the fuzzer waits out a 429 rather than failing. Exit 0 when every
invariant held, 1 when one broke, 2 on a setup error (including a 4xx mid-run). A failure prints the
seed, iteration, layer, mutation and sizes -- never a body -- and writes the exact bytes sent under
`--fuzz-out` (default: `messagefoundry-harness-fuzz` in the system temp directory, outside any
checkout). The same seed always produces the same bytes.

### Raw TCP and X12

`harness/config/tcp_x12.py` adds two independent paths on ports 2580 to 2583 (`tcp_in`,
`tcp_out`, `x12_in`, `x12_out`): an STX/ETX-framed `Tcp()` inbound carrying HL7 to a `Tcp()`
outbound that expects a reply frame, and an `X12()` inbound (`content_type="x12"`, framed by the
`ISA...IEA` interchange itself) to an `X12()` outbound that requires a TA1. The drivers and sinks
(`harness/drivers/tcp.py`, `x12.py`; `harness/sinks/tcp.py`, `x12.py`) use the engine's own pure
codecs, `messagefoundry.framing` and `messagefoundry.parsing.x12.X12FrameReader`, never
`transports/`. The X12 payloads come from a small synthetic builder,
`harness/drivers/_x12_interchange.py` (ISA15 `T`, no patient data).

```
python -m harness --scenario tcp_delivered              # AA ACK, PROCESSED, byte-for-byte at a tcp sink
python -m harness --scenario tcp_handler_error          # ADT^A03 -> the handler raises -> ERROR
python -m harness --scenario tcp_not_hl7_nak            # a non-HL7 frame -> framed AR NAK
python -m harness --scenario tcp_dead_letter            # a sink that closes unanswered -> retried, dead-lettered
python -m harness --scenario x12_delivered              # PROCESSED, verbatim at an x12 sink answering TA1*A
python -m harness --scenario x12_envelope_rejected      # IEA02 != ISA13 -> the handler raises -> ERROR
python -m harness --scenario x12_ta1_reject_dead_letter # TA1*R -> dead-lettered after one attempt
```

The engine records MSH-10 as the control id of an HL7 frame arriving over TCP, so the TCP
scenarios match by it. It records **no** control id for an X12 interchange (a non-HL7 inbound
commits its body with `control_id=None`), so the X12 scenarios list the inbound's newest rows,
open each new row's body once through the audited `GET /messages/{id}/raw` (surface `harness`),
and match this run's fresh ISA13 values. On an auth-enabled engine that read needs a token with
`messages:view_raw`, which the TCP and MLLP scenarios do not. A burst of other traffic large
enough to push this run's rows off that page reads as "not found", never as a pass.
