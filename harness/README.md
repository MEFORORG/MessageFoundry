# Test harness

A standalone PySide6 tool to exercise **everything the engine can do** with synthetic, PHI-free
traffic — send and receive HL7 v2 over MLLP and file, send malformed messages, inject delivery
faults, and watch what a running engine actually did with each message.

```powershell
python -m harness                      # launch the GUI
python -m harness --list-scenarios     # list headless scenarios
python -m harness --scenario processed # run one scenario in CI (exit 0 pass / 1 fail / 2 setup or skip)
python -m harness --coverage           # connector kinds by direction vs the scenarios covering them
python -m harness --list-profiles      # list headless load profiles
python -m harness --load smoke         # run a load profile (exit 0 SLOs met / 1 violation / 2 setup)
```

It reuses the engine's own MLLP framing + ACK builder (`messagefoundry.mllpcodec`), message
generators (`messagefoundry/generators`), and API client (`messagefoundry.apiclient`), so it
frames, acknowledges, and reads engine state exactly as the real components do. New message types
light up automatically as they're added to `messagefoundry/generators/all_types.py`.

It frames by the engine's one-frame rule too (ADR 0205): whether a payload holds a frame byte is
judged in one place, `FrameCodec.find_frame_byte` in `messagefoundry.framing`. At least the MLLP ACK writers (the Receive tab and the MLLP, load and
capture sinks) frame with `frame_neutralised`, which turns each frame byte into a space, so the
engine reads exactly one reply frame even when an echoed MSH-10 held one. The Send tab refuses such
a payload with `frame_checked` before it opens a connection and shows `not sent:` with the byte and
its position; the load sender refuses it on its open connection and counts it in `refused_sends`.
The Compose tab refuses one the same way by default; it sends one only when the operator ticks its
**Send MLLP frame bytes unchecked** box, for testing the engine's ingress refusal. The modules that frame unchecked are listed, with the
number of bare uses each makes and why, in `_DELIBERATE` in `tests/test_harness_frame_bytes.py`.
That test reads imports and attribute uses of `frame`; it does not see a frame assembled by hand.

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
  validation paths the generators can't. A message holding an MLLP frame byte is refused with
  `not sent:` unless the opt-in **Send MLLP frame bytes unchecked** box is ticked.
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
Receive tab already listening on 2576, say), exits 2 as a setup error; a scenario verdict is 0 or 1,
and a scenario whose precondition is missing here (the database family without a server) prints
`SKIP` and exits 2.

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
  every graph default equal to its endpoint default (or, where a graph casts a port into a URL, to
  that cast of it). The engine applies `MEFOR_VALUE_*` only with an
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
names it); its module docstring says what it may read.

It is also a gate. Every registered (kind, direction) pair must have a scenario or an entry, with a
reason, in `EXEMPT` in `harness/coverage.py`; `--coverage` prints a `GAP:` line and exits 1 when
one does not, and `tests/test_harness_coverage_gate.py` runs the same check in CI. A stale
exemption (its pair gained a scenario or is no longer registered) and a claim on a kind the engine
does not register are gaps too. The one exemption today is the Direct outbound, which needs S/MIME
keys and certificates on disk and is proven in its own family test instead.

A claim counts as coverage. A few families claim kinds their scenarios run only where the
dependency exists, and none of them passes without it: the database family needs a SQL Server
(`MEFOR_TEST_SQLSERVER`) and prints `SKIP` (exit 2) without one; DIMSE needs the `[dicom]` extra
and fails with "cannot run" without it; remote file needs the `[sftp]` extra and a password and
exits 2 (`SETUP`) without them, and runs over SFTP only (FTP and FTPS are not exercised). In the
test suite each is reported as a skip. The gate counts what a scenario CLAIMS, so a claimed pair
is covered even on a runner where its scenario skips -- and the Direct outbound, exempt here,
does run end to end in `tests/test_harness_email.py`.

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

The engine serves with sign-in on, and `--token` is a session for it. `python -m harness.load.rigadmin`
provisions an Administrator for the run and signs in for you; the guide below shows the three steps.

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

Each `hostile_<class>` scenario injects through the MLLP and File drivers (`hostile_framing_bytes`
through MLLP only, `hostile_framing_bytes_via_file` through File only) into the pass-through graph
`harness/config/hostile.py` (ports 2628/2629, `./harness_io/hostile_*`). It asserts the disposition;
the bytes the MLLP and File sinks received (identical to what was sent, except where the engine
documents a change: line endings normalized to CR); that every written file is a single name inside
its directory, with nothing where an unconfined `{MSH-10}.hl7` would have landed outside it; and
that `/health` answers with every hostile connection still running. A NUL, or a body that does not
decode on the connection's charset, is a documented ERROR.

MLLP frame bytes inside an HL7 v2 body are refused at ingress (ADR 0205), by any driver: ERROR,
and a NAK over MLLP. The one exception is an end block alone sent over MLLP. It ends the frame, so
the engine receives the message up to it, which holds no frame byte, and processes that prefix.

`KNOWN_DEFECTS` is the place for a scenario an engine defect fails, kept outside the registry. It is
empty since ADR 0205 fixed the last one, and its strict-xfail runner was removed with it; restore
that runner from git history before adding an entry.

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

### HTTP: the Http inbound, and the REST, SOAP, FHIR and DICOMweb outbounds

`harness/config/http.py` takes HL7 v2 over `POST` on `http_in` (2590) and a DICOM Part-10 object on
`http_dicom_in` (2591). ADT goes out as JSON to the REST outbound, ORM as a SOAP 1.1 envelope, ORU
as a FHIR Patient create, and the DICOM object as a STOW-RS `multipart/related` store. Each
outbound posts to a harness HTTP sink on loopback (`http_rest` 2592, `http_soap` 2593, `http_fhir`
2594, `http_dicomweb` 2595), which records the method, path, headers and body, and answers a status
the scenario chooses.

These outbounds sit behind `[egress].allowed_http`. `serve` turns
`[security].block_unlisted_outbound` on unless you set it, and then an empty list refuses all four,
so allow loopback first: `[egress] allowed_http = ["127.0.0.1"]`, or
`MEFOR_EGRESS_ALLOWED_HTTP=127.0.0.1`. The same rule applies to every other transport the directory
serves; the coverage graph's MLLP and File outbounds need `allowed_mllp` and `allowed_file_dirs`.
The Email outbounds also need `allowed_recipient_domains = ["harness.invalid"]`. That list is
deny-by-default whatever `block_unlisted_outbound` says, so leaving it empty refuses both.
The tests serve the graph with `allowed_http` set, and check that an empty or wrong list makes the
delivery scenarios fail.

```powershell
python -m harness --scenario http_rest_delivered          # also soap / fhir / dicomweb
python -m harness --scenario http_fhir_retry_dead_letter  # sink answers 503: retried, then dead-lettered
python -m harness --scenario http_rest_rejected_dead_letter  # sink answers 400: one attempt only
```

A delivery scenario checks that each message reached `PROCESSED` (by control id; a DICOM object
has none, so by the `message_id` in the inbound's `202` receipt), then checks every request the
sink saw: the destination's method, path and `Content-Type`, and this run's control id in the body.
The DICOMweb scenario also requires the stored part to equal the object it sent, byte for byte, and
is registered only where the `[dicom]` extra is installed. The sink redacts the values of common
credential headers and never logs a body. An outbound URL is always loopback: a sink binds nothing
else, so moving `host` moves only where a driver dials.

### TIMER, PassThrough and Loopback (internal inbounds)

`harness/config/internal.py` serves the three inbound kinds that have no external peer of their
own, and `harness/scenarios/internal.py` drives each from its natural source (ports and the
directory in `harness/endpoints/internal.py`, defaults 2610-2614):

- `internal_timer` -- nothing to inject. `IB_Internal_Timer` fires a fixed synthetic ADT^A08 every
  2 seconds into a File archive (`./harness_io/internal_timer_out` by default; a served harness
  keeps writing one small file per tick). The scenario counts only records received after it
  started and files that appeared after its sink started, so an earlier run cannot satisfy it.
- `internal_passthrough` -- MLLP in on 2610; the handler `Send`s into `PT_Internal_Relay`, whose
  own router forwards to a sink on 2611. The re-ingressed child is asserted on its own channel. The
  engine records a PassThrough child with no control id, so the scenario finds it by its body (an
  audited read); `tests/test_harness_internal.py` pins that gap with a strict xfail.
- `internal_loopback` -- MLLP in on 2612; the capturing outbound (`reingress_to`) dials a harness
  sink on 2613, and that sink's ACK is the message that re-enters on `LB_Internal_Reply`, whose
  router forwards it to a sink on 2614. The scenario asserts the forwarded copy is that ACK
  (MSA-2 naming the control id sent), not the original.

### Database (DatabasePoll in, Database out)

**This family is unverified without a server database.** The engine's DATABASE connector is
ODBC-only -- the SQL Server preset over the Microsoft ODBC Driver 18, or an operator-named ODBC
driver -- through `aioodbc`/`pyodbc` from the `[sqlserver]` extra. There is no SQLite path, and the
CI install line carries neither the extra nor a server, so on CI and on most machines both
scenarios report SKIPPED, with the missing piece named. A skip is never a pass (`--scenario` exits
2 and prints `SKIP`).

The graph is `harness/config/database/`, in its own directory so that serving `harness/config`
without a database stays clean (measured: without its credentials the graph's two connections fail
to start, isolated, and the engine reports DEGRADED). A DatabasePoll inbound, `DB-IN_Harness`, reads
`status = 'NEW'` rows of `dbo.mf_harness_inbox` and marks each `DONE` once it is durably received --
the poll needs that marker column, or every poll re-reads the same rows. ADT goes to a Database
outbound, `DB-OUT_Harness`, which writes `dbo.mf_harness_outbox` idempotently on the control id;
anything else is UNROUTED. The harness driver and sink create both tables. All SQL is
parameterized and the table names are constants.

Serve it with the server and its credentials in the environment (credentials never sit in source;
the server must present a certificate this host trusts, as the graph never weakens TLS, and
`[egress].allowed_db` -- `MEFOR_EGRESS_ALLOWED_DB` -- must list it, or `serve` refuses the dial):

```bash
export MEFOR_VALUE_HARNESS_DATABASE_SERVER=127.0.0.1 MEFOR_VALUE_HARNESS_DATABASE_PORT=1433
export MEFOR_VALUE_HARNESS_DATABASE_NAME=... MEFOR_VALUE_HARNESS_DATABASE_USERNAME=...
export MEFOR_VALUE_HARNESS_DATABASE_PASSWORD=...
export MEFOR_EGRESS_ALLOWED_DB=127.0.0.1
python -m messagefoundry serve --config harness/config/database --db ./harness-db.db --env dev
python -m harness --scenario database_roundtrip --engine URL --token T
```

`--coverage` counts the `database` inbound and outbound rows as covered because these scenarios
CLAIM them. That claim is made good only where a server exists; on a run that skipped, nothing
exercised the connector. `tests/test_harness_database.py` holds the end-to-end test, gated on
`MEFOR_TEST_SQLSERVER`. No CI step runs it, and wiring it into the existing SQL Server legs alone
would not verify anything: those present an untrusted certificate, so the test skips there.

### DICOM DIMSE (C-STORE SCP inbound, SCU outbound)

`harness/config/dimse.py` forwards every object its C-STORE SCP inbound receives, unchanged, to a
C-STORE SCU outbound whose peer is the harness DIMSE sink; the endpoints are `dimse_in` and
`dimse_out` (`harness/endpoints/dimse.py`), and the AE titles are in the graph's docstring. The
driver (`harness/drivers/dimse.py`) C-STOREs synthetic Basic Text SR objects with a fresh
SOPInstanceUID each; the sink (`harness/sinks/dimse.py`) records every C-STORE and answers Success
or a configured failure status. Serving `harness/config` now also binds that SCP, which needs the
`[dicom]` extra; without it that one inbound fails to start, harness discovery still works, and a
DIMSE scenario reports the missing extra rather than passing.

The engine records a DICOM object with no control id, so these scenarios match rows differently from
the HL7 ones: they snapshot the inbound's rows before sending, then read the bodies of rows that
arrived after it through the audited raw-body route (`surface="harness"`) and match them by
SOPInstanceUID. That needs a token with `messages:view_raw` as well as `messages:read`.
`harness/scenarios/dimse.py` lists the scenarios: delivered, retried-then-dead-lettered, and
refused-then-dead-lettered, each also counting the C-STOREs that reached the sink.

### Email and Direct (SMTP outbound)

`harness/config/email.py` takes MLLP on `email_in` (2660) and mails each ADT message to the
loopback SMTP sink on `email_smtp` (2661): ADT^A31 goes to a recipient the
`email_rejected_recipient` scenario makes the sink refuse with 550 at RCPT (dead-lettered, every
attempt refused), and every other ADT trigger goes to `clinic@harness.invalid` (`email_delivered`).
The hop is cleartext and declared so with `cleartext_accepted`; the graph's docstring says what
that declaration does and does not cover, and which egress allowlist entry it needs. The sink
(`harness/sinks/email.py`) is a minimal RFC 5321 server with no
dependency: EHLO/HELO, MAIL, RCPT, DATA with dot-unstuffing, RSET, NOOP, QUIT, and STARTTLS when
handed a server-side TLS context. It records the envelope and the message as submitted.

`harness/config/direct/` is the Direct (S/MIME over STARTTLS) graph. A Direct outbound loads its
keys and certificates when it is built, so that graph is served on its own with trust material
minted for the run (its docstring names the five `MEFOR_VALUE_DIRECT_*` values), and
`tests/test_harness_email.py` is where it runs: the sink receives an enveloped-data message over
STARTTLS that decrypts with the partner's key and carries the sender's signature. It is not a
registered scenario: a scenario runs against an engine that is already serving, and this one
needs certificates minted before that engine starts, plus a sink TLS context matching them. So
`--coverage` does not count the Direct outbound.

### Remote file (SFTP)

`remotefile_poll_in` and `remotefile_write_out` exercise the engine's REMOTEFILE connector over
SFTP, in both directions, against a real in-process SSH server (`harness/sinks/_sftp_server.py`,
paramiko's server classes, so they need the `[sftp]` extra). The server is the remotefile sink: it
binds 127.0.0.1 on `remotefile_sftp` (default 2670) and serves a temporary directory holding
`/inbox`, which the engine's inbound polls and the remotefile driver uploads into over SFTP, and
`/outbox`, which the engine's outbound writes. `remotefile_write_out` checks each written file
equals the upload byte for byte and sits directly in `/outbox`.

Host-key verification stays on. Each run mints a throwaway host key and pins it into the
`remotefile_known_hosts` file, which the engine and the driver both verify against; the rule about
the insecure escape, and the one known cause of a refused pin, are in
[`sinks/_sftp_server.py`](sinks/_sftp_server.py). The one password comes from
`MEFOR_VALUE_REMOTEFILE_HARNESS_PASSWORD`, set for both the engine and the harness. The graph reads
it without a default, so it lives in its own subdirectory and `serve --config harness/config` does
not load it:

```powershell
$env:MEFOR_VALUE_REMOTEFILE_HARNESS_PASSWORD = "<any throwaway value>"
python -m messagefoundry serve --config harness/config/remotefile --env dev
python -m harness --scenario remotefile_write_out --engine URL --token T
```

With no scenario running there is no server, and the inbound logs one failed poll per second and
retries. A missing extra or password is a SETUP error (exit 2), never a pass. FTP and FTPS are not
covered: there is no stdlib FTP server, and the reputable in-process one (pyftpdlib) is not a
dependency here.
