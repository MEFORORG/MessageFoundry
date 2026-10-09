# Input surfaces: what each one expects

**This page maps the product's input surfaces to the rules that say what each input must look
like.** It covers surfaces outside the operator API. The operator API has its own page,
[API-INPUT-VALIDATION.md](API-INPUT-VALIDATION.md).

For each surface the page says four things:

1. what structure the engine expects;
2. where the rule lives in code, by module and symbol;
3. what happens to input that breaks the rule;
4. which document owns the detail.

**This page is a map, not a second copy of the rules.** Where another document already defines a
structure, this page names it and links to it. Follow the link for settings, defaults and numbers.
Where no structure is defined anywhere, this page says so.

Every list here is "at least", and so is the page. A new connector or command can add a surface
before this page is edited. The code named in each section is the source of record. Where this page
and the code disagree, the code is right.

**Some surfaces are not mapped here.** They include at least:

- the Python modules and code sets in a configuration directory, beyond what the
  `connections.toml` section says;
- the results of the read-only lookups a Handler may make, `db_lookup` and `fhir_lookup`;
- the command lines of the separate toolkit, the test harness and the tray manager.

| Surface | Where its structure is defined |
|---|---|
| [Inbound listeners and sources](#most-inbound-bodies-pass-the-same-ingress-checks) | This page for the shared checks; [CONNECTIONS.md](CONNECTIONS.md) for each connector |
| [HL7 v2 messages and field content](#hl7-v2-the-engine-checks-the-envelope-and-your-code-checks-the-fields) | [HL7-VALIDATION.md](HL7-VALIDATION.md) |
| [Non-HL7 payloads](#non-hl7-payloads-are-checked-for-type-then-parsed-on-demand) | This page, with one owner document per type |
| [`connections.toml`](#connectionstoml-is-held-to-the-connector-factories) | [CONNECTIONS.md](CONNECTIONS.md) |
| [Service settings](#service-settings-are-defined-in-configurationmd) | [CONFIGURATION.md](CONFIGURATION.md) |
| [The command line](#the-command-line-is-defined-by-its-parser-and-no-prose-page-lists-it) | The parser itself |
| [The VS Code extension](#the-vs-code-extension-is-a-client-and-the-engine-rule-is-the-control) | The engine rules it calls into |
| [Web console rows marked `-`](#some-web-console-parameters-carry-no-named-rule) | A generated table; no document defines a structure for each |

---

## Most inbound bodies pass the same ingress checks

Most inbound connections receive a body in one of two ways. A listener takes it from a socket. A
polling source reads it from a directory, a remote directory or a database table. Either way, the
connector hands the raw bytes to one of two shared handlers in
[`pipeline/wiring_runner.py`](../messagefoundry/pipeline/wiring_runner.py):

- `RegistryRunner._handle_inbound` serves most connectors. Its return value is the reply to send.
- `RegistryRunner._handle_inbound_http` serves every connector that declares `wants_receipt`. Today
  that is at least the HTTP listener and the DICOM C-STORE receiver. It returns the engine
  `message_id`, or `None` when the body was refused.

Both handlers run the same checks, in the same order. The checks themselves live in
[`pipeline/ingress_guards.py`](../messagefoundry/pipeline/ingress_guards.py). The inbound's
`content_type` picks the path. The values are the members of `ContentType` in
[`content_type.py`](../messagefoundry/content_type.py), and the default is `hl7v2`.

### What a text body must pass

A text body is any `content_type` that is not binary. Today the binary types are `binary` and
`dicom`.

| Order | Check | Symbol | Applies to |
|---|---|---|---|
| 1 | The bytes decode in the connection's declared `encoding`, with no replacement characters | `decode_body` | every text type |
| 2 | The decoded text holds no NUL character | `check_decoded`, `IngressNulRejected` | every text type |
| 3 | The body holds no MLLP frame byte (`0x0B` or `0x1C`) inside the message | `check_decoded`, `IngressFrameByteRejected` | `hl7v2` only |
| 4 | The body holds one `MSH` segment, not two or more | `check_decoded`, `IngressMultipleMessagesRejected` | `hl7v2` only |
| 5 | The decoded text is no longer than `INGRESS_MAX_BYTES` | `check_decoded` | every text type except `hl7v2` |
| 6 | The first bytes match the declared type | `check_declared_type` | every text type except `hl7v2` |
| 7 | The body parses as an HL7 v2 message, inside its size limits | `Peek.parse` | `hl7v2` only |
| 8 | The message passes strict structural validation | `validate` in `parsing/validate.py` | `hl7v2`, and only when the inbound turns it on |

A body that passes is committed to the ingress stage. Only then does the sender get a positive
answer.

**A streaming inbound differs in at least three ways.** First, an inbound that sets its own
`max_message_bytes` uses that number as the size ceiling in check 7, in place of the engine default
(`peek_max_bytes`). Second, when a body is at or over the inbound's streaming threshold, check 8
does not run, even if the inbound turns strict validation on. Only check 7 reads the header.
Third, the handler then detaches large embedded documents before the commit. That step can refuse
the body too, with an `ERROR` row and a negative answer.
[ADR 0105](adr/0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md)
defines it.

The reasons for two of the checks are recorded. [ADR 0205](adr/0205-an-outbound-frame-holds-exactly-one-message.md) covers
check 3, and
[ADR 0206](adr/0206-an-hl7-write-or-re-encode-never-lets-data-become-structure.md) for check 4.

### What a binary body must pass

A binary body is never decoded as text. It must be no larger than `INGRESS_MAX_BYTES`
(`check_binary_size`), and its first bytes must match the declared type (`check_declared_type`). It
is then carried as base64 by `carry_binary_ingress`.
[ADR 0028](adr/0028-base64-binary-carriage-codec.md) defines that carriage form.

### What happens to a body that fails a check

**A body that a check refuses is recorded.** The handler writes a message row with status `ERROR`
and a reason. Nothing is accepted and then dropped.

**Do not treat a stored reason as free of message content.** Most reasons are fixed text that names
the check. The strict-validation reason is scrubbed, but a bare value from the message can survive
the scrub.

**One case can leave no message row.** If the handler itself faults, for example when the store
is down, no check refused the body. Usually no row is written. A fault after the commit leaves the
committed row, so check the message log before you resend by hand. On MLLP,
`MLLPSource._answer_handler_failure` records a `handler_error` connection event. A sender that
expects replies gets a negative acknowledgment, and the connection closes.

What the sender is told depends on the connector and the content type:

| Sender path | Answer for a refused body |
|---|---|
| An `hl7v2` inbound with an acknowledgment mode other than `none`, on a connector that writes the handler's reply back. MLLP does, and so does raw TCP. | A negative HL7 acknowledgment. `_handle_inbound` picks the reject or the error code for each check. `build_ack` in [`mllpcodec.py`](../messagefoundry/mllpcodec.py) builds it, and the inbound's `AckMode` picks the code family. |
| A non-HL7 inbound on MLLP, raw TCP or X12 | No reply. These connectors send nothing for a non-HL7 body, accepted or refused. |
| The HTTP listener, for any content type | `422` with a fixed JSON body and no `message_id`. It never sends an HL7 acknowledgment. |
| The DICOM C-STORE receiver | A DIMSE failure status. [DICOM.md](DICOM.md) section 3 states which status answers which refusal. |
| A polling source (file, remote file, database), for any content type | Nothing. There is no sender on the line. The `ERROR` row is the record. |

**A failure after the commit is not reported to the sender, with one exception.** Routing,
transform and delivery run after the positive answer. A failure there becomes the message's `ERROR`
or dead-letter disposition. [ADR 0001](adr/0001-staged-pipeline-architecture.md) explains why.

The exception is an HTTP inbound that sets `reply_from`. It holds the HTTP turn until the named
outbound's reply is captured, so the caller can see a delivery failure or a timeout. The HTTP
listener section of CONNECTIONS.md states each answer.

### Each connector adds its own rules in front of the shared checks

A connector frames the bytes, bounds them, and decides who may connect. Those rules run before the
shared handler sees a body. A body a connector refuses at this stage never became a received
message, so it has no message row. The connector logs it and, on most connectors, records a
connection event.

[CONNECTIONS.md](CONNECTIONS.md) owns every setting and default below. The source connectors
registered today are at least these. Read the `register_source(...)` calls in
[`messagefoundry/transports/`](../messagefoundry/transports/) for the current set.

| Connector | Expected framing | Rule lives in | Input that breaks the framing |
|---|---|---|---|
| MLLP | Each message in a block: `0x0B`, the message, `0x1C 0x0D` | `MLLPSource` in `transports/mllp.py`; `MLLPDecoder` in `mllpcodec.py`; `FrameDecoder` in `framing.py` | Bytes outside a block are discarded. A block over `max_frame_bytes` closes the connection with a `frame_oversize` event. |
| Raw TCP | A start byte and an end byte, from a preset or set explicitly | `TcpSource` and `_codec_from_settings` in `transports/tcp.py`; `FrameDecoder` | The same as MLLP. |
| X12 over TCP | One `ISA` to `IEA` interchange, with no transport delimiter | `X12Source` in `transports/x12.py`; `X12FrameReader` in `parsing/x12/interchange.py` | Bytes between interchanges are discarded. An interchange over `max_interchange_bytes` closes the connection with a `frame_oversize` event. |
| HTTP listener | One HTTP/1.x request per connection, with a `Content-Length` body on `POST`, `PUT` or `PATCH` | `HttpSource` in `transports/http_listener.py` | A synchronous `4xx` or `503`, and the body never reaches the engine. The HTTP listener section of CONNECTIONS.md lists each status and its cause. |
| File | A file in the watched directory that matches `pattern`. An `hl7v2` file may hold several messages; `split_batch` in `parsing/split.py` splits it on `MSH`. | `FileSource` in `transports/file.py` | A file that is over `max_file_bytes`, fails to decompress, does not match its declared type, or is refused by the scan hook moves to the error directory. It gets no message row. |
| Remote file (SFTP, FTP, FTPS) | The same shape as File, on a remote directory | `RemoteFileSource` in `transports/remotefile.py` | At least a file over `max_file_bytes`, or one that does not match its declared type, moves to the remote error directory. It gets no message row. |
| Database poll | Rows returned by the operator's `poll_statement`. The body is one column's value when `body_column` is set, and otherwise the whole row as a JSON object. | `DatabaseSource` in `transports/database.py` | A poll error is logged and the poller keeps running. |
| DICOM C-STORE receiver | A DIMSE association, then one stored object per C-STORE | `DicomScpSource` in `transports/dicom.py` | A DIMSE failure status. See [DICOM.md](DICOM.md) section 3. |
| Timer | No external input. The body is the `body` setting the operator wrote. | `TimerSource` in `transports/timer.py` | A bad schedule or a missing `body` is refused when the connection is built. |
| Loopback | No socket and no poll. The body is a reply the engine captured from a downstream partner. | `LoopbackSource` in `transports/loopback.py`; `RegistryRunner._process_response_item` | See the note below the table. |
| Pass-through | No socket and no poll. The body is what a Handler sent to it. | `PassThroughSource` in `transports/passthrough.py` | Not applicable. |

**A Loopback body does not pass the shared handlers.** A captured reply comes from outside the
engine, so treat it as untrusted. `_process_response_item` holds it to the size ceiling
(`reingress_size_error`) and, for `hl7v2`, to `Peek.parse`. It does not run the other checks in the
table above. A reply that fails is recorded with status `ERROR`.
[ADR 0013](adr/0013-query-response-orchestration.md) describes the path.

The two file sources run the type check themselves, before the shared handler. They call the same
function the listeners use, `_content_matches_declared` in
[`parsing/sniff.py`](../messagefoundry/parsing/sniff.py). That is why a mismatched file goes to the
error directory, and a mismatched socket body gets an `ERROR` row.

The file handling and quarantine policy in CONNECTIONS.md covers the file sources in more depth. So
does its section on resource limits, for the connection and rate caps on every listener.

---

## HL7 v2: the engine checks the envelope, and your code checks the fields

[HL7-VALIDATION.md](HL7-VALIDATION.md) owns this subject. It defines three tiers. The first two run
at ingress. The third runs in a Router or Handler. The HL7 conventions for engine code are in
[`messagefoundry/CLAUDE.md`](../messagefoundry/CLAUDE.md), and
[ADR 0054](adr/0054-low-allocation-builtins-hl7-parser.md) describes the parser.

**Tier 1 always runs.** `Peek.parse` in [`parsing/peek.py`](../messagefoundry/parsing/peek.py)
expects:

- a body that opens with an `MSH` segment, after any leading whitespace;
- a header long enough to read its field separator and encoding characters;
- a size and a segment count inside the caps `enforce_size_limits` applies;
- escape sequences that cannot expand past the budget `enforce_expansion_budget` applies.

The separators come from the message's own `MSH` segment. They are never assumed. A body that fails
gets an `ERROR` row and, on a replying inbound, a negative acknowledgment.

**Tier 2 is opt-in per inbound.** It checks the message structure against the HL7 version.
HL7-VALIDATION.md lists what that covers. It does not check field content.

**The engine defines no structure for the content of a field.** A date, a code, an identifier or a
name inside a field is not checked at ingress, at either tier. Checking it is the job of your Router
or Handler. Two tools exist for that:

- the consistency primitives in
  [`parsing/consistency.py`](../messagefoundry/parsing/consistency.py), described under Tier 3 in
  HL7-VALIDATION.md;
- code sets, described in [CODESETS.md](CODESETS.md).

A Handler that finds bad content chooses the outcome: it filters the message, or it raises and the
message takes the `ERROR` or dead-letter disposition.

One field-level grammar is defined: the path a Router or Handler uses to name a field, such as
`PID-3` or `PID-5.1`. `parse_path` in `parsing/peek.py` owns it.

---

## Non-HL7 payloads are checked for type, then parsed on demand

A non-HL7 body reaches your Router or Handler as a `RawMessage`
([`parsing/message.py`](../messagefoundry/parsing/message.py)).
[ADR 0004](adr/0004-payload-agnostic-ingress.md) defines that path.

**At ingress the engine checks the type, not the structure.** It applies the shared checks above.
The type check looks only at the first bytes of the body. Leading whitespace and a byte order mark
are skipped for the text types.

**The structure is checked when your code asks.** Each type has a codec. A Router or Handler calls
it against the `RawMessage`. If the codec refuses the body and your code lets the error raise, the
message takes the `ERROR` or dead-letter disposition. By then the sender has its receipt, except on
the `reply_from` path described above.

| `content_type` | First bytes the type check expects | Codec, called on demand | Owner document |
|---|---|---|---|
| `json` | `{` or `[` | `RawMessage.json()` | [ADR 0004](adr/0004-payload-agnostic-ingress.md). The engine defines no JSON schema. |
| `fhir` | `{` or `[` | `FhirPeek` and `FhirResource` in [`parsing/fhir/`](../messagefoundry/parsing/fhir/) | [ADR 0022](adr/0022-fhir-resource-codec-rest-client.md) |
| `xml` | `<` | The hardened parser and the opt-in schema validation in [`parsing/xml/`](../messagefoundry/parsing/xml/) | That package's own docstring. No XML schema is defined unless you supply one. |
| `x12` | `ISA` | `X12Peek`, `X12Message` and the opt-in implementation-guide validation in [`parsing/x12/`](../messagefoundry/parsing/x12/) | [ADR 0012](adr/0012-x12-edi-codec.md) |
| `dicom` | A 128-byte preamble, then `DICM` | `DicomPeek` and `DicomDataset` in [`parsing/dicom/`](../messagefoundry/parsing/dicom/) | [DICOM.md](DICOM.md), [ADR 0025](adr/0025-dicom-codec-store-connectors.md) |
| `binary` | None. Opaque bytes have no reliable signature. | `RawMessage.raw_bytes` | [ADR 0028](adr/0028-base64-binary-carriage-codec.md) |
| `text` | None. Arbitrary text has no reliable signature. | None | No structure is defined. |

`_content_matches_declared` in [`parsing/sniff.py`](../messagefoundry/parsing/sniff.py) is the source
of record for the middle-left column.

**A FHIR body is held to the JSON type check and no more at ingress.** Whether it is a valid FHIR
resource is decided only when a Handler builds a `FhirResource`.

---

## `connections.toml` is held to the connector factories

[CONNECTIONS.md](CONNECTIONS.md), section "Connections as data", owns this file's structure.
[ADR 0007](adr/0007-gui-manageable-connections-toml.md) records the decision.

The file has no schema of its own. Each entry is passed to the same factory a code-first
`inbound()` or `outbound()` call uses, so the factory's parameters and their types are the schema.
The rules live in [`config/connections_file.py`](../messagefoundry/config/connections_file.py):

- `load_connections_file` reads the file;
- `_reject_unknown` refuses a key the table does not define;
- `_check_setting_types` holds each `[settings]` value to the factory's parameter type.

A machine-readable form of the same schema comes from `messagefoundry connection schema --json`,
built by `build_schema` in
[`config/connection_schema.py`](../messagefoundry/config/connection_schema.py).

**A file that breaks a rule does not load.** The loader raises a `WiringError`.

**Do not assume a refusal is free of the values in the file.** The type check on `[settings]`
never repeats a value, because a setting can be a credential. Other refusals can. At least a bad
`ack_mode` or `transport` value is echoed in the message.

A connection's name is held to one more rule, shared with the operator API.
[API-INPUT-VALIDATION.md](API-INPUT-VALIDATION.md) states it.

The per-environment value files that `env()` references read are a related input.
[CONFIGURATION.md](CONFIGURATION.md) describes them under `[environments]`.

---

## Service settings are defined in CONFIGURATION.md

[CONFIGURATION.md](CONFIGURATION.md) is the structure of the service settings. It catalogs the
sections and keys of `messagefoundry.toml`, the `MEFOR_*` environment variables, and the order in
which a flag, a variable, the file and a default win.

The rules live in [`config/settings.py`](../messagefoundry/config/settings.py): the `ServiceSettings`
model defines the fields, `load_settings` builds it, and `_reject_unknown_file_keys` refuses a key or
section the model does not define.

**The file is checked more strictly than the environment.** An unknown key or section in the file
fails the start. A misspelled `MEFOR_*` variable is refused only in part: at least a typo in its
section part is still dropped without a warning. The opening notes of CONFIGURATION.md state the
exact scope; read them there.

---

## The command line is defined by its parser, and no prose page lists it

**No single document defines the structure of every command.** The parser is the definition.
`_build_parser` in [`messagefoundry/__main__.py`](../messagefoundry/__main__.py) declares each
subcommand of the `messagefoundry` command, with its flags, their types and their allowed choices.
`messagefoundry --help` and `messagefoundry <command> --help` print it.

This section covers the `messagefoundry` command only. `CLI_TIERS` in
[`cli_surface.py`](../messagefoundry/cli_surface.py) names subcommands across two commands: this
one and the separate `messagefoundry-toolkit` command, whose parser is in
`messagefoundry_toolkit/__main__.py`. The test harness and the tray manager have entry points of
their own. This page does not map those three.

Individual commands are described where they are used, for example in
[USER-GUIDE.md](USER-GUIDE.md), [SERVICE.md](SERVICE.md) and [CONFIGURATION.md](CONFIGURATION.md).

What happens to input the command line will not take:

| Input | Result |
|---|---|
| An unknown subcommand, an unknown flag, or a value outside a flag's type or choices | The parser prints a usage error to stderr and exits `2`. A subcommand's flags still match by unambiguous prefix, so a shortened flag can be read as a real one. The opening notes of [CONFIGURATION.md](CONFIGURATION.md) state that rule. |
| An authoring command the engine does not carry | One line naming the toolkit command, and exit `2`. |
| Malformed JSON given to `--data` or on stdin, on the commands that read operator JSON | An error that names which input was at fault, and a non-zero exit. `_load_operator_json` in [`cli_common.py`](../messagefoundry/cli_common.py) owns the rule. |
| Anything a command did not expect, raised as an uncaught error | One redacted line on the log stream and exit `1`. Under `--json`, an `{"error": ...}` object on stdout as well. `run_cli` in `cli_common.py` owns this floor. |

Several commands take a path to a configuration directory. The engine loads Python from that
directory, so the path is a trust decision, not only a format question. Of the files inside it, this
page maps `connections.toml` only. The Router and Handler modules are Python;
[CONNECTIONS.md](CONNECTIONS.md) describes how to author them. [CODESETS.md](CODESETS.md) defines
the code-set files.

Some commands read message files, at least `dryrun` and `check`. Those bodies go through the same
decode and guard functions as live ingress. The module docstring of
[`pipeline/ingress_guards.py`](../messagefoundry/pipeline/ingress_guards.py) states where the dry run
differs.

---

## The VS Code extension is a client, and the engine rule is the control

The extension in [`ide/`](../ide/) does not hold rules of its own that the engine depends on. It
sends input to the engine in at least these ways:

- it runs `messagefoundry` subcommands ([`ide/src/cli.ts`](../ide/src/cli.ts)), so the command-line
  and `connections.toml` rules above apply;
- it calls the operator API ([`ide/src/engineClient.ts`](../ide/src/engineClient.ts)), so
  [API-INPUT-VALIDATION.md](API-INPUT-VALIDATION.md) applies;
- it writes and edits files in the configuration directory, at least Python modules (`ide/src/newRoute.ts`). The engine loads those files later, like any other file there.

[`ide/README.md`](../ide/README.md) describes the extension. No document defines an input structure
for it apart from the engine rules it reaches.

The extension does check some input before it sends it. These checks help the author; they are not
the control. They include at least:

| Input | Check | Symbol |
|---|---|---|
| A connection name typed into the wizard | A letter, then letters, digits and underscores | `validateName` in `ide/src/connectionWizardModel.ts` |
| A port typed into the wizard | A whole number from 1 to 65535 | `validatePort`, same file |
| The connection editor form | Built from the engine's own `connection schema --json` output | `connectionSchema` in `ide/src/connectionSchema.ts` |
| A sample file picked for the Steps view | A size cap, checked when the file is picked | `MAX_SAMPLE_FILE_BYTES` in `ide/src/sampleFile.ts` |

The wizard's name rule is narrower than the engine's. API-INPUT-VALIDATION.md explains the
difference. The file pickers are covered by the file handling and quarantine policy in
[CONNECTIONS.md](CONNECTIONS.md).

---

## Some web console parameters carry no named rule

The web console at `/ui` applies the operator API's rules on some routes.
[API-INPUT-VALIDATION.md](API-INPUT-VALIDATION.md) says which, and what a refusal looks like.

**For the remaining parameters, no document says what each one must look like.** A generated
table lists the console's path and query parameters that are text, and the named rule each one
carries:
[`packaging/messagefoundry-webconsole/tests/golden/ui_input_rules.txt`](../packaging/messagefoundry-webconsole/tests/golden/ui_input_rules.txt).
Read that table for the current set, not this page.

**A `-` in that table does not mean the input is unchecked.** It means the parameter matches none of
the rules in the table's own index. That index holds the console's named rules. A `-` parameter can
still be held to a rule somewhere else. At least these cases exist:

| Where the rule is applied | Example |
|---|---|
| An engine type on the route itself | `approval_id` on the approval routes is declared as the API's resource id |
| An engine request model the handler builds | `to` and `source` on the message resend route; `channel_id` and `destination_name` on the dead-letter replay routes |
| The store the handler calls | `file_id` is held to its exact shape by `UploadStore` in [`uploads.py`](../messagefoundry/uploads.py) |
| A parser further in | `field_path` reaches `make_spec` in `store/content_search.py`, which applies the `parse_path` grammar |
| The console, after parsing | `received_from` and `received_to`, as API-INPUT-VALIDATION.md describes |
| A bound on the route declaration | `m` on the account page has a length bound; `target` on the search page has a fixed pattern |

**So the table cannot tell you which `-` parameters are open.** To learn what one parameter accepts,
read its route in
[`messagefoundry_webconsole/routes/`](../messagefoundry_webconsole/routes/) and follow the value to
the handler it reaches. No document lists that for each parameter.

**The table has other limits too.** It leaves out at least a form field sent in a request body and a
parameter that is not text. The docstrings in
`packaging/messagefoundry-webconsole/tests/test_golden_surface.py` state what it covers.

API-INPUT-VALIDATION.md records the two parameters that carry no rule on purpose, and why.
