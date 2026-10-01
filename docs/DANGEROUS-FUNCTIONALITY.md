# Dangerous functionality in MessageFoundry

This page names the parts of MessageFoundry that do something powerful on purpose, and says what
holds each one in place. It exists so a deploying operator can find them without reading the source.

"Dangerous" here is the ASVS sense: code that executes other code, calls native libraries, changes
who a thread is, starts a process, changes machine security settings, or parses input an attacker
can shape. None of it is a defect. All of it is worth knowing about before you deploy.

> **MessageFoundry is a not-deployed beta. There are zero running instances.** Everything below is
> written about what the shipped code *would* do on a first deployment, not about a live system.

## What this page covers

Five things:

1. **The engine wheel** -- the `messagefoundry` distribution itself.
2. **The deployment path the project documents** -- the container image in `docker/`, and the
   Windows service scripts in `scripts/service/` (section 8).
3. **The VS Code extension** in `ide/` (section 9, and its parsers in section 7).
4. **The web console**, `messagefoundry_webconsole`, which the engine serves at `/ui` (section 10).
5. **The toolkit**, `messagefoundry_toolkit`, shipped as the `messagefoundry-toolkit` distribution.
   It holds the authoring commands that ADR 0201 is moving out of the engine wheel, such as
   `adr-analyze`. The scans in sections 4, 5 and 7 read it with the engine.

The 2026-08-22 owner ruling on scope named the first two, and its purpose was to bring the
deployment path in. It says nothing about the other three, so each is here for its own reason:

- The web console runs inside the engine's own process.
- The extension ships to the same operators.
- The toolkit carries the engine's own commands. Each command it registers is a row in the
  engine's command table, `CLI_TIERS` in `messagefoundry/cli_surface.py`, and ADR 0201 moves
  those commands out of the engine wheel a slice at a time. A site must not leave this page by
  moving between wheels.

Shipping at the engine's version is not a reason on its own. See the test harness under "What is
deliberately not here".

It does not cover your Routers and Handlers. Those are yours, and section 1 explains why that
matters more than anything else here.

**Third-party components have their own page.** [`RISKY-COMPONENTS.md`](RISKY-COMPONENTS.md) says
which dependencies are designated risky, and why. This page covers the engine's own code and stands
on its own.

## The short version

| # | Class | Where | Default posture |
|---|---|---|---|
| 1 | Executing your Python | Routers and Handlers | In-process, no isolation |
| 2 | Loading config by file path | Config loader | Loads every non-`_` module it finds |
| 3 | Loading a provider module by name | Two provider seams | Off unless you name an external provider |
| 4 | Starting processes | 11 modules | Varies, see below |
| 5 | Calling native libraries | 17 modules, mostly Windows-only paths | On where the platform needs it |
| 6 | Changing thread identity | Windows alternate credentials | Off unless configured |
| 7 | Parsing hostile input | Message payloads, partner replies, uploads, browser requests, archives, the VS Code extension | On -- this is the product |
| 8 | Changing machine security settings | Windows service scripts | Only when an administrator runs one |
| 9 | Processes, terminals and webview scripts | VS Code extension | Runs the CLI on open and on save, once you trust the workspace |
| 10 | Writing server-built HTML into the page | Web console | On |

---

## 1. The engine executes your Python

This is the big one, and it is the whole design.

Routers and Handlers are Python modules you write. The engine imports them and calls them on the
message path, **in its own process, with its own privileges**. A Router can do anything the engine
account can do -- open a socket, read a file, call out to the network.

That is not a vulnerability. It is the differentiator: routing logic is code, not a drag-and-drop
canvas. `.github/SECURITY.md` states the trust boundary, and `docs/SERVICE.md` gives the directory
permissions that enforce it.

**What holds it.** One thing, and it is an operating-system control rather than a product one: the
access control list on the config directory. Whoever can write a file there can run code as the
engine. Get those permissions right first.

**The isolation seam exists and ships off.** `[sandbox].mode` defaults to `"off"`
(`config/settings.py`), which runs Routers and Handlers in-process. Setting it to `"subprocess"`
moves them into a per-inbound child process.

Read the trade before you flip it. The sanctioned live lookups -- `db_lookup` and `fhir_lookup`,
the read-only enrichment carve-out in ADR 0010 and ADR 0043 -- do not cross the isolation boundary.
A Handler that needs live enrichment runs with the sandbox off today. Turning isolation on would
break that Handler rather than protect it.

---

## 2. The config loader imports by file path

`config/wiring.py` builds an import spec from a path and executes the module. Two sites do this: the
loader's own finder, and the direct module load.

**What it means.** Every `.py` file in your config directory that does not start with `_` gets
imported at startup, and its top-level code runs. A file you dropped there to look at later is not
inert.

**What holds it.** The same directory permissions as section 1. There is no allowlist of filenames.

**Some tools write Python into a config directory, and the loader then runs it.** At least these:

- `messagefoundry import corepoint`, in `corepoint_import.py`, turns a Corepoint export into one
  module per channel in the `--out` folder. It reads the export with `defusedxml`, and checks that
  each generated module compiles before writing it. `compile` here only parses the source; nothing
  runs until the engine loads that folder.
- `messagefoundry init` scaffolds a new config repository with a starter feed.
- `messagefoundry restore --config-to` writes a backup's config files into a folder, so a restore
  is only as trusted as the backup it reads. Section 7 says what holds that read.
- The VS Code extension's new-route command writes a new module into your config directory.

Each writes code that runs with the engine's rights on its next start. Review what they wrote
before you point the engine at it.

---

## 3. Two seams import a provider module you name

Each takes a provider name from your service configuration and imports the engine module that
carries that name:

| Seam | File | Setting | What it imports |
|---|---|---|---|
| Secret provider | `config/secretprovider.py` | `[secrets].provider` | `messagefoundry.config.secretprovider_<name>` |
| Key provider | `store/keyprovider.py` | `[store].key_provider` | `messagefoundry.store.keyprovider_<name>` |

**What holds them.** Neither takes a dotted path. The name must be one of a fixed list in the code,
so the import can only reach a module inside the engine's own package. The import runs only when you
name an external provider; the built-in ones import nothing. Today only the `vault` module ships for
each seam, and any other external name fails closed with an error. The name comes from your service
configuration, never from a message.

Some other sites import a module whose name is fixed in the code, and take no input at all. At least
these: `auth/ldap.py` probes two `pyspnego` modules to learn whether Kerberos is available,
`verify/checks.py` imports the ODBC driver and a fixed list of engine modules, and the package's
`__init__.py` resolves its lazy exports from a fixed table.

`anon/leak.py` loads one file by path: the publish guard's scanner. It walks up the folders above
its own file and runs the first `scripts/security/scan_forbidden.py` it finds. In a source checkout
that is the repository's own scanner. From an installed wheel, the walk continues above the install
folder, so a file planted at that path in any parent folder would run. It serves the
de-identification leak check only, and is not on the message path.

---

## 4. The engine starts processes

11 modules start a process. The reason differs at each, and so does the form of the start:

| Module | What it runs | When | Form |
|---|---|---|---|
| `pipeline/sandbox.py` | The sandbox worker | Only when `[sandbox].mode = "subprocess"` | argument list |
| `pipeline/supervisor.py` | Engine-shard children | Only under `messagefoundry supervise` | argument list |
| `pipeline/dr.py` | The operator's disaster-recovery hook | A DR takeover or fail-back, when `[dr].takeover_hook` or `[dr].release_hook` is set | shell string |
| `service.py` | `sc.exe`, and elevated `cmd.exe` and `powershell.exe` | Service status, start, stop, restart and install | argument list, ShellExecute |
| `service_status.py` | `sc.exe query` | Reading the service's state | argument list |
| `auth/trust_anchors.py` | `icacls.exe`, read-only | Checking a trust anchor file's permissions | argument list |
| `store/store.py` | `icacls.exe` | Setting owner-only permissions on store and key files | argument list |
| `checks.py` | `ruff` and `mypy`, found on `PATH` | `messagefoundry check`, when they are installed | argument list |
| `tray/actions.py` | VS Code, the default browser, the default viewer | Tray menu actions | argument list, browser, os.startfile |
| `tray/app.py` | The default editor | Opening `tray.toml` from the tray | os.startfile |
| `tray/branding.py` | The tray again, under its branded launcher | Tray startup | argument list |

What each form means:

- **argument list** -- the program and each argument go to the OS as separate items, with no shell
  asked for.
- **browser** -- Python's `webbrowser.open`, which on Windows ends in `os.startfile`.
- **os.startfile** -- Windows opens the path with whatever program is registered for its type.
- **ShellExecute** -- the Windows `ShellExecuteW` or `ShellExecuteExW` call, which takes a program
  path and one parameter string.
- **shell string** -- one string that a shell parses and runs.

**What holds the argument-list starts.** Python hands the program and its arguments to the OS
without a shell, and `tray/actions.py` sets `shell=False` explicitly. Where the program is a Windows
system tool, the code pins its absolute path under the system directory, so a same-named program
planted in the working directory cannot run instead. The security lint marks the reviewed sites with
a `nosec` note naming the rule it answers.

Two argument-list starts are not pinned that way:

- `checks.py` is a developer tool. It runs `ruff` and `mypy` by bare name, so Windows may find a
  copy in the working directory before the one on `PATH`.
- `tray/actions.py` opens a folder in VS Code through its `code` command. On Windows that command
  is a batch file, `code.cmd`, and Windows runs a batch file through `cmd.exe`. So a shell does read
  that start's arguments, one of which is `repo_path` from `tray.toml`. The command is found with
  `shutil.which`, whose Windows search can include the working directory, so a planted `code.cmd`
  may win there too. What holds it: `repo_path` must name an existing folder, and the tray runs as
  the signed-in user, who owns `tray.toml`.

**What each child is handed.** A process started with no environment of its own gets a copy of the
engine's, and the engine's environment holds its secrets. `messagefoundry/childenv.py` builds the
environment for the sandbox worker, the disaster-recovery hook and the engine shards. Its
docstring says what each one gets, and why that is not an isolation boundary by itself. The other
starts in the table hand over the whole environment. `tests/test_child_process_environment.py`
lists each one that does so by inheritance, with its reason, and fails a new start that names no
environment.

**The other forms are the ones to look at hardest.**

**The disaster-recovery hook runs a shell string.** `pipeline/dr.py` calls
`asyncio.create_subprocess_shell`, so the operator's command runs through a shell exactly as
written. Its own docstring says why: the command comes from `[dr]` in the service configuration,
never from a message, so it is trusted the same way the backup destination path is. That reasoning
holds only while that configuration file is as well protected as the config directory in section 1.
On a first deployment, whoever can edit it can run a shell command as the engine.

**Service control builds an elevated command line.** `service.py` starts, stops and restarts the
service through `cmd.exe /s /c` running `net.exe`, raised through the Windows UAC prompt with
`ShellExecuteW` or `ShellExecuteExW`. It needs `cmd.exe` because a restart chains two `net` calls
with `&`, so the service name is written into a line a shell reads, and that line runs as
administrator. The install action does the same with an elevated `powershell.exe`, writing the
environment name into its command line. What holds both: the code refuses a service name or
environment name with any character outside a short safe set, before it builds the line. It also
pins `cmd.exe`, `net.exe` and `powershell.exe` to the system directory.

The install line also carries the installer script's path, which is not checked the same way. The
code finds `scripts/service/install-service.ps1` beside the installed package and runs it as
administrator with `-ExecutionPolicy Bypass`. So that script is only as safe as the folder it sits
in: whoever can write there can run code as administrator the next time someone installs the
service.

**The tray opens files and URLs through Windows.** `os.startfile`, and `webbrowser.open` on Windows,
run whatever program is registered for the file type or URL scheme. The tray opens its log file,
`tray.toml` and the web console this way. What holds it: the console address must be a plain `http`
or `https` URL with a host before it reaches the browser. View Log opens only a `.log` or `.txt`
file on a local, unmapped drive, so a log path from `tray.toml` or the service's registry cannot
make it run a `.bat` or `.lnk`. [`TRAY.md`](TRAY.md), *What "View Service Log" will open*, states
the full rule. That rule does not stop every contact with a network host. At least two paths still
reach one:

- When the tray builds its menu, it checks whether the configured log path exists, before any of
  View Log's checks. So a network path in `log_path` reaches that host each time the menu opens.
- When View Log resolves a local symbolic link that points at a share, the tray contacts that share
  before it refuses the path. Planting one needs write access to the log's own folder.

`tray.toml` itself opens with the signed-in user's own rights.

---

## 5. Native library calls

17 modules import `ctypes` to call into C libraries. Most are Windows platform work that has no
pure-Python equivalent:

- Credential and key storage: `secrets_dpapi.py`, and `store/crypto.py`, which tries to pin key
  material in memory so it is not paged to disk, and to wipe it after use
- File owner and permission checks: `config/wiring.py`, `auth/anchor_path.py`, `store/store.py`
- Log path check: `tray/actions.py`, which asks `kernel32`'s `GetDriveTypeW` whether View Log's
  drive letter is a mapped network drive, so it can refuse one before opening the file
- Process and job control: `pipeline/sandbox.py`
- Drop-folder confinement: `transports/file.py`, which on Windows calls `kernel32`'s `CreateFileW`
  with `FILE_FLAG_OPEN_REPARSE_POINT`, so it opens each path part as itself rather than through a
  link or junction, `GetFileInformationByHandleEx` to refuse a part that is one, and
  `GetFinalPathNameByHandleW` to confirm where the file it opened really is (BACKLOG #2507, #2535).
  It then moves and deletes the file through that handle with `SetFileInformationByHandle`, so the
  act cannot be redirected after the check. POSIX needs no `ctypes` for this; it opens each path part
  with `O_NOFOLLOW` and acts relative to the opened directory
- Service, tray and shell integration: `service.py`, `service_status.py`, `tray/app.py`,
  `tray/winsvc.py`, `tray/winshell.py`, `tray/instance.py`, `tray/branding.py`
- Diagnostics: `crashdump.py`
- Alternate file credentials: `transports/wincred.py`, covered in section 6

**What holds them.** Every library whose code runs is loaded by a name fixed in the code, never by a
path from configuration. On Windows that is a system library such as `kernel32` or `advapi32`. The
one non-Windows load is in `store/crypto.py`, which reaches the C library already loaded into the
process to call `mlock`. One load takes a computed path: `tray/branding.py` opens the tray's own
launcher with `LoadLibraryExW`, but as a data file, to read its version resource, so none of that
file's code runs. Most sites declare argument and return types before the call, so a wrong-width
argument fails at the boundary rather than corrupting the stack. Not all do: at least `service.py`,
`service_status.py` and `store/crypto.py` make some calls without declared types.

---

## 6. One path changes who a thread is

`transports/wincred.py` reaches a Windows file share under credentials other than the service
account. The sequence is `LogonUser` to get a token, `ImpersonateLoggedOnUser` to apply it to the
current thread, the file operation, then `RevertToSelf`.

**Why it is built this way.** Windows caches one credential set per host per session, so two
connections to the same server under different accounts would collide. Per-thread impersonation
keeps them apart. The logon type requests no privilege the service account does not already hold.

**What holds it.** Three things. The work runs on a dedicated worker thread rather than the shared
pool, so an impersonated identity cannot leak into unrelated work. `RevertToSelf` runs in a
`finally` block. And the whole path is off unless a connection configures alternate credentials.

`config/wiring.py` also opens the current process token, to read it. It does not change it.

---

## 7. The parsers accept input an attacker chooses

Message payloads, partner replies, uploaded files, browser requests and archives all arrive from
outside. So do replies and sample files the VS Code extension reads. The tables below list at least
the parsers that read them. `CLAUDE.md` states the rule
this follows:
**treat all message content as untrusted data, never as instructions.**

**The HL7 parser is deliberately tolerant, and that is not a defect to fix.** Real clinical traffic
is not conformant. A sending system that has worked for fifteen years will send a segment no
specification allows, and refusing it drops patient data on the floor. So the fast path
(`parsing/peek.py`, the built-in parser of ADR 0054) accepts what it is given, and strict validation (`parsing/validate.py`,
hl7apy) is opt-in per connection.

**Nobody should reach a passing security grade by making the parser strict.** That would trade a
real clinical requirement for a paper control.

**What holds it instead.** Bounds and hardening, not rejection:

- Two pre-parse caps in `parsing/peek.py`, both checked before any parsing happens: a 16 MiB
  whole-message byte ceiling matching the MLLP and file ingress caps, and a 10,000-segment
  count ceiling. A pathological message is refused cheaply rather than walked whole. Either
  cap can be disabled per connection, which is the operator's choice to make.
- XML hardening in `parsing/xml/harden.py` against external-entity and entity-expansion attacks,
  with the lxml posture recorded in ADR 0015 and ADR 0122.
- defusedxml's refusal of entity declarations, and of DTDs where the call site asks for that, at
  the `xml.etree` parse sites: at least `RawMessage.xml()`, the Corepoint import and the SVG
  sanitizer. It comes from a copy vendored in `_vendor/defusedxml/`. The SOAP gate in
  `transports/soap.py` hardens its own `xml.sax` parser instead.
- A pinned pydicom floor in ADR 0025 that excludes a known path-traversal issue.
- Directory-listing names from a remote share checked as single safe path components before they
  are joined, so a partner cannot return a traversal sequence.

**How the parser list is found.** A test reads the code, so the list comes from the tree, not
from memory. You can re-run the same scan over `messagefoundry/`, `messagefoundry_toolkit/` and
`messagefoundry_webconsole/`. A module is a parse site when its syntax tree holds at least one of
these:

1. An import, at any depth, of a format library: `hl7`, `hl7apy`, `lxml`, `defusedxml` (or the
   engine's vendored copy, `messagefoundry._vendor.defusedxml`), `xml`,
   `xmlschema`, `signxml`, `pydicom`, `pynetdicom`, `pyx12`, `fhir.resources`, `fhirpathpy`,
   `cbor2`, `webauthn`, `spnego` (the module the pyspnego package installs), `csv`,
   `email.parser`, `email.feedparser`, `pickle`, `marshal` or `shelve`.
2. A JSON decode: a call to `json.loads`, `json.load` or the engine's `json_loads_or_refusal`, or
   any `.json()` method call.
3. A form, header or mail decode: a call to `parse_qs`, `parse_qsl`, `parse_http_list`,
   `parse_keqv_list`, `message_from_bytes` or `message_from_string`.
4. A hand-written byte parser: `split`, `rsplit`, `partition`, `rpartition`, `find`, `rfind`,
   `index` or `rindex` called with a bytes literal first, or any `unpack`, `unpack_from` or
   `iter_unpack` call.
5. An inbound connector: a call to `register_source`.
6. A certificate or key decode: a call to any function whose name starts `load_pem_`,
   `load_der_` or `load_ssh_`, or to `load_key_and_certificates` or `load_pkcs12`.

A hit inside a codec package under `parsing/`, such as `parsing/xml/`, counts for the whole package.
Every parse site the scan finds sits in exactly one of the first two tables below. The first holds
the modules where any code reads input from outside the engine, whichever call the scan matched.
The second holds the ones that read only what the engine wrote itself or an operator supplied. The
third table lists hand-written parsers the patterns cannot see, found by reading the code.

**One rule decides a hand-over.** Some modules only hand outside input to other code. Such a module
is in the first table when it hands the input to a parser. A parser here is a format library, a
module under `parsing/`, or a module in the hand-read table. The module is in the second table when
it hands the input only to other engine code, which picks the parser. A module that does both is in
the first table. The rule places at least these modules:

- `pipeline/wiring_runner.py`, first. It hands each received body to `pipeline/ingress_guards.py`,
  and an HL7 body to `parsing/peek.py`.
- `pipeline/dryrun.py`, first. It reads fixture files itself, and hands bodies to `parsing/`.
- `store/store.py`, `store/postgres.py` and `store/sqlserver.py`, first. Each hands a stored
  message body to `parsing/binary.py`.
- `transports/loopback.py` and `transports/passthrough.py`, second. They hand their bodies to the
  engine's intake.
- `__main__.py`, second. It hands at least dry-run fixtures to `pipeline/dryrun.py` and
  `pipeline/dryrun_trace.py`, a Corepoint export to `corepoint_import.py`, and a backup to
  `pipeline/dr_backup.py`.
- `auth/service.py`, second. It hands an identity provider's token to `auth/oidc/`, and a passkey
  response to `auth/webauthn.py`. The first table's identity provider and passkey rows cover them.

The scan leaves some parsing out on purpose, and it has limits:

- `tomllib` is not in pattern 1. It reads at least service settings, connection files, environment
  value files, de-identification rules, the tray's settings, code sets and a reference sync's file.
  Of those, only the reference sync's file is known to come from another system. The code-set
  loader, `config/code_sets.py`, parses it, and is in the first table through its `csv` import.
- Libraries parse their own wire: uvicorn's HTTP server, the HTTP clients, TLS and `ldap3`. FastAPI
  decodes every other API request body as JSON, and checks it against a model before a route sees
  it. [`RISKY-COMPONENTS.md`](RISKY-COMPONENTS.md) covers those libraries. The engine's own HTTP
  inbound listener is hand-written, and it is in the first table. `ssl` also parses the
  certificates it loads itself, from a file path or from text in memory. Pattern 6 does not see
  those loads.
- A hand-written parser that makes none of these calls is missed by the scan. The third table holds
  the ones found by reading, and there may be more. A parser passed as a value rather than called,
  as in `asyncio.to_thread(json.loads, raw)`, is missed too. Parsing inside your own Routers and
  Handlers is yours (section 1).
- Archives and compressed streams have a scan of their own, in the list after these tables.

**Parsers that read input from outside the engine.**

| Input | Where it comes from | Modules |
|---|---|---|
| Inbound connectors | Whatever a sender or a polled source delivers. `transports/http_listener.py` reads the HTTP request line and headers itself. | `transports/file.py`, `transports/http_listener.py`, `transports/remotefile.py`, `transports/tcp.py`, `transports/x12.py`, `transports/database.py` |
| The intake path | Every received body. `pipeline/wiring_runner.py` is the shared ingress code. It hands each body to the decode and size guards, and an HL7 body to the peek, then to the parsers below. The live router and transform workers call the routing and transform core in `pipeline/dryrun.py` (`route_only`, `transform_one`), which hands each body to the parser for its content type. | `pipeline/wiring_runner.py`, `pipeline/dryrun.py` |
| Dry-run fixtures | The sample and batch files a dry run reads, such as the `--messages` files of `messagefoundry dryrun`. A fixture may be captured traffic. `read_fixture` reads each file, and `split_messages` hands a batch file to `parsing/split.py` to split. The scan's match in this module is different: a JSON decode of a value it encoded a moment before. | `pipeline/dryrun.py` |
| A stored message body, when retention strips its documents | The body a sender delivered, decrypted from the store. Each backend's retention pass hands it to `parsing/binary.py`, in the hand-read table below, to strip its embedded documents. The scan's matches here are different: JSON the engine wrote itself. | `store/store.py`, `store/postgres.py`, `store/sqlserver.py` |
| HL7 v2 | An inbound connection. Strict validation is opt-in. The tolerant parser is hand-written, so it is in the hand-read table below. | `parsing/message.py`, `parsing/validate.py` |
| MLLP frames and HL7 acknowledgements | An inbound sender, or the partner an outbound delivers to | `transports/mllp.py` |
| JSON and FHIR payloads | An inbound whose content type is `json` or `fhir`. They are parsed when a Router or Handler asks, as with `RawMessage.json()`. | `parsing/message.py`, `parsing/fhir/` |
| XML and SOAP | An inbound payload, a SOAP body fragment built from a message, or a partner's SOAP fault reply. `_vendor/defusedxml/` is the vendored defusedxml copy the stdlib-parser sites parse through. | `parsing/message.py`, `parsing/xml/`, `_vendor/defusedxml/common.py`, `_vendor/defusedxml/ElementTree.py`, `transports/soap.py` |
| X12 | An inbound whose content type is `x12` | `parsing/x12/` |
| DICOM | An inbound DICOM association or payload | `parsing/dicom/`, `transports/dicom.py` |
| A JSON payload for a database outbound | What a Handler built from a message | `transports/database.py` |
| An SVG attachment inside a stored message | A sender, through the message. It is read when the attachment is downloaded. | `api/svg_sanitize.py` |
| An uploaded file | The body of `POST /uploads`, or of `POST /ui/uploaded-logs/upload`, which the same handler serves. `api/multipart.py` is a hand-written `multipart/form-data` parser (ADR 0134), and its own comment calls each part's header block attacker-supplied. The route needs the files-upload permission and step-up authentication. | `api/app.py`, `api/multipart.py`, `uploads.py` |
| A reference sync's file source | A file another system exports. `pipeline/reference_sync.py` re-reads it on a schedule and hands it to the code-set loader, and a dry run's reference preview in `pipeline/dryrun.py` does too. The same loader reads the code sets in the config directory, which are operator input. | `config/code_sets.py` |
| The sandbox child's replies | The child runs your Routers and Handlers, so the parent treats what it sends back as untrusted | `pipeline/sandbox.py`, `pipeline/_sandbox_codec.py` |
| Partner and service replies | A partner's HTTP reply headers, a REST peer's Digest challenge, a FHIR server, a DICOMweb server, a SMART token endpoint, the AI provider | `transports/bounded_read.py`, `transports/rest.py`, `transports/fhir.py`, `transports/dicomweb.py`, `transports/smart.py`, `transports/ai_broker.py` |
| Text a remote peer sizes | A reply field, a traceback or an error text, clamped and redacted before it is logged or shown | `redaction.py` |
| Replies from an engine address | Whatever answers at the address a client is given. It is meant to be the engine, but nothing proves that before the parse. | `apiclient/client.py`, `tray/probe.py`, `verify/smoke.py` |
| Identity provider replies | The OpenID Connect token response and key set, and an ID token's header and claims | `auth/oidc/flow.py`, `auth/oidc/jwks.py`, `transports/signing.py` |
| A passkey response | A browser sends JSON with CBOR (Concise Binary Object Representation) inside. The `webauthn` library, from the optional `[webauthn]` extra, decodes the CBOR. | `auth/webauthn.py`, `messagefoundry_webconsole/routes/account.py` |
| A Kerberos sign-in token | The token a browser sends for Windows single sign-on, in its `Authorization: Negotiate` header. The API route decodes its base64, as the web console's `routes/sso.py` does, and pyspnego decodes the token. Kerberos sign-in is off unless configured. | `api/auth_routes.py`, `auth/ldap.py` |
| A TLS client's certificate | The certificate a TLS client presents, read again to find its issuer. The same module also decodes an operator's PKCS #12 file and certificate revocation lists. | `pki.py` |
| A partner's certificate | The recipient certificate a Direct outbound encrypts to. An operator names the file, but the partner issued what is in it. The module decodes it first, then checks it against the operator's trust anchor. It also reads the operator's own signing key. | `transports/direct.py` |
| Web console requests | The form bodies a browser posts, and the Content Security Policy reports it sends | `messagefoundry_webconsole/routes/_common.py`, `messagefoundry_webconsole/routes/connection_writes.py`, `messagefoundry_webconsole/routes/core.py`, `messagefoundry_webconsole/routes/monitoring_writes.py`, `messagefoundry_webconsole/routes/oidc.py` |
| A file from another system | A Corepoint export, read with `defusedxml` (section 2) | `corepoint_import.py` |
| A backup | The manifest and encrypted blocks `messagefoundry restore` reads. The archive list below says what bounds them. | `pipeline/dr_backup.py`, `store/backup_codec.py` |

**Parse sites left out, and why.**

| Why it is left out | Modules |
|---|---|
| It reads rows or files the engine wrote itself: its store, audit details, approval requests and log spool. It also decodes JSON it encoded a moment before: each value in the sealed state and reference caches | `store/metadata.py`, `store/crypto.py`, `store/sealed_cache.py`, `api/approvals.py`, `auth/channel_scope.py`, `auth/permissions.py`, `auth/service.py`, `auth/trust_anchors.py`, `log_spool.py` |
| It reads the responses the engine's own HTTP server writes | `api/protocol_headers.py` |
| It reads what an operator supplies: service settings, the code sets in the config directory and edits to them, private key files, command-line JSON, the install's package metadata, a restore token file and the trust anchor files it chooses to trust | `config/settings.py`, `config/codeset_edit.py`, `keywrap.py`, `__main__.py`, `cli_common.py`, `integrity.py`, `pipeline/dr.py`, `auth/trust_anchors.py` |
| It is an inbound whose own code reads nothing. The timer emits a body an operator configured. The loopback and pass-through inbounds take bodies the engine hands over: a partner's captured reply, or a Handler's output. Those bodies are outside input, and the parsers in the first table read them. | `transports/timer.py`, `transports/loopback.py`, `transports/passthrough.py` |
| It parses no input. It builds messages or reads `hl7apy`'s own schema tables. | `generators/_core.py`, `generators/siu.py`, `hl7schema.py`, `hl7structures.py` |

**Hand-written parsers the patterns cannot see.**

| What it parses | Modules |
|---|---|
| MLLP and TCP frames, before any other code sees the bytes | `framing.py`, `mllpcodec.py` |
| HL7 v2, in the engine's own tolerant parser (ADR 0054). It reads every inbound HL7 body, and the de-identification tools read captured traffic through it. | `parsing/_builtin_hl7.py`, `parsing/peek.py`, `anon/hl7.py` |
| HL7 batch files, split into messages | `parsing/split.py` |
| The first bytes of a payload, to check its declared content type | `parsing/sniff.py` |
| An inbound text body, decoded with its connection's declared character set and checked for NUL bytes and size, before the HL7 peek or a Router sees it. A binary body is only size-checked and base64-carried. | `pipeline/ingress_guards.py` |
| Base64 binary carriage (ADR 0028). Also the base64 documents a sender embeds in HL7 OBX-5, which intake detaches, retention strips and delivery puts back. | `parsing/binary.py` |
| The separators of a captured HL7 message, before de-identification | `anon/surrogates.py` |
| The reply from a network time server | `logging_setup.py` |
| Decision records, for `messagefoundry-toolkit adr-analyze`. It reads each `[0-9]*.md` file at the top of the `--adr-dir` folder, `docs/adr` by default. Regular expressions pick out each record's status, acceptance criteria and open items. For each `tests/`, `fixtures/`, `samples/` or `harness/` path a criterion names, it checks whether that path exists under `--repo-root`. A linked path that climbs out of that root with `..`, or has a part named for a DOS device such as `NUL` or `nul.py`, is reported and not checked, on every platform. A symbolic link inside that root is still followed. Nothing bounds a record's size, so a record is only as trusted as its author. | `messagefoundry_toolkit/adr_analyze.py` |

The first two tables rest on a judgement about where each input comes from, and the test cannot
check that judgement. Re-read a row when its module changes what it reads.

**How the extension's parser list is found.** The VS Code extension's TypeScript gets a scan of its
own, over `ide/src` without its `test` folder, as in section 9. It reads by pattern rather than by
syntax tree, and skips whole-line comments. A file is a parse site when a line of it holds at least
one of these:

1. A JSON decode: a call to `JSON.parse`, or any `.json()` call.
2. A line split: a `split` call whose first argument is a string or regular-expression literal that
   holds `\r` or `\n`.
3. A character read: a call to `charAt`, `charCodeAt` or `codePointAt`.
4. A network read: an import of Node's `http`, `https`, `http2`, `net`, `tls` or `dgram` module,
   with or without the `node:` prefix, or a call to the global `fetch` or `WebSocket`.

Every file this scan finds sits in exactly one of the first two tables below. The third lists files
the patterns cannot see, found by reading the code. The scan's limits include at least these:

- VS Code decodes a webview's messages before the extension sees them, and Node parses its own
  HTTP, TLS and URL formats. Those are left out, as the Python libraries are. What a webview page
  may ask the extension to do is section 9's subject.
- A regular expression is not a pattern, just as `re` is not one for Python. So the scan misses a
  file that parses text only with a regular expression, or that splits it on a named constant.
- A parser passed as a value, as in `.then(JSON.parse)`, is missed. So is a character read by
  index, as in `line[3]`.
- A page script kept inside a TypeScript template string is read as TypeScript. A line split
  there is written with a doubled backslash, so the scan misses it.
- A call is read one line at a time. A `split` whose argument starts on the next line is missed.
  A line inside a block comment that does not start with `*` counts as code, as it does for the section 9 counts.
- A type-only import of a network module counts as a network read, though it reads nothing. So
  does a call to a local function named `fetch`.
- Scripts outside `ide/src` are not scanned, such as the webview script in `ide/media/`.
- The web console's browser scripts, in `messagefoundry_webconsole/static/`, are not scanned. They
  parse what the console's own origin sends them (section 10), and what the browser keeps for that
  origin.

**Extension parsers that read input from outside.**

| Input | Where it comes from | Files |
|---|---|---|
| Replies from an engine address | Whatever answers at the engine URL setting. The file's own comment says that is not necessarily the engine, and a plain `http` URL gets no TLS. The Python clients' replies sit in the first table above for that reason too. Unlike `apiclient/client.py`, this client puts no size cap on a reply before it parses it, and a POST has no timeout. | `engineClient.ts` |
| An HL7 sample, and what a dry run made of it | The sample file you pick, which [`CONNECTIONS.md`](CONNECTIONS.md) lists as an upload feature, and the output a dry run built from it. The Test Bench diff splits them into segments and fields by hand, and the Steps view pulls the segment names out of the sample. A saved test case's recorded output is diffed the same way. `hl7diff.ts` does the same job as `anon/surrogates.py` in the engine's hand-read table. | `hl7diff.ts`, `hl7scope.ts` |

**Extension parse sites left out, and why.**

| Why it is left out | Files |
|---|---|
| It reads the JSON the MessageFoundry command line prints. The extension runs that command itself, and section 9 says when. Message content inside that JSON goes on to `hl7diff.ts`, in the table above. `connectionSchemaModel.ts` matches pattern 4 only because its caller passes it that command's result under the name `fetch`. | `cli.ts`, `connectionSchemaModel.ts`, `engineControlModel.ts`, `stepsModel.ts` |
| It reads your config source line by line, from the open editor or the config folder. That code runs when the engine loads it (sections 1 and 2), so reading its text trusts it no further. | `completionScope.ts`, `editorToolbar.ts`, `liveDebug.ts`, `stepsModel.ts`, `symbolIndex.ts`, `traceView.ts` |
| It reads your workspace's `.gitignore` and `.gitattributes`, to add the lines they lack | `sourceControl.ts` |
| It reads files that ship inside the extension: its HL7 schema tables and its snippets | `hl7schema.ts`, `insertElement.ts` |
| It reads a value you typed into the extension's connection form | `connectionForm.ts` |
| It reads back the saved Test Bench collections it stored itself, as JSON, in VS Code SecretStorage. It checks each collection's shape and drops a malformed one. The case bodies inside go on to `hl7diff.ts`, in the table above, when a collection is rerun | `collectionStore.ts` |
| It takes the first line of hover text it built, for a menu title. That text can carry words from the engine's reply, which `engineClient.ts` already parsed. | `statusBar.ts` |

**Extension files that parse text the patterns cannot see.**

| What it reads | Files |
|---|---|
| The code you are typing, matched with regular expressions to offer completions | `completion.ts` |
| Its own page's menu values, matched with a regular expression | `wiringMapWebview.ts` |

Neither reads input from outside, and there may be more files like them.

**Archives and compressed streams are parsed too.** A small input can expand into a huge one, and
an archive names its own members, so each reader below bounds both. These modules import an archive
or compression library:

- `parsing/compression.py` (ADR 0123) decompresses gzip, zlib-deflate and zip from partner feeds.
  The File connector's `decompress=` option uses its gzip reader, and a Handler may call any of the
  three. Every decompress call must name an output ceiling, or pass `None` on purpose for none. The
  reader enforces a ceiling as it goes, so a decompression bomb stops there rather than expanding
  in memory. The File
  connector's ceiling, `max_decompressed_bytes`, defaults to 64 MiB; setting it to `0` turns it off.
  A zip is refused whole for too many members, duplicate or overlapped members, or bytes before or
  after the archive. Each member's name must be a safe relative path, and its bytes must match the
  type its extension names. Members come back as bytes in memory; this module writes no file.
- `parsing/dicom/_inflate.py` bounds a deflated DICOM object's inflate before `pydicom` reads it,
  because `pydicom` would otherwise inflate the whole stream with no limit.
- `pipeline/dr_backup.py` reads a disaster-recovery backup, which is a tar archive, on
  `messagefoundry restore` and `restore-verify`. `_extract_member` never uses a member's stored name
  as a path: it streams the store member into one fixed file name. The reader accepts only an
  uncompressed tar, and both a member's declared size and the bytes actually read are capped. With
  `--config-to`, the restore writes the archive's config files under their own relative names. Each
  name must pass the same safe-path check as a zip member, and must resolve inside the destination.
  A member-count cap and a total-size cap apply too. An encrypted backup must decrypt with a store
  key, and every block of it must authenticate, so a tampered one fails before anything is
  extracted. With a store key configured, a plaintext backup is refused; one restores only on a
  machine with no store key.
- `support/bundle.py` only writes a zip, the support bundle. It reads none.

---

## 8. The Windows service scripts change machine security settings

Each script in `scripts/service/` runs from an elevated PowerShell and stops at once without
administrator rights. What each one grants or changes:

| Script | What it grants or changes |
|---|---|
| `install-service.ps1` | Copies NSSM into `C:\Program Files\MessageFoundry\nssm`, or the administrator-only folder `-NssmDir` names. Registers the engine as a Windows service through NSSM, and sets the account it runs as. An account with no password, such as the default virtual account, gets "Log on as a service" through a `secedit` rewrite of local security policy. Rewrites the permissions and owner of the data directory, and grants read on the config directory. |
| `uninstall-service.ps1` | Removes the service. With `-RemoveLogonRight`, rewrites local security policy with `secedit` again, to take "Log on as a service" back. With `-RemoveAccountAces`, removes the account's permission entries from the data and config directories. |
| `install-net-helper.ps1` | Registers `mefor-net-helper` (ADR 0056) as a service running as LocalSystem. It listens on the named pipe `\\.\pipe\mefor-net-helper` and adds or removes one floating IP address by running `netsh`. |
| `uninstall-net-helper.ps1` | Removes the helper service. With `-ReleaseAddress`, first asks the helper to remove the floating address from this machine. |
| `import-db-ca.ps1` | Adds a CA certificate to the machine-wide trust store, `Cert:\LocalMachine\Root`. |
| `measure-store-access.ps1` | A CI measurement, not a deployment step. It installs and uninstalls the service, and deletes the `-DataDir` it is given before it starts. Run it only on a disposable host: with its default `-ServiceName`, it would take over and then remove an engine service installed under that name. It also runs `python` from `PATH` while elevated. It runs NSSM only by full path, from the `-NssmDir` it hands the installer, so it runs the copy the installer checked. The CI job `windows-service-smoke` runs NSSM the same way. |

**The run-as account is the setting to look at hardest.** `install-service.ps1` defaults to a
least-privilege virtual account, `NT SERVICE\<ServiceName>`, with no password. `-AllowLocalSystem`
opts out, and the engine then runs as LocalSystem, the most privileged local account. Section 1
then means that whoever can write the config directory can run code as LocalSystem.
`-ServiceAccount` names any other account, such as a group managed service account.

Other switches on `install-service.ps1` change more than the service:

- `-LockConfigDir` turns off permission inheritance on the config directory and limits it to
  SYSTEM, Administrators and the service account. It also makes Administrators the owner of the
  directory and of everything in it. Without the switch, the script only adds a read grant.
- `-SuppressCrashDumps` writes machine-wide Windows Error Reporting keys under `HKLM`. They are
  keyed by program name. So they affect every process with that name on the machine, not only the
  engine.

**The installers run NSSM only from a folder administrators alone can write, and only a checked
copy.** `install-service.ps1` keeps the service's `nssm.exe` in `-NssmDir`,
`C:\Program Files\MessageFoundry\nssm` by default. It makes any folder it creates there
administrator-only. It then reads the owner and permissions of the file, its folder and each folder
above it, stopping below the drive root. It refuses when anyone else can write to or rename any of
them. It
fills the folder from `-NssmPath`, from `PATH`, or by downloading NSSM. It checks a download against
a fixed SHA-256 hash of the archive. Every copy, from any of those places, must also match a fixed
SHA-256 hash of `nssm.exe` itself before it is copied in. The installer refuses a `-NssmPath` copy
that does not match, and a copy already in the folder that does not match. It skips a `PATH` copy
that does not match, and downloads instead. Each message names both hashes. It then points the
service's registration at that copy, quoted, and reads it back. On a reinstall that replaces
whatever `nssm.exe` an earlier registration named. If it cannot, it disables the service.

The copy used to be cached in the data directory, where the engine's service account can modify
files. From there, code running as the engine could have replaced it, planted a library beside it,
or redirected the folder, and the next install would have run the result as administrator. A hash
check alone would have caught only the first of those three.

**The uninstall scripts run no NSSM at all.** Windows stops the service, and `sc.exe` removes it.

`install-net-helper.ps1` downloads nothing. It copies `mefor-net-helper.exe` from `-HelperSource`,
and `nssm.exe` from `-NssmPath` or `PATH`, into the helper's folder. `nssm.exe` must match the same
fixed hash. `mefor-net-helper.exe` must match `-HelperSha256`, a hash the operator has to pass.
This repository pins none for it, because each release builds the helper again. The script checks
each file before the copy. It checks the installed copies again, and deletes both if either fails,
or disables the service when it cannot delete them. It points the registration at the checked
`nssm.exe`, quoted, and reads it back. It prints the helper's signature status without requiring
one. It then starts the helper as LocalSystem.

**At least these gaps remain.** The hash check covers only the `nssm.exe` the two installers run
and register. Nothing checks an `nssm.exe` an administrator runs by hand, such as one on `PATH`.
`Start-Service` and `Restart-Service` need no NSSM. To run
NSSM by hand, use the checked copy in `-NssmDir`, or in the helper's folder, by its full path. That
copy was checked when it was installed, and it stays safe only while its folder is
administrator-only. `-HelperSha256` is only as good as the channel the operator took it from. With
`-AllowBroadAcl`, whoever can write the helper's folder can swap a binary, plant a library beside
it, or edit its configuration file, both between runs and during one.

It also runs the engine's `messagefoundry.exe`, from the repository's `.venv` unless `-AppExe`
names another, to read the address settings. It checks no hash on that program, and it runs it
elevated. So a planted `messagefoundry.exe` on that path would run as administrator.

**What holds the helper.** It refuses any request that names a different address, interface or
mask from the ones in its configuration file. It hands Windows only the values from that file. Its
pipe refuses network callers. Besides administrators, it admits only the engine service's own
account, or the account named with `-ClientAccount`. The installer refuses an install folder that
another account can write to or owns. It also refuses one whose permissions it cannot read. Whoever
can write there could replace a program that runs as LocalSystem. `-AllowBroadAcl` overrides that
refusal. The helper runs `netsh` from the system directory, never from `PATH`. Nothing in the
engine calls the helper yet.

**What holds the certificate import.** Every program on the machine trusts the machine store, not
only the engine. So a CA added there can vouch for any server. The script shows the certificate's
subject and thumbprint before it imports, and supports `-WhatIf`. It also accepts a `.p7b` bundle,
which it shows as one certificate but imports whole. So check every certificate in a bundle first.
SQL Server's ODBC Driver 18 reads only the machine store, so a SQL Server behind a private CA needs
this step. PostgreSQL can instead pin a CA file with `[store].ssl_root_cert`, which changes nothing
machine-wide.

The uninstall scripts leave most changes in place by default, and print a list of what is left
with the command that clears each item. "Log on as a service" stays by default because a shared
account may need it for other services.

---

## 9. The VS Code extension starts processes and runs webview scripts

The extension in `ide/` runs in VS Code with your own rights. These counts are over `ide/src`,
leaving out its `test` folder:

| Surface | Call | Sites | Files |
|---|---|---|---|
| Process starts | `execFile` | 5 | 3 |
| Terminals | `createTerminal` | 4 | 2 |
| Text typed into a terminal | `sendText` | 2 | 2 |
| Debug sessions | `startDebugging` | 1 | 1 |
| Links opened outside VS Code | `openExternal` | 3 | 3 |
| Webviews that run scripts | `enableScripts: true` | 14 | 13 |

**Process starts.** Node's `execFile` runs one program with an argument list and no shell.
`cli.ts` runs the MessageFoundry command line through a Python interpreter. It does so on its own,
not only when you ask. In a trusted workspace it runs `validate` and the graph and code-set reads
when the extension starts. It runs them again after you save a Python file or the config changes. Each of
those loads your config modules, so their top-level code runs each time (section 2).

Before it starts the engine, `statusBar.ts` runs that interpreter to check it, and to ask whether
an administrator account exists. What holds them: in a workspace you have not marked as trusted,
`cli.ts` refuses to run any interpreter. The extension never picks up a workspace `.venv` there,
and the engine start refuses there too. The interpreter setting, `messagefoundry.pythonPath`, is machine-scoped.
So a settings file checked into a repository cannot set it.

`git.ts` runs `git` for the source-control commands, and those do not check workspace trust. It
uses the path VS Code's own Git extension resolved. When that gives none, it runs `git` by bare
name with the workspace folder as its working folder. On Windows, that search may find a `git.exe`
in the workspace folder before the one on `PATH`, as section 4 says of `checks.py`.

**Terminals.** Two terminals run one program as the terminal's own process, with no shell reading
a command line: the engine's `serve`, and `provision-admin`. The other two type text into a shell:

- **MessageFoundry Setup** types each step of a generated setup plan with `sendText`, and runs it.
  It needs a trusted workspace and a yes in a dialog that lists every step first.
- **Install Git** types `winget install --id Git.Git -e` and does not press Enter. You run it
  yourself or close the terminal.

**Debug sessions.** The test bench's debug action starts a Python debug session. It runs
`messagefoundry dryrun` with `--show-phi` on one sample message, in a VS Code terminal. The config
folder it passes comes from the `messagefoundry.configDir` setting.

**Links.** `openExternal` hands a URL to the operating system, which opens it with whatever program
is registered for its scheme. The extension opens web console pages and the Git download page this
way. What holds it: the console links come from the engine URL setting. Each must pass a check that
allows only a web address before it reaches the operating system.

**Webviews.** Each script-enabled page carries a Content Security Policy with `default-src 'none'`
and a fresh nonce on `script-src`. So only the scripts the extension rendered into that page run.
`configEditors.ts` reuses the connection and code-set pages rather than building its own. Some page
scripts build markup with `innerHTML`, at least in `testBenchWebview.ts`. The policy blocks inline event
handlers, so markup injected that way cannot run script of its own.

A page script can also ask the extension to act. The Home view runs any VS Code command whose id
its page sends, with no list of allowed ids. The engine setup page, by contrast, runs only the
command behind a button it knows. So the Home view's policy is the only thing between its page and
every command VS Code has, including other extensions' commands.

**The extension also writes files that run later.** One is the new-route module in section 2.
Another is the git `pre-commit` hook that source-control setup writes to `.mefor-hooks/pre-commit`
and stages for commit. Setup then points git's `core.hooksPath` there, so git runs the hook on
every commit. It skips that step when git already has another hooks folder, or a `pre-commit` hook
in `.git/hooks`. Otherwise the new setting turns off every other hook in `.git/hooks`, such as a
`pre-push` or `commit-msg` hook, without a warning. In a linked worktree, where `.git` is a file,
the `pre-commit` check finds nothing, so even that hook can be turned off.

The hook runs `messagefoundry check`, which loads and dry-runs your config modules. So your config
code runs on every commit, and no workspace-trust check applies then. The hook prefers the
workspace's own `.venv` interpreter when one exists. So a repository that ships a `.venv`, or a
pulled change to the hook or the config, runs its own code on your next commit. The hook names
your config and message folders, which a checked-in `.vscode/settings.json` can set. Each is
single-quoted for the shell, so a crafted value cannot break out of its argument.

---

## 10. The web console writes server-built HTML into the page

The web console is a browser page the engine serves at `/ui`. Across its scripts, it writes HTML
into the page in 3 places, all through `innerHTML` in `messagefoundry_webconsole/static/app.js`:

- the live connections table, polled on an interval;
- the same table, pushed over a WebSocket;
- the fragment poller behind the Flow & trends page.

At each, the script writes an HTML fragment the engine built, as it arrived from the console's own
origin. It adds no markup of its own.

**What holds it.** The server builds its pages and fragments with
`messagefoundry_webconsole/_html.py`, which escapes every value unless the code wraps it in
`Markup` on purpose. So a message field is escaped unless some code chose to mark it safe. The
`/ui` Content Security Policy has no `unsafe-inline` or `unsafe-eval`. It comes in two forms. The
stricter one runs only scripts that carry that response's nonce, and scripts those load. The other
runs only scripts from the console's own origin. Under either, an event handler in injected markup
would not run.

The console's own Python starts no process, calls no native library, reads no archive and imports
nothing by name. It can ask the engine to reload its configuration, though. That runs section 2's
loader in the engine, which executes every config module again.

---

## What is deliberately not here

**Your Routers and Handlers.** The engine cannot know what they do. If yours shell out, call a
native library, or import by name, that is dangerous functionality in your deployment and belongs
in your own documentation.

**Third-party components.** [`RISKY-COMPONENTS.md`](RISKY-COMPONENTS.md) designates the risky ones.
Per-library decisions that matter to a deploying operator are recorded in the ADRs cited above.

**The published test harness.** `messagefoundry-harness` is a tool for testing an engine, and it
does start processes. It ships at the engine's version, as the toolkit does. But none of its commands
is a row in `CLI_TIERS`, it holds none of the code ADR 0201 moves out of the engine wheel, and it
does not run inside the engine. The extension's reason, shipping to the same operators, would reach it. So
leaving it out is a choice about this page, not a claim that it holds none of these classes.

## Keeping this page true

When you add a site in any class above, add it here in the same change. A highlight that has
quietly gone stale is worse than none, because a reader takes its silence for absence.

A test checks the lists and counts in six sections. `tests/test_dangerous_functionality_doc.py`
reads the code and fails when one of these no longer matches it:

- the section 4 table: a new process start, or a start that changes form, such as a new
  `shell=True`;
- the section 5 module list: a new `ctypes` import, and every library load must name its library
  with a literal;
- the section 7 parser tables: a parse site the six patterns find that the first two tables omit,
  a site in both, or a name there the scan does not find. A hand-read parser must exist, and the
  scan must not find it. The six patterns the page states must be the ones the test uses. The
  extension's three tables are held to its four patterns the same way;
- the section 7 archive list: a new module that imports an archive or compression library;
- the section 8 table: a script added to or removed from `scripts/service/`, or one with no
  administrator check;
- the section 9 table: each count in it. It also fails on any `child_process` call other than
  `execFile`, any VS Code task, and any use of `cluster`, `worker_threads` or `process.dlopen`, and
  when a file its `innerHTML` sentence names is missing or writes no HTML into its page;
- section 10: the count of HTML writes. It also checks that the console's Python starts no
  process, imports no `ctypes` or archive library, and imports nothing by name.

The checks read TypeScript and JavaScript by pattern, so a call named in a trailing comment counts.
Some things no test checks. They include what a script grants, what holds a site, and sections 1,
2, 3 and 6. In section 7, no test checks which table a parse site belongs in, or whether either
hand-read table is complete. Keep that prose true by hand.
