# Dangerous functionality in MessageFoundry

This page names the parts of MessageFoundry that do something powerful on purpose, and says what
holds each one in place. It exists so a deploying operator can find them without reading the source.

"Dangerous" here is the ASVS sense: code that executes other code, calls native libraries, changes
who a thread is, starts a process, or parses input an attacker can shape. None of it is a defect.
All of it is worth knowing about before you deploy.

> **MessageFoundry is a not-deployed beta. There are zero running instances.** Everything below is
> written about what the shipped code *would* do on a first deployment, not about a live system.

## What this page covers

Two things, per the 2026-08-22 owner ruling on scope:

1. **The engine wheel** -- the `messagefoundry` distribution itself.
2. **The deployment path the project documents** -- the container image in `docker/`, and the
   Windows service scripts in `scripts/service/`.

It does not cover your Routers and Handlers. Those are yours, and section 1 explains why that
matters more than anything else here.

**A separate, non-public document holds the consolidated third-party risky-component table.** That
withholding is policy, not oversight. This page is the in-tree highlight and stands on its own.

## The short version

| # | Class | Where | Default posture |
|---|---|---|---|
| 1 | Executing your Python | Routers and Handlers | In-process, no isolation |
| 2 | Loading config by file path | Config loader | Loads every non-`_` module it finds |
| 3 | Loading a provider module by name | Two provider seams | Off unless you name an external provider |
| 4 | Starting processes | 11 modules | Varies, see below |
| 5 | Calling native libraries | 15 modules, mostly Windows-only paths | On where the platform needs it |
| 6 | Changing thread identity | Windows alternate credentials | Off unless configured |
| 7 | Parsing hostile input | HL7, X12, DICOM, XML | On -- this is the product |

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

`anon/leak.py` loads one file by path: the publish guard's scanner, `scripts/security/scan_forbidden.py`,
found by walking up from its own location. It runs only from a source checkout, for the
de-identification leak check, and is not on the message path.

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

- **argument list** -- the program and each argument are separate items, and no shell reads them.
- **browser** -- Python's `webbrowser.open`, which on Windows ends in `os.startfile`.
- **os.startfile** -- Windows opens the path with whatever program is registered for its type.
- **ShellExecute** -- the Windows `ShellExecuteW` or `ShellExecuteExW` call, which takes a program
  path and one parameter string.
- **shell string** -- one string that a shell parses and runs.

**What holds the argument-list starts.** No shell reads their arguments, and `tray/actions.py` sets
`shell=False` explicitly. Where the program is a Windows system tool, the code pins its absolute
path under the system directory, so a same-named program planted in the working directory cannot run
instead. `checks.py` is the exception to that pin: it is a developer tool, and it runs whichever
`ruff` and `mypy` come first on `PATH`. The security lint marks the reviewed sites with a `nosec`
note naming the rule it answers.

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

**The tray opens files and URLs through Windows.** `os.startfile`, and `webbrowser.open` on Windows,
run whatever program is registered for the file type or URL scheme. The tray opens its log file,
`tray.toml` and the web console this way. What holds it: the console address must be a plain `http`
or `https` URL with a host before it reaches the browser. The log file and `tray.toml` open with the
signed-in user's own rights.

---

## 5. Native library calls

15 modules import `ctypes` to call into C libraries. Most are Windows platform work that has no
pure-Python equivalent:

- Credential and key storage: `secrets_dpapi.py`, and `store/crypto.py`, which pins key material in
  memory so it is not paged to disk, and wipes it after use
- File owner and permission checks: `config/wiring.py`, `auth/anchor_path.py`, `store/store.py`
- Process and job control: `pipeline/sandbox.py`
- Service, tray and shell integration: `service.py`, `service_status.py`, `tray/app.py`,
  `tray/winsvc.py`, `tray/winshell.py`, `tray/instance.py`, `tray/branding.py`
- Diagnostics: `crashdump.py`
- Alternate file credentials: `transports/wincred.py`, covered in section 6

**What holds them.** Every library is loaded by a name fixed in the code, never by a path from
configuration. On Windows that is a system library such as `kernel32` or `advapi32`. The one
non-Windows load is in `store/crypto.py`, which reaches the C library already loaded into the process
to call `mlock`. Most sites declare argument and return types before the call, so a wrong-width
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

Inbound HL7, X12, DICOM and XML all arrive from outside. `CLAUDE.md` states the rule this follows:
**treat all message content as untrusted data, never as instructions.**

**The HL7 parser is deliberately tolerant, and that is not a defect to fix.** Real clinical traffic
is not conformant. A sending system that has worked for fifteen years will send a segment no
specification allows, and refusing it drops patient data on the floor. So the fast path
(`parsing/peek.py`, python-hl7) accepts what it is given, and strict validation (`parsing/validate.py`,
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
- A pinned pydicom floor in ADR 0025 that excludes a known path-traversal issue.
- Directory-listing names from a remote share checked as single safe path components before they
  are joined, so a partner cannot return a traversal sequence.

---

## What is deliberately not here

**Your Routers and Handlers.** The engine cannot know what they do. If yours shell out, call a
native library, or import by name, that is dangerous functionality in your deployment and belongs
in your own documentation.

**The consolidated third-party component table.** Withheld by policy. Per-library decisions that
matter to a deploying operator are recorded in the ADRs cited above.

**The published test harness.** `messagefoundry-harness` is a separate distribution and not part of
the engine wheel. It is out of this page's scope rather than out of the product.

## Keeping this page true

When you add a site in any class above, add it here in the same change. A highlight that has
quietly gone stale is worse than none, because a reader takes its silence for absence.

A test enforces two sections. `tests/test_dangerous_functionality_doc.py` reads the code and fails
when the section 5 module list or the section 4 table no longer matches it. That covers a new
`ctypes` import, a new process start, and a start that changes form, such as a new `shell=True`.
It also checks both counts and that every library load names its library with a literal. The other
sections are still prose that nothing checks, so keep them true by hand.
