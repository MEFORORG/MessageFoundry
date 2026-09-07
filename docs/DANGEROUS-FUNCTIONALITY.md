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
| 3 | Loading a plug-in by name | Three provider seams | Off unless you name a class |
| 4 | Starting processes | Sandbox, shards, service control, tray | Varies, see below |
| 5 | Calling native libraries | 14 modules, Windows-only paths | On where the platform needs it |
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

## 3. Three seams load a class you name

Each of these takes a dotted module path from configuration and imports it:

| Seam | File | What it loads |
|---|---|---|
| Directory auth proxy | `auth/ldap.py` | An LDAP connection proxy |
| Secret provider | `config/secretprovider.py` | A secret backend |
| Key provider | `store/keyprovider.py` | A store encryption key backend |

**What holds them.** Each is off unless you configure a class, and the name comes from your own
service configuration rather than from a message. A fourth site, `verify/checks.py`, imports the
ODBC driver by a hard-coded literal name and takes no input at all.

`anon/leak.py` also loads by path, in the de-identification self-test. It is not on the message
path.

---

## 4. The engine starts processes

Eight places, and the reason differs at each:

| What | File | When |
|---|---|---|
| Sandbox worker | `pipeline/sandbox.py` | Only when `[sandbox].mode = "subprocess"` |
| Shard children | `pipeline/supervisor.py` | Only under `messagefoundry supervise` |
| Windows service control | `service.py`, `service_status.py` | Service install, start, stop, status |
| Tray actions | `tray/actions.py`, `tray/branding.py` | The Windows tray manager |
| Disaster-recovery hook | `pipeline/dr.py` | A backup or restore run |
| Trust-anchor import | `auth/trust_anchors.py` | Importing a CA certificate |
| Store maintenance | `store/store.py` | A maintenance operation |
| Commit fingerprint | `config/fingerprint.py` | Reading the git commit, best-effort |

**What holds most of them.** They pass an argument list rather than a shell string -- `tray/actions.py`
sets `shell=False` explicitly. The security lint marks the reviewed ones with a `nosec` note naming
the rule it answers.

**The disaster-recovery hook is the exception, and it is the one to look at hardest.**
`pipeline/dr.py` calls `asyncio.create_subprocess_shell`, so the operator's command runs through a
shell exactly as written. Its own docstring says why: the command comes from `[dr]` in the service
configuration, never from a message, so it is trusted the same way the backup destination path is.
That reasoning holds only while that configuration file is as well protected as the config directory
in section 1. On a first deployment, whoever can edit it can run a shell command as the engine.

---

## 5. Native library calls

Fourteen modules call into C libraries through `ctypes`. Most are Windows platform work that has no
pure-Python equivalent:

- **Credential and key storage** -- `secrets_dpapi.py`, `store/crypto.py`, `auth/passwords.py`
- **Process and job control** -- `pipeline/sandbox.py`, `config/wiring.py`
- **Service, tray and shell integration** -- `service.py`, `tray/app.py`, `tray/winsvc.py`,
  `tray/winshell.py`, `tray/instance.py`, `tray/branding.py`
- **Diagnostics** -- `crashdump.py`, `checks.py`
- **Alternate file credentials** -- `transports/wincred.py`, covered in section 6

**What holds them.** Argument and return types are declared before each call, so a wrong-width
argument fails at the boundary rather than corrupting the stack. Every one targets a Windows system
library by name, never a path from configuration.

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

This is documentation, so nothing enforces it. When you add a site in any class above, add it here
in the same change. A highlight that has quietly gone stale is worse than none, because a reader
takes its silence for absence.
