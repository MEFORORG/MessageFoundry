# Risky third-party components

This page designates which of the engine's third-party dependencies are **risky components**, says
what "risky" means here, and names the ones that were assessed and deliberately not designated.

It exists so a deploying operator knows where to look first when a dependency advisory lands, without
reading the source or guessing from a package name. A later section reads every component on the
examples of a risky component that ASVS, the Application Security Verification Standard, gives. It
uses dated public data.

> **MessageFoundry is a not-deployed beta. There are zero running instances.** Nothing below reports
> a live exposure. It describes what a first deployment would carry.

## Scope, and the denominator

The set assessed is the **core runtime closure**: every distribution a default engine install
carries, transitive dependencies included, with no optional extras and no development toolchain.
That is **34 distributions**, recorded in
[`security/runtime-closure-core.txt`](../security/runtime-closure-core.txt).

**Which denominator you pick changes the answer by about half, so it is stated rather than implied:**

| Denominator | Count | Why not this one |
|---|---|---|
| Names in `pyproject.toml`, core only | 19 | Misses everything transitive, which is a large share of what runs. |
| Names in `pyproject.toml`, core plus every extra | 45 | Still direct-only, and mixes in extras nobody enabled. |
| **Core runtime closure** | **34** | **Used for the tiers below.** What a default install actually executes. |
| **`sqlserver` runtime closure** | **36** | **Used for the `sqlserver` section only.** The core closure plus what that extra adds. |
| **`harness` runtime closure** | **38** | **Used for the `harness` section only.** The core closure plus what that extra adds. |
| `requirements.lock` | A superset | Exported with `--all-extras`, so it carries the dev toolchain. Designating packages no production install has weakens the signal for the ones it does. |

Two extras are assessed as well. The `sqlserver` runtime closure is **36 distributions**, recorded in
[`security/runtime-closure-sqlserver.txt`](../security/runtime-closure-sqlserver.txt). It has its
own section below, which classifies only the names the extra adds to the core closure.

It is assessed because the SQL Server store is the deployment the project's security assessment
names. This page chose its own scope; covering the extra here does not decide what that assessment
grades.

The `harness` runtime closure is **38 distributions**, recorded in
[`security/runtime-closure-harness.txt`](../security/runtime-closure-harness.txt). Installing the
harness wheel brings in these names, because the wheel's only dependency is
`messagefoundry[harness]`. The versions are the lock's; an install resolved from an index can take
newer ones, and a few names apply to one platform only. It has its own section below, which
classifies only the names the extra adds to the core closure.

It is assessed because the project's security assessment brought the harness wheel into its scope,
by owner ruling R1 of 2026-10-02, which
[`ASVS-ASSESSMENT-METHOD.md`](ASVS-ASSESSMENT-METHOD.md) section 2 records. The harness also imports
at least `paramiko`, `pydicom`, `pynetdicom`, `openpyxl`, `pyodbc` and `asyncpg` when a feature needs
one. The harness wheel declares none of them, so they are not in its closure and not assessed here
for it. `pyodbc` is assessed in the `sqlserver` section, for the engine.

An install that enables any other extra (`postgres`, `sftp`, `dicom`, `fhir`, `xml`, `x12`,
`webauthn`, `otel`, `vault`) carries dependencies **outside** all three sets. Those are not assessed
here, and that is a gap rather than an assertion of safety.

## The criterion

A distribution is designated risky if it meets **at least one** of these. The tier is the reason it
was designated, not a severity ranking.

1. **Hostile input.** It parses or deserializes data chosen by a party the engine does not control.
2. **Secrets and trust.** It performs cryptography, handles credentials, or decides what is trusted.
3. **Protocol termination.** It speaks a network protocol the engine exposes or dials.

Native compiled code is treated as an aggravating factor within a tier, not a tier of its own: a
memory-safety fault in a compiled parser is not the same class of event as a logic bug in a pure
Python one, and the tables below say which components carry it.

**Twenty-three of thirty-four are designated, and the proportion is the finding.** This is an
integration engine: its job is parsing clinical traffic from partners it does not control and
terminating network protocols. Most of its runtime closure is therefore in one of those two paths by
construction. A short list here would be a less honest document, not a safer engine.

## Tier 1 — hostile input

These see bytes chosen by a sending system. Everything in
[`DANGEROUS-FUNCTIONALITY.md`](DANGEROUS-FUNCTIONALITY.md) section 7 about deliberate parser
tolerance applies to the engine's own tolerant HL7 parser (ADR 0054), which is engine code and
not a component. `hl7apy` reads the same input. The tolerant parser was the `hl7` component
(python-hl7) until it was retired.

| Component | Why | Native |
|---|---|---|
| `hl7apy` | strict HL7 validation, opt-in per connection, on inbound HL7 | no |
| `pydantic` | validates untrusted request and config input | no |
| `pydantic-core` | the engine underneath it, compiled | **yes** |

The engine's XML hardening is not in this table, and that is not because it left the path. defusedxml
0.7.1 is vendored into [`messagefoundry/_vendor/defusedxml/`](../messagefoundry/_vendor/defusedxml/README.md)
rather than installed, so it is engine code and not a distribution in the closure. It still meets tier
1: it parses hostile XML, and the refusal it applies is the hardening. The README beside it records its
source, its hash and what changed.

Read it as designated, tier 1. The ASVS reading further down covers distributions only, so its counts
no longer include this copy. On that reading's maintenance test it would still be risky: upstream's
newest upload was 2023-09-29.

What the dependency audit and the SBOM can and cannot see of it is stated once, in
[`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md#the-one-vendored-python-source-which-does-ship).

## Tier 2 — secrets and trust

| Component | Why | Native |
|---|---|---|
| `cryptography` | store encryption, TLS material, signing | **yes** |
| `argon2-cffi` | password hashing | no |
| `argon2-cffi-bindings` | the compiled Argon2 binding | **yes** |
| `cffi` | the binding layer under both of the above | **yes** |
| `pycparser` | parses C declarations for `cffi` | no |
| `ldap3` | directory authentication, credentials on the wire | no |
| `pyasn1` | ASN.1 decoding beneath `ldap3` | no |
| `pyspnego` | SPNEGO and Kerberos negotiation | no |
| `sspilib` | Windows SSPI credential handling | **yes** |
| `certifi` | the CA bundle; it decides what is trusted | no |
| `truststore` | reads the operating system trust store | no |

## Tier 3 — protocol termination

| Component | Why | Native |
|---|---|---|
| `fastapi` | the engine's HTTP application surface | no |
| `starlette` | routing, requests, responses beneath it | no |
| `uvicorn` | the HTTP server that binds the socket | no |
| `h11` | HTTP/1.1 message parsing | no |
| `httptools` | compiled HTTP parsing | **yes** |
| `websockets` | the WebSocket protocol for the console | no |
| `httpx` | outbound HTTP for every egress connector | no |
| `httpcore` | connection and TLS handling beneath it | no |
| `idna` | decodes domain names from untrusted sources | no |

## Assessed and NOT designated

Naming these is the point. A designation list on its own says nothing about whether the rest was
looked at.

| Component | Why not |
|---|---|
| `aiosqlite` | an async wrapper over the standard library's `sqlite3`; it adds no parser and no protocol |
| `anyio` | async primitives, no input handling |
| `uvloop` | a compiled event loop; it moves bytes but parses none |
| `psutil` | compiled process and resource inspection, local only |
| `click` | command-line parsing, operator input on the local shell |
| `tomlkit` | parses operator-authored TOML from the config directory, which is inside the trust boundary |
| `annotated-doc`, `annotated-types`, `typing-extensions`, `typing-inspection` | typing shims, no runtime input handling |
| `tzdata` | timezone tables |

That is 11, and 23 plus 11 is 34. The arithmetic is stated so a reader can check the set is closed
rather than trusting that it is.

## The `sqlserver` extra

The SQL Server store backend and the `DATABASE` connector reach their database through `pyodbc`,
mostly by way of `aioodbc`. Those are the only names the extra adds to the core closure. The same
criterion applies, and the wire protocol itself belongs to the ODBC driver, assessed after the
tables.

### Designated

| Component | Tier | Why | Native |
|---|---|---|---|
| `pyodbc` | 1 and 2 | the compiled binding every database call through this extra goes through. It turns message values into statement parameters and decodes every row, including rows from a partner's database. It also hands the connection string, credential included, to the driver | **yes** |
| `aioodbc` | 2 | an async wrapper that runs `pyodbc` calls on a thread pool. It parses nothing, unlike `pyodbc`, but it holds the connection string, credential included, for the pool's lifetime | no |

### Assessed and NOT designated

None. Both names the extra adds are designated.

So 2 plus 0 is 2, and 34 plus 2 is 36.

### The ODBC driver is designated too, and the guard cannot see it

The extra also needs the Microsoft ODBC Driver 18 for SQL Server. It is an operating-system package
with no pip name, so no lock carries it and it is in neither count above. It meets all three tiers:

1. It parses every response the database server sends.
2. It performs the TLS handshake and applies the `Encrypt` and `TrustServerCertificate` settings,
   which decide what is trusted. It also carries the database credential.
3. It speaks the SQL Server wire protocol to every server the engine dials.

It is compiled code. Its version is whatever the host has installed, so an advisory against it
reaches an operator through Microsoft and the operating system's package manager, not through
`pip-audit`. The test described under *Keeping it true* does not cover it.

The `DATABASE` connector's `generic` dialect can instead load any ODBC driver the operator has
installed, such as one for PostgreSQL or Oracle. Those drivers are chosen per site and are not
assessed here.

### A pyodbc crash report that the driver turned out to cause

`pyproject.toml` records an upstream crash report against `pyodbc` 5.3.0, the version the lock
installed when this was written: `mkleehammer/pyodbc#1459`. Read on 2026-09-28, that issue is
closed as completed, on 2026-06-04. The maintainer's closing comment puts the root cause in a
regression in an 18.6 release of ODBC Driver 18, not in `pyodbc`. It says Microsoft fixed it in
18.6.0002.

So the defect to track is the driver's, which is one more reason to keep the driver current.
`pyodbc` 5.3.0 was still its newest release on that date.

## The `harness` extra

The test harness is a desktop tool, shipped as its own wheel, that sends test traffic to the engine,
receives what the engine delivers, and monitors the engine through its API. Its window is Qt, through
PySide6, and the `harness` extra is that dependency. These four names are what the extra adds to the
core closure. The same criterion applies.

On the reading of 2026-10-03, the harness imports four Qt modules: `QtCore`, `QtGui`, `QtNetwork` and
`QtWidgets`. All four ship in `pyside6-essentials`. That split decides the tables below.

### Designated

| Component | Tier | Why | Native |
|---|---|---|---|
| `pyside6-essentials` | 1, 2 and 3 | Qt itself, for the modules the harness uses. Its `QTcpServer` is the harness's MLLP receiver: it accepts the connection an engine outbound connection dials, and reads every byte that arrives. Its text engine then lays out and draws what arrives: the fields of each received message in a table, and the whole message once it is selected. It draws the messages the monitor fetches from the engine API the same way. Its sign-in dialog holds the engine password and authenticator code the operator types | **yes** |
| `shiboken6` | 1, 2 and 3 | the compiled binding runtime under PySide6. Every Qt call the harness makes goes through it, including the bytes the listener reads, the strings the widgets draw and the password the sign-in dialog returns. It plays the part `cffi` plays in tier 2 | **yes** |

### Assessed and NOT designated

| Component | Why not |
|---|---|
| `pyside6` | a metadistribution: the `PySide6` package initialiser, typing stubs and tool launchers. It ships no compiled module and parses no input. It exists to pull in the other three |
| `pyside6-addons` | compiled, but it holds only Qt modules the harness never imports, among them the web engine, multimedia, PDF, serial port and HTTP server modules. None of them runs, so none sees input. A harness change that imports one needs this row read again |

So 2 plus 2 is 4, and 34 plus 4 is 38.

### Why the listener meets tiers 1 and 3

The listener binds the loopback address only, so a peer has to be on the same host. The harness is
meant for synthetic traffic, too. Neither fact takes it out of the criterion:

1. **Hostile input.** The bytes it reads were chosen by whatever connected. In the harness's own use,
   that is an engine delivering a message that a sending system chose. Nothing in Qt or the listener
   checks that the traffic is synthetic, and any process on the host can connect.
2. **Protocol termination.** It terminates the TCP connection that an engine outbound connection
   dials. MLLP framing and the ACK are engine code, `messagefoundry.mllpcodec`, so the protocol Qt
   speaks is TCP itself.

Tier 2 comes from the sign-in dialog, not from the network. The harness signs in to the engine
through Qt input fields, so the password and the authenticator code pass through Qt and `shiboken6`
before `httpx` sends them. That is the same ground `aioodbc` is designated on: it holds a credential.
`pyside6-essentials` also ships Qt's TLS backends, but the harness opens no TLS connection through
Qt. Its HTTPS client for the engine API is `httpx`, already in the core closure, so Qt decides
nothing about trust.

All of Qt is compiled C++, so a fault in its socket or text handling is a memory-safety event in the
harness's process, not a Python exception.

### What the ASVS reading shows for these names, and what it cannot show

The generated reading further down reads these names with every other component on this page, on
all three of ASVS's examples. Its last table is *The names the assessed extras add*, and it has a
row for each of these names.

The results are stated there and not copied here, so a later re-read cannot leave this section
behind.

**A 0 in that table's advisory column is about a PyPI name, not about Qt.** That reading matches an
advisory to a component by its PyPI name, and says so with its tests. For these wheels, a 0 means it
counted no advisory naming the `pyside6`, `pyside6-addons`, `pyside6-essentials` or `shiboken6` PyPI
packages. It does not mean the Qt code inside those wheels has no known flaws.

A flaw filed against Qt itself, and not against one of those PyPI names, does not show up in that
reading. So the vulnerability-history example is read for the names of the wheels and not for the Qt
they carry. A name in that reading's *Not risky on any of the three* table is under the same limit.

That is a limit of the instrument, and this page does not close it. A reader who needs the Qt side
has to check Qt's own security notices against the Qt version the pinned wheels carry.

The pins to check are the ones in
[`security/runtime-closure-harness.txt`](../security/runtime-closure-harness.txt). The table's
pinned column is the pin on the snapshot date, and a later lock bump does not move it.

## Risky by ASVS's own examples, read from public data

The tiers above ask where a flaw would hurt most. ASVS asks something else. Its V15.1 chapter calls
a third-party library a risky component when it has "missing or poorly implemented security
controls around its development processes or functionality". Its examples are components that are
"poorly maintained, unsupported, at the end-of-life stage, or have a history of significant
vulnerabilities". This section reads every component on those examples.

<!-- BEGIN component-readings: rendered by scripts/security/component_readings.py from security/risky-component-readings.json. Do not edit by hand. -->

> **Snapshot date: 2026-10-04. Re-read by: 2027-01-02.** Every reading below comes from public data
> on the snapshot date: PyPI, the Python Package Index, and OSV, the Open Source Vulnerabilities
> database. It covers the versions the closure files pinned that day. Support status and advisory
> history go stale. After the re-read date, treat this section as out of date until
> [`scripts/security/component_readings.py`](../scripts/security/component_readings.py) runs again.

The readings, their sources and their windows are recorded in
[`security/risky-component-readings.json`](../security/risky-component-readings.json).

### What is read, and the test for each example

All 40 distributions this page assesses are read: the 34 in the core closure and the 6 that the
assessed extras add to it. The `sqlserver` extra adds 2: `aioodbc` and `pyodbc`. The `harness` extra
adds 4: `pyside6`, `pyside6-addons`, `pyside6-essentials` and `shiboken6`. That is not only the
designated part. A library can be risky on these examples even where the tiers did not designate it.

| Example | A component is risky on it when | Source |
|---|---|---|
| Poorly maintained | it has uploaded no release to PyPI in the 730 days before the snapshot. A pre-release counts; a release whose every file is yanked does not | PyPI JSON API |
| Unsupported or end of life | its PyPI project status, the marker Python standard PEP 792 defines, is `archived`, `deprecated` or `quarantined`, or its latest release is classified `Development Status :: 7 - Inactive`, or the pinned version is yanked or no longer listed | PyPI JSON and Simple APIs |
| A history of significant vulnerabilities | at least one advisory rated `HIGH` or `CRITICAL` was first published in the 1825 days (about 5 years) before the snapshot | OSV API |

OSV often records one flaw twice, once from the GitHub advisory database and once from the Python
advisory database. Records that name each other count once. A record does not count when every
GitHub advisory it names about that package has been withdrawn.

The severity is the GitHub advisory database's rating. Where it gives none, the script scores the
record's CVSS 3 vector and rates it on that system's scale. CVSS is the Common Vulnerability Scoring
System. An advisory with neither does not count. The ones in the window are named below so a reader
can judge them.

OSV matches an advisory to a component by its PyPI name. A flaw in code a wheel carries inside it,
such as a compiled library, shows up here only when an advisory names the PyPI package. So nothing
below shows that the code inside a wheel is free of known flaws.

These tests are mechanical. A small library that is finished can trip the first one without being
neglected. The reading says where to look; it does not say the library is broken.

**Risky on at least one example: 10 of 40. On maintenance: 2. On support: 0. On vulnerability
history: 8. Not risky on any: 30. 10 plus 30 is 40.**

### Poorly maintained

| Component | Newest release | Designated above |
|---|---|---|
| `aioodbc` | 2023-10-28 | yes, the `sqlserver` extra |
| `hl7apy` | 2024-03-13 | yes, tier 1 |

### Unsupported or end of life

None on the snapshot date.

### A history of significant vulnerabilities

| Component | Significant in the window | Newest of those | Designated above |
|---|---|---|---|
| `anyio` | 2 | 2026-09-18 | no |
| `certifi` | 1 | 2023-07-25 | yes, tier 2 |
| `click` | 1 | 2026-04-30 | no |
| `cryptography` | 8 | 2026-08-03 | yes, tier 2 |
| `h11` | 1 | 2025-04-24 | yes, tier 3 |
| `httpx` | 1 | 2022-04-28 | yes, tier 3 |
| `pyasn1` | 5 | 2026-07-14 | yes, tier 2 |
| `starlette` | 5 | 2026-06-15 | yes, tier 3 |

On the snapshot date OSV listed no advisory against any pinned version, in any of the 40. The table
above counts past advisories only.

Every advisory in the window carries a rating from one of the two sources.

1 record was left out because every GitHub advisory about the package it names is withdrawn:
`PYSEC-2024-38` against `fastapi`, twin of `GHSA-qf9m-vfgh-m389`.

1 record names a GitHub advisory that OSV does not have, so its status is unknown. It still counts:
`PYSEC-2026-2132` against `click`, naming `GHSA-47fr-3ffg-hgmw`.

### Not risky on any of the three

| Components | Designated above |
|---|---|
| `argon2-cffi`, `argon2-cffi-bindings`, `cffi`, `fastapi`, `httpcore`, `httptools`, `idna`, `ldap3`, `pycparser`, `pydantic`, `pydantic-core`, `pyodbc`, `pyside6-essentials`, `pyspnego`, `shiboken6`, `sspilib`, `truststore`, `uvicorn`, `websockets` | yes |
| `aiosqlite`, `annotated-doc`, `annotated-types`, `psutil`, `pyside6`, `pyside6-addons`, `tomlkit`, `typing-extensions`, `typing-inspection`, `tzdata`, `uvloop` | no |

Not risky here means that none of the three tests fired. It is not a clean result beyond them: the
vulnerability-history test reads advisories by PyPI name only, as stated with the tests above.

### How this reading and the tiers fit together

The tiers stay the designation. This reading does not move a component into or out of them. Where
the two agree is where to look first.

8 designated components are also risky on an ASVS example:

| Component | Designated above | Risky on |
|---|---|---|
| `aioodbc` | the `sqlserver` extra | maintenance |
| `certifi` | tier 2 | vulnerability history |
| `cryptography` | tier 2 | vulnerability history |
| `h11` | tier 3 | vulnerability history |
| `hl7apy` | tier 1 | maintenance |
| `httpx` | tier 3 | vulnerability history |
| `pyasn1` | tier 2 | vulnerability history |
| `starlette` | tier 3 | vulnerability history |

2 components are risky here and not designated above: `anyio` (vulnerability history), `click`
(vulnerability history). The tiers did not designate them under the exposure criterion. The reading
names them so that choice stays visible, and a reviewer can revisit it.

### The names the assessed extras add

The same readings again, for the names an assessed extra adds to the core closure. The advisory
column is how many advisories this reading counted under that PyPI name, of any severity and any
date, after the merging and the leaving out described with the tests above. Read it under the limit
stated there: a 0 is about the name, not about the code inside the wheel.

| Component | Added by | Pinned | Newest release | Advisories counted under the name | Risky on |
|---|---|---|---|---|---|
| `aioodbc` | `sqlserver` | 0.5.0 | 2023-10-28 | 0 | maintenance |
| `pyodbc` | `sqlserver` | 5.3.0 | 2025-10-17 | 0 | none |
| `pyside6` | `harness` | 6.11.2 | 2026-08-18 | 0 | none |
| `pyside6-addons` | `harness` | 6.11.2 | 2026-08-18 | 0 | none |
| `pyside6-essentials` | `harness` | 6.11.2 | 2026-08-18 | 0 | none |
| `shiboken6` | `harness` | 6.11.2 | 2026-08-18 | 0 | none |

<!-- END component-readings -->

## What this page is not

**It is not a vulnerability list.** It says where to look, not what is currently wrong. The
vulnerability-history reading above counts past advisories on a dated snapshot; it does not track
what is open today. Advisories
against these components are handled through the process in
[`.github/SECURITY.md`](../.github/SECURITY.md), and the machine-readable exception record is
[`security/vex/messagefoundry.openvex.json`](../security/vex/messagefoundry.openvex.json).

**It is not the consolidated threat-model table.** That document is withheld from public checkouts
by policy. This page is derived independently and stands on its own.

**It does not cover the extras other than `sqlserver` and `harness`.** See the scope note above.

## Keeping it true

`tests/test_risky_component_designation.py` fails when this page and
[`security/runtime-closure-core.txt`](../security/runtime-closure-core.txt) disagree: a dependency
that enters the closure without being classified here, or a name here that is not in the closure,
turns it red. It holds the `sqlserver` section to
[`security/runtime-closure-sqlserver.txt`](../security/runtime-closure-sqlserver.txt) the same way,
over the names that file adds to the core, and the `harness` section to
[`security/runtime-closure-harness.txt`](../security/runtime-closure-harness.txt), over the names
that one adds. The test is the reason the arithmetic above can be
trusted after the next dependency bump.

The same test holds each closure file to the lock it copies, in every name and version (BACKLOG
#1812, #1955). Each file's header names its lock and the command that regenerates both.

A bump that moves the lock without that command turns the test red in the same pull request. On a
Dependabot pull request, the lock-resync workflow runs the command for you.

Adding a dependency therefore means classifying it. Designating it is a judgement call; leaving it
out of both tables is not available.

The same test holds the ASVS reading to its snapshot,
[`security/risky-component-readings.json`](../security/risky-component-readings.json), with no
network. Every name this page assesses must have exactly one reading. That is each name in the core
closure, and each name an assessed extra's closure adds to it. No reading may name anything else. So
an extra that has a section on this page, and that the script does not read, turns the test red.

Each verdict must follow from its recorded readings under the recorded criteria. The section between
the markers must be exactly what the snapshot and the tiers above render, so a tier change needs
`python scripts/security/component_readings.py --render-only`.

The test does not go red when the re-read date passes, because a date alone would then fail every
unrelated pull request. Keeping the re-read date is a maintainer task. Run
`python scripts/security/component_readings.py` and commit what it writes. It reads the public data
again and rewrites both the snapshot and the section.
