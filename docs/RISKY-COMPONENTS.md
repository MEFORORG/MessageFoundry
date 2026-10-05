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
| `websockets` | the WebSocket protocol for the console, with a compiled extension | **yes** |
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

Not designated is a statement about the tiers only. A wheel in this table can still carry a bundled
copy of another project, as compiled code, source code or data. *What each wheel carries inside
it*, in the ASVS reading further down, says in which wheels a survey found one and in what form. It
also states what counts as a bundled copy, and the route this page takes for a not-designated wheel
that carries another project's code.

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
| `pyside6` | a metadistribution: the `PySide6` package initialiser, two small version and configuration modules, and typing stubs. It parses no input, and it exists to pull in the other three. It ships no compiled file. The survey further down listed the pinned Linux x86_64 and Windows amd64 wheels and found none in either |
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

That is a limit of the instrument. The same generated reading narrows it, under *What each wheel
carries inside it*, and does not by itself close it. That survey says, for every wheel this page
assesses, whether the pinned wheel carries a bundled copy of another project, and on what evidence.
It answers for three forms: compiled code, source code and data. The designated wheels here are
already highlighted by the table above. A wheel that is not designated, and that the survey did not
show to carry no code from another project, takes one of the two routes stated there.

That subsection says whether any advisory for Qt was read, and what the survey could not establish.
Where it read none, a reader who needs the Qt side still has to check Qt's own security notices
against the Qt version the pinned wheels carry.

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

OSV matches an advisory to a component by its PyPI name. A flaw in something a wheel carries inside
it from another project shows up here only when an advisory names the PyPI package. That holds for a
compiled library, for a copy of another project's source, and for its data. So nothing below shows
that what a wheel carries is free of known flaws. *What each wheel carries inside it*, further down,
says which wheels carry another project in any of those forms, and what this page does about each.

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

### What each wheel carries inside it

The vulnerability-history test reads advisories by PyPI name. This survey asks what that test
cannot: whether each of the 40 pinned wheels carries a bundled copy of another separately
distributed project, and in what form. The compiled-code answers were made by hand between
2026-10-04 and 2026-10-05, and the source and data answers on 2026-10-05, against the pins the
snapshot reads. The evidence, the files read and their hashes are recorded in
[`security/bundled-code-survey.json`](../security/bundled-code-survey.json). A run of the script
does not repeat it.

**This page's unit.** A bundled copy counts when it is a package, a library tree or a data set of
another project, in any form. The forms are compiled code, source code and data. A single module
adapted from another project is not that unit. It is recorded where the search found one, and is
owed no route. Lines copied into a wheel's own module are not counted.

**This page's criterion.** A wheel that is not designated is owed a route when it carries another
project's code, compiled or source. A wheel that carries only another project's data is listed below
with what it carries. It is owed no route, because data holds another project's tables and none of
its logic. That holds where the tables are kept as generated Python modules too. That line is this
page's choice, and a reader can draw it elsewhere: data still decides things, as a list of root
certificates decides what is trusted. A wheel whose answer is not established, for any form, is
treated as carrying code.

**Another project's compiled code: found in 9 of 40. Not found in 31. Not established: 0. 9 plus 31
plus 0 is 40.**

**Another project's source code: found in 0 of 40. Not found in 38. Not established: 2. 0 plus 38
plus 2 is 40.**

**Another project's data: found in 5 of 40. Not found in 33. Not established: 2. 5 plus 33 plus 2 is
40.**

Each count is what the search described below found, and not a statement of what a wheel holds. The
search reads names, sizes and marked text. It can miss a copy that has no marker, so a wheel counted
as not found can still carry one.

The table has one row for each wheel and form where the answer is not a plain no.

| Component | Pinned | Form | Carries | Evidence | Route |
|---|---|---|---|---|---|
| `argon2-cffi-bindings` | 26.1.0 | compiled code | Argon2 reference implementation (phc-winner-argon2), version not established | wheel file list and source tree | designated, tier 2 |
| `certifi` | 2026.7.22 | data | Mozilla's list of trusted root certificates, version not established | wheel file list and files opened | designated, tier 2 |
| `cffi` | 2.1.1 | compiled code | libffi, version not established | wheel file list and source tree | designated, tier 2 |
| `cryptography` | 50.0.1 | compiled code | OpenSSL 4.0.2; Rust crates, the 40 entries of the source distribution's `Cargo.lock` | wheel file list and source tree | designated, tier 2 |
| `hl7apy` | 1.3.5 | data | HL7 v2 definitions of messages, segments, fields and data types, the twelve versions from 2.1 to 2.8.2 | wheel file list and files opened | designated, tier 1 |
| `httptools` | 0.8.0 | compiled code | llhttp 9.4.1; http-parser 2.9.4 | wheel file list and source tree | designated, tier 3 |
| `idna` | 3.20 | data | IDNA and UTS 46 mapping tables, Unicode 18.0.0 | wheel file list and files opened | designated, tier 3 |
| `ldap3` | 2.9.1 | data | Directory server schemas: Active Directory 2012 R2, 389 Directory Server, eDirectory 8.8.8 and 9.1.4, OpenLDAP slapd 2.4, versions as the file names give them | wheel file list and files opened | designated, tier 2 |
| `pydantic-core` | 2.46.5 | compiled code | Rust crates, the 104 entries of the source distribution's `Cargo.lock` | wheel file list and source tree | designated, tier 1 |
| `pyside6-addons` | 6.11.2 | compiled code | Qt, version not established | project metadata | highlighted below |
| `pyside6-addons` | 6.11.2 | source code | not established | wheel not fetched | highlighted below |
| `pyside6-addons` | 6.11.2 | data | not established | wheel not fetched | highlighted below |
| `pyside6-essentials` | 6.11.2 | compiled code | Qt, version not established | project metadata | designated, the `harness` extra |
| `pyside6-essentials` | 6.11.2 | source code | not established | wheel not fetched | designated, the `harness` extra |
| `pyside6-essentials` | 6.11.2 | data | not established | wheel not fetched | designated, the `harness` extra |
| `shiboken6` | 6.11.2 | compiled code | Microsoft Visual C++ runtime libraries (Windows wheel) 14.44.35211.0, with two files at 14.24.28127.4 | wheel file list | designated, the `harness` extra |
| `tzdata` | 2026.4 | data | IANA Time Zone Database 2026d | wheel file list and files opened | none owed: data only |
| `uvloop` | 0.22.1 | compiled code | libuv 1.48.0 | wheel file list and source tree | highlighted below |

26 wheels were found to carry no compiled code, on the evidence of the wheel tag and file list:
`aioodbc`, `aiosqlite`, `annotated-doc`, `annotated-types`, `anyio`, `argon2-cffi`, `certifi`,
`click`, `fastapi`, `h11`, `hl7apy`, `httpcore`, `httpx`, `idna`, `ldap3`, `pyasn1`, `pycparser`,
`pydantic`, `pyspnego`, `starlette`, `tomlkit`, `truststore`, `typing-extensions`,
`typing-inspection`, `tzdata`, `uvicorn`.

4 wheels were found to carry no compiled code, on the evidence of the wheel file list and source
tree: `psutil`, `pyodbc`, `sspilib`, `websockets`.

1 wheel was found to carry no compiled code, on the evidence of the wheel file list: `pyside6`.

26 wheels have no row in the table: the search found no package, library tree or data set of another
project in them, in any form.

The word search ran over the 38 wheels that were fetched. It hit 90 files. Counted in files: 7 hold
a single module adapted from another project, 24 hold lines copied into a wheel's own module, and 59
hold prose that marks no copy, such as a project's own licence header. The record lists each hit
under its wheel.

**Single modules adapted from another project, as found:**

| Component | File | The project the file names | Designated above |
|---|---|---|---|
| `aioodbc` | `aioodbc/pool.py` | aiopg | yes, the `sqlserver` extra |
| `cffi` | `cffi/_cffi_gen_src.py` | cffi-buildtool | yes, tier 2 |
| `cffi` | `cffi/_imp_emulation.py` | CPython 3.11, the standard library's `imp` module | yes, tier 2 |
| `click` | `click/parser.py` | CPython, the standard library's `optparse` module | no |
| `ldap3` | `ldap3/utils/ordDict.py` | none named; the copyright line names a person, Raymond Hettinger | yes, tier 2 |
| `pydantic` | `pydantic/v1/datetime_parse.py` | Django | yes, tier 1 |
| `uvicorn` | `uvicorn/_types.py` | none named; the copyright line names the Django Software Foundation | yes, tier 3 |

Each row is what the file says of itself. No file was compared with the project it names, and no
advisory for that project was read. Under the unit above, none of these moves a count or owes a
route. The list is what the word search found, and it is not a full list: a module adapted from
another project that does not say so in one of the listed words is not in it.

`pydantic` also holds a second release line of its own project: `pydantic/v1`, 27 files, version
1.10.26. That is the same project, so it is not counted as another project's source. An advisory
against that line would name `pydantic`, at that line's own version numbers. The reading above asks
OSV for every advisory recorded under that name, at any version, and for the ones that affect the
pinned version. An advisory OSV records against that line would be among the first. Nothing was
asked at version 1.10.26, so the reading does not say which advisories affect that line.

5 wheels carry another project's data and none of its code: `certifi`, `hl7apy`, `idna`, `ldap3`,
`tzdata`. Not designated among them: `tzdata`. Under the criterion above, that owes no route. No
notice about any of that data was read.

Each answer rests on the evidence the record names. A wheel tagged `none-any` had its file list read
as well as its tag. For any other wheel that was fetched, one Linux x86_64 wheel and the Windows
amd64 wheel were read, where the lock carries them. A file list shows a bundled library and cannot
show code linked into an extension, so the pinned source distribution was read too. A wheel the
record does not name was not read, and can carry something else. That holds for another platform,
and for a second Linux x86_64 wheel where the lock carries more than one.

The source and data answers rest on the same wheels, fetched again. The search looked for a
directory with one of 15 vendoring names, a top-level name beyond the project's own, a licence file
named for another project, a large file that is not a Python module, and any of 12 marker words. The
words were looked for in each file outside `.dist-info` whose name ends in one of 10 suffixes:
`.py`, `.pyi`, `.pyx`, `.pxd`, `.pxi`, `.c`, `.h`, `.txt`, `.md`, `.rst`. The record gives the
names, the size and the words under `search`. A Python module was opened as a possible table only
where its name or size suggested one, which is a judgement and not an exact rule. Not every large
module was opened. Under `cannot_see`, the record names large modules that were not, so a count of
not found does not rest on every large module having been read. No file was compared with the
project it names.

As a control, the same search was run over `pip-26.2.1-py3-none-any.whl`, a wheel known to vendor
source and not one of the wheels surveyed. The directory search fired on `pip/_vendor`. The
licence-file search fired on
`pip-26.2.1.dist-info/licenses/src/pip/_vendor/cachecontrol/LICENSE.txt`. The size search fired on
`pip/_vendor/certifi/cacert.pem`. The word search fired on `pip/_vendor/__init__.py`. The
top-level-name search has no control: that wheel has one top-level name, its own.

No source distribution was read for `pyside6` or `shiboken6`. Their compiled answers rest on wheel
file lists alone, which cannot show what is linked into a compiled file.

No wheel was fetched for `pyside6-addons` or `pyside6-essentials`. Their compiled answers rest on
PyPI project metadata, which lists no file. What the table names for such a wheel is the least it
carries: nothing else was looked for. For the same reason, no source or data answer is established
for such a wheel.

A designated wheel is already highlighted, by its tier. No carried project's advisories were read
for a designated wheel. 2 wheels are not designated and counted as carrying another project's code.
Each takes one of two routes: this page highlights it as risky on what it carries, or reads the
carried project's own advisories.

**Highlighted as risky on what it carries:**

| Component | Carries | Why |
|---|---|---|
| `pyside6-addons` | Qt, version not established | It holds compiled Qt modules, among them the web engine, multimedia and PDF modules. The harness imports none of them, but an install puts them on disk. A flaw filed against Qt names Qt, not `pyside6-addons`, so the vulnerability-history reading would not show it. |
| `uvloop` | libuv 1.48.0 | libuv is the event loop's I/O layer, so the socket reads and writes of an engine that runs on `uvloop` go through it. An advisory against libuv names libuv, not `uvloop`, so the vulnerability-history reading would not show it. |

No advisory for a carried project was read for these. A reader who needs that has to check the
carried project's own security notices against the version the pinned wheel carries. Where the table
gives no version, the survey did not establish one. Highlighting here does not move a wheel into a
tier.

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

The same test holds the survey of what each wheel carries,
[`security/bundled-code-survey.json`](../security/bundled-code-survey.json), in at least these ways
(BACKLOG #2935). Every name in an assessed closure must have a survey answer, so a new dependency
needs one in the same pull request. Each answer must cover compiled code, source code and data. A
wheel that is not designated, and not shown to carry no code from another project, must have a
recorded route. A wheel that carries only data must have none. The record must state its search and
name a control the search fired on. And the page's survey tables, its counts and its list of adapted
modules must say what the record says.

The page's unit and criterion are written in the script that renders the section. The test holds the
page to its own copy of the unit's sentences, and of some of the criterion's. It holds a few
hand-written sentences about the survey the same way, and not every one. The record's `method`
states the unit in its own words, and no test holds those words to the page.

The survey is made by hand, and no script repeats it. It is dated to the pins the snapshot reads, so
a version bump alone does not turn the test red. A re-read that moves a pin does: the script then
names each wheel whose survey answer is behind, and the test fails until that wheel is surveyed
again. The record's `method` says how each answer was reached.

The test does not go red when the re-read date passes, because a date alone would then fail every
unrelated pull request. Keeping the re-read date is a maintainer task. Run
`python scripts/security/component_readings.py` and commit what it writes. It reads the public data
again and rewrites both the snapshot and the section.
