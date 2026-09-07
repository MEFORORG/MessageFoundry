# Risky third-party components

This page designates which of the engine's third-party dependencies are **risky components**, says
what "risky" means here, and names the ones that were assessed and deliberately not designated.

It exists so a deploying operator knows where to look first when a dependency advisory lands, without
reading the source or guessing from a package name.

> **MessageFoundry is a not-deployed beta. There are zero running instances.** Nothing below reports
> a live exposure. It describes what a first deployment would carry.

## Scope, and the denominator

The set assessed is the **core runtime closure**: every distribution a default engine install
carries, transitive dependencies included, with no optional extras and no development toolchain.
That is **41 distributions**, recorded in
[`security/runtime-closure-core.txt`](../security/runtime-closure-core.txt).

**Which denominator you pick changes the answer by about half, so it is stated rather than implied:**

| Denominator | Count | Why not this one |
|---|---|---|
| Names in `pyproject.toml`, core only | 19 | Misses everything transitive. Over half of what runs is absent. |
| Names in `pyproject.toml`, core plus every extra | 42 | Still direct-only, and mixes in extras nobody enabled. |
| **Core runtime closure** | **41** | **Used here.** What a default install actually executes. |
| `requirements.lock` | 100 | Exported with `--all-extras`, so it carries the dev toolchain. Designating packages no production install has weakens the signal for the ones it does. |

An install that enables an extra (`postgres`, `sqlserver`, `sftp`, `dicom`, `fhir`, `xml`, `x12`,
`webauthn`, `otel`, `vault`, `harness`) carries dependencies **outside** this set. Those are not
assessed here, and that is a gap rather than an assertion of safety.

## The criterion

A distribution is designated risky if it meets **at least one** of these. The tier is the reason it
was designated, not a severity ranking.

1. **Hostile input.** It parses or deserializes data chosen by a party the engine does not control.
2. **Secrets and trust.** It performs cryptography, handles credentials, or decides what is trusted.
3. **Protocol termination.** It speaks a network protocol the engine exposes or dials.

Native compiled code is treated as an aggravating factor within a tier, not a tier of its own: a
memory-safety fault in a compiled parser is not the same class of event as a logic bug in a pure
Python one, and the tables below say which components carry it.

**Twenty-six of forty-one are designated, and the proportion is the finding.** This is an
integration engine: its job is parsing clinical traffic from partners it does not control and
terminating network protocols. Most of its runtime closure is therefore in one of those two paths by
construction. A short list here would be a less honest document, not a safer engine.

## Tier 1 — hostile input

These see bytes chosen by a sending system. Everything in
[`DANGEROUS-FUNCTIONALITY.md`](DANGEROUS-FUNCTIONALITY.md) section 7 about deliberate parser
tolerance applies to the first two.

| Component | Why | Native |
|---|---|---|
| `hl7` | python-hl7, the tolerant parser on the message hot path | no |
| `hl7apy` | strict HL7 validation, opt-in per connection, same input | no |
| `pydantic` | validates untrusted request and config input | no |
| `pydantic-core` | the engine underneath it, compiled | **yes** |
| `defusedxml` | processes hostile XML; it is the hardening, and it is in the path | no |
| `pyyaml` | deserialization surface | no |

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
| `watchfiles` | compiled filesystem watching, local paths only |
| `psutil` | compiled process and resource inspection, local only |
| `click` | command-line parsing, operator input on the local shell |
| `colorama` | terminal colour on Windows |
| `python-dotenv` | reads a local env file |
| `tomlkit` | parses operator-authored TOML from the config directory, which is inside the trust boundary |
| `prometheus-client` | metric formatting; the scrape surface is the engine's own route |
| `annotated-doc`, `annotated-types`, `typing-extensions`, `typing-inspection` | typing shims, no runtime input handling |
| `tzdata` | timezone tables |

That is 15, and 26 plus 15 is 41. The arithmetic is stated so a reader can check the set is closed
rather than trusting that it is.

## What this page is not

**It is not a vulnerability list.** It says where to look, not what is currently wrong. Advisories
against these components are handled through the process in
[`.github/SECURITY.md`](../.github/SECURITY.md), and the machine-readable exception record is
[`security/vex/messagefoundry.openvex.json`](../security/vex/messagefoundry.openvex.json).

**It is not the consolidated threat-model table.** That document is withheld from public checkouts
by policy. This page is derived independently and stands on its own.

**It does not cover the extras.** See the scope note above.

## Keeping it true

`tests/test_risky_component_designation.py` fails when this page and
[`security/runtime-closure-core.txt`](../security/runtime-closure-core.txt) disagree: a dependency
that enters the closure without being classified here, or a name here that is not in the closure,
turns it red. The test is the reason the arithmetic above can be trusted after the next dependency
bump.

Adding a dependency therefore means classifying it. Designating it is a judgement call; leaving it
out of both tables is not available.
