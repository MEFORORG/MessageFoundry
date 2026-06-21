# Non-HL7 transform support — leverageable Python components (research)

**Date:** 2026-06-19 · **Status:** research / findings (no code) · **Owner action:** see *Decision & backlog* below.

This document records a one-time component evaluation so we don't have to re-run it. The driving
question (from the website positioning copy): *"Can you do more with HL7 than with the rest?"* —
honestly, **you can transform every format with the full power of Python, but only HL7 v2 ships a
structured, standard-aware transform model built in.** This studies which **real Python components**
could give the other formats more of that built-in scaffolding, without breaking MessageFoundry's
constraints.

## The gap we're closing

What a Router/Handler receives today, and the built-in transform support per format:

| Format | Router/Handler gets | Built-in transform support |
|---|---|---|
| **HL7 v2** (default) | a `Message` | **Full & structured** — read/set by field path (`msg["MSH-9.2"]`, `msg["PID-3.1.1"] = …`), iterate repetitions, add/delete segments, type/trigger/control-id accessors, MSH-aware re-encode, opt-in strict (hl7apy) validation, parse tree. |
| **X12 EDI** | a `RawMessage` | A dedicated **on-demand codec** (`parsing/x12/`): tolerant routing peek, interchange splitting, structured read/set — called explicitly against the raw. Strict guide validation is **deferred** (ADR 0012). |
| **JSON** | a `RawMessage` | `.json()` → a parsed `dict` you transform in plain Python. |
| **XML / SOAP / other** | a `RawMessage` | `.raw` / `.text` — full Python, bring (or call) your own parser. |

It's a difference in **built-in support, not raw capability**. This research asks: for which of the
"lesser" rows is closing that gap (a) high-value and (b) cleanly doable with a real, license-clean,
offline component?

## Constraints any component must satisfy

- **License:** the engine is **AGPL-3.0-or-later**. A *bundled* dependency must be compatible with AGPL
  distribution — permissive (MIT/BSD/Apache-2.0/PSF) is ideal; GPL is a problem.
- **On-prem / PHI-safe / offline:** **no network I/O during parse/transform.** A library that needs a
  cloud service or a live FHIR/terminology server is disqualified for the transform path (it would also
  break the at-least-once *pure re-run* invariant). Inbound payloads are **untrusted PHI-bearing data**.
- **Minimal-dependency:** the base install stays lean; format drivers ship as **optional extras** (the
  `messagefoundry[sqlserver]` / `[postgres]` / planned `[x12]` precedent), never core.
- **Code-first logic:** a structured *library/model* (like `Message`/`X12Message`) is welcome — it is
  code-first scaffolding. A **declarative transform DSL / channel element** is **not** (CLAUDE.md §1/§4).
- **Two-tier parsing:** a cheap tolerant routing peek on the hot path + opt-in strict/schema validation
  on the slow path (the python-hl7 / hl7apy split).
- **The proven integration pattern (`parsing/x12/`, ADR 0012):** a pure, **console-importable** library
  under `parsing/` (zero engine imports; refers to its content type by literal string), called **on
  demand** by Routers/Handlers against `RawMessage.raw`/`.json()` — never pushed through `pipeline/`,
  with the heavy/compiled dependency isolated in an optional extra.

## Methodology

Multi-agent research (6 format-family researchers → adversarial verifiers → synthesis). Each candidate
was checked for: PyPI existence (to catch hallucinated/typosquat packages), license, maintenance/last
release, Python 3.11+ support, dependency weight, and offline/PHI-safety. **Versions, dates, and CVE
identifiers below are a snapshot gathered by automated web lookup on 2026-06-19 and drift — re-confirm
the exact pinned version, license, and any CVE before adoption** (standard `pyproject.toml` + `uv lock`
verify-then-add discipline).

## Bottom line

- **FHIR is the one high-leverage gap, and it's the only format where a model is *adoptable* rather than
  hand-rolled.** It is the one non-HL7 format that, like HL7 v2, has both a **typed domain model** *and* a
  **standard field-path language**. Mature, permissive, pure-offline libraries cover it: **`fhir.resources`**
  (typed model) + **`fhirpathpy`** (FHIRPath). Enriches existing backlog **#20**.
- **A safe `.xml()` door is the highest-*leverage* single move** — one hardened XML accessor structurally
  serves FHIR-XML, CDA/C-CDA, SOAP, and NCPDP SCRIPT. ADR 0004 already flagged **`defusedxml`** for it.
  New backlog **#30** (with a thin `XmlMessage` + `[xml]` extras as the larger follow-on).
- **X12 strict validation can finally land** via **`pyx12`** as an optional `[x12]` extra — its only
  runtime dep is `defusedxml` (already on the roadmap), so net new weight is ~zero. Completes ADR 0012's
  explicitly-deferred SEF/guide validator. New backlog **#31**.
- **JSON's model is already adequate** (`RawMessage.json()`); the only worthwhile add is **opt-in JSON
  Schema validation** (`fastjsonschema`), the hl7apy slow-path analog — not a JSON model.
- **Plain text and bespoke XML dialects (incl. C-CDA) are adequately served** by `RawMessage` + the safe
  `.xml()` door + Python. A dedicated CDA codec is large/low-priority unless a concrete CDA feed exists.

## Per-format recommendation

| Format | Current state | Recommended component(s) | What it adds | License / offline / maint (2026-06-19) | Verdict |
|---|---|---|---|---|---|
| **FHIR** (JSON/XML) | bare `RawMessage.json()`; Handler walks nested dicts | **`fhir.resources`** (typed model) + **`fhirpathpy`** (FHIRPath) | Typed `FhirResource` (construct/read/set/validate/encode) + standard field-path query — the `Message`/`X12Message`-grade gap | BSD-3 / MIT · offline (no terminology calls) · both active | **optional-extra** `[fhir]` |
| **XML / SOAP** | `RawMessage.raw`; no `.xml()`; unsafe to bare-parse untrusted input | **`defusedxml`** (stdlib parse) + hardened **`lxml`** (XPath model); `[xml]`: **`xmlschema`** (XSD), **`signxml`** (WS-Security) | Safe `.xml()` accessor; thin `XmlMessage` (XPath read/set + namespace re-encode); opt-in XSD validate; offline XMLDSig sign/verify | `defusedxml` PSF / `lxml` BSD / `xmlschema` MIT / `signxml` Apache-2.0 · offline *when hardened* · all active | **adopt-core** (safe parse) + **optional-extra** `[xml]` |
| **X12 EDI** | hand-rolled `parsing/x12/`; strict validation **deferred** | **`pyx12`** | HIPAA implementation-guide strict validation (837/835/270-271/834/276-277/278) + 997/999 generation | BSD-3 · fully offline (guides bundled), sole dep `defusedxml` · active (4.x) | **optional-extra** `[x12]` |
| **JSON** | `RawMessage.json()` — adequate | **`fastjsonschema`** (or `jsonschema`); optional `jsonpath-ng` | Opt-in JSON Schema validation (slow-path contract gate); stable field addressing | BSD / MIT / Apache-2.0 · offline (bundle schemas) · active | **optional-extra** `[json-schema]` (model: **leave as-is**) |
| **C-CDA / CDA** | XML via `RawMessage.raw` | safe `.xml()` + Python now; *(large/low-pri)* a `parsing/cda/` over the same lxml+defusedxml substrate | Parse/route/validate constrained clinical XML; optional CDA→FHIR via `python-fhir-converter` | substrate BSD/PSF · converter MIT but **stale + pins `lxml==5.3.0`** (conflicts core) | **reference-only** now; `parsing/cda/` deferred |
| **NCPDP D.0** | bare `RawMessage` | **`dzero-python`** | Telecom D.0 fixed-field parse/serialize | MIT · pure-Python, zero-dep, offline · 1.0.2 **Beta** | **reference-only** (adopt-if-demand) |
| **DICOM** | not handled | `pydicom` / `pynetdicom` | Imaging dataset model + DIMSE networking | MIT · **transport, not transform** | **reference-only** (future `transports/` connector) |
| **Plain text / delimited** | `RawMessage.text` | none | n/a — Python string ops suffice | — | **leave as-is** |

## The strategic priority — FHIR (enriches backlog #20)

FHIR is the most valuable gap because it is simultaneously (a) the most strategically important non-HL7
format for a healthcare engine, (b) something the engine will receive as `content_type=fhir` (JSON or
XML body), and (c) the **only** non-HL7 format where excellent pure-Python, offline, permissively-
licensed building blocks already exist — so the work is **integration, not hand-rolling a codec**. Today
a bare `RawMessage.json()` leaves a Handler author manually walking nested dicts — exactly the friction
`Message`/`X12Message` were built to remove.

**Components (both verified — real, offline, AGPL-bundle-safe, actively maintained):**

- **`fhir.resources`** (BSD-3, pydantic-v2) → the typed `FhirResource` analog of `Message`/`X12Message`.
  Construct/read/set/validate/encode R5/R4B/STU3, JSON by default. Validation is **local pydantic schema
  work with zero terminology-server calls** — offline and PHI-safe. It drags `fhir-core` + `pydantic-core`
  (a compiled wheel), which is exactly why it belongs in an **extra**, not core. *(pydantic itself is
  already a core dep. Note: `fhir.resources`' XML support rides **lxml**, not defusedxml — keep FHIR-XML
  ingress on the hardened-lxml path, or off.)*
- **`fhirpathpy`** (MIT, ANTLR4 runtime) → the FHIRPath evaluator, the standard idiomatic field-path
  language and the true analog of `msg["PID-3.1.1"]`. Light runtime (`antlr4-runtime` + `python-dateutil`),
  works directly on a `RawMessage.json()` dict. *(PyPI name is `fhirpathpy`; the repo is
  `beda-software/fhirpath-py`. Do **not** confuse with `fhirpath` by nazrulworld — a GPLv3,
  Elasticsearch-backed search DSL; wrong tool and wrong license.)*

**Proposed shape:** a pure `parsing/fhir/` package (zero engine imports; refers to its content type by
the literal `"fhir"`; console-importable), with a thin **`FhirResource`** accessor (parse/validate/encode
via `fhir.resources`) and FHIRPath read/extract via `fhirpathpy`. Add `content_type=fhir`;
Routers/Handlers call it on demand against `RawMessage.json()`; a Handler returns
`Send(to, resource.model_dump_json())`. Dependency ships only as `messagefoundry[fhir]`, never core.

**Two-tier split:** tolerant peek = `fhirpathpy.evaluate(msg.json(), "Bundle.entry.resource.ofType(MessageHeader).event.code")`
for routing (cheap, on the dict, no typed instantiation); opt-in strict-validate = full `fhir.resources`
pydantic parse (raises on non-conformant structure/cardinality) — the slow path, off the routing hot path.

**MVP includes:** the `[fhir]` extra, the `FhirResource` accessor, FHIRPath peek + query.
**MVP defers (genuinely unsolved in pure Python — do not attempt):**
- **Profile / StructureDefinition conformance** (US Core, etc.) and **terminology/code-binding validation**
  — these are HAPI/Firely (Java/.NET) territory; no production-ready offline pure-Python option.
  (`fhircraft` is the one near-miss but defaults to network registry lookups + is pre-1.0 — **watch**, not
  a dependency.)
- **Bidirectional HL7 v2 ↔ FHIR mapping** — there is **no production-ready pure-Python v2↔FHIR converter**,
  so mapping stays **hand-authored code-first Handlers** (python-hl7 `Message` in → `fhir.resources`
  resource out). This is consistent with the code-first-logic rule and the #20 note that "HL7 v2 ↔ FHIR
  mapping is a separate, larger effort — leave it to handlers initially."
- Any **FHIR REST client** (`fhirpy`/`fhirclient`) — network-bound; belongs with the FHIR *transport* half
  of #20 under `transports/`, never in `parsing/`.

## Quick wins

### `.xml()` RawMessage accessor + structured XML support (backlog #30)

ADR 0004 already flagged this (`.xml()` "needs a safe parser — `defusedxml`"). It is the **highest-leverage
single move**: one safe XML door structurally serves FHIR-XML, CDA/C-CDA, SOAP, and NCPDP SCRIPT. The
non-negotiable: inbound XML is untrusted PHI-bearing data — a bare `ElementTree.fromstring()` is an
XXE/billion-laughs liability the instant any XML accessor ships.

Two layers, by use:

- **Routing peek / field extraction (core, small):** `RawMessage.xml()` backed by **`defusedxml`**
  (PSF, pure-Python, zero-dep, offline-by-design) over the stdlib ElementTree, with
  `forbid_dtd`/`forbid_external`/`forbid_entities` **on**. This is the small core quick win.
- **XPath set / namespace-aware re-encode model (`[xml]`, medium):** a hand-rolled thin **`XmlMessage`**
  (the `Message`/`X12Message` analog — XPath read/set + namespace-aware re-encode) over **hardened
  `lxml`**, since no off-the-shelf XML *model* qualifies. **`defusedxml` does not cover lxml**, and its
  bundled `defusedxml.lxml` submodule is **deprecated since 2019** — harden lxml directly instead:
  pin a recent lxml and construct an explicit parser with `resolve_entities=False, no_network=True,
  huge_tree=False, load_dtd=False`. *(The research flagged CVE-2026-41066 — iterparse/`ETCompatXMLParser`
  defaulting `resolve_entities=True`, fixed in lxml 6.1.0 — verify the current advisory + a safe pinned
  version at adoption.)* This earns its keep mainly for **namespace-heavy SOAP/CDA**.

Optional `[xml]` companions (slow path / outbound): **`xmlschema`** (MIT-style, pure-Python) for opt-in
XSD validation — **pin schemas locally; it can fetch a remote `schemaLocation`** (egress vector);
**`signxml`** (Apache-2.0) for offline XMLDSig / WS-Security sign/verify (relevant to the WS-SOAP outbound
work, ADR 0015). *(For a lossy-but-cheap dict view, `xmltodict` with `disable_entities=True` is fine for a
routing peek but is not a canonical/signed re-encode tool.)*

### X12 strict validator — `pyx12` (backlog #31)

The reason ADR 0012 deferred strict X12 validation ("risk of a heavy/uncertain/possibly-hallucinated
dependency") is now obsolete: **`pyx12`** (BSD-3, Python 3.11+, active) ships its own HIPAA
implementation-guide maps + code lists, is **fully offline**, and its **sole runtime dependency is
`defusedxml`** — already on the roadmap, so net new transitive weight is ~zero. Wire it as the **opt-in
strict-validate slow path** behind the existing hand-rolled tolerant `X12Peek`/`X12Message` (two-tier
intact), called on demand against `RawMessage.raw`, shipped as `messagefoundry[x12]`. Bonus: free 997/999
acknowledgement generation. **Do not replace** the hand-rolled codec — keep it as the dependency-free hot
path; `pyx12` is the additive strict tier only. **Before committing, confirm the shipped map coverage**
matches the partners' specific guide versions (e.g. `005010X222A1` 837P, `X223A2` 837I, `X221A1` 835,
`X279A1` 270/271).

## Integration approach (all follow the `parsing/x12/` pattern)

Every recommended add is a pure library under `parsing/` with **zero engine imports**, **console-importable**,
called **on demand** against `RawMessage`, with the heavy/compiled dependency isolated in an **optional
extra**. None is pushed through the pipeline hot path; the only new *core* code is the tiny hardened-XML
parse helper.

- **FHIR** — `parsing/fhir/`: a `FhirResource` accessor (fhir.resources) + FHIRPath peek/query (fhirpathpy).
  Two-tier as above. Extra: `[fhir]`.
- **XML/SOAP** — `parsing/xml/`: a hardened safe-parse helper (core) + a thin `XmlMessage` (lxml). Extra:
  `[xml]` (xmlschema, signxml).
- **CDA** — *(deferred / low-priority)* `parsing/cda/` would reuse the XML substrate: `CdaPeek`
  (templateId/code peek) + `CdaDocument` (XPath read/set + re-encode) + `validate.py` wrapping lxml XSD +
  `lxml.isoschematron` against **bundled official HL7 C-CDA schemas** (strict IG validation deferrable, as
  for X12). A distinct `[cda]` extra could offer **`python-fhir-converter`** for CDA→FHIR migration — but it
  **pins `lxml==5.3.0`**, conflicting with the core lxml and the hash-locked posture, so it must stay an
  isolated optional extra, never core. **Lowest priority unless a concrete CDA feed exists** — until then,
  parse C-CDA via the safe `.xml()` door + Python.
- **X12 strict** — no new model; bolt `pyx12` on as the strict tier (see above).
- **JSON** — no model. Add only opt-in **JSON Schema validation** as the standard-aware slow path:
  **`fastjsonschema`** (BSD, pure-Python, zero-dep — posture-aligned default) or `jsonschema` where richer
  draft coverage/error detail justifies its `rpds-py` Rust extension. **Bundle schemas locally; forbid
  remote `$ref`** (SSRF/egress vector); only compile operator-authored (trusted) schemas. Optional thin
  `jsonpath-ng` (Apache-2.0, zero-dep) helper for stable field addressing.

## Honest non-recommendations

- **A generic mapping/transform DSL** — `glom` (its S/T spec *is* a small declarative mapping DSL),
  `dpath`, `jsonpath-ng`-as-a-mapping-layer. All real/permissive/offline, but they're restructuring helpers
  a Handler can `pip install` and call; bundling buys little and drifts toward the declarative-transform
  surface the project deliberately holds out of core (CLAUDE.md §1/§4). **Bring-your-own.**
- **A JSON or generic-XML `Message` model.** JSON arrives already-navigable from the stdlib; an `XmlMessage`
  is worth it *only* for namespace-heavy SOAP/CDA (above), not as a blanket wrapper. Don't model a domain
  that isn't there.
- **`defusedxml.lxml`** — deprecated/unmaintained since 2019. Harden lxml directly.
- **Network clients used inside a transform** — `zeep` (SOAP), `fhirpy`/`fhirclient` (FHIR REST),
  `pynetdicom` (DICOM). Real and maintained, but they do network I/O — a PHI-egress vector and a violation
  of the pure-re-run invariant. If ever needed they belong under `transports/` as a Connection, never in
  `parsing/`.
- **`pydicom`** — excellent and pure-Python, but DICOM is large-binary imaging with its own DIMSE protocol;
  out of the text-transform family. A future `transports/` connector at most (tracked as backlog #24).
- **Abandoned / unviable / typosquat / GPL packages — avoid:** `pyCCDA` / `ccda-parser`
  (self-described unstable, murky provenance, unhardened parse), `ccda-processor` (2019 HTML renderer,
  wrong scope), `ccda-builder` / `ccdakit` (404 / generation-only / design-phase), `x12-python` (single
  0.1.0, dead repo — the hallucination/typosquat class CLAUDE.md §5 warns about), `badX12` (2018,
  parse-only, py3.6-era pins), `bots-edi-parser` (GPL-3.0 + placeholder URLs), `fhirpath` (nazrulworld,
  GPLv3 — superseded by `fhirpathpy`), `pathling` (Spark/JVM + terminology-server calls). `pydifact` is
  actively maintained but **out of scope** (EDIFACT, not X12). `fhircraft` (offline FHIR profile validation)
  is a near-miss but network-default + pre-1.0 — **watch**, not adopt.

## Effort & risk

| Item | Effort | Key risk |
|---|---|---|
| `.xml()` safe accessor (`defusedxml`) — **#30** core | **Small** | Hardening flags must be exactly right; mandatory the instant any untrusted XML is parsed. |
| `pyx12` X12 strict extra — **#31** | **Small–Medium** | Shipped map coverage may not match a partner's specific guide version — verify before committing. Single (revived) maintainer line. |
| `[json-schema]` opt-in validation (`fastjsonschema`) | **Small** | Must bundle schemas locally + forbid remote `$ref`; only compile trusted operator-authored schemas. |
| `[fhir]` — `fhir.resources` + `fhirpathpy` — **#20** | **Medium** | `pydantic-core` compiled-wheel weight (isolated in extra); FHIR-XML rides lxml not defusedxml — keep on hardened path or off; pin the resource-version sub-package (R4 family); scope profile/terminology validation + v2↔FHIR mapping explicitly *out*. |
| `parsing/xml/` thin `XmlMessage` over hardened lxml + `[xml]` (xmlschema, signxml) — **#30** follow-on | **Medium** | Hand-rolled model maintenance; namespace handling; lxml C-extension cuts against single-binary posture (mitigated by prebuilt wheels); xmlschema can fetch remote `schemaLocation` — pin locally. Earns its keep for SOAP/CDA + XSD gating + signatures. |
| `parsing/cda/` (+ `[cda]` `python-fhir-converter`) | **Large** | Bundling/maintaining official HL7 C-CDA schemas; converter is stale/pre-1.0 with a conflicting `lxml==5.3.0` pin — strictly isolated extra, CDA→FHIR-only. Lowest priority unless a concrete CDA feed exists. |
| `[ncpdp]` via `dzero-python` | **Small (if demand)** | Single 1.0.2 Beta release, limited track record — evaluate maturity before committing; D.0 fixed-field only (SCRIPT/XML rides the generic XML door). |

## Decision & backlog

This research did **not** change scope on its own (locking v0.2 scope is a separate owner exercise). It
feeds the backlog ([`BACKLOG.md`](../BACKLOG.md)):

- **#20 FHIR** — enriched with the concrete component picks above (`fhir.resources` + `fhirpathpy`,
  `[fhir]` extra, two-tier split, the explicit *defer* list: profile/terminology validation, v2↔FHIR
  mapping, REST client).
- **#30** — safe `.xml()` `RawMessage` accessor (`defusedxml`, core) + a thin `XmlMessage` over hardened
  lxml with a `[xml]` extra (`xmlschema` XSD, `signxml` WS-Security) as the larger follow-on. *(new)*
- **#31** — X12 strict implementation-guide validation via `pyx12` (`[x12]` extra), completing ADR 0012's
  deferred validator. *(new)*

Lower-priority / situational (captured here, not yet backlog items): opt-in JSON Schema validation
(`fastjsonschema`, `[json-schema]`); NCPDP D.0 via `dzero-python` (`[ncpdp]`, adopt-if-demand); a dedicated
`parsing/cda/` codec (large, build only on a real CDA feed).

Related ADRs: [ADR 0004](../adr/0004-payload-agnostic-ingress.md) (payload-agnostic ingress,
`RawMessage`, the `.xml()` lean), [ADR 0012](../adr/0012-x12-edi-codec.md) (the `parsing/x12/` codec
pattern + deferred strict validator), [ADR 0003](../adr/0003-non-hl7-transports-database-rest-soap.md)
(non-HL7 transport posture + optional-extra dependency rule),
[ADR 0015](../adr/0015-ws-soap-outbound-mtls-wssecurity.md) (WS-SOAP outbound + WS-Security — the `signxml`
context).

## Verification snapshot (2026-06-19 — versions/CVEs drift, re-confirm at adoption)

All recommended packages confirmed real on PyPI, permissively licensed, pure-Python/offline (no network
I/O on the transform path), and actively maintained as of this date:

- **`fhir.resources`** — BSD-3, pydantic-v2. <https://pypi.org/project/fhir.resources/>
- **`fhirpathpy`** (beda-software) — MIT, ANTLR4 runtime. <https://github.com/beda-software/fhirpath-py>
- **`pyx12`** — BSD-3, pure-Python, HIPAA guides bundled; sole dep `defusedxml`.
  <https://pyx12.readthedocs.io/>
- **`defusedxml`** — PSF, wraps the stdlib expat parser. <https://pypi.org/project/defusedxml/>
- **`lxml`** (hardened) — BSD-3, C-extension; pin a current version (verify CVE-2026-41066 fix ≥ 6.1.0).
- **`xmlschema`** (sissaschool) — MIT-style, pure-Python + bundled base schemas. <https://xmlschema.readthedocs.io/>
- **`signxml`** — Apache-2.0, XMLDSig. **`fastjsonschema`** — BSD, pure-Python, zero-dep.
  **`dzero-python`** — MIT, pure-Python (NCPDP D.0, Beta).

> Caveat: exact version numbers, release dates, and CVE identifiers were gathered by automated web lookup
> at the time of writing. Treat them as a snapshot and re-verify the pinned version, license, maintenance
> status, and security advisories when the work is actually scheduled.
