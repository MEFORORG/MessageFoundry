# ADR 0122 — WSDL import: pure SOAP operation/message type-tree + validate-against-WSDL (no zeep)

- **Status:** Accepted (2026-07-17) — demand-gate build (BACKLOG #69 trigger: a SOAP partner ships a WSDL a
  migration depends on). Owner-directed lane `dg-s6` (DEMAND-GATE-BACKLOG plan, Wave 1). Build authorized;
  pushes/PR owner-approved.
- **Built:** `messagefoundry/parsing/xml/wsdl.py` (new pure module) + `WsdlError`/`WsdlSecurityError` in
  `parsing/xml/errors.py`, exported from `parsing/xml/__init__.py`.
- **Decision in one line:** parse a **WSDL 1.1** document into a **typed, read-only operation/message
  tree** with the **already-hardened** lxml parser (`harden.parse_bytes` — XXE/DTD/network off) and validate
  a SOAP envelope's body against the WSDL's **embedded XSD** via the **already-no-network**
  `schema.validate_against` — reusing the ADR 0015 SOAP transport's hand-built envelopes untouched, adding
  **no dependency** (no zeep, no suds), and closing the **distinct `wsdl:import` / `xsd:import` network
  resolution path** the existing `xmlschema` no-network config does *not* cover.
- **Related:** [ADR 0015](0015-ws-soap-outbound-mtls-wssecurity.md) (the WS-* / mTLS SOAP outbound whose
  envelopes this validates but does not replace), BACKLOG [#31](../BACKLOG.md) (the pure XML/SOAP codec this
  extends — `parsing/xml/`), BACKLOG [#69](../BACKLOG.md), BACKLOG [#70](../BACKLOG.md)
  (synchronous in-transform WSCall — **declined-by-design**, so a WSDL is a *contract* artifact here, never a
  live-call generator), [CLAUDE.md](../../CLAUDE.md) §4 (the pure `parsing/` carve-out a client may import),
  §8 (untrusted XML is attacker-influenceable), §9 (PHI-safe failure reporting).

## Context

BACKLOG #69 (demand-gate) asks for **WSDL import**: parse a partner's WSDL into a typed operation/message
tree and **validate SOAP envelopes against it**. The gap is real — `transports/soap.py` builds request
envelopes by string concatenation and has **no** WSDL awareness, so an operator porting a Corepoint SOAP
feed hand-transcribes the operation names, message parts, and target namespaces from the WSDL and has **no
machine check** that a built envelope conforms.

The re-scoring flagged the classic risk: a full WSDL/SOAP stack (**zeep**, **suds**) is a heavy, transitively
large dependency that would drag a code-generation / dynamic-proxy model into the engine — exactly the
declined "visual/templated authoring" and declined "synchronous WSCall" (#70) directions. The workaround
already exists (envelopes are hand-buildable in a code-first Handler), so the bar is: **add the contract
check, add no framework.**

Two hard constraints shape the design:

1. **The XML attack surface is already solved once, here — do not re-open it.** `parsing/xml/harden.py`
   locks lxml down (`resolve_entities=False`, `no_network=True`, `load_dtd=False`, `huge_tree=False`, DOCTYPE
   rejection); `parsing/xml/schema.py` builds `xmlschema.XMLSchema(..., allow="local", base_url=None)` so a
   crafted `schemaLocation` can't fetch over the network. A WSDL is just XML — it **must** ride the same
   hardened parse, or it re-introduces XXE/SSRF on a *new* untrusted document class.

2. **A WSDL has a network-resolution path the XSD lockdown does NOT auto-cover.** `xmlschema`'s `allow=
   "local"` governs **`xsd:import`/`xsd:include`/`schemaLocation`** *inside a schema it is already loading*.
   But **`wsdl:import`** (WSDL 1.1 §2.1.1, a WSDL importing another WSDL/schema by `location=`) is a **WSDL
   construct**, parsed by *our* code before any schema is built — so it is a **separate, un-covered resolver
   seam**. A naïve importer that dereferenced `wsdl:import location="https://attacker/…"` would SSRF straight
   past the XSD lockdown. This path must be locked to no-network **explicitly**, in the WSDL layer.

## Decision

### A pure, read-only `WsdlDefinition` — parse, don't proxy

`parse_wsdl(data: bytes | str) -> WsdlDefinition` parses a **WSDL 1.1** document through
`harden.parse_bytes` (so the untrusted WSDL gets the identical XXE/DTD/no-network lockdown as every other
body in the codec) and walks it into a frozen, typed tree:

```python
@dataclass(frozen=True)
class WsdlPart:
    name: str
    element: str | None   # QName "{ns}local" of the referenced global element (document/literal)
    type: str | None      # QName of the referenced type (rpc/encoded — parsed, validated best-effort)

@dataclass(frozen=True)
class WsdlOperation:
    name: str
    soap_action: str | None
    input_element: str | None   # resolved body element QName for the request  (or None)
    output_element: str | None  # resolved body element QName for the response (or None)

@dataclass(frozen=True)
class WsdlDefinition:
    target_namespace: str | None
    operations: Mapping[str, WsdlOperation]   # by operation name
    # the embedded <wsdl:types> XSD schema(s), serialized, for validate_against
```

This is a **contract type-tree**, not a client: there is **no** dynamic proxy, no code generation, no live
call. It reuses the ADR 0015 SOAP transport's hand-built envelopes **unchanged** — the WSDL is consulted to
*check* an envelope, never to *drive* one. (BACKLOG #70's synchronous in-transform WSCall stays
declined-by-design; a WSDL here is a validation contract, consistent with the purity/at-least-once invariant.)

### Envelope validation rides the existing no-network XSD path

`WsdlDefinition.validate_request(envelope, operation)` (and `validate_response`) :

1. parse the SOAP envelope through `harden.parse_bytes` (hardened, no-network),
2. locate the single `soap:Body` child element (SOAP 1.1 **and** 1.2 envelope namespaces),
3. confirm its QName matches the operation's resolved `input_element`/`output_element` — a **PHI-safe**
   structural check (it compares element *QNames*, never element *content*),
4. validate that body element against the WSDL's **embedded** `<wsdl:types>` XSD via
   `schema.validate_against` — which parses the body through the hardened parser and builds the schema with
   remote fetching **disabled**.

The result is the existing `XmlSchemaResult` (`valid: bool`, `reasons: tuple[str, ...]`) whose reasons are
already **PHI-safe** (failing element *path* + xmlschema reason *category*, never the offending value). A
structural mismatch (wrong body element for the operation) is reported the same PHI-safe way — QName +
category, never content.

### The `wsdl:import` / cross-schema resolution path is locked to no-network — explicitly

`parse_wsdl` collects every `wsdl:import` and every schema `xsd:import`/`xsd:include` and inspects its
`location`/`schemaLocation`:

- A **remote** location (`http:`, `https:`, `ftp:`, `//host` network-path, or any URI with a scheme+authority)
  is **refused** — `parse_wsdl` raises `WsdlSecurityError` (a PHI-safe message naming the scheme only, never
  the full URL's query/fragment). This is the seam `xmlschema`'s `allow="local"` does not cover, closed in the
  WSDL layer **before** any schema is built. Fail-closed: an unresolved remote import is an error, not a
  silent skip.
- A **relative/local** location is **not fetched** either (a pure codec does no disk or network I/O); it is
  recorded as *unresolved*. Validation against a type defined only in an unresolved import then **fails
  closed** through `xmlschema` (it cannot resolve the type → the build raises → surfaced as
  `XmlValidationError`), never silently passing. The common single-document WSDL with an **embedded**
  `<wsdl:types>` schema needs no import and validates fully.

This is deliberately conservative: MessageFoundry validates against **what the operator shipped in the one
WSDL document**, and refuses to reach across the network to complete a partial contract. An operator whose
partner splits the contract across imported documents inlines/merges them locally (the same posture as the
local-XSD requirement in `schema.py`).

### No new dependency

`parse_wsdl` uses only `lxml` (already in the `[xml]` extra) via the hardened parser, and `validate_against`
uses only `xmlschema` (already in `[xml]`). **No zeep, no suds, no new locked package** — `pyproject.toml`
and `requirements.lock` are untouched.

## Consequences

**Positive**

- A partner WSDL becomes a **machine-checkable contract**: a Handler validates a built request envelope (and a
  captured response envelope, ADR 0013) against the operation's schema **before** it leaves / after it
  arrives, catching a mis-shaped body at author time instead of as a partner-side SOAP `<Fault>`.
- **Zero new attack surface and zero new dependency:** the untrusted WSDL rides the existing hardened parse;
  envelope validation rides the existing no-network XSD validator; the one genuinely new resolver seam
  (`wsdl:import`) is fail-closed to no-network.
- Pure and client-importable (CLAUDE.md §4): the console / test harness may render a WSDL's operation tree
  without touching the engine.
- The ADR 0015 SOAP transport is **untouched** — hand-built envelopes stay the execution path; this only
  *checks* them.

**Negative / costs**

- **WSDL 1.1 only**, **document/literal** the first-class case (rpc/encoded parts are parsed best-effort but
  not the modern interop style); WSDL 2.0 and multi-document import-graphs are out of scope. An operator with
  a split contract merges it locally.
- Validation covers the **SOAP body against the embedded XSD** + the operation's expected body QName; it does
  **not** validate SOAP headers, WS-Security, or MIME/MTOM attachments (those stay ADR 0015 transport
  concerns).
- A partial contract (types only reachable via an unresolved import) **fails closed** — correct, but it means
  the operator must ship a self-contained WSDL to get a green validation.

## Alternatives considered

| Alternative | Why considered | Why rejected | Verdict |
|---|---|---|---|
| **Pure `parse_wsdl` + reuse `harden`/`schema`** *(chosen)* | No dep, no new attack surface, closes the `wsdl:import` seam | WSDL 1.1 / document-literal / embedded-schema first-class only; import-graphs fail closed | **Adopted** |
| **Add `zeep` (or `suds`)** | Full WSDL 1.1/2.0, dynamic client, type marshalling | Heavy transitive dep; drags a dynamic-proxy / codegen model in (declined authoring/#70 directions); large audit surface for a demand-gate niche | **Rejected (AVOID zeep)** |
| **Validate via `xmlschema` alone, no WSDL layer** | `xmlschema` already loads XSDs no-network | Loses the operation→message→element mapping (the actual ask); and `xmlschema`'s `allow="local"` does **not** govern `wsdl:import`, leaving that SSRF seam open | **Rejected** |
| **Resolve `wsdl:import` over the network** | Completes a split contract automatically | SSRF straight past the XSD lockdown on a new untrusted document class (CLAUDE.md §8) | **Rejected (fail-closed no-network)** |

## Testing strategy (required artifacts)

- Parse a single-document document/literal WSDL → the operation tree (names, soapAction, resolved input/output
  body element QNames).
- Validate a **conformant** request envelope → `valid=True`; a **non-conformant** one (wrong child, missing
  required element) → `valid=False` with **PHI-safe** reasons (QName/category, never content).
- Structural mismatch (a body element that is not the operation's expected element) → PHI-safe `valid=False`.
- **Security:** a WSDL with a **DOCTYPE** → refused (rides `harden.parse_bytes`); a `wsdl:import` /
  `xsd:import` with an **`http(s)://` location** → `WsdlSecurityError` (no-network seam), and the error names
  the scheme only, never the full URL.
- A malformed / non-WSDL XML document → `WsdlError` (a `ValueError` subclass, so a Handler's `except
  ValueError` routes it to the error/dead-letter path — count-and-log holds for free).
- The `[xml]` extra absence → the clear `RuntimeError` from `_deps` (distinct from the `ValueError` data
  errors), unchanged.

## Amendment (2026-11-10) -- any import location is refused, and the XSD build reads only inside its root (BACKLOG #5537, #5539)

Two statements above were false in the shipped code, and both are corrected here rather than in place.

- *"A relative/local location is not fetched either."* For a schema location it was. The guard refused
  only a location with a scheme or a `//host` authority, so a relative, rooted or Windows backslash UNC
  location passed. On an `xsd:import`, `xsd:include` or `xsd:redefine` inside an embedded schema,
  `xmlschema`, built with `allow="local"` and `base_url=None`, then resolved a relative location against
  the process's working directory and opened it. A `wsdl:import` location was never opened by anything;
  nothing reads it. `xsd:override` was never inspected at all, even with an `http:` URL. `parse_wsdl`
  now refuses **any** `location`/`schemaLocation`, an empty one included, on `wsdl:import`,
  `xsd:import`, `xsd:include`, `xsd:redefine` and `xsd:override` with `WsdlSecurityError`, naming the
  element and a well-known scheme, or the kind of reference ("a local path", "a network path"), never
  text from the location. An `xsd:import` that names only a `namespace` stays legal: it loads nothing
  of the author's, and a well-known namespace such as XML-DSig resolves to `xmlschema`'s bundled copy.
  This is the end state the decision above already asked for, a contract inlined into the one WSDL
  document.
- *"`schema.py` builds `xmlschema.XMLSchema(..., allow="local", base_url=None)`."* It still passes
  `allow="local"`, now with `defuse="always"` and an `opener` whose only handler reads `file:` URLs
  under two roots: `xmlschema`'s bundled schemas, and, for a schema given as a path, a confinement
  root, where each file is first checked by `parse_bytes`. The schema file the caller names is read
  as named, a link at that name included, and checked by `parse_bytes`; it is handed to `xmlschema`
  as a file URL, so an include that includes it back is recognised rather than loaded twice. A
  location that holds a newline or opens with `<`, which `xmlschema` would parse as an inline
  document past the opener, is refused in every schema document read. A location the opener
  refuses, at least a file under the root that declares a DOCTYPE or is malformed, a link the walk
  refuses (out of the root, to a UNC or device path, or through more than 32 links), a location
  that cannot be read as a file, such as a directory or a file the process may not read, under the
  root or in the bundled schemas, or a file
  outside the root, fails the build on an include, redefine or override, and on an
  import too, unless the refused file is the one the import names and `xmlschema` bundles a copy of
  that namespace: then the import falls back to that copy, as the stock W3C XML-DSig schema, which
  carries a DOCTYPE, needs. A refusal inside a file such an import did open still fails the build.
  A `schema_root` that is a filesystem root is refused, and so, on Windows, is a drive-relative
  schema path or `schema_root`, such as `C:`, `C:.`, `C:foo` or `file:///C:`, which resolves
  against that drive's own current directory. A plain relative one resolves against the working
  directory, the engine install root under the shipped Windows service, as it did before. Skipping
  any other
  refused import would leave its namespace undeclared, and a `lax` or `skip` wildcard would then admit
  that namespace's content unchecked. The confinement root is the schema's own
  directory, or the directory the caller passes as `validate_against`'s `schema_root` keyword. That
  keyword exists for a bundle whose schemas include across sibling directories: the HL7 CDA R2 entry
  schema includes `../../processable/coreschemas/...`, and IHE XDS bundles do the same, so confining
  them to the entry schema's directory refused a load that worked before. Below the root, each path is
  walked one component at a time with `lstat`, and a symlink or junction whose target text is a UNC or
  device path, or lies outside the root, is refused before it is followed. Nothing in `schema.py` calls
  `realpath`: on Windows it opens the path, and it rewrites a mapped drive to its UNC path and a long
  path to its `\\?\` form, which the text check would then refuse. An inline schema, which is how
  every embedded WSDL schema arrives, has no confinement root, so its own include, import, redefine or
  override location is opened only when it names a file in `xmlschema`'s bundled schemas. `xmlschema`'s
  `allow="sandbox"` was tried and not used: it compares URL string prefixes, narrows to each includer's
  directory, and blocks the bundled schemas.

The backslash UNC form did reach the network on the shipped configuration. Measured 2026-11-10 with
`xmlschema` 4.3.2 and Python 3.14 on Windows: an inline schema's `xs:include` of
`\\nonexist-5539.invalid\share\x.xsd` was normalised to `file:////nonexist-5539.invalid/share/x.xsd`
and opened, and failed with WinError 53, *"The network path was not found"*, so the open went to
Windows network-path resolution. Whether it would then have completed an SMB session against a live
host, and with which credentials, was not measured. An earlier reading of a different call shape saw
the form rewritten to a drive-rooted local path; it does not hold for this one. The guard refuses the
form, and the opener in `schema.py` refuses a UNC or device location on its text, before anything
touches it.
