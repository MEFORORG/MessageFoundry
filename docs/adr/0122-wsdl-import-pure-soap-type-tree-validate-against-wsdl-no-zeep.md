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
