# ADR 0004 — Payload-agnostic ingress (non-HL7 sources)

- **Status:** Accepted (2026-06-12) — ratified on the owner's go; the **ingress contract** (§1–§6, build
  order §7.1) is being built now, the non-HL7 *source* (§7.2) follows as a separate PR. The *direction*
  was already chosen in [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) §5 (option B). The four
  §"To resolve" leans are taken as the answers: **DB-IN first**; `RawMessage` = `.raw`/`.text`/`.json()`
  (`.xml()` shipped #31); a **callable** summary hook; a small `content_type` **enum**. (Proposed → Accepted
  same day.)
- **Built:** Nothing here yet. It builds on the **already-shipped** non-HL7 *destinations* (REST/DATABASE/
  SOAP, ADR 0003) and on a reliability core that is **already format-agnostic**: the staged queue +
  ingress/routed/outbound stages and the disposition finalizer
  ([store/store.py](../../messagefoundry/store/store.py) `_maybe_finalize_message`) carry no HL7 coupling
  (verified). What is HL7-specific is only the **parse/route/validate/ack** surface on the ingress path.
- **Supersedes:** ADR 0003's promise that "(B) is designed in a follow-up ADR before any non-HL7 source."
- **Related:** [ADR 0001](0001-staged-pipeline-architecture.md) (the staged pipeline this feeds),
  [CONNECTIONS.md](../CONNECTIONS.md) (the `REST-IN`/`DB-IN`/`SOAP-IN` rows marked "awaiting
  payload-agnostic ingress").

## Context

MessageFoundry's outbound migration is well covered (three non-HL7 destinations), but it has **no non-HL7
source**: the ingress hot path is HL7-centric. Per the grounding of
[wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py) `_handle_inbound` (~L502–565), each
received message is: **decode** bytes→text (generic) → **`Peek.parse`** ([parsing/peek.py](../../messagefoundry/parsing/peek.py),
HL7) → optional **strict-validate** ([parsing/validate.py](../../messagefoundry/parsing/validate.py),
hl7apy) → **`enqueue_ingress`** with `control_id` (MSH-10), `message_type` (MSH-9), and `summary`
([parsing/summary.py](../../messagefoundry/parsing/summary.py), PID/ORC) → **`build_ack`**
([transports/mllp.py](../../messagefoundry/transports/mllp.py), MLLP AA/AE/AR). The Router and each
Handler then receive an HL7 **`Message`** ([parsing/message.py](../../messagefoundry/parsing/message.py))
with `msg["MSH-9.1"]` / `.set()` / `.encode()` (built by `Message.parse` in
[pipeline/dryrun.py](../../messagefoundry/pipeline/dryrun.py)).

A database row, a JSON webhook body, or a SOAP request is **not** HL7. So a non-HL7 *source* must either
(A) emit an HL7 envelope, or (B) make ingress **payload-agnostic**. ADR 0003 chose **(B)**. The good news
from the grounding: **(B) is contained** — the reliability core (stages, handoffs, disposition machine,
count-and-log invariant) is already generic, and the ACK/NAK machinery is already MLLP-specific. The work
is a **`content_type` tag** + **branching the HL7-specific steps** + **a non-HL7 programming object** for
Routers/Handlers.

## Decision (proposed)

### 1. `content_type` is a per-inbound attribute, default `hl7v2`

Add `content_type: str` to `inbound(...)` and `InboundConnection`
([config/wiring.py](../../messagefoundry/config/wiring.py)), defaulting to **`hl7v2`** so **every existing
config is unchanged**. A non-HL7 source declares e.g. `inbound("REST-IN_…", …, content_type="json")`
(`json` | `xml` | `text` | `hl7v2`). It rides to the pipeline like `ack_mode`/`validation` do today
(`_source_config`).

### 2. Branch the HL7-specific ingress steps on `content_type`

In `_handle_inbound`: **decode stays generic**; then for `content_type == "hl7v2"` the path is exactly
as today (Peek → optional strict-validate → HL7-derived `control_id`/`message_type`/`summary` →
`build_ack`/NAK). For any other `content_type`, **skip** `Peek.parse` and `validate`, commit the decoded
raw to the ingress stage, and derive the store fields generically (§4). The synchronous **HL7 NAK** path
is untouched (it only applies to `hl7v2` over MLLP — see §6).

### 3. Routers/Handlers receive a polymorphic payload — HL7 `Message` *or* a generic `RawMessage`

Keep the **same** `RouterFn`/`HandlerFn` signatures and the same `Send` (which already accepts
`Message | str`). What changes is the object `route_only`/`transform_one` build from the raw, branched on
`content_type`:

- `hl7v2` → the HL7 **`Message`** (today's behavior, unchanged — full back-compat).
- otherwise → a new **`RawMessage`** exposing `.raw` (the decoded `str`), `.content_type`, and ergonomic
  accessors `.text` and `.json()` (parse the body to a `dict`/`list`; raises a clear error the Handler
  can turn into FILTERED/ERROR). Mutation is "produce a new outbound string" — a non-HL7 Handler returns
  `Send(to, some_str)` (e.g. a JSON string, a SOAP envelope), which the built destinations already accept.

Routers/Handlers are **code-first and bound to one inbound**, so the author knows which type they get; a
shared `Payload` protocol (`.raw`/`.content_type`) documents the common surface. (`Message` gains
`content_type = "hl7v2"` for symmetry.)

### 4. Store metadata for non-HL7 — generic, with an extension hook

`messages.message_type`, `control_id`, `summary` are HL7-derived today. For non-HL7: set
`message_type = content_type` (e.g. `"json"`), and **`control_id`/`summary` null by default** (the raw is
still stored verbatim, and the disposition/counts are unaffected — they're format-blind). Provide a small
**per-inbound extractor hook** (e.g. an optional callable, or later a declarative path) so an operator who
*wants* a searchable id/summary for a non-HL7 feed can populate them — designed now, the hook itself is a
follow-up. No schema change (the columns are already nullable text).

### 5. Validation is per-content-type; HL7 strict stays `hl7v2`-only

`validation.strict` (hl7apy) applies **only** to `hl7v2`; declaring it on a non-HL7 inbound is a
`WiringError` (fail loud). Schema validation for other types (JSON Schema, XSD) is a **future** opt-in,
not built here. Handler-level business validation already works content-agnostically (the Handler reads
the payload and returns `None`/raises).

### 6. ACK/NAK + disposition — the core is already generic

The **disposition state machine** (`RECEIVED → ROUTED/UNROUTED → FILTERED/PROCESSED/ERROR`,
`_maybe_finalize_message`) and the count-and-log invariant are **unchanged** — they already carry no HL7
coupling, so a non-HL7 message flows through them as-is. The **synchronous HL7 NAK** (and `build_ack`,
`AckMode`/`AckAfter`) is **MLLP/`hl7v2`-specific and stays that way**; a non-HL7 *source* owns its own
receive-time response (a DB poll marks the row processed; a webhook returns HTTP 2xx/4xx) — that lives in
the **source connector**, built per-source after this contract lands. A decode/parse failure on a non-HL7
inbound records `ERROR` (as today) and the source decides its wire response.

### 7. Build order

1. **This contract** — `content_type` plumbing + the ingress branch (§2) + `RawMessage`/`Payload` (§3) +
   generic store fields (§4), with the existing HL7 path untouched and fully regression-tested.
2. **The first non-HL7 source** — a **REST-IN webhook** *or* a **DB-IN poll** (the File source is the
   polling template; a webhook needs an HTTP listener the connector owns, kept out of `api/`). That's its
   own ADR-free build PR once this contract is accepted.

## Options considered

1. **(A) Source emits HL7 vs (B) payload-agnostic ingress.** (A) keeps the engine purely HL7 but forces
   non-clinical data into HL7 shape and buries mapping in the connector. **(B) CHOSEN** (owner, ADR 0003)
   — honest about a real non-HL7 estate; the grounding shows it's contained (generic core).
2. **Router/Handler input: a generic dict/tree vs the HL7 `Message` vs a polymorphic `Message |
   RawMessage` (CHOSEN).** A single generic object for *everything* would break every existing HL7 config
   (`msg["MSH-9.1"]`). Forcing non-HL7 through `Message` is wrong (no segments/fields). The polymorphic
   split keeps HL7 byte-for-byte compatible and gives non-HL7 an honest, simple `RawMessage`.
3. **Summary for non-HL7: null vs mandatory extractor vs hook (CHOSEN).** Mandating an extractor per feed
   is friction; null-with-an-optional-hook keeps v1 small and the searchable summary correct (empty, not
   wrong).

## Consequences

**Positive**
- Unblocks non-HL7 *sources* — the inbound half of non-HL7 integration (DB/REST/SOAP).
- **Zero change to existing HL7 configs** (`content_type` defaults to `hl7v2`; the HL7 path is untouched).
- Small surface: the reliability core, stages, and disposition machine don't move; only the
  parse/route input branches.

**Negative / risks**
- **Touches the hot path** (`_handle_inbound`, `route_only`/`transform_one`) — must be regression-tested
  hard so HL7 behavior is byte-identical; the branch adds a conditional to the busiest code.
- **A second Router/Handler programming model** (`RawMessage`) to document and support; the `Message |
  RawMessage` union is a slightly larger contract.
- **Searchability gap** for non-HL7 until an operator wires the summary hook (acceptable; the raw is
  retained and counts are exact).
- Non-HL7 **sources still don't exist** after this — this is the enabling contract, not a feature on its
  own; value lands with the first source.

## To resolve on acceptance

1. **`RawMessage` surface** — exactly `.raw` / `.text` / `.content_type` / `.json()`? Add `.xml()` (needs
   a safe parser — `defusedxml`, a new dep) now or later? (lean: `.raw`/`.text`/`.json()` now; `.xml()`
   when the first XML source needs it.)
   **Resolved (BACKLOG #31):** `.xml()` shipped, backed by `defusedxml` with `forbid_dtd` /
   `forbid_entities` / `forbid_external` all ON (raise-don't-parse on a DOCTYPE so a Handler routes the
   message to FILTERED/ERROR; mirrors `transports/soap.py::_assert_well_formed_fragment`). The
   `lxml`/XSD/`[xml]`-extra `XmlMessage` layer stays **deferred** to a real namespace-heavy SOAP/CDA feed
   (`defusedxml` does not cover `lxml`).
2. **First non-HL7 source** — **REST-IN webhook** or **DB-IN poll** first? (lean: DB-IN — it reuses the
   File polling template and needs no new listener; the migration's "Data Point DBs" want it.)
3. **Summary/id hook shape** — an optional per-inbound callable vs a declarative path expression. (lean:
   a callable now, declarative later.)
4. **`content_type` values** — the closed set (`hl7v2`/`json`/`xml`/`text`) as an enum, or a free string?
   (lean: a small enum, extensible.)

---

*On acceptance: build §7.1 (the ingress contract) as one PR behind the standard quartet gate, with the
existing HL7 ingress/route/transform tests proving byte-identical behavior; then the first non-HL7 source
as a second PR. Update CLAUDE.md §2/§8 (the "two-tier parsing"/ingress description) and
[CONNECTIONS.md](../CONNECTIONS.md) only when code ships.*

---

## Amendment (2026-07-17) — accept-time magic-byte content check per declared content_type (ASVS 5.2.2, WP #245)

The accept-time content sniff on the file sources is now a **per-`content_type` magic-byte check**,
dispatched by `ContentType` in `transports/file.py` `_content_matches_declared` (replacing the prior
hl7v2-only `_looks_like_hl7` gate): **HL7V2/None** → MSH/FHS/BHS head sniff (`_looks_like_hl7`, so the
hl7v2 path is byte-identical); **X12** → leading `ISA` (tolerating the same BOM/whitespace/`0x0b`/`0x0c`
leading noise the X12 codec's `find_isa_start` accepts); **DICOM** → the Part-10 128-byte preamble +
`DICM` magic at offset 128 (every DICOM object the engine produces or can parse carries it, so a
readable object never false-quarantines); **JSON/FHIR** → a leading `{`/`[` after BOM/whitespace (FHIR
is "HL7 FHIR JSON", so it shares the JSON magic — see the 2026-07-17 follow-up below); **XML** →
a leading `<`; **BINARY/TEXT** → accepted unchecked (binary is opaque bytes carried base64 per ADR 0028;
text is arbitrary — neither has a reliable leading signature). A drop whose leading bytes
contradict its declared `content_type` is quarantined to the source's `.error` dir with a WARNING —
never a silent drop — before its bytes reach the pipeline; the pipeline codec/parser remains the real
validator that records `ERROR`. The two sources **differ on `None`**: the local `FileSource` treats
`None` as hl7v2 (its historical default, sniff-on), while `RemoteFileSource` guards `is not None` and
skips the check on `None` (its stricter sniff-off default) — neither converges on the other. Conformant
traffic passes its magic-byte check, so a synthetic/CI box on conformant fixtures is byte-identical; no
new setting (an always-on accept-gate like the `_looks_like_hl7` gate it replaces). Known limit: only a
UTF-8 BOM is stripped for JSON/XML — a UTF-16-BOM document on a json/xml inbound would quarantine (use
`content_type=binary`/`text` for such payloads).

### Follow-up (2026-07-17) — narrow FHIR to the JSON shape (ASVS 5.2.2 → full Pass, #245)

The original amendment above left **FHIR** accepted unchecked ("deliberately not narrowed"), which held
ASVS 5.2.2 at **Partial** (a declared `content_type=fhir` inbound was the last file source that took a PDF
or other non-JSON drop without a content check). Since `ContentType.FHIR` is documented as **"HL7 FHIR
JSON"** (`config/models.py`) it is reliably JSON-sniffable, so `_content_matches_declared` now dispatches
FHIR through the **same** leading-`{`/`[` sniff as JSON (`case ContentType.JSON | ContentType.FHIR`). A
non-JSON body on a fhir inbound is now quarantined to `.error` like any other content-vs-type mismatch,
driving 5.2.2 to **Pass** in both postures (posture-independent — both `File` and `RemoteFile` dispatch
through the shared helper). Accepting a top-level `[` for FHIR is superset-permissive by design (a single
resource and a bundle are both `{…}`); the accept-gate can only admit more, and `parsing/fhir` stays the
real validator. **Only `binary` (opaque bytes) and `text` (arbitrary) remain unchecked** — an explicit,
honestly-noted policy: neither carries a reliable leading signature, so quarantining on shape would be a
false-positive risk with no security value.
