# ADR 0025 — DICOM codec + C-STORE store connectors

- **Status:** **Accepted (2026-06-20) — ratified on the owner's go.** Build may start (0028 is Accepted on main; per the land-order base64's carriage code + `RawMessage` additions merge first, then the DICOM codec/SCP build on `.raw_bytes`). Design-only (no code yet). **Ratified in lockstep
  with [ADR 0028](0028-base64-binary-carriage-codec.md)** (the base64 binary-carriage contract this ADR consumes for
  its binary payload — neither flips to Accepted until both are reconciled; this revision drops the original latin-1
  round-trip and cites 0028 §3, satisfying that hard prerequisite). The "To resolve on acceptance" confirmations are
  recommended at the positions stated below; on acceptance they are taken as the answers (the analog of
  [ADR 0012](0012-x12-edi-codec.md)'s `## Resolved` and [ADR 0022](0022-fhir-resource-codec-rest-client.md)'s
  `## Decision (proposed)` staying captioned "(proposed)" after the status bullet flips).
- **Built (this ADR):** Nothing here yet. It layers DICOM semantics over **already-shipped** substrate the way
  FHIR ([ADR 0022](0022-fhir-resource-codec-rest-client.md)) and X12 ([ADR 0012](0012-x12-edi-codec.md)) did — **with
  one substrate caveat those two did not have:** DICOM is a **binary** payload, and the shipped non-HL7 ingress path
  is **`str`-only**. That impedance is handled by **consuming the base64 binary-carriage contract**
  ([ADR 0028](0028-base64-binary-carriage-codec.md) §3): the SCP carries the object via
  `RawMessage.from_bytes(data, content_type="dicom")` (the one encode → `.raw = mfb64:v1:<base64>`) and the codec
  recovers the exact bytes via `RawMessage.raw_bytes` (the one decode), **not** by claiming the binary object rides
  the text branch unchanged and **not** via the lossy latin-1 round-trip (which corrupts across the store — §3, §4,
  *Negative/risks*). With that carriage in place it reuses:
  - the payload-agnostic ingress ([ADR 0004](0004-payload-agnostic-ingress.md)): `_handle_inbound`'s **non-HL7
    branch** ([wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py)) decodes a non-HL7 body, commits it
    to the ingress stage as `message_type = ic.content_type.value`, and hands the Router/Handler a **`RawMessage`**
    (`.raw`/`.text`/`.json()`/`.encode()` — [parsing/message.py](../../messagefoundry/parsing/message.py)). **That
    branch is `str`-typed end to end** (`raw.decode(encoding)`; `RawMessage(raw: str, …)`; `enqueue_ingress(raw:
    str)`), so DICOM rides it **only because the SCP commits the object as the ASCII-safe `mfb64:v1:` base64 form
    (via `RawMessage.from_bytes`) and the codec re-derives the exact bytes via `RawMessage.raw_bytes`** before
    parsing (§3/§4) — the routing/finalizer behaviour is then inherited, but the byte-faithful carriage is an
    explicit decision, not free.
  - the connector **registry** ([transports/base.py](../../messagefoundry/transports/base.py)) and the
    `SourceConnector`/`DestinationConnector` contracts the new C-STORE SCP source + the C-STORE SCU / DICOMweb
    STOW-RS destinations register into. The inbound **listen-source** template ([transports/mllp.py](../../messagefoundry/transports/mllp.py),
    `MLLPSource`) — bind-on-`start`, cooperative bounded-grace `stop`, commit-before-ACK — is the shape the SCP
    follows; the off-loop blocking-call + loop-bridge pattern is already used by `db_lookup`
    ([pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py) `_run_lookup`).
  - the staged queue + at-least-once / count-and-log invariant ([ADR 0001](0001-staged-pipeline-architecture.md))
    the SCP commits each received object into via `store.enqueue_ingress`
    ([store/store.py](../../messagefoundry/store/store.py)) **before** returning the C-STORE success status.
  - the fail-closed egress allowlist arms in [pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py)
    (`_allowlist_for` / `check_egress_allowed`) that the new outbound destinations fold into — DICOMweb (HTTP)
    into `allowed_http`, DIMSE (raw socket) into `allowed_tcp` — exactly the way X12 and FHIR added their arms.
  - **Net-new (not free) wiring this ADR must add — three additive `wiring_runner.py` edits, plus the bind-guard
    generalization:** the **two** egress branches above; a **third** edit adding `ConnectorType.DIMSE` to the
    `(MLLP, TCP, X12)` tuple in `_source_config` so the SCP listener inherits the bind-host injection + peer-IP
    allowlist passthrough (§6.4); and a **generalization of (or a sibling to) the MLLP-only `check_mllp_tls_exposure`
    guard** so a non-loopback cleartext DIMSE SCP is refused fail-closed (§6.4 / §9 — the existing guard does **not**
    cover TCP/X12/DIMSE today, so this is net-new security work, not a fold-in).
- **Decision in one line:** ship DICOM as **two decoupled pieces** — a pure, console-importable `parsing/dicom/`
  codec (a two-tier `DicomPeek`/`DicomDataset` plus DICOM→HL7 mapping helpers, backed by the optional `pydicom`
  library, referenced by the literal string `"dicom"`, imported on demand by code-first Routers/Handlers against
  a `RawMessage` whose bytes are recovered via `RawMessage.raw_bytes` — the base64 carriage of [ADR 0028](0028-base64-binary-carriage-codec.md) §3) **plus** DICOM **store connectors** under new additive
  `ConnectorType`s — a **Phase-1** inbound **C-STORE SCP** source (`DicomScpSource`, via `pynetdicom`, run **off the
  asyncio loop**, durable-commit-before-SUCCESS) so modalities/PACS can send images/SR, and **Phase-2 (design-now/
  build-later)** outbound **C-STORE SCU** + **C-ECHO** verification + a **DICOMweb STOW-RS** destination that
  **reuses `transports/rest.py`'s shared helpers** as a SIBLING connector (exactly as the SOAP and FHIR destinations
  do). The differentiator over the incumbents is that the SR→HL7 mapping (Corepoint "DICOM Gear") is a **code-first
  pure-Python Handler**, not a proprietary GUI mapper. It is the direct DICOM mirror of how X12 and FHIR shipped.
- **Related:** [ADR 0004](0004-payload-agnostic-ingress.md) (the `content_type` ingress path this rides;
  `RawMessage`), [ADR 0028](0028-base64-binary-carriage-codec.md) (the **binary-carriage contract** this ADR
  consumes — `RawMessage.from_bytes`/`.raw_bytes`/`.is_binary` + the `mfb64:v1:` marker; it **supersedes** the
  original latin-1 carriage and is **ratified in lockstep** with this ADR), [ADR 0012](0012-x12-edi-codec.md) (the pure `parsing/x12/` codec pattern + the optional-extra
  dependency rule + the dedicated-`ConnectorType` + the two security-parity egress branches **and the `_source_config`
  bind-host tuple edit** this mirrors), [ADR 0022](0022-fhir-resource-codec-rest-client.md) (the pure-codec-plus-
  transport split, the SIBLING-of-rest.py destination pattern, and the egress-arm fold this mirrors most closely),
  [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) (the REST destination + non-HL7 transport registry /
  optional-extra posture the DICOMweb destination builds on), [ADR 0010](0010-handler-callable-db-lookup.md) (the
  off-loop transform + `run_coroutine_threadsafe` loop-bridge the SCP's foreign-thread C-STORE handler reuses),
  [ADR 0001](0001-staged-pipeline-architecture.md) (the staged queue + at-least-once / count-and-log + ACK-on-receipt
  invariant the SCP's commit-before-SUCCESS satisfies), **backlog #7 / ADR 0023** (the future inbound HTTP listener
  that an inbound DICOMweb STOW-RS *receiver* is gated on — not designed here; ADR 0023 is not yet authored, so the
  backlog #7 handle is the canonical reference), [CLAUDE.md](../../CLAUDE.md) §1/§2/§4/§6/§8/§9 (no-grouping-unit
  graph, code-first logic, the pure `parsing/` library + console carve-out, asyncio off-loop discipline, two-tier
  parsing, PHI rules), [CONNECTIONS.md](../CONNECTIONS.md), [PHI.md](../PHI.md), and the project backlog DICOM line
  item.

## Context

The migration estate is not all HL7-over-MLLP. **DICOM** (Digital Imaging and Communications in Medicine) is the
imaging interoperability lane — radiology modalities, PACS, and reporting systems exchange image objects and
**DICOM Structured Reports (SR)** over the DIMSE network protocol and, increasingly, over **DICOMweb** HTTP.
MessageFoundry has **no DICOM support today**.

**The driver is a named potential adopter** — a radiology practice currently on **Corepoint's DICOM option
("DICOM Gear")** that wants to move to MessageFoundry. It is important to be precise about what the incumbents
actually do, because it scopes this ADR:

- **Corepoint "DICOM Gear" is primarily a TRANSFORMATION tool.** It receives DICOM objects, parses the **DICOM
  header** and **DICOM SR**, and **maps them into HL7 v2** — e.g. SR measurements → HL7 **ORU/OBX** feeding a
  PowerScribe 360 dictation workflow, and header fields → HL7 **orders** to a RIS. The value the radiology
  practice buys is the *mapping*, expressed in Corepoint's proprietary GUI.
- **Mirth Connect's DICOM is narrower:** a **C-STORE SCP** listener (receive) + a **C-STORE SCU** sender (send),
  and nothing more — no Modality Worklist (MWL), no Query/Retrieve. It is a transport, not a transformer.

**Why the engine model fits — via codec + a code-first transform.** MessageFoundry's differentiator is exactly
the piece Corepoint sells behind a GUI: the SR→HL7 / header→HL7 mapping is a **pure-Python Handler**, authored
code-first against the `messagefoundry` surface, versioned in the org's config repo, unit-testable with no socket.
The "replace the DICOM Gear value" demo is therefore: **receive an SR object → a Router peeks the modality / SOP
class → a Handler extracts the SR measurements and builds an HL7 v2 ORU with OBX segments → an outbound MLLP
connection delivers it to PowerScribe.** This is the same shape as every other non-HL7 lane the engine already
runs (X12, FHIR): a pure codec parses on demand, a code-first Handler maps, the engine stays format-blind.

The *ingress contract* for "not HL7" already exists ([ADR 0004](0004-payload-agnostic-ingress.md)): a non-`hl7v2`
inbound skips the HL7 peek/validate/ACK, commits the body, and the Router/Handler receive a generic **`RawMessage`**.
So — as with X12 and FHIR — the *routing/finalizer wiring is reused*; what is missing is **(a)** a way to
*parse/route/transform* DICOM from a code-first Router/Handler, **(b)** a *transport* that can receive a DICOM
object off the wire (the inbound C-STORE SCP) and, later, send one (the outbound SCU / DICOMweb STOW-RS), and
**(c)** — the one piece FHIR/X12 did not need — a **byte-faithful** way to carry a *binary* object through the
`str`-typed ingress/store/RawMessage substrate (the base64 carriage of [ADR 0028](0028-base64-binary-carriage-codec.md) §3, below).

Four facts shape the design and make it a near-clone of [ADR 0022](0022-fhir-resource-codec-rest-client.md), **with
one genuine deviation** (the binary impedance):

- **DICOM is a BINARY payload — the shipped non-HL7 ingress path is `str`-only.** This is the one place DICOM does
  **not** ride the FHIR/X12 precedent unchanged, and it is called out here so the build does not assume "free."
  X12 and FHIR work over the non-HL7 branch because both are **text** (X12 is delimited ASCII/EBCDIC segments;
  FHIR is JSON/XML). A DICOM **Part-10** object is binary — a 128-byte arbitrary-byte preamble + `'DICM'` + binary
  transfer-syntax-encoded value representations (`OB`/`OW`/`UN`, little/big-endian, possibly encapsulated) — and is
  **not valid UTF-8**. The shipped branch decodes with a **strict** codec (`raw.decode(encoding)`, default `utf-8`
  — [wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py) `_handle_inbound`), stores a **`str`**
  (`Store.enqueue_ingress(raw: str)` / `record_received(raw: str)` across all three backends —
  [store/store.py](../../messagefoundry/store/store.py)), and `RawMessage.__init__(self, raw: str, …)` /
  `.raw`/`.text`/`.encode()` are all **`str`** ([parsing/message.py](../../messagefoundry/parsing/message.py)).
  Fed a DICOM object under the default encoding, `raw.decode("utf-8")` raises `UnicodeDecodeError`, the object
  dead-letters as `ERROR`, and **nothing is stored** — violating the §9 / scope-contract "preserve + store the raw
  received object" PHI rule. **A naive latin-1 round-trip does not save it, either:** latin-1 maps every byte
  `0x00–0xFF` to a codepoint, so a DICOM object becomes a `str` carrying `NUL` (U+0000) — and a Part-10 object's
  mandatory **128-byte all-zero preamble guarantees 128 of them**. A `NUL`-bearing parameterized string is
  **rejected at psycopg bind on Postgres** and **silently truncated on SQLite / SQL Server** (the `str`/TEXT store
  columns + identity cipher carry it verbatim), so latin-1 reintroduces exactly the corruption it claims to avoid.
  **Decision (§3/§4 — consume [ADR 0028](0028-base64-binary-carriage-codec.md) §3):** the DICOM SCP carries the
  object via `RawMessage.from_bytes(data, content_type="dicom")` — the one encode, producing `.raw =
  mfb64:v1:<base64>` — and the codec re-derives the exact original bytes via `RawMessage.raw_bytes` (the one decode)
  before handing them to `pydicom`. base64's ASCII alphabet (`[A-Za-z0-9+/=]`) has **no `NUL`, no HL7 delimiter, no
  CR/LF**, so it rides the `str`/TEXT store and the identity/AES-GCM cipher unchanged and the recovered bytes are the
  original object verbatim. Never `utf-8`, never `errors="replace"`, never latin-1. (A bytes-native
  `RawMessage`/`enqueue_ingress`/store column is the structurally heavier alternative; it is a real, non-additive
  substrate change to the forbidden ingress hotspots and all three store backends and is therefore **not** chosen
  here — see *Options #7* and *To resolve on acceptance*.)
- **DICOM is self-describing, but DIMSE is not HTTP-shaped.** A DICOM object's structure (the tag dictionary, the
  transfer-syntax encoding) is intrinsic — a standard DICOM parser knows the boundaries. But the **network**
  framing is the DIMSE upper-layer protocol (association negotiation, PDUs), which is **not** an HTTP body or a
  delimited byte stream. So unlike FHIR (which rides HTTP and reuses `rest.py`), the *inbound DIMSE* path needs a
  real **association-accepting server** (`pynetdicom`), and unlike X12 it cannot be a thin socket — `pynetdicom`'s
  AE server is **blocking/threaded, not asyncio-native**, which is the central asyncio-correctness problem this ADR
  solves (§3). The *outbound DICOMweb* path, by contrast, **is** HTTP and **does** reuse `rest.py`.
- **A real, vetted library exists.** DICOM's data model is large, version-specific, and conformance-bearing, so a
  **typed library is the right call** (as with FHIR, against X12's hand-roll). **`pydantic`-free, pure-Python**
  options exist: **`pydicom`** (the DICOM dataset/SR codec) and **`pynetdicom`** (the DIMSE network stack, built on
  `pydicom`). Both are pure-Python and — crucially for §9 — usable for **headers + SR only with NO `numpy`** (numpy
  is `pydicom`'s *optional* pixel-data dependency; this ADR never touches pixel data, so numpy is never pulled).
  The picks ride the CLAUDE.md §5/§7 verify-before-add gate at the dep-vet (§7 below).
- **The whole DICOM object is PHI.** A DICOM dataset carries `PatientName`, `PatientID`/MRN, and DOB in the header,
  **and** pixel data can carry burned-in PHI. The received object is treated as a **PHI body**, identical to an HL7
  message body: stored through the encrypting store path (byte-exact via the `mfb64:v1:` base64 carriage, [ADR
  0028](0028-base64-binary-carriage-codec.md) §3), never logged at INFO+, egress-allowlisted, TLS on the wire
  off-loopback (§9). (base64 is **encoding, not obfuscation** — the carried body is still PHI and the no-log rules
  apply unchanged.)

The same two project constraints that shaped X12 and FHIR apply verbatim:

- **No grouping unit / code-first logic** ([CLAUDE.md](../../CLAUDE.md) §1/§4). DICOM logic (which modality / SOP
  class goes where, how an SR maps to an HL7 v2 ORU) belongs in **code-first Routers/Handlers**, not a new
  declarative DICOM-mapping surface or a bespoke object pushed through the engine. The SR→HL7 mapping is a
  **Handler**, never a declarative mapper — this is the explicit anti-Corepoint-GUI position.
- **Payload-agnostic, hot-path-cheap** ([CLAUDE.md](../../CLAUDE.md) §8). Routing must not force a full validated
  parse; the DICOM analog of "read the separators from MSH" is a **shallow tag read** of routing-relevant elements
  (`Modality`, `SOPClassUID`, the calling/called **AE Title**, `StudyInstanceUID`) — no full `pydicom.Dataset`
  walk on the hot path.

## Decision (proposed)

DICOM ships as **two decoupled pieces** wired through existing seams, closely mirroring FHIR and X12. Edits to the
engine hotspots are **additive only**; **no routing-logic** in `pipeline/wiring_runner.py` (`_handle_inbound`,
`route_only`, `transform_one`) or `pipeline/dryrun.py` (`_payload`) is touched. **Three additive `wiring_runner.py`
edits** are required — two `ConnectorType`-keyed egress branches and one `_source_config` bind-host tuple entry for
the SCP listener — **plus a generalization of the (currently MLLP-only) non-loopback-TLS bind-guard** so the SCP is
not fail-open (§6.4). All are the same kind of additive, type-keyed edits X12 and FHIR added, not pipeline routing
logic. Nothing DICOM-typed is added to the `Payload` union (`Message | RawMessage`); nothing in `pipeline/` learns
DICOM. The one genuine substrate deviation from FHIR/X12 — that a **binary** object is carried through a `str`-typed
ingress via the base64 carriage of [ADR 0028](0028-base64-binary-carriage-codec.md) §3 (`RawMessage.from_bytes` at
the SCP, `.raw_bytes` in the codec — Context, §3, §4) — is handled at the SCP/codec boundary, not by teaching the
pipeline.

### 1. A pure, console-importable codec at `parsing/dicom/` (NOT pushed through the pipeline)

A new package mirroring [parsing/fhir/](../../messagefoundry/parsing/fhir) and [parsing/x12/](../../messagefoundry/parsing/x12)
— **pure, side-effect-free, zero I/O, zero engine imports** (so the console may import it for a client-side DICOM
tag-tree viewer — the §4 Parse-Tree analog, the §4 carve-out). Every module carries the
`# SPDX-License-Identifier: AGPL-3.0-or-later` header and `from __future__ import annotations`. **It must import
nothing from `messagefoundry.config`, `pipeline`, `store`, or `transports`** — internal imports are sibling-only —
and it refers to the DICOM content type by the **literal string `"dicom"`** (never `ContentType.DICOM`), so a
console import of `parsing.dicom` pulls in no engine. Two purity tests guard this (§5).

It is **two-tier**, mirroring the project's python-hl7(tolerant)/hl7apy(strict) split and FHIR's
`FhirPeek`/`FhirResource`:

- **`DicomPeek`** ([parsing/dicom/peek.py](../../messagefoundry/parsing/dicom)) — the **tolerant routing peek**
  (the hot-path analog of HL7 `Peek` / `X12Peek` / `FhirPeek`). A frozen dataclass with a `DicomPeek.parse(raw, *,
  ...) -> DicomPeek` classmethod taking `RawMessage | bytes`. **It treats the input as untrusted DATA** and recovers the
  object bytes via `RawMessage.raw_bytes` when handed a `RawMessage` (the one decode — [ADR 0028](0028-base64-binary-carriage-codec.md) §3; or uses raw `bytes` directly — never base64-decoding a bare `str` itself), then does a
  **cheap, shallow tag read** of routing-relevant elements **without constructing a full dataset walk** — using
  `pydicom`'s lazy/`stop_before_pixels=True`, `specific_tags=[…]` read so the pixel data is never materialised:
  - `sop_class_uid: str | None` (`(0008,0016)` — the object-type discriminator, the DICOM analog of MSH-9; the
    Enhanced/Basic SR class UIDs are how a Router recognises an SR);
  - `modality: str | None` (`(0008,0060)` — `CT`/`MR`/`US`/`SR`/…);
  - `study_instance_uid` / `series_instance_uid` / `sop_instance_uid` (the study/series/instance identity);
  - `transfer_syntax_uid: str | None` (the encoding the object arrived in);
  - the negotiated **AE titles** when the peek is fed them by the SCP (`calling_ae_title` / `called_ae_title` —
    a Router most often filters on the source modality's AE Title).
  - Optionally **`is_structured_report() -> bool`** (true for the SR SOP classes) so a Router branches SR vs image
    without a full parse.
  - Raises **`DicomPeekError`** on unparseable/non-DICOM input.
  The peek reads only the **file-meta + a handful of header tags** — never the SR content tree, never pixel data,
  never a declared length it trusts blindly (`stop_before_pixels` bounds the header).
- **`DicomDataset`** ([parsing/dicom/dataset.py](../../messagefoundry/parsing/dicom)) — the **full, navigable
  model** for transforms (the strict/slow path, the HL7 `Message` / `FhirResource` analog), backed by `pydicom`.
  `DicomDataset.parse(raw, *, ...) -> DicomDataset` recovers the bytes (via `RawMessage.raw_bytes`, the [ADR 0028](0028-base64-binary-carriage-codec.md) §3 decode, §3/§4)
  and constructs the dataset (`stop_before_pixels=True` — **headers and SR only, NO pixel data**); typed read of
  header elements by keyword/tag; and an **SR walk** that traverses the SR `ContentSequence` (the `pydicom`
  `codes`/value-type tree) to extract **measurement and coded content** (each `NUM` content item's concept-name
  code, measured value, and units; `CODE`/`TEXT` items as needed). This is **not** the hot path — it is constructed
  on demand inside a Handler. `pydicom` is the import that pulls the optional `[dicom]` extra; `DicomDataset.parse`
  raises a clear, actionable **`RuntimeError`** if the extra is not installed (mirroring how `FhirResource.parse`
  and the SQL-Server/Postgres connectors fail when their extra is absent). **That missing-extra `RuntimeError` is
  deliberately OUTSIDE the `ValueError` dead-letter contract:** it is a deploy/config error, not a data error, so a
  Handler's `except ValueError` will **not** catch it — an install without the `[dicom]` extra surfaces as an
  internal error / connection failure, **not** a per-message `ERROR` disposition (identical to ADR 0022's FHIR
  posture).
- **DICOM→HL7 mapping helpers** ([parsing/dicom/hl7_map.py](../../messagefoundry/parsing/dicom)) — pure functions a
  **code-first Handler** calls to build HL7 v2 from a parsed `DicomDataset`: **header → ORM/ORU fields** (patient,
  study, accession, ordering-provider fields drawn from the standard header tags) and **SR content → OBX** (each SR
  `NUM` measurement → an HL7 `OBX` segment with the coded concept name in OBX-3, the value in OBX-5, the units in
  OBX-6). These are **helpers** the Handler composes — they build segments/fields the Handler assembles into a
  python-hl7 `Message`; they are **not** a declarative mapper and **not** invoked by the pipeline. The Handler owns
  the mapping decisions (which measurements, which message type, which target); the helpers spare it the
  boilerplate of the standard tag→field correspondences. This is the code-first replacement for Corepoint's GUI
  mapper.
- **`DicomError(ValueError)`** base → **`DicomPeekError(DicomError)`** (the `FhirPeekError` analog). Deriving from
  `ValueError` means a Router/Handler already routing `ValueError` to the dead-letter path catches malformed/
  non-DICOM bodies **without special-casing** — the count-and-log invariant (never accept-and-drop) holds for free.
  (The missing-extra `RuntimeError` above is intentionally **not** a `DicomError` — it is not a data error.)
  **PHI rule (do not break):** `DicomError`/`DicomPeekError` messages — and *any* codec/transport log line — carry
  only **routing-safe identifiers** (`SOPClassUID`, `Modality`, a study/series/instance UID, an AE Title), **never
  the dataset, an element value, or pixel data**; the full PHI-bearing object goes only to the secured store, the
  same way `rest.py` logs `_redact_url(...)` not the URL/body (§9 / [CLAUDE.md](../../CLAUDE.md) §9 — never log a
  full payload at INFO or above; never raise the service to DEBUG in prod).

Routers/Handlers call this library **on demand** against the `RawMessage` (`DicomPeek` to route, `DicomDataset` +
the mapping helpers to transform), the codec recovering the original bytes via `RawMessage.raw_bytes` ([ADR 0028](0028-base64-binary-carriage-codec.md) §3, §3/§4).
**Nothing DICOM-typed is added to the `Payload` union**, and **nothing in `pipeline/` is taught about DICOM**.
DICOM ↔ HL7 v2 **mapping stays in code-first Handlers** — `DicomDataset` in → python-hl7 `Message` out, hand-authored
— **never** in the connector/codec/pipeline. Headers/SR only; **no pixel-data manipulation, no `numpy`** (Out of
scope) — which is also a **security boundary**, not just a dependency note: with no pixel decode there is no
pixel-decompression-bomb surface (§9, *Negative/risks*).

### 2. DICOM store connectors — a Phase-1 C-STORE SCP source + Phase-2 SCU / C-ECHO / DICOMweb STOW-RS destinations

**Phase 1 (build now, once Accepted) — `DicomScpSource` (inbound C-STORE SCP).** A `SourceConnector`
([transports/base.py](../../messagefoundry/transports/base.py)) at
[transports/dicom.py](../../messagefoundry/transports) that runs a `pynetdicom` **Application Entity (AE)
C-STORE SCP**, so modalities/PACS can **send** image and SR objects to MessageFoundry. It mirrors `MLLPSource`'s
listen-source shape — `polls_shared_resource = False`, binds its own port, ignores `leader_gate` — but the AE
server is blocking/threaded, so it runs **off the asyncio event loop** and bridges each received object back onto
the loop (§3). Its per-association C-STORE handler commits each received dataset durably to the **ingress stage**
**before** returning the C-STORE **SUCCESS** status (§3 — the DIMSE analog of MLLP's commit-before-ACK), committing
the object via `RawMessage.from_bytes(..., content_type="dicom")` so the byte sequence is preserved exactly through
the `str`-typed store as the ASCII-safe `mfb64:v1:` base64 form ([ADR 0028](0028-base64-binary-carriage-codec.md) §3, §3/§4),
and returns the C-STORE response itself (no engine-built reply — like the File/non-HL7 sources, `self._handler(...)`
returns `None` and the connector owns its own receive-time DIMSE response). Settings: the SCP's **AE Title**, bind
host/port (default DICOM port **104**), the accepted **presentation contexts** (the SOP classes + transfer
syntaxes it negotiates — defaulting to the SR and common image storage classes), a **calling-AE allowlist** (which
peer AE Titles + IPs may associate), a **`max_object_bytes` per-object size cap** (rejecting an over-cap C-STORE
with a failure DIMSE status **before** the durable commit — the count-and-log-safe analog of X12's
`max_interchange_bytes`; §9), DoS caps (max associations, PDU size, association/DIMSE timeout), and the TLS context
(§9). It registers under a new `ConnectorType.DIMSE` via `register_source`.

**Phase 2 (design now, build later) — outbound parity + the modern HTTP path.** Designed here so the seams are
right; built behind the Phase-1 slice:

- **`DicomScuDestination` (outbound C-STORE SCU)** — a `DestinationConnector` that **sends/forwards** a DICOM
  object to a downstream PACS via a C-STORE association (full **Mirth-sender parity**). Same `ConnectorType.DIMSE`
  transport family, host/port + called/calling AE Title settings; runs the blocking association off the loop
  (`asyncio.to_thread`), raises `DeliveryError` (transient — pipeline retries) / `NegativeAckError(permanent=True)`
  (the SCP refused with a non-retryable DIMSE status → dead-letter) from `send`. The outgoing object's bytes are
  recovered from the `str` payload via `RawMessage.raw_bytes` ([ADR 0028](0028-base64-binary-carriage-codec.md) §3) before the association (§3/§4).
- **C-ECHO verification (SCU + SCP)** — DICOM's connectivity ping (table stakes both incumbents have). The
  `DicomScpSource` accepts the **Verification SOP Class** so a peer can C-ECHO it; `DicomScuDestination.test_connection`
  issues a **C-ECHO SCU** (the `probe_tcp_reachable` analog for DIMSE) so the console's "Test Connection" works.
- **`DicomWebDestination` (outbound DICOMweb STOW-RS)** — the modern HTTP imaging path that **exceeds both
  incumbents** (neither Mirth's nor Corepoint's DICOM option ships DICOMweb send out of the box). It is its own
  **`DestinationConnector` subclass** that **reuses the shared module-level helpers** in
  [transports/rest.py](../../messagefoundry/transports/rest.py) — **exactly as the SOAP and FHIR destinations do**.
  `SoapDestination`/`FhirDestination` are *not* wrappers of `RestDestination`; each is a sibling `DestinationConnector`
  that imports rest.py's `_NO_REDIRECT_OPENER`/`_NoRedirectHandler`, `_insecure_opener`, `_redact_url`,
  `enforce_outbound_length_limits`, `refuse_cleartext_credentials`, the `_RETRYABLE_4XX` retry idiom, plus
  `signer_from_destination` — and follows rest.py's status→retry idiom. `DicomWebDestination` does the **same**: it
  **does not compose or instantiate `RestDestination`**, and it does **not** re-implement HTTP. It implements the
  `DestinationConnector` contract: one `async def send(self, payload: str) -> DeliveryResponse | None`, optional
  `aclose`/`test_connection` overrides, and it raises **only** `DeliveryError`/`NegativeAckError` from the delivery
  path. **Added on top of REST (the net-new logic):** the STOW-RS **`multipart/related; type="application/dicom"`**
  request body framing (one or more DICOM instances POSTed to `{base}/studies` or `{base}/studies/{StudyInstanceUID}`),
  the STOW-RS `Accept: application/dicom+json` response handling, and parsing the **STOW-RS response** (the
  per-instance `FailedSOPSequence` → a permanent `NegativeAckError`; a transport 5xx/timeout → a transient
  `DeliveryError`). The framing/UID reads come from `DicomPeek` against the outgoing object (cheap, no full parse).
  It registers under a new `ConnectorType.DICOMWEB` via `register_destination`. **`dicomweb-client`** (MIT) is a
  permissible alternative for the multipart/response handling, but **prefer reusing `rest.py`** if practical — the
  multipart framing is modest and the sibling-of-rest.py pattern keeps the HTTP plumbing (TLS posture, redirect
  refusal, cleartext-credential refusal, the retry/dead-letter classification, the JWS/mTLS hooks, the egress
  gate) in one place; Options #3 weighs both.

All connectors are **one-way dependent**: `transports/dicom.py` imports `parsing/dicom/` (for `DicomPeek` to read
the object's SOP class/UIDs) and — for the DICOMweb destination — `transports/rest.py`'s helpers, **never the
reverse** — preserving the dependency direction and the console carve-out.

### 3. The C-STORE SCP runs OFF the asyncio loop, carries the binary object byte-faithfully, and commits-before-SUCCESS

`pynetdicom`'s `AE.start_server`/association handling is **blocking/threaded, not asyncio-native** — so the SCP
must never run it on the event loop, and its C-STORE handler executes on a **foreign (pynetdicom acceptor)
thread**, not the loop. The project already has the exact pattern for this — `db_lookup`'s off-loop transform +
`run_coroutine_threadsafe` bridge ([ADR 0010](0010-handler-callable-db-lookup.md),
[wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py) `_run_lookup`):

- **`start(handler, *, leader_gate=None)`** captures the running loop (`self._loop = asyncio.get_running_loop()`,
  exactly as `RegistryRunner` does) and starts the `pynetdicom` AE server **off the loop** (it owns its own
  acceptor threads; `start` returns once it is accepting associations). `leader_gate` is ignored — a DICOM SCP
  binds its own per-node port (a listen source, no shared-resource double-read).
- **The C-STORE handler** (the `evt.EVT_C_STORE` callback, running on the pynetdicom thread):
  - **encodes the received dataset to its Part-10 bytes and carries them via `RawMessage.from_bytes(dataset_bytes,
    content_type="dicom")`** — the one base64 encode ([ADR 0028](0028-base64-binary-carriage-codec.md) §3). Because
    `enqueue_ingress` / the store column / `RawMessage` are `str`-typed, the object is committed as the ASCII-safe
    `mfb64:v1:<base64>` form (never `utf-8`, never `errors="replace"`, never latin-1 — whose `NUL`s a Part-10
    preamble guarantees and the store would reject on Postgres / truncate on SQLite/SQL Server), and the §1 codec
    re-derives the exact bytes via `RawMessage.raw_bytes` (the one decode). This is why the stored raw round-trips
    byte-exact and the store cipher operates on a `NUL`-free ASCII body — there is **no** UTF-8 decode of a binary
    body, so no `UnicodeDecodeError` and no silent corruption.
  - reaches back into the loop-owned store via **`asyncio.run_coroutine_threadsafe(store.enqueue_ingress(...),
    self._loop)`** and blocks **the worker thread** (never the loop) on `future.result(timeout)` for the durable
    commit. It **never** calls an `async` store method directly from the SCP thread, and it does no blocking DICOM
    I/O on the loop.
  - **Timeout failure policy (explicit — this protects the commit-before-SUCCESS / no-duplicate invariant).**
    `future.result(timeout)` raising `concurrent.futures.TimeoutError` does **not** cancel the already-scheduled
    `enqueue_ingress` coroutine — it may still commit on the loop afterward. So on timeout the handler returns a
    **DIMSE failure** status (never a false SUCCESS — a dropped, uncommitted object must be re-sent), and the commit
    **must be idempotent against the SCU's re-send** (de-dupe on `SOPInstanceUID`, or accept a documented duplicate
    re-ingest). Returning SUCCESS on a timeout where the commit never landed would silently drop and break
    count-and-log; returning failure after a commit that *did* land yields a re-sent duplicate the idempotency rule
    absorbs. The **timeout budget** must account for `enqueue_ingress` serializing on the store's `asyncio.Lock`
    (so under many concurrent associations a healthy commit can legitimately wait behind the lock) plus the WAL
    commit — set it generously enough that the timeout fires only on a genuinely stuck loop, not on expected
    concurrent load. (See *To resolve on acceptance*.)
- **Durable-commit-before-SUCCESS** — the count-and-log + ACK-on-receipt analog ([ADR 0001](0001-staged-pipeline-architecture.md),
  [CLAUDE.md](../../CLAUDE.md) §2). The handler returns the C-STORE **`0x0000` (Success)** status **only after**
  the received object (the full object bytes, carried as the `mfb64:v1:` base64 form) is durably committed to the **ingress
  stage** (`store.enqueue_ingress`, status `RECEIVED`, `message_type = "dicom"`, `summary=None`) through the loop
  bridge. This is the DIMSE-level equivalent of "AA-on-receipt": the raw is durable before SUCCESS, and
  routing/transform/delivery happen later in the staged workers.
  - **Cheap, legitimately-rejectable receive-time failures** (a dataset that will not decode, an abstract-syntax /
    SOP-class the SCP did not negotiate, a body that cannot be peeked, **or an object over `max_object_bytes`**)
    return a **failure DIMSE status** synchronously **before** the enqueue — the C-STORE analog of MLLP's
    synchronous AE/AR NAK.
  - **Any post-commit failure** (routing/transform/delivery) **MUST NOT** turn into a C-STORE failure status — it
    is a logged `ERROR`/dead-letter disposition + AlertSink, exactly as post-ACK MLLP failures are. Returning
    Success **before** the object is durable would silently drop on crash and break count-and-log; returning
    Failure **after** a durable commit would make a healthy ingest re-send a duplicate.
- **At-least-once + purity** — the SCP commits the raw exactly once per received object; a crash/cancel **before**
  the ingress commit just means the SCU re-sends (at-least-once holds). Because a re-run re-derives output, the
  SR→HL7 Handler must be **pure** (CLAUDE.md §2) — message in → message out, no side effects (the SR→ORU mapping
  is a deterministic transform); any live read uses the sanctioned `db_lookup` (ADR 0010), which already raises on
  a Router and in dry-run.
- **Cooperative cancellation + clean shutdown** ([CLAUDE.md](../../CLAUDE.md) §2/§6) — `stop()` is `async def` (it
  mirrors `MLLPSource.stop()` and is awaited on the loop by `RegistryRunner`), so its **blocking** steps must run
  **off the loop**, or shutting one SCP down would stall every other listener/worker/retry-timer/API call for the
  whole grace window: (1) stop accepting **new** associations; (2) let an in-flight C-STORE that has already begun
  its durable commit finish (a crash/cancel before the commit just means a re-send); (3) shut the `pynetdicom` AE
  server down under a **bounded grace** via `await asyncio.to_thread(self._ae.shutdown)` (the blocking
  `AE.shutdown()` never runs on the loop), then abort stragglers; (4) **join the off-loop server thread** via
  `await asyncio.to_thread(self._server_thread.join, grace)` with a bounded timeout and an abort path for a
  straggler that will not join. So `async def stop()` **never blocks the event loop**. It responds to
  `RegistryRunner`'s stop and is reachable from the ASGI-lifespan `engine.stop()`; resource teardown is idempotent
  (the `aioodbc` `aclose()` analog — safe if nothing was ever opened).

### 4. Ingress rides the existing payload-agnostic branch — byte-faithfully, via the base64 carriage (ADR 0028 §3)

`content_type="dicom"` rides the **existing** non-HL7 branch ([ADR 0004](0004-payload-agnostic-ingress.md)) for
**routing/transform/finalizer** behaviour, but **not for free as a binary payload** — the branch is `str`-typed
(`raw.decode(encoding)`; `enqueue_ingress(raw: str)`; `RawMessage(raw: str, …)`), and a binary DICOM object is not
UTF-8-decodable, while a latin-1 ride would carry `NUL`s the store rejects/truncates (Context, §3). DICOM therefore
rides it **only because the SCP commits the object via `RawMessage.from_bytes(..., content_type="dicom")`** — the one
base64 encode, producing the ASCII-safe `mfb64:v1:` form (so the stored raw round-trips byte-exact) — and **the codec
re-derives the bytes via `RawMessage.raw_bytes`** before parsing ([ADR 0028](0028-base64-binary-carriage-codec.md)
§3). With that carriage: the transform worker passes `"dicom"` as `RawMessage.content_type`, the engine stays
**format-blind** (no HL7 parsing of a DICOM object, no DICOM-typed object in the `Payload` union, nothing in
`pipeline/` learns DICOM), and a DICOM Handler reads the `RawMessage` (`.is_binary` is true; `.raw_bytes` recovers
the exact object) and calls the codec on demand. **No `_handle_inbound`/`_peek_for_loopback`/`dryrun._payload`
routing-logic edit is needed** — the existing `if not hl7v2:` and the non-`HL7V2` `_peek_for_loopback` branch already
handle any non-`HL7V2` value generically. **Note the dryrun caveat:** `dryrun._payload` UTF-8-decodes a `bytes` body
(`raw.decode("utf-8")`) — a raw binary DICOM object fed to `dryrun` directly would not decode, so the SCP path (which
commits the `mfb64:v1:` `str` via `from_bytes`) is the supported ingress; a binary `.dcm` fixture for `dryrun` must
be supplied already **base64-carried** (the `mfb64:v1:` form — the §8 sample fixture is generated as such).
Malformed/non-DICOM input — including a corrupt carried body, which surfaces as `BinaryCarriageError` from
`.raw_bytes` ([ADR 0028](0028-base64-binary-carriage-codec.md) §5) — dead-letters as `ERROR` (fail-loud, the
count-and-log invariant), **carrying only routing-safe identifiers in the log/error — never the object/pixel data**
(§1 PHI rule, §9).

**summary is left empty (`summary=None`) — a deliberate PHI boundary.** DICOM ingress passes `summary=None`
(consistent with the non-HL7 branch), so operators get **no** searchable patient/study identifier for a DICOM
message in the store/console. This is PHI-conservative: the `messages.summary` column is **plaintext,
volume-encryption-only** (PHI.md §3 residual — it is *not* routed through the store cipher), so keeping it empty
keeps `PatientName`/MRN out of the one PHI column not individually encrypted. **If** a study/patient summary is ever
surfaced for DICOM search, it lands in that plaintext column and must be treated accordingly (and audited via
`messages:view_summary`); the MVP keeps `summary=None`.

### 5. Purity is enforced by two tests (mirroring FHIR/X12)

Mirroring the FHIR/X12 "console-carve-out import-purity guard":
1. A **runtime** test — a subprocess that `import messagefoundry.parsing.dicom`, then scans `sys.modules` for any
   `messagefoundry.pipeline`/`store`/`transports`/`api`/`console` module and fails if present. (`config` is
   **excluded** from this runtime scan — the root `messagefoundry/__init__` imports config models unconditionally.)
2. A **static** test that closes the config gap — globs every `*.py` in `parsing/dicom/` and asserts no line
   imports `messagefoundry.config`/`.pipeline`/`.store`/`.transports`/`.api`/`.console`. This is what enforces the
   "literal `"dicom"`, never `ContentType.DICOM`" rule the runtime test cannot — and that `pydicom` is imported
   **lazily** (inside functions) so a console peek-import does not require the `[dicom]` extra.

### 6. Additive hotspot edits — `ContentType.DICOM`, two `ConnectorType`s, factories, exports, three `wiring_runner` edits

The config models are **transport-agnostic by design** ([config/models.py](../../messagefoundry/config/models.py))
— so the only `models.py` edits are additive enum members; DICOM options live in the flat `settings` dict, **no
new `Source`/`Destination` fields**.

6.1. **`ContentType.DICOM = "dicom"`** — a **new, additive** member in
[config/models.py](../../messagefoundry/config/models.py) (after `FHIR`). A DICOM inbound declares
`inbound("IB_…", DICOM(...), router=…, content_type="dicom")` and rides the existing non-HL7 branch (byte-faithfully
via the `mfb64:v1:` base64 carriage, [ADR 0028](0028-base64-binary-carriage-codec.md) §3 / §4) → the stored `message_type` is literally `"dicom"`, no HL7 parse/peek/ACK, and the
Router/Handler see `RawMessage.content_type == "dicom"` so they can branch. A **dedicated `ContentType.DICOM`
(CHOSEN), not a reuse of an existing tag** — the X12/FHIR precedent (each got its own `ContentType`) and the need
for a Handler to branch on a DICOM body favour a distinct tag. (`strict` is HL7-only — the existing `inbound()`
validation in [config/wiring.py](../../messagefoundry/config/wiring.py) already raises `WiringError`, no new guard
code.)

6.2. **`ConnectorType.DIMSE = "dimse"` and `ConnectorType.DICOMWEB = "dicomweb"`** — two **new, additive** members
in [config/models.py](../../messagefoundry/config/models.py) (after `FHIR`), with the trailing prose comment
updated. The split is load-bearing: **DIMSE** is the raw DICOM upper-layer (the C-STORE SCP **source** + the
C-STORE SCU **destination** + C-ECHO), gated by the **TCP** egress arm like a raw socket; **DICOMWEB** is STOW-RS
over **HTTP**, gated by the **HTTP** egress arm like REST/SOAP/FHIR (§6.4). The DIMSE source registers via
`register_source`; the DIMSE SCU destination + the DICOMweb destination via `register_destination`. (`ConnectorType`
is the *transport* key; `ContentType.DICOM` is the *payload* tag — distinct concerns.)

6.3. **`DICOM()` and `DICOMweb()` factories** — additive, keyword-only, in
[config/wiring.py](../../messagefoundry/config/wiring.py) near `Rest()`/`FHIR()`, each returning a
`ConnectionSpec(ConnectorType.X, {…flat dict…})` with `env()`-able secrets passed through verbatim:

```python
def DICOM(*, host,                     # str | EnvRef — DIMSE peer/bind AE host (may be env())
          port=104,                    # int | EnvRef — standard DICOM port
          ae_title,                    # this engine's AE Title (SCP) / calling AE Title (SCU)
          called_ae_title=None,        # the peer's AE Title (SCU destination); SCP accepts a calling-AE allowlist
          presentation_contexts=None,  # SOP classes + transfer syntaxes to negotiate (default: SR + common storage)
          tls=False,                   # DICOM-over-TLS off-loopback (§9); TLS 1.2+ floor when on
          max_object_bytes=...,        # per-C-STORE-object size cap; over-cap → DIMSE failure BEFORE commit (§9)
          max_associations=10, pdu_size=..., timeout_seconds=30.0,
          ) -> ConnectionSpec:
    # Host/port gated by [egress].allowed_tcp (raw-socket transport, like MLLP/X12).
    return ConnectionSpec(ConnectorType.DIMSE, {"host": host, "port": port, ...})


def DICOMweb(*, url,                    # str | EnvRef — DICOMweb STOW-RS BASE url, e.g. https://host/dicom-web
             study_uid=None,            # POST to {base}/studies or {base}/studies/{study_uid}
             headers=None,
             bearer_token=None, basic_user=None, basic_password=None,  # env() secrets
             timeout_seconds=30.0, verify_tls=True, encoding="utf-8",
             capture_response=False, reingress_to=None,
             ) -> ConnectionSpec:
    # NOTE: the endpoint is stored under the settings key "url" (NOT "base_url") — the SAME key Rest()/FHIR()
    # use, RestDestination's helpers read, and check_egress_allowed() reads (§6.4). It is a DICOMweb *base*
    # URL semantically; the key name stays "url" so the HTTP egress gate works unchanged.
    return ConnectionSpec(ConnectorType.DICOMWEB, {"url": url, ...})
```

The auth/TLS/header/timeout/capture knobs on `DICOMweb()` are the **same keys** `Rest()`/`FHIR()` expose (so OAuth
bearer tokens flow through the same `env()`-resolved, secret-redacted `bearer_token` path; a cert-authenticated
endpoint can reuse the ADR 0015 per-connection mTLS opener). Add `"DICOM"` and `"DICOMweb"` to `__all__`
([config/wiring.py](../../messagefoundry/config/wiring.py)) and re-export both from the top-level `messagefoundry`
surface next to `FHIR`/`Rest` so config modules can `from messagefoundry import DICOM, DICOMweb`.

6.4. **`wiring_runner.py` — three additive edits, plus the bind-guard generalization.** DICOM needs **three**
additive `ConnectorType`-keyed edits in [pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py)
— the **two** egress branches (security parity for the destinations) **and** a **third** `_source_config` tuple edit
for the SCP listener — **plus** a generalization of the non-loopback-TLS bind-guard (net-new, because the existing
guard is MLLP-only). No new helper, no new `[egress]` list, no `EgressSettings` change (the reuse path is the
smaller change; a dedicated `allowed_dimse`/`allowed_dicomweb` list is rejected unless an operator needs separate
control — Options #4):

- **(egress 1) `_allowlist_for`** (the function whose `(TCP, X12)` and `(REST, SOAP, FHIR)` tuples return the
  matching list) — add `ConnectorType.DIMSE` to the `(TCP, X12)` tuple that returns `egress.allowed_tcp`, and
  `ConnectorType.DICOMWEB` to the `(REST, SOAP, FHIR)` tuple that returns `egress.allowed_http`, so `deny_by_default`
  correctly refuses an unlisted DICOM destination.
- **(egress 2) `check_egress_allowed`** — **fold `DICOMWEB` into the existing `(REST, SOAP, FHIR)` host-check
  branch** (the branch body reads `dest.settings.get("url", "")`, calls `_http_egress_allowed`, and emits a
  `dest.type.value`-parameterized warning + `WiringError` that already names "dicomweb" generically; **this is
  exactly why `DICOMweb()` stores the endpoint under `"url"`**), and **add a standalone `DIMSE` branch modelled on
  X12's** (read `host`/`port`, match via `_mllp_egress_allowed` against `egress.allowed_tcp`, raise a `WiringError`
  on miss). **Both egress arms are mandatory:** `_allowlist_for` alone makes `deny_by_default` pass, but without the
  `check_egress_allowed` branch the host is never matched (a new type would fall through every `elif` and be
  **silently allowed** — a fail-open PHI-egress hole). (Reference the **symbol names** `_allowlist_for` /
  `check_egress_allowed`, and the HTTP-fold **branch body**, rather than hard line numbers — line numbers in an
  append-only ADR rot as `wiring_runner.py` changes; confirm exact sites at build time, *To resolve on acceptance*.)
- **(source) `_source_config`** — **add `ConnectorType.DIMSE` to the `(MLLP, TCP, X12)` tuple in `_source_config`**
  so the SCP **source** inherits the `settings["host"] = ic.bind_address or bind_host` bind-host injection **and**
  the `source_ip_allowlist` passthrough (the peer-IP allowlist the listener enforces at accept time). **This is the
  third additive edit and is easy to miss from a "two egress branches" framing** — ADR 0012 enumerated this same
  `_source_config` edit as one of X12's wiring edits. Without it the SCP binds the author-supplied/default host with
  **no peer-IP allowlist** and outside the `--allow-insecure-bind` bind-guard — a fail-open bind for a PHI-receiving
  listener.
- **(bind-guard generalization — net-new security work, NOT a free fold-in) the non-loopback-TLS guard.** The
  shipped `check_mllp_tls_exposure` is **MLLP-only** — its first line is `if source.type is not ConnectorType.MLLP:
  return`, so **TCP, X12, and DIMSE listeners are NOT guarded today**. There is therefore **no existing
  "MLLP/TCP/X12 bind-guard arm" the SCP can simply "join."** A non-loopback cleartext `ConnectorType.DIMSE` SCP
  would otherwise bind and accept associations with **no startup refusal**, putting DICOM header + pixel-data PHI on
  the LAN in cleartext (a §9 / PHI.md §4 violation). So this ADR **generalizes `check_mllp_tls_exposure`** (or adds
  a sibling guard) to **also refuse a non-loopback DIMSE SCP without DICOM-over-TLS unless `--allow-insecure-bind`**.
  This is an **additive but net-new** edit, called out here so the build does not treat it as already covered.
- `check_source_allowed` needs no change for the destinations; the **DIMSE source** (the SCP) is a listener — once
  it is in the `_source_config` tuple it carries `[inbound].bind_host` + the peer-IP allowlist for the (now
  generalized) bind-guard, but has nothing to connect-gate.

6.5. **Exports.** Add `dicom` to the import tuple in
[transports/__init__.py](../../messagefoundry/transports/__init__.py) so importing the package registers the DIMSE
source/destination + the DICOMweb destination at load (like `rest`/`soap`/`fhir`/`x12`; registration is the side
effect). Re-export the **headline** codec types — `DicomPeek`, `DicomDataset`, `DicomPeekError` — from
[parsing/__init__.py](../../messagefoundry/parsing/__init__.py) and add them to its `__all__` (mirroring the FHIR/X12
block), keeping lower-level internals reachable only under `messagefoundry.parsing.dicom`.

### 7. Dependencies — the `messagefoundry[dicom]` optional extra (verified, not core)

Per CLAUDE.md §5/§7 (verify a dependency exists / is reputable / correctly named **before** adding; AI-suggested
packages are often hallucinated) — the picks ride the verify-then-add gate at the **dep-vet** before build:

| Package | PyPI name | License | Role / capability |
|---|---|---|---|
| **`pydicom`** (`>=3.0.2,<4`) | `pydicom` | **MIT AND BSD-3-Clause** (dep-vet CLEARED 2026-06-20): MIT-licensed code that **vendors GDCM/CREATIS data-dictionary files under BSD-3-Clause**, so the distribution SPDX is the conjunction — record the GDCM/CREATIS BSD-3 attribution in the project **NOTICE** (PEP 639). | the DICOM dataset/SR codec — `DicomPeek` (shallow tag read), `DicomDataset` (header + SR walk). **Pure-Python; headers/SR only → `numpy` is NOT pulled** (numpy is pydicom's *optional* pixel-data dep, never used here). **Floor `>=3.0.2` excludes 2.4.0–2.4.4 — CVE-2026-32711 (High, CVSS 7.8; FileSet/DICOMDIR path traversal; patched 3.0.2/2.4.5); not in our C-STORE/SR path, excluded anyway.** |
| **`pynetdicom`** (`>=3.0.4,<4`) | `pynetdicom` | **MIT** (dep-vet CLEARED 2026-06-20) | the DIMSE network stack (built on `pydicom`): the C-STORE **SCP** (Phase-1 source), the C-STORE **SCU** + **C-ECHO** (Phase-2). Required because Phase 1+2 DIMSE is pursued. **3.0.4 requires `pydicom>=3,<4`**, so the 3.x lines pair cleanly + are numpy-free + support py3.11+3.13 (the earlier `>=2.1` floor pinned `pydicom<2.5` and was inconsistent with a 3.x pydicom). |
| **`dicomweb-client`** | `dicomweb-client` | **MIT** (dep-vet CLEARED 2026-06-20) | **its OWN Phase-2 extra — NOT in core `[dicom]`** because it pulls **`numpy` + `pillow` + `requests`**, which would break the headers/SR → no-numpy property of the core extra. STOW-RS multipart/response handling **iff** `rest.py` reuse is impractical; prefer reusing `rest.py` (Options #3). |

They ship as an **optional extra**, never core (mirroring `[fhir]`/`[sqlserver]`/`[postgres]`/`[sftp]` in
[pyproject.toml](../../pyproject.toml)); the base/SQLite-only install stays driverless. The DICOM transport code in
`transports/` and the codec in `parsing/dicom/` **function-local-import** these (like the FHIR codec) so SQLite-only
installs without the extra still import cleanly:

```toml
# DICOM (DIMSE C-STORE SCP/SCU) connectors/codec (ADR 0025, BACKLOG #NN). Lazy-imported, so SQLite-only installs
# that never use DICOM skip it. pynetdicom (the DIMSE upper-layer) drags pydicom (the DICOM data-set/SR codec);
# both pure-Python — HEADERS/SR ONLY, so NO numpy. Floors per dep-vet (2026-06-20): pydicom>=3.0.2 excludes
# CVE-2026-32711 (2.4.0–2.4.4); pynetdicom>=3.0.4 requires pydicom>=3,<4 (the 3.x lines pair cleanly + numpy-free).
dicom = ["pynetdicom>=3.0.4,<4", "pydicom>=3.0.2,<4"]
# dicomweb-client is its OWN Phase-2 extra — it drags numpy+pillow+requests, so it must NOT ride core [dicom];
# added only if rest.py reuse proves impractical (Options #3). Pin its floor at the Phase-2 dep-vet.
dicomweb = ["dicomweb-client"]
```

Follow DEP-1 ([CLAUDE.md](../../CLAUDE.md) §7, memory `depadd-relock-gotcha`). **Dep-vet CLEARED all three
(coordinator, 2026-06-20)** with these locked outcomes: **`pydicom` = MIT AND BSD-3-Clause** (MIT code + vendored
GDCM/CREATIS data-dictionary files; record the GDCM/CREATIS BSD-3 attribution in **NOTICE**, PEP 639),
**`pynetdicom` = MIT**, **`dicomweb-client` = MIT** (the last isolated to its own **Phase-2 extra** — it drags
numpy+pillow+requests, so it must not ride core `[dicom]`). Add the `[dicom]` extra to
[pyproject.toml](../../pyproject.toml) with the **locked floors `pynetdicom>=3.0.4,<4` + `pydicom>=3.0.2,<4`**,
re-lock with the lock header's **relative** `uv export` command **from the repo root** (or the DEP-1 drift check
fails), and run the audit. **The floors are the 3.x lines, which pair cleanly** (pynetdicom 3.0.4 requires
`pydicom>=3,<4`; numpy-free; py3.11+3.13) — the earlier `>=2.1`/`>=2.4` pair was both **inconsistent** (pynetdicom
2.1.0 pins `pydicom<2.5`, so it cannot use 3.x) and **unsafe** (`pydicom>=2.4` admits 2.4.0–2.4.4, vulnerable to
**CVE-2026-32711**, High/CVSS 7.8 — FileSet/DICOMDIR path traversal, patched 3.0.2/2.4.5). The only pydicom 3.0
break is the pixel-handler module move (`pydicom.pixel_data_handlers`→`pydicom.pixels`) — **out of scope** (no
pixel handling here). If
`pynetdicom`/`pydicom` ship no stubs/`py.typed`, add `"pynetdicom.*"`/`"pydicom.*"` to the **existing**
`[[tool.mypy.overrides]]` `module = […]` list — not a new block — confirmed against the installed wheels. The
floors above are **library-realism minimums**, to be **pinned exactly at build time**, not numbers asserted from a
snapshot.

### 8. A worked sample Router + Handler — the "replace the DICOM Gear value" demo

A synthetic, PHI-free sample under [samples/](../../samples) implementing the radiology-practice flow code-first:
an `inbound(...)` C-STORE SCP with `content_type="dicom"` → a **Router** that `DicomPeek`s the object and forwards
SR objects to the measurements Handler (filtering non-SR) → a **Handler** that `DicomDataset.parse`s the SR, walks
the `ContentSequence` for measurements, uses the mapping helpers to build an HL7 v2 **ORU** with one `OBX` per
measurement, and returns a `Send` to an **outbound MLLP** connection (the PowerScribe analog). Plus a synthetic
`.dcm` SR fixture (PHI-free, generated — never real PHI), provided **base64-carried** (the `mfb64:v1:` form) so the
codec and a `dryrun`-style harness recover the exact bytes via `RawMessage.raw_bytes` ([ADR 0028](0028-base64-binary-carriage-codec.md) §3, §4). This is the standalone-value demo:
the SR→PowerScribe flow the practice runs on Corepoint's DICOM Gear, authored as **pure Python**.

## Options considered

1. **DICOM as `RawMessage` + an on-demand library (CHOSEN) vs a parsed DICOM object added to the `Payload`
   union.** Adding `Payload = Message | RawMessage | DicomDataset` with `dryrun.py::_payload()` branching on
   `ContentType.DICOM` would edit the **forbidden routing hotspots**, couple the pipeline to DICOM + the heavy
   `pydicom`/`pynetdicom` libraries, and force a full dataset parse on the hot path even when a Router needs only
   the `Modality`/`SOPClassUID` peek. **Rejected.** `RawMessage` + an on-demand `parsing/dicom/` library keeps the
   engine format-blind, matches the X12/FHIR/JSON/XML precedent, and lets the cheap routing tier (`DicomPeek` with
   `specific_tags`) run without a full dataset walk and without pixel data.

2. **A Phase-1 C-STORE SCP + Phase-2 SCU/C-ECHO/DICOMweb (CHOSEN: hybrid) vs classic-DIMSE-only vs DICOMweb-only.**
   *Classic-DIMSE-only* (Mirth's posture — SCP + SCU + C-ECHO, no HTTP) is the table-stakes parity but misses the
   modern HTTP imaging lane. *DICOMweb-only* (STOW-RS over HTTP, reusing `rest.py`) is the cleanest build but the
   named adopter's modalities/PACS speak **DIMSE C-STORE**, not DICOMweb, so it does not unblock the driver.
   **CHOSEN: the hybrid** — build the **inbound C-STORE SCP first** (it is what the radiology practice needs to
   send SR objects in, and it carries the asyncio-correctness risk that must be proven), and **design** outbound
   SCU + C-ECHO (Mirth parity) + a DICOMweb STOW-RS destination (the path that **exceeds** both incumbents) so the
   seams are right, building them after the Phase-1 slice. Phasing is §"Phasing".

3. **DICOMweb STOW-RS by reusing `rest.py`'s helpers (CHOSEN) vs `dicomweb-client`.** `dicomweb-client` (MIT) is
   real, reputable, and handles the STOW-RS multipart framing — a real convenience, **but the dep-vet found it drags
   `numpy` + `pillow` + `requests`** (it would break the core extra's headers/SR → no-numpy property, so it can only
   live in a separate Phase-2 extra — §7). But reusing `rest.py`'s shared
   helpers as a SIBLING connector (the SOAP/FHIR pattern) keeps the HTTP plumbing — the TLS-verifying no-redirect
   opener, cleartext-credential refusal, the retry/dead-letter classification idiom, the JWS/mTLS hooks, and the
   `allowed_http` egress gate — in **one** place, audited once, and the `multipart/related; type="application/dicom"`
   framing is modest to add. **CHOSEN: reuse `rest.py` (prefer)**, with `dicomweb-client` as a **permissible
   Phase-2 fallback** if the multipart/response handling proves heavier than a thin layer over `rest.py`. (Either
   way the destination is a sibling `DestinationConnector` that does **not** wrap `RestDestination`.)

4. **Fold DICOM into the existing `allowed_http`/`allowed_tcp` egress arms (CHOSEN) vs dedicated
   `allowed_dicomweb`/`allowed_dimse` lists.** A dedicated list gives an operator separate control but adds two
   `EgressSettings` fields + two `_split_list` validator entries + `_allowlist_for` returns, and a fail-open hole
   if any arm is missed. DICOMweb is HTTP (so `allowed_http`) and DIMSE is a raw socket (so `allowed_tcp`, exactly
   like X12) — the existing arms fit. **Rejected (dedicated lists), CHOSEN (reuse `allowed_http`/`allowed_tcp`)** —
   the smaller, lower-risk change, with both `_allowlist_for` and `check_egress_allowed` branches added so the new
   types are **never** fail-open. (A dedicated list remains available later if operators need it.)

5. **A code-first SR→HL7 Handler (CHOSEN) vs a declarative DICOM-mapping surface (the Corepoint-GUI model).** A
   declarative field-mapping surface is precisely Corepoint DICOM Gear's model — and **declined-by-design** for
   MessageFoundry ([CLAUDE.md](../../CLAUDE.md) §12, [BACKLOG.md](../BACKLOG.md) #26: visual/template-driven
   authoring is declined; code-first Routers/Handlers *are* the differentiator). The SR→HL7 mapping is a **pure
   Python Handler** that calls the codec's mapping helpers; the helpers spare boilerplate but the Handler owns the
   decisions. **Rejected (declarative mapper), CHOSEN (code-first Handler).**

6. **The C-STORE SCP off the loop with a `run_coroutine_threadsafe` bridge (CHOSEN) vs forcing `pynetdicom` onto
   the loop / a custom thread+queue bridge.** `pynetdicom`'s AE server is blocking/threaded; running it on the loop
   would block intake, and a bespoke thread+queue is a new primitive to get right. The project's **established**
   off-loop pattern is `asyncio.to_thread` for blocking work + `run_coroutine_threadsafe(coro, captured_loop)` to
   bridge a foreign-thread callback back to the loop-owned store (the `db_lookup` precedent). **Rejected (on-loop /
   custom bridge), CHOSEN (off-loop AE server + the `db_lookup`-style loop bridge)** — proven, isolated by the
   runner, cooperatively cancellable.

7. **Carry the binary object via the base64 binary-carriage contract (CHOSEN — consume [ADR 0028](0028-base64-binary-carriage-codec.md) §3) vs a lossless latin-1 round-trip vs a bytes-native ingress/store/`RawMessage` contract.**
   DICOM is binary and the shipped non-HL7 ingress/store/`RawMessage` path is `str`-only (Context, §3, §4). Three routes:
   - **A latin-1 round-trip** (`bytes.decode("latin-1")` to commit, `str.encode("latin-1")` to recover) *looks*
     byte-exact for any 0–255 byte, and an earlier draft of this ADR chose it. **REJECTED:** it is **not** lossless
     across the store — latin-1 carries every byte, including `NUL` (U+0000), and a Part-10 object's mandatory
     128-byte all-zero preamble guarantees 128 `NUL`s, which **psycopg rejects at bind on Postgres** and **SQLite /
     SQL Server silently truncate**. It reintroduces exactly the corruption it claims to prevent (Context, §3).
   - **A bytes-native** substrate (a `raw_bytes`/`bytea` column, a bytes-capable `enqueue_ingress`, a bytes-or-str
     `RawMessage`, plus a second binary cipher path) is the structurally "correct" fix, but it is a **non-additive
     change to the forbidden ingress hotspots and all three store backends** and severs the encoded-TEXT cipher seam
     — large, cross-cutting, and risky for a format that can be carried losslessly without it.
   - **The base64 carriage of [ADR 0028](0028-base64-binary-carriage-codec.md) §3** (`RawMessage.from_bytes` →
     `mfb64:v1:<base64>` to commit, `.raw_bytes` to recover) is byte-exact, **ASCII-safe** (no `NUL` / HL7 delimiter
     / CR, so it rides the `str`/TEXT store + identity/AES-GCM cipher unchanged), and **additive** (it lives at the
     SCP/codec boundary, touching no pipeline routing logic, with exactly one encode and one decode that consumers
     never hand-roll). **CHOSEN: consume ADR 0028's base64 carriage** for Phase 1+2; the bytes-native substrate is
     recorded as the future option if a non-text format ever needs more than a lossless string carriage (*To resolve
     on acceptance*).

## Consequences

**Positive**

- **Zero pipeline routing-logic risk.** `_handle_inbound`/`route_only`/`transform_one` and `dryrun.py` routing
  logic are untouched; DICOM rides the proven non-HL7 ingress/route/transform/finalizer path (carrying the binary
  object via the [ADR 0028](0028-base64-binary-carriage-codec.md) §3 base64 carriage at the SCP/codec boundary, not by teaching the pipeline). The only
  `wiring_runner.py` edits are the three additive type-keyed edits + the bind-guard generalization (§6.4) — security
  parity, not routing logic.
- **A pure, console-importable DICOM library.** Routers/Handlers and the PySide6 console get
  `DicomPeek`/`DicomDataset` + the mapping helpers against `RawMessage`, trivially unit-testable with no socket and
  no engine — and the console gets a **DICOM tag-tree viewer** (the Parse-Tree analog) for free.
- **The "DICOM Gear" value, code-first.** The SR→PowerScribe and header→RIS flows the radiology practice runs on
  Corepoint become **pure-Python Handlers** — versioned, diffable, unit-tested — the differentiator over a
  proprietary GUI mapper.
- **No HTTP re-implementation for DICOMweb.** `DicomWebDestination` **reuses the shipped, stdlib-only `rest.py`
  helpers** (the same ones SOAP/FHIR reuse) — TLS verification, redirect refusal, cleartext-credential refusal, the
  retry/dead-letter classification idiom, the JWS/mTLS hooks — plus the fail-closed egress gate, adding only the
  STOW-RS multipart layer. It does not wrap or instantiate `RestDestination`.
- **Reliability honest under DIMSE.** The C-STORE SCP commits the object durably to ingress **before** returning
  SUCCESS (count-and-log + ACK-on-receipt analog), with an explicit timeout-failure policy (timeout → DIMSE
  failure + idempotent re-ingest, never a false SUCCESS); a post-commit failure is an `ERROR`/dead-letter +
  AlertSink, not a DIMSE failure; a crash before commit re-runs on the SCU's re-send — at-least-once holds,
  broker-free.
- **Exceeds both incumbents on the HTTP lane.** A DICOMweb STOW-RS destination is a path neither Mirth's nor
  Corepoint's DICOM option ships out of the box.
- **Base install unaffected.** `pydicom`/`pynetdicom` are an optional `[dicom]` extra; SQLite-only installs never
  pull them — and **never pull `numpy`** (headers/SR only).

**Negative / risks**

- **Binary-over-`str` impedance — the one genuine deviation from FHIR/X12, and a dependency on [ADR 0028](0028-base64-binary-carriage-codec.md).**
  Unlike X12/FHIR (text), DICOM is binary and the shipped non-HL7 ingress/store/`RawMessage` substrate is `str`-only;
  a naive UTF-8 ride would `UnicodeDecodeError` and store nothing, and a latin-1 ride would carry `NUL`s that Postgres
  rejects at bind and SQLite/SQL Server truncate (breaking the "preserve the raw object" PHI rule either way). The
  mitigation — **consuming ADR 0028's base64 carriage** (`RawMessage.from_bytes` → `mfb64:v1:` at the SCP commit,
  `.raw_bytes` recovery in the codec) — is byte-exact, ASCII-safe, and additive, but it is a **discipline the build
  must honour exactly** (never `utf-8`, never `errors="replace"`, never latin-1 on a DICOM body; the §8 fixture and
  any `dryrun` input must be `mfb64:v1:` base64-carried) **and a hard ratification dependency** (this ADR is ratified
  in lockstep with ADR 0028; the build is gated on ADR 0028's `from_bytes`/`.raw_bytes`/`.is_binary` landing). A
  future non-text format needing more than a lossless string carriage would force the bytes-native substrate
  (Options #7).
- **A foreign-thread network server in-process.** `pynetdicom`'s AE server is blocking/threaded; the SCP must run
  it off the loop and bridge each C-STORE back via `run_coroutine_threadsafe`, with a bounded-grace cooperative
  `async stop()` whose blocking `AE.shutdown()` / thread-`join` run **off the loop** (`asyncio.to_thread`) so
  shutdown never stalls other listeners/workers/API calls. Getting the loop-capture, the off-loop start, the
  `future.result(timeout)` policy, and the shutdown ordering right is the central correctness risk (the
  `db_lookup`/`MLLPSource.stop` precedents bound it; a real-association test proves it).
- **New compiled-adjacent dependencies in the `[dicom]` extra.** `pynetdicom` + `pydicom` are heavier than the
  hand-rolled X12 codec. Confined to an extra and to `parsing/dicom/` + `transports/dicom.py`, but they must be
  pinned, hash-locked, and audited (DEP-1). **Dep-vet CLEARED (2026-06-20):** `pydicom` = **MIT AND BSD-3-Clause**
  (MIT + vendored GDCM/CREATIS files → NOTICE attribution), `pynetdicom` = **MIT**, `dicomweb-client` = **MIT**
  (isolated to a Phase-2 extra — it drags numpy+pillow+requests). Floors locked to the 3.x lines
  (`pynetdicom>=3.0.4,<4` + `pydicom>=3.0.2,<4`, which pair cleanly and are numpy-free); `pydicom>=3.0.2` also
  excludes **CVE-2026-32711** (the 2.4.0–2.4.4 FileSet/DICOMDIR path traversal).
- **PHI-leak risk in error/log paths.** A DICOM dataset (and pixel data) is PHI; because `DicomError`/`DicomPeekError`
  derive from `ValueError` and feed the `ERROR`/dead-letter log path, a careless implementation could embed the
  object or an element value in an exception/log line. The §1 PHI rule (object/values/pixel data never in the
  message/log; only `SOPClassUID`/`Modality`/UIDs/AE Title; mirror `_redact_url`) is a **hard invariant** the build
  must honour — covered by review and a test.
- **DIMSE-over-the-wire is network-bound and the bind-guard is net-new.** A non-loopback DICOM SCP must require
  **DICOM-over-TLS** (the `pynetdicom` TLS-context analog of MLLP-over-TLS, TLS 1.2+ floor) or the explicit
  `serve --allow-insecure-bind` escape; cleartext PHI on the LAN is a §9 violation. **The shipped
  `check_mllp_tls_exposure` is MLLP-only** (TCP/X12/DIMSE are not guarded today), so this is **not** a free
  fold-in — the guard must be **generalized** (or a sibling added) to refuse a non-loopback cleartext DIMSE SCP
  fail-closed (§6.4). Until that generalization lands, a DIMSE SCP would be fail-open on the wire.
- **Untrusted-dataset DoS surface.** A C-STORE object is untrusted DATA: a maliciously large or pathological
  dataset could exhaust memory/disk before the durable commit. Mitigations: a **per-object `max_object_bytes` cap**
  (over-cap → DIMSE failure **before** commit, the X12 `max_interchange_bytes` analog), the association-layer caps
  (max associations, PDU size, timeouts), `stop_before_pixels=True` bounding the header read, and **no pixel
  decode** (so **no decompression-bomb surface** — the no-numpy/no-pixel boundary is a security control, not just a
  dependency note). The codec treats the dataset as untrusted (never trusts a declared length blindly).
- **STOW-RS response classification is heuristic.** Mapping a STOW-RS `FailedSOPSequence` / HTTP status to
  permanent-vs-transient refines the HTTP-status base but is not exhaustive across servers; the conservative rule
  (HTTP status wins when in doubt; a 5xx/timeout stays transient) bounds the risk, and `capture_response` lets an
  operator route the full STOW-RS response to a Handler.
- **Purity regression risk.** `parsing/dicom/` must import **zero** engine/`config`; the two import-purity tests
  (§5) guard it — and the `pydicom` import inside the codec must stay lazy enough that a console peek-import does
  not require the `[dicom]` extra.

**Out of scope (deferred / explicitly NOT promised)**

- **MWL SCP / serving a Modality Worklist** — **OWNER EXPLICITLY DECLINED.** Not designed, not built, not a future
  item under this ADR.
- **MPPS** (Modality Performed Procedure Step) and **Query/Retrieve** (C-FIND / C-MOVE / C-GET) — not built.
- **DICOMweb QIDO-RS / WADO-RS retrieval** (query/retrieve over HTTP) — not built; this ADR's DICOMweb is the
  **STOW-RS store/send destination** only.
- **An inbound DICOMweb (STOW-RS) RECEIVER** — needs the future **inbound HTTP listener (backlog #7 / ADR 0023)**
  the inbound FHIR facade is also gated on; the listener must live in `transports/`, not `api/`, to preserve the
  one-way dependency. **Dependency noted, not built here** (ADR 0023 is not yet authored — backlog #7 is the
  canonical handle).
- **A bytes-native ingress/store/`RawMessage` substrate** — DICOM is carried byte-faithfully via the additive base64
  carriage of [ADR 0028](0028-base64-binary-carriage-codec.md) §3 (Options #7); the larger bytes-native contract is recorded as a future option, not built here.
- **Pixel-data transformation / rendering, and `numpy`** — headers + SR only; the codec reads
  `stop_before_pixels=True` and never pulls `numpy`.
- **DICOM ↔ HL7 v2 mapping as a built declarative converter** — mapping stays **hand-authored code-first Handlers**
  (`DicomDataset` in → python-hl7 `Message` out), consistent with the code-first-logic rule and the declined
  visual/template-authoring stance. The codec ships **helpers**, not a mapper.
- **A "channel"/"route" element** — there is none; the SR→HL7 flow is an inbound Connection naming a Router naming
  a Handler naming an outbound Connection, wired by name (the no-grouping-unit graph).

## Phasing

- **Phase 1 — build now (once Accepted; gated on [ADR 0028](0028-base64-binary-carriage-codec.md)'s carriage API landing):** the pure `parsing/dicom/` codec (`errors` → `peek` → `dataset` →
  `hl7_map`, recovering object bytes via `RawMessage.raw_bytes` in `peek`/`dataset`) with the two import-purity tests + the PHI-no-log
  assertion + synthetic PHI-free `.dcm`/SR fixtures (`mfb64:v1:` base64-carried, §8); the **inbound C-STORE SCP** `DicomScpSource`
  (off-loop `pynetdicom` AE server, `run_coroutine_threadsafe` loop-bridge with the explicit timeout-failure policy,
  durable-commit-before-SUCCESS via `RawMessage.from_bytes`, calling-AE allowlist, `max_object_bytes` cap, off-loop
  bounded-grace `stop`); the §6 wiring (`ContentType.DICOM`, `ConnectorType.DIMSE`, the `DICOM()` factory, exports,
  the §6.4 DIMSE egress arm + the `_source_config` tuple edit + the generalized bind-guard); and the §8 worked
  SR→ORU sample.
- **Phase 2 — design now, build later:** outbound **C-STORE SCU** (`DicomScuDestination`, Mirth-sender parity);
  **C-ECHO** verification (SCU `test_connection` + SCP Verification SOP Class); the **DICOMweb STOW-RS**
  `DicomWebDestination` (sibling of `rest.py`, `ConnectorType.DICOMWEB`, the `DICOMweb()` factory, the §6.4
  `allowed_http` egress fold); and `capture_response`/re-ingress for the STOW-RS response if a Handler needs it.

## To resolve on acceptance

- **Confirm the ADR number is 0025** and the Phase-1 (codec + C-STORE SCP + SR→ORU sample) / Phase-2 (SCU, C-ECHO,
  DICOMweb STOW-RS) split; add the `Proposed` row for 0025 to [docs/adr/README.md](README.md) at authoring (it
  flips to `Accepted` on go).
- **Confirm the binary-carriage decision** — **consume [ADR 0028](0028-base64-binary-carriage-codec.md) §3's base64
  carriage** (SCP commits via `RawMessage.from_bytes(..., content_type="dicom")` → `mfb64:v1:<base64>`; codec recovers
  via `RawMessage.raw_bytes`; never `utf-8`/`errors="replace"`/latin-1), and that the stored raw round-trips
  byte-exact through the store cipher — vs. the larger bytes-native ingress/store/`RawMessage` substrate (Options #7).
  The base64 carriage is the recommended default (additive, byte-exact, ASCII-safe — no `NUL` corruption); the
  bytes-native substrate is a non-additive ingress-hotspot change deferred unless a future format needs it. **This
  ADR is ratified in lockstep with ADR 0028 and the build is gated on its carriage API (`from_bytes`/`.raw_bytes`/
  `.is_binary`) landing — confirm ADR 0028's final number with the coordinator before the README cross-links resolve
  (it is filed as 0027 pending the retention-#34 reconciliation; recommended renumber 0028).**
- **Dependency dep-vet — DONE (coordinator, 2026-06-20); apply these locked outcomes at build** ([CLAUDE.md](../../CLAUDE.md) §5/§7):
  `pydicom` + `pynetdicom` (+ optional `dicomweb-client`) confirmed real/reputable/maintained. License: **`pydicom`
  = MIT AND BSD-3-Clause** (MIT + vendored GDCM/CREATIS data-dictionary files → record the GDCM/CREATIS BSD-3
  attribution in **NOTICE**, PEP 639), **`pynetdicom` = MIT**, **`dicomweb-client` = MIT**. **Locked floors
  `pynetdicom>=3.0.4,<4` + `pydicom>=3.0.2,<4`** (the 3.x lines pair cleanly + are numpy-free; `pydicom>=3.0.2`
  excludes CVE-2026-32711). **Keep `dicomweb-client` in its own Phase-2 extra** (it drags numpy+pillow+requests —
  out of core `[dicom]`). Add the `[dicom]` extra to [pyproject.toml](../../pyproject.toml), re-run `uv lock`/`uv
  export` from the repo root, and run the DEP-1 audit — **do not** trust an unverified snapshot.
- **Confirm the egress reuse** (`DICOMWEB → allowed_http`, `DIMSE → allowed_tcp`) vs dedicated
  `allowed_dicomweb`/`allowed_dimse` lists (the recommended default is reuse — Options #4); and that the `DICOMweb()`
  factory stores its endpoint under the `"url"` key so the §6.4 HTTP egress gate reads it unchanged.
- **Confirm the three `wiring_runner.py` edits exist before build** — the two egress branches (`_allowlist_for` +
  `check_egress_allowed`, DIMSE→`allowed_tcp` / DICOMWEB→`allowed_http`) **and** the `_source_config` tuple edit
  adding `ConnectorType.DIMSE` to `(MLLP, TCP, X12)` for the SCP bind-host + peer-IP allowlist — and verify the
  concrete edit sites by **symbol name** at build time (line numbers rot in an append-only ADR).
- **Confirm the C-STORE SCP commit-before-SUCCESS + timeout-failure contract** — SUCCESS only after
  `enqueue_ingress` returns; decode/SOP-class-mismatch/over-`max_object_bytes` failures return a DIMSE failure
  status **before** enqueue; a `future.result(timeout)` timeout returns a DIMSE **failure** (never a false SUCCESS)
  with an **idempotent** re-ingest (de-dupe on `SOPInstanceUID` or accept a documented duplicate), and the timeout
  budget accounts for the store `asyncio.Lock` + WAL commit under expected concurrency; post-commit failures are
  `ERROR`/dead-letter, never a DIMSE failure — and the off-loop `pynetdicom` AE server + `run_coroutine_threadsafe`
  loop-bridge + **off-loop** (`asyncio.to_thread`) bounded-grace `stop()` ordering.
- **Confirm the calling-AE allowlist + DICOM-over-TLS posture + the bind-guard generalization** — the SCP refuses
  associations from an unlisted calling AE Title / peer IP, and a non-loopback bind requires TLS 1.2+ (or
  `--allow-insecure-bind`); since `check_mllp_tls_exposure` is **MLLP-only today**, confirm it is **generalized**
  (or a sibling guard added) to also refuse a non-loopback cleartext DIMSE SCP fail-closed — this is net-new work,
  not a fold-in.
- **Confirm the mypy override scope** against the installed wheels: add `"pydicom.*"`/`"pynetdicom.*"` to the
  existing `[[tool.mypy.overrides]]` list **only if** they lack a `py.typed` marker.
- **Decide the DICOMweb STOW-RS build approach concretely** — reuse `rest.py`'s helpers (recommended) vs
  `dicomweb-client` — at the Phase-2 build, weighing the multipart framing effort (Options #3).
- **Build order on go** (each behind the standard quartet gate — `ruff format --check` · `ruff check` · `mypy
  messagefoundry` · `pytest` with `QT_QPA_PLATFORM=offscreen`): (1) the pure `parsing/dicom/` codec
  (`errors` → `peek` → `dataset` → `hl7_map`, recovering bytes via `RawMessage.raw_bytes`) with the two import-purity tests + the
  PHI-no-log assertion + synthetic PHI-free fixtures; (2) the `DicomScpSource` C-STORE SCP (off-loop AE server +
  loop-bridge + commit-before-SUCCESS via `RawMessage.from_bytes` + timeout-failure policy) with a real-association loopback test
  proving `receive → enqueue_ingress → RawMessage → DicomPeek` end-to-end with a byte-exact round-trip, + the §6
  DIMSE wiring (`ContentType.DICOM`, `ConnectorType.DIMSE`, the `DICOM()` factory, exports, the §6.4 egress arm +
  `_source_config` edit + generalized bind-guard) + the §8 SR→ORU sample; (3) Phase-2 — `DicomScuDestination` +
  C-ECHO + `DicomWebDestination` (sibling of `rest.py`, `ConnectorType.DICOMWEB`, the `DICOMweb()` factory, the
  `allowed_http` egress fold); (4) docs — add the `DICOM-IN`/`DICOM-OUT`/`DICOMWEB-OUT` rows and the per-connector
  `### DICOM — DICOM(...)` / `### DICOMweb — DICOMweb(...)` sections in [CONNECTIONS.md](../CONNECTIONS.md), update
  [CLAUDE.md](../../CLAUDE.md) §8, enrich the BACKLOG DICOM item, and flip this ADR's [README.md](README.md) row to
  Accepted.
