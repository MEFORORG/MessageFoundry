# HL7 Conventions

Moved verbatim from the root `CLAUDE.md` §8. A nested `CLAUDE.md` loads when Claude reads files
under this directory, so these conventions reach engine work without costing context in the docs,
scripts and coordination sessions that never touch `messagefoundry/`. Nothing changed in the move.

- **Two-tier parsing, by design:** **python-hl7** does fast, tolerant field *peek* on the hot
  path (routing/filtering); **hl7apy** does version-aware validation, **opt-in per inbound
  connection** (`validation.strict`) — it's the slow path, kept off routing. Don't route
  everything through the hl7apy object model.
- **Ingress is payload-agnostic** ([ADR 0004](../docs/adr/0004-payload-agnostic-ingress.md)). An inbound's
  `content_type` (default `hl7v2`) selects the path: `hl7v2` gets the HL7 peek/validate/ACK above and
  Routers/Handlers receive a `Message`; any other value skips HL7 parsing and they receive a `RawMessage`
  (`.raw`/`.text`/`.json()`). HL7 stays the default and unchanged — never HL7-parse a non-HL7 body.
  **X12 EDI** rides this path (`content_type=x12`): a pure tolerant codec lives at `parsing/x12/`
  (`X12Peek` routing peek, `X12Message`, interchange splitter) + an ISA/IEA-framed `X12()` raw-TCP
  connector ([ADR 0012](../docs/adr/0012-x12-edi-codec.md)) — Routers/Handlers call the codec on demand
  against the `RawMessage`; it is never pushed through the pipeline.
  **DICOM** rides this path too (`content_type=dicom`, [ADR 0025](../docs/adr/0025-dicom-codec-store-connectors.md)):
  a pure tolerant codec lives at `parsing/dicom/` (`DicomPeek` routing peek, `DicomDataset`
  + SR→HL7 helpers) called on demand against the `RawMessage`, plus an inbound **C-STORE SCP** connector
  (`DICOM()` inbound) and the **outbound C-STORE SCU + C-ECHO** (`DICOM()` outbound) and **DICOMweb STOW-RS**
  (`DICOMweb()`, a stdlib sibling of `transports/rest.py`) destinations; SR→HL7 mapping is a code-first
  Handler. Headers/SR only — **no pixel data** — DIMSE behind a `[dicom]` extra (pydicom + pynetdicom),
  DICOMweb needs no extra. MWL, Query/Retrieve (C-FIND/C-MOVE/C-GET), and an inbound DICOMweb receiver
  (needs the ADR 0023 HTTP listener) are out of scope.
- **Binary payloads** (arbitrary bytes) carry NUL-safely over the str/TEXT ingress + store via the
  `mfb64:v1:` base64 marker ([ADR 0028](../docs/adr/0028-base64-binary-carriage-codec.md)):
  `RawMessage.from_bytes()` / `.raw_bytes`. Carriage is **orthogonal** to format — `content_type` stays
  the format tag — and HL7 OBX-5 ED embedding is supported. **Never latin-1** for binary (it corrupts
  on NUL).
- **Never mutate raw HL7 with string slicing.** Work via the parsed model and re-encode.
- **Parse defensively** — real-world HL7 is frequently non-conformant. Route parse/validation
  failures to the error/dead-letter path (logged as `ERROR`); never crash the connection.
- **Read encoding characters from MSH** (field/component/repetition/escape/subcomponent);
  don't hardcode `|^~\&`.
- Be **explicit about HL7 version** for strict inbound connections; don't rely on silent
  autodetection.
- **Preserve the original raw message** in the store alongside the transformed form, so an
  operator always sees what actually arrived.
- Keep transforms **pure where possible**: message in → message out; side effects (DB, network)
  belong in connections/transports. The sanctioned exceptions are the **read-only** `db_lookup` (ADR
  0010) and `fhir_lookup` (ADR 0043) for live enrichment/gating (provider/eligibility lookups) — never a
  write or other side effect.
- **ACK/NAK:** generate proper AA/AE/AR for MLLP inbound connections; the ack mode (original vs
  enhanced vs none) is **configurable per inbound connection** (`AckMode`). Under the staged
  pipeline the ACK is **on receipt** (`ack_after=ingest`, the default — `AckAfter`): decode/parse/
  strict-validate failures still **NAK synchronously** (AR/AE), but a message that parses is **AA'd
  once committed to the ingress stage**, *before* routing/transform/delivery. So a routing/transform
  or delivery failure happens **after** the sender was told AA — it is **not** NAK'd; operators rely
  on the message's `ERROR`/dead-letter disposition + the AlertSink, not the ACK, for post-ingress
  failures. (`ack_after=delivered`, deferring the ACK until delivery, is planned, not built.)
