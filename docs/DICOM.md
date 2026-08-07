# DICOM Support in MessageFoundry

> **Status:** Phases 1 + 2 of [ADR 0025](adr/0025-dicom-codec-store-connectors.md) are **built and on `main`**
> (Phase 1 = inbound C-STORE SCP + codec, PR #439; Phase 2 = outbound C-STORE SCU + C-ECHO + DICOMweb STOW-RS,
> PR #478). This is the at-a-glance reference; the per-connector settings + worked examples live in the DICOM
> section of [CONNECTIONS.md](CONNECTIONS.md), and the design rationale in
> [ADR 0025](adr/0025-dicom-codec-store-connectors.md).

MessageFoundry treats imaging as a first-class lane: modalities/PACS exchange **image and Structured Report
(SR)** objects over the **DIMSE** network protocol and, increasingly, over **DICOMweb** HTTP. The engine
carries a DICOM object **opaquely** (payload-agnostic ingress, [ADR 0004](adr/0004-payload-agnostic-ingress.md)),
base64-carried byte-faithfully through the str/store substrate ([ADR 0028](adr/0028-base64-binary-carriage-codec.md)),
and a **pure, code-first** codec parses it on demand. The differentiator over the incumbents: the **SR → HL7 v2
mapping is a versioned, unit-testable Python Handler**, not a proprietary GUI mapper.

**Scope boundary (by design): headers + Structured Report only — no pixel data, no `numpy`.**

---

## 1. What's supported

| Capability | Direction | Status | Surface |
|---|---|:--:|---|
| **C-STORE SCP** — receive stored objects | inbound (DIMSE) | ✅ | `DICOM()` + `content_type="dicom"` |
| **C-STORE SCU** — forward/send objects to a PACS | outbound (DIMSE) | ✅ | `DICOM(host=…, called_ae_title=…)` |
| **C-ECHO** — connectivity verification | both | ✅ | SCP accepts Verification; SCU `test_connection` |
| **DICOMweb STOW-RS** — store/send over HTTP | outbound (HTTP) | ✅ | `DICOMweb(url=…)` |
| **DICOM codec** — `DicomPeek` (routing) + `DicomDataset` (header + SR walk) | — | ✅ | `messagefoundry.parsing.dicom` |
| **SR/header → HL7 v2** mapping (ORU/OBX, PID/OBR) | — | ✅ | code-first Handler + `parsing.dicom.hl7_map` |
| **DICOM-over-TLS** (server + client, opt-in mTLS) | both | ✅ | `tls=true` (+ cert/key/ca) |

## 2. What's intentionally *not* supported

These are **declined or deferred by design** in [ADR 0025](adr/0025-dicom-codec-store-connectors.md):

| Not built | Why |
|---|---|
| **MWL** (serving a Modality Worklist) | Owner explicitly declined; Mirth doesn't serve it either |
| **MPPS** (Modality Performed Procedure Step) | Out of scope |
| **Query/Retrieve** — C-FIND / C-MOVE / C-GET | Out of scope (Mirth doesn't have these) |
| **DICOMweb QIDO-RS / WADO-RS** (query/retrieve over HTTP) | Out of scope; our DICOMweb is **store/send only** |
| **Inbound DICOMweb (STOW-RS) receiver** | Deferred — needs the inbound HTTP listener (ADR 0023, not yet authored; [backlog](archive/backlog/BACKLOG-CLOSED.md#7-inbound-soaprest-listener--web-service-source-v03) #7) |
| **Pixel-data transformation / rendering**, `numpy` | Headers + SR only — also a security boundary (no decompression-bomb surface) |

---

## 3. Transports

### Inbound — C-STORE SCP (`DICOM()` inbound)
A `pynetdicom` Application Entity C-STORE SCP so modalities/PACS can **send** objects in. Runs the blocking AE
server **off the asyncio event loop**, bridges each received object back onto the loop, and returns C-STORE
**Success only after** the object is durably committed to the ingress stage (**commit-before-SUCCESS** — the
DIMSE analog of MLLP's commit-before-ACK; nothing is accepted-and-dropped). Security: calling-AE allowlist +
peer-IP allowlist + `require_called_ae_title` + a `max_object_bytes` cap (over-cap → DIMSE failure *before*
commit) + DICOM-over-TLS. A non-loopback cleartext SCP is refused at startup unless `serve --allow-insecure-bind`.

### Outbound — C-STORE SCU + C-ECHO (`DICOM()` outbound)
Forward an object to a downstream PACS over a C-STORE association (full Mirth-sender parity). The blocking
association runs **off the loop**; the C-STORE status is classified onto the engine's retry model:

- **Success** (`0x0000`) / **Warning** (`0xB0xx`, stored with a caveat) → delivered.
- **Out of Resources** (`0xA7xx`) or an association/transport failure → **transient** `DeliveryError` (retried).
- A **rejected presentation context**, an **unencodable dataset**, or any **hard refusal** (Cannot Understand,
  dataset-mismatch, Not Authorized, SOP-class-unsupported) → **permanent** `NegativeAckError` → dead-letter
  (a deterministic failure never head-blocks the FIFO lane).

`test_connection` issues a **C-ECHO** (the console's "Test Connection"). DICOM-over-TLS client verifies the
peer's server cert (loads the system trust store; `tls_ca_file` pins a private anchor; `tls_cert_file`/`_key_file`
opt into mTLS).

### Outbound — DICOMweb STOW-RS (`DICOMweb()`)
The modern HTTP imaging lane — `POST {base}/studies` (or `…/studies/{study_uid}`) framed as
`multipart/related; type="application/dicom"`. It is a **sibling of the REST destination**: it reuses
`transports/rest.py`'s hardened HTTP plumbing (no-redirect TLS-verifying opener, cleartext-credential refusal,
the retry/dead-letter classification, the `[egress].allowed_http` gate) and adds only the multipart framing
(with a per-request collision-checked random boundary) + `application/dicom+json` response handling (a per-instance
`FailedSOPSequence` → permanent dead-letter). **No new dependency** and **no `[dicom]` extra** — the object rides
as opaque bytes. This **exceeds** both incumbents (neither Mirth nor Corepoint ships DICOMweb send out of the box).

---

## 4. Codec — `messagefoundry.parsing.dicom`

A pure, side-effect-free, console-importable library (zero engine imports), mirroring the python-hl7 / hl7apy
two-tier split:

- **`DicomPeek`** — the tolerant **routing** peek (a cheap shallow tag read: SOP class, modality,
  study/series/instance UIDs, AE titles, `is_structured_report()`); no full dataset walk, no pixel data.
- **`DicomDataset`** — the full **header + SR `ContentSequence` walk** (measurements as coded NUM items), built
  on demand in a Handler.
- **`hl7_map`** — pure helpers a code-first Handler composes to build HL7 v2 (header → ORM/ORU fields; each SR
  measurement → an `OBX`), HL7-escaped and CR/LF-guarded.

Backed by the optional **`[dicom]` extra** (`pydicom>=3.0.2,<4` + `pynetdicom>=3.0.4,<4`, pure-Python, **no
numpy**), lazily imported so a SQLite-only install and a console peek-import stay driverless.

---

## 5. Reliability & PHI

- **At-least-once + commit-before-SUCCESS.** The SCP commits the raw object durably before SUCCESS; a crash/cancel
  before commit just means the SCU re-sends. Routers/transforms must be **pure**; outbound delivery must be
  **idempotent** (a re-store of the same `SOPInstanceUID` is the native lever).
- **Count-and-log.** Every received object is persisted with a disposition — never accepted-and-dropped; a
  malformed/non-DICOM body dead-letters as `ERROR` (fail-loud).
- **PHI.** A DICOM object is PHI (header + pixel data). It is stored through the encrypting store, **never logged
  at INFO+**, and egress-allowlisted. Every log/error line carries only **routing-safe identifiers** (SOP
  class/instance UID, AE title, peer host) or a redacted URL — never the dataset, an element value, or pixel data.
- **Egress is fail-closed.** A DIMSE destination is gated by `[egress].allowed_tcp`; a DICOMweb destination by
  `[egress].allowed_http` — both enforced at load/reload/start.

---

## 6. vs. Mirth & Corepoint

| Capability | Mirth | Corepoint "DICOM Gear" | MessageFoundry |
|---|:--:|:--:|:--:|
| C-STORE SCP (receive) | ✅ | ✅ | ✅ |
| C-STORE SCU (send) | ✅ | ✅ | ✅ |
| C-ECHO | ✅ | ✅ | ✅ |
| SR/header → HL7 v2 transform | ~ (transport only) | ✅ (GUI mapper) | ✅ **code-first Handler** |
| DICOMweb STOW-RS send | ❌ | ❌ | ✅ **(exceeds both)** |
| MWL / Query-Retrieve / pixel data | ❌ | partial | ❌ (out of scope) |

**Net:** full parity with Mirth's DICOM transport scope, a code-first replacement for the transformation value
Corepoint sells behind a GUI, and the modern DICOMweb send lane neither incumbent ships — while deliberately
omitting MWL / Query-Retrieve / pixel handling.

> **Validation note:** the connectors are verified against the DICOM protocol with real `pynetdicom` loopback
> tests (and the DICOMweb framing/classification with mocked HTTP), **not yet** against a specific vendor PACS.
> A real-feed validation (the partner's SOP classes, transfer syntaxes, AE titles) is the step before cutover.

---

## 7. Pointers

- Per-connector settings + worked Router/Handler examples: [CONNECTIONS.md](CONNECTIONS.md) (§ DICOM).
- Design rationale, options, security analysis: [ADR 0025](adr/0025-dicom-codec-store-connectors.md).
- Binary carriage of the object through the store: [ADR 0028](adr/0028-base64-binary-carriage-codec.md).
- Payload-agnostic ingress (`content_type` / `RawMessage`): [ADR 0004](adr/0004-payload-agnostic-ingress.md).
- PHI handling rules: [PHI.md](PHI.md).
