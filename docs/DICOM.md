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
| **Inbound DICOMweb (STOW-RS) receiver** | Deferred — needs the inbound HTTP listener (ADR 0023, not yet authored; [backlog](BACKLOG.md) #7) |
| **Pixel-data transformation / rendering**, `numpy` | Headers + SR only — also a security boundary (no decompression-bomb surface) |

---

## 3. Transports

### Inbound — C-STORE SCP (`DICOM()` inbound)
A `pynetdicom` Application Entity C-STORE SCP so modalities/PACS can **send** objects in. Runs the blocking AE
server **off the asyncio event loop**, bridges each received object back onto the loop, and returns C-STORE
**Success only after** the object is durably committed to the ingress stage (**commit-before-SUCCESS** — the
DIMSE analog of MLLP's commit-before-ACK; nothing is accepted-and-dropped). Security: calling-AE allowlist +
peer-IP allowlist + `require_called_ae_title` + a `max_object_bytes` cap (charged against the raw received
Data Set *before* it is decoded, so an over-cap object is a DIMSE failure before any decode, re-encode or
commit; never above the engine's 16 MiB binary ingress ceiling, and an object past twice it ends the
association before it is held) + DICOM-over-TLS. An object the engine's
ingress refuses is recorded `ERROR` and answered with a DIMSE failure, never Success (BACKLOG #1910). A non-loopback cleartext SCP is refused at startup unless `serve --allow-insecure-bind`.

**The SCP checks the peer address before it reads anything.** The address is known as soon as the
connection is accepted, so that check comes first. The calling AE title is only known once the
association request is read, so that check comes later. The table lists at least these controls,
in the order the SCP applies them.

| Control | When the SCP applies it | What a peer that fails it gets |
|---|---|---|
| `source_ip_allowlist` | when the connection is accepted, before the TLS handshake and before anything is read from the peer | the connection is closed. No association forms, so no object is sent |
| the caps on connections with no association yet | when the connection is accepted, after the address check, on cleartext and on TLS | the connection is closed before a thread is started for it |
| the TLS handshake (`tls=true`), with the client certificate when `tls_ca_file` is set | after the address check, on the connection's own thread, and within 10 seconds | the connection is closed. A handshake that is slow, or never starts, does not delay another sender's |
| the deadline on the association request | on the connection's own thread, for the whole of the first PDU, within `timeout_seconds` | the connection is closed, and the refusal is logged. No association was started for it |
| `calling_ae_allowlist` and `require_called_ae_title` | when the association request is read | the association is rejected. No object is sent |
| `max_pdu_size` | for each PDU after the association request, on the length the PDU declares, before its body is read | an A-ABORT, and the association ends |
| twice the effective `max_object_bytes` | for each object, as its fragments arrive, before pynetdicom holds them | an A-ABORT, and the association ends. No status is sent for that object |
| the effective `max_object_bytes` | for each C-STORE, once the object has been received and before it is decoded | status `0xC010`, below |

The 10 second handshake bound is a deadline for the whole handshake. It is the same constant the
MLLP listener uses, and it is not a setting.

One SCP holds at most 256 connections with no association yet, and at most 32 from one peer address.
A connection counts from accept until its association starts.
So that is also at most 256 TLS handshakes at once, and at most 32 from one peer.
A connection over either number is closed. The numbers are the MLLP listener's two connection caps.
Here they are constants, not settings.

**A peer has `timeout_seconds` to deliver its whole association request.** That is a deadline, not
an idle timer, so a peer that sends a byte at a time is ended on time, as a silent one is. The clock
starts when the SCP starts to read, after any TLS handshake and any
`max_associations_per_second` wait. An SCU sends its request as soon as it connects, so a working
sender does not meet this. The first PDU has to be a well-formed association request of at most 256 KiB.
PS3.8 sets no limit on that PDU, so a larger request is legal in the format, but a modality would
not need one. Anything else is closed at once. A first PDU that is not an association request, and
a request over that size, get no answer: the rest of what the peer sent is left unread, and a close
over unread data resets the connection, so an answer could not be relied on. A whole request the SCP
decodes and refuses gets an A-ASSOCIATE-RJ, rejected-permanent, before the close, so a sender can
tell it will be refused again. At least these are refused that way: one whose protocol version
field does not set bit 0, which names version 1, and one the association could not negotiate, such as a presentation context that names no
transfer syntax or no abstract syntax. A whole request that does not decode is an invalid PDU, and
gets the A-ABORT the standard's state table gives one. The SCP runs pynetdicom's own presentation
context negotiation on the request before it starts the association, so a request that would fail
there never starts one.

**After that, each PDU has a deadline too.** The SCP reads a PDU's header and then its body, and
each read has `timeout_seconds`, however slowly the bytes arrive. A peer that stops part way through
a PDU is ended there. This is a deadline per read, not per object, so at the default 30 seconds a
sender sending PDUs of the shipped 16 KiB `max_pdu_size` has to keep up about 0.5 KiB per second.
Raising `max_pdu_size`, or lowering `timeout_seconds`, raises that floor. A peer that keeps finishing
PDUs is not ended by this. Each send has a `timeout_seconds` deadline for the whole send too, so a
peer that stops reading, or reads a little at a time, is ended. Once the SCP is stopping, a send has
at most 1.5 seconds more, so that the status for an object committed as the stop began still goes
out.
`timeout_seconds` has to be at least 1 second, since it is a deadline on every read and send and a
tiny one would end nearly every peer. `max_pdu_size` has to be from 4096 to 1 MiB: `0` would offer a
peer no limit at all, a size of six bytes or less breaks a pynetdicom sender, and a larger one would
be read whole before any of it is counted. The connection is refused when it is built otherwise.

**A PDU longer than the SCP takes, and an object past twice its cap, end the association.** The SCP
reads each PDU's header and checks the length it declares before it reads the body (owner ruling
B462-R3). A P-DATA-TF, the PDU that carries an object, may be as long as the `max_pdu_size` the SCP
offered: a pynetdicom sender fragments to exactly that, and PS3.8 Annex D.1 bounds that field. Any
other PDU may be as long as an association request, 256 KiB. A longer one gets an A-ABORT, and its
body is not read, so a peer cannot have the SCP read the 4 GiB a PDU can declare.

The SCP then counts each object's fragments as they arrive, before pynetdicom holds them, which it
does until the object's last fragment arrives. An object over the effective `max_object_bytes` but
not past twice it is held, and then refused with the final status `0xC010`. The effective cap is the smaller of `max_object_bytes` and the engine's 16 MiB binary ingress
ceiling, so at the shipped 128 MiB it is 16 MiB, and a 20 MiB object, under the configured value,
is still over it. One past
twice the effective cap gets an A-ABORT instead, so what the SCP holds of one object stays bounded: 32 MiB at the
shipped default, where the effective cap is 16 MiB, plus the one PDU being read. The count starts
again at each object's last fragment, so a long association of objects under the cap is never
charged as one. A command set past 64 KiB is ended the same way; a real one is a few hundred bytes.
So is a P-DATA-TF that pynetdicom would fail on, at least a second command set in one message, a
data set fragment before its command, a command set pynetdicom cannot read, and anything after the
item that completes a message; pynetdicom would log each with a traceback, or lose its thread to
it. So is any command but a C-STORE or C-ECHO request, the two the SCP serves, since pynetdicom
serves some others on a thread of their own, outside the hold below.

While a whole object waits for the SCP to serve the one before it, the SCP reads nothing more on
that association, and TCP holds the peer back. A peer that sends objects without waiting for their
statuses therefore has at most two held at once: the one being served and the next.

The SCP will not start, and refuses each connection, while pynetdicom's process-wide
`STORE_RECV_CHUNKED_DATASET` is set. That setting would write each object being received to a
temporary file in plaintext, outside the store.

The abort changes what a sender of a large object sees. `0xC010` is a final refusal, which a sender
does not retry. A failed association reads as transient, and this engine's own C-STORE client
retries one at the head of its lane, so a sender whose own cap is above twice this SCP's would
retry such an object for as long as it is sent. The engine's client defaults to 128 MiB. Clamping
the client to a peer's limit is separate work, not built here.

**A peer that stalls before its request is complete does not use up `max_associations`.** It never
gets an association, so with `max_associations=2` and three stalled peers held, a real sender is
served. At least these limits apply:

- A stalled peer holds one of the slots above until the deadline. Up to 32 stalled connections from
  one address, or 256 in all, would refuse a sender that shares the address, or any sender, until
  those deadlines run out. A peer that reconnects as soon as it is closed can take the slot again,
  so a sender then gets in only by reaching a free slot first. A sender behind one NAT address
  shares that address with every other sender there.
- A connection waiting on `max_associations_per_second` has no association yet, so it holds a slot
  too. A rate low enough to keep many senders waiting can fill the slots, and a connection over them
  is closed.
- A peer that sends a whole request and then stalls has an association, so it counts against
  `max_associations`. The idle timer, the header read and the body read each have `timeout_seconds`,
  so one peer could hold that slot for about three times `timeout_seconds`, 90 seconds at the default.
  Only an association the SCP accepted can do this. Over `max_associations` the request is rejected
  once it is decoded, whatever follows it. Before the SCP closes a connection it has answered, it
  reads off what the peer has already sent behind the request, up to 64 KiB and without waiting for
  more, so the close does not reset the connection and lose the answer. A peer that has sent more
  than that can still get a reset in place of the answer. The same holds for the A-ABORT that ends
  an association whose PDU is too long, since its body is left unread.
- An object up to twice the effective `max_object_bytes` is held whole before it is refused, and
  an association holds up to two objects at once. So at the defaults the SCP can hold about 64 MiB
  per association, `max_associations` times over, plus what the C-STORE handler makes of an object
  under the cap when it decodes and re-encodes it.

**A sender the SCP refuses at accept sees only a closed connection.** It gets no DIMSE status and
no association rejection. So the sender cannot tell this refusal from an SCP it cannot reach, and a
sender that retries a failed connection will retry this one. This engine's own C-STORE client does:
it treats a failed association as transient, and the object keeps its place at the head of its
lane while it retries. The reason is in the SCP's log, not on the sender's side. Add the sender's
address to `source_ip_allowlist` to admit it.

**A refused address is logged once a minute, not once per connection.** The SCP writes one
`WARNING` per refused address per 60 seconds, and at most 20 such lines per 60 seconds over every
address together. Each line carries the SCP's running count of refusals, logged or not. An
association the SCP ends, because a read or a send ran out `timeout_seconds` or for one of the limits
above, is not a refusal, since the SCP had accepted it. It gets a `WARNING` that says the SCP ended an association, under the same throttle,
with its own count, so it never uses up an address's refusal line.

**A failed TLS handshake is counted and logged as a throttled `WARNING`** (vault BACKLOG
#3784). [PHI.md section 7, row 7](PHI.md#7-logging--phi-redaction) states what is counted,
the throttle, and what a line names. Each failure's detail is a `DEBUG` line. The SCP writes
no connection event for it.

**The C-STORE status the SCP answers tells the sender whether to re-send** (BACKLOG #2103). DICOM PS3.4
Annex B (Table B.2-1) has no "object too large" status. It has two failure classes that matter here.
**Out of Resources** (`0xA7xx`) says the SCP cannot take the object now; senders, this engine's own SCU
among them, retry it. **Cannot Understand** (`0xCxxx`) says the SCP will not take this object; senders
treat it as final. So the SCP answers the final class for a refusal that would repeat on a re-send, and
Out of Resources only for a failure that may clear.

The SCP answers at least these statuses:

| Status | Class | When the SCP answers it |
|---|---|---|
| `0x0000` | Success | the object is durably committed to the ingress stage |
| `0xC010` | Cannot Understand, final | the object is over the effective `max_object_bytes`, the smaller of `max_object_bytes` and the 16 MiB ingress ceiling, raw or re-encoded, but not past twice that, where the association is aborted instead; or a deflated object inflates past the SCP's inflate bound. That bound is the lesser of `max_object_bytes` and 16 MiB, the ceiling the codec applies when a Router parses the object (BACKLOG #2104). Both limits are fixed, so a re-send is refused again |
| `0xC000` | Cannot Understand, final | the object would not decode or re-encode, the engine's ingress refused it and recorded `ERROR`, or the SCP hit an error it did not expect, including running out of memory |
| `0xA700` | Out of Resources, re-send | the commit raised, for example a store that is down; the commit did not finish within `timeout_seconds`; or the engine's loop is not running |
| `0x0124` | Refused: Not Authorized | the peer IP is not in `source_ip_allowlist`. This is a second check behind the one at accept, which closes such a peer's connection before any association forms, so a sender should not see this status. Each one is logged |

The low byte of `0xC010` is the SCP's own choice, which PS3.4 allows inside `0xCxxx`. It separates an
over-cap refusal from a decode failure in the sender's log. It stays clear of the codes `pynetdicom`
answers on its own for C-STORE: `0xC001` and `0xC002` for a malformed handler status, and `0xC211`
when the handler raises.

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

A pure, side-effect-free, console-importable library (zero engine imports), mirroring the HL7 v2 tolerant parser / hl7apy
two-tier split:

- **`DicomPeek`** — the tolerant **routing** peek (a cheap shallow tag read: SOP class, modality,
  study/series/instance UIDs, AE titles, `is_structured_report()`); no full dataset walk, no pixel data.
- **`DicomDataset`** — the full **header + SR `ContentSequence` walk** (measurements as coded NUM items), built
  on demand in a Handler.
- **`hl7_map`** — pure helpers a code-first Handler composes to build HL7 v2 (header → ORM/ORU fields; each SR
  measurement → an `OBX`), HL7-escaped and CR/LF-guarded.

Backed by the optional **`[dicom]` extra** (`pydicom>=3.0.2,<3.1` + `pynetdicom==3.0.4`, pure-Python, **no
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
