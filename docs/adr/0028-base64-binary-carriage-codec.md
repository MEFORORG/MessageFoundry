# ADR 0028 — base64 binary-carriage codec (+ HL7 OBX-5 ED embedding)

- **Status:** **Accepted (2026-06-20) — ratified on the owner's go.** Build may start (per the land-order, the carriage codec + `RawMessage` additions land first; consumers like DICOM [ADR 0025](0025-dicom-codec-store-connectors.md) build on `.raw_bytes`). Design-only so far (no code yet). The "To resolve on acceptance" confirmations are recommended at the stated positions and are taken as the answers on acceptance (the `## Decision (proposed)` heading stays captioned "(proposed)" after the status flips, as in [ADR 0022](0022-fhir-resource-codec-rest-client.md), mirroring [ADR 0012](0012-x12-edi-codec.md)'s `## Resolved`).
- **Built (this ADR):** Nothing here yet. It layers a **binary-carriage** semantic over **already-shipped** substrate the way FHIR ([ADR 0022](0022-fhir-resource-codec-rest-client.md)) and X12 ([ADR 0012](0012-x12-edi-codec.md)) layered codecs over the payload-agnostic ingress — no new dependency, stdlib `base64` only. Reused seams:
  - the payload-agnostic ingress ([ADR 0004](0004-payload-agnostic-ingress.md)): the non-HL7 branch of `_handle_inbound` ([wiring_runner.py:748-761](../../messagefoundry/pipeline/wiring_runner.py)) already commits a non-HL7 body verbatim to the ingress stage and hands the Router/Handler a **`RawMessage`** ([parsing/message.py:430-476](../../messagefoundry/parsing/message.py));
  - the str/TEXT store substrate on all three backends — `messages.raw` + `queue.payload` are `TEXT`/`NVARCHAR(MAX)` ([store/store.py:413,435](../../messagefoundry/store/store.py), [store/postgres.py:110,125](../../messagefoundry/store/postgres.py), [store/sqlserver.py:68,94](../../messagefoundry/store/sqlserver.py));
  - the store cipher seam — `IdentityCipher` stores verbatim and `AesGcmCipher` wraps with the `mfenc:v1:` envelope ([store/crypto.py:37,68-80,105-138](../../messagefoundry/store/crypto.py)); the carriage marker rides *beneath* it as an independent inner layer.
  - **Net-new (not free):** a pure `parsing/` codec module (stdlib `base64`); four `RawMessage` additions (`from_bytes`, `.raw_bytes`, `.binary()`, `.is_binary`); **one** source-boundary call site that constructs binary `RawMessage`s via `from_bytes` instead of the verbatim decode; the secondary OBX-5 ED embed/extract helpers; root [parsing/__init__.py](../../messagefoundry/parsing/__init__.py) re-exports.
- **Decision in one line:** carry arbitrary **bytes** over the str/TEXT ingress+store as **unbroken standard base64** behind a self-describing **`mfb64:v1:`** marker, exposed as **exactly one encode and one decode** on `RawMessage` (a pure stdlib codec), so consumers like DICOM ([ADR 0025](0025-dicom-codec-store-connectors.md)) never hand-roll base64 and never rely on the lossy latin-1 round-trip. **Supersedes [ADR 0025](0025-dicom-codec-store-connectors.md)'s latin-1 Option #7** for byte carriage; 0025 must be updated to cite §3 and drop its latin-1 round-trip before either ratifies (*To resolve on acceptance*).
- **Related:** [ADR 0004](0004-payload-agnostic-ingress.md) (payload-agnostic ingress — the `RawMessage` path this extends); [ADR 0012](0012-x12-edi-codec.md) + [ADR 0022](0022-fhir-resource-codec-rest-client.md) (the pure-`parsing/`-codec house pattern this mirrors); [ADR 0010](0010-handler-callable-db-lookup.md) (the `db_lookup` purity carve-out — base64 is the *opposite*: pure+deterministic, so it needs no carve-out); [ADR 0025](0025-dicom-codec-store-connectors.md) (DICOM — **the downstream consumer this ADR unblocks**; its binary-substrate problem is what this ratifies); the store-encryption context — `PREFIX = "mfenc:v1:"` and the cipher protocol in [store/crypto.py](../../messagefoundry/store/crypto.py); [CLAUDE.md](../../CLAUDE.md) §2 (reliability/purity + count-and-log invariants), §4 (the pure-`parsing/` console carve-out), §8 (HL7 conventions), §9 (PHI rules); [docs/PHI.md](../PHI.md) (PHI-at-rest + no-log rules); [docs/CONNECTIONS.md](../CONNECTIONS.md) (the connector surface a future binary-mode knob would live on).

---

## Context

MessageFoundry's non-HL7 ingress and **all three** store backends are **str/TEXT end-to-end**. The inbound listener hands a `SourceConnector` **bytes** (`InboundHandler = Callable[[bytes], Awaitable[str | None]]`, [transports/base.py:45](../../messagefoundry/transports/base.py)), and `_handle_inbound` immediately **decodes those bytes to `str`** under the connection's declared `encoding` (default `utf-8`, [wiring_runner.py:726-732](../../messagefoundry/pipeline/wiring_runner.py)). Everything downstream is `str`: the `RawMessage` the Router/Handler sees holds `raw: str` ([message.py:439-440](../../messagefoundry/parsing/message.py)); the store columns `messages.raw` and `queue.payload` are `TEXT` (SQLite/Postgres) / `NVARCHAR(MAX)` (SQL Server); and the **identity cipher binds the body verbatim into that TEXT column** ([crypto.py:73-76](../../messagefoundry/store/crypto.py)). There is no `BLOB`/`bytea` anywhere on the message path.

**The substrate problem (the crux).** Arbitrary bytes cannot ride a `str`/TEXT column safely. Two routes both fail:

- **Decode-as-text.** Non-UTF-8 bytes raise `UnicodeDecodeError`, and the current handler falls back to **`raw.decode("latin-1")`** — labelled "lossless byte view" at [wiring_runner.py:736](../../messagefoundry/pipeline/wiring_runner.py). It is **not** lossless across the store: latin-1 maps every byte `0x00–0xFF` to a Unicode codepoint, so a binary body becomes a `str` containing **`NUL` (U+0000)** and high codepoints. On Postgres, psycopg **rejects** a parameterized string containing `NUL` at bind time (`"string literal cannot contain NUL"`); on SQLite and SQL Server a `NUL` **silently truncates** the stored value. A DICOM Part-10 object is a **guaranteed** hit — its mandatory 128-byte all-zero preamble is 128 `NUL`s before the `DICM` magic. So today's latin-1 fallback is a **latent data-corruption bug** for any intentional binary body, and it only ever runs on the `ERROR`/NAK path — there is no *successful* way to carry bytes at all.
- **Store raw bytes in a BLOB column.** This would mean a `BLOB`/`bytea` schema migration on all three backends and a second, binary-typed cipher path — and it breaks the encoded-**TEXT** cipher seam (`encrypt(str) -> str`). Large, and it severs the clean `str`-in/`str`-out contract the cipher and the staged queue rely on.

**base64 over TEXT is the fix.** Encode bytes to **unbroken standard base64** — an ASCII-safe alphabet (`[A-Za-z0-9+/=]`) with **no `NUL`, no HL7 delimiter (`|^~\&`), no CR/LF** — *at the source boundary*, before the body ever becomes a stored `str`. The TEXT substrate, the identity cipher, and the staged queue carry it unchanged; the codec decodes it back to bytes on demand. No schema migration, no second cipher path, no latin-1.

**DICOM is consumer #1 and must be reconciled with this in lockstep.** [ADR 0025](0025-dicom-codec-store-connectors.md) (DICOM codec + store/connectors, Proposed 2026-06-20) needs a sanctioned way to carry a Part-10 object through ingress+store. As currently written, 0025's Option #7 **chooses** the latin-1 round-trip (`bytes.decode("latin-1")` at the SCP commit, `str.encode("latin-1")` to recover in the codec) and asserts it is "byte-exact for any 0–255 byte sequence." That assertion is **factually wrong across the store**: a `NUL` (U+0000) byte — and a DICOM Part-10 object's mandatory 128-byte all-zero preamble guarantees 128 of them — is rejected at psycopg bind on Postgres and silently truncated on SQLite/SQL Server (the substrate problem above). So 0025-as-written would reintroduce exactly the corruption this ADR exists to prevent. This ADR's carriage layer **supersedes** 0025's latin-1 Option #7: **0025 must be updated to cite §3 (`RawMessage.from_bytes` at the SCP, `.raw_bytes` in the codec) and drop the latin-1 round-trip before either ratifies** (*To resolve on acceptance*; flag to the DICOM-window coordinator). X12-binary and the HL7 OBX-5 ED document case (below) are the other near-term consumers.

**Competitive baseline.** Every integration engine base64s binary for the same reason — binary cannot live in a text/HL7 substrate, and base64's alphabet has no HL7-delimiter or CR collision. Mirth/NextGen Connect ships a **File Reader/Writer "Binary" mode** that auto-base64-encodes/decodes whole files at the *connector* (issue #274), plus a `FileUtil.encode/decode` scripting util; **HL7 Soup** has a File Writer "Binary" message-type that "automatically decodes the value from base64"; **Qvera QIE** exposes `qie.base64EncodeBytes(...)` + `message.setNode('OBX-5', ...)`; **InterSystems IRIS** has first-class OBX-`ED` `StoreFieldStreamBase64`/`GetFieldStreamBase64`. (Corepoint/Rhapsody plausibly offer connector binary-write auto-decode and declarative encode/decode actions, but their docs are gated and this is **unverified** — we do not lean on it.) Two observations carry into the decision: (1) competitors key "this body is binary" off **connector config or data-type**, never an **in-band self-describing marker on the stored body** — MessageFoundry's `mfb64:v1:` sentinel (orthogonal to `content_type`, distinct from the `mfenc:` cipher envelope) is a defensible **novelty**, not table stakes; (2) the line-wrap hazard is universally flagged — **emit unbroken** base64, never MIME-wrapped.

**PHI / inflation.** A base64-carried body is **still PHI** — base64 is encoding, not obfuscation; the no-log rules ([CLAUDE.md](../../CLAUDE.md) §9, [docs/PHI.md](../PHI.md)) apply unchanged and the codec logs nothing. base64 inflates ~33%, so size caps and the retention budget must measure the **encoded** size (the size actually at rest).

**HL7 ED use case (secondary).** Inside an otherwise-normal HL7 v2 message, a document (PDF, image) is embedded in **OBX-5** with **OBX-2 = `ED`** (Encapsulated Data); the ED datatype's component 4 (`Encoding` = `Base64`) is HL7's **own in-band marker** for the base64 in component 5. This shares the same stdlib base64 primitives but is a **different layer with a different marker** — covered as a subordinate section, never wrapped in `mfb64:`.

Project constraints honored throughout: **No grouping unit / code-first** ([CLAUDE.md](../../CLAUDE.md) §1) — this adds no "channel"/"route" element and no declarative transform surface; **payload-agnostic, hot-path-cheap** ([CLAUDE.md](../../CLAUDE.md) §8) — carriage is orthogonal to `content_type` and adds nothing to HL7 routing; **`parsing/` stays pure** ([CLAUDE.md](../../CLAUDE.md) §4) — the codec is stdlib-only and console-importable.

---

## Decision (proposed)

### 1. A pure binary-carriage codec module under `parsing/`

Add a **pure, side-effect-free** module — proposed **`messagefoundry/parsing/binary.py`** (a single ~150-line file; not a subpackage like `x12/`/`fhir/`, and **not** `base64.py`, which would shadow the stdlib) — depending on **stdlib `base64` only, zero new dependencies**. It is console-importable under the [CLAUDE.md](../../CLAUDE.md) §4 `parsing/` carve-out (the console may import it for raw-view rendering), exactly as `parsing/x12/` and `parsing/fhir/` are.

It provides the low-level primitives and the typed error:

- `encode(data: bytes) -> str` — `base64.b64encode(data).decode("ascii")` → an **unbroken** standard-base64 string, then prefixed with the canonical marker (§2). **`b64encode`, never `base64.encodebytes`** — `encodebytes` inserts a `\n` every 76 bytes (RFC 2045 MIME wrap), which would plant CR/LF in the body and, inside an HL7 field, break the segment.
- `decode(s: str) -> bytes` — strip the marker, **strip incidental whitespace/CR/LF**, validate, and `base64.b64decode(...)`. Malformed input (bad padding / non-alphabet content) **raises a typed `BinaryCarriageError`** so the message **dead-letters** (`ERROR`) rather than corrupting silently — honoring the count-and-log invariant ([CLAUDE.md](../../CLAUDE.md) §2). Catch `binascii.Error` explicitly and re-raise typed; never `except:` ([CLAUDE.md](../../CLAUDE.md) §6).
- `is_marked(s: str) -> bool` — a prefix test for `mfb64:v1:`.

Exports follow the X12/FHIR idiom — a module `__all__`, re-exported from the root [parsing/__init__.py](../../messagefoundry/parsing/__init__.py) `__all__` with a "full surface under the submodule" comment.

### 2. The `mfb64:v1:` carriage form, and its independence from the cipher layer

The canonical self-describing stored form is:

```
mfb64:v1:<unbroken-standard-base64>
```

- **`mfb64:`** — the sentinel that says "this body is carried binary." **`v1`** versions the carriage so a future algorithm (e.g. base85, if 33% inflation ever bites) can ship as `v2` without ambiguity.
- It is an **independent INNER layer beneath the store cipher**. The cipher is the **outer** layer with its own `mfenc:v1:` envelope ([crypto.py:37,108-112](../../messagefoundry/store/crypto.py)):
  - **Identity cipher** stores the `mfb64:v1:…` string **verbatim** — round-trips intact.
  - **AES-GCM cipher** wraps the whole `mfb64:v1:…` string inside `mfenc:v1:<key_id>:<base64(nonce‖ct‖tag)>`. On read, `decrypt()` **fully consumes** its own envelope and returns the inner `mfb64:v1:…` plaintext **before** the carriage codec ever sees it — so there is **no double-decode** and the two base64 layers never interleave.
  - **No prefix collision:** `mfb64:` ≠ `mfenc:`, and `cipher.is_encrypted()` is a `startswith("mfenc:v1:")` test only ([crypto.py:80,105](../../messagefoundry/store/crypto.py)) — it never matches a carriage marker.

### 3. Binary carriage contract — the API (for ADR 0025 to cite)

> **This section is the citable contract. ADR 0025 (DICOM) and every future binary consumer references it. The rule is: exactly one encode, exactly one decode, and consumers never hand-roll base64.**

- **One encode — at the SOURCE boundary:**
  `RawMessage.from_bytes(data: bytes, content_type: str) -> RawMessage`
  The **only** place bytes become a carried body. It calls the §1 `encode`, producing a `RawMessage` whose `.raw` is `mfb64:v1:<base64>`. The non-HL7 source path (`_handle_inbound`) constructs binary `RawMessage`s through this factory **instead of** the verbatim/latin-1 decode, so intentional binary never touches the lossy fallback.
- **One decode — at the CODEC / consumer boundary:**
  `RawMessage.raw_bytes -> bytes` (property) and its method alias `RawMessage.binary() -> bytes` — strip the marker, decode, **fail loud** on corruption. This is the **only** decode; a DICOM/X12 codec calls `.raw_bytes`, never `base64.b64decode(msg.raw)`.
- **The test:**
  `RawMessage.is_binary -> bool` — whether `.raw` carries the `mfb64:v1:` marker. Symmetric with `cipher.is_encrypted()`. The console/replay/dead-letter raw-view branches on this **without** a `content_type → is-binary` registry.

Consumers **never** call `base64.*` directly; the marker/whitespace/fail-loud logic lives in exactly one place.

### 4. The `RawMessage` additions

`RawMessage` is `str`-only today — `.raw`, `.text`, `.json()`, `.xml()`, `.encode()` all return/operate on `str` ([message.py:430-476](../../messagefoundry/parsing/message.py)); there is **no** bytes accessor. This ADR adds, backed by the §1 codec:

| Member | Kind | Returns | Behavior |
|---|---|---|---|
| `from_bytes(data, content_type)` | classmethod factory | `RawMessage` | `encode` bytes → `mfb64:v1:<base64>`; the one encode |
| `.raw_bytes` | property | `bytes` | strip marker → `b64decode` → bytes; fail loud (§5) |
| `.binary()` | method | `bytes` | alias of `.raw_bytes` (symmetric with `.text`/`.json()`/`.xml()`) |
| `.is_binary` | property | `bool` | `mfb64:v1:` marker present? |

The existing str accessors are unchanged. (`content_type` stays the **format** tag — `dicom`, `x12`, `application/octet-stream`; the marker is **carriage**, orthogonal to it.)

### 5. Fail-loud decode (count-and-log)

`.raw_bytes`/`decode` raise the typed `BinaryCarriageError` (wrapping `binascii.Error`) on bad padding or non-alphabet content. The caller routes the message to the **error/dead-letter path** (`ERROR` disposition) — never a silent short read, never a swallowed exception. This preserves the **count-and-log invariant**: every received message is persisted and finalized with a true disposition; a corrupt carried body is a logged `ERROR`, not an accept-and-drop ([CLAUDE.md](../../CLAUDE.md) §2/§6).

**Purity / reliability.** base64 encode and decode are **pure and deterministic** — same bytes in, same string out; same string in, same bytes out — with **no external side effects**. They satisfy the at-least-once reliability invariant outright: a re-run after a crash re-derives the identical carried body, so routers/transforms that carry binary stay pure. This is the **opposite** of `db_lookup` ([ADR 0010](0010-handler-callable-db-lookup.md)), which needed an explicit non-purity carve-out because its result can differ across passes; carriage needs **no** carve-out.

### 6. What this is NOT

- **NOT a new `content_type`.** Carriage is **orthogonal** to format. `content_type` stays the format tag; `mfb64:` is how bytes ride, whatever the format.
- **NOT a pipeline routing-logic edit.** `parsing/` stays pure; the **only** seams are the source-boundary `from_bytes` call site and the `RawMessage` accessors. Routing/filtering logic is untouched.
- **NOT a "channel"/"route" element.** No graph-bundling object is added.
- **NOT a declarative/visual transform surface, and NOT a `BLOB`/`bytea` store migration** — encode/decode stays code-first via the `RawMessage` API ([CLAUDE.md](../../CLAUDE.md) §12, [BACKLOG #26](../BACKLOG.md)) and all three backends stay TEXT/NVARCHAR(MAX), preserving the encoded-TEXT cipher seam (both also listed under Consequences → Out of scope).

### 7. HL7 OBX-5 ED embedding (secondary)

A **subordinate** capability, sharing the §1 primitives but **not** the `mfb64:` wrapper. Inside an HL7 v2 message (`content_type = hl7v2`, parsed to a `Message`), a document is embedded in **OBX-5** with **OBX-2 = `ED`**. The ED datatype's five components are `<source-app HD> ^ <type-of-data ID> ^ <data-subtype ID> ^ <Encoding ID> ^ <Data>`, and **component 4 = `Base64`** is HL7's **own in-band marker** for the base64 payload in component 5. Example single OBX:

```
OBX|1|ED|PDF^^^^||^Application^PDF^Base64^JVBERi0xLjQK...||||||F
```

Helpers (proposed as functions in `parsing/binary.py`, or as `Message` methods — see open questions) **embed** bytes into an OBX-5 ED field and **extract** bytes back out:

- They emit the data component with **unbroken** `b64encode` — **CR/LF-collision-safe**: HL7's segment delimiter is **CR**, and any wrapped base64 (`encodebytes`) would plant a `\n` (LF) every 76 bytes (RFC 2045) — a CR/LF that many tolerant HL7 parsers treat as a segment terminator, truncating the OBX. The base64 alphabet itself never collides with `|^~\&`.
- The in-band marker is the **`Base64` literal in component 4** — read from the **parsed segment**. **No `mfb64:` wrapper ever appears inside an HL7 field** (it would corrupt the segment); an HL7-aware **Handler** branches on component 4 and decodes component 5.
- **Decode posture:** tolerate a partner's incidental whitespace (strip it), but let bad **padding** (`binascii.Error`) **propagate** as fail-loud → `ERROR`. Read the `Encoding` component from the parsed model; never string-slice ([CLAUDE.md](../../CLAUDE.md) §8).
- **Multi-OBX auto-chunking is deferred** (§ Out of scope). For oversized documents some senders split across consecutive `ED` OBX segments keyed by OBX-1 Set ID; the receiver must **concatenate OBX-5 data in OBX-1 order, then decode once** (per-chunk decode is unsafe — chunk boundaries are not guaranteed to fall on 4-char base64 groups). The MVP helper handles a **single** OBX-5; chunking is a follow-up.

**The one-line distinction:** the ED `Base64` component is HL7's in-band marker for a base64 document *inside a field*; `mfb64:v1:` is MessageFoundry's substrate marker for a *whole binary payload* in the TEXT store. They never nest — the OBX-5 document is decoded by an HL7-aware Handler, not by the carriage codec.

---

## Options considered

1. **Carriage encoding: base64-over-TEXT (CHOSEN) vs latin-1 round-trip vs a BLOB/bytea migration.** *latin-1* — decode bytes as latin-1 into the existing TEXT column — is the current `wiring_runner.py:736` fallback and the route DICOM ([ADR 0025](0025-dicom-codec-store-connectors.md)) currently **chooses** (its Option #7) and which this ADR supersedes: it plants `NUL` (U+0000), which Postgres rejects at bind and SQLite/SQL-Server silently truncate; a DICOM preamble guarantees the hit, so its "byte-exact for any 0–255 byte sequence" claim does not hold across the store. **Rejected** (latent corruption). A *BLOB/bytea migration* across all three backends would store true bytes but is large, needs a second binary cipher path, and breaks the encoded-TEXT cipher seam. **Rejected/deferred.** base64 over the existing TEXT substrate has no NUL/delimiter/CR collision, needs no migration, and preserves the cipher seam. **CHOSEN.**
2. **Binary signaling: a self-describing `mfb64:` marker (CHOSEN) vs `content_type`-alone.** Signaling binariness via `content_type` alone forces the console/replay/dead-letter raw-view to consult a `content_type → is-binary` registry to know whether to decode-for-display — coupling, and brittle for ad-hoc/unknown types. The in-band marker is **stateless and self-describing**: `.is_binary` answers from the body itself, no registry (the defensible novelty per Context). **Rejected (content_type-alone), CHOSEN (marker).**
3. **Decode access: a `RawMessage` accessor (CHOSEN) vs consumers calling `base64.b64decode(.raw)` themselves.** Hand-rolled decode at each call site re-implements the marker-strip, whitespace tolerance, and fail-loud typed-error logic everywhere — drift and silent-corruption risk. One `.raw_bytes`/`.binary()` accessor centralizes it. **Rejected (hand-rolled), CHOSEN (accessor).**
4. **Connector binary mode (Mirth/HL7-Soup style) — relate, DEFER.** A `File`/source flag that auto-base64-encodes a whole file on read and a destination that auto-decodes on write is the strongest competitor analog (Mirth File Reader/Writer "Binary", HL7 Soup). It is **not rejected** — but its **mechanism is `from_bytes`** (the source-boundary encode this ADR builds). Shipping the config *knob* is a separable follow-up; this ADR builds the mechanism it would call. **Deferred (knob), built (mechanism).**
5. **Corepoint-style declarative encode/decode action — REJECTED.** A declarative/visual "base64 encode" transform step contradicts the code-first, no-declarative-transform stance ([CLAUDE.md](../../CLAUDE.md) §12). **Rejected.**

---

## Consequences

**Positive**

- **Unblocks DICOM ([ADR 0025](0025-dicom-codec-store-connectors.md))** and any binary consumer with one sanctioned, citable carriage contract (§3) — once 0025 is updated to cite §3 in place of its latin-1 Option #7 (the lockstep reconciliation, *To resolve on acceptance*); the latin-1 corruption window is then closed for intentional binary.
- **Zero new dependency** — stdlib `base64` only; the codec is pure and console-importable ([CLAUDE.md](../../CLAUDE.md) §4), matching the X12/FHIR pure-codec pattern.
- **No schema migration** — TEXT/NVARCHAR(MAX) and both ciphers carry `mfb64:` unchanged; the cipher's `mfenc:` envelope stays the clean outer layer with no double-decode.
- **Reliability-safe** — pure+deterministic encode/decode satisfies the at-least-once invariant with **no** ADR-0010-style carve-out.
- **Centralized** — exactly one encode, one decode; consumers never hand-roll base64, so the marker/whitespace/fail-loud rules live in one place.
- **Self-describing** — `.is_binary` lets console/replay/dead-letter raw-views decode-for-display with no `content_type` registry (the novelty per Context).

**Negative / risks**

- **~33% size inflation** at rest (and in the encrypted envelope). Size caps and the retention budget must measure the **encoded** size; very large binaries (DICOM pixel data) stress the TEXT column and the staged queue. Attachment-offload (Mirth-style) is a possible future mitigation, out of scope here.
- **PHI surface** — a base64 body is still PHI; the no-log rules ([CLAUDE.md](../../CLAUDE.md) §9, [docs/PHI.md](../PHI.md)) apply, and **raw-view decode-for-display is a console concern that must be audited** like any raw PHI access. The codec itself logs nothing.
- **Two markers, one alphabet** — `mfb64:` (substrate) and the OBX-5 `Base64` component (in-field) must never be confused or nested; the §7 rule is load-bearing and must be enforced by review.
- **One new source-boundary call site** — the non-HL7 `from_bytes` path is net-new behavior on the hot ingress path and must be covered by tests (round-trip + corrupt-input dead-letter + NUL-bearing binary across all three store backends).

**Out of scope (deferred / explicitly NOT promised)**

- The **connector binary-mode knob** (auto-encode-on-read / auto-decode-on-write `File`/destination flag) — mechanism (`from_bytes`) is built; the config surface is a follow-up (Option 4).
- **Multi-OBX auto-chunking** for oversized ED documents (concatenate-then-decode by OBX-1 Set ID) — MVP handles a single OBX-5 (§7).
- A **BLOB/bytea store migration** — explicitly not done (Option 1).
- **DICOM specifics** — the codec, store layout, and connectors are [ADR 0025](0025-dicom-codec-store-connectors.md)'s scope; this ADR only ratifies the carriage layer it consumes.
- **Strict ED conformance / RP (Reference Pointer)** — RP points to data on *another* system (an outbound fetch), violating router/transform purity; only inline `ED` is in scope. Full ED-component validation is deferred.
- A **`v2` carriage algorithm** (e.g. base85) — `v1` (base64) is the only build; the version field reserves the seam.

---

## To resolve on acceptance

- **Module name — recommend `messagefoundry/parsing/binary.py`** (single pure file; not `base64.py` — shadows stdlib; not a subpackage — it is ~150 lines, unlike `x12/`/`fhir/`). Confirm `binary.py` vs a more general `codecs.py` if non-base64 carriers are anticipated.
- **OBX-5 ED helpers as standalone functions vs `Message` methods — recommend standalone functions in `parsing/binary.py`** (keeps the codec self-contained and `Message` lean), with thin `Message` convenience wrappers only if call-site ergonomics demand it. Confirm.
- **Ship the connector binary-mode knob now or later — recommend later** (Option 4): build the `from_bytes` mechanism now, defer the `File`/destination config flag to a follow-up once a concrete feed needs it.
- **Retrofit the `wiring_runner.py:736` latin-1 fallback — recommend yes, as a scoped follow-up.** The intentional-binary path goes through `from_bytes` and never hits the fallback; but the fallback should still be reconsidered so an *accidental* non-UTF-8 body on the `ERROR` path is stored NUL-safe (e.g. base64-carry the byte view) rather than risking the Postgres bind failure / silent truncation. Confirm scope (this ADR vs a dedicated fix).
- **Reconcile ADR 0025 and ADR 0028 in lockstep (a hard prerequisite to either ratifying).** ADR 0025 as written **chooses** the latin-1 round-trip (Option #7) and claims it is "byte-exact for any 0–255 byte sequence" — which is **false on Postgres (NUL bind-reject) / SQLite / SQL Server (NUL truncation)**, and a DICOM Part-10 object's 128-byte all-zero preamble guarantees the hit. Shipping 0025-as-written reintroduces exactly the corruption this ADR exists to prevent. So before either ADR flips to Accepted, 0025 must be revised to **consume this contract**: swap the SCP's `bytes.decode("latin-1")` commit for **`RawMessage.from_bytes(data, content_type="dicom")`** (§3), swap the codec's `.encode("latin-1")` byte recovery for **`.raw_bytes`** (§3), drop the "byte-exact for any 0–255 byte sequence" assertion, and cite §3. Flag to the **DICOM-window coordinator** that 0025's Option #7 is a live mechanism conflict with this ADR, not a pending citation.
- **ADR number — 0028 (allocated; owner-confirmed 2026-06-20).** The coordinator allocated this ADR **0028**; retention (#34) keeps **0027** (cited in Accepted [ADR 0026](0026-off-box-egress-update-check.md)). The [docs/adr/README.md](README.md) index row and the 0028 reservation are coordinator-owned (landed in PR #428); this file ships as `0028-base64-binary-carriage-codec.md`.

---

*On acceptance: build §1–§5 (the pure codec + `RawMessage` additions + the one source-boundary `from_bytes` seam), then §7 (the OBX-5 ED helpers), behind the standard quartet gate (`ruff format --check` · `ruff check` · `mypy messagefoundry` · `pytest` with `QT_QPA_PLATFORM=offscreen`); add round-trip, corrupt-input-dead-letter, and NUL-bearing-binary-across-all-three-backends tests; re-export from [parsing/__init__.py](../../messagefoundry/parsing/__init__.py); and flip this ADR's coordinator-owned [README.md](README.md) row to Accepted.*