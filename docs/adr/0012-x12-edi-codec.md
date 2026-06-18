# ADR 0012 — X12 EDI codec: tolerant codec + raw-framed transport

- **Status:** Accepted (2026-06-14) — ratified on the owner's go; **built** (the pure `parsing/x12/` codec,
  `transports/x12.py`, the additive wiring, samples + tests, quartet green). This ADR records the two
  decoupled pieces (a pure `parsing/x12/` codec + a
  `transports/x12.py` raw-TCP connector), the **`RawMessage`-only ingress contract** (zero `pipeline/`
  *routing-logic* edits), the **ISA-framing fork** (why the X12 transport cannot reuse the shared
  `FrameCodec`), and the **deferred** strict guide validator and X12 acknowledgments. **The six prior open
  questions are decided** (2026-06-14, see §"Resolved"): accept the two additive `wiring_runner.py` security-parity
  branches (#1); hand-rolled, dependency-free MVP (#2); defer acks — opaque relay v1 (#3); single
  `ContentType.X12` (#4); preserve the terminator verbatim (#5); synthetic `.edi` samples (#6).
- **Built:** Nothing here yet. It builds on the **already-shipped** payload-agnostic ingress
  ([ADR 0004](0004-payload-agnostic-ingress.md)): `ContentType.X12 = "x12"` **already exists** in
  [config/models.py](../../messagefoundry/config/models.py) ("relayed opaquely … routes as `RawMessage`"),
  and `_handle_inbound`'s **non-HL7 branch** already decodes a non-HL7 body verbatim, commits it to the
  ingress stage, and hands the Router/Handler a `RawMessage` (`.raw`/`.text`/`.json()`/`.encode()`). X12
  inherits ingress/routing/finalizer behaviour **for free**. It reuses the connector **registry**
  ([transports/base.py](../../messagefoundry/transports/base.py)), the `Source`/`Destination` models, and
  the `TcpSource` socket-plumbing *shape* ([transports/tcp.py](../../messagefoundry/transports/tcp.py)) —
  but **not** its `FrameCodec` ([transports/framing.py](../../messagefoundry/transports/framing.py); see
  Context).
- **Related:** [ADR 0004](0004-payload-agnostic-ingress.md) (the `content_type` ingress path this rides),
  [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) (the non-HL7 transport registry pattern + the
  optional-extra dependency posture; its `ConnectorType.TCP` was annotated "X12 over TCP" — see Context),
  [ADR 0001](0001-staged-pipeline-architecture.md) (the staged queue X12 feeds),
  [CLAUDE.md](../../CLAUDE.md) §1/§4/§8 (no-grouping-unit graph, code-first logic, two-tier parsing, the
  pure `parsing/` library + console carve-out), [CONNECTIONS.md](../CONNECTIONS.md).

## Context

The migration estate is not all HL7-over-MLLP. **ASC X12 EDI** — eligibility (270/271), claims (837),
remittance (835), claim status (276/277) — is a real inbound/outbound format, and MessageFoundry has no X12
support today. The *ingress contract* for "not HL7" already exists ([ADR 0004](0004-payload-agnostic-ingress.md)):
a non-`hl7v2` inbound skips the HL7 peek/validate/ACK, commits the body verbatim, and the Router/Handler
receive a generic **`RawMessage`**. `ContentType.X12` is already a member of the enum. So the *ingress wiring
is done* — what is missing is **(a)** a way to *parse/route/transform* X12 from a Router/Handler, and **(b)**
a *transport* that can frame X12 off a raw TCP stream.

Two project constraints shape the design:

- **No grouping unit / code-first logic** ([CLAUDE.md](../../CLAUDE.md) §1/§4). X12 logic (which group /
  transaction goes where, how a claim maps) belongs in **code-first Routers/Handlers**, not a new declarative
  X12 surface or a bespoke object pushed through the engine.
- **Payload-agnostic, hot-path-cheap** ([CLAUDE.md](../../CLAUDE.md) §8). Routing must not force a full parse;
  the X12 analog of "read the separators from MSH" is a **fixed-offset ISA read**.

**Why a dedicated transport rather than reusing the existing TCP connector.** `ConnectorType.TCP`'s own
annotation says "raw TCP with configurable delimiter framing (X12 over TCP, ADR 0003)" — so reusing TCP is
the obvious first hypothesis, and the brief's build-check ("prove `TCP::receive()` with raw framing populates
`RawMessage` on a real X12 ISA") asks us to *probe that path first*. It does not hold for general X12:

X12-over-TCP has **no transport sentinel** — the *frame is the interchange* (`ISA…IEA<segment-terminator>`),
and the four delimiters (including the segment terminator) are **discovered from the ISA header**, not
configured. The shared `FrameCodec`/`FrameDecoder` is **single-byte start/end delimiter framing**
(`start: int`, `end: int`, `trailer: int | None`, fed byte-by-byte). It cannot express a 3-character `ISA`
start token, a per-interchange discovered (possibly multi-byte `CR`+`LF`) segment terminator, or an
`IEA`-segment-plus-terminator end. Configuring TCP's `end` byte to the segment terminator frames each
*segment* (wrong); a partner who does not wrap each interchange in a fixed sentinel produces zero or mis-split
frames. So the existing TCP connector works *only* for the narrow "one interchange per connection, fixed
wrapping" case — fine as the **build-check probe**, not as the shipped capability. The shipped capability
needs an **ISA-aware frame assembler**. This fork is the heart of this ADR.

## Decision (proposed)

X12 ships as **two decoupled pieces** wired through existing seams. Edits to the engine hotspots are
**additive only**, and **no routing-logic** in `pipeline/wiring_runner.py` (`_handle_inbound`,
`route_only`, `transform_one`) or `pipeline/dryrun.py` (`_payload`) is touched. (Two *additive,
`ConnectorType`-keyed security branches* in `wiring_runner.py` are required for security parity — see
§"Resolved" #1; they are not pipeline logic.)

### 1. A pure, console-importable codec at `parsing/x12/` (NOT pushed through the pipeline)

A new package mirroring `parsing/` — **pure, side-effect-free, zero I/O, zero engine imports** (so the
console may import it, the §4 carve-out). **It must import nothing from `messagefoundry.config`,
`pipeline`, `store`, or `transports`** — it works on `str`/`bytes` only and refers to the X12 content type
by the literal string `"x12"` (never `ContentType.X12`), so a console import of `parsing.x12` pulls in no
engine. A unit test asserts this (import `messagefoundry.parsing.x12`, assert no `config`/`pipeline`/
`store`/`transports` module was imported).

- **`X12Peek`** — the tolerant routing peek (the HL7 `Peek` analog). `X12Peek.parse(raw, max_bytes)` does a
  **cheap fixed-offset ISA read** + a shallow `GS`/`ST` header walk — **never a full parse on the hot path**.
  Accessors: `sender_qual`/`sender_id` (ISA05/06, trailing-space-trimmed), `receiver_qual`/`receiver_id`
  (ISA07/08), `version` (ISA12 — the **interchange envelope** version, distinct from the GS08 guide version),
  `control_number` (ISA13), `usage`/`is_test` (ISA15), plus **`groups()`** — a **list** of
  `{gs01_functional_id, gs02/gs03 app sender/receiver, gs06_control, gs08_version, transactions: [st01, …]}`
  (see §6). Raises **`X12PeekError`** on unparseable/non-X12 input.
- **`X12Interchange`** — a pure streaming **splitter/assembler**: one stream → N `ISA…IEA` frames, with a
  `feed()`-style API so the transport (and File/console) can split multiple interchanges from one payload.
  The frame logic lives **here**, not in the transport, so it is unit-testable without a socket. Optional
  structural integrity checks (ISA13==IEA02, GS06==GE02, ST02==SE02, the SE01/GE01/IEA01 counts) live as a
  pure helper.
- **`X12Message`** — a mutable model (the HL7 `Message` analog): `parse(raw)` using **discovered**
  delimiters; read/set by segment + element[.component] index (e.g. `ISA-09`, `NM1-03`); add/delete segments;
  `encode()` re-emitting with the **same discovered delimiters**. Never string-slices the raw. For
  transforms, **not** the hot path.
- **`discover_delimiters`** + **`X12PeekError`** are exported. The MVP codec is **hand-rolled and
  dependency-free** (X12 tokenization is trivial once delimiters are known — see §5).

Routers/Handlers call this library **on demand** against `RawMessage.raw` (`X12Peek` to route, `X12Message`
to transform). **Nothing X12-typed is added to the `Payload` union** (`Message | RawMessage`), and **nothing
in `pipeline/` is taught about X12**. This is exactly how JSON/XML/SOAP feeds already work and how the
console already consumes `parsing/`.

### 2. A thin raw-TCP connector at `transports/x12.py` with its OWN ISA/IEA frame reader

`X12Source` reuses `TcpSource`'s **socket-plumbing shape** (`start_server`, the `_on_client` loop, the DoS
guards `max_connections`/`receive_timeout`, cooperative stop) but **replaces the `FrameCodec` decoder** with
the ISA/IEA assembler from `parsing/x12/`: trim leading whitespace/BOM, scan for the literal `ISA` start
token, read the fixed 106-byte ISA window to **discover** the four delimiters, then accumulate, splitting on
the discovered segment terminator, until a segment whose leading three bytes are `IEA` is closed by that
terminator; yield each complete interchange's bytes and loop. It needs its own buffer cap
(**`max_interchange_bytes`**) since the `FrameDecoder`-keyed OOM guard no longer applies.

`X12Destination` frames **opaquely** — it writes the interchange bytes **verbatim** (no synthetic sentinel;
optional `expect_reply`). The Handler already produced a complete `ISA…IEA` interchange.

Both register under a **new `ConnectorType.X12`** (see §3). The assembler is **one-way dependent**:
`transports/x12.py` imports `parsing/x12/`, **never the reverse** (preserving the dependency direction and
the console carve-out).

### 3. Additive hotspot edits — `ContentType.X12` reuse, a new `ConnectorType.X12`, an `X12()` factory, exports

- **`ContentType.X12`** — **already exists**; no edit. An X12 inbound declares
  `inbound("IB_…", X12(...), content_type=ContentType.X12)` and rides the existing non-HL7 branch.
- **`ConnectorType.X12 = "x12"`** — a **new, additive** enum member in
  [config/models.py](../../messagefoundry/config/models.py), mirroring `TCP`/`REST`/etc. **Required:** the
  registry is **one builder per `ConnectorType`** (`_SOURCES: dict[ConnectorType, SourceBuilder]`), so
  reusing `ConnectorType.TCP` would overwrite `TcpSource` at import time, and the framing differs
  fundamentally (§2). No existing branch keys off the *absence* of X12; `build_source`/`build_destination`
  resolve by dict lookup. (`ConnectorType.X12` is the *transport* key; `ContentType.X12` is the *payload*
  tag — distinct concerns.)
- **`X12()` factory** — additive, in [config/wiring.py](../../messagefoundry/config/wiring.py), returning a
  spec for `ConnectorType.X12` with `{host, port, encoding, max_connections, receive_timeout,
  connect_timeout, timeout_seconds, expect_reply, max_interchange_bytes}`. Mirrors `Tcp(...)` but **omits
  the delimiter-framing knobs** — delimiters are discovered from ISA, never configured. Add `"X12"` to
  `__all__`.
- **Exports** — add `x12` to the import tuple in
  [transports/__init__.py](../../messagefoundry/transports/__init__.py) so importing the package registers
  the X12 source+destination at load (same line as `tcp`/`mllp`/`file`); re-export the X12 surface from
  [parsing/__init__.py](../../messagefoundry/parsing/__init__.py) (mirroring `Message`/`RawMessage`).

### 4. Delimiter discovery strictly from the ISA header; fail loud, never guess

`discover_delimiters` reads the four delimiters by **absolute offset** from the located `ISA`:

- **element separator** = byte at `+3`;
- **component separator** = byte at `+104`;
- **segment terminator** = the byte at `+105`, **or the two-byte sequence** `raw[105:107]` when
  `raw[105]==CR (0x0D)` and `raw[106]==LF (0x0A)` (a partner using `CR+LF` as the terminator). The terminator
  is therefore **one or two bytes**; the single-byte `+105` read is the common case, not the rule. The
  splitter and `X12Message.encode()` **must agree** on this discovered terminator.
- **repetition separator** = byte at `+82` (ISA11) — treated as a real repetition separator **only when
  ISA12 (version) ≥ `"00501"`** (005010 redefined ISA11 as the repetition separator). For ISA12 ≤ `"00401"`,
  ISA11 is the literal `"U"` (Interchange Control Standards Identifier) and **there is no repetition
  separator** — a unit test asserts a 004010 ISA yields none.

The four delimiters **must be mutually distinct**, and the ISA must pass the **separator-position sanity
gate**: every element-separator position implied by the fixed ISA element widths — offsets
`6, 17, 20, 31, 34, 50, 53, 69, 76, 81, 83, 89, 99, 101, 103` (all element-separator offsets except the
defining one at `+3`) — must equal the element separator. (Derive these in code from the ISA width table,
not a hand-typed list.) On a delimiter collision or a sanity-gate failure, the codec raises
**`X12PeekError`** — the Router routes the message to the **error/dead-letter** path (status `ERROR`) rather
than guessing, honouring the count-and-log invariant (never accept-and-drop). Hardcoding `*~:^` is **wrong** —
trading partners legitimately vary all four.

### 5. Tolerant peek + structural integrity for MVP; strict guide-driven validation deferred

Mirroring the project's two-tier **python-hl7 (tolerant, hot path) / hl7apy (strict, opt-in)** split: the
MVP ships `X12Peek` (delimiters + ISA fields + the per-group `GS01`/`GS08`/`ST01` list) and the **optional
structural integrity** helper (control-number and segment-count tie-out). A **strict implementation-guide
validator** (e.g. `005010X222A1` for 837P — a GS08 value — the hl7apy analog for X12) is **explicitly
deferred**: routing needs only the cheap peek, full SEF/guide validation is a slow path few feeds need at
MVP, and adding it now risks pulling in a heavy/uncertain dependency. The MVP adds **no new dependency**
([CLAUDE.md](../../CLAUDE.md) §5/§7: verify a dependency exists before adding it — deferring avoids an
unvetted/possibly-hallucinated package).

### 6. `peek()` returns interchange identity + a **list** of `(GS01, GS08, [ST01…])` groups

One ISA may carry **multiple `GS` groups**, and one `GS` **multiple `ST` sets**, so `GS01`/`ST01` are **not
single-valued**. `X12Peek.groups()` returns the full list so a Router can fan out or filter precisely (the
no-grouping-unit graph: a Router returns handler name(s) per the transactions it sees). Each group exposes
**`gs08` (Version/Release/Industry Identifier Code)** — the **implementation-guide version** a Router most
often branches on (e.g. `005010X222A1` 837P vs `005010X223A2` 837I), which lives in GS08, *not* ISA12.
Returning only the first `GS01`/`ST01` would **silently mis-route** multi-group interchanges (the most common
real failure mode), so it is rejected.

### 7. Build order

1. **Vertical-slice proof first (the brief's build-check).** Probe the raw-TCP receive path on a real
   synthetic X12 ISA *before* building the full codec: a real-socket loopback test (the
   `tests/test_tcp_transport.py::test_round_trip_opaque_relay` pattern — `port=0`, read `sockport`, send,
   assert the handler received the **verbatim** interchange) proving `receive() → RawMessage(raw, "x12") →
   X12Peek` end-to-end. Done with a minimal `X12Source` (ISA/IEA assembler) + verbatim `X12Destination`.
2. **The pure codec** — `parsing/x12/` (`delimiters` → `peek` → `interchange` → `message`) with full unit
   tests (non-default separators, the version-gated `U`/no-repetition case for 004010, multi-`GS`/multi-`ST`
   `groups()` incl. `gs08`, concatenated interchanges, a `CR`+`LF` terminator, `IEA` bytes appearing
   mid-segment without early truncation, integrity tie-out, `X12PeekError` on malformed input, `X12Message`
   read/set/`encode()` round-trip with the **same** delimiters, and the import-purity test).
3. **Wiring + samples** — the `X12()` factory, `ConnectorType.X12`, exports, the §"Resolved" #1 security
   branches (if approved), a synthetic PHI-free `samples/messages/x12_270_eligibility.edi` fixture
   (delimiters `* ^ : ~`, version `00501`, control numbers tied out), and an optional `samples/config` X12
   inbound example.

## Options considered

1. **`RawMessage` + on-demand library (CHOSEN) vs a parsed `X12Message` added to `Payload`.** Adding
   `Payload = Message | RawMessage | X12Message` with `dryrun.py::_payload()` branching on `ContentType.X12`
   would edit the **forbidden routing hotspots**, couple the pipeline to X12, and force a full parse on the
   hot path even when a Router only needs the ISA peek. **Rejected.** `RawMessage` + on-demand `parsing/x12/`
   matches the brief (X12 routes as `RawMessage`; codec is a pure library), keeps the engine format-blind,
   and mirrors JSON/XML/SOAP.
2. **A new ISA/IEA frame reader (CHOSEN) vs reusing the shared `FrameCodec`.** *(a)* `TcpSource` with an
   `stx_etx` preset — **rejected**: only works for partners who wrap each interchange in STX/ETX. *(b)* An
   `isa` preset in `framing.py` — **rejected**: ISA framing is not a fixed start/end *byte* pair and bolting
   multi-byte/ISA logic into the shared codec risks the MLLP/TCP paths. *(c)* Extend `FrameDecoder` with a
   sentinel-scanning mode — **rejected** as scope creep into a shared hotspot. The clean split is a **pure
   assembler in `parsing/x12/`** + a **thin socket in `transports/x12.py`**. (The existing TCP connector
   remains valid for the narrow "one interchange per connection, fixed wrapping" case — and is the build-check
   probe.)
3. **A dedicated `ConnectorType.X12` (CHOSEN) vs reusing `ConnectorType.TCP` + a `framing="isa"` flag.** The
   flag forces editing `transports/tcp.py` to branch on an X12 mode, couples two transports, and muddies
   `TcpSource`'s "opaque relay, no parse" contract. **Rejected** — the one-builder-per-`ConnectorType`
   registry and the framing fork make a dedicated key cohesive and unavoidable.
4. **Hand-rolled tolerant codec (CHOSEN for MVP) vs adopting a third-party X12 library now** (e.g.
   `pyx12`). **Deferred, not rejected** — flagged for the owner (bundled vs an optional extra like
   `[sqlserver]`/`[postgres]`); any package verified real/reputable before proposing.
5. **Delimiter discovery: fixed-offset ISA read (CHOSEN) vs hardcoding `*~:^` vs heuristic recovery.**
   Hardcoding breaks real partners; heuristic recovery (guessing when a delimiter appears in data) is
   **rejected** for PHI-bearing claims — prefer dead-lettering over guessing (inbound EDI is untrusted data).

## Consequences

**Positive**

- **Zero pipeline routing-logic risk.** `_handle_inbound`/`route_only`/`transform_one` and `dryrun.py` are
  untouched; X12 rides the proven non-HL7 ingress/route/transform/finalizer path.
- **A pure, console-importable X12 library** — Routers/Handlers and the console get `X12Peek`/`X12Message`
  against `RawMessage.raw`, trivially unit-testable without a socket.
- **Correct multi-partner framing** — discovered delimiters + an ISA-aware reader handle real X12 (varying
  delimiters, multi-`GS` interchanges, multi-byte terminators) where the shared `FrameCodec` cannot.
- **Fail-loud, count-and-log honest** — malformed/non-X12 input dead-letters as `ERROR` rather than silently
  mis-framing or guessing.
- **No new dependency at MVP** — base install unaffected; a strict validator/library can be added later as an
  optional extra.

**Negative / risks**

- **ISA-framing fragility.** The 106-byte ISA assumption breaks under cosmetic mid-segment newlines, a 2-byte
  `CR`+`LF` terminator shifting offsets, or a missing trailing terminator. The assembler validates the
  separator-position pattern and dead-letters on mismatch — a naive `raw[0:106]` slice would silently
  mis-frame and **corrupt downstream feeds**.
- **Cosmetic trailing newlines** (a partner who pretty-prints `~` + `CR/LF` for readability, distinct from
  `CR+LF`-as-terminator): the **store preserves the raw interchange bytes verbatim** (newlines included), but
  `X12Message.encode()` re-emits with the discovered delimiters only and is therefore **not guaranteed
  byte-identical** when cosmetic whitespace was present. Documented, not a defect.
- **A new buffer cap** — `max_interchange_bytes` must be ported explicitly; without it a slowloris/huge-
  interchange peer grows the buffer unbounded.
- **Two additive `wiring_runner.py` security branches** (bind-host + egress allowlist) are needed for X12 to
  inherit the existing security controls — see §"Resolved" #1.
- **Purity regression risk** — `parsing/x12/` must import **zero** engine/IO/logging/`config`; the
  import-purity test guards this.

**Out of scope (deferred / known limitations)**

- **Strict implementation-guide (837/835/270) validation** — the hl7apy/SEF analog. Deferred (§5).
- **X12 acknowledgments** — **no TA1 (interchange ack), 997, or 999 (functional ack)** at MVP; the inbound is
  opaque relay (an opaque framed reply only if a Handler emits one). The X12 analog of the configurable HL7
  `AckMode`, deferred to a follow-up.
- **Segment-level transforms beyond field read/set** — richer loop/transaction-set structural editing is
  future.
- **Release/escape characters and binary `BIN`/`BDS` segments** — the tolerant MVP **rejects/dead-letters**
  these rather than silently corrupting; a known limitation.
- **Finer content-type subtypes** (`x12_837`/`x12_835`) — single `ContentType.X12`; Routers branch on the
  peek's `ST01`/`GS08`.

## Resolved (2026-06-14)

1. **`wiring_runner.py` security-parity branches (the one real deviation from the brief). → ACCEPT BOTH.** A
   faithful X12 transport gets two **additive, `ConnectorType`-keyed** branches (verified against the code):
   `_source_config` ([wiring_runner.py:1038](../../messagefoundry/pipeline/wiring_runner.py)) injects
   `[inbound].bind_host` only for `MLLP`/`TCP` listeners — the X12 *source* joins that tuple so it honours the
   `serve --allow-insecure-bind` bind-guard; `check_egress_allowed`
   ([wiring_runner.py:1117](../../messagefoundry/pipeline/wiring_runner.py)) fail-closed-gates *destinations*
   by `ConnectorType` — the X12 *destination* is added there (reusing `[egress].allowed_tcp`) so it cannot be
   fail-open. (`check_source_allowed` needs **no** edit — a listener has nothing to connect-gate.) These are
   additive security parity, not routing logic.
2. **Strict validator + dependency policy. → HAND-ROLLED, NO NEW DEP.** Tolerant peek + structural integrity
   tie-out only at MVP; a strict guide validator (and any third-party library, as an optional `[x12]` extra)
   is a later follow-up.
3. **Acknowledgments. → DEFERRED (opaque relay v1).** No `TA1`/`997`/`999` at MVP, matching the current
   `Tcp()` posture and ACK-on-receipt; a configurable `AckMode` analog is a follow-up.
4. **`content_type` granularity. → SINGLE `ContentType.X12`.** Routers branch on the peek's `ST01`/`GS08`;
   finer tags (`x12_837`/`x12_835`) are not added.
5. **Segment-terminator normalization. → PRESERVE VERBATIM.** The store keeps the raw interchange bytes
   byte-exact; `X12Message.encode()` normalizes to the discovered delimiters only on an explicit transform
   (documented as not guaranteed byte-identical when cosmetic whitespace was present).
6. **Sample fixtures. → SYNTHETIC `.edi` SAMPLES.** Create synthetic PHI-free `samples/messages/*.edi` (270
   now, 837P/835 later) plus a `samples/config` X12 inbound example module.

---

*On acceptance: build §7.1 (the vertical-slice proof: `X12Source` ISA/IEA assembler + verbatim
`X12Destination` + a real-socket loopback test proving `receive() → RawMessage → X12Peek`) as the first PR
behind the standard quartet gate (`ruff format --check` · `ruff check` · `mypy messagefoundry` · `pytest`
with `QT_QPA_PLATFORM=offscreen`); then the pure `parsing/x12/` codec; then wiring (`X12()` factory,
`ConnectorType.X12`, exports, the approved §"Resolved" #1 branches) + synthetic samples. Keep `parsing/x12/`
importing zero engine/IO/`config`. Update [CLAUDE.md](../../CLAUDE.md) §8 and [CONNECTIONS.md](../CONNECTIONS.md)
only when code ships, and flip this ADR's `README.md` row to Accepted.*
