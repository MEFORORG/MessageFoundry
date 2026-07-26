# 0123 — Compression codec (gzip/zip/deflate) + file-connector compress/decompress option

- **Status:** Accepted (2026-07-17) — built.
- **Date:** 2026-07-17
- **Related:** [ADR 0004](0004-payload-agnostic-ingress.md) (payload-agnostic ingress / `RawMessage`),
  [ADR 0028](0028-base64-binary-carriage-codec.md) (the sibling *carriage* codec — orthogonal to
  compression), [ADR 0001](0001-staged-pipeline-architecture.md) (staged pipeline / re-run purity),
  [ADR 0011](0011-timer-scheduled-source.md) (the File-connector poll skeleton),
  [CLAUDE.md](../../CLAUDE.md) §8 (parse defensively, never accept-and-drop), §9 (PHI), BACKLOG #172.

---

## Context

A partner file feed frequently delivers **gzipped or zipped** archives, or requires **compressed
outbound** drops. Today MessageFoundry has no compression primitive: the nearest mechanism, the ADR
0028 base64 binary-carriage codec (`parsing/binary.py`), makes bytes NUL-safe over the str/TEXT
ingress+store but does **not** compress or decompress. A Handler that must accept a `.gz` drop has to
reach for `import gzip` ad-hoc, and there is no file-connector knob to gzip a drop on the way out or
gunzip an archive on the way in.

Two [CLAUDE.md](../../CLAUDE.md) invariants bound the design:

- **Re-run purity (§2 reliability invariant, verbatim):** *"routers and transforms must be pure
  (message in → message out, no external side effects) … At-least-once now relies on a re-run
  re-deriving identical output."* A compression call inside a Handler must therefore be
  **deterministic** — the same bytes in must yield the same bytes out on every re-run. Stock
  `gzip.compress` embeds a **wall-clock mtime** in the header, so its output differs every second; that
  would silently break purity for any transform that gzips.

- **Never accept-and-drop; parse defensively (§8, §12):** a corrupt or oversized archive on the inbound
  path must be routed to the error/quarantine path, **never** silently discarded, and must never crash
  the connection.

- **PHI / DoS (§9):** decompression is a classic **decompression-bomb** DoS surface. The file source's
  existing `max_file_bytes` cap only bounds the **compressed** input (`stat().st_size`) — a 16 MiB gzip
  can expand to gigabytes. And a decompressed body is PHI: it must never be logged, and (per ADR 0028)
  a NUL-bearing decompressed body must not corrupt the store.

## Decision

Add a **pure compression codec** `messagefoundry/parsing/compression.py` and an **opt-in
compress/decompress option** on the File connector — gzip-only at the connector, the full
gzip/zip/deflate surface in the codec for Handler use.

### §1 — A pure codec module (`parsing/compression.py`)

Stdlib-only (`gzip`, `zlib`, `zipfile`, `io`) — **no engine imports** — so it sits under the `parsing/`
carve-out (a client may import it, like `parsing/binary.py` / `parsing/x12`). Public surface:

- `gzip_compress(data, *, level=6) -> bytes` / `gzip_decompress(data, *, max_output_bytes=None) -> bytes`
- `deflate_compress(data, *, level=6) -> bytes` / `deflate_decompress(data, *, max_output_bytes=None) -> bytes`
  (zlib-wrapped DEFLATE, the "deflate" of HTTP/PDF)
- `zip_compress(entries, *, level=None) -> bytes` (build a multi-entry archive) /
  `zip_decompress(data, *, max_output_bytes=None, max_entries=1024) -> dict[str, bytes]`
- `CompressionError(ValueError)` — every corrupt/oversized/invalid-argument failure raises this one
  type; subclassing `ValueError` means an existing connector `except (TimeoutError, OSError)` does not
  swallow it and it surfaces as the deliberate content error it is.

**Determinism (re-run purity).** `gzip_compress` fixes `mtime=0` in the header so the output is a pure
function of `(data, level)` — a gzipping Handler stays re-run-stable. `zip_compress` fixes each entry's
ZIP date to a constant. This is the load-bearing correctness point, not a nicety.

**Decompression-bomb ceiling.** Every decompress takes an optional `max_output_bytes`. It is enforced
**incrementally** (bounded reads via `gzip.GzipFile.read(n)` / a `zlib.decompressobj` `max_length`
loop / per-entry bounded zip reads) so a bomb is refused **after producing at most the ceiling**, never
after fully expanding in memory. Exceeding it raises `CompressionError`; a truncated/corrupt stream
raises `CompressionError` (never a bare `zlib.error`/`EOFError`/`BadZipFile`). Codec error messages name
the **codec and the byte ceiling only** — never any decompressed content.

The **connector** restricts itself to **single-stream gzip** (`compress="gzip"` / `decompress="gzip"`);
multi-entry zip and raw deflate are left to a Handler-composed codec call, where the author controls
entry selection and re-assembly.

### §2 — File **destination** compress option

`File(..., compress="gzip")` gzips the encoded body before the atomic temp-then-rename write and, when
the rendered filename does not already end in `.gz`, appends `.gz`. `compress=None` (default) is
byte-identical to today. Only `"gzip"` (or `None`) is accepted; any other value raises `ValueError` at
construction. The compression runs on the already-`encode_wire_body`-encoded bytes, so an un-encodable
body still fails content-free first (ADR 0028 lineage).

### §3 — File **source** decompress option — **before** the sniff and the AV scan

`File(..., decompress="gzip")` gunzips each candidate file's bytes in `_scan_once` **immediately after
the read and before** the `_looks_like_hl7` content sniff, the pre-ingest AV/ICAP scan hook, **and** the
HL7 batch split. Ordering is a security property: the sniff and the scanner must see the **real**
(decompressed) HL7/scannable bytes, not the gzip container.

The **decompressed-size ceiling** is a new `max_decompressed_bytes` setting (default **64 MiB**), passed
to `gzip_decompress` as `max_output_bytes`. Because the split, the sniff, and every downstream stage
operate on the decompressed bytes, bounding the decompressed output also bounds post-split expansion —
closing the gap that `max_file_bytes` (compressed `st_size` only) leaves open.

A gunzip failure (`CompressionError` — corrupt archive **or** ceiling exceeded) is treated exactly like
the existing oversize / non-HL7 rejects: the **original compressed file is moved to `.error`** and a
warning is logged (codec message only, **no body, no decompressed bytes**). It never became a received
message, so — like those siblings — there is no store disposition; it is quarantined, never
accept-and-dropped. Decompress runs regardless of `content_type` (a gzipped X12/binary drop decompresses
too), before the `content_type`-gated sniff.

### §4 — Wiring

`File()` (`config/wiring.py` ~L980) gains `compress`, `decompress`, and `max_decompressed_bytes` kwargs
(disjoint from the Timer factory — the two BACKLOG items share only the wiring module). The
`connections.toml` loader already forwards `[settings]` as kwargs to the factory, so the knobs are
declarable as data with no loader change.

## Acceptance Criteria

- **AC-1** — WHEN a Handler calls `gzip_compress(b)` twice, THE SYSTEM SHALL return byte-identical
  output both times (mtime fixed → re-run pure). → `tests/test_compression.py::test_gzip_compress_is_deterministic`
- **AC-2** — WHEN `gzip_decompress(gzip_compress(b))` runs, THE SYSTEM SHALL return `b`. →
  `tests/test_compression.py::test_gzip_roundtrip`
- **AC-3** — IF a gzip stream decompresses beyond `max_output_bytes`, THEN THE SYSTEM SHALL raise
  `CompressionError` without fully expanding it. → `tests/test_compression.py::test_gzip_decompress_bomb_ceiling`
- **AC-4** — IF a decompress input is corrupt/truncated, THEN THE SYSTEM SHALL raise `CompressionError`
  (not a bare `zlib.error`/`BadZipFile`). → `tests/test_compression.py::test_decompress_rejects_corrupt`
- **AC-5** — WHERE `decompress="gzip"`, WHEN a `.gz` HL7 file is dropped, THE SYSTEM SHALL gunzip it,
  sniff the decompressed bytes, and emit the HL7 to the handler. →
  `tests/test_connections_file.py::test_file_source_gunzips_before_sniff`
- **AC-6** — IF a dropped archive is corrupt or exceeds `max_decompressed_bytes`, THEN THE SYSTEM SHALL
  move the original file to `.error` and never emit it. →
  `tests/test_connections_file.py::test_file_source_quarantines_decompression_bomb`
- **AC-7** — WHERE `compress="gzip"`, THE SYSTEM SHALL write a `.gz` file whose gunzip is the original
  payload. → `tests/test_connections_file.py::test_file_destination_gzip_compress`

## Options considered

1. **Pure codec + gzip-only connector option (CHOSEN).** Fits the `parsing/` carve-out and the connector
   registry; the deterministic `gzip_compress` keeps transforms pure; the incremental ceiling closes the
   bomb surface. Zip/deflate ship in the codec for Handler use but stay off the connector (single-stream
   only), keeping the connector's failure surface small.
2. **Connector-only, no codec.** Rejected — a Handler that needs to unpack a multi-entry zip or gzip an
   OBX document mid-transform would have no primitive and would re-import `gzip` ad-hoc, defeating the
   "centralize the rules" principle.
3. **Reuse the ADR 0028 base64 marker to also mean "compressed".** Rejected — carriage (NUL-safety) and
   compression are **orthogonal** concerns (ADR 0028 §7); overloading the marker would couple two
   independent layers and forbid "compressed-and-not-base64" (the on-disk gzip case).
4. **A dependency (e.g. `zstandard`).** Rejected for the MVP — a new locked dep needs an owner-approved
   DEP-1 lock refresh, and stdlib gzip/zlib/zipfile covers the Corepoint parity gap. zstd/brotli remain
   a demand-gated follow-up.

## Consequences

**Positive** — Corepoint file-feed parity (gzip in/out) with zero pipeline change; a pure, deterministic
codec any Handler can call against `RawMessage`/`Message`; the inbound path gains a real decompressed-size
DoS ceiling that the compressed-only `max_file_bytes` cap could not provide.

**Negative / risks** — The connector is single-stream gzip only (zip/deflate are Handler-composed by
design). `gzip_compress` fixing `mtime=0` means the header carries no real timestamp — intentional
(purity over metadata). The 64 MiB default decompressed ceiling may reject a legitimately-large archive;
operators raise `max_decompressed_bytes` explicitly.

**Out of scope** — zstd/brotli/lz4 (new deps, demand-gated); a *streaming* decompressor for
larger-than-memory archives (bounded by the ceiling instead); auto-detecting the compression format from
magic bytes on the connector (the operator declares `decompress="gzip"`).

## To resolve on acceptance

- [x] Confirm connector scope = single-stream gzip; zip/deflate stay Handler-only. *(Confirmed.)*
- [x] Confirm `gzip_compress` fixes `mtime=0` for re-run purity. *(Confirmed.)*
- [x] Confirm the decompressed-size ceiling default (64 MiB) and that it bounds post-split expansion.
  *(Confirmed.)*
