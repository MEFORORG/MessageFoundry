# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure content-sniffing helpers (ASVS 5.2.2 / 1.3.4).

Cheap, side-effect-free magic-byte checks shared by the file transports (``transports/file.py``,
``transports/remotefile.py``), the offline uploaded-logs store (``uploads.py`` — a leaf that must not
import a transport), and the attachment detach/download paths (``pipeline/wiring_runner.py`` /
``api/app.py``). Two families live here:

* **Ingress content-vs-declared-type sniff** (:func:`_content_matches_declared`) — do a file's leading
  bytes structurally match the inbound connection's declared ``content_type``? Rejects a binary/non-HL7
  drop that merely carries the right extension before its bytes reach the pipeline.
* **Attachment MIME-vs-magic agreement** (:func:`attachment_mime_agrees`) — do a detached OBX-5 ED
  document's leading bytes agree with the sender-declared OBX-5.2 MIME? A contradiction (an ``image/png``
  label on non-PNG bytes) is stored/served as ``application/octet-stream`` so a mislabelled
  active-content payload can never render as its claimed inert type (narrows the 1.3.4 residual).

Kept in ``parsing/`` (not ``transports/``) so a leaf like ``uploads.py`` can reuse them without importing
a transport. The one config dependency is :class:`~messagefoundry.config.models.ContentType`; these stay
pure functions with no I/O, engine state, or DB (the CLAUDE.md §4 ``parsing/`` carve-out)."""

from __future__ import annotations

import base64
import binascii

from messagefoundry.config.models import ContentType

# Segment ids a valid HL7 v2 payload (single message or batch file) may start with.
_HL7_LEADING_SEGMENTS = (b"MSH", b"FHS", b"BHS")


def _looks_like_hl7(raw: bytes) -> bool:
    """Cheap content sniff: does ``raw`` start with an HL7 v2 header segment (ASVS 5.2.2)?

    Mirrors what the tolerant parser accepts at the very start — an optional UTF-8 BOM, an MLLP
    start byte, and leading whitespace — then requires the first segment id to be MSH (message), FHS
    (file) or BHS (batch). This rejects a binary or non-HL7 file that merely carries the ``.hl7``
    extension before its bytes enter the pipeline, without rejecting a structurally-odd-but-textual
    HL7 message (which still flows through and is recorded as ``ERROR`` by the parser)."""
    head = raw.lstrip(b"\x0b\r\n \t")
    if head.startswith(b"\xef\xbb\xbf"):  # UTF-8 BOM
        head = head[3:].lstrip(b"\x0b\r\n \t")
    return head[:3] in _HL7_LEADING_SEGMENTS


# Leading noise tolerated before a JSON/XML/X12 magic byte: ASCII whitespace incl. the MLLP start byte
# (0x0b) and form-feed (0x0c) that the X12 codec's find_isa_start tolerates (parsing/x12/delimiters.py),
# plus an optional UTF-8 BOM. Superset-permissive BY DESIGN: this is a cheap accept-gate, so stripping
# extra leading noise can only ADMIT more content — the pipeline codec/parser stays the real validator
# that records ERROR — and must never wrongly quarantine a document a downstream codec would accept
# (ASVS 5.2.2 false-positive guard).
_LEADING_WS = b" \t\r\n\x0b\x0c"


def _lstrip_bom_ws(raw: bytes) -> bytes:
    head = raw.lstrip(_LEADING_WS)
    if head.startswith(b"\xef\xbb\xbf"):  # UTF-8 BOM
        head = head[3:].lstrip(_LEADING_WS)
    return head


def _content_matches_declared(content_type: ContentType | None, raw: bytes) -> bool:
    """Cheap magic-byte content check (ASVS 5.2.2): do ``raw``'s leading bytes structurally match the
    inbound's declared ``content_type``? True = matches (or the type has no reliable signature, so it is
    accepted unchecked); False = the bytes contradict the declared format and the caller quarantines the
    file to its ``.error`` dir before it enters the pipeline (never a silent drop).

    ``None`` is treated as HL7V2 — the local FileSource's historical None→hl7v2 default; the remote source
    now converges onto the same semantics (its former None-skips-sniff carve-out was removed, ASVS 5.2.2).
    ``FHIR`` is "HL7 FHIR JSON" (config/models.py), so it gets the same leading-``{``/``[`` sniff as
    ``JSON`` — a PDF or other non-JSON body on a ``content_type=fhir`` inbound is quarantined (ASVS 5.2.2).
    Only ``BINARY``/``TEXT`` stay unchecked, by explicit policy: binary is opaque bytes carried base64 (ADR
    0028) and text is arbitrary — neither has a reliable leading signature, so both are accepted as-is (the
    pipeline codec/parser stays the real validator that records ERROR)."""
    match content_type:
        case ContentType.HL7V2 | None:
            return _looks_like_hl7(raw)
        case ContentType.X12:
            return _lstrip_bom_ws(raw).startswith(b"ISA")
        case ContentType.DICOM:
            # DICOM Part-10: 128-byte preamble + the "DICM" magic. Every DICOM object the engine produces
            # (C-STORE SCP save_as enforce_file_format=True, dicom.py) or parses (dcmread force=False,
            # peek.py/dataset.py — REQUIRES the magic) carries it, so this never quarantines a DICOM the
            # engine could actually read (fixture make_sr_part10 passes).
            return len(raw) >= 132 and raw[128:132] == b"DICM"
        case ContentType.JSON | ContentType.FHIR:
            # FHIR is HL7 FHIR JSON, so it shares the JSON magic (leading { or [ after BOM/ws). Accepting a
            # top-level [ for FHIR is superset-permissive by design (a single resource is {…}, a bundle is
            # too) — the accept-gate can only ADMIT more; parsing/fhir stays the real validator.
            return _lstrip_bom_ws(raw)[:1] in (b"{", b"[")
        case ContentType.XML:
            return _lstrip_bom_ws(raw).startswith(b"<")
        case _:  # BINARY / TEXT — opaque bytes / arbitrary text, no reliable signature → accept unchecked
            return True


# --- attachment MIME-vs-magic downgrade (ASVS 1.3.4 / 5.2.2) ----------------------------------------
# A detached OBX-5 ED document carries a sender-declared OBX-5.2 MIME. Map each SNIFFABLE MIME family to
# the magic-byte prefix(es) the decoded document must lead with; a declared MIME in one of these families
# whose bytes contradict its signature is downgraded to application/octet-stream (never rendered as its
# claimed inert type). Everything else (text/*, application/octet-stream, application/dicom, audio/*, …)
# carries no reliable leading signature and is accepted as declared.
_MAGIC_PREFIXES: dict[str, tuple[bytes, ...]] = {
    "application/pdf": (b"%PDF-",),
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/gif": (b"GIF87a", b"GIF89a"),
    "image/tiff": (b"II*\x00", b"MM\x00*"),
    "application/zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
}
# MIMEs sniffed by first non-whitespace byte (structured-syntax text families).
_XML_MIMES = frozenset({"application/xml", "text/xml", "image/svg+xml"})


def attachment_mime_agrees(content_type: str | None, head: bytes) -> bool:
    """Whether a sender-declared attachment MIME (OBX-5.2) agrees with the document's leading ``head``
    bytes (ASVS 1.3.4 / 5.2.2).

    True when the declared MIME is not a sniffable family (no reliable leading signature → the label is
    accepted) OR its magic bytes match. False only when the MIME names a sniffable family whose signature
    ``head`` CONTRADICTS — the caller then stores/serves ``application/octet-stream`` so a mislabelled
    active-content payload can't be rendered as its claimed inert type. A blank MIME is accepted (nothing
    is declared to contradict); an empty/unconfirmable ``head`` against a sniffable family is treated as a
    contradiction (conservative — a claimed image must actually look like one)."""
    mime = (content_type or "").split(";", 1)[0].strip().lower()
    if not mime:
        return True
    exact = _MAGIC_PREFIXES.get(mime)
    if exact is not None:
        return head.startswith(exact)
    if mime in _XML_MIMES or mime.endswith("+xml"):
        return _lstrip_bom_ws(head).startswith(b"<")
    if mime == "application/json" or mime.endswith("+json"):
        return _lstrip_bom_ws(head)[:1] in (b"{", b"[")
    return True  # no reliable signature for this MIME → accept the declared label unchecked


# --- text-only upload gate (ASVS 14.2.8) ------------------------------------------------------------
# The uploaded-logs feature (uploads.py) scopes uploads to text diagnostic logs (.hl7/.txt/.xml). POST
# /uploads enforces that format contract with HTTP 415 by rejecting any body that is either (a) a known
# metadata-bearing binary container — its leading magic bytes match a sniffable family (JPEG/PNG/PDF/ZIP
# incl. DOCX, GIF, TIFF: the SAME _MAGIC_PREFIXES families the 5.2.2 attachment sniff uses) — or (b) not
# plausibly plain text (a NUL byte, or a high density of non-printable control bytes in the sampled head).
# With only plaintext admitted, no embedded-metadata container (EXIF/XMP/docProps) can ever be stored —
# which is what makes "no metadata stripping" (ASVS 14.2.8) closeable WITHOUT a stripping engine.

# Control bytes that are legitimate inside a text diagnostic log: tab, LF, CR, vertical-tab/form-feed, and
# the MLLP frame bytes (0x0b start-block, 0x1c/0x1d end-block/segment markers) an HL7 capture may carry.
# Every other C0 control byte (and DEL, 0x7f) counts toward the non-text density.
_TEXT_ALLOWED_CONTROLS = frozenset(b"\t\n\r\x0b\x0c\x1c\x1d")
# >30% control bytes in the sampled head => not plausibly text. Loose on purpose: real .hl7/.txt/.xml logs
# sit far below it (segment/line terminators are the allowed set), while a header-less binary blob sits far
# above it — the point is to catch binaries the magic table doesn't name, not to police odd-but-textual logs.
_CONTROL_DENSITY_LIMIT = 0.30
_TEXT_SAMPLE_BYTES = 8192


def nontext_upload_reason(data: bytes) -> str | None:
    """Return a human reason when ``data`` is NOT admissible as a plain-text uploaded log (ASVS 14.2.8),
    else ``None``. Two independent, pure (no-I/O) rejections, reusing the 5.2.2 magic-byte families:

    * a leading magic-byte signature of a metadata-bearing binary container (JPEG/PNG/PDF/ZIP incl. DOCX,
      GIF, TIFF) — these carry embedded metadata (EXIF/XMP/docProps) the text-only feature refuses to store;
    * a body that is not plausibly plain text — it contains a NUL byte, or the sampled head has a high
      density of non-printable control bytes.

    POST /uploads maps a non-``None`` reason to HTTP 415 BEFORE the file is written, so a container can never
    reach the store. This is a stricter, binary-shaped gate than the 5.2.2 extension/content sniff (which
    maps a text-but-mismatched body to 400); a container carrying a permitted text extension is caught here
    first (415), so the 5.2.2 400 path handles the remaining text-vs-extension mismatches."""
    head = _lstrip_bom_ws(data)
    for mime, prefixes in _MAGIC_PREFIXES.items():
        if head.startswith(prefixes):
            return f"body is a {mime} container; the uploaded-logs feature accepts only plain-text logs"
    sample = data[:_TEXT_SAMPLE_BYTES]
    if b"\x00" in sample:
        return "body contains NUL bytes; the uploaded-logs feature accepts only plain-text logs"
    controls = sum(1 for b in sample if (b < 0x20 or b == 0x7F) and b not in _TEXT_ALLOWED_CONTROLS)
    if sample and controls / len(sample) > _CONTROL_DENSITY_LIMIT:
        return (
            "body has a high density of control characters; the uploaded-logs feature accepts only "
            "plain-text logs"
        )
    return None


def b64_head(b64: str, max_bytes: int = 32) -> bytes:
    """Decode the leading ``max_bytes`` of a (verbatim) base64 document for a magic-byte sniff, tolerant
    of embedded whitespace. Base64 encodes in independent 4-char groups, so a multiple-of-4 prefix decodes
    to the document's exact leading bytes without materializing the whole payload. Returns ``b""`` when the
    prefix isn't decodable (the caller treats an unconfirmable magic as a contradiction and downgrades to
    octet-stream — conservative)."""
    compact = "".join(b64.split())
    need = ((max_bytes + 2) // 3) * 4
    chunk = compact[:need]
    chunk = chunk[: len(chunk) - (len(chunk) % 4)]
    if not chunk:
        return b""
    try:
        return base64.b64decode(chunk)
    except (binascii.Error, ValueError):
        return b""
