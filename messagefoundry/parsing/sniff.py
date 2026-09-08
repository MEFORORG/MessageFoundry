# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure content-sniffing helpers (ASVS 5.2.2 / 1.3.4).

Cheap, side-effect-free magic-byte checks shared by the file transports (``transports/file.py``,
``transports/remotefile.py``), the offline uploaded-logs store (``uploads.py`` — a leaf that must not
import a transport), and the attachment detach/download paths (``pipeline/wiring_runner.py`` /
``api/app.py``). Three families live here:

* **Ingress content-vs-declared-type sniff** (:func:`_content_matches_declared`) — do a body's leading
  bytes structurally match the inbound connection's declared ``content_type``? Rejects a binary/non-HL7
  drop that merely carries the right extension before its bytes reach the pipeline. The file sources
  call it on a file's original bytes; the network listeners (MLLP/TCP/HTTP/database poll) reach it
  through the shared ingress handler in ``pipeline/wiring_runner.py``, on the head that
  :func:`text_sniff_head` derives from their already-decoded body (BACKLOG #1109).
* **Attachment MIME-vs-magic agreement** (:func:`attachment_mime_agrees`) — do a detached OBX-5 ED
  document's leading bytes agree with the sender-declared OBX-5.2 MIME? A contradiction (an ``image/png``
  label on non-PNG bytes) is stored/served as ``application/octet-stream`` so a mislabelled
  active-content payload can never render as its claimed inert type (narrows the 1.3.4 residual).
* **Archive-member admission** (:func:`archive_member_name_reason` / :func:`archive_member_content_reason`)
  — is a ZIP member's name a safe relative path, and do its bytes correspond to the type its own
  extension names? Called by :func:`~messagefoundry.parsing.compression.zip_decompress`, which is the
  Handler-facing archive reader, so members reach Handler code already checked (BACKLOG #1128).

Kept in ``parsing/`` (not ``transports/``) so a leaf like ``uploads.py`` can reuse them without importing
a transport. The one config dependency is :class:`~messagefoundry.config.models.ContentType`; these stay
pure functions with no I/O, engine state, or DB (the CLAUDE.md §4 ``parsing/`` carve-out)."""

from __future__ import annotations

import base64
import binascii

from messagefoundry.config.models import ContentType
from messagefoundry.controlchars import has_control_char

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


#: The str-domain twin of :data:`_LEADING_WS`, plus U+FEFF (what a UTF-8/UTF-16 BOM decodes to). Derived
#: from the byte set rather than retyped, so the tolerated leading noise has ONE definition.
_LEADING_WS_STR = _LEADING_WS.decode("ascii") + "\ufeff"

#: Characters of a decoded body that :func:`text_sniff_head` encodes. The longest text magic is three
#: bytes (``ISA`` / ``MSH``); eight characters leave headroom for a multi-byte first character while
#: keeping the work O(1) instead of re-encoding a whole 16 MiB body.
_TEXT_SNIFF_HEAD_CHARS = 8


def text_sniff_head(text: str) -> bytes:
    """UTF-8 head bytes of an already-DECODED body, to hand to :func:`_content_matches_declared`.

    The file sources sniff a file's original bytes because they have no declared encoding to decode
    with. A network listener does: it decodes with the connection's ``encoding`` before anything else,
    so sniffing its ORIGINAL bytes would quarantine a legitimate ``encoding="utf-16"`` JSON body, which
    leads with the two BOM bytes and then ``{`` interleaved with NULs, never a bare ``{``. Sniffing the
    decoded head instead makes the check encoding-independent, and identical to the byte sniff for every
    ASCII-superset encoding (utf-8, latin-1, cp1252, ascii).

    Leading whitespace/BOM is stripped in str space first, so the head starts at the first significant
    character however much whitespace preceded it; :func:`_content_matches_declared` strips again in
    byte space, which is idempotent."""
    return text.lstrip(_LEADING_WS_STR)[:_TEXT_SNIFF_HEAD_CHARS].encode("utf-8")


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


# --- archive-member admission (ASVS 5.2.2 "within an archive", 5.3.2) --------------------------------
# ASVS 5.2.2 asks that an accepted file, "either on its own or within an archive such as a zip file",
# have its extension checked against an expected extension and its contents validated as corresponding
# to the type that extension represents. The ingress sniff above answers a DIFFERENT question — it keys
# on the inbound connection's DECLARED content_type — and a ZIP member has no connection declaring
# anything. What a member does carry is its own name, and therefore its own extension, so the verb is
# directly expressible here with no policy input: the archive names the type, and the bytes either
# correspond or they do not. That is why this arm needs no ceiling parameter and no operator setting.
#
# Every discriminator below is the SAME one the declared-type arm uses (via _content_matches_declared or
# _MAGIC_PREFIXES), so extension-keyed and declaration-keyed checks cannot drift apart.

#: Extensions whose expected content is a structured format the engine already discriminates. Mapped to
#: the ContentType so the check is literally :func:`_content_matches_declared` — one definition.
_EXTENSION_CONTENT_TYPE: dict[str, ContentType] = {
    ".hl7": ContentType.HL7V2,
    ".json": ContentType.JSON,
    ".fhir": ContentType.FHIR,
    ".xml": ContentType.XML,
    ".dcm": ContentType.DICOM,
    ".edi": ContentType.X12,
    ".x12": ContentType.X12,
}

#: Extensions whose expected content is an opaque container with a leading magic signature. Aliased onto
#: the attachment table above rather than retyped, for the same single-definition reason. ``.gz`` is the
#: one entry with no MIME twin there (RFC 1952 header magic).
_EXTENSION_MAGIC: dict[str, tuple[bytes, ...]] = {
    ".pdf": _MAGIC_PREFIXES["application/pdf"],
    ".png": _MAGIC_PREFIXES["image/png"],
    ".jpg": _MAGIC_PREFIXES["image/jpeg"],
    ".jpeg": _MAGIC_PREFIXES["image/jpeg"],
    ".gif": _MAGIC_PREFIXES["image/gif"],
    ".tif": _MAGIC_PREFIXES["image/tiff"],
    ".tiff": _MAGIC_PREFIXES["image/tiff"],
    ".zip": _MAGIC_PREFIXES["application/zip"],
    ".gz": (b"\x1f\x8b",),
}


def _member_extension(name: str) -> str:
    """Lower-cased extension of an archive member's own leaf name, or ``""`` when it has none. A dot that
    starts the leaf (``.gitignore``) is not an extension."""
    leaf = name.rsplit("/", 1)[-1]
    dot = leaf.rfind(".")
    return leaf[dot:].lower() if dot > 0 else ""


def archive_member_name_reason(name: object) -> str | None:
    """Return a human reason when an archive member's name is not a safe RELATIVE path, else ``None``
    (ASVS 5.3.2). The name is chosen by whoever built the archive — for an inbound feed, a remote party —
    so it is untrusted data that a Handler will join onto a directory.

    **Reject, never rewrite**, for the reason measured on the remote file source
    (:func:`messagefoundry.transports.remotefile._is_contained_name`): stripping the traversal off
    ``../../adt.hl7`` yields ``adt.hl7``, which aliases onto a REAL file in the caller's own directory, so
    mutation converts a refusal into a wrong-file read. Refusing one archive is strictly better.

    Nested directories are ADMITTED (``sub/b.hl7``), because a legitimate archive carries them and this
    check bounds where the path can land rather than how deep it goes. What is refused is anything that
    could leave the extraction root, plus the shapes a naive join cannot see: an absolute path, an empty
    or ``.``/``..`` component, a backslash (ZIP APPNOTE mandates ``/`` as the separator, so a backslash is
    a Windows separator smuggled through a slash-only check), a drive-relative prefix (``C:x.hl7`` carries
    no separator at all), and any control character.

    Two of those arms are unreachable through CPython's own reader, which is a fact about the library and
    not a reason to drop them. ``zipfile._sanitize_filename`` runs inside ``ZipInfo.__init__`` on the read
    path as well as the write path: it truncates a member name at the first NUL everywhere, and replaces
    ``os.sep`` with ``/`` — so the backslash arm is live wherever ``os.sep`` is not a backslash and dead on
    Windows. Measured on CPython 3.14. A caller reading the archive by some other route still gets both."""
    if not isinstance(name, str) or not name:
        return "member name is empty"
    if has_control_char(name):
        return "member name contains a control character"
    if "\\" in name:
        return "member name contains a backslash, which a slash-only containment check cannot see"
    if len(name) >= 2 and name[0].isascii() and name[0].isalpha() and name[1] == ":":
        return "member name is drive-relative"
    if name.startswith("/"):
        return "member name is an absolute path"
    for part in name.split("/"):
        if part in ("", ".", ".."):
            return "member name has an empty or relative path component"
    return None


def archive_member_content_reason(name: str, data: bytes) -> str | None:
    """Return a human reason when an archive member's CONTENT contradicts the type its own extension
    names, else ``None`` (ASVS 5.2.2). Call it after :func:`archive_member_name_reason`.

    An extension this table does not name has no expected signature, so the member is accepted unchecked
    and the caller stays the real validator. That keeps the gate superset-permissive — it can only refuse
    a member that positively contradicts itself, never one whose type is merely unmodelled — which is why
    it does not have to be switched on or configured. It is also why it does NOT close the verb's L2 "all
    files being accepted" clause on its own: at least ``.txt``, ``.csv`` and ``.dat`` carry no signature to
    check, and asserting otherwise would be a control resting on a false premise."""
    ext = _member_extension(name)
    declared = _EXTENSION_CONTENT_TYPE.get(ext)
    prefixes = _EXTENSION_MAGIC.get(ext)
    if declared is not None:
        matches = _content_matches_declared(declared, data)
    elif prefixes is not None:
        matches = data.startswith(prefixes)
    else:
        return None  # no expected signature for this extension — accepted unchecked
    return None if matches else f"member content does not match the {ext} extension it carries"
