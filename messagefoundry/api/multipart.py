# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Minimal stdlib ``multipart/form-data`` parser for the uploaded-logs endpoint (ADR 0134).

**No `python-multipart`.** The engine deliberately carries no multipart dependency — the console
already hand-parses urlencoded bodies with stdlib (``routes/core.py`` no-multipart stance). A single
file upload is a trivial `multipart/form-data` body, so it is hand-parsed here with the stdlib: the
boundary is read from the ``Content-Type``, each part is located by the offset of the boundary
delimiter, and each part's ``Content-Disposition`` gives its field name + (for a file) filename. A
**hard size cap** is enforced on each part before any of its content is copied.

What it refuses, at least: more than ``_MAX_PARTS`` parts, a part header block over
``_MAX_PART_HEADER_BYTES``, a file part over the caller's cap, a text field over
``_MAX_FIELD_BYTES``, and, in :func:`parse_single_file_upload`, a body with no file part or with
more than one. BACKLOG #5787 adds, at least: a body with no closing delimiter line; a line before
the close marker that starts with ``--<boundary>`` but is not a delimiter line; boundary text in the
preamble, which would otherwise drop the first part; a line starting with ``--<boundary>`` after the
close marker; and a part with no header block, or with no ``name`` or ``filename`` parameter, under
the rule in the next paragraph.

**Headerless and nameless parts** (BACKLOG #5787). This is the one statement of the rule; the
docstrings and comments below point here. A part is nameless when no Content-Disposition parameter
of its header block has the key ``name`` or ``filename``, whatever its value's form
(:func:`_disposition_params` says what a parameter is). In a body that closes, a part with no header
block and a nameless part are each refused with a 400, at any size. In a body that does not close, a
part with no header block over ``_MAX_FIELD_BYTES`` is refused with that 400 at once, a nameless part
over ``_MAX_FIELD_BYTES`` gets the field cap's 413, and a smaller one of either is not refused for
itself, so the body gets the missing close marker refusal unless another check refuses it first.

**How a Content-Disposition is read** (BACKLOG #5787). One quote-aware tokenizer,
:func:`_disposition_params`, reads each Content-Disposition line into ``(key, value)`` pairs, and a
part's ``name``, ``filename`` and whether it is nameless all come from those pairs. What a
parameter is, and when its value is read, is that function's docstring.

**What a delimiter line is** (BACKLOG #5787). ``--<boundary>`` counts only at the start of the body
or right after a CR or an LF, so boundary text in the middle of a line is part content. After it come
an optional ``--`` (the close marker), optional spaces and tabs, then a CR, an LF or the end of the
body. A bare CR counts as a line break before a delimiter and after one, because HL7 ends its segments
with one: a close marker right after a file's last segment CR, and a CR run after a delimiter, both
still parse. A body cut inside its close marker, ending ``--<boundary>-``, is refused as unclosed.
A close-marker line with text after its padding (``--<boundary>--epilogue``) is refused, not taken as
the close, because the same line inside a file would otherwise end the file there. A file line
that is a plain delimiter line splits the file. Where the rest has no blank CRLF line, it has no
header block, and is refused; where it has one, the rest reads as a part with a header block,
refused unless its header happens to name a part (next paragraph), under the rule above.

**What it still trusts.** A part's content must not hold a whole delimiter line. Because a bare CR is
a line break, every HL7 segment start is a line start, so a file whose segment is a close-marker
line (``--<boundary>--``, padding allowed) still ends there, and a body cut short after such a
segment is taken as complete, unless the epilogue after it holds a line starting with the
boundary, which a body with the real close marker later always does. A file line that only starts
with the close marker (``--<boundary>--note``) is refused in a whole body, but a body cut right
after its ``--<boundary>--``, or inside padding after it, leaves a valid close and is taken as
complete. At least those remain, and a split whose rest happens to read as a named part (its own
``Content-Disposition`` with a ``name`` or ``filename`` parameter).
A real client picks a boundary its content never holds (RFC 2046), so this is the same invariant
every multipart parser rests on, narrowed from any boundary text to a whole line of it.

Scope: exactly what an upload form needs — one file part + optional small text fields. It is not a
general RFC-2388 implementation (no nested multipart/mixed, no transfer-encoding decode); those are out
of scope for an operator file upload and are not accepted.
"""

from __future__ import annotations

import asyncio
import contextvars
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

# The Content-Disposition tokenizer (:func:`_disposition_params`). Each ``search`` of
# ``_DISP_ITEM`` reads one item and consumes all it scans, with possessive quantifiers and
# alternatives told apart by their first character, so a line is read in one linear pass: this is
# the **ReDoS guard** (CodeQL py/polynomial-redos). The header block is attacker-supplied, and the
# regex this replaced, ``(\w+)="..."`` unanchored, restarted at every offset of a word run and was
# quadratic on one until a lookbehind guard was added. Running the parse in a worker thread
# (BACKLOG #5522) does not make a quadratic scan safe, for the reason ``parse_upload_off_loop``'s
# docstring states. The cost is pinned by the scan-budget tests in ``tests/test_multipart.py``.
#:
#: One item: either a quoted-string where a key belongs, or a key (the run up to a space, separator,
#: ``=`` or quote, or nothing right before an ``=``) then, optionally, spaces, ``=``, spaces and a
#: value: a quoted-string (groups 4 to 6: its opening quote, its text, its closing quote, empty if the
#: line ends first) or a token (the run up to a space or separator). A backslash in a quoted-string
#: takes the next character with it, so ``\"`` does not close the string: this is the escaped
#: reading, and :func:`_disposition_params` says when the other is used.
_DISP_ITEM = re.compile(
    r'"(?:[^"\\]|\\[\s\S])*+"?+'
    r'|([^ \t;,="]++|(?==))'
    r'(?:([ \t]*+)=([ \t]*+)(?:(")((?:[^"\\]|\\[\s\S])*+)("?+)|[^ \t;,]*+))?'
)
#: The escapes a quoted value's text is decoded for. A backslash before any other character is kept,
#: so a Windows path such as ``C:\logs\a.hl7`` reads as written.
_DISP_ESCAPE = re.compile(r'\\([\\"])')
#: What may follow a quoted value's closing quote: the end of the line, a space or a separator.
_DISP_AFTER_VALUE = frozenset(" \t;,")
_DISPOSITION_HEADER = "content-disposition:"

#: Cap on one part's header block. RFC 2388 part headers are ``Content-Disposition`` plus at most a
#: ``Content-Type``/``Content-Transfer-Encoding``, so 16 KiB is orders of magnitude more than any real
#: client sends. Without it the block is bounded only by the request body cap — ``[store]
#: .max_upload_bytes``, 25 MiB by default and up to 512 MiB — because that cap is applied to a part's
#: *content*, only after its header has already been parsed. The scan is linear (see the guard above),
#: but it ran synchronously on the asyncio event loop that also drives every listener and worker, and
#: linear is not free at that size: a single request would block the engine for ~0.35 s at 25 MiB and
#: ~7 s at the ceiling (the worker thread since BACKLOG #5522 does not help a single scan; see
#: ``parse_upload_off_loop``). Bounding the header bounds the cost and, incidentally, gives the
#: ReDoS analysis a length-bounded source instead of an attacker-sized one. The tokenizer that
#: replaced the regex (BACKLOG #5787) loops in Python once per item: measured 2026-11-21 on a dev
#: box, the slowest shape the scan-budget tests time (``=""`` repeated) took ~4 ms for a
#: 12,000-character line, and a body of 16 parts with header blocks of that shape near this cap
#: ~76 ms (~22 ms for ``a=b`` items), against ~5 ms for the regex.
_MAX_PART_HEADER_BYTES = 16 * 1024

#: Cap on the number of parts in one body. The upload route keeps one file part and reads no other
#: field, so 16 is generous for a real upload form. Without it the part count is bounded only by the
#: body cap: a 25 MiB body of empty parts is about 2.9 million segments, each one split, copied and
#: header-parsed by the parser this replaced. Measured 2026-11-10 on a dev box, that took about 2 s
#: with a peak near 150 MiB, about six times the body. The walk stops at the first part over the cap.
_MAX_PARTS = 16

#: Cap on one non-file part's bytes, named or not (the module docstring's rule on nameless parts
#: says when one is refused before this cap). ``max_file_bytes`` bounds only file parts, so a
#: text field was bounded by the body cap alone and was decoded into a ``str`` of up to the whole
#: body. The upload route keeps no text field, so this only has to admit a short form value.
_MAX_FIELD_BYTES = 16 * 1024

#: The upload parse's own executor (BACKLOG #5522). Not the loop's default executor: router and
#: transform work runs there. Two workers bound the threads, and so the CPU, that concurrent upload
#: parses can take in this process. Later parses queue here. A semaphore around ``asyncio.to_thread``
#: would not hold that bound, because a cancelled request (the request deadline) releases its slot
#: while its thread keeps parsing. Memory is not bounded by this: each request's body, and the copy
#: of its file part the parse returns, outlive the worker until the route is done with them.
_PARSE_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="mefor-upload-parse")


class MultipartError(ValueError):
    """The body is not a well-formed single-file ``multipart/form-data`` request."""


class MultipartTooLargeError(MultipartError):
    """A file part exceeds the caller's byte cap, or a non-file part with a header block exceeds
    ``_MAX_FIELD_BYTES`` (HTTP 413). A part with no header block, or a nameless one, may get the
    base :class:`MultipartError` (HTTP 400) instead; the module docstring's rule on headerless and
    nameless parts says when."""


@dataclass(frozen=True)
class FilePart:
    """One uploaded file part: the form field ``name``, the client ``filename``, and the raw bytes."""

    name: str
    filename: str
    data: bytes


@dataclass(frozen=True)
class MultipartForm:
    """The parsed parts of a ``multipart/form-data`` body: file parts + simple text fields."""

    files: list[FilePart] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)


def parse_boundary(content_type: str | None) -> bytes | None:
    """Extract the boundary token (as bytes) from a ``multipart/form-data`` Content-Type, or ``None``."""
    ct = content_type or ""
    if "multipart/form-data" not in ct.lower():
        return None
    for param in ct.split(";"):
        param = param.strip()
        if param.lower().startswith("boundary="):
            value = param[len("boundary=") :].strip()
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            # RFC 2046 boundaries are ASCII; latin-1 round-trips any byte a client might send.
            return value.encode("latin-1") if value else None
    return None


def _disposition_params(value: str) -> list[tuple[str, str | None]]:
    r"""The parameters of one Content-Disposition value (the text after ``Content-Disposition:``),
    in order, as ``(key, value)`` pairs with the key lowercased (BACKLOG #5787).

    The value is read left to right as RFC 6266 and RFC 7578 write it, tolerantly. Spaces, tabs,
    ``;`` and ``,`` separate items. An item is a key, then, if an ``=`` follows it (spaces allowed
    around the ``=``), a value: a quoted-string, read as the next paragraph says, or else a token,
    which runs to the next space or separator. A key with no ``=`` after it is the
    disposition type, or stray text, and is not a parameter; so ``form-data`` is not, and a first
    item such as ``filename="a.hl7"`` is. A quoted-string where a key belongs is skipped. A key is
    the whole run before its ``=``, so ``x-name``, ``foo*name`` and the extended ``filename*`` are
    their own keys, and text inside a quoted value is never a key.

    **Two readings of a quoted value.** Most clients never backslash-escape one: a browser, httpx
    and curl by default percent-encode a ``"`` (as ``%22``), and a browser leaves a backslash as it
    is, so ``name="a\"; filename="b.hl7"`` is a name that ends in a backslash. Some, such as curl
    with ``--form-escape``, write ``x="a\"b"``. So a quoted value is read first as the regex this
    replaced read it, to the first ``"`` with every backslash kept, where that quote is followed by
    the end of the line, a space or a separator. Otherwise it is read with the escapes, ``\"`` and
    ``\\`` decoded and any other backslash kept, where that reading closes; and otherwise to the
    first ``"`` again, if there is one.

    The pair's value is the text so read, when the quoted-string is written right after ``key=``
    with no space. Otherwise it is ``None``: a token, a value with spaces around its ``=`` and an
    unclosed quoted-string with no later ``"`` give the key but no value, as the regex this
    replaced read none of them."""
    pairs: list[tuple[str, str | None]] = []
    pos, end = 0, len(value)
    while (item := _DISP_ITEM.search(value, pos)) is not None:
        pos = item.end()
        key, before, after, quote = item.group(1, 2, 3, 4)
        if key is None or before is None:
            continue  # a quoted-string where a key belongs, or a key with no "="
        text: str | None = None
        if quote is not None:
            raw, opened = item.group(5), item.start(5)
            # Without a backslash the two readings are one, and the escaped match already holds it.
            literal = value.find('"', opened) if "\\" in raw else -1
            if literal != -1 and (literal + 1 == end or value[literal + 1] in _DISP_AFTER_VALUE):
                text, pos = value[opened:literal], literal + 1
            elif item.group(6):
                text = _DISP_ESCAPE.sub(r"\1", raw)
            elif literal != -1:
                text, pos = value[opened:literal], literal + 1
            if before or after:
                text = None
        pairs.append((key.lower(), text))
    return pairs


def _disposition(head: bytes) -> tuple[str | None, str | None, bool]:
    """A part's Content-Disposition ``name`` and ``filename`` (each ``None`` if no value was read),
    and whether the part is named, all from :func:`_disposition_params`' pairs: named means a
    parameter keyed exactly ``name`` or ``filename``, whatever its value's form (the module
    docstring's rule on nameless parts). Where a key repeats, the last value read wins."""
    text = head.decode("latin-1", "replace")
    name: str | None = None
    filename: str | None = None
    named = False
    for line in text.split("\r\n"):
        if line[: len(_DISPOSITION_HEADER)].lower() == _DISPOSITION_HEADER:
            for key, value in _disposition_params(line[len(_DISPOSITION_HEADER) :]):
                if key not in ("name", "filename"):
                    continue
                named = True
                if value is not None and key == "name":
                    name = value
                elif value is not None:
                    filename = value
    return name, filename, named


#: The hint a refusal gives when the likeliest cause is a file sent as a plain field (no
#: ``filename``), as ``curl -F 'file=<log.hl7'`` sends one, rather than as a file part.
_FILE_AS_FIELD_HINT = 'Send a file as a file part with a plain filename parameter (filename="...")'

#: Ends the CR/LF run a non-conforming client leaves after a delimiter (the old parser ``lstrip``-ed
#: it).
_NOT_CRLF = re.compile(rb"[^\r\n]")

#: The rest of a delimiter line after ``--<boundary>``, up to its line break (the module docstring
#: defines the line): the close marker, if any, then transport padding. It always matches, and the
#: byte after it decides the line. The quantifiers are possessive as a rule for padding matches here;
#: under ``match`` with nothing after them, a plain pattern would not backtrack either.
_DELIM_TAIL = re.compile(rb"(--)?+[ \t]*+")


@dataclass(frozen=True)
class _Part:
    """One part, located in the body by offset. Nothing of its content has been copied."""

    name: str | None
    filename: str | None
    start: int  # the first byte of the part's content
    end: int  # one past its last byte, before the CRLF that precedes the next delimiter

    def file(self, body: bytes, filename: str) -> FilePart:
        """This part as a :class:`FilePart`, which takes the one copy of its content."""
        return FilePart(
            name=self.name or "file", filename=filename, data=body[self.start : self.end]
        )


def _locate_parts(content_type: str | None, body: bytes, *, max_file_bytes: int) -> list[_Part]:
    """Find every part of a ``multipart/form-data`` body by offset and apply every cap, copying no
    part's content (BACKLOG #5522).

    The body is walked with ``find`` rather than ``split``: a split copies each segment, and the old
    walk then sliced, partitioned and trimmed it again, about four copies of every admitted part, all
    alive at once. Here the only copy of a part's content is the one the caller takes of a value it
    keeps. Two passes: the first counts parts, bounds each header block and finds each part with no
    header block, all before any header is parsed; the second parses each header, which says
    whether the part is a file or nameless, and applies the nameless rule (module docstring) and the
    file and field caps to the part's length.

    Raises what :func:`parse_multipart_form` documents."""
    boundary = parse_boundary(content_type)
    if boundary is None:
        raise MultipartError("Content-Type is not multipart/form-data with a boundary")
    delim = b"--" + boundary
    lines = _DelimiterLines(body, delim)
    # (header start, header end, content start, content end) for each part with a header block.
    spans: list[tuple[int, int, int, int]] = []
    count = 0
    closed = False
    pending: MultipartError | None = None  # a headerless part's refusal, raised if the body closes
    # Anything before the first delimiter line is the ignorable preamble, unless it holds boundary
    # text; the close marker ends the walk, and anything after it is the ignorable epilogue, unless a
    # line of it starts with the boundary.
    pos = lines.next(0)
    seen = pos != -1
    if seen and body.find(delim, 0, pos) != -1:
        # BACKLOG #5787: bytes before the first delimiter on its own line (a BOM, stray text) make
        # that line preamble, so the first part would be dropped unseen.
        raise MultipartError(
            "multipart body has boundary text before its first delimiter line; the first part "
            "would be lost"
        )
    while pos != -1:
        start, closed = lines.tail(pos)
        if closed:
            if lines.next(start) != -1:
                # BACKLOG #5787: no client writes a delimiter after its close marker, and a file
                # line that is a close-marker line, ahead of the real one, leaves exactly this.
                raise MultipartError(
                    "multipart body has a line starting with the boundary after its close "
                    "marker; a file line may hold the close marker"
                )
            break
        nxt = lines.next(start)
        end = len(body) if nxt == -1 else nxt
        # After each delimiter line comes CRLF, then the part's header block.
        if body.startswith(b"\r\n", start, end):
            start += 2
        else:
            # In C rather than a byte at a time: a run of CR/LF here can be most of the body.
            first = _NOT_CRLF.search(body, start, end)
            start = end if first is None else first.start()
        if nxt == -1 and start == end:
            # A last delimiter line with nothing after it is not a part. Not counting it keeps an
            # unterminated body at the part cap refused below for its missing terminator rather
            # than for the part cap, which is the refusal that names the cause.
            break
        count += 1
        if count > _MAX_PARTS:
            # Refuse before any header is parsed: a body of this shape is never a real form.
            raise MultipartError(f"multipart body has more parts than the limit of {_MAX_PARTS}")
        sep = body.find(b"\r\n\r\n", start, end)
        if sep == -1:
            # Refused, not skipped, as the module docstring's rule on headerless parts says (BACKLOG
            # #5787). No real client sends a part without a header block, and one is what is left
            # when a file line, such as an HL7 segment after a bare CR, is a whole delimiter line:
            # skipping it would store the file cut short there. A 400, not a 413: the size is not
            # what the client has to change, and the other likely cause is headers ended with bare
            # LFs. Over the field cap it is raised at once; otherwise the first such part's refusal
            # waits for the walk's end, so an unclosed body, often one cut inside a header block, is
            # refused for that cause.
            size = end - start - (2 if body.endswith(b"\r\n", start, end) else 0)
            headerless = MultipartError(
                f"multipart part of {size} bytes has no header block ended by a blank CRLF line; "
                "headers ended with bare LFs, or a file line that is a whole boundary delimiter "
                "line, leave one"
            )
            if size > _MAX_FIELD_BYTES:
                raise headerless
            pending = pending or headerless
        else:
            if sep - start > _MAX_PART_HEADER_BYTES:
                # Refuse rather than skip: a header this size is never a real client, and skipping
                # would surface as the confusing "no file part" error instead of the real problem.
                raise MultipartError(
                    f"multipart part header block is {sep - start} bytes; the limit is "
                    f"{_MAX_PART_HEADER_BYTES}"
                )
            content_start = sep + 4
            content_end = end
            if body.endswith(b"\r\n", content_start, end):
                content_end = end - 2  # the CRLF before the next delimiter
            spans.append((start, sep, content_start, content_end))
        pos = nxt
    if closed and pending is not None:
        raise pending
    parts: list[_Part] = []
    for head_start, head_end, content_start, content_end in spans:
        head = body[head_start:head_end]
        name, filename, named = _disposition(head)
        size = content_end - content_start
        if closed and not named:
            # BACKLOG #5787, under the module docstring's rule on nameless parts: refused, not
            # skipped. A file split at a whole delimiter line, whose rest holds a blank CRLF line,
            # leaves this shape, and skipping it would store the file cut short. A ``name`` whose
            # value is not read (an unquoted ``name=x``) still names the part, so that part is
            # left to the field cap, as before.
            raise MultipartError(
                "multipart part has neither a name nor a filename in its Content-Disposition; "
                "a file line that is a whole boundary delimiter line can leave one"
            )
        if filename is not None:
            if size > max_file_bytes:
                raise MultipartTooLargeError(
                    f"uploaded file part is {size} bytes; the limit is {max_file_bytes}"
                )
        elif size > _MAX_FIELD_BYTES:
            raise MultipartTooLargeError(
                f"multipart text field is {size} bytes; the limit is {_MAX_FIELD_BYTES}. "
                f"{_FILE_AS_FIELD_HINT}"
            )
        parts.append(_Part(name=name, filename=filename, start=content_start, end=content_end))
    # BACKLOG #5787: a body the walk did not close is refused, because a body that ends before its
    # close marker (for example one built from a file still being written) is one, and its last part
    # would otherwise run to the end of the body and be taken as complete. Checked last, so a body
    # that fails a check above gets that refusal. Only a close marker on its own delimiter line ends
    # the walk, so close-marker text in the middle of a line does not pass a cut-short body.
    if not closed:
        if not seen:
            # No delimiter line at all. At least an empty body, one built with a boundary the
            # declared one is not a prefix of, and one whose only boundary text sits mid-line land
            # here. A body built with a longer boundary (declared B, body uses BX) does not: its
            # lines start with ``--B``, so ``_DelimiterLines.tail`` usually refuses the first of
            # them. Not when X is ``--`` and padding: that first line then reads as the close.
            raise MultipartError(
                "multipart body holds no delimiter for the boundary its Content-Type names"
            )
        raise MultipartError(
            "multipart body has no closing boundary delimiter; the upload may be truncated"
        )
    return parts


class _DelimiterLines:
    """Finds each ``--<boundary>`` that starts a line of one body, in order (BACKLOG #5787; the
    module docstring defines a delimiter line).

    There are two ``find`` streams, one per line-break byte, and each keeps its last hit until the
    walk passes it, so each stream scans the body about once however many delimiters it holds. That
    cache is why :meth:`next` must be called with a ``frm`` that never decreases."""

    def __init__(self, body: bytes, delim: bytes) -> None:
        self._body = body
        self._delim = delim
        self._needles = (b"\n" + delim, b"\r" + delim)
        # Each stream's last hit: the offset of its line-break byte, -1 for none left, -2 unread.
        self._hits = [-2, -2]

    def next(self, frm: int) -> int:
        """The offset of the first ``--<boundary>`` at or after ``frm`` that starts a line, or -1.
        ``frm`` must be at least the previous call's: a cached hit past it is not searched behind,
        and the one walk in :func:`_locate_parts` only moves forward."""
        if frm == 0 and self._body.startswith(self._delim):
            return 0
        best = -1
        for k, needle in enumerate(self._needles):
            hit = self._hits[k]
            if hit != -1 and hit < frm - 1:
                hit = self._body.find(needle, max(frm - 1, 0))
                self._hits[k] = hit
            if hit != -1 and (best == -1 or hit + 1 < best):
                best = hit + 1
        return best

    def tail(self, pos: int) -> tuple[int, bool]:
        """Read the delimiter line at ``pos``: the offset just past its padding, and whether it is
        the close marker.

        Raises :class:`MultipartError` for a line that starts with the delimiter but is not a
        delimiter line, rather than read it as content, with one exception: ``--<boundary>-`` at the
        end of the body is a cut inside the close marker, so it returns as an unclosed delimiter
        line and the walk refuses the body for its missing close marker. A real client picks a boundary its content
        never holds, so such a line means a body built with a longer boundary than the one declared,
        or a part that holds the boundary text at a line start, and splitting or closing there would
        take a part as other than it was sent. Refusing also means a body of such lines stops at the
        first one, so only real delimiter lines, which the part cap bounds, keep the walk going."""
        body = self._body
        name_end = pos + len(self._delim)
        if name_end == len(body) - 1 and body[name_end] == 0x2D:  # a "-", read without a slice copy
            # A body cut inside its close marker: an unclosed delimiter line, not a foreign one, so
            # the walk refuses it for the missing close marker, the refusal that names the cause.
            return len(body), False
        match = _DELIM_TAIL.match(body, name_end)
        assert match is not None  # the pattern matches the empty string
        after = match.end()
        if after < len(body) and body[after] not in b"\r\n":
            raise MultipartError(
                "multipart body has a line that starts with the boundary delimiter but is not a "
                "delimiter line; the body may use another boundary than its Content-Type names, "
                "or a part may hold a line that starts with the boundary"
            )
        return after, match.group(1) is not None


def parse_multipart_form(
    content_type: str | None, body: bytes, *, max_file_bytes: int
) -> MultipartForm:
    """Parse a ``multipart/form-data`` body into file parts + text fields.

    Raises :class:`MultipartError` if the Content-Type is not multipart, the body is malformed, it
    has no closing delimiter line, it holds more than ``_MAX_PARTS`` parts, it has boundary text in
    its preamble or a boundary line after its close marker, or a line starts with the delimiter but
    is not a delimiter line (all HTTP 400 at the route), and :class:`MultipartTooLargeError` if a
    file part exceeds ``max_file_bytes`` or a non-file part with a header block exceeds
    ``_MAX_FIELD_BYTES`` (HTTP 413 at the route). A part with no header block, or a nameless one,
    is refused as the module docstring's rule on them says, with a 400 or the field cap's 413.

    The order, where a body has more than one fault: first the walk's refusals (preamble boundary
    text, the part count, an oversized header block, a part with no header block that the rule
    refuses at once, a misdelimited line, a boundary line after the close marker), in body order;
    then the rest of the headerless rule; then, part by part, the nameless rule and the size caps;
    then, last, a body with no delimiter line or no close marker. So an unclosed body with a file
    or field part over its cap gets the 413, and an unclosed body cut inside a header block gets
    the missing close marker refusal. The module docstring says what a
    delimiter line is, how a Content-Disposition is read, and what the parser still trusts of a
    part's content.

    The function is synchronous and walks the whole body. The upload route keeps one file and no
    field, so it calls :func:`parse_upload_off_loop`, which runs :func:`parse_single_file_upload`
    off the event loop; there is no off-loop form of this function, which keeps the text fields."""
    form = MultipartForm()
    for part in _locate_parts(content_type, body, max_file_bytes=max_file_bytes):
        if part.filename is not None:
            form.files.append(part.file(body, part.filename))
        elif part.name is not None:
            form.fields[part.name] = body[part.start : part.end].decode("utf-8", "replace")
    return form


def parse_single_file_upload(
    content_type: str | None, body: bytes, *, max_file_bytes: int
) -> FilePart:
    """Parse a body expected to carry exactly one file part; return it. Raises :class:`MultipartError`
    if no file part is present or more than one is, and what :func:`parse_multipart_form` raises.

    Text fields are bounded but never decoded or kept, and only the one file part's content is
    copied out of ``body``."""
    parts = _locate_parts(content_type, body, max_file_bytes=max_file_bytes)
    files = [(part, part.filename) for part in parts if part.filename is not None]
    if not files:
        detail = "no file part in the multipart/form-data body"
        if parts:
            detail += f". {_FILE_AS_FIELD_HINT}"
        raise MultipartError(detail)
    if len(files) > 1:
        raise MultipartError(f"multipart body has {len(files)} file parts; an upload carries one")
    part, filename = files[0]
    return part.file(body, filename)


async def parse_upload_off_loop(
    content_type: str | None, body: bytes, *, max_file_bytes: int
) -> FilePart:
    """:func:`parse_single_file_upload` on :data:`_PARSE_EXECUTOR`, for an async caller, with the
    caller's context variables (as ``asyncio.to_thread`` passes them). It raises what that function
    raises.

    **What leaves the loop, and what does not.** This is the one statement of that limit; the
    comments that rely on it point here. The per-part Python work runs on the worker thread. At least
    each ``find`` over the body, each regex match in a header block, and the copy of the file part is
    still one C call that holds the GIL while it runs, so the event loop can still lose the time of the
    longest such call.

    When a request is cancelled (the request deadline) while its parse is still queued, the work
    item left on the executor holds an emptied list, not the body; the cancelled coroutine's own
    frame lets go of it when its Task does. A parse that has already started runs to the end,
    since a thread cannot be stopped."""
    held = [body]

    def parse() -> FilePart:
        if not held:  # only after a cancel, so nobody reads this refusal
            raise MultipartError("the upload was cancelled before its parse started")
        data = held.pop()
        return parse_single_file_upload(content_type, data, max_file_bytes=max_file_bytes)

    ctx = contextvars.copy_context()
    try:
        return await asyncio.get_running_loop().run_in_executor(_PARSE_EXECUTOR, ctx.run, parse)
    finally:
        held.clear()
