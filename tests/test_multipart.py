# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Stdlib multipart/form-data parser for uploaded logs (ADR 0134) — no python-multipart."""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import gc
import re
import sys
import threading
import time
import tracemalloc
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.api import multipart
from messagefoundry.api.multipart import (
    _MAX_PART_HEADER_BYTES,
    FilePart,
    MultipartError,
    MultipartForm,
    MultipartTooLargeError,
    parse_boundary,
    parse_multipart_form,
    parse_single_file_upload,
)

_B = "----WebKitFormBoundaryABC123"


def _body(parts: list[bytes]) -> bytes:
    delim = f"--{_B}".encode()
    out = b""
    for p in parts:
        out += delim + b"\r\n" + p + b"\r\n"
    out += delim + b"--\r\n"
    return out


def test_parse_boundary() -> None:
    assert parse_boundary(f"multipart/form-data; boundary={_B}") == _B.encode()
    assert parse_boundary('multipart/form-data; boundary="quoted-bnd"') == b"quoted-bnd"
    assert parse_boundary("application/json") is None
    assert parse_boundary(None) is None


def test_single_file_upload_extracts_bytes() -> None:
    hl7 = b"MSH|^~\\&|A|B|C|D|202601010000||ADT^A01|X1|P|2.5\rPID|1||MRN\r"
    part = (
        b'Content-Disposition: form-data; name="file"; filename="acme.hl7"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + hl7
    )
    body = _body([part])
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024
    )
    assert file.filename == "acme.hl7"
    assert file.name == "file"
    assert file.data == hl7  # exact bytes preserved (CR delimiters intact)


def test_file_plus_text_field() -> None:
    part_file = b'Content-Disposition: form-data; name="file"; filename="x.hl7"\r\n\r\nMSH|body'
    part_field = b'Content-Disposition: form-data; name="content_type"\r\n\r\nhl7v2'
    form = parse_multipart_form(
        f"multipart/form-data; boundary={_B}", _body([part_file, part_field]), max_file_bytes=1024
    )
    assert len(form.files) == 1
    assert form.files[0].data == b"MSH|body"
    assert form.fields["content_type"] == "hl7v2"


def test_too_large_rejected() -> None:
    part = b'Content-Disposition: form-data; name="file"; filename="big"\r\n\r\n' + b"x" * 100
    with pytest.raises(MultipartTooLargeError):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", _body([part]), max_file_bytes=10
        )


def test_non_multipart_rejected() -> None:
    with pytest.raises(MultipartError):
        parse_single_file_upload("application/json", b"{}", max_file_bytes=1024)


def test_no_file_part_rejected() -> None:
    part = b'Content-Disposition: form-data; name="just_a_field"\r\n\r\nvalue'
    with pytest.raises(MultipartError):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", _body([part]), max_file_bytes=1024
        )


# --- ReDoS guard on the Content-Disposition parameter regex (CodeQL py/polynomial-redos) ---------

#: The pre-guard pattern. Kept here so the equivalence test proves the ``(?<!\w)`` guard is a pure
#: performance change; if the production regex ever drifts, this test is what catches the semantic gap.
#: It is also the live positive control for the cost arms below: swapped into the shipping parse path,
#: it shows that the budget those arms assert against is a line a quadratic scan cannot get under.
_LEGACY_DISPOSITION_PARAM = re.compile(r'(\w+)="([^"]*)"')

#: Length of the hostile word run the cost arms measure. 12,000 word characters and no further ``="``
#: is 73 percent of ``_MAX_PART_HEADER_BYTES``, so the arms measure close to the largest header the
#: parser will actually admit rather than an arbitrary size. Measured 2026-09-03 on a dev box:
#: ``parse_single_file_upload`` handles this body in ~0.16 ms with the shipped pattern and ~0.7 s with
#: the unguarded one -- a separation of about 3,900x, which is the room the budget below spends.
_HOSTILE_HEADER_CHARS = 12_000

#: The one line both cost arms are measured against, sitting between the two costs recorded above. The
#: margins run in OPPOSITE directions across it, which is why a single number does the work of two.
#:
#: **Above the line (the production arm) a stall turns a pass into a failure, so the margin is huge:**
#: ~290x, and the estimate is best-of-5, so a runner would have to stall for 50 ms five separate times
#: inside a 0.16 ms window to fake a red.
#:
#: **Below the line (the control arm) a stall can only help, so the margin stays tight:** ~13x, and one
#: sample is enough there because noise cannot deflate it.
#:
#: **Deliberately one number rather than a ceiling plus a lower floor.** A floor beneath the ceiling
#: would open a band in which a half-fixed scan clears both arms; sharing the line makes the control
#: prove that this exact budget discriminates. If some future CPython makes the unguarded scan fast
#: enough to slip under it, the control reds -- which is the correct thing to be told, because at that
#: point the instrument has stopped discriminating and the number needs re-deriving.
_SCAN_BUDGET_SECONDS = 0.05


@pytest.mark.parametrize(
    "line",
    [
        'Content-Disposition: form-data; name="file"; filename="acme.hl7"',
        'Content-Disposition:form-data;name="a";filename="b.txt"',
        'Content-Disposition: form-data; filename="a;b=c.txt"; name="f"',
        'Content-Disposition: form-data; name=""',
        'Content-Disposition: form-data; foo*name="x"',
        'Content-Disposition: form-data; name="x" name="y"',
        'Content-Disposition: form-data; 9name="d"; _n="e"',
        'Content-Disposition: form-data; name = "spaced"',
        'name="a"filename="b"',
        "Content-Disposition: form-data",
    ],
)
def test_disposition_param_regex_matches_legacy_semantics(line: str) -> None:
    """The ``(?<!\\w)`` ReDoS guard must not change which parameters are extracted.

    Read through the module rather than a from-import, so this file has exactly ONE way to name the
    pattern and it is the one the arms below substitute. A second, permanently-real binding would sit
    right beside three tests that replace it, and nothing would say which is which."""
    assert multipart._DISPOSITION_PARAM.findall(line) == _LEGACY_DISPOSITION_PARAM.findall(line)


def _hostile_upload() -> tuple[str, bytes]:
    """A well-formed single-file upload whose Content-Disposition carries a long word run and no
    further ``="``. That is the shape an unguarded ``(\\w+)="…"`` walks quadratically: the scan
    restarts at every offset inside the run and each restart walks the rest of it.

    The size invariant lives here rather than in one arm, because it is a property of the fixture and
    every arm depends on it."""
    assert _MAX_PART_HEADER_BYTES // 2 < _HOSTILE_HEADER_CHARS < _MAX_PART_HEADER_BYTES, (
        f"the hostile header must sit near the cap the parser admits, not merely under it: "
        f"{_HOSTILE_HEADER_CHARS} against a cap of {_MAX_PART_HEADER_BYTES}. Over the cap and the "
        f"arms time the refusal path; far under it and they stop measuring the worst case the engine "
        f"actually accepts. Moving the cap means re-deriving BOTH this size and the budget below: "
        f"the control arm's cost grows with the square of this number."
    )
    part = (
        b'Content-Disposition: form-data; name="file"; filename="acme.hl7"; '
        + b"a" * _HOSTILE_HEADER_CHARS
        + b"\r\n\r\nMSH|body"
    )
    return f"multipart/form-data; boundary={_B}", _body([part])


def _parse_seconds(reps: int) -> float:
    """Best-of-``reps`` seconds for the real ``parse_single_file_upload`` on the hostile body.

    The MINIMUM is the noise-free estimate: a scheduling hiccup can only inflate a sample, never
    deflate one, so one slow slice on a loaded runner cannot fake a red.

    The parse is asserted to SUCCEED on every rep. Without that an arm could pass by timing an early
    error path — a refused boundary, or a header the size cap rejected — instead of the scan it claims
    to measure."""
    content_type, body = _hostile_upload()
    best = float("inf")
    for _ in range(reps):
        start = time.perf_counter()
        file = parse_single_file_upload(content_type, body, max_file_bytes=1024)
        best = min(best, time.perf_counter() - start)
        assert file.filename == "acme.hl7"
    return best


def test_a_hostile_disposition_header_stays_inside_the_scan_budget() -> None:
    """A Content-Disposition line of many word chars and no ``="`` must not blow up quadratically.

    The header block is attacker-supplied, and the worker thread the upload route parses in does
    not spare the event loop a scan (``multipart.parse_upload_off_loop`` says why), so a quadratic
    scan here is a whole-engine denial of service, not a slow request. ``_MAX_PART_HEADER_BYTES``
    bounds the input as well, but the two controls are independent on purpose: the cap is a size
    policy someone could reasonably raise, while this bounds what the scan costs at the size the cap
    admits today.

    **This replaced a growth-ratio assertion, and the ratio is why BACKLOG #1385 has this row.** The
    old arm timed the bare regex at n and 4n and required the quotient under 8.0, reasoning that
    quadratic scaling multiplies by ~16 and linear stays near ~4. It ejected PR 669 anyway, at ratio
    **8.02**. A ratio is not inherently steadier than a wall-clock budget. It is steadier only where a
    budget would have thin headroom, and here a budget has enormous headroom. The old statistic put the
    whole test inside a 2x window (4 measured, 8 asserted) and put the noise in the NUMERATOR, where a
    ``min`` over reps clamps deflation and nothing clamps inflation — so every scheduling hiccup pushed
    the quotient one way, up. Re-run 15 times on an IDLE box on 2026-09-03 it ranged **3.73 to 6.80**,
    already 85 percent of the way to its own bound with nothing else competing for the core.

    The separation between linear and quadratic on this input is ~3,900x, not 4x, so an absolute
    budget carries ~290x of headroom where the ratio carried 1.9x. It also times the shipping entry
    point rather than a detached regex, so the cost claim is about the parse an upload really runs.
    """
    seconds = _parse_seconds(5)
    assert seconds < _SCAN_BUDGET_SECONDS, (
        f"the hostile header scan cost {seconds:.4f}s against a {_SCAN_BUDGET_SECONDS}s budget"
    )


def test_the_unguarded_pattern_blows_that_same_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live positive control: the SAME body and the SAME budget, with the ``(?<!\\w)`` guard removed
    from the shipping parse path.

    Without it the arm above is unfalsifiable. A budget nothing on this input could ever exceed would
    pass while measuring nothing, and so would an input that had quietly stopped being hostile — which
    the old ratio arm had no way to notice either, since it never ran a pattern it expected to be slow.
    This one does: it patches the module global ``_disposition`` reads, so the whole shipping path runs
    unguarded rather than a regex held off to one side.

    One rep, deliberately. The assertion is that the scan is SLOW, so noise moves it the safe way."""
    monkeypatch.setattr(multipart, "_DISPOSITION_PARAM", _LEGACY_DISPOSITION_PARAM)
    seconds = _parse_seconds(1)
    assert seconds > _SCAN_BUDGET_SECONDS, (
        f"the unguarded pattern parsed the hostile header in {seconds:.4f}s, inside the "
        f"{_SCAN_BUDGET_SECONDS}s budget. The budget no longer separates a linear scan from a "
        f"quadratic one, so the arm above is not measuring anything"
    )


class _ScanSentinel:
    """Stands in for the disposition pattern and fails loudly on ANY use of it.

    It trips from ``__getattr__`` rather than by implementing ``finditer``, because a stand-in pinned
    to one method name degrades into an ``AttributeError`` the day the scan is rewritten to call
    something else — and this file already calls ``findall`` on that same object. An
    ``AttributeError`` would still red, but it would name the wrong problem."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"{self.reason} (the scan asked the pattern for {name!r})")


def test_oversized_part_header_is_refused_not_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A part header block past ``_MAX_PART_HEADER_BYTES`` is rejected before ``_disposition`` runs.

    The per-part ``max_file_bytes`` cap applies to a part's *content*, and only AFTER its header has
    been parsed — so without this bound the header scan's input is the whole request body (25 MiB by
    default, 512 MiB at the ceiling). A real client never approaches it: a Content-Disposition plus
    a Content-Type is a couple hundred bytes.

    **"Before" is the whole claim, so it is asserted rather than described.** A sentinel stands in for
    the pattern and raises if the scan reaches it, so the refusal has to arrive with the header
    unscanned. Checking only that ``MultipartError`` is raised passes identically with the cap moved
    below the scan — and that reordering is exactly the regression that hands the header scan a
    body-sized input again, which is the reason the cap exists.
    """
    sentinel = _ScanSentinel(
        "the size cap should have refused this header before anything scanned it"
    )
    monkeypatch.setattr(multipart, "_DISPOSITION_PARAM", sentinel)
    fat = b"X" * (_MAX_PART_HEADER_BYTES + 1)
    part = (
        b'Content-Disposition: form-data; name="file"; filename="a.hl7"\r\nX-Pad: '
        + fat
        + b"\r\n\r\nbody"
    )
    with pytest.raises(MultipartError, match="header block"):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", _body([part]), max_file_bytes=10_000_000
        )


def test_the_scan_sentinel_fires_when_a_header_is_scanned(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative control for the sentinel: it has to be able to report a scan that DID happen, or the
    arm above passes for the wrong reason — a sentinel that could never fire proves nothing about
    ordering. An ordinary under-cap header reaches ``_disposition`` normally, so the same substitution
    must raise there."""
    monkeypatch.setattr(multipart, "_DISPOSITION_PARAM", _ScanSentinel("reached"))
    part = b'Content-Disposition: form-data; name="file"; filename="a.hl7"\r\n\r\nMSH|body'
    with pytest.raises(AssertionError, match="asked the pattern for"):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", _body([part]), max_file_bytes=1024
        )


def test_realistic_part_header_is_well_under_the_cap() -> None:
    """Non-vacuity for the cap: an ordinary upload's header must be nowhere near the limit, so the
    bound can never start rejecting legitimate traffic."""
    head = b'Content-Disposition: form-data; name="file"; filename="acme.hl7"\r\nContent-Type: application/octet-stream'
    assert len(head) * 50 < _MAX_PART_HEADER_BYTES
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}",
        _body([head + b"\r\n\r\nMSH|body"]),
        max_file_bytes=1024,
    )
    assert file.filename == "acme.hl7"


# --- part-count and text-field caps (BACKLOG #5522) -----------------------------------------------


def _field(name: str, value: bytes) -> bytes:
    return f'Content-Disposition: form-data; name="{name}"'.encode() + b"\r\n\r\n" + value


_FILE_PART_HEAD = b'Content-Disposition: form-data; name="file"; filename="a.hl7"\r\n\r\n'
_FILE_PART = _FILE_PART_HEAD + b"MSH|body"


def _no_part_parse(head: bytes) -> tuple[str | None, str | None]:
    raise AssertionError("a part header was parsed")


def _parts(n: int) -> list[bytes]:
    """One file part and ``n - 1`` small text fields: ``n`` parts in all."""
    return [_FILE_PART] + [_field(f"f{i}", b"v") for i in range(n - 1)]


def test_too_many_parts_is_refused_before_any_part_is_parsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One part over ``_MAX_PARTS`` is refused with the 400 base error, and no part header is read.

    The sentinel on ``_disposition`` is what makes "refused" mean "refused up front": a cap that
    parsed the first ``_MAX_PARTS`` parts and then stopped would still raise, but only after it had
    done the per-part work the cap exists to bound. The next test shows the sentinel can fire."""
    monkeypatch.setattr(multipart, "_disposition", _no_part_parse)
    with pytest.raises(MultipartError, match="more parts than the limit") as caught:
        parse_multipart_form(
            f"multipart/form-data; boundary={_B}",
            _body(_parts(multipart._MAX_PARTS + 1)),
            max_file_bytes=1024,
        )
    # 400, not 413: the handler maps the base class to 400 and only the subclass to 413.
    assert type(caught.value) is MultipartError


def test_the_part_parse_sentinel_fires_when_a_part_is_parsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative control for the sentinel above: on a body the cap admits, the same substitution must
    raise, or the arm above could pass because the monkeypatch never reached the parse."""
    monkeypatch.setattr(multipart, "_disposition", _no_part_parse)
    with pytest.raises(AssertionError, match="a part header was parsed"):
        parse_multipart_form(
            f"multipart/form-data; boundary={_B}",
            _body(_parts(multipart._MAX_PARTS)),
            max_file_bytes=1024,
        )


def _peak_allocated(func: Callable[[], object]) -> int:
    """Bytes ``func`` allocated at its peak, over what was allocated when it started."""
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        base, _ = tracemalloc.get_traced_memory()
        with contextlib.suppress(MultipartError):
            func()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if not was_tracing:
            tracemalloc.stop()
    return peak - base


_BIG = 4 * 1024 * 1024


class _FindCounter(bytes):
    """A body that counts the ``find`` calls made on it."""

    finds = 0

    def find(self, *args: Any) -> int:
        self.finds += 1
        return super().find(*args)


def test_the_walk_stops_at_the_first_part_over_the_cap() -> None:
    """The part cap bounds the walk itself, not only the answer: a body of thousands of empty parts
    is refused after about ``_MAX_PARTS`` parts' worth of ``find`` calls, so a refusal reached only
    after walking every part (and the per-part cost the cap exists to bound) shows here."""
    delim = f"--{_B}".encode()
    body = _FindCounter(
        _body(_parts(multipart._MAX_PARTS))[: -len(delim) - 4] + (delim + b"\r\n") * 10_000
    )
    with pytest.raises(MultipartError, match="more parts than the limit"):
        parse_multipart_form(f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024)
    assert 0 < body.finds <= 3 * (multipart._MAX_PARTS + 2), body.finds


def test_a_part_with_no_header_block_is_bounded_too() -> None:
    """A part with no blank line after its headers is skipped, and is bounded like a nameless field
    rather than by the body cap alone."""
    junk = b"x" * (multipart._MAX_FIELD_BYTES + 1)
    with pytest.raises(MultipartError, match="no header block") as caught:
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", _body([_FILE_PART, junk]), max_file_bytes=1024
        )
    assert type(caught.value) is MultipartError  # 400: the size is not the cause to fix
    small = b"x" * multipart._MAX_FIELD_BYTES
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", _body([_FILE_PART, small]), max_file_bytes=1024
    )
    assert file.data == b"MSH|body"


def test_an_admitted_file_part_is_copied_once() -> None:
    """BACKLOG #5522 / #5520 item 20: the parse copies the file part it returns, once, and nothing
    else of the body. The old walk split, sliced, partitioned and trimmed each part, about four
    copies alive at once, so its peak was several times the body."""
    body = _body(
        [b'Content-Disposition: form-data; name="file"; filename="a.hl7"\r\n\r\n' + b"x" * _BIG]
    )
    ct = f"multipart/form-data; boundary={_B}"
    peak = _peak_allocated(lambda: parse_single_file_upload(ct, body, max_file_bytes=2 * _BIG))
    assert _BIG <= peak < 1.5 * _BIG, (
        f"the parse allocated {peak} bytes at its peak for a {_BIG}-byte part"
    )


def test_a_too_many_parts_refusal_copies_nothing_of_the_body() -> None:
    """#5520 item 21: the refusal must not copy the unsplit remainder of the body. The large part is
    the one past the cap, so a walk that copied it on the way to the count would show here."""
    parts = _parts(multipart._MAX_PARTS) + [_field("tail", b"x" * _BIG)]
    body = _body(parts)
    ct = f"multipart/form-data; boundary={_B}"
    with pytest.raises(MultipartError, match="more parts than the limit"):
        parse_multipart_form(ct, body, max_file_bytes=1024)
    peak = _peak_allocated(lambda: parse_multipart_form(ct, body, max_file_bytes=1024))
    assert peak < _BIG // 4, f"the refusal allocated {peak} bytes for a {len(body)}-byte body"


def test_an_oversized_field_refusal_copies_nothing_of_the_field() -> None:
    """The field cap is checked on the part's length, before any of its content is copied."""
    body = _body([_FILE_PART, _field("note", b"x" * _BIG)])
    ct = f"multipart/form-data; boundary={_B}"
    with pytest.raises(MultipartTooLargeError):
        parse_multipart_form(ct, body, max_file_bytes=1024)
    peak = _peak_allocated(lambda: parse_multipart_form(ct, body, max_file_bytes=1024))
    assert peak < _BIG // 4, f"the refusal allocated {peak} bytes for a {len(body)}-byte body"


def test_a_trailing_delimiter_line_without_a_close_marker_is_refused() -> None:
    """#5520 item 22: a body at the part cap that ends with a delimiter line but no ``--`` close
    marker is not over the cap, since that last line has no part after it to count. Since BACKLOG
    #5787 it is refused for the missing close marker instead, not for the part count."""
    delim = f"--{_B}".encode()
    body = b"".join(delim + b"\r\n" + p + b"\r\n" for p in _parts(multipart._MAX_PARTS))
    with pytest.raises(MultipartError, match="no closing boundary delimiter"):
        parse_multipart_form(
            f"multipart/form-data; boundary={_B}", body + delim + b"\r\n", max_file_bytes=1024
        )


_TRUNCATED_HL7 = b"MSH|^~\\&|A|B|C|D|202601010000||ADT^A01|X1|P|2.5\rPID|1||MR"


@pytest.mark.parametrize(
    "tail",
    [b"", b"\r\n", f"\r\n--{_B}".encode(), f"\r\n--{_B}\r\n".encode()],
    ids=["mid-content", "after-crlf", "delimiter-no-close", "delimiter-line-no-close"],
)
def test_a_body_cut_short_of_its_closing_delimiter_is_refused(tail: bytes) -> None:
    """BACKLOG #5787: a truncated upload has no closing delimiter, and its last part used to be
    kept as if whole. Each cut point is refused rather than ingested."""
    head = f"--{_B}\r\n".encode() + _FILE_PART_HEAD + _TRUNCATED_HL7
    with pytest.raises(MultipartError, match="no closing boundary delimiter") as caught:
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", head + tail, max_file_bytes=1024
        )
    assert type(caught.value) is MultipartError  # 400, not 413


@pytest.mark.parametrize(
    "body",
    [b"", _body([_FILE_PART]).replace(_B.encode(), b"OtherBoundary")],
    ids=["empty", "other"],
)
def test_a_body_with_no_matching_delimiter_is_refused_naming_the_boundary(body: bytes) -> None:
    """A body with no delimiter for the Content-Type's boundary is refused for that, not as a
    truncated upload, which would send the operator after the network rather than the client."""
    with pytest.raises(MultipartError, match="no boundary delimiter matching its Content-Type"):
        parse_multipart_form(f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024)


def test_a_line_that_only_starts_with_the_boundary_is_content() -> None:
    """BACKLOG #5787: a delimiter is the boundary alone on its line, or the close marker. A content
    line that merely starts with the boundary text used to split the file part, cutting it short
    while the body still closed, so the cut file was kept as if whole."""
    content = f"line1\r\n--{_B}x more\r\n--{_B}\tpadded-not\r\nend".encode()
    body = _body([_FILE_PART_HEAD + content])
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024
    )
    assert file.data == content


@pytest.mark.parametrize(
    "after_close", [b"", b"\r", b" \t", b"epilogue", b"\r\nepilogue"], ids=repr
)
def test_a_close_marker_followed_by_anything_closes_the_body(after_close: bytes) -> None:
    """RFC 2046 makes everything after the close delimiter an ignorable epilogue, so ``--B--``
    closes the body whatever follows it, as on main before BACKLOG #5787."""
    body = f"--{_B}\r\n".encode() + _FILE_PART + f"\r\n--{_B}--".encode() + after_close
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024
    )
    assert file.data == b"MSH|body"


def test_a_long_padding_run_after_a_boundary_is_scanned_once() -> None:
    """A backtracking padding match gave a 25 MiB run of spaces back one byte at a time on a
    failed match, about 0.3 s with the GIL held. The possessive match scans it once."""
    content = b"a\r\n--" + _B.encode() + b" " * (25 * 1024 * 1024) + b"x"
    body = _body([_FILE_PART_HEAD + content])
    started = time.perf_counter()
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", body, max_file_bytes=len(body)
    )
    elapsed = time.perf_counter() - started
    assert file.data == content
    assert elapsed < 0.1, f"the parse took {elapsed:.3f} s"


def test_transport_padding_after_a_delimiter_still_delimits() -> None:
    """Control: RFC 2046 lets spaces or tabs follow the boundary on its line."""
    body = f"--{_B} \t\r\n".encode() + _FILE_PART + f"\r\n--{_B}--\r\n".encode()
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024
    )
    assert file.filename == "a.hl7"


def test_boundary_text_inside_a_line_is_content_not_a_split() -> None:
    """BACKLOG #5787: a delimiter starts a line (RFC 2046). The same text later in a line is part
    content, so it neither splits the part nor closes the body early."""
    content = f"OBX|1|TX|||see --{_B}-- and --{_B}\rNTE|1|tail".encode()
    body = _body([_FILE_PART_HEAD + content])
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024
    )
    assert file.data == content


def test_a_bare_lf_client_and_a_preamble_still_parse() -> None:
    """Control for the line anchor: a delimiter after a bare LF, and one after a preamble line,
    are still found, as before."""
    body = (
        b"preamble\r\n"
        + f"--{_B}\n".encode()
        + _FILE_PART_HEAD
        + b"MSH|body\n"
        + f"--{_B}--\n".encode()
    )
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024
    )
    assert file.data == b"MSH|body\n"  # only a CRLF before the delimiter is trimmed, as before


def test_a_part_with_neither_name_nor_filename_is_bounded_too() -> None:
    """#5520 item 23: the field cap applies to every non-file part. A part with neither ``name=``
    nor ``filename=`` used to be copied whole and then skipped, bounded only by the body cap."""
    nameless = b"Content-Disposition: form-data\r\n\r\n" + b"x" * (multipart._MAX_FIELD_BYTES + 1)
    with pytest.raises(MultipartTooLargeError, match="text field"):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}",
            _body([_FILE_PART, nameless]),
            max_file_bytes=1024,
        )
    under = b"Content-Disposition: form-data\r\n\r\n" + b"x" * multipart._MAX_FIELD_BYTES
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", _body([_FILE_PART, under]), max_file_bytes=1024
    )
    assert file.data == b"MSH|body"


def test_a_file_sent_as_a_plain_field_names_the_cause_at_any_size() -> None:
    """#5520 item 25, its message half: under the field cap, the "no file part" refusal now gives the
    same hint the over-cap refusal gives, so the client hears the cause either way."""
    with pytest.raises(MultipartError, match="no file part.*plain filename parameter"):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}",
            _body([_field("file", b"MSH|body")]),
            max_file_bytes=1024,
        )


def test_a_second_file_part_is_refused() -> None:
    """#5520 item 9: the single-file parse used to admit up to ``_MAX_PARTS`` file parts and return
    the first, dropping the rest unread. A body with two is refused with the 400 base error."""
    with pytest.raises(MultipartError, match="2 file parts") as caught:
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}",
            _body([_FILE_PART, _FILE_PART]),
            max_file_bytes=1024,
        )
    assert type(caught.value) is MultipartError


def test_the_single_file_parse_does_not_decode_text_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """#5520 item 33: the single-file parse keeps no field, so it builds no ``MultipartForm`` and
    decodes no field value."""

    def no_form(*args: object, **kwargs: object) -> MultipartForm:
        raise AssertionError("the single-file parse built a whole form")

    monkeypatch.setattr(multipart, "parse_multipart_form", no_form)
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}",
        _body([_FILE_PART, _field("note", b"v")]),
        max_file_bytes=1024,
    )
    assert file.data == b"MSH|body"


_PROBE: contextvars.ContextVar[str] = contextvars.ContextVar("multipart_probe", default="unset")


async def test_the_off_loop_parse_carries_the_callers_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#5520 item 26: ``run_in_executor`` alone runs the parse with an empty context, unlike
    ``asyncio.to_thread``. The parse must see the caller's context variables."""
    real = multipart.parse_single_file_upload
    seen: list[str] = []

    def parse(*args: Any, **kwargs: Any) -> FilePart:
        seen.append(_PROBE.get())
        return real(*args, **kwargs)

    monkeypatch.setattr(multipart, "parse_single_file_upload", parse)
    token = _PROBE.set("caller")
    try:
        file = await multipart.parse_upload_off_loop(
            f"multipart/form-data; boundary={_B}", _body([_FILE_PART]), max_file_bytes=1024
        )
    finally:
        _PROBE.reset(token)
    assert file.data == b"MSH|body"
    assert seen == ["caller"]


async def test_a_cancelled_queued_parse_lets_go_of_its_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#5520 item 24: a request cancelled while its parse waits for a worker must not leave its body
    referenced by the work item queued on the executor until a worker reaches it. Both workers are
    held busy, a third parse is queued and cancelled, and the body's reference count must fall back
    to what this test alone holds."""
    real = multipart.parse_single_file_upload
    release = threading.Event()
    started = threading.Semaphore(0)

    def blocking(*args: Any, **kwargs: Any) -> FilePart:
        started.release()
        release.wait(timeout=30)
        return real(*args, **kwargs)

    monkeypatch.setattr(multipart, "parse_single_file_upload", blocking)
    ct = f"multipart/form-data; boundary={_B}"
    busy = [
        asyncio.ensure_future(
            multipart.parse_upload_off_loop(ct, _body([_FILE_PART]), max_file_bytes=1024)
        )
        for _ in range(2)
    ]
    try:
        for _ in range(2):
            assert await asyncio.to_thread(started.acquire, True, 10), "a worker never started"
        body = _body([_FILE_PART]) + b"unique"
        base = sys.getrefcount(body)
        queued = asyncio.ensure_future(
            multipart.parse_upload_off_loop(ct, body, max_file_bytes=1024)
        )
        await asyncio.sleep(0.05)
        queued.cancel()
        # Waited on rather than awaited: an awaited CancelledError's traceback would keep the
        # parse's frame, and so the body, alive in this test's own frame.
        await asyncio.wait([queued])
        assert queued.cancelled()
        del queued
        gc.collect()
        assert sys.getrefcount(body) == base, "the queued work item still holds the body"
    finally:
        release.set()
        await asyncio.gather(*busy)


def test_an_unterminated_body_over_the_part_cap_is_refused() -> None:
    """With no closing delimiter, a body of ``_MAX_PARTS + 1`` parts is still over the cap. The
    count must not assume a terminator segment is there to absorb one split."""
    delim = f"--{_B}".encode()
    body = b"".join(delim + b"\r\n" + p + b"\r\n" for p in _parts(multipart._MAX_PARTS + 1))
    with pytest.raises(MultipartError, match="more parts than the limit"):
        parse_multipart_form(f"multipart/form-data; boundary={_B}", body, max_file_bytes=1024)


def test_an_epilogue_after_the_terminator_does_not_count_as_parts() -> None:
    """RFC 2046 makes everything after the closing delimiter an ignorable epilogue, so delimiter
    text there is not a part. A well-formed one-file body with such an epilogue still parses."""
    epilogue = (f"--{_B}\r\n".encode()) * (multipart._MAX_PARTS * 2)
    file = parse_single_file_upload(
        f"multipart/form-data; boundary={_B}", _body([_FILE_PART]) + epilogue, max_file_bytes=1024
    )
    assert file.data == b"MSH|body"


def test_a_body_at_the_part_cap_still_parses() -> None:
    """Positive control for the cap: exactly ``_MAX_PARTS`` parts is admitted, so the count includes
    the closing delimiter correctly and the refusal is not off by one."""
    form = parse_multipart_form(
        f"multipart/form-data; boundary={_B}",
        _body(_parts(multipart._MAX_PARTS)),
        max_file_bytes=1024,
    )
    assert len(form.files) == 1
    assert len(form.fields) == multipart._MAX_PARTS - 1


def test_an_oversized_text_field_is_refused_as_too_large() -> None:
    """A non-file field past ``_MAX_FIELD_BYTES`` is refused with the 413 subclass. Before the cap a
    text field was bounded only by the body cap and decoded whole into a ``str``."""
    big = _field("note", b"x" * (multipart._MAX_FIELD_BYTES + 1))
    with pytest.raises(MultipartTooLargeError, match="text field .* plain filename parameter"):
        parse_single_file_upload(
            f"multipart/form-data; boundary={_B}", _body([_FILE_PART, big]), max_file_bytes=1024
        )


def test_a_text_field_at_the_cap_still_parses() -> None:
    """Positive control: a field of exactly ``_MAX_FIELD_BYTES`` is kept, decoded, beside the file."""
    value = b"x" * multipart._MAX_FIELD_BYTES
    form = parse_multipart_form(
        f"multipart/form-data; boundary={_B}",
        _body([_FILE_PART, _field("note", value)]),
        max_file_bytes=1024,
    )
    assert form.fields["note"] == value.decode()


def test_many_lines_that_only_start_with_the_boundary_are_refused() -> None:
    """Each such content line costs a find, so the walk refuses a run longer than the part cap
    rather than walking a body full of them; a run at the cap is still content."""
    ct = f"multipart/form-data; boundary={_B}"
    lines = f"\r\n--{_B}x".encode()
    at_cap = _body([_FILE_PART_HEAD + b"a" + lines * multipart._MAX_PARTS])
    assert parse_single_file_upload(ct, at_cap, max_file_bytes=4096).data.startswith(b"a\r\n")
    over = _body([_FILE_PART_HEAD + b"a" + lines * (multipart._MAX_PARTS + 1)])
    with pytest.raises(
        MultipartError, match="lines between two delimiters that start with the boundary"
    ):
        parse_single_file_upload(ct, over, max_file_bytes=4096)
