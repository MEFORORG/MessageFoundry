# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Stdlib multipart/form-data parser for uploaded logs (ADR 0134) — no python-multipart."""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import gc
import hashlib
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


_FILE_PART = b'Content-Disposition: form-data; name="file"; filename="a.hl7"\r\n\r\nMSH|body'


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
    """#5520 item 22, revised by #5787: a body at the part cap that ends with a delimiter line but no
    ``--`` close marker used to parse. That last line is still not counted as a part, so the refusal
    is for the missing terminator, not the part cap; with the close marker the same body parses."""
    delim = f"--{_B}".encode()
    body = b"".join(delim + b"\r\n" + p + b"\r\n" for p in _parts(multipart._MAX_PARTS))
    with pytest.raises(MultipartError, match="no closing boundary delimiter"):
        parse_multipart_form(
            f"multipart/form-data; boundary={_B}", body + delim + b"\r\n", max_file_bytes=1024
        )
    form = parse_multipart_form(
        f"multipart/form-data; boundary={_B}", body + delim + b"--\r\n", max_file_bytes=1024
    )
    assert len(form.files) == 1
    assert len(form.fields) == multipart._MAX_PARTS - 1


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


# --- BACKLOG #5787: a body with no closing delimiter is refused -----------------------------------
#
# The first half refuses a body with no closing delimiter. The second half counts a delimiter after
# the first only at a line start (multipart._LineStartDelimiters). The differential arm below pins
# what both halves leave alone: every body in the corpus that carries close-marker text must parse
# exactly as origin/main parsed it, outcome for outcome, except the rows _ANCHORED_OUTCOMES names.
# The outcomes were recorded by running origin/main's parser (at ec75a5f61bf) over this same corpus,
# so a change that moves any other row, accept or refuse, shows here. The record says what main did,
# not that each outcome is right.

_CT_B = "multipart/form-data; boundary=B"
_CT_WK = f"multipart/form-data; boundary={_B}"
_FP = b'Content-Disposition: form-data; name="file"; filename="a.hl7"\r\n\r\n'


def _corpus() -> list[tuple[str, str, bytes]]:
    """(id, Content-Type, body). Edge shapes, then the test_multipart bodies. Only the rows
    _ANCHORED_OUTCOMES names may move from origin/main's outcome."""
    cap = multipart._MAX_FIELD_BYTES
    return [
        ("plain", _CT_B, b"--B\r\n" + _FP + b"MSH|x\r\n--B--\r\n"),
        ("delim-cr-run", _CT_B, b"--B\r\r\n" + _FP + b"MSH|x\r\n--B--\r\n"),
        ("delim-lf-only", _CT_B, b"--B\n" + _FP + b"MSH|x\r\n--B--\r\n"),
        ("delim-crlf-run", _CT_B, b"--B\r\n\r\n\r\n" + _FP + b"MSH|x\r\n--B--\r\n"),
        ("close-after-bare-cr", _CT_B, b"--B\r\n" + _FP + b"MSH|x\r--B--"),
        ("close-no-newline", _CT_B, b"--B\r\n" + _FP + b"MSH|x\r\n--B--"),
        ("close-then-cr", _CT_B, b"--B\r\n" + _FP + b"MSH|x\r\n--B--\r"),
        ("close-then-epilogue", _CT_B, b"--B\r\n" + _FP + b"MSH|x\r\n--B--epilogue"),
        ("close-then-padding", _CT_B, b"--B\r\n" + _FP + b"MSH|x\r\n--B--  \t\r\n"),
        ("delim-padding", _CT_B, b"--B  \t\r\n" + _FP + b"MSH|x\r\n--B--\r\n"),
        ("preamble", _CT_B, b"preamble text\r\n--B\r\n" + _FP + b"MSH|x\r\n--B--\r\n"),
        ("mid-line-delim", _CT_B, b"--B\r\n" + _FP + b"MSH|x--B\r\n" + _FP + b"y\r\n--B--\r\n"),
        ("mid-line-close", _CT_B, b"--B\r\n" + _FP + b"MSH|x--B--trailing"),
        ("close-only", _CT_B, b"--B--\r\n"),
        ("close-in-preamble", _CT_B, b"pre --B-- post"),
        ("empty-part-then-close", _CT_B, b"--B\r\n--B--\r\n"),
        ("no-header-part", _CT_B, b"--B\r\nnoheader\r\n--B\r\n" + _FP + b"z\r\n--B--\r\n"),
        ("two-files", _CT_B, b"--B\r\n" + _FP + b"1\r\n--B\r\n" + _FP + b"2\r\n--B--\r\n"),
        ("field-only", _CT_B, b"--B\r\n" + _field("note", b"v") + b"\r\n--B--\r\n"),
        ("file-too-large", _CT_B, b"--B\r\n" + _FP + b"x" * 2000 + b"\r\n--B--\r\n"),
        ("not-multipart", "application/json", b"--B\r\n" + _FP + b"MSH|x\r\n--B--\r\n"),
        ("wk-single-file", _CT_WK, _body([_FILE_PART])),
        ("wk-file-and-field", _CT_WK, _body([_FILE_PART, _field("content_type", b"hl7v2")])),
        ("wk-no-file", _CT_WK, _body([_field("just_a_field", b"value")])),
        ("wk-at-part-cap", _CT_WK, _body(_parts(multipart._MAX_PARTS))),
        ("wk-over-part-cap", _CT_WK, _body(_parts(multipart._MAX_PARTS + 1))),
        ("wk-field-at-cap", _CT_WK, _body([_FILE_PART, _field("note", b"x" * cap)])),
        ("wk-field-over-cap", _CT_WK, _body([_FILE_PART, _field("note", b"x" * (cap + 1))])),
        ("wk-noheader-at-cap", _CT_WK, _body([_FILE_PART, b"x" * cap])),
        ("wk-noheader-over-cap", _CT_WK, _body([_FILE_PART, b"x" * (cap + 1)])),
        (
            "wk-header-over-cap",
            _CT_WK,
            _body([b"X-Pad: " + b"a" * _MAX_PART_HEADER_BYTES + b"\r\n" + _FILE_PART]),
        ),
        (
            "wk-epilogue-delims",
            _CT_WK,
            _body([_FILE_PART]) + (f"--{_B}\r\n".encode()) * (multipart._MAX_PARTS * 2),
        ),
    ]


def _outcome(content_type: str, body: bytes) -> tuple[Any, ...]:
    """What ``parse_multipart_form`` makes of a body, in a form that compares by value."""
    try:
        form = parse_multipart_form(content_type, body, max_file_bytes=1024)
    except MultipartError as exc:
        return ("refused", type(exc).__name__, str(exc))
    return (
        "parsed",
        [(f.name, f.filename, _digest(f.data)) for f in form.files],
        [(name, _digest(value.encode())) for name, value in sorted(form.fields.items())],
    )


def _digest(value: bytes) -> bytes | tuple[int, str]:
    """A short value as itself; a long one as its length and SHA-256, to keep the record readable."""
    return value if len(value) <= 64 else (len(value), hashlib.sha256(value).hexdigest())


#: origin/main's outcome for each corpus body, recorded at ec75a5f61bf. Every body here carries
#: close-marker text; #5787 leaves each one as it was, except the rows _ANCHORED_OUTCOMES names.
_MAIN_OUTCOMES: dict[str, tuple[Any, ...]] = {
    "plain": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "delim-cr-run": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "delim-lf-only": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "delim-crlf-run": ("parsed", [], []),
    "close-after-bare-cr": ("parsed", [("file", "a.hl7", b"MSH|x\r")], []),
    "close-no-newline": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "close-then-cr": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "close-then-epilogue": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "close-then-padding": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "delim-padding": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "preamble": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "mid-line-delim": ("parsed", [("file", "a.hl7", b"MSH|x"), ("file", "a.hl7", b"y")], []),
    "mid-line-close": ("parsed", [("file", "a.hl7", b"MSH|x")], []),
    "close-only": ("parsed", [], []),
    "close-in-preamble": ("parsed", [], []),
    "empty-part-then-close": ("parsed", [], []),
    "no-header-part": ("parsed", [("file", "a.hl7", b"z")], []),
    "two-files": ("parsed", [("file", "a.hl7", b"1"), ("file", "a.hl7", b"2")], []),
    "field-only": ("parsed", [], [("note", b"v")]),
    "file-too-large": (
        "refused",
        "MultipartTooLargeError",
        "uploaded file part is 2000 bytes; the limit is 1024",
    ),
    "not-multipart": (
        "refused",
        "MultipartError",
        "Content-Type is not multipart/form-data with a boundary",
    ),
    "wk-single-file": ("parsed", [("file", "a.hl7", b"MSH|body")], []),
    "wk-file-and-field": ("parsed", [("file", "a.hl7", b"MSH|body")], [("content_type", b"hl7v2")]),
    "wk-no-file": ("parsed", [], [("just_a_field", b"value")]),
    "wk-at-part-cap": (
        "parsed",
        [("file", "a.hl7", b"MSH|body")],
        [
            ("f0", b"v"),
            ("f1", b"v"),
            ("f10", b"v"),
            ("f11", b"v"),
            ("f12", b"v"),
            ("f13", b"v"),
            ("f14", b"v"),
            ("f2", b"v"),
            ("f3", b"v"),
            ("f4", b"v"),
            ("f5", b"v"),
            ("f6", b"v"),
            ("f7", b"v"),
            ("f8", b"v"),
            ("f9", b"v"),
        ],
    ),
    "wk-over-part-cap": (
        "refused",
        "MultipartError",
        "multipart body has more parts than the limit of 16",
    ),
    "wk-field-at-cap": (
        "parsed",
        [("file", "a.hl7", b"MSH|body")],
        [("note", (16384, "1536c422c31cc98834759d7085cda394a3510a03d78188248986a6b1a7207d03"))],
    ),
    "wk-field-over-cap": (
        "refused",
        "MultipartTooLargeError",
        'multipart text field is 16385 bytes; the limit is 16384. Send a file as a file part with a plain filename parameter (filename="...")',
    ),
    "wk-noheader-at-cap": ("parsed", [("file", "a.hl7", b"MSH|body")], []),
    "wk-noheader-over-cap": (
        "refused",
        "MultipartError",
        "multipart part of 16385 bytes has no header block ended by a blank CRLF line; a part without one is skipped only up to 16384 bytes",
    ),
    "wk-header-over-cap": (
        "refused",
        "MultipartError",
        "multipart part header block is 16454 bytes; the limit is 16384",
    ),
    "wk-epilogue-delims": ("parsed", [("file", "a.hl7", b"MSH|body")], []),
}

#: The rows the line-start anchor moves (the second half of #5787): each holds delimiter text in the
#: middle of a line, which is now part content rather than a delimiter.
_ANCHORED_OUTCOMES: dict[str, tuple[Any, ...]] = {
    # The mid-line ``--B`` stays inside the one file instead of splitting it in two.
    "mid-line-delim": ("parsed", [("file", "a.hl7", _digest(b"MSH|x--B\r\n" + _FP + b"y"))], []),
    # The only close marker is mid-line, so the body has none.
    "mid-line-close": (
        "refused",
        "MultipartError",
        "multipart body has no closing boundary delimiter; the upload may be truncated",
    ),
}


_CORPUS = _corpus()
_MULTIPART_CORPUS = [c for c in _CORPUS if c[1] != "application/json"]


def _close_marker(content_type: str) -> bytes:
    boundary = parse_boundary(content_type) or b"B"
    return b"--" + boundary + b"--"


@pytest.mark.parametrize(("case", "content_type", "body"), _CORPUS, ids=[c[0] for c in _CORPUS])
def test_a_body_with_a_close_marker_parses_as_main_did_unless_listed(
    case: str, content_type: str, body: bytes
) -> None:
    """#5787 differential arm: neither half moves a corpus body, whatever its shape (a CR run after a
    delimiter, a close marker after a bare CR, anything after the close marker, a preamble ending
    mid-line), except the rows holding delimiter text mid-line after the first delimiter. Those
    move to _ANCHORED_OUTCOMES, and each of those differs from main. It pins ``parse_multipart_form``; ``parse_single_file_upload``
    shares the same walk and terminator check."""
    # Close-marker text, not a line-start close: the rows _ANCHORED_OUTCOMES names hold it mid-line.
    assert _close_marker(content_type) in body, "every corpus body holds close-marker text"
    if case in _ANCHORED_OUTCOMES:
        assert _ANCHORED_OUTCOMES[case] != _MAIN_OUTCOMES[case]
        assert _outcome(content_type, body) == _ANCHORED_OUTCOMES[case]
    else:
        assert _outcome(content_type, body) == _MAIN_OUTCOMES[case]


def test_the_recorded_outcomes_cover_the_whole_corpus() -> None:
    """The record and the corpus must name the same bodies, or a body could go uncompared."""
    assert [case for case, _, _ in _CORPUS] == list(_MAIN_OUTCOMES)
    assert set(_ANCHORED_OUTCOMES) <= set(_MAIN_OUTCOMES)


@pytest.mark.parametrize(
    ("case", "content_type", "body"),
    _MULTIPART_CORPUS,
    ids=[c[0] for c in _MULTIPART_CORPUS],
)
def test_the_same_body_without_its_close_marker_is_refused(
    case: str, content_type: str, body: bytes
) -> None:
    """#5787: each corpus body with its close marker turned into a plain delimiter is refused. A body
    origin/main parsed is refused for the missing terminator (or, for the epilogue body, for the part
    cap, since the walk now runs on into the delimiter text that sat after the close marker). A body
    main refused keeps main's refusal from ``parse_multipart_form``, class and all, because the
    terminator check runs last. (``parse_single_file_upload`` refuses a no-file or two-file body
    after the walk, so an unterminated one of those now gets the terminator refusal there.) A row
    the line-start anchor moved to a refusal keeps that refusal; for those rows this arm is no
    control of the terminator check, since the terminated body is refused the same way."""
    marker = _close_marker(content_type)
    unterminated = body.replace(marker, marker[:-2])
    assert marker not in unterminated
    with pytest.raises(MultipartError) as caught:
        parse_multipart_form(content_type, unterminated, max_file_bytes=1024)
    main = _ANCHORED_OUTCOMES.get(case, _MAIN_OUTCOMES[case])
    if main[0] == "refused":
        assert (type(caught.value).__name__, str(caught.value)) == main[1:]
    elif case == "wk-epilogue-delims":
        assert "more parts than the limit" in str(caught.value)
    else:
        assert "no closing boundary delimiter" in str(caught.value)
        assert type(caught.value) is MultipartError  # 400: the body is malformed, not too large


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        (_CT_B, b""),
        (_CT_B, b"no delimiter here"),
        ("multipart/form-data; boundary=Y", b"--B\r\n" + _FP + b"MSH|x\r\n--B--\r\n"),
    ],
    ids=["empty", "no-delimiter", "other-boundary"],
)
def test_a_body_with_no_delimiter_at_all_is_not_called_truncated(
    content_type: str, body: bytes
) -> None:
    """#5787: a body holding no delimiter for the declared boundary (an empty one, or one built with
    another boundary) is refused, and the refusal does not send the client looking for a truncation."""
    with pytest.raises(MultipartError, match="no delimiter for the boundary") as caught:
        parse_multipart_form(content_type, body, max_file_bytes=1024)
    assert type(caught.value) is MultipartError
    with pytest.raises(MultipartError, match="no delimiter for the boundary"):
        parse_single_file_upload(content_type, body, max_file_bytes=1024)


_TAIL = len(f"\r\n--{_B}--\r\n")


@pytest.mark.parametrize("cut", [3, 4, 7, 12, 30, _TAIL, _TAIL + 3, _TAIL + 10])
def test_a_truncated_upload_is_refused_not_ingested(cut: int) -> None:
    """#5787: an upload cut short before its close marker is complete was taken as a whole file of
    whatever bytes arrived. It is refused now, by both entry points, whether the cut falls in the
    close marker or in the file's own bytes (the last cuts lose ``MRN`` and more)."""
    body = _body([_FILE_PART + b"\r\nPID|1||MRN"])
    truncated = body[:-cut]
    assert f"--{_B}--".encode() not in truncated
    for parse in (parse_multipart_form, parse_single_file_upload):
        with pytest.raises(MultipartError, match="no closing boundary delimiter"):
            parse(_CT_WK, truncated, max_file_bytes=1024)
    # Positive control: the whole body parses.
    assert parse_single_file_upload(_CT_WK, body, max_file_bytes=1024).data.endswith(b"MRN")


@pytest.mark.parametrize("cut", [1, 2])
def test_a_cut_that_leaves_the_close_marker_whole_still_parses(cut: int) -> None:
    """Losing only the CRLF after ``--boundary--`` leaves the close marker whole, so the body parses
    as it did before #5787."""
    body = _body([_FILE_PART + b"\r\nPID|1||MRN"])
    file = parse_single_file_upload(_CT_WK, body[:-cut], max_file_bytes=1024)
    assert file.data == b"MSH|body\r\nPID|1||MRN"


# --- BACKLOG #5787, second half: a delimiter counts only at a line start --------------------------


@pytest.mark.parametrize("cut", [1, 5, 12])
def test_a_truncated_upload_whose_content_holds_the_close_marker_mid_line_is_refused(
    cut: int,
) -> None:
    """A cut-short body whose file content holds ``--<boundary>--`` in the middle of a line was taken
    as complete on origin/main, ending at that text. It is refused now, by both entry points."""
    marker = f"--{_B}--".encode()
    body = _body([_FILE_PART + b"\r\nOBX|1|TX|||quoted " + marker + b" text\r\nPID|1||MRN"])
    truncated = body[: -(_TAIL + cut)]
    assert marker in truncated
    for parse in (parse_multipart_form, parse_single_file_upload):
        with pytest.raises(MultipartError, match="no closing boundary delimiter"):
            parse(_CT_WK, truncated, max_file_bytes=1024)
    # Positive control: the whole body parses, and the mid-line text stays in the file.
    whole = parse_single_file_upload(_CT_WK, body, max_file_bytes=1024).data
    assert marker in whole
    assert whole.endswith(b"PID|1||MRN")


def test_delimiter_text_mid_line_stays_inside_the_file() -> None:
    """``--<boundary>`` in the middle of a content line is content. origin/main split the file there
    and returned only its first piece."""
    content = b"MSH|body\r\nNTE|1||see --" + _B.encode() + b"\r\nPID|1||MRN"
    got = parse_single_file_upload(
        _CT_WK, _body([_FILE_PART[: -len(b"MSH|body")] + content]), max_file_bytes=1024
    )
    assert got.data == content


@pytest.mark.parametrize(
    "prefix",
    [b"", b"pre\r\n", b"pre\n", b"pre\r", b"\n", b"\r", b" ", b"\xef\xbb\xbf", b"pre"],
    ids=["start", "crlf", "lf", "bare-cr", "lone-lf", "lone-cr", "space", "bom", "mid-line"],
)
def test_the_first_delimiter_counts_wherever_it_sits(prefix: bytes) -> None:
    """The first delimiter is the first ``--<boundary>`` anywhere, as on origin/main, so a stray
    byte or a preamble ending mid-line before it does not turn the first part into preamble."""
    body = prefix + b"--B\r\n" + _FP + b"MSH|x\r\n--B--\r\n"
    assert parse_single_file_upload(_CT_B, body, max_file_bytes=1024).data == b"MSH|x"


def test_a_preamble_ending_mid_line_keeps_both_file_parts() -> None:
    """origin/main refused this body for its two file parts; it still does, rather than dropping
    the first one as preamble."""
    body = b"pre--B\r\n" + _FP + b"A\r\n--B\r\n" + _FP + b"B\r\n--B--"
    with pytest.raises(MultipartError, match="2 file parts"):
        parse_single_file_upload(_CT_B, body, max_file_bytes=1024)


@pytest.mark.parametrize(("body", "at", "expected"), [(b"x\n--B", 2, 2), (b"x\r--B", 2, 2)])
def test_a_later_delimiter_right_at_the_search_offset_is_found(
    body: bytes, at: int, expected: int
) -> None:
    """The cursor search starts one byte before ``at``, where the line end of a delimiter at ``at``
    sits."""
    assert multipart._LineStartDelimiters(body, b"--B").find(at) == expected


def test_the_delimiter_search_refuses_to_go_back() -> None:
    """The cursors keep state, so a smaller offset than the last one would skip delimiters."""
    delims = multipart._LineStartDelimiters(b"--B\r\nx\r\n--B\r\ny\r\n--B--", b"--B")
    assert delims.find(5) == 8
    with pytest.raises(RuntimeError):
        delims.find(4)


def test_delimiters_after_mixed_line_ends_are_each_found_in_order() -> None:
    """Delimiters after CR and after LF, interleaved, with mid-line delimiter text between them:
    each cursor keeps a hit the other one beat and hands it back on a later call."""
    fields = [
        b"--B\r\n" + _field("a", b"1 --B mid") + b"\r",
        b"--B\r\n" + _field("b", b"2") + b"\n",
        b"--B\r\n" + _field("c", b"3 --B--") + b"\r",
        b"--B\r\n" + _field("d", b"4") + b"\r\n",
        b"--B--\r\n",
    ]
    form = parse_multipart_form(_CT_B, b"".join(fields), max_file_bytes=1024)
    # The line end before a delimiter stays in the content unless it is a CRLF, as on origin/main.
    assert form.fields == {"a": "1 --B mid\r", "b": "2\n", "c": "3 --B--\r", "d": "4"}


def _python_lines(run: Callable[[], object]) -> int:
    """How many Python lines ``run`` executes, in any file, by ``sys.settrace``. Every file, so a
    per-occurrence loop counts wherever it is written."""
    count = 0

    def trace(frame: Any, event: str, arg: Any) -> Any:
        nonlocal count
        if event == "line":
            count += 1
        return trace

    # A collection during the run would trace any Python finalizer it calls; keep it out.
    gc.collect()
    gc.disable()
    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        run()
    finally:
        sys.settrace(previous)
        gc.enable()
    return count


def test_mid_line_delimiter_text_is_skipped_without_a_python_step_per_occurrence() -> None:
    """A file holding the delimiter text mid-line many times costs the walk no more Python lines
    than a file holding it once: each cursor moves forward only, so the skip runs in C."""

    def lines(occurrences: int) -> int:
        content = b"x--B" * occurrences
        body = b"--B\r\n" + _FP + content + b"\r\n--B--\r\n"

        def run() -> None:
            assert (
                parse_single_file_upload(_CT_B, body, max_file_bytes=len(content)).data == content
            )

        return _python_lines(run)

    once, many = lines(1), lines(100_000)
    assert once > 0  # the instrument sees the parse at all
    assert many == once, (once, many)
