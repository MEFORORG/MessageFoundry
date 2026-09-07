# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Stdlib multipart/form-data parser for uploaded logs (ADR 0134) — no python-multipart."""

from __future__ import annotations

import re
import time

import pytest

from messagefoundry.api import multipart
from messagefoundry.api.multipart import (
    _MAX_PART_HEADER_BYTES,
    MultipartError,
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

    The header block is attacker-supplied and ``parse_single_file_upload`` runs synchronously on the
    asyncio event loop, so a quadratic scan here is a whole-engine denial of service, not a slow
    request. ``_MAX_PART_HEADER_BYTES`` bounds the input as well, but the two controls are independent
    on purpose: the cap is a size policy someone could reasonably raise, while this bounds what the
    scan costs at the size the cap admits today.

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
        f"the hostile header cost {seconds:.4f}s of the event loop against a "
        f"{_SCAN_BUDGET_SECONDS}s budget"
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
    default, 512 MiB at the ceiling) on the asyncio event loop. A real client never approaches it: a
    Content-Disposition plus a Content-Type is a couple hundred bytes.

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
