# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Compression codec (ADR 0123) — pure gzip/zlib-deflate/zip.

Covers round-trips, the re-run-purity determinism guarantee (fixed gzip mtime / zip date), the
incremental decompression-bomb ceiling on every decompressor, corrupt/truncated rejection as
``CompressionError``, argument validation, and the top-level re-exports Handlers use.
"""

from __future__ import annotations

import gzip
import io
import os
import random
import threading
import time
import zipfile
import zlib
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, Literal

import pytest

from messagefoundry.parsing import compression
from messagefoundry.parsing._bounded_inflate import InflateResult
from messagefoundry.parsing.compression import (
    CompressionError,
    deflate_compress,
    deflate_decompress,
    gzip_compress,
    gzip_decompress,
    zip_compress,
    zip_decompress,
)
from messagefoundry.parsing.sniff import archive_member_name_reason

_BODY = b"MSH|^~\\&|SEND|FAC|RECV|FAC|20260717||ADT^A01|1|P|2.5\rPID|1||123^^^MRN\r" * 200


# --- gzip --------------------------------------------------------------------


def test_gzip_roundtrip() -> None:
    assert gzip_decompress(gzip_compress(_BODY), max_output_bytes=None) == _BODY


def test_gzip_compress_is_deterministic() -> None:
    # Re-run purity (CLAUDE.md §2): a gzipping Handler must produce identical bytes each run. Stock
    # gzip.compress embeds a wall-clock mtime; gzip_compress fixes mtime=0.
    first = gzip_compress(_BODY)
    time.sleep(1.1)  # cross a wall-clock second — mtime would differ if it were not fixed
    assert gzip_compress(_BODY) == first


def test_gzip_compress_omits_mtime_header() -> None:
    # The 4-byte little-endian mtime at header offset 4..8 must be zero.
    blob = gzip_compress(_BODY)
    assert blob[4:8] == b"\x00\x00\x00\x00"


def test_gzip_decompress_bomb_ceiling() -> None:
    # A tiny gzip of highly-compressible data expands hugely; the ceiling refuses it incrementally.
    bomb = gzip_compress(b"\x00" * (5 * 1024 * 1024))
    assert len(bomb) < 50_000  # small on the wire
    with pytest.raises(CompressionError, match="ceiling"):
        gzip_decompress(bomb, max_output_bytes=1024)


def test_gzip_decompress_at_ceiling_ok() -> None:
    payload = b"a" * 1000
    out = gzip_decompress(gzip_compress(payload), max_output_bytes=1000)
    assert out == payload


def test_gzip_multi_member() -> None:
    # Concatenated gzip members decode to the concatenation (GzipFile handles multi-member).
    concat = gzip_compress(b"AAA") + gzip_compress(b"BBB")
    assert gzip_decompress(concat, max_output_bytes=None) == b"AAABBB"


def test_gzip_decompress_rejects_corrupt() -> None:
    with pytest.raises(CompressionError):
        gzip_decompress(b"this is not a gzip stream", max_output_bytes=None)


def test_gzip_decompress_rejects_truncated() -> None:
    blob = gzip_compress(_BODY)
    with pytest.raises(CompressionError):
        gzip_decompress(blob[: len(blob) // 2], max_output_bytes=None)


# --- deflate -----------------------------------------------------------------


def test_deflate_roundtrip() -> None:
    assert deflate_decompress(deflate_compress(_BODY), max_output_bytes=None) == _BODY


def test_deflate_is_deterministic() -> None:
    assert deflate_compress(_BODY) == deflate_compress(_BODY)


def test_deflate_decompress_bomb_ceiling() -> None:
    bomb = deflate_compress(b"\x00" * (5 * 1024 * 1024))
    with pytest.raises(CompressionError, match="ceiling"):
        deflate_decompress(bomb, max_output_bytes=1024)


def test_deflate_decompress_rejects_corrupt() -> None:
    with pytest.raises(CompressionError):
        deflate_decompress(b"\xff\xff\xff\xff not deflate", max_output_bytes=None)


def test_deflate_decompress_rejects_truncated() -> None:
    blob = deflate_compress(_BODY)
    with pytest.raises(CompressionError):
        deflate_decompress(blob[:10], max_output_bytes=None)


# --- zip ---------------------------------------------------------------------


def test_zip_roundtrip_multi_entry() -> None:
    entries = {"a.hl7": _BODY, "sub/b.txt": b"hello"}
    out = zip_decompress(zip_compress(entries), max_output_bytes=None)
    assert out == entries


def test_zip_is_deterministic() -> None:
    entries = {"a.hl7": _BODY, "b.hl7": _BODY}
    assert zip_compress(entries) == zip_compress(entries)


def test_zip_decompress_total_ceiling() -> None:
    entries = {f"f{i}.dat": b"\x00" * 100_000 for i in range(4)}
    with pytest.raises(CompressionError, match="ceiling"):
        zip_decompress(zip_compress(entries), max_output_bytes=1000)


def test_zip_decompress_entry_cap() -> None:
    entries = {f"f{i}": b"x" for i in range(10)}
    with pytest.raises(CompressionError, match="member"):
        zip_decompress(zip_compress(entries), max_output_bytes=None, max_entries=3)


def test_zip_decompress_rejects_corrupt() -> None:
    with pytest.raises(CompressionError):
        zip_decompress(b"PK not really a zip", max_output_bytes=None)


# --- argument validation -----------------------------------------------------


@pytest.mark.parametrize("bad", [-1, 10, 1.5])
def test_compress_rejects_bad_level(bad: object) -> None:
    with pytest.raises(CompressionError, match="level"):
        gzip_compress(b"x", level=bad)  # type: ignore[arg-type]


def test_decompress_rejects_negative_ceiling() -> None:
    with pytest.raises(CompressionError, match="max_output_bytes"):
        gzip_decompress(gzip_compress(b"x"), max_output_bytes=-1)


def test_error_message_names_no_body() -> None:
    # PHI guard: the ceiling error names the codec and the byte cap only, never decompressed content.
    secret = b"PID|1||SSN-999-99-9999" * 5000
    try:
        gzip_decompress(gzip_compress(secret), max_output_bytes=100)
    except CompressionError as exc:
        assert b"SSN" not in str(exc).encode()
        assert "999-99" not in str(exc)
    else:  # pragma: no cover - the ceiling must fire
        raise AssertionError("expected CompressionError")


# --- re-exports --------------------------------------------------------------


def test_top_level_reexports() -> None:
    import messagefoundry as mf

    assert mf.gzip_compress is gzip_compress
    assert mf.gzip_decompress is gzip_decompress
    assert mf.CompressionError is CompressionError


def test_gzip_interops_with_stdlib() -> None:
    # gzip_compress output is a standard gzip stream stdlib gzip.decompress reads (and vice-versa).
    assert gzip.decompress(gzip_compress(_BODY)) == _BODY
    assert gzip_decompress(gzip.compress(_BODY), max_output_bytes=None) == _BODY


# --- #1237: the ceiling is REQUIRED, not merely defaulted ---------------------


@pytest.mark.parametrize(
    "fn, arg",
    [
        (gzip_decompress, b""),
        (deflate_decompress, b""),
        (zip_decompress, b""),
    ],
)
def test_ceiling_has_no_default(fn: object, arg: bytes) -> None:  # #1237
    """Calling a decompressor without ``max_output_bytes`` is a TypeError, not an unbounded read.

    Asserted on the SIGNATURE as well as the call, because the call alone is a weak pin: these
    functions raise ``CompressionError`` on malformed input, so a bare ``pytest.raises`` could pass
    for the wrong reason if the parameter were ever given a default back. Checking that the parameter
    has *no default* is what actually discriminates.
    """
    import inspect

    param = inspect.signature(fn).parameters["max_output_bytes"]  # type: ignore[arg-type]
    assert param.default is inspect.Parameter.empty, "max_output_bytes must have NO default (#1237)"
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
    with pytest.raises(TypeError):
        fn(arg)  # type: ignore[operator]


def test_explicit_none_still_means_unbounded() -> None:  # #1237
    # The opt-out survives: a caller who has bounded the input upstream passes None deliberately.
    # This is the half that makes the change safe to land -- behaviour is unchanged, only the
    # silence is removed.
    big = b"\x00" * (2 * 1024 * 1024)
    assert gzip_decompress(gzip_compress(big), max_output_bytes=None) == big
    assert deflate_decompress(deflate_compress(big), max_output_bytes=None) == big
    assert zip_decompress(zip_compress({"a": big}), max_output_bytes=None) == {"a": big}


def test_max_entries_keeps_its_default() -> None:  # #1237
    # Deliberately NOT made required: max_entries already ships ON (1024) and is enforced against the
    # central directory before any member is extracted, so it is not the silent-default defect.
    import inspect

    assert inspect.signature(zip_decompress).parameters["max_entries"].default == 1024


# --- archive-member admission (#1128, ASVS 5.2.2 within-an-archive / 5.3.2) ---


def _hostile_zip(entries: dict[str, bytes]) -> bytes:
    """Build a ZIP whose member names bypass ``zip_compress`` (which a Handler would not control).

    ``zipfile.ZipInfo`` writes the filename verbatim, so this is the only way to produce the names a
    hostile or compromised partner would put in an archive. Synthetic data only."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0)), payload)
    return buf.getvalue()


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd.hl7",  # the *.hl7 pattern matches it; fnmatch's * spans /
        "sub/../../escape.hl7",  # traversal in the middle, not the head
        "/abs/adt.hl7",  # absolute
        "C:evil.hl7",  # drive-relative: carries NO separator, slips a slash-only check
        "..",
        ".",
        "win\\dir\\adt.hl7",  # backslash: APPNOTE mandates /, so this is a smuggled separator
        "double//slash.hl7",  # empty component
        "",
        "bad\x00name.hl7",
        "bell\x07.hl7",
    ],
)
def test_archive_member_name_reason_refuses_traversal(name: str) -> None:
    assert archive_member_name_reason(name) is not None


@pytest.mark.parametrize(
    "name",
    [
        "adt.hl7",
        "sub/dir/b.hl7",
        "file with spaces.hl7",
        "unicode-é.hl7",
        ".gitignore",  # a leading dot on the leaf is a name, not an extension
        "no_extension",
        "a..b.hl7",  # dots that are not a whole component
    ],
)
def test_archive_member_name_reason_admits_legitimate(name: str) -> None:
    # The must-not-fire arm. A check that refuses everything is not a control.
    assert archive_member_name_reason(name) is None


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd.hl7",
        "sub/../../escape.hl7",
        "/abs/adt.hl7",
        "C:evil.hl7",
    ],
)
def test_zip_decompress_refuses_traversal_member_names(name: str) -> None:
    # End to end through the reader, on the shapes CPython's zipfile hands back intact. Two hostile
    # shapes are pinned elsewhere because its own writer/reader normalize them away, which is a fact
    # about the library and not about the guard: a NUL-bearing name is TRUNCATED at the NUL on read
    # (measured: "bad\x00name.hl7" reads back as "bad"), so it can never reach the guard through this
    # door and is pinned on the guard directly above; a backslash reaches the guard only off Windows,
    # for the reason the next test records.
    blob = _hostile_zip({name: _BODY})
    with pytest.raises(CompressionError, match="refused"):
        zip_decompress(blob, max_output_bytes=None)


@pytest.mark.skipif(
    os.sep == "\\",
    reason=(
        "zipfile._sanitize_filename replaces os.sep with '/', so on Windows a backslash member name "
        "cannot reach the guard through zipfile at all -- measured on CPython 3.14. It DOES reach it "
        "wherever os.sep is not a backslash, which is where this arm runs."
    ),
)
def test_zip_decompress_refuses_backslash_member_name() -> None:
    # A hostile archive can carry a literal backslash in the stored name, which a slash-only containment
    # check reads as one long harmless filename. ZipInfo will not write one, so patch the stored bytes:
    # the two names are the same length, so both the local header and the central directory copies swap
    # in place with no offset fixups.
    blob = _hostile_zip({"win/dir/adt.hl7": _BODY}).replace(
        b"win/dir/adt.hl7", b"win\\dir\\adt.hl7"
    )
    with zipfile.ZipFile(
        io.BytesIO(blob)
    ) as zf:  # the patch must survive the reader, or this proves
        assert zf.namelist() == ["win\\dir\\adt.hl7"]  # nothing about the guard
    with pytest.raises(CompressionError, match="backslash"):
        zip_decompress(blob, max_output_bytes=None)


def test_zip_decompress_admits_legitimate_nested_and_odd_names() -> None:
    entries = {
        "sub/dir/b.hl7": _BODY,
        "file with spaces.hl7": _BODY,
        "unicode-é.hl7": _BODY,
        "notes.txt": b"free text, no signature to check",
        ".gitignore": b"*.pyc",
        "no_extension": b"\x00\x01\x02",
    }
    assert zip_decompress(_hostile_zip(entries), max_output_bytes=None) == entries


def test_zip_decompress_refuses_member_contradicting_its_extension() -> None:
    # ASVS 5.2.2: the member's own extension names the expected type, and these bytes are not it.
    with pytest.raises(CompressionError, match=r"does not match the \.hl7 extension"):
        zip_decompress(_hostile_zip({"adt.hl7": b"%PDF-1.7 not hl7"}), max_output_bytes=None)
    with pytest.raises(CompressionError, match=r"does not match the \.json extension"):
        zip_decompress(_hostile_zip({"r.json": b"<Patient/>"}), max_output_bytes=None)
    with pytest.raises(CompressionError, match=r"does not match the \.pdf extension"):
        zip_decompress(_hostile_zip({"doc.pdf": _BODY}), max_output_bytes=None)


def test_zip_decompress_admits_members_matching_their_extension() -> None:
    entries = {
        "adt.hl7": _BODY,
        "r.json": b'{"resourceType":"Patient"}',
        "r.xml": b"<Patient/>",
        "doc.pdf": b"%PDF-1.7\nbody",
        "img.png": b"\x89PNG\r\n\x1a\nrest",
        "inner.gz": gzip_compress(b"x"),
        "claim.edi": b"ISA*00*",
    }
    assert zip_decompress(_hostile_zip(entries), max_output_bytes=None) == entries


def test_zip_decompress_leaves_unmodelled_extensions_unchecked() -> None:
    # Stated so the limit is pinned rather than assumed: at least .txt, .csv and .dat carry no signature
    # to check, so this gate does NOT close the verb's L2 "all files being accepted" clause on its own.
    entries = {"a.txt": b"\x00\x01", "b.csv": b"%PDF-1.7", "c.dat": b"anything"}
    assert zip_decompress(_hostile_zip(entries), max_output_bytes=None) == entries


def test_zip_member_refusal_names_no_content_or_filename() -> None:
    # PHI guard: a member name can carry a patient identifier, so the refusal names the member's
    # POSITION and the structural reason only -- never the name, never the body.
    blob = _hostile_zip({"../SMITH_JOHN_999-99-9999.hl7": b"PID|1||SSN-999-99-9999"})
    try:
        zip_decompress(blob, max_output_bytes=None)
    except CompressionError as exc:
        assert "SMITH" not in str(exc)
        assert "999-99" not in str(exc)
        assert "member 1" in str(exc)
    else:  # pragma: no cover - the guard must fire
        raise AssertionError("expected CompressionError")


def test_zip_member_name_is_refused_before_any_bytes_are_read() -> None:
    # The name check dominates the size ceiling: a traversal name in a bomb archive is refused for what
    # it is, before the bomb is spent. Both would raise, so assert on WHICH reason came back.
    blob = _hostile_zip({"../bomb.dat": b"\x00" * 4_000_000})
    with pytest.raises(CompressionError, match="relative path component"):
        zip_decompress(blob, max_output_bytes=1000)


@pytest.mark.parametrize("second_body", [b"first", b"second"])
def test_zip_rejects_duplicate_member_names(second_body: bytes) -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("unique.txt", b"keep")
        zf.writestr("duplicate.txt", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zf.writestr("duplicate.txt", second_body)
    with pytest.raises(CompressionError, match="duplicate") as caught:
        zip_decompress(archive.getvalue(), max_output_bytes=None)
    assert "duplicate.txt" not in str(caught.value)
    assert second_body.decode() not in str(caught.value)


def test_zip_duplicate_directories_do_not_collide_with_file_mapping() -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("d/", b"")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zf.writestr("d/", b"")
        zf.writestr("d/a.txt", b"payload")
    assert zip_decompress(archive.getvalue(), max_output_bytes=7, max_entries=3) == {
        "d/a.txt": b"payload"
    }


def test_zip_directory_entries_still_count_toward_member_cap() -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("d/", b"")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zf.writestr("d/", b"")
        zf.writestr("d/a.txt", b"payload")
    with pytest.raises(CompressionError, match="3 members, over the 2-member cap"):
        zip_decompress(archive.getvalue(), max_output_bytes=None, max_entries=2)


# --- #1964: the bounded inflate stops at the end of the stream -----------------

# The Lander's reproduction: an all-zero body whose output needs more than one output round.
_MULTI_ROUND = b"\x00" * (3 * compression._CHUNK)
_CAP = 16 * 1024 * 1024


def _returns_within[T](fn: Callable[[], T], seconds: float = 10.0) -> T:
    """Run ``fn`` on a worker thread and fail, rather than hang, if it has not returned in time.

    The defect is an endless loop, so the test must not rely on the call returning. A daemon thread
    lets the assertion fire while a regressed loop keeps spinning in the background until exit.
    """
    outcome: list[T | BaseException] = []

    def target() -> None:
        try:
            outcome.append(fn())
        except BaseException as exc:  # handed back to the test thread below, never swallowed
            outcome.append(exc)

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(seconds)
    assert outcome, f"did not return within {seconds}s: the inflate loop never ended (#1964)"
    result = outcome[0]
    if isinstance(result, BaseException):
        raise result
    return result


@pytest.mark.timeout(30)
def test_deflate_multi_round_stream_with_a_trailing_byte_is_refused() -> None:  # #1964
    stream = zlib.compress(_MULTI_ROUND) + b"X"
    with pytest.raises(CompressionError, match="trailing data after the end of the deflate stream"):
        _returns_within(lambda: deflate_decompress(stream, max_output_bytes=_CAP))


@pytest.mark.timeout(30)
@pytest.mark.parametrize(
    "trailing",
    [b"X", b"\x00", zlib.compress(b"second stream")],
    ids=["byte", "nul-pad", "second-stream"],
)
@pytest.mark.parametrize("body", [b"\x00" * 100, _MULTI_ROUND], ids=["one-round", "multi-round"])
def test_deflate_refuses_any_bytes_after_the_end_of_the_stream(
    body: bytes, trailing: bytes
) -> None:  # #1964
    # One rule for every shape. The one-round case used to return the body and drop the trailing
    # bytes without a word, which is accept-and-drop; the multi-round case used to hang.
    stream = zlib.compress(body) + trailing
    with pytest.raises(CompressionError, match="trailing data"):
        _returns_within(lambda: deflate_decompress(stream, max_output_bytes=None))


@pytest.mark.timeout(30)
@pytest.mark.parametrize("cap", [1024, len(_MULTI_ROUND) - 1], ids=["early", "on-the-last-round"])
def test_deflate_ceiling_still_fires_before_the_trailing_check(cap: int) -> None:  # #1964
    # Over the ceiling with junk after it is refused as over the ceiling. "on-the-last-round" crosses
    # the cap in the same round that reaches the end of the stream, so it pins the order of the two
    # checks, not only that the ceiling fires early on a bomb.
    stream = zlib.compress(_MULTI_ROUND) + b"X"
    with pytest.raises(CompressionError, match="ceiling"):
        _returns_within(lambda: deflate_decompress(stream, max_output_bytes=cap))


def _stored_stream_of_exact_length(length: int) -> bytes:
    # Level 0 stores the payload, so the stream length moves one byte per payload byte.
    rng = random.Random(length)
    for size in range(length - 64, length):
        stream = zlib.compress(rng.randbytes(size), 0)
        if len(stream) == length:
            return stream
    raise AssertionError(f"no stored stream of exactly {length} bytes")


@pytest.mark.timeout(30)
@pytest.mark.parametrize("windows", [1, 2])
def test_deflate_trailing_data_on_a_window_boundary(windows: int) -> None:  # #1964
    # A stream that ends exactly on an input window leaves nothing in that window, so only the
    # "a later window exists" half of the trailing check can see the extra byte.
    stream = _stored_stream_of_exact_length(windows * compression._CHUNK)
    assert len(_returns_within(lambda: deflate_decompress(stream, max_output_bytes=None))) > 0
    with pytest.raises(CompressionError, match="trailing data"):
        _returns_within(lambda: deflate_decompress(stream + b"Z", max_output_bytes=None))


@pytest.mark.parametrize(
    "data, cap",
    [
        (zlib.compress(b"\x00" * 300_000), 1000),
        (b"\xff\xff\xff\xff not deflate", None),
        (zlib.compress(b"hello") + b"X", None),
    ],
    ids=["ceiling", "corrupt", "trailing"],
)
def test_deflate_error_leaves_a_bytearray_resizable(data: bytes, cap: int | None) -> None:  # #1964
    # A caller that keeps the error must still be able to grow its own buffer. A memoryview window
    # held by the raising frame would pin the buffer and make extend() raise BufferError. The
    # signature says bytes, but nothing stops a Handler passing a bytearray at run time.
    buf = bytearray(data)
    with pytest.raises(CompressionError) as caught:
        deflate_decompress(buf, max_output_bytes=cap)  # type: ignore[arg-type]
    assert caught.value.__traceback__ is not None  # the raising frame is still reachable here
    buf.extend(b"more")


def test_deflate_bomb_stops_at_the_ceiling_not_a_window_past_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # #1964
    # The module promises a bomb is refused after producing at most the ceiling. Asking zlib for a
    # whole window each round would overshoot a small ceiling by up to one window.
    produced: list[int] = []
    real = zlib.decompressobj

    class _Counting:
        def __init__(self, *, wbits: int) -> None:
            self._inner = real(wbits=wbits)

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            piece = self._inner.decompress(data, max_length)
            produced.append(len(piece))
            return piece

        def __getattr__(self, name: str) -> object:
            return getattr(self._inner, name)

    monkeypatch.setattr(
        compression, "zlib", SimpleNamespace(decompressobj=_Counting, error=zlib.error)
    )
    with pytest.raises(CompressionError, match="ceiling"):
        deflate_decompress(zlib.compress(_MULTI_ROUND), max_output_bytes=1024)
    assert sum(produced) == 1025


def test_deflate_stream_spanning_many_input_windows() -> None:  # #1964
    # Level 0 does not compress, so the stream is many 64 KiB input windows long. The exact size
    # passes and one byte less is refused, so the windowed loop neither loses nor double-counts.
    payload = random.Random(1964).randbytes(1024 * 1024 + 7)
    stream = zlib.compress(payload, 0)
    assert deflate_decompress(stream, max_output_bytes=len(payload)) == payload
    with pytest.raises(CompressionError, match="ceiling"):
        deflate_decompress(stream, max_output_bytes=len(payload) - 1)


def test_deflate_feeds_each_input_byte_a_bounded_number_of_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # #1964
    # Handing zlib the whole remaining input every round copies it every round, which is quadratic
    # in the compressed size. Count the bytes fed rather than time the call, so the test is exact.
    fed: list[int] = []

    class _Recording:
        def __init__(self, *, wbits: int) -> None:
            self._inner = zlib.decompressobj(wbits=wbits)

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            fed.append(len(data))
            return self._inner.decompress(data, max_length)

        def flush(self) -> bytes:
            return self._inner.flush()

        @property
        def eof(self) -> bool:
            return self._inner.eof

        @property
        def unconsumed_tail(self) -> bytes:
            return self._inner.unconsumed_tail

        @property
        def unused_data(self) -> bytes:
            return self._inner.unused_data

    monkeypatch.setattr(
        compression, "zlib", SimpleNamespace(decompressobj=_Recording, error=zlib.error)
    )
    payload = random.Random(1964).randbytes(4 * 1024 * 1024)
    stream = zlib.compress(payload, 0)
    assert deflate_decompress(stream, max_output_bytes=None) == payload
    # Quadratic feeding hands zlib about len(stream) ** 2 / (2 * 64 KiB) bytes, about 128 MiB here.
    assert sum(fed) <= 3 * len(stream), f"fed {sum(fed)} bytes for a {len(stream)}-byte stream"


@pytest.mark.timeout(30)
def test_gzip_multi_round_member_with_trailing_bytes_ends() -> None:  # #1964
    # GzipFile runs its own loop. Pin that it ends on the same shape: a non-NUL byte is refused as
    # a bad next member, and NUL padding is accepted, which is the stdlib gzip rule.
    member = gzip_compress(_MULTI_ROUND)
    with pytest.raises(CompressionError, match="corrupt"):
        _returns_within(lambda: gzip_decompress(member + b"X", max_output_bytes=_CAP))
    assert (
        _returns_within(lambda: gzip_decompress(member + b"\x00" * 8, max_output_bytes=_CAP))
        == _MULTI_ROUND
    )


@pytest.mark.timeout(30)
def test_zip_multi_round_member_with_trailing_bytes_ends() -> None:  # #1964
    # zipfile runs its own loop, bounded by each member's compressed size. Pin only that it ends.
    # That bytes after the archive are refused is pinned by the #1976 tests below, not here.
    archive = zip_compress({"a.bin": _MULTI_ROUND}) + b"X"

    def call() -> object:
        # Returned, not raised, so a prompt refusal also counts as ending.
        try:
            return zip_decompress(archive, max_output_bytes=_CAP)
        except CompressionError:
            return "refused"

    _returns_within(call)


# --- #1598: every zipfile failure is a CompressionError that names no member ------

# The filename is patient-shaped on purpose: zipfile's RuntimeError for an encrypted member and its
# BadZipFile for a bad CRC both embed it.
_PHI_NAME = "SMITH_JOHN_MRN123.txt"


def _two_member_zip_with_second_patched(*, flag: int = 0, method: int | None = None) -> bytes:
    """A stored two-member archive whose SECOND member has ``flag`` OR-ed into its 16-bit
    general-purpose flags and, if given, ``method`` as its compression method, in both the local header and the
    central directory. Stored bodies contain no ``PK`` signature, so the header search is exact."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("ok.txt", b"first")
        zf.writestr(_PHI_NAME, b"second")
    blob = bytearray(buf.getvalue())
    # (signature, offset of the flags field, offset of the method field) for each header kind.
    for signature, flag_at, method_at in ((b"PK\x03\x04", 6, 8), (b"PK\x01\x02", 8, 10)):
        second = blob.index(signature, blob.index(signature) + 1)
        blob[second + flag_at] |= flag & 0xFF
        blob[second + flag_at + 1] |= flag >> 8
        if method is not None:
            blob[second + method_at : second + method_at + 2] = method.to_bytes(2, "little")
    return bytes(blob)


def test_zip_patch_helper_control_archive_still_decompresses() -> None:  # #1598
    # Control: with nothing patched the helper's archive is well formed, so the refusals below come
    # from the flag and the method, not from a helper that corrupts the archive.
    assert zip_decompress(_two_member_zip_with_second_patched(), max_output_bytes=None) == {
        "ok.txt": b"first",
        _PHI_NAME: b"second",
    }


def _second_member_body_corrupted() -> bytes:
    # One byte of the stored body changes, so zipfile's CRC check fails with a BadZipFile whose
    # message is "Bad CRC-32 for file '<name>'".
    blob = _two_member_zip_with_second_patched()
    return blob.replace(b"second", b"Second", 1)


def _second_member_name_not_utf8() -> bytes:
    # The UTF-8 name flag, with a name byte that is not UTF-8, in both headers. zipfile raises a
    # builtin UnicodeDecodeError whose .object holds the raw name bytes.
    blob = _two_member_zip_with_second_patched(flag=0x0800)
    return blob.replace(b"SMITH_", b"SMITH\xff")


def _central_directory_offset_too_large() -> bytes:
    # The end record claims the central directory starts 1000 bytes later than it does, so zipfile
    # computes a negative member offset and BytesIO.seek raises ValueError("negative seek value").
    # The #1976 layout check sees that offset first and refuses the archive before any member opens,
    # so zip_decompress never reaches the seek. The case stays to pin that this refusal names no
    # member either, and the control below pins that the shape still breaks zipfile itself.
    blob = bytearray(_two_member_zip_with_second_patched())
    eocd = blob.rindex(b"PK\x05\x06")
    offset = int.from_bytes(blob[eocd + 16 : eocd + 20], "little")
    blob[eocd + 16 : eocd + 20] = (offset + 1000).to_bytes(4, "little")
    return bytes(blob)


def _second_member_codec_corrupted(compress_type: int) -> bytes:
    # A compressed member whose first stream bytes are garbage. Neither lzma.LZMAError nor
    # compression.zstd.ZstdError is an OSError.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("ok.txt", b"first")
        zf.writestr(zipfile.ZipInfo(_PHI_NAME), b"second" * 50, compress_type=compress_type)
    blob = bytearray(buf.getvalue())
    local = blob.index(b"PK\x03\x04", blob.index(b"PK\x03\x04") + 1)
    name_len, extra_len = (
        int.from_bytes(blob[local + 26 : local + 28], "little"),
        int.from_bytes(blob[local + 28 : local + 30], "little"),
    )
    data_at = local + 30 + name_len + extra_len
    # LZMA: the properties after zipfile's 4-byte version/size prefix. Zstandard: the frame magic.
    start = 4 if compress_type == zipfile.ZIP_LZMA else 0
    blob[data_at + start : data_at + start + 5] = b"\xff" * 5
    return bytes(blob)


def _second_member_zstd_corrupted() -> bytes:
    pytest.importorskip("compression.zstd", reason="this Python build has no Zstandard support")
    return _second_member_codec_corrupted(zipfile.ZIP_ZSTANDARD)


_UNSUPPORTED = "member 2 uses a zip feature this reader does not support"


@pytest.mark.parametrize(
    ("build", "reason"),
    [
        pytest.param(
            lambda: _two_member_zip_with_second_patched(flag=0x01),
            _UNSUPPORTED,
            id="encrypted-flag",
        ),
        pytest.param(
            lambda: _two_member_zip_with_second_patched(method=98), _UNSUPPORTED, id="method-98"
        ),
        pytest.param(
            _second_member_body_corrupted, r"member 2 is corrupt.*\(BadZipFile\)", id="bad-crc"
        ),
        pytest.param(
            lambda: _second_member_codec_corrupted(zipfile.ZIP_LZMA),
            r"member 2 is corrupt.*\(LZMAError\)",
            id="lzma-corrupt",
        ),
        pytest.param(
            _second_member_zstd_corrupted, r"member 2 is corrupt.*\(ZstdError\)", id="zstd-corrupt"
        ),
        pytest.param(
            _second_member_name_not_utf8,
            r"^zip archive is corrupt.*\(UnicodeDecodeError\)",
            id="name-not-utf8",
        ),
        pytest.param(
            _central_directory_offset_too_large,
            r"^data before the start of the zip archive$",
            id="cd-offset-past-archive",
        ),
    ],
)
def test_zip_unreadable_member_is_a_compression_error_naming_no_filename(
    build: Callable[[], bytes], reason: str
) -> None:  # #1598
    blob = build()
    with pytest.raises(CompressionError, match=reason) as exc:
        zip_decompress(blob, max_output_bytes=None)
    # PHI guard: the member name must not reach the message or anything chained to it. zipfile's own
    # messages embed it, so a `from exc` would carry the name on __cause__, and a raise inside the
    # handler would carry it on __context__.
    assert "SMITH" not in str(exc.value)
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


def test_zip_negative_seek_shape_still_breaks_zipfile() -> None:  # #1598, #1976
    # Control for the negative-seek case above: the layout check now refuses that archive first, so
    # this pins that the shape itself is still the one zipfile fails on with a negative seek.
    zf = zipfile.ZipFile(io.BytesIO(_central_directory_offset_too_large()))
    with zf, pytest.raises(ValueError, match="negative seek value"):
        zf.read(zf.infolist()[0])


# --- #1977: one bounded-inflate primitive, two trailing rules ------------------------------------


def _raw_deflate(body: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(body) + compressor.flush()


def test_both_callers_run_the_one_shared_inflate_loop() -> None:  # #1977
    # Two copies of one loop let a fix reach one and not the other, which is how #1964 happened.
    from messagefoundry.parsing import _bounded_inflate
    from messagefoundry.parsing.dicom import _inflate as dicom_inflate

    assert vars(compression)["bounded_inflate"] is _bounded_inflate.bounded_inflate
    assert vars(dicom_inflate)["bounded_inflate"] is _bounded_inflate.bounded_inflate
    # The #1964 window-boundary tests size their streams in compression._CHUNK windows.
    assert compression._CHUNK == _bounded_inflate.CHUNK


@pytest.mark.timeout(30)
@pytest.mark.parametrize(
    "trailing",
    [b"X", b"\x00", zlib.compress(b"second stream")],
    ids=["byte", "nul-pad", "second-stream"],
)
@pytest.mark.parametrize("body", [b"\x00" * 100, _MULTI_ROUND], ids=["one-round", "multi-round"])
@pytest.mark.parametrize("keep_output", [True, False], ids=["keep", "discard"])
@pytest.mark.parametrize("exact_ceiling", [True, False], ids=["exact", "window"])
def test_the_shared_loop_pins_both_trailing_rules(
    body: bytes, trailing: bytes, keep_output: bool, exact_ceiling: bool
) -> None:  # #1977
    # The same stream and the same tail through both rules. "refuse" is the codec's rule and "stop"
    # is the DICOM guard's. The multi-round body is the #1964 shape that used to loop forever.
    from messagefoundry.parsing._bounded_inflate import InflateTrailingData, bounded_inflate

    stream = _raw_deflate(body) + trailing

    def run(rule: Literal["refuse", "stop"]) -> object:
        return bounded_inflate(
            stream,
            zlib.decompressobj(-zlib.MAX_WBITS),
            max_output_bytes=_CAP,
            trailing=rule,
            keep_output=keep_output,
            exact_ceiling=exact_ceiling,
        )

    with pytest.raises(InflateTrailingData):
        _returns_within(lambda: run("refuse"))
    stopped = _returns_within(lambda: run("stop"))
    assert stopped == InflateResult(body if keep_output else b"", len(body), eof=True)


def test_the_shared_loop_refuses_an_unknown_trailing_rule() -> None:  # #1977
    # The Literal type binds only under mypy. A mistyped rule must not fall through to "stop", the
    # permissive one, and silently accept a tail.
    from messagefoundry.parsing._bounded_inflate import bounded_inflate

    with pytest.raises(ValueError, match="unknown trailing-data rule"):
        bounded_inflate(
            zlib.compress(b"x") + b"JUNK",
            zlib.decompressobj(),
            max_output_bytes=None,
            trailing="Refuse",  # type: ignore[arg-type]
            keep_output=True,
            exact_ceiling=True,
        )


@pytest.mark.parametrize("rule", ["refuse", "stop"])
@pytest.mark.parametrize("keep_output", [True, False], ids=["keep", "discard"])
def test_the_shared_loop_ceiling_stops_one_byte_over_or_one_window_over(
    rule: Literal["refuse", "stop"], keep_output: bool
) -> None:  # #1977
    # exact_ceiling=True is the codec's promise: at most one byte past the ceiling. False is the DICOM
    # guard's old request size: the count may pass the ceiling by up to one window before it fires.
    from messagefoundry.parsing._bounded_inflate import (
        CHUNK,
        InflateCeilingExceeded,
        bounded_inflate,
    )

    produced: dict[bool, int] = {}
    for exact in (True, False):
        counting = _CountingDecompressor(zlib.decompressobj(-zlib.MAX_WBITS))
        with pytest.raises(InflateCeilingExceeded) as caught:
            bounded_inflate(
                _raw_deflate(_MULTI_ROUND),
                counting,
                max_output_bytes=1024,
                trailing=rule,
                keep_output=keep_output,
                exact_ceiling=exact,
            )
        assert caught.value.ceiling == 1024
        produced[exact] = counting.produced
    assert produced[True] == 1025
    assert 1025 < produced[False] <= 1024 + CHUNK


def test_the_shared_loop_reports_a_truncated_stream_and_leaves_the_verdict_to_the_caller() -> None:
    # #1977: the codec refuses a truncated stream and the DICOM guard stands aside for dcmread, so the
    # loop reports it rather than deciding.
    from messagefoundry.parsing._bounded_inflate import bounded_inflate

    stream = _raw_deflate(b"hello world" * 100)[:-4]
    result = bounded_inflate(
        stream,
        zlib.decompressobj(-zlib.MAX_WBITS),
        max_output_bytes=None,
        trailing="refuse",
        keep_output=True,
        exact_ceiling=True,
    )
    assert result.eof is False


def test_dicom_guard_still_stands_aside_for_a_break_inside_the_crossing_window() -> None:  # #1977
    # The DICOM verdict the shared loop must not move. The guard asks zlib for a whole window each
    # round, so a stream that breaks inside the window that crosses the cap raises zlib.error first
    # and is left to dcmread, whose decode path answers Cannot Understand. Asking for one byte past
    # the cap would call it a bomb, and the SCP answers a bomb with Out of Resources, which a sender
    # may retry.
    from messagefoundry.parsing.dicom._inflate import bounded_inflate_or_error
    from messagefoundry.parsing.dicom.errors import DicomBombError

    compressor = zlib.compressobj(0, zlib.DEFLATED, -zlib.MAX_WBITS)
    prefix = compressor.compress(b"A" * 5000) + compressor.flush(zlib.Z_SYNC_FLUSH)
    corrupt = prefix + bytes([0xFF] * 6)
    with pytest.raises(zlib.error):
        zlib.decompressobj(-zlib.MAX_WBITS).decompress(corrupt)  # the stream really is corrupt
    bounded_inflate_or_error(corrupt, max_bytes=4000)  # crosses the cap in the breaking window
    bounded_inflate_or_error(corrupt, max_bytes=6000)  # breaks under the cap
    # Control: the same prefix, valid to its end, IS over the cap.
    valid = prefix + compressor.flush()
    with pytest.raises(DicomBombError):
        bounded_inflate_or_error(valid, max_bytes=4000)


class _CountingDecompressor:
    """Wraps a real decompressor and counts every byte it hands back."""

    def __init__(self, inner: Any) -> None:
        self.produced = 0
        self._inner = inner

    def decompress(self, data: Any, max_length: int = 0, /) -> bytes:
        piece: bytes = self._inner.decompress(data, max_length)
        self.produced += len(piece)
        return piece

    def flush(self) -> bytes:
        piece: bytes = self._inner.flush()
        self.produced += len(piece)
        return piece

    @property
    def eof(self) -> bool:
        return bool(self._inner.eof)

    @property
    def unconsumed_tail(self) -> bytes:
        return bytes(self._inner.unconsumed_tail)

    @property
    def unused_data(self) -> bytes:
        return bytes(self._inner.unused_data)


# --- #1976: zip_decompress refuses bytes outside the archive ---------------------------------------


def _zip_with_comment(comment: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("a.bin", date_time=(1980, 1, 1, 0, 0, 0)), b"payload")
        zf.comment = comment
    return buf.getvalue()


@pytest.mark.parametrize("comment", [b"", b"an archive comment"], ids=["no-comment", "comment"])
def test_zip_clean_archive_is_accepted(comment: bytes) -> None:  # #1976
    # The declared comment is part of the archive, so it is not trailing data.
    assert zip_decompress(_zip_with_comment(comment), max_output_bytes=_CAP) == {
        "a.bin": b"payload"
    }


@pytest.mark.parametrize("tail", [1, 1000], ids=["one-byte", "1000-bytes"])
@pytest.mark.parametrize("comment", [b"", b"an archive comment"], ids=["no-comment", "comment"])
def test_zip_refuses_a_small_tail_after_the_archive(tail: int, comment: bytes) -> None:  # #1976
    # zipfile finds the end record by scanning back from the end, so a tail inside its 64 KiB window
    # opened and read normally, and the extra bytes were dropped without a word.
    archive = _zip_with_comment(comment) + b"J" * tail
    with pytest.raises(CompressionError, match="trailing data after the end of the zip archive"):
        zip_decompress(archive, max_output_bytes=_CAP)


def test_zip_refuses_a_tail_past_the_end_record_scan_window() -> None:  # #1976
    # Past the window zipfile cannot find the end record at all, so stdlib already refuses it as
    # corrupt. Pinned so both tail sizes stay refused whichever check catches them.
    archive = zip_compress({"a.bin": b"payload"}) + b"J" * 70_000
    with pytest.raises(CompressionError):
        zip_decompress(archive, max_output_bytes=_CAP)


def test_zip_refuses_a_comment_shorter_than_it_declares() -> None:  # #1976
    # zipfile reads a short comment without complaint. The archive ends before its own end record
    # says it does, so it is truncated, and the codec refuses a truncated input.
    archive = _zip_with_comment(b"an archive comment")[:-5]
    with pytest.raises(CompressionError, match="truncated zip archive comment"):
        zip_decompress(archive, max_output_bytes=_CAP)


@pytest.mark.parametrize(
    "prefix",
    [
        b"J" * 100,
        zip_compress({"first.bin": b"first payload"}),
        zip_compress({"first.bin": b"first payload"}) + b"J" * 70_000,
    ],
    ids=["junk", "first-archive", "archive-and-long-junk"],
)
def test_zip_refuses_bytes_before_the_archive(prefix: bytes) -> None:  # #1976
    # zipfile skips anything in front of the archive as prepended data, so a joined pair returned only
    # the second archive's members and dropped the first without a word. The last case is also a tail
    # past the scan window after the first archive, which ends in a valid archive and so opens.
    archive = prefix + zip_compress({"second.bin": b"second payload"})
    with pytest.raises(CompressionError, match="data before the start of the zip archive"):
        zip_decompress(archive, max_output_bytes=_CAP)


def test_zip_refuses_bytes_before_an_empty_archive() -> None:  # #1976
    # An empty archive has no member offset to check, so the end record itself must start the input.
    empty = zip_compress({})
    assert zip_decompress(empty, max_output_bytes=_CAP) == {}
    with pytest.raises(CompressionError, match="data before the start of the zip archive"):
        zip_decompress(b"J" * 10 + empty, max_output_bytes=_CAP)
