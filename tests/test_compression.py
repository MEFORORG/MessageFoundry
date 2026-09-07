# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Compression codec (ADR 0123) — pure gzip/zlib-deflate/zip.

Covers round-trips, the re-run-purity determinism guarantee (fixed gzip mtime / zip date), the
incremental decompression-bomb ceiling on every decompressor, corrupt/truncated rejection as
``CompressionError``, argument validation, and the top-level re-exports Handlers use.
"""

from __future__ import annotations

import gzip
import io
import os
import time
import zipfile

import pytest

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
