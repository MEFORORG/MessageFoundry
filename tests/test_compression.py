# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Compression codec (ADR 0123) — pure gzip/zlib-deflate/zip.

Covers round-trips, the re-run-purity determinism guarantee (fixed gzip mtime / zip date), the
incremental decompression-bomb ceiling on every decompressor, corrupt/truncated rejection as
``CompressionError``, argument validation, and the top-level re-exports Handlers use.
"""

from __future__ import annotations

import gzip
import time

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
