# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``store/metadata.py`` JSON hardening: no bare NaN/Infinity token from the reference sink (BACKLOG
#6711), and deeply nested JSON reads as malformed in the three decoders (BACKLOG #6712)."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import FileRef, ReferenceSpec
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.store.metadata import (
    decode_response_headers,
    encode_reference_value,
    encode_response_headers,
    merge_user_metadata,
    user_metadata,
)
from messagefoundry.store.store import MessageStore

# Deep enough to exhaust json's C scanner on every supported platform (measured: 100_000 overflows).
_DEEP = "[" * 200_000


def _strict_loads(text: str) -> Any:
    """``json.loads`` that refuses the non-standard ``NaN``/``Infinity`` tokens, as a strict reader does."""

    def refuse(token: str) -> Any:
        raise ValueError(f"non-standard JSON token {token!r}")

    return json.loads(text, parse_constant=refuse)


# --- #6711: encode_reference_value ------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        {"rate": float("nan")},
        ["a", [float("inf")]],
    ],
    ids=["nan", "inf", "-inf", "nested-in-dict", "nested-in-list"],
)
def test_a_non_finite_float_is_refused_as_unencodable(value: Any) -> None:
    with pytest.raises(TypeError, match="non-finite") as info:
        encode_reference_value(value)
    # Unchained: json's ValueError carries notes naming the dict keys on the path, and a reference
    # key may be PHI for a patient-keyed set.
    assert info.value.__cause__ is None
    assert info.value.__context__ is None


def test_a_nested_value_too_deep_to_encode_is_refused_as_unencodable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dry-run catches only TypeError, so json's RecursionError must arrive as one too."""

    def overflow(value: Any, **kwargs: Any) -> str:
        raise RecursionError("maximum recursion depth exceeded while encoding a JSON object")

    monkeypatch.setattr(json, "dumps", overflow)
    with pytest.raises(TypeError, match="nested too deep") as info:
        encode_reference_value({"a": 1})
    assert info.value.__context__ is None


@pytest.mark.parametrize("value", [1.5, 0.0, -2.25, 1e308, {"x": [1.5, None, True]}])
def test_a_finite_value_still_encodes_as_before(value: Any) -> None:
    """Positive control: only the non-finite case changed, so every other snapshot is byte-identical."""
    encoded = encode_reference_value(value)
    assert encoded == json.dumps(value)
    assert _strict_loads(encoded) == value


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
def test_a_non_finite_decimal_encodes_as_valid_json(value: Decimal) -> None:
    """A Decimal becomes its string, as the DATABASE producer's ``_json_default`` writes it too, so the
    output is a JSON string, never a bare token."""
    assert _strict_loads(encode_reference_value(value)) == str(value)


@pytest.mark.parametrize(
    ("rate", "outcome"), [("nan", (0, 1)), ("inf", (0, 1)), ("1.5", (1, 0))], ids=str
)
async def test_a_toml_nan_fails_the_sync_and_writes_no_snapshot(
    tmp_path: Path, rate: str, outcome: tuple[int, int]
) -> None:
    """End to end: a ``nan`` in a reference TOML is refused at the sink, so the set is not committed.
    The finite twin syncs, so the sink, not some other refusal, is what failed the others."""
    src = tmp_path / "rates.toml"
    src.write_text(f"[acme]\nrate = {rate}\n", encoding="utf-8")
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        runner = ReferenceSyncRunner(
            store,
            lambda: [ReferenceSpec(name="rates", source=FileRef(path=str(src)))],
            ReferenceSettings(),
            egress=EgressSettings(deny_by_default=False),
        )
        result = await runner.sync_all()
        assert (result.synced, result.failed) == outcome
        assert ("rates" in store.reference_view()) is (outcome == (1, 0))
    finally:
        await store.close()


# --- #6712: the three decoders ----------------------------------------------------------------


def test_the_deep_input_really_reaches_the_recursion_limit() -> None:
    """Positive control: without it the deep case could pass as an ordinary decode error."""
    with pytest.raises(RecursionError):
        json.loads(_DEEP)


@pytest.mark.parametrize("bad", [_DEEP, "{not json"], ids=["deep-nesting", "plain-malformed"])
def test_decoders_read_malformed_input_as_empty(bad: str) -> None:
    """Deep nesting raises json's ``RecursionError``; it must read like any other malformed cell."""
    assert decode_response_headers(bad) == {}
    assert user_metadata(bad) is None
    assert json.loads(merge_user_metadata(bad, [("k", "v")])) == {"user": {"k": "v"}}


def _encoder_overflows_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """json's encoder depth limit sits below its decoder's (measured: a 16_000-deep value decodes
    but will not re-encode on 3.14), but where exactly is stack-dependent, so it is simulated."""
    real = json.dumps
    calls = {"n": 0}

    def dumps(value: Any, **kwargs: Any) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RecursionError("maximum recursion depth exceeded while encoding a JSON object")
        return real(value, **kwargs)

    monkeypatch.setattr(json, "dumps", dumps)


def test_user_metadata_reads_a_bag_too_deep_to_re_encode_as_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored = json.dumps({"user": {"k": "v"}})
    _encoder_overflows_once(monkeypatch)
    assert user_metadata(stored) is None


def test_merge_user_metadata_refuses_when_existing_will_not_re_encode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refused rather than written back as the ops alone, which would erase the readable lineage."""
    stored = json.dumps({"correlation_id": "c", "user": {"old": "x"}})
    _encoder_overflows_once(monkeypatch)
    with pytest.raises(ValueError, match="too deeply nested") as info:
        merge_user_metadata(stored, [("k", "v")])
    assert info.value.__context__ is None


def test_a_non_str_cell_reads_as_empty() -> None:
    """The TypeError arm the old decoders carried: a non-str cell still reads as no metadata."""
    cell: Any = memoryview(b'{"user": {"k": "v"}}')
    assert decode_response_headers(cell) == {}
    assert user_metadata(cell) is None
    assert json.loads(merge_user_metadata(cell, [("k", "v")])) == {"user": {"k": "v"}}


@pytest.mark.parametrize("wrap", [bytes, bytearray], ids=["bytes", "bytearray"])
def test_a_bytes_cell_keeps_its_lineage_through_merge(wrap: Any) -> None:
    """``json.loads`` parsed a bytes cell before this branch; it still must, or the merge below would
    write the ops alone over the lineage."""
    cell: Any = wrap(json.dumps({"correlation_id": "c", "user": {"old": "x"}}).encode("utf-8"))
    assert json.loads(merge_user_metadata(cell, [("k", "v")])) == {
        "correlation_id": "c",
        "user": {"old": "x", "k": "v"},
    }
    assert json.loads(user_metadata(cell) or "null") == {"old": "x"}
    assert decode_response_headers(wrap(b'{"Location": "/x"}')) == {"Location": "/x"}


def test_a_malformed_bytes_cell_reads_as_empty() -> None:
    """The hardening still holds for bytes: deep nesting and a bad UTF-8 byte read as malformed."""
    assert user_metadata(_DEEP.encode("ascii")) is None  # type: ignore[arg-type]
    assert user_metadata(b'{"user": {"k": "\xff"}}') is None  # type: ignore[arg-type]


def test_an_unreadable_cell_is_logged_without_its_content(caplog: pytest.LogCaptureFixture) -> None:
    marker = "SYNTHETIC-MRN-5550199"
    with caplog.at_level("WARNING", logger="messagefoundry.store.metadata"):
        assert user_metadata('{"user": {"k": "' + marker + '"') is None
        assert user_metadata("[" * 200_000 + '"' + marker) is None
    assert len(caplog.records) == 2
    assert all(marker not in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("bag", ['"xyz"', "5", '[["a", "b"]]', "null"])
def test_merge_user_metadata_treats_a_non_object_user_bag_as_empty(bag: str) -> None:
    stored = '{"correlation_id": "c", "user": ' + bag + "}"
    assert json.loads(merge_user_metadata(stored, [("k", "v")])) == {
        "correlation_id": "c",
        "user": {"k": "v"},
    }


def test_decode_response_headers_keeps_only_string_values() -> None:
    stored = json.dumps({"Location": "/x", "N": 1, "B": True, "F": 1.5, "Z": None, "L": ["a"]})
    assert decode_response_headers(stored) == {"Location": "/x"}


def test_response_headers_round_trip() -> None:
    headers = {"Location": "/Patient/1", "ETag": 'W/"7"'}
    assert decode_response_headers(encode_response_headers(headers)) == headers
