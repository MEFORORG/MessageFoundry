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
    # Content-free and unchained: a reference value may be PHI for a patient-keyed set.
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


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


async def test_a_toml_nan_fails_the_sync_and_writes_no_snapshot(tmp_path: Path) -> None:
    """End to end: a ``nan`` in a reference TOML is refused at the sink, so the set is not committed."""
    src = tmp_path / "rates.toml"
    src.write_text("[acme]\nrate = nan\n", encoding="utf-8")
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        runner = ReferenceSyncRunner(
            store,
            lambda: [ReferenceSpec(name="rates", source=FileRef(path=str(src)))],
            ReferenceSettings(),
            egress=EgressSettings(deny_by_default=False),
        )
        result = await runner.sync_all()
        assert (result.synced, result.failed) == (0, 1)
        assert "rates" not in store.reference_view()
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


def test_merge_user_metadata_falls_back_to_the_ops_when_existing_will_not_re_encode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored = json.dumps({"correlation_id": "c", "user": {"old": "x"}})
    _encoder_overflows_once(monkeypatch)
    assert json.loads(merge_user_metadata(stored, [("k", "a"), ("k", "b")])) == {"user": {"k": "b"}}


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
