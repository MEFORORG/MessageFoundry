# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``store/metadata.py`` JSON hardening: no bare NaN/Infinity token from the reference sink (BACKLOG
#6711), and deeply nested JSON never escapes the three decoders as json's ``RecursionError`` (BACKLOG
#6712): the header decoder reads it as malformed, while ``merge_user_metadata`` and ``user_metadata``
raise ``MetadataTooDeepError``."""

from __future__ import annotations

import json
import types
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import FileRef, ReferenceSpec
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import Stage
from messagefoundry.store import metadata as metadata_module
from messagefoundry.store.cell_tag import message_cell_aad
from messagefoundry.store.metadata import (
    MetadataTooDeepError,
    decode_response_headers,
    encode_reference_value,
    encode_response_headers,
    merge_user_metadata,
    user_metadata,
)
from messagefoundry.store.store import MessageStore
from tests.test_metadata_bag import _to_routed

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


# --- #6712: the three decoders; only the header decoder reads deep nesting as empty ----------


def test_the_deep_input_really_reaches_the_recursion_limit() -> None:
    """Positive control: without it the deep case could pass as an ordinary decode error."""
    with pytest.raises(RecursionError):
        json.loads(_DEEP)


@pytest.mark.parametrize("bad", [_DEEP, "{not json"], ids=["deep-nesting", "plain-malformed"])
def test_the_header_decoder_reads_malformed_input_as_empty(bad: str) -> None:
    """Deep nesting raises json's ``RecursionError``; here it reads like any other malformed cell."""
    assert decode_response_headers(bad) == {}


def test_merge_user_metadata_reads_plain_malformed_input_as_empty() -> None:
    """Unchanged from main: an unparseable cell is "no metadata", so the merge writes the ops alone."""
    assert json.loads(merge_user_metadata("{not json", [("k", "v")])) == {"user": {"k": "v"}}


# A well-formed cell holding the correlation lineage beside a value too deep to decode.
_DEEP_CELL = '{"corr": "x", "user": {"old": "y"}, "z": ' + "[" * 200_000 + "]" * 200_000 + "}"


def test_merge_user_metadata_raises_on_a_cell_too_deep_to_decode() -> None:
    """Read as ``{}``, the merge would write back the ops alone and erase the cell's other keys, the
    correlation lineage among them; on main json's ``RecursionError`` escaped instead. Raised
    unchained, content-free, and not a ``ValueError``."""
    with pytest.raises(MetadataTooDeepError, match="decode") as info:
        merge_user_metadata(_DEEP_CELL, [("k", "v")])
    assert info.value.__cause__ is None
    assert info.value.__context__ is None
    assert not isinstance(info.value, ValueError)


async def test_a_setmeta_handoff_leaves_a_too_deep_stored_cell_unchanged(tmp_path: Path) -> None:
    """End to end on the store: the handoff aborts, and the stored cell, ``corr`` included, is the
    same text afterwards, so no lineage is erased."""
    store = await MessageStore.open(tmp_path / "deep.db")
    try:
        mid, rtd = await _to_routed(store)
        aad = message_cell_aad("metadata", message_id=mid, channel_id="IB")
        await store._db.execute(
            "UPDATE messages SET metadata=? WHERE id=?", (store._enc(_DEEP_CELL, aad=aad), mid)
        )
        await store._db.commit()
        with pytest.raises(MetadataTooDeepError):
            await store.transform_handoff(
                routed_id=rtd.id,
                message_id=mid,
                channel_id="IB",
                deliveries=[("OB1", "OUTBODY")],
                meta_ops=[("k", "v")],
            )
        msg = await store.get_message(mid)
        assert msg is not None
        assert msg["metadata"] == _DEEP_CELL
        # Aborted whole: the routed row survives and no outbound row was produced.
        cur = await store._db.execute("SELECT stage FROM queue WHERE message_id=?", (mid,))
        assert [row["stage"] for row in await cur.fetchall()] == [Stage.ROUTED.value]
    finally:
        await store.close()


def test_user_metadata_reads_plain_malformed_input_as_none() -> None:
    """Unchanged from main: an unparseable cell is "no metadata"."""
    assert user_metadata("{not json") is None


@pytest.mark.parametrize("deep", [_DEEP, _DEEP.encode("ascii")], ids=["str", "bytes"])
def test_user_metadata_raises_on_a_cell_too_deep_to_decode(deep: Any) -> None:
    """None would send a dynamic_headers delivery out without its headers; on main json's
    RecursionError faulted it instead, so the delivery retried. Raised unchained, content-free."""
    with pytest.raises(MetadataTooDeepError) as info:
        user_metadata(deep)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None
    assert not getattr(info.value, "__notes__", None)
    assert not isinstance(info.value, ValueError)  # no ValueError arm may read it as "none"


def _encoder_overflows_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """json's encoder depth limit sits below its decoder's (measured: a 16_000-deep value decodes
    but will not re-encode on 3.14), but where exactly is stack-dependent, so it is simulated. The
    fault is scoped to the module under test, not the process-wide ``json.dumps``."""
    real = json.dumps
    calls = {"n": 0}

    def dumps(value: Any, **kwargs: Any) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RecursionError("maximum recursion depth exceeded while encoding a JSON object")
        return real(value, **kwargs)

    monkeypatch.setattr(metadata_module, "json", types.SimpleNamespace(dumps=dumps))


def test_user_metadata_raises_on_a_bag_too_deep_to_re_encode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stored = json.dumps({"user": {"k": "v"}})
    _encoder_overflows_once(monkeypatch)
    with pytest.raises(MetadataTooDeepError, match="re-encode") as info:
        user_metadata(stored)
    assert info.value.__context__ is None


async def test_a_dynamic_headers_read_faults_rather_than_proceeding_without_headers() -> None:
    """The delivery-side reader: it must not hand back None (deliver with no headers) for a deep cell."""

    class _Store:
        async def message_metadata_json(self, message_id: str) -> str:
            return _DEEP

    runner = RegistryRunner.__new__(RegistryRunner)
    runner.store = _Store()  # type: ignore[assignment]
    with pytest.raises(MetadataTooDeepError):
        await runner._user_metadata_for("m1")


def test_merge_user_metadata_refuses_when_existing_will_not_re_encode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refused rather than written back as the ops alone, which would erase the readable lineage."""
    stored = json.dumps({"correlation_id": "c", "user": {"old": "x"}})
    _encoder_overflows_once(monkeypatch)
    with pytest.raises(MetadataTooDeepError, match="re-encode") as info:
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
    assert decode_response_headers(_DEEP.encode("ascii")) == {}  # type: ignore[arg-type]
    assert user_metadata(b'{"user": {"k": "\xff"}}') is None  # type: ignore[arg-type]


def test_an_unreadable_cell_is_logged_without_its_content(caplog: pytest.LogCaptureFixture) -> None:
    marker = "SYNTHETIC-MRN-5550199"
    with caplog.at_level("WARNING", logger="messagefoundry.store.metadata"):
        assert user_metadata('{"user": {"k": "' + marker + '"') is None
        assert decode_response_headers("[" * 200_000 + '"' + marker) == {}
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
