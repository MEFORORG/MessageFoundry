# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``store/metadata.py`` JSON hardening: no bare NaN/Infinity token from the reference sink (BACKLOG
#6711), and deeply nested JSON never escapes the three decoders as json's ``RecursionError`` (BACKLOG
#6712): the header decoder reads it as malformed, while ``merge_user_metadata`` and ``user_metadata``
raise ``MetadataTooDeepError``."""

from __future__ import annotations

import json
import types
from datetime import date
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


def test_a_nested_value_too_deep_to_encode_is_refused_as_unencodable() -> None:
    """The dry-run catches only TypeError, so json's RecursionError must arrive as one too. A real
    value too deep for the encoder, so no process-wide ``json.dumps`` is patched (BACKLOG #6711)."""
    deep: Any = "leaf"
    for _ in range(200_000):
        deep = [deep]
    with pytest.raises(TypeError, match="nested too deep") as info:
        encode_reference_value(deep)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None


@pytest.mark.parametrize(
    ("value", "cause"),
    [
        ({"rate": float("nan")}, "a non-finite float"),
        (10**5000, "an oversized int"),
        ({"k": object()}, "cannot serialize a object value"),
    ],
    ids=["non-finite", "oversized-int", "unencodable-type"],
)
def test_the_refusal_names_the_kind_of_value_and_carries_no_notes(value: Any, cause: str) -> None:
    """BACKLOG #6711 items 4 and 6: the error's own text names the kind of value, and json's notes
    naming the dict keys on the path ride on nothing."""
    with pytest.raises(TypeError, match=cause) as info:
        encode_reference_value(value)
    assert not getattr(info.value, "__notes__", None)
    assert info.value.__cause__ is None and info.value.__context__ is None


def test_a_circular_value_names_its_cause() -> None:
    loop: list[Any] = []
    loop.append(loop)
    with pytest.raises(TypeError, match="a circular value"):
        encode_reference_value(loop)


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


def test_a_non_text_cell_reads_as_empty_and_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    """The TypeError arm the old decoders carried: a cell that is not text or bytes still reads as
    no metadata, and is now logged by its type name."""
    cell: Any = 12345
    with caplog.at_level("WARNING", logger="messagefoundry.store.metadata"):
        assert decode_response_headers(cell) == {}
        assert user_metadata(cell) is None
        assert json.loads(merge_user_metadata(cell, [("k", "v")])) == {"user": {"k": "v"}}
    assert any("not text: int" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview], ids=["bytes", "bytearray", "view"])
def test_a_bytes_cell_keeps_its_lineage_through_merge(wrap: Any) -> None:
    """``json.loads`` parsed a bytes cell before this branch; it still must, or the merge below would
    write the ops alone over the lineage. A memoryview cell reads the same way (BACKLOG #6712)."""
    cell: Any = wrap(json.dumps({"correlation_id": "c", "user": {"old": "x"}}).encode("utf-8"))
    assert json.loads(merge_user_metadata(cell, [("k", "v")])) == {
        "correlation_id": "c",
        "user": {"old": "x", "k": "v"},
    }
    assert json.loads(user_metadata(cell) or "null") == {"old": "x"}
    assert decode_response_headers(wrap(b'{"Location": "/x"}')) == {"Location": "/x"}


def test_a_malformed_bytes_cell_reads_as_empty() -> None:
    """The hardening still holds for bytes: the header decoder reads deep nesting as malformed, and
    every decoder reads a bad UTF-8 byte as malformed."""
    assert decode_response_headers(_DEEP.encode("ascii")) == {}
    assert user_metadata(b'{"user": {"k": "\xff"}}') is None


def test_an_unreadable_cell_is_logged_without_its_content(caplog: pytest.LogCaptureFixture) -> None:
    marker = "SYNTHETIC-MRN-5550199"
    with caplog.at_level("WARNING", logger="messagefoundry.store.metadata"):
        assert user_metadata('{"user": {"k": "' + marker + '"') is None
        assert decode_response_headers("[" * 200_000 + '"' + marker) == {}
    assert len(caplog.records) == 2
    for record in caplog.records:
        # The message, its arguments and any attached exception: none may carry the content.
        assert marker not in record.getMessage()
        assert all(marker not in str(arg) for arg in (record.args or ()))
        assert record.exc_info is None and record.exc_text is None


def test_every_malformed_cell_read_as_empty_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Each malformed cell read as ``{}`` leaves its own WARNING, as on main: none is held back."""
    with caplog.at_level("WARNING", logger="messagefoundry.store.metadata"):
        for _ in range(5):
            assert user_metadata('{"user": ') is None
        assert decode_response_headers("{") == {}
    assert len(caplog.records) == 6


def test_a_released_memoryview_cell_reads_as_empty(caplog: pytest.LogCaptureFixture) -> None:
    """A released memoryview reads as no metadata in every decoder, as on main."""
    view = memoryview(json.dumps({"user": {"k": "v"}}).encode("utf-8"))
    view.release()
    with caplog.at_level("WARNING", logger="messagefoundry.store.metadata"):
        assert decode_response_headers(view) == {}
        assert user_metadata(view) is None
        assert json.loads(merge_user_metadata(view, [("k", "v")])) == {"user": {"k": "v"}}
    assert any("released memoryview" in r.getMessage() for r in caplog.records)


def test_a_foreign_type_error_names_only_its_class() -> None:
    """A TypeError that is not the default's own refusal may carry a value in its text, so the
    refusal names its class only (BACKLOG #6711)."""

    class _Leaky(Decimal):
        def __str__(self) -> str:
            raise TypeError("SYNTHETIC-MRN-5550199")

    with pytest.raises(TypeError, match=r"an unencodable value \(TypeError\)") as info:
        encode_reference_value({"k": _Leaky("1")})
    assert "SYNTHETIC" not in str(info.value)


def _chain(exc: BaseException | None) -> list[BaseException]:
    """``exc`` and every exception on its cause and context chain."""
    seen: list[BaseException] = []
    while exc is not None and all(exc is not s for s in seen):
        seen.append(exc)
        exc = exc.__cause__ or exc.__context__
    return seen


def test_naming_the_cause_chains_nothing_to_json_s_error() -> None:
    """A refusal names its kind after json's handler has exited and encodes nothing a second time,
    so a value that would raise on a second pass cannot chain json's error, whose notes name the
    key, to whatever that pass raised (BACKLOG #6711)."""

    class _Overflowing(date):
        def isoformat(self) -> str:
            raise OverflowError("synthetic")

    marker = "SYNTHETIC-KEY-123"
    with pytest.raises(TypeError, match="a non-finite float") as info:
        encode_reference_value({marker: float("nan"), "z": _Overflowing(2026, 1, 1)})
    for exc in _chain(info.value):
        assert marker not in str(exc)
        assert all(marker not in note for note in getattr(exc, "__notes__", ()))
    assert info.value.__cause__ is None and info.value.__context__ is None


@pytest.mark.parametrize(
    "value",
    [{"a": float("nan"), "b": object()}, {"a": float("nan"), "b": 10**5000}],
    ids=["beside-an-unencodable-type", "beside-an-oversized-int"],
)
def test_a_mixed_value_names_the_kind_json_stopped_on(value: Any) -> None:
    with pytest.raises(TypeError, match="a non-finite float"):
        encode_reference_value(value)


def test_a_coercion_error_is_not_read_as_one_of_json_s_own() -> None:
    """A ValueError a coercion raises through json is named generically, whatever its text."""

    class _Digits(date):
        def isoformat(self) -> str:
            raise ValueError("synthetic: too many digits")

    with pytest.raises(TypeError, match="it holds an unencodable value$"):
        encode_reference_value({"k": _Digits(2026, 1, 1)})


def test_the_unreadable_cell_warning_names_its_row(caplog: pytest.LogCaptureFixture) -> None:
    """The WARNING names the row's reference, cut and scrubbed."""
    with caplog.at_level("WARNING", logger="messagefoundry.store.metadata"):
        assert user_metadata('{"user": ', row_id="0123456789abcdef0123") is None
        assert user_metadata('{"user": ', row_id="bad\nid") is None
    first, second = (r.getMessage() for r in caplog.records)
    assert "message 0123456789ab " in first
    assert "message bad?id " in second


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
