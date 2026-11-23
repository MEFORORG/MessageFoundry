# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The off-box audit tee withholds the recovery wrap (owner ruling 2026-11-22).

A store minted under ``[store].key_provider = "host"`` keeps the store master key, wrapped under the
recovery key, in its audit genesis row (``audit_genesis_detail``). The row keeps it, behind the
audit read gates. The tee's copy of the row, which reaches the process's log handlers, the
off-box forwarder among them, and from the log file ``GET /logs/tail`` and the support bundle,
ships it as ``<withheld>``.

Before this, the copy of a genesis row in the in-heap or Transit scheme held no wrap only because
:func:`~messagefoundry.redaction.safe_text`'s length bound cut its detail before the wrap.
``test_the_wrap_is_withheld_where_the_length_bound_does_not_cut_it`` widens that bound; it fails
against the origin/main tee, whose line then holds the wrap (measured 2026-11-22). The chain case ``a_minted_genesis_rows_recovery_wrap_stays_out_of_the_log`` in
``tests/audit_chain_cases.py`` runs the end-to-end path on all three backends.
"""

from __future__ import annotations

import functools
import json
import logging
import sys
from math import nan as NAN

import pytest

from messagefoundry.redaction import _REDACT_WINDOW, safe_text
from messagefoundry.store import audit_tee
from messagefoundry.store import store as store_module
from messagefoundry.store.audit_tee import emit_audit_tee
from messagefoundry.store.crypto import STORE_ID_BYTES
from messagefoundry.store.custody import _WRAP_BYTES
from messagefoundry.store.store import AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail
from tests.test_audit_offbox_tee import _handlerless_process, _ListHandler

_STORE_ID = bytes(range(STORE_ID_BYTES))
_WRAP = bytes(range(0x40, 0x40 + _WRAP_BYTES))
_GENESIS = audit_genesis_detail("d2e36e3289bcfa5b", _STORE_ID, _WRAP)


def _tee(detail: str | None, action: str = AUDIT_KEY_EPOCH_ACTION) -> list[str]:
    handler = _ListHandler()
    logger = logging.getLogger("messagefoundry.audit")
    logger.addHandler(handler)
    try:
        emit_audit_tee(
            action=action,
            actor="system",
            channel_id=None,
            detail=detail,
            ts=1.0,
            row_id=1,
            seq=1,
            row_hash="a" * 64,
        )
    finally:
        logger.removeHandler(handler)
    return handler.messages


_REAL_LOADS = json.loads


def _refuse_the_withholding_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the tee's withholding parse, the one ``json.loads`` call given an ``object_hook``,
    raise ``RecursionError``, as ``json`` does on a nest too deep for the stack it reads on.

    Raised on purpose rather than by a real nest, because how deep ``json`` reads depends on the C
    stack the reading thread has left, not on ``sys.getrecursionlimit()``: a 30 000-deep nest,
    inside the redaction window, parsed on the ubuntu leg's main thread and was refused on
    Windows' (measured 2026-11-22, Python 3.14). ``tests/test_sandbox_codec.py``'s
    ``test_recursion_error_is_not_a_value_error`` records the same lesson. Every other call goes
    to the real ``json.loads``."""

    def loads(text: str, **kwargs: object) -> object:
        if "object_hook" in kwargs:
            raise RecursionError("simulated deep nesting")
        return _REAL_LOADS(text, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(json, "loads", loads)


def test_the_withheld_field_is_the_name_the_genesis_writer_uses() -> None:
    assert store_module._AUDIT_RECOVERY_WRAP_FIELD in audit_tee._WITHHELD_DETAIL_FIELDS
    assert json.loads(_GENESIS)["recovery_wrap"] == _WRAP.hex()  # the control: the row holds it


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_the_tee_line_withholds_the_wrap_and_keeps_the_rest(fmt: str, capsys) -> None:
    """Through the stdout handler ``serve`` installs, every filter on it."""
    with _handlerless_process():
        from messagefoundry.logging_setup import configure_logging

        configure_logging("INFO", fmt=fmt)
        capsys.readouterr()
        _tee(_GENESIS)
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if AUDIT_KEY_EPOCH_ACTION in ln]
    assert len(lines) == 1, out
    assert _WRAP.hex() not in out
    line = lines[0]
    inner = json.loads(line)["message"] if fmt == "json" else line.split("audit: ", 1)[1]
    shipped = json.loads(json.loads(inner)["detail"])
    assert shipped == {**json.loads(_GENESIS), "recovery_wrap": "<withheld>"}


def test_the_wrap_is_withheld_where_the_length_bound_does_not_cut_it(monkeypatch) -> None:
    """With ``safe_text`` given room for the whole genesis detail, the copy still holds no wrap."""
    monkeypatch.setattr(audit_tee, "safe_text", functools.partial(safe_text, limit=4096))
    (line,) = _tee(_GENESIS)
    assert _WRAP.hex() not in line
    assert json.loads(json.loads(line)["detail"])["recovery_wrap"] == "<withheld>"


def test_a_nested_wrap_is_withheld_and_the_rest_of_the_detail_kept() -> None:
    record = {"outer": {"recovery_wrap": _WRAP.hex(), "n": 1}, "list": [{"recovery_wrap": "x"}]}
    (line,) = _tee(json.dumps(record))
    assert _WRAP.hex() not in line
    withheld = {"recovery_wrap": "<withheld>"}
    assert json.loads(json.loads(line)["detail"]) == {
        "outer": {**withheld, "n": 1},
        "list": [withheld],
    }


@pytest.mark.parametrize(
    "detail",
    [
        # A name, a reason or text that only quotes the field name, and parses cleanly, is left
        # alone. The tee calls this on key epoch rows only, which no client writes.
        json.dumps({"username": "svc_recovery_wrap", "roles": ["Administrator"]}),
        json.dumps({"error": "no recovery_wrap"}),
        "not JSON: recovery_wrap",
    ],
    ids=["a-username", "a-value", "not-json"],
)
def test_a_detail_that_only_quotes_the_name_is_left_alone(detail: str) -> None:
    assert audit_tee._withhold_detail(detail) is detail


def test_a_detail_that_names_no_withheld_field_is_left_alone() -> None:
    detail = json.dumps({"n": 1, "store_id": _STORE_ID.hex()})
    assert audit_tee._withhold_detail(detail) is detail
    assert audit_tee._withhold_detail(None) is None


def test_a_held_key_is_re_encoded_with_json_dumps_defaults() -> None:
    """``json.dumps``'s defaults, so a line separator stays escaped and NaN stays NaN."""
    text = f"a{chr(0x2028)}b"
    kept = audit_tee._withhold_detail(json.dumps({"recovery_wrap": "x", "s": text, "f": NAN}))
    assert kept == json.dumps({"recovery_wrap": "<withheld>", "s": text, "f": NAN})
    assert kept is not None and chr(0x2028) not in kept


@pytest.mark.parametrize(
    "detail",
    [
        json.dumps({"inner": json.dumps({"recovery_wrap": _WRAP.hex(), "n": 1})}),
        json.dumps(json.dumps({"recovery_wrap": _WRAP.hex(), "n": 1})),
    ],
    ids=["in-a-string-value", "a-json-string"],
)
def test_a_json_text_held_in_a_string_is_withheld_too(detail: str) -> None:
    kept = audit_tee._withhold_detail(detail)
    assert kept is not None and _WRAP.hex() not in kept
    assert "<withheld>" in kept and '"n\\": 1' in kept


@pytest.mark.parametrize(
    ("detail", "too_deep"),
    [
        pytest.param(json.dumps({"recovery_wrap": _WRAP.hex()}), True, id="too-deep-to-read"),
        pytest.param(
            f'{{"recovery_wrap": "{_WRAP.hex()}", "n": {"1" * 5000}}}',
            False,
            id="an-integer-too-long-to-parse",
        ),
    ],
)
def test_a_fault_while_withholding_withholds_the_whole_detail(
    detail: str, too_deep: bool, monkeypatch, caplog
) -> None:
    if too_deep:
        _refuse_the_withholding_parse(monkeypatch)
    else:
        # The precondition: this interpreter refuses a 5000-digit integer, as by default.
        assert 0 < sys.get_int_max_str_digits() < 5000
    monkeypatch.setattr(audit_tee, "_WITHHOLD_FAULT_LOGGED", False)
    with caplog.at_level(logging.WARNING, logger=audit_tee.__name__):
        (line,) = _tee(detail)
    assert _WRAP.hex() not in line
    assert json.loads(json.loads(line)["detail"]) == {"withheld": "<withheld>"}
    assert any("could not withhold" in r.getMessage() for r in caplog.records)


def test_a_detail_over_the_window_that_names_the_field_ships_whole_unparsed(monkeypatch) -> None:
    """The parse is held to the redaction window the tee's other passes use."""
    detail = json.dumps({"recovery_wrap": _WRAP.hex(), "pad": "x" * _REDACT_WINDOW})
    loads: list[str] = []

    def counting(text: str, **_kwargs: object) -> object:
        loads.append(text)
        return {}

    monkeypatch.setattr(json, "loads", counting)
    assert audit_tee._withhold_detail(detail) == audit_tee._DETAIL_WITHHELD_WHOLE
    assert loads == []


def test_a_fault_in_the_withholding_warning_does_not_escape_the_tee(monkeypatch) -> None:
    """The row is committed before the tee runs, so no logging fault may reach its caller."""

    calls: list[object] = []

    def broken(*args: object, **_kwargs: object) -> None:
        calls.append(args)
        raise RuntimeError("a log filter failed")

    monkeypatch.setattr(audit_tee, "_WITHHOLD_FAULT_LOGGED", False)
    monkeypatch.setattr(audit_tee.log, "warning", broken)
    _refuse_the_withholding_parse(monkeypatch)
    (line,) = _tee(json.dumps({"recovery_wrap": _WRAP.hex()}))
    assert len(calls) == 1  # the control: the warning ran, and raised
    assert _WRAP.hex() not in line
    assert json.loads(json.loads(line)["detail"]) == {"withheld": "<withheld>"}


def test_the_withheld_action_is_the_key_epoch_action() -> None:
    assert audit_tee._KEY_EPOCH_ACTION == AUDIT_KEY_EPOCH_ACTION


@pytest.mark.parametrize(
    "detail",
    [
        json.dumps({"recovery_wrap": _WRAP.hex()}),
        json.dumps({"username": "1" * 4400 + "recovery_wrap", "reason": "x"}),
        json.dumps({"username": "u recovery_wrap", "pad": "x" * _REDACT_WINDOW}),
        "[" * 30_000 + '"recovery_wrap"' + "]" * 30_000,
    ],
    ids=["holds-the-key", "a-4400-digit-run", "over-the-window", "too-deep"],
)
def test_any_other_rows_detail_ships_as_without_the_withholding(detail: str, monkeypatch) -> None:
    """A client can write the name into a row; only the engine's key epoch rows are withheld
    from, so its copy ships as the tee shipped it before the placeholder existed. The control is
    the same row with the withheld field list emptied, which is that tee's path."""
    (line,) = _tee(detail, action="user.create")
    monkeypatch.setattr(audit_tee, "_WITHHELD_DETAIL_FIELDS", frozenset())
    (control,) = _tee(detail, action="user.create")
    assert line == control
    assert "<withheld>" not in line


def test_an_observer_is_passed_the_rows_own_detail(monkeypatch) -> None:
    seen: list[str | None] = []
    monkeypatch.setattr(audit_tee, "_OBSERVERS", (lambda *a: seen.append(a[-1]),))
    _tee(_GENESIS)
    assert seen == [_GENESIS]
