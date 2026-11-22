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
``test_the_wrap_is_withheld_where_the_length_bound_does_not_cut_it`` shows that bound was all that
kept it out. The chain case ``a_minted_genesis_rows_recovery_wrap_stays_out_of_the_log`` in
``tests/audit_chain_cases.py`` runs the end-to-end path on all three backends.
"""

from __future__ import annotations

import functools
import json
import logging

import pytest

from messagefoundry.redaction import safe_text
from messagefoundry.store import audit_tee
from messagefoundry.store import store as store_module
from messagefoundry.store.audit_tee import emit_audit_tee
from messagefoundry.store.crypto import STORE_ID_BYTES
from messagefoundry.store.store import AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail
from tests.test_audit_offbox_tee import _handlerless_process

_STORE_ID = bytes(range(STORE_ID_BYTES))
_WRAP = bytes(range(0x40, 0x40 + 65))
_GENESIS = audit_genesis_detail("d2e36e3289bcfa5b", _STORE_ID, _WRAP)


class _Lines(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def _tee(detail: str | None) -> list[str]:
    handler = _Lines()
    logger = logging.getLogger("messagefoundry.audit")
    logger.addHandler(handler)
    try:
        emit_audit_tee(
            action=AUDIT_KEY_EPOCH_ACTION,
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
    return handler.lines


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


@pytest.mark.parametrize(
    "detail",
    [
        json.dumps({"outer": {"recovery_wrap": _WRAP.hex()}, "list": [{"recovery_wrap": "x"}]}),
        # Names the field but is not JSON, or nests too deep to read: the whole detail is withheld.
        f'{{"recovery_wrap": "{_WRAP.hex()}"',
        "[" * 100_000 + f'"recovery_wrap {_WRAP.hex()}"' + "]" * 100_000,
        # Or quotes the name where it is not a key: the whole detail is withheld.
        json.dumps({"error": f"recovery_wrap={_WRAP.hex()}"}),
        json.dumps(f"recovery_wrap {_WRAP.hex()}"),
    ],
    ids=["nested", "unparsed", "deep", "in-a-value", "a-json-string"],
)
def test_a_detail_naming_the_field_anywhere_ships_without_its_value(detail: str) -> None:
    (line,) = _tee(detail)
    assert _WRAP.hex() not in line
    assert "<withheld>" in line


def test_a_detail_that_names_no_withheld_field_is_left_alone() -> None:
    detail = json.dumps({"n": 1, "store_id": _STORE_ID.hex()})
    assert audit_tee._withhold_detail(detail) is detail
    assert audit_tee._withhold_detail(None) is None


def test_an_observer_is_passed_the_rows_own_detail(monkeypatch) -> None:
    seen: list[str | None] = []
    monkeypatch.setattr(audit_tee, "_OBSERVERS", (lambda *a: seen.append(a[-1]),))
    _tee(_GENESIS)
    assert seen == [_GENESIS]
