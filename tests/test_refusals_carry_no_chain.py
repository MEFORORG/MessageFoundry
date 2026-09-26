# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refusals that withhold content keep it off the exception chain too (BACKLOG #1796).

``tests/test_from_none_is_not_redaction.py`` held three sites as UNSAFE. Each raised its refusal
inside the handler, so the caught error stayed on ``__context__`` (``from None``) or ``__cause__``
(``from exc``), and anything that walks the chain would have read what the message withheld. Each
would have leaked on first deployment:

* the operator resend's 4xx (``api/app.py`` ``_guard_resubmission``) over an ``IngressGuardError``
  whose own cause, from ``pipeline/ingress_guards.py``, was a Unicode error holding the WHOLE body;
* ``transports/database.py`` ``_lookup_max_rows``, where ``int()``'s ``ValueError`` quotes the
  env()-resolved value the message says it withholds;
* ``transports/rest.py`` ``refuse_url_credentials``, where ``urlsplit().port``'s ``ValueError``
  quotes the port field, which is the password in ``https://svc:PW/path``.

Every test here fails against the pre-fix code. Each asserts the planted value is reachable from
NEITHER the message NOR anything on ``__cause__``/``__context__``, walking both links at every step.
The walker is controlled first, and each refusal has a control beside it that still admits.
Synthetic values only.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from messagefoundry.api import app as api_app
from messagefoundry.config.models import ContentType
from messagefoundry.config.wiring import InboundConnection
from messagefoundry.parsing.peek import HL7PeekError
from messagefoundry.pipeline import ingress_guards
from messagefoundry.pipeline.ingress_guards import (
    IngressGuardError,
    admit_resubmitted_body,
    decode_ingress,
)
from messagefoundry.transports.database import _lookup_max_rows
from messagefoundry.transports.http_auth import HttpAuthError
from messagefoundry.transports.rest import refuse_url_credentials
from tests.test_ingress_guard_parity import _inbound

#: Stands in for a body, a resolved setting or a password. Letters only, so every site accepts it.
_PLANTED = "SYNTHETICPLANTED"
_ADT = "MSH|^~\\&|A|B|C|D|20260926||ADT^A01|1|P|2.5\rPID|1||" + _PLANTED


def _chain(exc: BaseException) -> list[BaseException]:
    """Every exception reachable from ``exc`` by ``__cause__`` or ``__context__``, ``exc`` first.

    Both links at every step: following ``__cause__ or __context__`` skips a context whenever a
    cause is set, which is exactly the shape a ``from exc`` inside a handler produces."""
    seen: list[BaseException] = []
    stack: list[BaseException | None] = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or any(cur is s for s in seen):
            continue
        seen.append(cur)
        stack += [cur.__cause__, cur.__context__]
    return seen


def _holders(exc: BaseException) -> list[str]:
    """The type names of every exception on ``exc``'s chain whose text, args or attributes hold the
    planted value. ``.object`` is read by name, since a Unicode error keeps it off ``__dict__``."""
    hits = []
    for e in _chain(exc):
        fields = (str(e), repr(e.args), repr(getattr(e, "object", None)), repr(vars(e)))
        if any(_PLANTED in f for f in fields):
            hits.append(type(e).__name__)
    return hits


def _assert_bare(exc: BaseException) -> None:
    assert _chain(exc) == [exc], [type(e).__name__ for e in _chain(exc)]
    assert _holders(exc) == []


def test_the_walker_finds_what_from_none_leaves_behind() -> None:
    """Control: the pre-fix shape is found, so a clean reading below means clean."""
    with pytest.raises(ValueError) as caught:
        try:
            (_PLANTED + chr(0xE9)).encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("refused at position N") from None
    assert _holders(caught.value) == ["UnicodeEncodeError"]
    with pytest.raises(AssertionError):
        _assert_bare(caught.value)


# ---- pipeline/ingress_guards.py: no refusal chains the error it replaces -----------------------


def test_a_resubmission_the_charset_cannot_hold_keeps_no_body_on_the_chain() -> None:
    with pytest.raises(IngressGuardError) as caught:
        admit_resubmitted_body(_ADT + chr(0xE9), _inbound(encoding="ascii"))
    assert caught.value.phase == "decode"
    assert caught.value.reason.startswith("encode error (ascii): ")
    _assert_bare(caught.value)


def test_an_undecodable_body_keeps_no_body_on_the_chain() -> None:
    body = (_PLANTED + chr(0xE9)).encode("latin-1")
    with pytest.raises(IngressGuardError) as caught:
        decode_ingress(body, _inbound(content_type=ContentType.JSON))
    assert caught.value.phase == "decode"
    _assert_bare(caught.value)


def test_a_parse_refusal_keeps_what_the_parser_quoted_off_the_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """python-hl7's own error sits under ``HL7PeekError``, and it can quote the body it failed on."""

    class _Refusing:
        @staticmethod
        def parse(text: str, *, max_bytes: int | None) -> None:
            try:
                raise ValueError(text)
            except ValueError as exc:
                raise HL7PeekError("could not parse HL7 message") from exc

    monkeypatch.setattr(ingress_guards, "Peek", _Refusing)
    with pytest.raises(IngressGuardError) as caught:
        admit_resubmitted_body(_ADT, _inbound())
    assert caught.value.phase == "parse"
    assert caught.value.reason == "parse error: HL7PeekError: could not parse HL7 message"
    _assert_bare(caught.value)


def test_an_admitted_resubmission_is_unchanged() -> None:
    """Control: a body the guards accept still comes back in the form the listener commits."""
    assert admit_resubmitted_body(_ADT, _inbound()) == _ADT


# ---- api/app.py _guard_resubmission: the 4xx carries no chain -----------------------------------


class _AuditSink:
    def __init__(self) -> None:
        self.rows: list[tuple[str, dict[str, object]]] = []

    async def record_audit(self, action: str, **kwargs: object) -> None:
        self.rows.append((action, kwargs))


async def _guard(raw: str, inbound: InboundConnection | None, sink: _AuditSink) -> str:
    engine: Any = SimpleNamespace(store=sink)
    identity: Any = SimpleNamespace(username="operator")
    request = Request({"type": "http", "client": ("127.0.0.1", 50000), "headers": []})
    return await api_app._guard_resubmission(
        engine,
        identity,
        request,
        raw=raw,
        inbound=inbound,
        action="resend.refused",
        channel_id="in",
        detail={"id": "m1"},
    )


async def test_the_resubmission_4xx_carries_no_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """The API half alone: a guard error that DOES carry content must not ride under the 4xx."""

    async def _refuse(raw: str, inbound: InboundConnection | None) -> str:
        try:
            raise ValueError(raw)
        except ValueError as exc:
            raise IngressGuardError("parse error: withheld", phase="parse") from exc

    monkeypatch.setattr(api_app, "admit_resubmission", _refuse)
    sink = _AuditSink()
    with pytest.raises(HTTPException) as caught:
        await _guard(_ADT, None, sink)
    assert caught.value.status_code == 422
    assert caught.value.detail == "parse error: withheld"
    _assert_bare(caught.value)
    [(action, row)] = sink.rows
    assert action == "resend.refused"
    assert json.loads(str(row["detail"])) == {
        "id": "m1",
        "phase": "parse",
        "reason": "parse error: withheld",
    }


async def test_the_resubmission_4xx_end_to_end_carries_no_body() -> None:
    with pytest.raises(HTTPException) as caught:
        await _guard(_ADT + chr(0xE9), _inbound(encoding="ascii"), _AuditSink())
    assert caught.value.status_code == 422
    _assert_bare(caught.value)


async def test_an_admitted_resubmission_passes_the_api_guard() -> None:
    """Control: the hoisted raise is reached only on a refusal."""
    sink = _AuditSink()
    assert await _guard(_ADT, _inbound(), sink) == _ADT
    assert sink.rows == []


# ---- transports/database.py _lookup_max_rows ------------------------------------------------------


@pytest.mark.parametrize("value", [_PLANTED, f"1{_PLANTED}", f" 1 {_PLANTED}"])
def test_a_refused_max_rows_keeps_the_value_off_the_chain(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        _lookup_max_rows(value, "LK_1796")
    assert "value withheld" in str(caught.value)
    _assert_bare(caught.value)


def test_a_numeric_max_rows_is_still_read() -> None:
    """Control: the refusal fires on the value, not on every string."""
    assert _lookup_max_rows("25", "LK_1796") == 25
    assert _lookup_max_rows(0, "LK_1796") is None


# ---- transports/rest.py refuse_url_credentials ----------------------------------------------------


def test_a_password_read_as_a_port_stays_off_the_chain() -> None:
    with pytest.raises(HttpAuthError) as caught:
        refuse_url_credentials(f"https://svc:{_PLANTED}/path", "url", error=HttpAuthError)
    assert "not a number from 0 to 65535" in str(caught.value)
    _assert_bare(caught.value)


def test_a_numeric_port_is_still_admitted() -> None:
    """Control: the refusal fires on a non-numeric port, not on every explicit one."""
    refuse_url_credentials("https://svc.example.invalid:8443/path", "url")
