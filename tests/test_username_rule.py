# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5521: the username a new local account may take.

``POST /users`` accepted any name up to the length cap: empty, white space alone, control
characters and NUL, and the audit trail's synthetic actor names. The rule now lives in
``messagefoundry/auth/usernames.py``. ``AuthService.create_local_user`` applies it before anything
is generated or written, and ``UserCreateRequest`` mirrors it. Each refusal has a control: a name
next to it that passes.
"""

from __future__ import annotations

import ast
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from starlette.requests import Request

from messagefoundry.api import create_app
from messagefoundry.api.auth_models import UserCreateRequest
from messagefoundry.api.security import DIRECTORY_GRANTED_BY
from messagefoundry.auth import Role
from messagefoundry.auth.service import InvalidUsername
from messagefoundry.auth.usernames import RESERVED_ACTOR_FORMS, username_refusal
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import _add, _auth, _login, _reauth, _service

REFUSED = [
    "",
    " ",
    "   ",
    "\t",
    "a\x00b",
    "a\x07b",
    "a\x1bb",
    "a\x7fb",
    "a\x85b",
    "a\x9fb",
    " bob",
    "bob ",
    "bob\n",
    "\xa0bob",
    "system",
    "System",
    "SYSTEM",
    "system:",
    "system:rotate-key",
    "system:cluster-convergence",
    "<oidc>",
    "<kerberos>",
    "<reconciler>",
    "<>",
    "cli:Administrator",
    "CLI:root",
    # Format, separator and surrogate characters, and a fullwidth spelling of a reserved name.
    "sys\u200btem",
    "\ufeffsystem",
    "\u202esystem",
    "a\u2028b",
    "a\ud800b",
    "\uff53\uff59\uff53\uff54\uff45\uff4d",
    # Default-ignorable code points outside the control categories: a combining grapheme joiner and
    # a variation selector that leave "system" reading as "system", and a name of Hangul fillers.
    "sys\u034ftem",
    "system\ufe0f",
    "\u3164",
    "\uffa0bob",
    "bob\U000e0100",
    # Blank glyphs from no control or ignorable class, alone and at an edge, where the white-space
    # check does not see them: the Braille pattern blank, the null notehead, the Khitan filler.
    "\u2800",
    "bob\u2800",
    "\u2800bob",
    "\U0001d159",
    "bob\U00016fe4",
    # BACKLOG #5520 item 37: the directory sign-in's synthetic granted_by marker,
    # api.security.DIRECTORY_GRANTED_BY, which the "<...>" form refuses.
    "<directory>",
]

#: BACKLOG #5520 items 3, 14 and 35: reserved forms spelled with a lookalike of their colon or
#: angle brackets that NFKC leaves as it is. Each renders as a reserved form, so each is refused.
LOOKALIKE_DELIMITERS = [
    "cli\u2236root",  # RATIO
    "cli\ua789root",  # MODIFIER LETTER COLON
    "system\u02f8rotate-key",  # MODIFIER LETTER RAISED COLON
    "SYSTEM\u2236x",
    "\u2039oidc\u203a",  # SINGLE LEFT/RIGHT-POINTING ANGLE QUOTATION MARK
    "\u3008kerberos\u3009",  # LEFT/RIGHT ANGLE BRACKET (CJK)
    "\u2329reconciler\u232a",  # LEFT/RIGHT-POINTING ANGLE BRACKET, which NFKC takes to U+3008/9
    "\u02c2directory\u02c3",  # MODIFIER LETTER LEFT/RIGHT ARROWHEAD
    "\u27e8oidc\u27e9",  # MATHEMATICAL LEFT/RIGHT ANGLE BRACKET
    "\u2039oidc>",
    "cli" + chr(0x0903) + "root",  # DEVANAGARI SIGN VISARGA
    "cli" + chr(0x0A83) + "root",  # GUJARATI SIGN VISARGA
    "cli" + chr(0x17D6) + "root",  # KHMER SIGN CAMNUC PII KUUH
    chr(0x1D236) + "oidc" + chr(0x1D237),  # GREEK INSTRUMENTAL NOTATION SYMBOL-40 and SYMBOL-42
]

#: The controls: names beside each refused form that the rule must leave alone.
ACCEPTED = [
    "bob",
    "jane.doe",
    "a b",
    "systems",
    "mysystem",
    "system-admin",
    "sys:tem",
    "<bob",
    "bob>",
    "directory",
    "Jos\xe9",
    "cli",
    "client",
    "sysadmin",
    # What the module docstring says the rule admits: a space separator inside the name.
    "a\u3000b",
    # Controls for LOOKALIKE_DELIMITERS: a lookalike delimiter outside a reserved form.
    "sys\u2236tem",
    "\u2039bob",
    "bob\u203a",
    # Letters the confusables data lists for "<" and ">", left out of the table: a Canadian
    # syllabics name that starts with PA and ends with PO is not a "<...>" form.
    chr(0x1438) + chr(0x140A) + chr(0x1433),
]


@pytest.mark.parametrize("name", REFUSED)
def test_the_rule_refuses(name: str) -> None:
    assert username_refusal(name) is not None


@pytest.mark.parametrize("name", ACCEPTED)
def test_the_rule_accepts(name: str) -> None:
    assert username_refusal(name) is None


@pytest.mark.parametrize("name", LOOKALIKE_DELIMITERS)
def test_the_rule_refuses_a_reserved_form_with_a_lookalike_delimiter(name: str) -> None:
    """BACKLOG #5520 items 3, 14 and 35. The controls are ACCEPTED's lookalikes outside a form."""
    assert username_refusal(name) is not None
    with pytest.raises(ValidationError):
        UserCreateRequest(username=name, email="x@example.test", roles=[])


#: BACKLOG #5519: reserved forms spelled with accented letters. A store or audit column that
#: compares accent-insensitively finds each as the reserved form, so each is refused. Precomposed
#: and combining spellings both, and a dotted capital I, whose case fold carries a combining dot.
ACCENTED_RESERVED = [
    "s\xfdst\xe9m",  # precomposed y with acute, e with acute
    "sy\u0301stem",  # y + COMBINING ACUTE ACCENT
    "syst\xe8m:rotate-key",
    "cl\xed:root",
    "CL\u0130:root",  # LATIN CAPITAL LETTER I WITH DOT ABOVE
    "<oidc>\u0332",  # trailing COMBINING LOW LINE
]

#: Controls for ACCENTED_RESERVED: accented names that are not a reserved form once unaccented.
ACCENTED_ACCEPTED = ["Jos\xe9", "s\xfdstems", "cl\xedent", "Ren\xe9e"]


@pytest.mark.parametrize("name", ACCENTED_RESERVED)
def test_the_rule_refuses_a_reserved_form_spelled_with_accents(name: str) -> None:
    """BACKLOG #5519: the accent-insensitive collation case of the reserved-name check."""
    assert username_refusal(name) is not None
    with pytest.raises(ValidationError):
        UserCreateRequest(username=name, email="x@example.test", roles=[])


@pytest.mark.parametrize("name", ACCENTED_ACCEPTED)
def test_the_rule_accepts_an_accented_name_outside_a_reserved_form(name: str) -> None:
    assert username_refusal(name) is None


def test_the_directory_marker_is_a_reserved_form() -> None:
    """BACKLOG #5520 item 37: the comment on DIRECTORY_GRANTED_BY says the rule refuses it."""
    assert DIRECTORY_GRANTED_BY in REFUSED
    assert username_refusal(DIRECTORY_GRANTED_BY) is not None
    # Control: the bare word is not reserved, as the module docstring says.
    assert username_refusal("directory") is None


def _literal_actors() -> list[tuple[str, str]]:
    """Every synthetic audit actor the engine package spells as a literal: a constant, or the
    constant head of an f-string, passed as an ``actor=`` keyword or as an ``actor`` parameter's
    default, and the module constants named ``*_ACTOR`` or ``*_GRANTED_BY``."""
    root = Path(__file__).resolve().parents[1] / "messagefoundry"
    found: list[tuple[str, str]] = []

    def text(node: ast.expr | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr) and node.values:
            return text(node.values[0])
        return None

    for path in sorted(root.rglob("*.py")):
        where = path.relative_to(root.parent).as_posix()
        for node in ast.walk(ast.parse(path.read_text("utf-8"))):
            values: list[ast.expr | None] = []
            if isinstance(node, ast.Call):
                values += [kw.value for kw in node.keywords if kw.arg == "actor"]
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                positional = node.args.posonlyargs + node.args.args
                with_default = positional[len(positional) - len(node.args.defaults) :]
                pairs: list[tuple[ast.arg, ast.expr | None]] = list(
                    zip(with_default, node.args.defaults, strict=True)
                )
                pairs += zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
                values += [default for arg, default in pairs if arg.arg == "actor"]
            elif isinstance(node, ast.Assign | ast.AnnAssign):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(
                    isinstance(t, ast.Name) and t.id.endswith(("_ACTOR", "_GRANTED_BY"))
                    for t in targets
                ):
                    values.append(node.value)
            for value in values:
                literal = text(value)
                if literal is not None:
                    found.append((where, literal))
    return found


def test_every_literal_audit_actor_is_a_reserved_form() -> None:
    """BACKLOG #5520 item 3: a census for RESERVED_ACTOR_FORMS. Each synthetic actor the engine
    package spells as a literal where ``_literal_actors`` looks must be a form the rule refuses, so
    a new literal actor form there fails here until it is added to the rule. An actor built at run
    time, or passed under another name, is not seen. The positive control: the census finds the
    forms the rule's comment names."""
    actors = _literal_actors()
    literals = {literal for _, literal in actors}
    for expected in ("system", "system:rotate-key", "<oidc>", "<kerberos>", "<reconciler>", "cli:"):
        assert expected in literals, (expected, sorted(literals))
    assert DIRECTORY_GRANTED_BY in literals
    assert actors
    unreserved = [(where, lit) for where, lit in actors if not RESERVED_ACTOR_FORMS.fullmatch(lit)]
    assert not unreserved, unreserved


@pytest.mark.parametrize("name", REFUSED)
def test_the_request_model_mirrors_the_rule(name: str) -> None:
    with pytest.raises(ValidationError):
        UserCreateRequest(username=name, email="a@example.org")


@pytest.mark.parametrize("name", ACCEPTED)
def test_the_request_model_accepts_what_the_rule_accepts(name: str) -> None:
    assert UserCreateRequest(username=name, email="a@example.org").username == name


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "usernames.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


@pytest.mark.parametrize("name", ["system", "<oidc>", "a\x00b", "   ", " bob"])
async def test_the_service_refuses_before_anything_is_generated_or_written(
    engine: Engine, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)

    async def no_credential(*args: Any, **kwargs: Any) -> str:
        raise AssertionError("a credential was generated for a refused name")

    monkeypatch.setattr(service, "_generate_issued_credential", no_credential)
    audits_before = len(await engine.store.list_audit(limit=100_000))
    with pytest.raises(InvalidUsername):
        await service.create_local_user(
            username=name, display_name=None, email="a@example.org", roles=[], actor="t"
        )
    assert await engine.store.list_users() == []
    assert len(await engine.store.list_audit(limit=100_000)) == audits_before


async def test_post_users_refuses_a_reserved_name_and_writes_nothing(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 1))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        token = (await _login(c, "root")).json()["token"]
        _, token = await _reauth(c, token)
        refused = await c.post(
            "/users", json={"username": "system", "email": "a@example.org"}, headers=_auth(token)
        )
        control = await c.post(
            "/users", json={"username": "sysop", "email": "a@example.org"}, headers=_auth(token)
        )
    assert refused.status_code == 422, refused.text
    assert await engine.store.get_user_by_username("system") is None
    assert control.status_code == 201, control.text


async def test_the_route_answers_the_services_refusal_with_400(engine: Engine) -> None:
    """The request model refuses first on the JSON plane, so the route's own mapping is driven
    past it: a body built without validation reaches the service, which refuses, and the route
    answers 400, not 500."""
    from fastapi import HTTPException
    from fastapi.routing import APIRoute

    service = await _service(engine)
    app = create_app(engine, auth=service)
    endpoint = next(
        r.endpoint
        for r in app.routes
        if isinstance(r, APIRoute) and r.path == "/users" and "POST" in (r.methods or ())
    )
    body = UserCreateRequest.model_construct(
        username="system", display_name=None, email="a@example.org", roles=[]
    )
    request = Request({"type": "http", "client": ("127.0.0.1", 1), "headers": []})
    with pytest.raises(HTTPException) as refused:
        await endpoint(
            body=body, request=request, service=service, identity=SimpleNamespace(username="root")
        )
    assert refused.value.status_code == 400
    assert await engine.store.get_user_by_username("system") is None
