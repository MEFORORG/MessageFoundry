# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A sign-in ends the session its presented token BECAME, for a bounded time (vault BACKLOG #3028).

Engine PR 2028 (BACKLOG #2146) made the supersession's read and revoke one store operation, so a
rotation that starts after it fails closed. It left one case open: an elevation that FINISHED before
it. The presented hash then named no session, the supersession ended nothing, and the session lived
on under its new token. A rotation now records a link from the retired hash to its successor, and
the supersession follows that link to the live end, inside its own store transaction.

These pin the service half. The store half, on every backend, is
``tests/_session_rotation_contract.py``'s ``assert_session_lineage_contract``.
"""

from __future__ import annotations

import ast
import asyncio
import re
import sqlite3
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import closing
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.oidc import FederatedPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.store.session_lineage import LINEAGE_MAX_HOPS, revoke_through_lineage
from messagefoundry.store.store import MessageStore, SessionRecord
from tests._ast_sites import code_names, code_strings, parse_source
from tests.test_session_supersession import (
    PW,
    _live,
    _oidc_settings,
    _service,
    _superseded,
    _token,
)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "lineage.db")
    yield s
    await s.close()


async def _elevate(service: AuthService, token: str) -> str:
    """Complete a real password step-up on ``token`` and return the token it was rotated to."""
    identity = await service.identity_for_token(token, activity=False)
    assert identity is not None
    elevation = await service.reauth(identity, PW, token=token)
    assert elevation.ok and elevation.token is not None, elevation
    assert elevation.token != token
    return elevation.token


async def test_an_elevation_that_finished_before_the_sign_in_does_not_keep_the_session_live(
    store: MessageStore,
) -> None:
    # Closing item 3 of the row. The elevation runs to completion, so its rotation has committed
    # before the sign-in's supersession statement runs. The browser still presents the OLD token,
    # which now names no session row.
    service = await _service(store)
    prior = await _token(service)
    rotated = await _elevate(service, prior)
    assert await store.get_session(hash_token(prior)) is None, "the rotation did not retire it"
    assert await _live(service, rotated)

    new = await _token(service, supersedes=prior)

    assert not await _live(service, rotated), (
        "the sign-in replaced this browser's session, but the session lives on under its new token"
    )
    assert await _live(service, new)
    assert await _superseded(store) == [
        {
            "scope": "superseded",
            "session": hash_token(rotated)[:12],
            "presented": hash_token(prior)[:12],
            "actor": "op",
        }
    ]


async def test_an_elevation_during_the_identity_provider_round_trip_is_followed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The federated leg, the widest window: the START leg stages the presented hash, an elevation
    # in another tab rotates the session while the browser is at the identity provider, and the
    # cookie-less callback supersedes the staged hash. The IdP exchange is replaced at the one seam
    # the service calls, as tests/test_session_supersession.py does.
    service = await _service(store, **_oidc_settings())
    await service.set_ad_group_map([("cn=mf-ops,dc=x", Role.OPERATOR.value)], actor="admin")
    jdoe_id = uuid4().hex
    await store.create_user(
        user_id=jdoe_id,
        username="jdoe",
        auth_provider="ad",
        directory_object_id="guid-jdoe",
        password_generated=False,
    )
    await service.bind_federated_subject(
        jdoe_id, "S-1-5-21-fed", expected_issuer=None, expected_subject=None, actor="admin"
    )
    prior = await _token(service)

    def _exchange(*_a: object, **_k: object) -> FederatedPrincipal:
        return FederatedPrincipal(
            username="jdoe",
            subject="S-1-5-21-fed",
            issuer="https://idp.example",
            amr=("pwd", "mfa"),
            acr=None,
            expires_at=time.time() + 600,
            auth_time=time.time(),
        )

    monkeypatch.setattr(service, "_exchange_and_validate", _exchange)
    flow_id, url = await service.begin_oidc_login(
        client=None, public_origin="https://ops.example", prior_session=prior
    )
    rotated = await _elevate(service, prior)  # finishes while the browser is at the IdP
    outcome = await service.complete_oidc_login(
        flow_id=flow_id,
        state=dict(parse_qsl(urlsplit(url).query))["state"],
        code="authcode",
        client=None,
        public_origin="https://ops.example",
    )
    assert outcome.ok, outcome
    assert not await _live(service, rotated), "the federated callback did not follow the lineage"


async def test_the_link_is_followed_over_several_elevations(store: MessageStore) -> None:
    service = await _service(store)
    prior = await _token(service)
    end = prior
    for _ in range(3):
        end = await _elevate(service, end)
    await _token(service, supersedes=prior)
    assert not await _live(service, end), "the chain was not followed to its live end"


async def test_a_link_older_than_the_window_is_not_followed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(store, session_idle_timeout_minutes=240)
    window = service.supersession_lineage_seconds
    assert window >= service.oidc_flow_ttl_seconds, "the window must outlast the longest sign-in"
    prior = await _token(service)
    rotated = await _elevate(service, prior)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + window + 5)
    assert await _live(service, rotated)
    await _token(service, supersedes=prior)
    assert await _live(service, rotated), "a link past its window ended a session"
    assert await _superseded(store) == []


def _links(path: Path) -> list[tuple[str, str]]:
    with closing(sqlite3.connect(path)) as db:
        return [
            (str(r[0]), str(r[1]))
            for r in db.execute("SELECT retired_hash, successor_hash FROM session_lineage")
        ]


async def test_a_retired_token_authenticates_nothing_while_its_link_is_live(
    store: MessageStore, tmp_path: Path
) -> None:
    # Closing item 2. The link exists and is inside its window, and the retired token still
    # resolves to nothing, on every path that reads a session by a presented token.
    service = await _service(store)
    prior = await _token(service)
    rotated = await _elevate(service, prior)
    assert _links(tmp_path / "lineage.db") == [(hash_token(prior), hash_token(rotated))]
    assert await service.identity_for_token(prior) is None
    assert await service.identity_for_token(prior, activity=False) is None
    assert await store.get_session(hash_token(prior)) is None
    assert await _live(service, rotated), "presenting the retired token ended its successor"


async def test_a_token_whose_hash_links_to_a_live_session_authenticates_nothing(
    store: MessageStore, tmp_path: Path
) -> None:
    # The same, from the other side: a link row a database writer forged from a hash whose token it
    # holds to someone else's live session. The validator reads `sessions` only, so the forged
    # token is refused and the session it points at is untouched.
    service = await _service(store)
    victim = await _token(service, "other")
    forged = "a-token-nobody-was-ever-issued"
    with closing(sqlite3.connect(tmp_path / "lineage.db")) as db:
        db.execute(
            "INSERT INTO session_lineage (retired_hash, successor_hash, retired_at) VALUES (?,?,?)",
            (hash_token(forged), hash_token(victim), time.time()),
        )
        db.commit()
    assert await service.identity_for_token(forged) is None
    assert await _live(service, victim)


_BACKENDS = ("store.py", "postgres.py", "sqlserver.py")
_STORE_DIR = Path(__file__).resolve().parents[1] / "messagefoundry" / "store"
_LINEAGE = re.compile(r"\bsession_lineage\b|SESSION_LINEAGE_|\brevoke_through_lineage\b")


def _functions_naming_the_lineage(source: str) -> set[str]:
    """Every top-level function or method whose CODE names the lineage table, one of its
    statements, or the shared walk; a docstring or comment that mentions them does not count. A
    nested function counts as the method it sits in."""
    tree = parse_source(source)
    named: set[str] = set()
    tops: list[ast.stmt] = list(tree.body)
    for cls in tree.body:
        if isinstance(cls, ast.ClassDef):
            tops.extend(cls.body)
    for node in tops:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and any(
            _LINEAGE.search(text) for text in (*code_names(node), *code_strings(node))
        ):
            named.add(node.name)
    return named


@pytest.mark.parametrize("backend", _BACKENDS)
def test_only_the_rotation_the_supersession_and_the_purge_touch_the_lineage(backend: str) -> None:
    # Closing item 2, structurally, and only this much: in the three backend modules, no method but
    # these three spells the table, one of its statements or the shared walk in code. A read through
    # a statement under another name, or from a new module, is outside what this proves; the
    # behavioural tests above cover the validator itself.
    source = (_STORE_DIR / backend).read_text(encoding="utf-8")
    assert _functions_naming_the_lineage(source) == {
        "rotate_session",
        "supersede_session",
        "purge_expired_sessions",
    }


def test_the_service_follows_the_lineage_from_the_supersession_alone() -> None:
    # `_load_session` and the validator never pass a lineage window; only the sign-in's
    # supersession does. `_end_lapsed_session` shares the store call and passes none.
    source = (Path(__file__).resolve().parents[1] / "messagefoundry/auth/service.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    passing: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            for call in ast.walk(node):
                if isinstance(call, ast.Call) and any(
                    k.arg == "lineage_since" for k in call.keywords
                ):
                    passing.add(node.name)
    assert passing == {"_supersede_session_hash"}
    assert not _LINEAGE.search(source)


async def test_the_lineage_reaches_no_further_than_one_supersession(store: MessageStore) -> None:
    # A followed link ends the live end once. Presenting the retired token again finds a revoked row
    # and writes nothing.
    service = await _service(store)
    prior = await _token(service)
    await _elevate(service, prior)
    await _token(service, supersedes=prior)
    await _token(service, supersedes=prior)
    assert len(await _superseded(store)) == 1


async def test_the_lapsed_credential_revoke_does_not_follow_the_lineage(
    store: MessageStore,
) -> None:
    # `_end_lapsed_session` shares `supersede_session`. It revokes the row it was handed, and a row a
    # rotation re-keyed first is not reported as ended; the next presentation of the new token is
    # refused by the same gate. So it passes no lineage window.
    service = await _service(store)
    prior = await _token(service)
    rotated = await _elevate(service, prior)
    await service._end_lapsed_session(hash_token(prior), "op", at="session", client=None)
    assert await _live(service, rotated)


async def test_the_reaper_purges_links_by_the_window_it_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The lifespan hands the reaper the service's window, and the reaper must pass it to the purge,
    # or no link is ever deleted.
    from messagefoundry.api import app as api_app

    monkeypatch.setattr(api_app, "_SESSION_REAP_INTERVAL", 0)
    monkeypatch.setattr(api_app, "_SESSION_REAP_FIRST_DELAY", 0)
    seen: list[float | None] = []
    done = asyncio.Event()

    class _Store:
        async def purge_expired_sessions(
            self,
            *,
            now: float | None = None,
            idle_seconds: float | None = None,
            lineage_seconds: float | None = None,
        ) -> None:
            seen.append(lineage_seconds)
            done.set()

    task = asyncio.create_task(
        api_app._session_reaper(_Store(), idle_seconds=60.0, lineage_seconds=420.0)  # type: ignore[arg-type]
    )
    try:
        await asyncio.wait_for(done.wait(), timeout=5)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert seen[0] == 420.0


def test_the_lifespan_hands_the_reaper_the_supersession_window() -> None:
    source = (Path(__file__).resolve().parents[1] / "messagefoundry/api/app.py").read_text(
        encoding="utf-8"
    )
    reapers = [c for c in ast.walk(parse_source(source)) if isinstance(c, ast.Call)]
    passing = [
        c
        for c in reapers
        if isinstance(c.func, ast.Name)
        and c.func.id == "_session_reaper"
        and any(
            k.arg == "lineage_seconds"
            and isinstance(k.value, ast.Attribute)
            and k.value.attr == "supersession_lineage_seconds"
            for k in c.keywords
        )
    ]
    assert len(passing) == 1, "the lifespan no longer passes the window to the reaper"


# --- the shared walk, with no database: a rotation that lands mid-walk, and the hop bound ----------


def _record(token_hash: str) -> SessionRecord:
    return SessionRecord(
        token_hash=token_hash,
        user_id="u",
        created_at=0.0,
        expires_at=1.0,
        last_used_at=0.0,
        revoked_at=1.0,
        client=None,
    )


async def test_a_rotation_landing_mid_walk_costs_a_step_not_the_revoke() -> None:
    # On the server backends each step is its own statement, so a rotation can commit between a
    # step's lineage read and the next step's revoke. Here `b` is re-keyed to `c` exactly then. The
    # walk's revoke of `b` matches nothing, it reads `b`'s new link, and it ends `c`.
    live = {"b"}
    links = {"a": "b"}
    calls: list[str] = []

    async def _revoke(h: str) -> SessionRecord | None:
        calls.append(f"revoke {h}")
        if h in live:
            live.discard(h)
            return _record(h)
        return None

    async def _successor(h: str, since: float) -> str | None:
        calls.append(f"follow {h}")
        found = links.get(h)
        if h == "a":  # the rotation of b -> c commits right after this read
            live.discard("b")
            live.add("c")
            links["b"] = "c"
        return found

    ended = await revoke_through_lineage(
        "a", lineage_since=0.0, revoke=_revoke, successor=_successor
    )
    assert ended is not None and ended.token_hash == "c"
    assert calls == ["revoke a", "follow a", "revoke b", "follow b", "revoke c"]


async def test_the_walk_stops_at_its_hop_bound() -> None:
    async def _successor(h: str, since: float) -> str | None:
        return str(int(h) + 1)

    def _revoke_only(target: int) -> Callable[[str], Awaitable[SessionRecord | None]]:
        async def _revoke(h: str) -> SessionRecord | None:
            return _record(h) if h == str(target) else None

        return _revoke

    reach = await revoke_through_lineage(
        "0", lineage_since=0.0, revoke=_revoke_only(LINEAGE_MAX_HOPS), successor=_successor
    )
    assert reach is not None and reach.token_hash == str(LINEAGE_MAX_HOPS)
    past = await revoke_through_lineage(
        "0", lineage_since=0.0, revoke=_revoke_only(LINEAGE_MAX_HOPS + 1), successor=_successor
    )
    assert past is None, "the walk followed more links than its bound"
