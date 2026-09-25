# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1256: two concurrent binds of one federated subject to two accounts must not both land.

**MOVED FROM THE LOGIN PATH TO THE ADMIN BIND BY BACKLOG #1143 / #295 (ADR 0184).** Until then a
federated login bound the presented subject on the account's first federated login, and this module
raced two such FIRST LOGINS. A login no longer binds -- it selects its account by the pair, and an
unbound pair is refused -- so that race cannot happen any more. The same race now lives at the one
path that binds, ``AuthService.bind_federated_subject``, and this module races two of those.

**THE APPLICATION GUARD IS CORRECT AND IS NOT WHAT THIS TESTS.** The bind reads the pair's current
holder and refuses with ``FederatedSubjectHeld`` when a different account holds it, and only then
writes. ``test_one_subject_cannot_be_bound_to_two_accounts`` in the sibling module pins the
sequential case.

What the guard cannot do is make its own read-then-write atomic. The read and the write are separate
awaits, so two binds interleaving between them can both observe "no holder" and both write.
``ux_users_federated_subject`` closes that, and the bind renders the loser's integrity error as the
same refusal the sequential path raises.

***WHY NOT SIMPLY ASSERT THE INDEX EXISTS.*** Because that test PASSES ON THE DEFECT: it measures a
declaration and says nothing about the race. The acceptance has to demonstrate the race itself.

***THE INTERLEAVING IS FORCED, NOT HOPED FOR.*** Two coroutines started together and left to the
scheduler may serialise, and then the test passes on the defect. The barrier below makes both reads
complete before either write can proceed. ``test_the_race_was_actually_exercised`` asserts the barrier
did its job; without it a green run here would not tell "the index held" from "the two binds never
raced".
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import oidc
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import FederatedBinding, FederatedSubjectHeld
from messagefoundry.store.store import MessageStore
from tests.test_auth_oidc_service import (
    PRINCIPAL,
    _claims,
    _FakeLdap,
    _flow,
    _mint,
    _service,
)

#: One verified identity, asked for by two accounts at the same instant.
SUBJECT = "S-1-concurrent"


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    """Local rather than imported: ``rsa_key`` is a module-scoped FIXTURE in the sibling suite, and a
    fixture is resolved by name in the module that requests it -- importing the function object does
    not register it here. Same key size, same scope, so the cost is identical."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


async def _two_accounts(store: MessageStore) -> tuple[str, str]:
    """Two directory mirror rows, as Kerberos sign-ins would leave them: unbound."""
    first, second = uuid4().hex, uuid4().hex
    await store.create_user(user_id=first, username="jdoe", auth_provider="ad")
    await store.create_user(user_id=second, username="bsmith", auth_provider="ad")
    return first, second


async def _run_race(
    store: MessageStore, rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> tuple[list[Any], list[bool]]:
    """Two admin binds of ONE subject to two accounts, held open until both have read the holder.

    Returns the two outcomes and what each bind OBSERVED at the read -- the second is what proves the
    race happened rather than the two calls quietly serialising.
    """
    service = await _service(store, rsa_key, bind=None)
    first, second = await _two_accounts(store)

    # FORCE THE INTERLEAVE. Both binds must finish reading the holder before either writes.
    barrier = asyncio.Barrier(2)
    observed: list[bool] = []
    real_read = store.get_user_by_federated_subject

    async def read_then_wait(*args: Any, **kwargs: Any) -> Any:
        holder = await real_read(*args, **kwargs)
        observed.append(holder is None)
        # BOUNDED. If either bind returns before reaching this point, only one party ever arrives
        # and an unbounded `wait()` hangs the worker; pytest-timeout's `thread` method then kills the
        # xdist worker with no stack. 10s is far above what a healthy interleave needs and far below
        # the per-test caps, so a real hang fails here, named.
        await asyncio.wait_for(barrier.wait(), timeout=10)
        return holder

    monkeypatch.setattr(store, "get_user_by_federated_subject", read_then_wait)
    outcomes = await asyncio.gather(
        service.bind_federated_subject(first, SUBJECT, actor="admin"),
        service.bind_federated_subject(second, SUBJECT, actor="admin"),
        return_exceptions=True,
    )
    monkeypatch.undo()
    return list(outcomes), observed


async def test_only_one_of_two_concurrent_binds_succeeds(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE DEFECT ITSELF: without ux_users_federated_subject, BOTH of these would bind."""
    store = await MessageStore.open(":memory:")
    try:
        outcomes, _ = await _run_race(store, rsa_key, monkeypatch)
        won = [o for o in outcomes if isinstance(o, FederatedBinding)]
        lost = [o for o in outcomes if isinstance(o, BaseException)]
        assert len(won) == 1, f"expected exactly one bind to win, got {len(won)}: {outcomes!r}"
        assert len(lost) == 1
        assert isinstance(lost[0], FederatedSubjectHeld), (
            "the race loser must get the SAME refusal the sequential path raises, not an integrity "
            f"error surfacing as a 500: {lost[0]!r}"
        )
        holders = [u for u in await store.list_users() if u.oidc_subject == SUBJECT]
        assert len(holders) == 1
    finally:
        await store.close()


async def test_the_race_was_actually_exercised(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE CONTROL ON THE TEST ABOVE, and it is the row that makes its green mean something.

    If the two binds serialised, the second would read a holder that already exists, the ordinary
    guard would refuse it, and the test above would pass WITHOUT the index ever being consulted.
    Both reads observing "no holder" is what says the interleave really happened.
    """
    store = await MessageStore.open(":memory:")
    try:
        _, observed = await _run_race(store, rsa_key, monkeypatch)
        assert observed == [True, True], (
            "both binds had to observe NO holder for this to be the concurrent case; "
            f"observed {observed!r} -- the calls serialised and the index was never exercised"
        )
    finally:
        await store.close()


async def test_a_second_bind_for_a_DIFFERENT_subject_is_untouched(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEGATIVE CONTROL. The index is filtered and two-column, so two accounts bound to two DIFFERENT
    subjects must both bind, and both then sign in -- otherwise this change would refuse ordinary
    federation."""
    store = await MessageStore.open(":memory:")
    try:
        other = AdPrincipal(
            username="bsmith",
            display_name="B Smith",
            email="bsmith@corp.example",
            dn="CN=bsmith,DC=corp,DC=example",
            groups=PRINCIPAL.groups,
        )
        ldap = _FakeLdap(by_username={"jdoe": PRINCIPAL, "bsmith": other})
        service = await _service(store, rsa_key, ldap=ldap, bind=None)
        first, second = await _two_accounts(store)
        await service.bind_federated_subject(first, "S-1-alice", actor="admin")
        await service.bind_federated_subject(second, "S-2-bob", actor="admin")

        tokens = {
            "c1": _mint(rsa_key, _claims(sub="S-1-alice", preferred_username="jdoe@corp.example")),
            "c2": _mint(rsa_key, _claims(sub="S-2-bob", preferred_username="bsmith@corp.example")),
        }
        monkeypatch.setattr(
            oidc,
            "exchange_code",
            lambda **kw: {"id_token": tokens[kw["code"]], "access_token": "at"},
        )
        for code, user_id in (("c1", first), ("c2", second)):
            out = await service.authenticate_oidc(
                code, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
            )
            assert out.ok, f"a distinct subject was refused: {out!r}"
            assert out.identity is not None and out.identity.user_id == user_id
    finally:
        await store.close()


def test_the_index_is_declared_on_every_backend() -> None:
    """Deliberately LAST and deliberately NOT the acceptance test -- see this module's docstring.

    Asserting the index exists cannot see the race and would pass on the defect if the columns were
    unconstrained. It earns its place only as a parity check that no backend was missed, which the
    race test above cannot give: it runs on SQLite alone. Each backend's refusal of a second holder
    is exercised against a live server by ``tests/_federated_unbind_store_contract.py``, which the
    gated Postgres and SQL Server suites run.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store"
    for backend in ("store.py", "postgres.py", "sqlserver.py"):
        src = (root / backend).read_text(encoding="utf-8")
        assert "ux_users_federated_subject" in src, (
            f"{backend} declares no federated-subject unique index, so the race it closes on the "
            "other backends is still open there"
        )
