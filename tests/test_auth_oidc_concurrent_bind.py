# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1256: two concurrent FIRST logins for one federated subject must not both bind.

**THE APPLICATION GUARD IS CORRECT AND IS NOT WHAT THIS TESTS.** ``auth/service.py`` resolves the
presenting subject, refuses with ``federated_subject_already_bound`` when a different account holds it,
and only then records the binding. Every non-concurrent case is covered, and
``test_one_subject_cannot_bind_two_accounts`` in the sibling module pins exactly that.

What the guard cannot do is make its own read-then-write atomic. The read and the write are separate
awaits, so two logins interleaving between them can both observe "no holder" and both bind.
``ux_users_federated_subject`` closes that, and the caller renders the loser's integrity error as the
same refusal the sequential path returns.

***WHY NOT SIMPLY ASSERT THE INDEX EXISTS.*** Because that test PASSES ON THE DEFECT. The guard's own
in-code comment already records "no UNIQUE constraint names these columns on any backend" -- so a test
that measures constraints re-derives a comment and says nothing about the race. #1256's correction block
says this in as many words. The acceptance had to demonstrate the race itself.

***THE INTERLEAVING IS FORCED, NOT HOPED FOR.*** A test that merely starts two coroutines and hopes they
interleave is a coin flip that passes on the defect whenever the scheduler happens to serialise them --
silently, and more often on a fast machine. The barrier below makes both reads complete before either
write can proceed, so the race is deterministic. ``test_the_race_was_actually_exercised`` asserts the
barrier did its job; without it a green run here would not distinguish "the index held" from "the two
logins never actually raced".
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import oidc
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.store.store import MessageStore
from tests.test_auth_oidc_service import (
    PRINCIPAL,
    _claims,
    _FakeLdap,
    _flow,
    _mint,
    _service,
)

#: One verified identity, presenting twice at the same instant.
SUBJECT = "S-1-concurrent"


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    """Local rather than imported: ``rsa_key`` is a module-scoped FIXTURE in the sibling suite, and a
    fixture is resolved by name in the module that requests it -- importing the function object does
    not register it here. Same key size, same scope, so the cost is identical."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


async def _run_race(
    store: MessageStore,
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[Any], list[bool]]:
    """Two federated logins for ONE subject, held open until both have read the current holder.

    Returns the two outcomes and what each login OBSERVED at the read -- the second is what proves the
    race happened rather than the two calls quietly serialising.
    """
    other = AdPrincipal(
        username="bsmith",  # a genuinely different on-prem object, not a rename
        display_name="B Smith",
        email="bsmith@corp.example",
        dn="CN=bsmith,DC=corp,DC=example",
        groups=PRINCIPAL.groups,
    )
    ldap = _FakeLdap(by_username={"jdoe": PRINCIPAL, "bsmith": other})
    service = await _service(store, rsa_key, ldap=ldap)

    # The token endpoint is a module global, so a per-call stub would have the two logins overwrite
    # each other's token and collapse onto one account. Hand each caller its own token instead, keyed
    # by the code it presents.
    tokens = {
        "code-jdoe": _mint(rsa_key, _claims(sub=SUBJECT, preferred_username="jdoe@corp.example")),
        "code-bsmith": _mint(
            rsa_key, _claims(sub=SUBJECT, preferred_username="bsmith@corp.example")
        ),
    }

    def fake_exchange(**kwargs: Any) -> dict[str, object]:
        return {"id_token": tokens[kwargs["code"]], "access_token": "at-never-stored"}

    monkeypatch.setattr(oidc, "exchange_code", fake_exchange)

    # FORCE THE INTERLEAVE. Both logins must finish reading the holder before either writes.
    barrier = asyncio.Barrier(2)
    observed: list[bool] = []
    real_read = store.get_user_by_federated_subject

    async def read_then_wait(*args: Any, **kwargs: Any) -> Any:
        holder = await real_read(*args, **kwargs)
        observed.append(holder is None)
        await barrier.wait()  # neither proceeds to the write until both have read
        return holder

    monkeypatch.setattr(store, "get_user_by_federated_subject", read_then_wait)

    async def login(code: str) -> Any:
        return await service.authenticate_oidc(
            code, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
        )

    outcomes = await asyncio.gather(
        login("code-jdoe"), login("code-bsmith"), return_exceptions=True
    )
    return list(outcomes), observed


async def test_only_one_of_two_concurrent_binds_succeeds(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE DEFECT ITSELF: before ux_users_federated_subject, BOTH of these bound."""
    store = await MessageStore.open(":memory:")
    try:
        outcomes, _ = await _run_race(store, rsa_key, monkeypatch)
        for out in outcomes:
            assert not isinstance(out, BaseException), (
                f"a login raised rather than returning: {out!r}"
            )
        ok = [o for o in outcomes if o.ok]
        refused = [o for o in outcomes if not o.ok]
        assert len(ok) == 1, f"expected exactly one bind to win, got {len(ok)}: {outcomes!r}"
        assert len(refused) == 1
        assert refused[0].reason == "federated_subject_already_bound", (
            "the race loser must get the SAME refusal the sequential path returns, not a 500 or a "
            f"different reason: {refused[0]!r}"
        )
    finally:
        await store.close()


async def test_the_race_was_actually_exercised(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE CONTROL ON THE TEST ABOVE, and it is the row that makes its green mean something.

    If the two logins serialised -- scheduler, a lock, a future refactor -- the second would read a
    holder that already exists, the ordinary guard would refuse it, and the test above would pass
    WITHOUT the index ever being consulted. It would then keep passing after a revert.

    Both reads observing "no holder" is what says the interleave really happened.
    """
    store = await MessageStore.open(":memory:")
    try:
        _, observed = await _run_race(store, rsa_key, monkeypatch)
        assert observed == [True, True], (
            "both logins had to observe NO holder for this to be the concurrent case; "
            f"observed {observed!r} -- the calls serialised and the index was never exercised"
        )
    finally:
        await store.close()


async def test_a_second_bind_for_a_DIFFERENT_subject_is_untouched(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEGATIVE CONTROL. The index is filtered and two-column, so two accounts binding two DIFFERENT
    subjects must both succeed -- otherwise this change would refuse ordinary federation."""
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
        service = await _service(store, rsa_key, ldap=ldap)

        tokens = {
            "c1": _mint(rsa_key, _claims(sub="S-1-alice", preferred_username="jdoe@corp.example")),
            "c2": _mint(rsa_key, _claims(sub="S-2-bob", preferred_username="bsmith@corp.example")),
        }
        monkeypatch.setattr(
            oidc,
            "exchange_code",
            lambda **kw: {"id_token": tokens[kw["code"]], "access_token": "at"},
        )
        for code in ("c1", "c2"):
            out = await service.authenticate_oidc(
                code, _flow(), redirect_uri="https://ops.example/ui/oidc/callback"
            )
            assert out.ok, f"a distinct subject was refused: {out!r}"
    finally:
        await store.close()


def test_the_index_is_declared_on_every_backend() -> None:
    """Deliberately LAST and deliberately NOT the acceptance test -- see this module's docstring.

    Asserting the index exists cannot see the race and would pass on the defect if the columns were
    unconstrained. It earns its place only as a parity check that no backend was missed, which the
    race test above cannot give: it runs on SQLite alone, because the Postgres and SQL Server suites
    need live servers.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store"
    for backend in ("store.py", "postgres.py", "sqlserver.py"):
        src = (root / backend).read_text(encoding="utf-8")
        assert "ux_users_federated_subject" in src, (
            f"{backend} declares no federated-subject unique index, so the race it closes on the "
            "other backends is still open there"
        )
