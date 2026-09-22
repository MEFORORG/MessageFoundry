# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1438 (ASVS 6.2.4): the BUNDLED breach corpus must fail closed, not screen nothing.

Its own module rather than a section of `test_auth_core.py`, for two reasons. The subject is one
mechanism with one fixture, and `test_auth_core.py` is contested by concurrent work restructuring the
per-number corpus gates that live there. `test_auth_core.py` keeps the BUILD-time bar (BACKLOG #1134:
at least 3000 corpus entries clear the shipped policy); this file holds the RUNTIME guard that the
same number implies. Read them together.

The shape being defended is the one this project keeps rediscovering: **an empty result and a good
result rendering identically.** `violations` returned `[]` whether the corpus screened the password or
had silently failed to load, and `[]` is the success value, so nothing anywhere could report the
difference. Every arm below therefore has a stated failure reading -- see the table in the #1438 row.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from pathlib import Path

import pytest

from messagefoundry.auth import PasswordPolicy
from messagefoundry.auth import policy as policy_module
from messagefoundry.auth.policy import ASVS_6_2_4_MIN_CORPUS_ENTRIES, BreachCorpusUnavailable
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

#: A password the stand-in corpora below declare leaked. Holds no CONTEXT_WORDS entry and clears the
#: default length, so the breach clause is the only one it can trip -- which is what lets an arm read
#: the presence or absence of that one clause.
_LEAKED = "a-stand-in-leaked-passphrase"


@pytest.fixture
def bundled_corpus(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[Callable[[Sequence[str] | None], None]]:
    """Point the loader at a stand-in bundled corpus holding exactly the entries you pass.

    `policy_module.files` is the module-level name the loader calls, and a `pathlib.Path` already
    satisfies the `/` + `read_bytes()` shape of an `importlib.resources` Traversable, so no fake class
    is needed. The `lru_cache` is cleared on BOTH sides: a truncated corpus left cached would disarm
    every later test in the session, which is the same silent-no-op failure this section exists over.
    """

    def use(entries: Sequence[str] | None) -> None:
        """A sequence writes exactly those entries; `None` leaves the file absent entirely."""
        root = tmp_path / "pkg"
        (root / "data").mkdir(parents=True, exist_ok=True)
        if entries is not None:
            (root / "data" / "common_passwords.txt").write_text(
                "\n".join(entries), encoding="utf-8"
            )
        monkeypatch.setattr(policy_module, "files", lambda _package: root)
        policy_module._common_passwords.cache_clear()

    yield use
    policy_module._common_passwords.cache_clear()


@pytest.fixture
async def empty_store() -> AsyncIterator[MessageStore]:
    """An in-memory store with no users, so `initialize` takes the first-run branch (BACKLOG #1447).

    `_ensure_bootstrap_admin` returns early on `count_users() > 0`, so an empty store is a
    precondition of every arm below and not an incidental detail of the fixture.
    """
    store = await MessageStore.open(":memory:")
    try:
        yield store
    finally:
        await store.close()


def test_a_truncated_bundled_corpus_refuses_a_password_instead_of_accepting_it(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """THE POSITIVE CONTROL for #1438: delete the guard in `_common_passwords` and this test fails.

    `correct-horse-battery-staple-xyz` is asserted ACCEPTED against the real corpus by
    `test_breach_corpus_growth_did_not_over_block_or_regress` above, so it clears every other clause
    and isolates the breach clause. Against a five-entry corpus the pre-#1438 loader returned an empty
    `frozenset`, `violations` returned `[]`, and that is byte-identical to a password which really was
    screened. An exception is the only outcome a test can tell apart from that silence.
    """
    bundled_corpus(["123456", "password", "qwerty", "letmein", "dragon"])
    with pytest.raises(BreachCorpusUnavailable, match="below the floor"):
        PasswordPolicy().violations("correct-horse-battery-staple-xyz")


def test_an_empty_bundled_corpus_refuses(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """Truncation to zero bytes is the cheapest way to disable the screen, so it gets its own arm."""
    bundled_corpus([])
    with pytest.raises(BreachCorpusUnavailable, match="0 entries"):
        PasswordPolicy().violations("correct-horse-battery-staple-xyz")


def test_a_missing_bundled_corpus_refuses(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """Deleting the file must not read as `nothing is breached` either. A distinct cause from the two
    arms above, and a distinct message: the read failed rather than returning too little."""
    bundled_corpus(None)
    with pytest.raises(BreachCorpusUnavailable, match="could not be read"):
        PasswordPolicy().violations("correct-horse-battery-staple-xyz")


def test_the_shipped_bundled_corpus_clears_the_runtime_floor() -> None:
    """The arm that keeps the three above honest.

    A guard wired to fire unconditionally would pass every one of them, so the shipped corpus has to
    be asserted through the SAME call path and come back clean. Measured at the time of writing:
    15,045 entries against a floor of 3,000.
    """
    assert len(policy_module._common_passwords()) >= ASVS_6_2_4_MIN_CORPUS_ENTRIES
    assert PasswordPolicy().violations("correct-horse-battery-staple-xyz") == []


def test_the_guard_stays_out_of_the_way_when_screening_is_turned_off(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """`check_breached=False` is a deliberate operator choice, so a corpus nobody consults is not a
    defect. This also pins that the guard did not become an unconditional import-time assertion."""
    bundled_corpus([])
    assert PasswordPolicy(check_breached=False).violations("correct-horse-battery-staple-xyz") == []


def test_startup_reports_an_unusable_bundled_corpus_as_an_error(
    bundled_corpus: Callable[[Sequence[str] | None], None], caplog: pytest.LogCaptureFixture
) -> None:
    """The loud half. Without this the operator meets the defect as a 500 on a password change, which
    is a window the eager load closes (the loader is `lru_cache`d and otherwise read lazily)."""
    from messagefoundry.auth.service import _error_if_bundled_corpus_unusable

    bundled_corpus([])
    with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
        _error_if_bundled_corpus_unusable(True)
    assert [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR], (
        "an unusable bundled corpus logged nothing at startup"
    )
    assert "REFUSED" in caplog.records[0].getMessage()


def test_startup_is_silent_when_screening_is_turned_off(
    bundled_corpus: Callable[[Sequence[str] | None], None], caplog: pytest.LogCaptureFixture
) -> None:
    from messagefoundry.auth.service import _error_if_bundled_corpus_unusable

    bundled_corpus([])
    with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
        _error_if_bundled_corpus_unusable(False)
    assert caplog.records == []


# --- BACKLOG #1447: the same guard, on the one input it can never screen -------------------------
#
# #1438 above made an unusable corpus REFUSE a password. That is right for every password a person
# chooses and wrong for exactly one caller, the bootstrap generator -- whose reasoning is stated at
# its own call site in `AuthService._generate_policy_password`, not repeated here.
#
# WHAT THESE ARMS ADD is the pairing. A blanket suppression passes the positive arms and fails the
# controls, and that contrast is the only thing that can tell this targeted fix apart from the
# weakening the row forbids. Measured against the two mutations a future edit would plausibly make:
#
#   `suppress_breach_check` default flipped to True (a blanket suppression)  -> 7 arms fail, both
#       controls among them. This is the one-character mutation the controls exist for.
#   `self.check_breached` dropped from the gate (the override becomes two-way) -> 2 arms fail:
#       `..._can_only_suppress_never_assert_a_screen` and #1438's `..._screening_is_turned_off`.


def test_the_per_call_override_suppresses_the_clause_the_policy_still_enforces(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """The unit pin, both arms in one body so neither can drift out of the other's sight.

    Same policy, same unusable corpus, same password: the default call RAISES and the overridden call
    returns clean. Delete the `suppress_breach_check` gate in `violations` and the second assert
    raises instead of returning a list.
    """
    bundled_corpus([])
    policy = PasswordPolicy()
    with pytest.raises(BreachCorpusUnavailable):
        policy.violations("correct-horse-battery-staple-xyz")
    assert policy.violations("correct-horse-battery-staple-xyz", suppress_breach_check=True) == []


def test_the_per_call_override_can_only_suppress_never_assert_a_screen(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """The override is AND-ed with the field, so it is one-directional by construction.

    `suppress_breach_check=False` against `check_breached=False` must NOT start screening: a library
    call that overrode a documented operator setting from the inside is a capability with no caller
    and a worse failure mode than the one being fixed.

    The stand-in corpus is USABLE (padded to exactly the floor) and holds the password under test, so
    the first assert proves the screen really does fire against it. Without that arm the second one
    passes on a policy whose breach clause is broken in every direction.
    """
    bundled_corpus([f"padding-entry-{n}" for n in range(ASVS_6_2_4_MIN_CORPUS_ENTRIES)] + [_LEAKED])
    assert "not be a common or breached password" in PasswordPolicy().violations(_LEAKED)
    off = PasswordPolicy(check_breached=False)
    assert off.violations(_LEAKED, suppress_breach_check=False) == []


async def test_a_first_run_mints_the_bootstrap_admin_when_the_corpus_is_unusable(
    bundled_corpus: Callable[[Sequence[str] | None], None], empty_store: MessageStore
) -> None:
    """THE POSITIVE CONTROL for #1447, and the interaction the row was filed over.

    Found by reading the call graph, not by a red leg: `initialize` -> `_ensure_bootstrap_admin` ->
    `_generate_policy_password` -> `violations`, with no `try` at the lifespan call in `api/app.py`.
    So the failure reading is not a wrong password, it is `BreachCorpusUnavailable` escaping here and
    an engine that does not start at all on a fresh install whose corpus did not ship intact.

    The minted credential is logged in with, so this cannot pass on a generator that returned
    something unusable.
    """
    bundled_corpus([])
    service = AuthService(empty_store, AuthSettings())
    boot = await service.initialize()
    assert boot is not None and boot.username == "admin"
    assert (await service.login("admin", boot.password)).ok


async def test_an_operator_supplied_first_administrator_still_refuses_on_an_unusable_corpus(
    bundled_corpus: Callable[[Sequence[str] | None], None], empty_store: MessageStore
) -> None:
    """THE NEGATIVE CONTROL, and it is the arm that makes the one above mean anything.

    Identical preconditions to the positive arm -- empty store, unusable corpus, a first-run
    provisioning path -- with ONE variable changed: who chose the password. An operator chose this
    one, so the corpus is the whole point and refusing is correct.

    Flip `suppress_breach_check`'s default to True -- the one-character mutation that turns this
    targeted fix into the blanket one the row forbids -- and this test goes red with DID NOT RAISE
    while the positive arm above still passes. Dropping `check_breached` from the gate does NOT fail
    this arm (it screens MORE, not less); see the measured mutation table at the top of this section.
    """
    bundled_corpus([])
    service = AuthService(empty_store, AuthSettings())
    with pytest.raises(BreachCorpusUnavailable):
        await service.provision_first_administrator(
            username="opsadmin", password="an-operator-chosen-passphrase", actor="installer"
        )


async def test_a_user_password_change_still_refuses_while_the_same_service_mints_a_token(
    bundled_corpus: Callable[[Sequence[str] | None], None], empty_store: MessageStore
) -> None:
    """The tightest pairing available: ONE service, ONE unusable corpus, two paths through it.

    Environment is held constant to the point of being the same object, so nothing but the per-call
    argument can explain the difference. The bootstrap mints; the human's replacement password is
    refused. A blanket suppression makes the `raises` block fail.
    """
    bundled_corpus([])
    service = AuthService(empty_store, AuthSettings())
    boot = await service.initialize()
    assert boot is not None
    out = await service.login("admin", boot.password)
    assert out.ok and out.identity is not None
    with pytest.raises(BreachCorpusUnavailable):
        await service.change_password(out.identity, "a-human-chosen-replacement-pass")


async def test_an_admin_reset_issues_a_credential_on_an_unusable_corpus(
    bundled_corpus: Callable[[Sequence[str] | None], None], empty_store: MessageStore
) -> None:
    """`admin_reset_password` reaches the same generator, so it is covered by the same suppression.

    Its failure mode was never a dead engine -- the store is non-empty by then -- but a 500 on a
    running one, on the path an administrator uses to unstick a locked-out user. Worth its own arm
    because it is a SECOND caller of `_generate_policy_password`, and a fix applied at the bootstrap
    call rather than inside the generator would pass every arm above and fail this one.
    """
    bundled_corpus([])
    service = AuthService(empty_store, AuthSettings())
    assert await service.initialize() is not None
    admin = await empty_store.get_user_by_username("admin")
    assert admin is not None
    issued = await service.admin_reset_password(admin.id, actor="admin")
    assert issued.password and len(issued.password) >= 20
