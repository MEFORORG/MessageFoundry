# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A deploying site's own context words: ``[auth].password_extra_context_words`` (BACKLOG #1132).

ASVS 6.1.2 names organization names, product names, project codenames, and department or role
names as the words a context list should hold. A vendor constant cannot hold them, so the site
supplies them. These tests pin at least these properties:

* a site term refuses a password that contains it, on the create path and the change path alike;
* a site term can only ADD to the shipped ``CONTEXT_WORDS``, never remove one;
* each list that fires names its own clause;
* a bad value refuses at load, or at direct construction, rather than being dropped or loading as a
  screen that does nothing;
* the match is case-insensitive in both directions;
* an administrator's reset never issues a generated password the site's terms refuse.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from messagefoundry.auth import policy as policy_module
from messagefoundry.auth import service as service_module
from messagefoundry.auth.policy import CONTEXT_WORDS, SITE_CONTEXT_WORD_CLAUSE, PasswordPolicy
from messagefoundry.auth.service import (
    AuthService,
    FirstAdministratorRefused,
    TemporaryPasswordUnavailable,
)
from messagefoundry.config.settings import (
    EXTRA_CONTEXT_WORD_MIN_LENGTH,
    AuthSettings,
    load_settings,
)
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_admin, login_admin

#: The shipped-list clause, and the site-term clause. They differ on purpose: the published list holds
#: only the shipped terms, so a refused user must be told when the word is one of the site's.
_CLAUSE = "not contain a word from the context-word deny-list"
_SITE = SITE_CONTEXT_WORD_CLAUSE
#: A passphrase that clears every other screen, with one slot for the term under test.
_TEMPLATE = "zq-{}-vy-long-passphrase"


def _site(*terms: str) -> AuthSettings:
    # Breach screening off: the terms under test are not in the corpus, and this keeps each
    # assertion about the one clause these tests exist for.
    return AuthSettings(password_check_breached=False, password_extra_context_words=list(terms))


# --- the policy --------------------------------------------------------------------------------


def test_a_site_term_is_refused_like_a_shipped_one() -> None:
    policy = PasswordPolicy.from_settings(_site("AcmeHealth"))
    # Control: the template alone is clean, so a refusal below is the term's doing.
    assert policy.violations(_TEMPLATE.format("")) == []
    assert policy.violations(_TEMPLATE.format("acmehealth")) == [_SITE]
    # Without the setting the same password passes: the setting is what added the term.
    assert PasswordPolicy(check_breached=False).violations(_TEMPLATE.format("acmehealth")) == []


@pytest.mark.parametrize("spelling", ["ACMEHEALTH", "AcmeHealth", "acmeHEALTH"])
def test_the_match_is_case_insensitive_both_ways(spelling: str) -> None:
    # Configured mixed-case, typed in another case.
    policy = PasswordPolicy.from_settings(_site("AcmeHealth"))
    assert policy.violations(_TEMPLATE.format(spelling)) == [_SITE]


def test_a_directly_built_policy_normalises_case_too() -> None:
    # The settings loader lower-cases, but a caller that builds the dataclass itself must not get a
    # term that can never match.
    policy = PasswordPolicy(check_breached=False, extra_context_words=frozenset({"GLOBEX"}))
    assert policy.extra_context_words == frozenset({"globex"})
    assert policy.violations(_TEMPLATE.format("globex")) == [_SITE]


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("", id="empty"),
        pytest.param("x", id="one-letter"),
        pytest.param(" acme", id="leading-space"),
        pytest.param("acme health", id="inner-space"),
    ],
)
def test_a_directly_built_policy_refuses_a_bad_term(bad: str) -> None:
    # The loader refuses these, but a direct caller skips the loader. An empty term would refuse
    # every password and a one-letter term nearly every one, so the dataclass refuses them too.
    with pytest.raises(ValueError):
        PasswordPolicy(extra_context_words=frozenset({bad}))


def test_a_shipped_term_keeps_the_shipped_clause_with_site_terms_set() -> None:
    policy = PasswordPolicy.from_settings(_site("globex"))
    assert policy.violations(_TEMPLATE.format("mirth")) == [_CLAUSE]


def test_a_password_holding_both_kinds_gets_both_clauses() -> None:
    # Each list is tested on its own. A password with a shipped term AND a site term names both, so
    # a user who removes only the published word is not refused a second time with no warning.
    policy = PasswordPolicy.from_settings(_site("globex"))
    assert policy.violations(_TEMPLATE.format("mirth-globex")) == [_CLAUSE, _SITE]


def test_a_site_term_that_repeats_a_shipped_one_keeps_the_shipped_clause_alone() -> None:
    # "admin" is published in docs/SECURITY.md, so its refusal must not also claim it is the site's.
    policy = PasswordPolicy.from_settings(_site("admin", "globex"))
    assert policy.extra_context_words == frozenset({"globex"})
    assert policy.violations(_TEMPLATE.format("admin")) == [_CLAUSE]


def test_a_directly_built_policy_refuses_site_terms_with_the_screen_off() -> None:
    # The loader refuses this pair (test_site_terms_with_the_screen_off_refuse). A direct caller skips
    # the loader, and the terms would otherwise load and screen nothing.
    with pytest.raises(ValueError, match="check_context is False"):
        PasswordPolicy(check_context=False, extra_context_words=frozenset({"globex"}))


def test_the_two_floors_agree() -> None:
    # settings.py keeps a copy because config does not import auth. The copy must not drift.
    assert EXTRA_CONTEXT_WORD_MIN_LENGTH == policy_module.EXTRA_CONTEXT_WORD_MIN_LENGTH


def test_a_site_term_cannot_remove_a_shipped_one() -> None:
    policy = PasswordPolicy.from_settings(_site("globex"))
    assert policy.context_words >= CONTEXT_WORDS
    assert policy.context_words == CONTEXT_WORDS | {"globex"}
    not_refused = [w for w in CONTEXT_WORDS if policy.violations(_TEMPLATE.format(w)) != [_CLAUSE]]
    assert not not_refused, f"shipped terms no longer refused with a site term set: {not_refused}"


def test_repeating_a_shipped_term_changes_nothing() -> None:
    policy = PasswordPolicy.from_settings(_site("Admin", "admin"))
    assert policy.context_words == CONTEXT_WORDS


def test_turning_the_screen_off_with_no_site_terms_still_works() -> None:
    policy = PasswordPolicy(check_breached=False, check_context=False)
    assert policy.violations(_TEMPLATE.format("admin")) == []


# --- load-time validation ------------------------------------------------------------------------


def test_the_default_is_empty() -> None:
    assert AuthSettings().password_extra_context_words == []
    assert PasswordPolicy.from_settings(AuthSettings()).context_words == CONTEXT_WORDS


def test_terms_are_trimmed_lower_cased_and_deduplicated_at_load() -> None:
    s = _site("  Acme ", "ACME", "Globex")
    assert s.password_extra_context_words == ["acme", "globex"]


@pytest.mark.parametrize("bad", ["", "   ", "\t"])
def test_an_empty_or_whitespace_entry_refuses(bad: str) -> None:
    with pytest.raises(ValidationError, match="empty or whitespace-only"):
        _site("acme", bad)


def test_a_term_with_inner_whitespace_refuses() -> None:
    # "acme health" would never refuse "AcmeHealth2026", so it would load as a screen that misses.
    with pytest.raises(ValidationError, match="contains whitespace"):
        _site("acme health")


def test_a_term_below_the_floor_refuses() -> None:
    short = "x" * (EXTRA_CONTEXT_WORD_MIN_LENGTH - 1)
    with pytest.raises(ValidationError, match="shorter than"):
        _site(short)
    # The floor itself is accepted, so the boundary is where the constant says.
    assert _site("x" * EXTRA_CONTEXT_WORD_MIN_LENGTH).password_extra_context_words


def test_the_floor_admits_every_shipped_term() -> None:
    # The floor is justified by the shortest shipped term. If a shorter one ever ships, the site
    # could not add its peer, and the justification would be stale.
    assert min(len(w) for w in CONTEXT_WORDS) >= EXTRA_CONTEXT_WORD_MIN_LENGTH


def test_site_terms_with_the_screen_off_refuse() -> None:
    with pytest.raises(ValidationError, match="password_check_context is false"):
        AuthSettings(password_check_context=False, password_extra_context_words=["acme"])


def test_the_environment_carries_a_comma_separated_list() -> None:
    s = load_settings(environ={"MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS": "Acme, Globex"})
    assert s.auth.password_extra_context_words == ["acme", "globex"]


def test_the_environment_accepts_a_json_array() -> None:
    # Split on commas, '["acme","globex"]' would load terms that keep the brackets and quotes, and
    # those match nothing.
    s = load_settings(environ={"MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS": '["Acme", "globex"]'})
    assert s.auth.password_extra_context_words == ["acme", "globex"]


def test_a_malformed_json_array_in_the_environment_refuses() -> None:
    with pytest.raises(ValidationError, match="does not parse"):
        load_settings(environ={"MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS": '["acme",'})


def test_a_blank_environment_value_means_no_site_terms() -> None:
    s = load_settings(environ={"MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS": "  "})
    assert s.auth.password_extra_context_words == []


def test_an_empty_piece_in_the_environment_list_refuses() -> None:
    # "acme,,globex" is a typo. Dropping the gap silently would hide it.
    with pytest.raises(ValidationError, match="empty or whitespace-only"):
        load_settings(environ={"MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS": "acme,,globex"})


def test_a_trailing_comma_in_the_environment_list_refuses() -> None:
    # Unlike the OIDC and egress lists, which drop an empty piece, this one refuses it: a trailing
    # comma is the same typo as a doubled one. docs/CONFIGURATION.md states this.
    with pytest.raises(ValidationError, match="empty or whitespace-only"):
        load_settings(environ={"MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS": "acme,globex,"})


def test_the_toml_key_loads(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text('[auth]\npassword_extra_context_words = ["Acme", "globex"]\n', encoding="utf-8")
    s = load_settings(config_path=cfg, environ={})
    assert s.auth.password_extra_context_words == ["acme", "globex"]


# --- every path that screens a chosen password -----------------------------------------------------


async def test_the_service_screens_site_terms_on_create_and_change() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _site("globex"))
        identity, _, _ = await login_admin(service)
        password = _TEMPLATE.format("GLOBEX")
        # Create: POST /users screens through password_violations before create_local_user.
        assert service.password_violations(password, username="newuser") == [_SITE]
        # Change: self-service and forced rotation both go through change_password.
        assert await service.change_password(identity, password) == [_SITE]
        # Control: a clean password changes, so the refusal above was the term's.
        assert await service.change_password(identity, _TEMPLATE.format("")) == []
    finally:
        await store.close()


async def test_the_first_administrator_is_screened_for_site_terms() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _site("globex"))
        await service.initialize()
        with pytest.raises(FirstAdministratorRefused, match="this site's additions"):
            await service.provision_first_administrator(
                username="firstadmin", password=_TEMPLATE.format("globex"), actor="test"
            )
    finally:
        await store.close()


# --- the temporary-password generator ------------------------------------------------------------
#
# An administrator's reset issues a generated password through the same policy. Before BACKLOG
# #1132's round-two fix its last-resort return appended "aA1!" to a token WITHOUT screening it, so a
# site term inside that token went out as a credential the policy refuses. Measured 2026-09-28 with
# every three-character site term: the issued password carried the site-term clause.
# Fake tokens are 32 characters, the generator's cut, so the assertions compare them whole.


def _tokens(values: list[str]) -> Iterator[str]:
    yield from values
    while True:
        yield values[-1]


def _fake_tokens(monkeypatch: pytest.MonkeyPatch, source: Iterator[str]) -> None:
    # Only the service module's token source is replaced, and the generator is its one user of
    # token_urlsafe. Session and grant tokens come from auth/tokens.py and stay real.
    fake = SimpleNamespace(token_urlsafe=lambda n=None: next(source))
    monkeypatch.setattr(service_module, "secrets", fake)


async def test_a_reset_refuses_when_every_token_holds_a_site_term(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _site("globex"))
        admin = await create_admin(service)
        # Every token carries the site term.
        _fake_tokens(monkeypatch, _tokens(["zq-globex-" + "v" * 22]))
        with pytest.raises(TemporaryPasswordUnavailable, match="password_extra_context_words"):
            await service.admin_reset_password(admin.user_id, actor="test")
        # Nothing was issued: the account still signs in with the password it had.
        assert (await service.login(admin.username, admin.password)).ok
    finally:
        await store.close()


async def test_a_reset_issues_the_first_token_that_clears_the_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Control for the refusal above: the loop keeps trying, and what it returns clears the policy.
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _site("globex"))
        admin = await create_admin(service)
        clean = "zq-" + "v" * 29
        _fake_tokens(monkeypatch, _tokens(["zq-globex-" + "v" * 22] * 5 + [clean]))
        issued = await service.admin_reset_password(admin.user_id, actor="test")
        assert issued.password == clean
        assert service.policy.violations(issued.password) == []
    finally:
        await store.close()


async def test_the_suffixed_form_is_screened_and_covers_a_missing_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A token with no digit fails an opt-in digit rule; the suffixed form carries one and is issued.
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store,
            AuthSettings(
                password_check_breached=False,
                password_require_digit=True,
                password_extra_context_words=["globex"],
            ),
        )
        admin = await create_admin(service)
        token = "zq-" + "v" * 29
        _fake_tokens(monkeypatch, _tokens([token]))
        issued = await service.admin_reset_password(admin.user_id, actor="test")
        assert issued.password == token + "aA1!"
        assert service.policy.violations(issued.password) == []
    finally:
        await store.close()


@pytest.mark.parametrize(("min_length", "expected"), [(15, 32), (64, 64)])
async def test_a_generated_password_is_cut_to_the_length_a_user_must_type(
    min_length: int, expected: int
) -> None:
    # The site-term hit rate grows with length. The generator cuts each token to the policy minimum,
    # never under 32 characters (192 bits), so a raised minimum does not raise the refusal rate.
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store, _site("globex").model_copy(update={"password_min_length": min_length})
        )
        admin = await create_admin(service)
        issued = await service.admin_reset_password(admin.user_id, actor="test")
        assert len(issued.password) == expected
    finally:
        await store.close()
