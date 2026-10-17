# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3169: a user bind the directory ended busy (51), unavailable (52), unwillingToPerform
(53) or adminLimitExceeded (11) judged no password, so it is an outage, never a wrong password.

ldap3's ``bind()`` returns ``False`` for each of those exactly as it does for invalidCredentials
(49). Before this change ``LdapAuthenticator.authenticate`` read every refused bind on a found entry
as ``DirectoryBind(FOUND)`` with no principal, which ``AuthService._reauth_ad`` answers ``False``,
and :meth:`AuthService.reauth` counts that toward the engine lockout. So a busy domain controller
would have charged a user who typed the right password. Now the bind raises
:class:`LdapUnansweredError`, which the re-bind reads as ``directory_unavailable`` and does not count.

Driven at three depths: the REAL ``LdapAuthenticator`` over the ldap3 doubles of
``tests/test_ldap_timeouts.py``; a REAL ldap3 stack decoding a bindResponse from the loopback server
of ``tests/test_ldap_search_result_codes.py``, for each code, plus a Notice of Disconnection carrying
52, which ldap3 raises as a session the server ended and never hands to the code check; and the REAL ``AuthService`` step-up re-bind over the
doubles of ``tests/test_ad_user_account_control.py``, read where a caller meets it: the outcome, the
engine lockout counter, the per-session re-proof budget and the ``auth.reauth`` audit row. Each
refusal has a control on the same doubles: 49 still counts. Every other code keeps its reading from
before this change, which a Manager ruling fixed; 50 stands for them here. **Not exercised:** a real
domain controller. Synthetic data only; no PHI.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import ldap3
import pytest
from ldap3.core.exceptions import LDAPSessionTerminatedByServerError
from ldap3.core.results import (
    RESULT_ADMIN_LIMIT_EXCEEDED,
    RESULT_BUSY,
    RESULT_INSUFFICIENT_ACCESS_RIGHTS,
    RESULT_INVALID_CREDENTIALS,
    RESULT_UNAVAILABLE,
    RESULT_UNWILLING_TO_PERFORM,
)

from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.ldap import (
    DirectoryAnswer,
    LdapAuthenticator,
    LdapError,
    LdapUnansweredError,
)
from tests.test_ad_user_account_control import _signed_in_estate
from tests.test_ldap_referrals import _BIND_RESPONSE, _tlv
from tests.test_ldap_search_result_codes import _done, _Reply, _scripted_dc
from tests.test_ldap_timeouts import _ad_settings, _install_fakes

#: The codes the row names. None judged the password.
_UNJUDGED = [
    pytest.param(RESULT_ADMIN_LIMIT_EXCEEDED, "adminLimitExceeded", id="11-adminLimitExceeded"),
    pytest.param(RESULT_BUSY, "busy", id="51-busy"),
    pytest.param(RESULT_UNAVAILABLE, "unavailable", id="52-unavailable"),
    pytest.param(RESULT_UNWILLING_TO_PERFORM, "unwillingToPerform", id="53-unwillingToPerform"),
]

_PASSWORD = "synthetic-user-pw-3169"


def _bind_ends_with(monkeypatch: pytest.MonkeyPatch, code: int) -> list[str | None]:
    """Over the ldap3 double already installed, end every explicit bind with ``code``, as ldap3's
    synchronous strategy leaves it: ``bind()`` returns ``False`` and ``result`` holds the code.
    Returns the DN of each bind, so a test can tell the real bind from the decoy."""
    binds: list[str | None] = []

    def bind(self: Any) -> bool:
        binds.append(getattr(self, "_bind_dn", None))
        self.result = {"result": code, "description": "x", "message": "", "type": "bindResponse"}
        return False

    monkeypatch.setattr(ldap3.Connection, "bind", bind)
    return binds


def _search_finds_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every search ends with success and no entries, so the bind is the timing-equalizing decoy."""

    def search(self: Any, **_kw: Any) -> bool:
        self.result, self.entries = {"result": 0}, []
        return True

    monkeypatch.setattr(ldap3.Connection, "search", search)


def test_the_codes_are_ldap3s() -> None:
    """The set is spelled in literals, because every ldap3 import in the module is lazy."""
    assert frozenset(p.values[0] for p in _UNJUDGED) == ldap_module._UNJUDGED_BIND_CODES
    assert RESULT_INVALID_CREDENTIALS not in ldap_module._UNJUDGED_BIND_CODES


# --- the authenticator ------------------------------------------------------------------------------


@pytest.mark.parametrize(("code", "name"), _UNJUDGED)
def test_an_unjudged_user_bind_raises_rather_than_reading_as_a_refused_password(
    monkeypatch: pytest.MonkeyPatch, code: int, name: str
) -> None:
    """RED when the bind on a found entry answers ``DirectoryBind(FOUND)`` for this code."""
    _install_fakes(monkeypatch)
    _bind_ends_with(monkeypatch, code)
    with pytest.raises(LdapUnansweredError, match=rf"user bind with result code {code} \({name}\)"):
        LdapAuthenticator(_ad_settings()).authenticate("alice", _PASSWORD)


@pytest.mark.parametrize(
    "code",
    [RESULT_INVALID_CREDENTIALS, RESULT_INSUFFICIENT_ACCESS_RIGHTS],
    ids=["49-invalidCredentials", "50-insufficientAccessRights"],
)
def test_every_other_refused_bind_still_judged_the_found_account(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """THE CONTROL: the same doubles, with 49, still answer a refused password on the found entry.
    50 is kept as it read before this change, by the Manager's ruling, not because it judged one."""
    _install_fakes(monkeypatch)
    _bind_ends_with(monkeypatch, code)
    bind = LdapAuthenticator(_ad_settings()).authenticate("alice", _PASSWORD)
    assert bind.answer is DirectoryAnswer.FOUND and bind.principal is None


@pytest.mark.parametrize("code", [*(p.values[0] for p in _UNJUDGED), RESULT_INVALID_CREDENTIALS])
def test_the_decoy_bind_keeps_the_lookups_answer_whatever_its_code(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """The timing-equalizing decoy reads no result code: the lookup already answered, and an
    outage there would replace "not in the directory" (or "disabled") with "try again later"."""
    _install_fakes(monkeypatch)
    binds = _bind_ends_with(monkeypatch, code)
    _search_finds_nothing(monkeypatch)
    bind = LdapAuthenticator(_ad_settings()).authenticate("nobody", _PASSWORD)
    assert bind.answer is DirectoryAnswer.NOT_FOUND
    assert len(binds) == 1 and "mf-nonexistent-timing-equalizer" in str(binds[0])


@pytest.mark.parametrize(
    "result",
    [{"result": True}, {"result": "51"}, {"result": None}, None],
    ids=["bool", "text", "no-code", "no-result"],
)
def test_a_code_that_is_not_an_integer_keeps_todays_reading(result: object) -> None:
    """Only an integer in the set is refused; anything else is left to the caller, as before."""
    ldap_module._refuse_unjudged_bind(SimpleNamespace(result=result))


# --- through a real ldap3 stack: the bindResponse decode ------------------------------------------

_ALICE = b"CN=alice,OU=Users,DC=example,DC=com"


def _alice(_raw: bytes) -> list[_Reply]:
    """The user search: one enabled entry, then success."""

    def attr(name: bytes, value: bytes) -> bytes:
        return _tlv(0x30, _tlv(0x04, name) + _tlv(0x31, _tlv(0x04, value)))

    attrs = attr(b"sAMAccountName", b"alice") + attr(b"userAccountControl", b"512")
    return [(_tlv(0x64, _tlv(0x04, _ALICE) + _tlv(0x30, attrs)), b""), _done(0)]


@pytest.mark.parametrize("code", [*(p.values[0] for p in _UNJUDGED), RESULT_INVALID_CREDENTIALS])
def test_real_ldap3_leaves_the_bind_code_where_the_refusal_reads_it(code: int) -> None:
    """ldap3 decodes the bindResponse and leaves its code on ``conn.result``, so the refusal sees
    it, for each of the four codes and the 49 control. RED if a future ldap3 cleared or moved it:
    the outage arms would then read as 49 does."""

    def bind_reply(raw: bytes) -> _Reply | None:
        return _done(code, tag=_BIND_RESPONSE) if _ALICE in raw else None

    with _scripted_dc(_alice, bind_reply=bind_reply) as (_dc, authenticator):
        if code == RESULT_INVALID_CREDENTIALS:
            bind = authenticator.authenticate("alice", _PASSWORD)
            assert bind.answer is DirectoryAnswer.FOUND and bind.principal is None
        else:
            with pytest.raises(LdapUnansweredError, match=rf"user bind with result code {code} "):
                authenticator.authenticate("alice", _PASSWORD)


# --- the step-up re-bind, where the lockout is charged ----------------------------------------------


async def _rebind_after(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> tuple[Any, int, list[str], int]:
    """Sign ``alice`` in, end every later bind with ``code``, re-bind once with the right password,
    and return the elevation, the row's failed-attempt count, the ``auth.reauth`` details and the
    number of sessions the per-session re-proof budget has charged."""
    async with _signed_in_estate(monkeypatch, ["alice"]) as (_directory, service, store, tokens):
        _bind_ends_with(monkeypatch, code)
        identity = await service.identity_for_token(tokens["alice"])
        assert identity is not None
        elevation = await service.reauth(identity, _PASSWORD, token=tokens["alice"])
        row = await store.get_user(identity.user_id)
        assert row is not None
        details = [str(dict(r)["detail"]) for r in await store.list_audit(action="auth.reauth")]
        return elevation, row.failed_attempts, details, len(service._reproof_session_failures)


@pytest.mark.parametrize(("code", "name"), _UNJUDGED)
async def test_a_busy_re_bind_is_not_counted_toward_the_engine_lockout(
    monkeypatch: pytest.MonkeyPatch, code: int, name: str
) -> None:
    """Closing step 1. RED when the re-bind charges the row, or audits it as a wrong password."""
    elevation, failed, details, charged = await _rebind_after(monkeypatch, code)
    assert not elevation.ok and elevation.directory_unconfirmed is True
    assert failed == 0, f"a bind ended with {code} ({name}) was counted as a wrong password"
    assert charged == 0, f"a bind ended with {code} ({name}) was charged to the session"
    assert any('"reason": "directory_unavailable"' in d for d in details), details


async def test_a_refused_password_is_still_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE CONTROL: 49 on the same doubles is a wrong password, and counts."""
    elevation, failed, details, charged = await _rebind_after(
        monkeypatch, RESULT_INVALID_CREDENTIALS
    )
    assert not elevation.ok and elevation.directory_unconfirmed is not True
    assert failed == 1 and charged == 1
    assert not any('"reason": "directory_unavailable"' in d for d in details), details


# --- 52 as a Notice of Disconnection: a different path, to the same reading ----------------------

#: RFC 4511 section 4.4.1: an unsolicited extendedResponse under messageID 0, resultCode
#: unavailable (52), responseName (context tag 10) naming the notice.
_NOTICE_OF_DISCONNECTION = _tlv(
    0x30,
    _tlv(0x02, bytes([0]))  # messageID 0: unsolicited
    + _tlv(
        0x78,
        _tlv(0x0A, bytes([RESULT_UNAVAILABLE]))
        + _tlv(0x04, b"")
        + _tlv(0x04, b"")
        + _tlv(0x8A, b"1.3.6.1.4.1.1466.20036"),
    ),
)


def test_real_ldap3_reads_a_notice_of_disconnection_at_the_bind_as_an_outage() -> None:
    """A DC may answer the bind with a Notice of Disconnection, carrying 52, instead of a
    bindResponse. ldap3 never hands that code to the refusal: it raises
    ``LDAPSessionTerminatedByServerError`` from the bind, which ``authenticate`` maps to a plain
    :class:`LdapError`, not :class:`LdapUnansweredError`. The step-up re-bind reads any
    ``LdapError`` as ``directory_unavailable``, so this too is an outage, not a wrong password.
    RED if it ever read as a refused password on the found entry."""

    def bind_reply(raw: bytes) -> _Reply | None:
        return (_NOTICE_OF_DISCONNECTION, b"") if _ALICE in raw else None

    with (
        _scripted_dc(_alice, bind_reply=bind_reply) as (_dc, authenticator),
        pytest.raises(LdapError, match="session terminated by server") as caught,
    ):
        authenticator.authenticate("alice", _PASSWORD)
    assert not isinstance(caught.value, LdapUnansweredError)
    assert isinstance(caught.value.__cause__, LDAPSessionTerminatedByServerError)
