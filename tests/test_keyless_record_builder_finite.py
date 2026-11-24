# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A keyless store's record builders refuse a float that is not finite (BACKLOG #6717 item 9).

With a sealer, :meth:`RowSealer.seal` refuses a NaN or an infinity, because SQLite stores a NaN as
``NULL``. With no sealer the builders wrote an empty seal and let the value through, so a keyless
store wrote the NaN and read back ``None`` without a word. Each builder now refuses it there too.
"""

from __future__ import annotations

import math
from dataclasses import fields, replace
from typing import Any

import pytest

from messagefoundry.store.store import (
    SessionRecord,
    UserAuthzRecord,
    UserRow,
    approval_tombstone,
    approval_tombstone_async,
    new_approval_row,
    seal_approval,
    seal_approval_async,
    seal_session,
    seal_session_async,
    seal_user,
    seal_user_async,
)

_NON_FINITE = [math.nan, math.inf, -math.inf]


def _session(**changes: Any) -> SessionRecord:
    base = SessionRecord(
        token_hash="t" * 64,
        user_id="u-6717",
        created_at=1.0,
        expires_at=3.0,
        last_used_at=2.0,
        revoked_at=None,
        client="198.51.100.7",
    )
    return replace(base, **changes)


def _approval(**changes: Any) -> Any:
    row = new_approval_row(
        approval_id="a-6717",
        operation="op",
        params="{}",
        requester="r",
        requester_user_id="u-6717",
        requested_at=1.0,
        expires_at=None,
    )
    return replace(row, **changes)


def _sample(annotation: object) -> Any:
    text = str(annotation)
    if "bool" in text:
        return False
    if "int" in text:
        return 0
    if "float" in text:
        return 0.0
    return "x"


def _user(**changes: Any) -> UserAuthzRecord:
    row = UserRow(**{f.name: _sample(f.type) for f in fields(UserRow)})
    return UserAuthzRecord(row=replace(row, **changes))


@pytest.mark.parametrize("value", _NON_FINITE)
def test_seal_session_refuses_a_non_finite_float_with_no_sealer(value: float) -> None:
    with pytest.raises(ValueError, match="not finite"):
        seal_session(None, _session(reauth_at=value))


@pytest.mark.parametrize("value", _NON_FINITE)
async def test_seal_session_async_refuses_a_non_finite_float_with_no_sealer(value: float) -> None:
    with pytest.raises(ValueError, match="not finite"):
        await seal_session_async(None, _session(idp_auth_time=value))


@pytest.mark.parametrize("value", _NON_FINITE)
def test_seal_approval_refuses_a_non_finite_float_with_no_sealer(value: float) -> None:
    with pytest.raises(ValueError, match="not finite"):
        seal_approval(None, _approval(expires_at=value))


@pytest.mark.parametrize("value", _NON_FINITE)
async def test_seal_approval_async_refuses_a_non_finite_float_with_no_sealer(value: float) -> None:
    with pytest.raises(ValueError, match="not finite"):
        await seal_approval_async(None, _approval(requested_at=value))


@pytest.mark.parametrize("value", _NON_FINITE)
def test_seal_user_refuses_a_non_finite_float_with_no_sealer(value: float) -> None:
    with pytest.raises(ValueError, match="not finite"):
        seal_user(None, _user(created_at=value))


@pytest.mark.parametrize("value", _NON_FINITE)
async def test_seal_user_async_refuses_a_non_finite_float_with_no_sealer(value: float) -> None:
    with pytest.raises(ValueError, match="not finite"):
        await seal_user_async(None, _user(created_at=value))


@pytest.mark.parametrize("value", _NON_FINITE)
async def test_approval_tombstone_refuses_a_non_finite_decision_time_with_no_sealer(
    value: float,
) -> None:
    with pytest.raises(ValueError, match="not finite"):
        approval_tombstone(None, "a-6717", approver="ap", decided_at=value)
    with pytest.raises(ValueError, match="not finite"):
        await approval_tombstone_async(None, "a-6717", approver="ap", decided_at=value)


async def test_a_finite_record_still_takes_an_empty_seal_with_no_sealer() -> None:
    """The control: a finite row is unchanged, so the refusal is the only new behaviour."""
    assert seal_session(None, _session(seal="old")).seal == ""
    assert (await seal_session_async(None, _session(seal="old"))).seal == ""
    assert seal_approval(None, _approval(seal="old")).seal == ""
    assert (await seal_approval_async(None, _approval(seal="old"))).seal == ""
    assert seal_user(None, _user(authz_seal="old")).row.authz_seal == ""
    assert (await seal_user_async(None, _user(authz_seal="old"))).row.authz_seal == ""
    assert approval_tombstone(None, "a-6717", approver="ap", decided_at=1.0) == ""
    assert await approval_tombstone_async(None, "a-6717", approver="ap", decided_at=1.0) == ""
