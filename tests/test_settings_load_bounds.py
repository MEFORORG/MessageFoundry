# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Load-time bounds on numeric settings that a consumer would otherwise read as nonsense.

Each case plants one value and asserts the model refuses it, with the field named in the error.
Where 0 is a documented off value, 0 still loads and at least a negative is refused.
"""

from __future__ import annotations

import types
from typing import Any, Union, get_args, get_origin

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    ApiSettings,
    AuthSettings,
    RetentionSettings,
    StoreSettings,
    _Section,
)

# --- [auth] (BACKLOG #5318) ----------------------------------------------------------------------

#: (field, value the load must refuse). In SlidingWindowRateLimiter a negative per-key count refuses
#: every attempt after a key's first and a negative global count refuses every attempt, a negative
#: session cap ends every federated session at once, and a cap of 0 pending flows refuses every
#: federated sign-in.
_AUTH_REFUSED: list[Any] = [
    ("password_min_length", -1),
    ("max_sessions_per_user", -1),
    ("oidc_jwks_ttl_seconds", -1),
    ("oidc_jwks_min_refetch_seconds", -1),
    # JwksCache refuses an int past the float range (BACKLOG #6904), so the load refuses it too.
    pytest.param("oidc_jwks_ttl_seconds", 10**400, id="oidc_jwks_ttl_seconds-past-float-range"),
    pytest.param(
        "oidc_jwks_min_refetch_seconds",
        10**400,
        id="oidc_jwks_min_refetch_seconds-past-float-range",
    ),
    ("oidc_flow_cache_max", 0),
    ("oidc_flow_cache_max", -1),
    ("oidc_session_max_hours", 0),
    ("oidc_session_max_hours", -1),
    ("login_rate_limit_per_ip", -1),
    ("login_rate_limit_global", -1),
    ("login_rate_limit_window_seconds", -1.0),
    ("phi_read_rate_limit_per_actor", -1),
    ("phi_read_rate_limit_global", -1),
    ("phi_read_rate_limit_window_seconds", -1.0),
]

#: (field, value that still loads): the documented off value 0, and the smallest working value.
_AUTH_LOADS: list[tuple[str, Any]] = [
    ("password_min_length", 0),
    ("max_sessions_per_user", 0),
    ("oidc_jwks_ttl_seconds", 0),
    ("oidc_jwks_min_refetch_seconds", 0),
    ("oidc_flow_cache_max", 1),
    ("oidc_session_max_hours", None),
    ("oidc_session_max_hours", 1),
    ("login_rate_limit_per_ip", 0),
    ("login_rate_limit_global", 0),
    ("login_rate_limit_window_seconds", 0.0),
    ("phi_read_rate_limit_per_actor", 0),
    ("phi_read_rate_limit_global", 0),
    ("phi_read_rate_limit_window_seconds", 0.0),
]


@pytest.mark.parametrize(("field", "value"), _AUTH_REFUSED)
def test_auth_refuses_a_value_outside_its_bounds(field: str, value: Any) -> None:
    with pytest.raises(ValidationError) as info:
        AuthSettings(**{field: value})
    assert field in str(info.value)


@pytest.mark.parametrize(("field", "value"), _AUTH_LOADS)
def test_auth_loads_its_floor(field: str, value: Any) -> None:
    assert getattr(AuthSettings(**{field: value}), field) == value


def test_the_oidc_allow_list_comment_claims_no_runtime_recheck() -> None:
    """S09-58: the comment once said jwks and flow re-check the allow-list before each outbound
    call, and no OIDC runtime module reads it. This pins the comment only: a runtime re-check added
    later is welcome, and should change the comment with it."""
    import inspect

    from messagefoundry.config import settings

    source = inspect.getsource(settings)
    assert "re-check before each outbound call" not in source
    assert "Only the\n    # model-validator reads it, at load" in source


# --- [store], [api] and every float in every section (BACKLOG #5769) ----------------------------

_NON_FINITE = [float("nan"), float("inf"), float("-inf")]

#: The [store] timing fields: acquire_timeout, which the row names, and the rest of them.
_STORE_TIMING = [
    "acquire_timeout",
    "schema_lock_timeout",
    "lease_ttl_seconds",
    "warm_pool_timeout",
    "group_commit_window_ms",
]


@pytest.mark.parametrize("value", _NON_FINITE)
@pytest.mark.parametrize("field", _STORE_TIMING)
def test_a_store_timing_field_refuses_nan_and_infinity(field: str, value: float) -> None:
    with pytest.raises(ValidationError) as info:
        StoreSettings(**{field: value})  # type: ignore[arg-type]
    assert field in str(info.value)


@pytest.mark.parametrize("value", _NON_FINITE)
def test_the_wal_checkpoint_cadence_refuses_nan_and_infinity(value: float) -> None:
    """A NaN or +inf cadence would never run the checkpoint, so purged frames stay in the WAL."""
    with pytest.raises(ValidationError):
        RetentionSettings(wal_checkpoint_seconds=value)


def _is_float_field(annotation: object) -> bool:
    """``float`` or an optional/union of it; never a container such as ``dict[str, float]``,
    which the root refusal does not walk."""
    if annotation is float:
        return True
    return get_origin(annotation) in (Union, types.UnionType) and float in get_args(annotation)


def _section_float_fields() -> list[tuple[type[_Section], str]]:
    # Only the shipped sections: a test module's own _Section subclass would otherwise join the
    # census or not, by import order.
    found: set[tuple[type[_Section], str]] = set()
    pending: list[type[_Section]] = list(_Section.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if not cls.__module__.startswith("messagefoundry."):
            continue
        for name, info in cls.model_fields.items():
            if _is_float_field(info.annotation):
                found.add((cls, name))
    return sorted(found, key=lambda pair: (pair[0].__name__, pair[1]))


def test_the_census_finds_floats() -> None:
    """The positive control for the census below: an empty census would pass vacuously."""
    found = {(cls.__name__, name) for cls, name in _section_float_fields()}
    assert ("StoreSettings", "lease_ttl_seconds") in found
    assert ("RetentionSettings", "wal_checkpoint_seconds") in found
    assert len(found) >= 40  # 50 at the time of writing


@pytest.mark.parametrize(("cls", "field"), _section_float_fields())
def test_every_section_float_refuses_nan(cls: type[_Section], field: str) -> None:
    """The root fix on _Section reaches a float field added later too. A field with its own
    finiteness check refuses first, under its own message; either way the field is named."""
    with pytest.raises(ValidationError) as info:
        cls(**{field: float("nan")})
    assert field in str(info.value)


def test_an_infinity_is_refused_under_the_root_message() -> None:
    """+inf passes ``lease_ttl_seconds``' own ``<= 0`` check, so the root check names it."""
    with pytest.raises(ValidationError, match="lease_ttl_seconds must be a finite number"):
        StoreSettings(lease_ttl_seconds=float("inf"))


@pytest.mark.parametrize(("field", "value"), [("port", 0), ("port", 65536), ("pool_size", 0)])
def test_store_refuses_a_port_or_pool_out_of_range(field: str, value: int) -> None:
    with pytest.raises(ValidationError) as info:
        StoreSettings(**{field: value})  # type: ignore[arg-type]
    assert field in str(info.value)


def test_the_store_statement_timeout_refuses_a_negative_and_keeps_zero() -> None:
    with pytest.raises(ValidationError):
        StoreSettings(command_timeout=-1)
    assert StoreSettings(command_timeout=0).command_timeout == 0


@pytest.mark.parametrize("value", [0, -1])
def test_the_store_login_timeout_is_at_least_one_second(value: int) -> None:
    """asyncpg reads a 0 connect timeout as already expired, so no connection would open."""
    with pytest.raises(ValidationError, match="connect_timeout"):
        StoreSettings(connect_timeout=value)
    assert StoreSettings(connect_timeout=1).connect_timeout == 1


@pytest.mark.parametrize("value", [-1, 65536])
def test_api_refuses_a_port_out_of_range(value: int) -> None:
    with pytest.raises(ValidationError):
        ApiSettings(port=value)


@pytest.mark.parametrize("value", [0, 65535])
def test_api_loads_a_port_at_either_end_of_the_range(value: int) -> None:
    assert ApiSettings(port=value).port == value
