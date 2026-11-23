# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Load-time bounds on numeric settings that a consumer would otherwise read as nonsense.

Each case plants one value and asserts the model refuses it, with the field named in the error.
Where 0 is a documented off value, 0 still loads and only a negative is refused.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import AuthSettings

# --- [auth] (BACKLOG #5318) ----------------------------------------------------------------------

#: (field, value the load must refuse). A negative count reads as "refuse every attempt after the
#: first" in RateLimiter, a negative session cap ends every federated session at once, and a cap of
#: 0 pending flows refuses every federated sign-in.
_AUTH_REFUSED: list[tuple[str, Any]] = [
    ("password_min_length", -1),
    ("max_sessions_per_user", -1),
    ("oidc_jwks_ttl_seconds", -1),
    ("oidc_jwks_min_refetch_seconds", -1),
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
def test_auth_refuses_a_value_below_its_floor(field: str, value: Any) -> None:
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
