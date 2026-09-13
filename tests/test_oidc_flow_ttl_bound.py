# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``[auth].oidc_flow_ttl_seconds`` is bounded at both ends (BACKLOG #1156, ASVS 10.1.2).

Its sibling ``oidc_clock_skew_seconds`` has been validator-capped since it was introduced; this one
shipped with no validator at all, so a site could stage OIDC flows with a negative, zero or
effectively unbounded lifetime and the configuration would load clean.

Why the endpoints are wrong is in the validator's own comment. What this module pins is that the
refusal EXISTS and that it DISCRIMINATES: the refusal cases fail an accepts-everything validator,
and the acceptance cases fail a refuses-everything one, so the pair rules out both mutants without
asserting on any field this change does not own.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from messagefoundry.auth.oidc.flow import DEFAULT_FLOW_TTL_SECONDS
from messagefoundry.config.settings import AuthSettings

_REFUSED = "oidc_flow_ttl_seconds must be between 30 and 1800"


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(-5, id="negative-discards-the-flow-cookie-on-receipt"),
        pytest.param(29, id="just-below-the-floor"),
        pytest.param(1801, id="just-above-the-ceiling"),
    ],
)
def test_out_of_range_flow_ttl_is_refused_at_config_load(value: int) -> None:
    with pytest.raises(ValidationError, match=_REFUSED):
        AuthSettings(oidc_flow_ttl_seconds=value)


@pytest.mark.parametrize("value", [pytest.param(30, id="floor"), pytest.param(1800, id="ceiling")])
def test_the_boundary_values_themselves_load(value: int) -> None:
    """Both endpoints are inclusive, and this is the arm a refuses-everything mutant fails."""
    assert AuthSettings(oidc_flow_ttl_seconds=value).oidc_flow_ttl_seconds == value


def test_the_shipped_default_is_inside_the_bound() -> None:
    """The bound must never refuse the value the product ships with.

    Read the default off the model rather than restating it, so that moving the default without
    moving the bound fails here rather than at an operator's first start. The round trip is
    load-bearing: ``validate_default`` is off, so constructing ``AuthSettings()`` alone does not run
    this validator at all.
    """
    shipped = AuthSettings().oidc_flow_ttl_seconds
    assert AuthSettings(oidc_flow_ttl_seconds=shipped).oidc_flow_ttl_seconds == shipped


def test_the_settings_default_matches_the_flow_cache_default() -> None:
    """One value, two independently declared defaults, and nothing pinned them together.

    ``FlowCache`` is a library primitive with its own ``DEFAULT_FLOW_TTL_SECONDS``, used whenever it
    is constructed without a settings object. If the two drift, a direct construction silently
    stages flows for a different window than the configured engine does, and no bound catches it
    because both values would sit inside 30..1800.
    """
    assert AuthSettings().oidc_flow_ttl_seconds == DEFAULT_FLOW_TTL_SECONDS
