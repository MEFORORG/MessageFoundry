# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``[auth].oidc_flow_ttl_seconds`` is bounded at both ends (BACKLOG #1156, ASVS 10.1.2).

Its sibling ``oidc_clock_skew_seconds`` has been validator-capped since it was introduced; this one
shipped with no validator at all, so a site could stage OIDC flows with a negative, zero or
effectively unbounded lifetime and the configuration would load clean.

The three consequences are in the validator's own comment. What this module pins is that the refusal
EXISTS and that it discriminates -- an accepting-everything validator and an absent one look
identical from a passing suite, which is why every refusal case here is paired with an acceptance
case that must still load.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.settings import AuthSettings

# A value that loads. Also the shipped default, so the acceptance arm doubles as a guard against a
# bound that would refuse the product's own default.
DEFAULT_TTL = 300


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(-5, id="negative-discards-the-flow-cookie-on-receipt"),
        pytest.param(0, id="zero-discards-the-flow-cookie-on-receipt"),
        pytest.param(29, id="just-below-the-floor"),
        pytest.param(1801, id="just-above-the-ceiling"),
        pytest.param(100_000_000, id="starves-the-reject-when-full-flow-cache"),
    ],
)
def test_out_of_range_flow_ttl_is_refused_at_config_load(value: int) -> None:
    with pytest.raises(ValueError, match="oidc_flow_ttl_seconds must be between 30 and 1800"):
        AuthSettings(oidc_flow_ttl_seconds=value)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(30, id="the-floor-itself"),
        pytest.param(DEFAULT_TTL, id="the-shipped-default"),
        pytest.param(1800, id="the-ceiling-itself"),
    ],
)
def test_in_range_flow_ttl_still_loads(value: int) -> None:
    assert AuthSettings(oidc_flow_ttl_seconds=value).oidc_flow_ttl_seconds == value


def test_the_shipped_default_is_inside_the_bound() -> None:
    """The bound must never refuse the value the product ships with.

    Read from the model rather than from ``DEFAULT_TTL`` so that moving the default without moving
    the bound fails here rather than at an operator's first start.
    """
    shipped = AuthSettings().oidc_flow_ttl_seconds
    assert AuthSettings(oidc_flow_ttl_seconds=shipped).oidc_flow_ttl_seconds == shipped


def test_the_sibling_cap_is_untouched() -> None:
    """The positive control for the whole module.

    ``oidc_clock_skew_seconds`` was already capped. If this assertion ever fails alongside the ones
    above, the cause is the validator machinery rather than this field's own bound -- which is the
    distinction a bare "the tests are red" cannot draw.
    """
    with pytest.raises(ValueError, match="oidc_clock_skew_seconds must be between 0 and 300"):
        AuthSettings(oidc_clock_skew_seconds=301)
    assert AuthSettings(oidc_clock_skew_seconds=60).oidc_clock_skew_seconds == 60
