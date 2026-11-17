# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``[alerts]`` send timeouts, cooldowns and SMTP port load only in range (BACKLOG #5770).

A huge timeout would let each wait on a peer hold the one-event-at-a-time alert worker, a
non-finite one fails every send, an infinite cooldown would make the first page the last, a port
outside 0-65535 would fail every send, and a boolean would load as a number, `true` as 1 and
`false` as 0. Each is refused at load, and the defaults and the caps themselves still load.
"""

from __future__ import annotations

import math
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    _ALERT_COOLDOWN_MAX_SECONDS,
    _ALERT_SEND_TIMEOUT_MAX_SECONDS,
    AlertRule,
    AlertsSettings,
)

_NON_FINITE = [math.inf, -math.inf, math.nan]


@pytest.mark.parametrize("field", ["webhook_timeout", "email_timeout"])
@pytest.mark.parametrize("value", [*_NON_FINITE, 0.0, -1.0, _ALERT_SEND_TIMEOUT_MAX_SECONDS + 1])
def test_a_send_timeout_out_of_range_is_refused(field: str, value: float) -> None:
    with pytest.raises(ValidationError, match=field):
        AlertsSettings.model_validate({field: value})


@pytest.mark.parametrize("value", [*_NON_FINITE, -1.0, _ALERT_COOLDOWN_MAX_SECONDS + 1])
def test_a_realert_window_out_of_range_is_refused(value: float) -> None:
    with pytest.raises(ValidationError, match="realert_seconds"):
        AlertsSettings(realert_seconds=value)


@pytest.mark.parametrize("value", [-1, 65536])
def test_an_smtp_port_out_of_range_is_refused(value: int) -> None:
    with pytest.raises(ValidationError, match="email_smtp_port"):
        AlertsSettings(email_smtp_port=value)


@pytest.mark.parametrize(
    "kwargs",
    [
        {},  # the defaults
        {"webhook_timeout": _ALERT_SEND_TIMEOUT_MAX_SECONDS},
        {"email_timeout": _ALERT_SEND_TIMEOUT_MAX_SECONDS},
        {"realert_seconds": 0.0},  # no throttle
        {"realert_seconds": _ALERT_COOLDOWN_MAX_SECONDS},
        {"email_smtp_port": 0},  # smtplib's default, port 25
        {"email_smtp_port": 65535},
    ],
)
def test_in_range_alert_settings_load(kwargs: dict[str, Any]) -> None:
    AlertsSettings.model_validate(kwargs)


@pytest.mark.parametrize("value", [*_NON_FINITE, 0.0, _ALERT_COOLDOWN_MAX_SECONDS + 1])
def test_a_rule_cooldown_out_of_range_is_refused(value: float) -> None:
    with pytest.raises(ValidationError, match="cooldown_seconds"):
        AlertRule(cooldown_seconds=value)


@pytest.mark.parametrize("value", [*_NON_FINITE, -1.0])
def test_a_rule_oldest_age_out_of_range_is_refused(value: float) -> None:
    with pytest.raises(ValidationError, match="min_oldest_seconds"):
        AlertRule(event_type="queue_buildup", min_oldest_seconds=value)


def test_in_range_rule_values_load() -> None:
    AlertRule(cooldown_seconds=_ALERT_COOLDOWN_MAX_SECONDS)
    AlertRule(event_type="queue_buildup", min_oldest_seconds=0.0)


@pytest.mark.parametrize(
    "field", ["webhook_timeout", "email_timeout", "realert_seconds", "email_smtp_port"]
)
def test_a_boolean_is_refused_for_a_numeric_alert_setting(field: str) -> None:
    with pytest.raises(ValidationError, match="not a boolean"):
        AlertsSettings.model_validate({field: True})


@pytest.mark.parametrize("field", ["cooldown_seconds", "min_oldest_seconds", "min_depth"])
def test_a_boolean_is_refused_for_a_numeric_rule_field(field: str) -> None:
    with pytest.raises(ValidationError, match="not a boolean"):
        AlertRule.model_validate({"event_type": "queue_buildup", field: True})
