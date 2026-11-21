# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connection policy models refuse a boolean where a number is meant (BACKLOG #5509).

The settings sections refuse ``true``/``false`` on a numeric key through the shared
``NumbersRefuseBool`` base. The policy models in ``config/models.py`` that ``connections.toml``
and code-first wiring build were plain ``BaseModel`` subclasses, so pydantic's lax mode read
``backoff_seconds = true`` as 1.0 and ``max_attempts = false`` as 0, a permanent no-retry
failure. They now share the same guard."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from messagefoundry.config.models import (
    ActiveWindow,
    BatchConfig,
    BuildupThreshold,
    RetryPolicy,
    SaturationThreshold,
    StallThreshold,
    Validation,
)

_REFUSAL = "expects a number, not a boolean"

#: One valid payload per model, so a probe changes only the field under test.
_BASE: dict[type[BaseModel], dict[str, object]] = {
    RetryPolicy: {},
    BuildupThreshold: {},
    StallThreshold: {},
    SaturationThreshold: {},
    ActiveWindow: {"days": [0], "start": "08:00", "end": "17:00"},
    BatchConfig: {"max_count": 10, "max_wait_ms": 500},
    Validation: {},
}

#: Every numeric field of each model, and a bool spelling of it.
_CASES: list[tuple[type[BaseModel], str, object]] = [
    (RetryPolicy, "max_attempts", False),
    (RetryPolicy, "max_attempts", True),
    (RetryPolicy, "backoff_seconds", True),
    (RetryPolicy, "backoff_multiplier", True),
    (RetryPolicy, "max_backoff_seconds", True),
    (BuildupThreshold, "max_depth", True),
    (BuildupThreshold, "max_oldest_seconds", True),
    (StallThreshold, "max_oldest_seconds", True),
    (SaturationThreshold, "sustain_samples", True),
    (SaturationThreshold, "min_growth", True),
    (ActiveWindow, "days", [True]),
    (BatchConfig, "max_count", True),
    (BatchConfig, "max_wait_ms", True),
    (Validation, "strict_timeout_s", False),
]


@pytest.mark.parametrize(
    ("model", "name", "value"),
    _CASES,
    ids=[f"{m.__name__}.{n}={v!r}" for m, n, v in _CASES],
)
def test_a_policy_model_refuses_a_bool_on_a_number(
    model: type[BaseModel], name: str, value: object
) -> None:
    with pytest.raises(ValidationError, match=f"{name}.* {_REFUSAL}"):
        model.model_validate({**_BASE[model], name: value})


@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize("model", list(_BASE), ids=lambda m: m.__name__)
def test_every_numeric_field_is_covered(model: type[BaseModel], value: bool) -> None:
    """A sweep over every field: none reads a bool as a number, so a numeric field added later
    without the guard fails here."""
    for name in model.model_fields:
        try:
            built = model.model_validate({**_BASE[model], name: value})
        except ValidationError:
            continue
        got = getattr(built, name)
        assert isinstance(got, bool) or not isinstance(got, int | float), (model, name)


def test_an_assigned_bool_is_refused_on_retry_policy() -> None:
    """``RetryPolicy`` validates assignment, so ``policy.max_attempts = False`` is refused too."""
    policy = RetryPolicy()
    with pytest.raises(ValidationError, match=_REFUSAL):
        policy.max_attempts = False
    assert policy.max_attempts == 100


def test_numbers_and_bool_fields_still_load() -> None:
    """The guard refuses only a bool read as a number: numbers, ``None`` and real bool fields
    load as before."""
    assert RetryPolicy(max_attempts=0, backoff_seconds=1).max_attempts == 0
    assert RetryPolicy(max_attempts=None).max_attempts is None
    assert BuildupThreshold(max_depth=5, max_oldest_seconds=None).max_depth == 5
    assert StallThreshold(max_oldest_seconds=float("inf")).max_oldest_seconds is None
    assert BatchConfig(max_count=2, max_wait_ms=1).max_count == 2
    assert ActiveWindow.model_validate(_BASE[ActiveWindow]).days == frozenset({0})
    assert Validation(strict=True, strict_timeout_s=0).strict is True
