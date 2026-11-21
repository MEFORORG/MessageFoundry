# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connection models refuse a boolean where a number is meant (BACKLOG #5509).

The settings sections refuse ``true``/``false`` on a numeric key through the shared
``NumbersRefuseBool`` base. The models in ``config/models.py`` were plain ``BaseModel``
subclasses, so pydantic's lax mode read a bool as 1 or 0 wherever they validate laxly: code-first
construction such as ``RetryPolicy(max_attempts=False)``, a permanent no-retry failure, and the
``connections.toml`` schedule table, where ``days = [true]`` read as Tuesday. The retry, buildup,
stall and batch tables already validate strictly (BACKLOG #5899). They now share the one guard,
which also names the bool on that strict path. Synthetic config only."""

from __future__ import annotations

import inspect
import textwrap
from datetime import time
from pathlib import Path
from typing import Annotated

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

from messagefoundry.config import models
from messagefoundry.config.bool_numbers import NumbersRefuseBool
from messagefoundry.config.connections_file import load_connections_data
from messagefoundry.config.models import (
    ActiveWindow,
    BatchConfig,
    BuildupThreshold,
    ConnectorType,
    Destination,
    RetryPolicy,
    SaturationThreshold,
    StallThreshold,
    Validation,
)
from messagefoundry.config.wiring import Registry, WiringError

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
    Destination: {"name": "OB", "type": ConnectorType.MLLP},
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
    (ActiveWindow, "days", frozenset({True, 2})),
    (BatchConfig, "max_count", True),
    (BatchConfig, "max_wait_ms", True),
    (Validation, "strict_timeout_s", False),
    (Destination, "waiting_display_delay", True),
]


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize(
    ("model", "name", "value"),
    _CASES,
    ids=[f"{m.__name__}.{n}={v!r}" for m, n, v in _CASES],
)
def test_a_policy_model_refuses_a_bool_on_a_number(
    model: type[BaseModel], name: str, value: object, strict: bool
) -> None:
    payload = {**_BASE[model], name: value}
    if strict:
        if model in (ActiveWindow, Destination):
            pytest.skip("validated laxly: set and time fields arrive as TOML arrays and strings")
        with pytest.raises(ValidationError, match=f"{name}.* {_REFUSAL}"):
            model.model_validate(payload, strict=True)
    else:
        with pytest.raises(ValidationError, match=f"{name}.* {_REFUSAL}"):
            model.model_validate(payload)


#: Numbers, alone and in a list, that a numeric field validates: a value inside the usual bounds,
#: such as ``ge=2`` or a weekday ordinal, as well as 1. No dict probe: the free-form ``settings``
#: dicts would take one as a number, and no model here has a dict-of-numbers field.
_NUMBER_PROBES: tuple[object, ...] = (1, 5, [1], [5])


def _holds_a_number(got: object) -> bool:
    if isinstance(got, bool):
        return False
    if isinstance(got, int | float):
        return True
    if isinstance(got, dict):
        return any(_holds_a_number(item) for item in got.values())
    if isinstance(got, list | tuple | set | frozenset):
        return any(_holds_a_number(item) for item in got)
    return False


def _numeric_models() -> list[type[BaseModel]]:
    """Every model in ``config.models`` with a field that validates at least one of
    :data:`_NUMBER_PROBES` to a value holding a number."""
    found = []
    for _, model in inspect.getmembers(models, inspect.isclass):
        if not issubclass(model, BaseModel) or model.__module__ != models.__name__:
            continue
        if any(
            _assigns_a_number(model, name, probe)
            for name in model.model_fields
            for probe in _NUMBER_PROBES
        ):
            found.append(model)
    return found


def _assigns_a_number(model: type[BaseModel], name: str, probe: object) -> bool:
    """Whether the field's own type and bounds, with no model validator, read ``probe`` as a
    value holding a number."""
    field = model.model_fields[name]
    adapter: TypeAdapter[object] = TypeAdapter(Annotated[field.annotation, field])  # type: ignore[arg-type]
    try:
        got = adapter.validate_python(probe)
    except ValidationError:
        return False
    return _holds_a_number(got)


def test_every_model_with_a_number_shares_the_guard() -> None:
    """A model added to ``config.models`` with a numeric field, as a plain ``BaseModel``, fails
    here. The positive control is that the walk finds the models this file probes, a set field
    and a bounded one among them."""
    numeric = _numeric_models()
    assert {RetryPolicy, BatchConfig, Destination, ActiveWindow} <= set(numeric)
    assert [m.__name__ for m in numeric if not issubclass(m, NumbersRefuseBool)] == []


def test_an_assigned_bool_is_refused_on_retry_policy() -> None:
    """``RetryPolicy`` validates assignment, so ``policy.max_attempts = False`` is refused too."""
    policy = RetryPolicy()
    with pytest.raises(ValidationError, match=_REFUSAL):
        policy.max_attempts = False
    assert policy.max_attempts == 100


def _load(sub_table: str) -> Registry:
    text = textwrap.dedent(
        """
        [[outbound]]
        name = "OB"
        transport = "mllp"
          [outbound.settings]
          host = "partner.example"
          port = 2700
        """
    ) + textwrap.dedent(sub_table)
    registry = Registry()
    load_connections_data(text.encode("utf-8"), Path("connections.toml"), registry)
    return registry


@pytest.mark.parametrize(
    ("sub_table", "key"),
    [
        ("[outbound.retry]\nmax_attempts = false\n", "max_attempts"),
        ("[outbound.buildup]\nmax_depth = true\n", "max_depth"),
        ("[outbound.stall]\nmax_oldest_seconds = true\n", "max_oldest_seconds"),
        ("[outbound.batch]\nmax_count = 10\nmax_wait_ms = true\n", "max_wait_ms"),
        (
            '[outbound.schedule]\n[[outbound.schedule.windows]]\ndays = [true]\nstart = "08:00"\n'
            'end = "17:00"\n',
            "days",
        ),
    ],
)
def test_a_bool_in_connections_toml_names_the_key_and_the_bool(sub_table: str, key: str) -> None:
    with pytest.raises(WiringError, match=f"{key} {_REFUSAL}"):
        _load(sub_table)


def test_a_self_referencing_destination_setting_still_loads() -> None:
    """The guard stops at a value validation handed back unchanged, so a free-form ``settings``
    value that refers to itself does not send the walk into a loop."""
    looped: dict[str, object] = {"a": 1}
    looped["self"] = looped
    built = Destination(name="OB", type=ConnectorType.MLLP, settings={"opts": looped})
    assert built.settings["opts"] is looped


def test_numbers_and_bool_fields_still_load() -> None:
    """The guard refuses only a bool read as a number: numbers, ``None`` and real bool fields
    load as before."""
    assert RetryPolicy(max_attempts=0, backoff_seconds=1).max_attempts == 0
    assert RetryPolicy(max_attempts=None).max_attempts is None
    assert BuildupThreshold(max_depth=5, max_oldest_seconds=None).max_depth == 5
    assert StallThreshold(max_oldest_seconds=float("inf")).max_oldest_seconds is None
    assert BatchConfig(max_count=2, max_wait_ms=1).max_count == 2
    assert ActiveWindow(days=frozenset({0, 6}), start=time(8), end=time(17)).days == {0, 6}
    assert Validation(strict=True, strict_timeout_s=0).strict is True
    assert Destination(name="OB", type=ConnectorType.MLLP, simulate=True).simulate is True
