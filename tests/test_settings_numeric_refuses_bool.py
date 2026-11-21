# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A boolean on a numeric settings key is refused, never coerced to 0 or 1 (BACKLOG #5509).

pydantic's lax mode turns ``True`` into ``1`` and ``False`` into ``0`` for an ``int`` or ``float``
field, so ``delete_message_bodies_after_days = false`` in messagefoundry.toml would read as 0,
"keep indefinitely", and ``max_upload_bytes = true`` as a one-byte cap. The shared ``_Section``
base refuses a bool that validation would read as a number, at least on a scalar, an optional or
constrained number, a list, set or dict of numbers and a nested model's fields. An environment
string such as ``"5"`` still parses."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import pytest
from pydantic import BaseModel, Field, PositiveInt, ValidationError

from messagefoundry.config.settings import (
    DeliverySettings,
    _Section,
    load_settings,
)


def _sections() -> list[type[_Section]]:
    """Every engine ``_Section`` subclass, nested ones such as ``[cluster.vip]`` included. A test
    module's own subclass is left out, so every xdist worker collects the same list."""
    found: list[type[_Section]] = []
    pending: list[type[_Section]] = [_Section]
    while pending:
        for sub in pending.pop().__subclasses__():
            pending.append(sub)
            if sub.__module__.startswith("messagefoundry."):
                found.append(sub)
    return sorted(found, key=lambda model: model.__qualname__)


_FIELDS: list[tuple[type[_Section], str]] = [
    (model, name) for model in _sections() for name in sorted(model.model_fields)
]


#: The guard's own refusal text, not pydantic's "Input should be a valid boolean".
_REFUSAL = "expects a number, not a boolean"


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


def _probe(model: type[BaseModel], name: str, value: object) -> str:
    """``refused-bool`` when the guard refused ``value``, ``refused`` when the field refused it
    otherwise, ``number`` when a bool-only input validated to a value holding a number, ``kept``
    when it validated otherwise, and ``unknown`` when another check refused."""
    try:
        built = model.model_validate({name: value})
    except ValidationError as exc:
        mine = [err for err in exc.errors() if err["loc"][:1] == (name,)]
        if any(_REFUSAL in err["msg"] for err in mine):
            return "refused-bool"
        return "refused" if mine else "unknown"
    return "number" if _holds_a_number(getattr(built, name)) else "kept"


def test_the_sweep_reaches_numeric_and_nested_fields() -> None:
    """Positive control: a sweep that refuses nothing with the bool message proves nothing."""
    names = {(model.__name__, name) for model, name in _FIELDS}
    assert ("ClusterVipSettings", "prefix") in names
    refused = [(m, n) for m, n in _FIELDS if _probe(m, n, True) == "refused-bool"]
    assert len(refused) > 100
    assert any(
        m.__name__ == "SecuritySettings" and n == "delete_message_bodies_after_days"
        for m, n in refused
    )


@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize(("model", "name"), _FIELDS, ids=[f"{m.__name__}.{n}" for m, n in _FIELDS])
def test_no_section_field_reads_a_bool_as_a_number(
    model: type[_Section], name: str, value: bool
) -> None:
    assert _probe(model, name, value) != "number"
    assert _probe(model, name, [value]) != "number"


class _Shapes(_Section):
    """A probe section holding numeric shapes no shipped section may have today."""

    constrained: Annotated[int, Field(ge=0)] | None = None
    positive: PositiveInt | None = None
    numbers: list[int] = []
    rates: dict[str, float] = {}
    days: frozenset[int] = frozenset()
    flag: bool = False


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("constrained", True),
        ("positive", True),
        ("numbers", [3, False]),
        ("rates", {"x": False}),
        ("days", [False]),
    ],
)
def test_every_numeric_shape_refuses_a_bool(name: str, value: object) -> None:
    with pytest.raises(ValidationError, match=_REFUSAL):
        _Shapes.model_validate({name: value})


def test_the_list_probe_can_see_a_list_of_numbers() -> None:
    """Control for the sweep's list half: without the guard ``[True]`` on a ``list[int]`` field
    validates to ``[1]``, which the probe reads as ``number``."""

    class _Plain(BaseModel):
        numbers: list[int] = []

    assert _probe(_Plain, "numbers", [True]) == "number"
    assert _probe(_Shapes, "numbers", [True]) == "refused-bool"


def test_false_on_a_positive_bound_names_the_bool_not_the_bound() -> None:
    with pytest.raises(ValidationError, match=_REFUSAL):
        DeliverySettings.model_validate({"retry_backoff_seconds": False})


def test_a_bool_field_and_numbers_still_validate() -> None:
    built = _Shapes.model_validate(
        {"flag": True, "numbers": [1, 2], "rates": {"x": 0.5}, "days": [0], "positive": 3}
    )
    assert built.flag is True and built.numbers == [1, 2] and built.days == frozenset({0})


def test_a_bool_in_the_file_refuses_load_naming_the_key(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[security]\ndelete_message_bodies_after_days = false\n", encoding="utf-8")
    with pytest.raises(ValidationError) as caught:
        load_settings(config_path=cfg, environ={})
    assert f"delete_message_bodies_after_days {_REFUSAL}" in str(caught.value)


_RULE = '[[alerts.rules]]\nevent_type = "queue_buildup"\n'


@pytest.mark.parametrize(
    ("body", "path"),
    [
        ("cooldown_seconds = true\n", "rules[0].cooldown_seconds"),
        ("cooldown_seconds = false\n", "rules[0].cooldown_seconds"),
        ("min_depth = true\n", "rules[0].min_depth"),
        ("min_oldest_seconds = false\n", "rules[0].min_oldest_seconds"),
        ("[[alerts.rules.escalate]]\nafter_count = false\n", "rules[0].escalate[0].after_count"),
        ("[[alerts.rules.escalate]]\nafter_count = true\n", "rules[0].escalate[0].after_count"),
    ],
)
def test_a_bool_in_a_nested_alert_rule_refuses_naming_its_path(
    tmp_path: Path, body: str, path: str
) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(_RULE + body, encoding="utf-8")
    with pytest.raises(ValidationError) as caught:
        load_settings(config_path=cfg, environ={})
    assert f"{path} {_REFUSAL}" in str(caught.value)


def test_a_bool_in_an_alert_schedule_window_refuses_at_its_location(tmp_path: Path) -> None:
    """``ActiveWindow`` refuses the bool itself, so the message names its own field and the
    error's location names the rest of the path."""
    cfg = tmp_path / "messagefoundry.toml"
    window = '[[alerts.rules.schedule.windows]]\ndays = [false]\nstart = "08:00"\nend = "17:00"\n'
    cfg.write_text(_RULE + window, encoding="utf-8")
    with pytest.raises(ValidationError) as caught:
        load_settings(config_path=cfg, environ={})
    (err,) = caught.value.errors()
    assert err["loc"] == ("alerts", "rules", 0, "schedule", "windows", 0, "days")
    assert f"days {_REFUSAL}" in err["msg"]


def test_a_number_and_an_environment_string_still_parse(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[delivery]\nretry_backoff_seconds = 9\n", encoding="utf-8")
    s = load_settings(config_path=cfg, environ={"MEFOR_DELIVERY_RETRY_MAX_ATTEMPTS": "7"})
    assert s.delivery.retry_backoff_seconds == 9.0
    assert s.delivery.retry_max_attempts == 7


def test_an_optional_numeric_field_still_takes_none() -> None:
    assert DeliverySettings(retry_max_attempts=None).retry_max_attempts is None
    with pytest.raises(ValidationError, match=_REFUSAL):
        DeliverySettings.model_validate({"retry_max_attempts": True})
