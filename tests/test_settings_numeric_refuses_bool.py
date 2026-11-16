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


def _probe(model: type[BaseModel], name: str, value: object) -> str:
    """``refused`` when the field itself refused ``value``, ``number`` when it took a bool as a
    number, ``kept`` when it validated otherwise, and ``unknown`` when another check refused."""
    try:
        built = model.model_validate({name: value})
    except ValidationError as exc:
        mine = [err for err in exc.errors() if err["loc"][:1] == (name,)]
        if any("boolean" in err["msg"] for err in mine):
            return "refused-bool"
        return "refused" if mine else "unknown"
    got = getattr(built, name)
    return "number" if isinstance(got, int | float) and not isinstance(got, bool) else "kept"


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
    with pytest.raises(ValidationError, match="boolean"):
        _Shapes.model_validate({name: value})


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
    assert "delete_message_bodies_after_days" in str(caught.value)
    assert "boolean" in str(caught.value)


def test_a_bool_in_a_nested_alert_rule_refuses_naming_its_path(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        '[[alerts.rules]]\nevent_type = "queue_buildup"\ncooldown_seconds = true\n',
        encoding="utf-8",
    )
    with pytest.raises(ValidationError) as caught:
        load_settings(config_path=cfg, environ={})
    assert "rules[0].cooldown_seconds expects a number" in str(caught.value)


def test_a_number_and_an_environment_string_still_parse(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[delivery]\nretry_backoff_seconds = 9\n", encoding="utf-8")
    s = load_settings(config_path=cfg, environ={"MEFOR_DELIVERY_RETRY_MAX_ATTEMPTS": "7"})
    assert s.delivery.retry_backoff_seconds == 9.0
    assert s.delivery.retry_max_attempts == 7


def test_an_optional_numeric_field_still_takes_none() -> None:
    assert DeliverySettings(retry_max_attempts=None).retry_max_attempts is None
    with pytest.raises(ValidationError, match="boolean"):
        DeliverySettings.model_validate({"retry_max_attempts": True})
