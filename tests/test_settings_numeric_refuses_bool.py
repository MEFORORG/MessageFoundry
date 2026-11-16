# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A boolean on a numeric settings key is refused, never coerced to 0 or 1 (BACKLOG #5509).

pydantic's lax mode turns ``True`` into ``1`` and ``False`` into ``0`` for an ``int`` or ``float``
field, so ``delete_message_bodies_after_days = false`` in messagefoundry.toml would read as 0,
"keep indefinitely", and ``max_upload_bytes = true`` as a one-byte cap. The shared ``_Section`` base now refuses a bool
on every numeric field, while an environment string such as ``"5"`` still parses."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from messagefoundry.config.settings import (
    DeliverySettings,
    SecuritySettings,
    _numeric_field_names,
    _section_models,
    load_settings,
)

_NUMERIC_FIELDS: list[tuple[str, type[BaseModel], str]] = [
    (section, model, name)
    for section, model in sorted(_section_models().items())
    for name in sorted(_numeric_field_names(model))
]


def test_the_sweep_finds_numeric_fields() -> None:
    """Positive control: the sweep below proves nothing if it parametrizes over no fields."""
    assert len(_NUMERIC_FIELDS) > 100
    assert ("security", SecuritySettings, "delete_message_bodies_after_days") in _NUMERIC_FIELDS


@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize(
    ("section", "model", "name"), _NUMERIC_FIELDS, ids=[f"{s}.{n}" for s, _, n in _NUMERIC_FIELDS]
)
def test_every_numeric_field_refuses_a_bool(
    section: str, model: type[BaseModel], name: str, value: bool
) -> None:
    with pytest.raises(ValidationError) as caught:
        model.model_validate({name: value})
    mine = [e for e in caught.value.errors() if e["loc"] == (name,)]
    assert mine, f"[{section}].{name} accepted {value!r}"
    assert "boolean" in mine[0]["msg"]


def test_a_bool_in_the_file_refuses_load_naming_the_key(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[security]\ndelete_message_bodies_after_days = false\n", encoding="utf-8")
    with pytest.raises(ValidationError) as caught:
        load_settings(config_path=cfg, environ={})
    assert "delete_message_bodies_after_days" in str(caught.value)
    assert "boolean" in str(caught.value)


def test_a_number_and_an_environment_string_still_parse(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[delivery]\nretry_backoff_seconds = 9\n", encoding="utf-8")
    s = load_settings(config_path=cfg, environ={"MEFOR_DELIVERY_RETRY_MAX_ATTEMPTS": "7"})
    assert s.delivery.retry_backoff_seconds == 9.0
    assert s.delivery.retry_max_attempts == 7


def test_an_optional_numeric_field_still_takes_none() -> None:
    assert DeliverySettings(retry_max_attempts=None).retry_max_attempts is None
    with pytest.raises(ValidationError):
        DeliverySettings.model_validate({"retry_max_attempts": True})
