# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Input rules on the auth request models (``messagefoundry/api/auth_models.py``)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from messagefoundry.api.auth_models import (
    DirectoryUserCreateRequest,
    UserCreateRequest,
    UserUpdateRequest,
)

_BAD_NAMES = ["", " ", "\t 　", "jd\x00oe", "a\nb", "a\rb", "a\x7fb", "a\x85b"]


@pytest.mark.parametrize("name", _BAD_NAMES)
def test_directory_create_refuses_a_blank_or_control_character_username(name: str) -> None:
    """BACKLOG #5784."""
    with pytest.raises(ValidationError):
        DirectoryUserCreateRequest.model_validate({"username": name})


def test_directory_create_takes_an_ordinary_username() -> None:
    assert DirectoryUserCreateRequest.model_validate({"username": "jdoe"}).username == "jdoe"


@pytest.mark.parametrize("name", _BAD_NAMES)
def test_user_update_refuses_a_blank_or_control_character_display_name(name: str) -> None:
    """BACKLOG #5784."""
    with pytest.raises(ValidationError):
        UserUpdateRequest.model_validate({"display_name": name})


@pytest.mark.parametrize("name", _BAD_NAMES)
def test_user_create_refuses_a_blank_or_control_character_display_name(name: str) -> None:
    with pytest.raises(ValidationError):
        UserCreateRequest.model_validate(
            {"username": "jdoe", "email": "j@example.org", "display_name": name}
        )


def test_user_update_display_name_still_clears_and_takes_ordinary_text() -> None:
    assert UserUpdateRequest.model_validate({"display_name": None}).display_name is None
    body = UserUpdateRequest.model_validate({"display_name": "Jane Doe-O'Neil"})
    assert body.display_name == "Jane Doe-O'Neil"
