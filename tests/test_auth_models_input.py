# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Input rules on the auth request models (``messagefoundry/api/auth_models.py``)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from messagefoundry.api.auth_models import (
    CustomRoleRequest,
    DirectoryUserCreateRequest,
    UserCreateRequest,
    UserUpdateRequest,
)

_BAD_NAMES = ["", " ", "\t \u3000", "jd\x00oe", "a\nb", "a\rb", "a\x7fb", "a\x85b"]


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


def _role(**fields: object) -> CustomRoleRequest:
    body: dict[str, object] = {"display_name": "Lab-Ops", "permissions": ["monitoring:read"]}
    body.update(fields)
    return CustomRoleRequest.model_validate(body)


@pytest.mark.parametrize("name", _BAD_NAMES)
def test_custom_role_refuses_a_blank_or_control_character_name(name: str) -> None:
    """BACKLOG #5785."""
    with pytest.raises(ValidationError):
        _role(display_name=name)


@pytest.mark.parametrize(
    "name", ["Administrator", "administrator", " ADMINISTRATOR ", "Viewer", "auditor", "Coding"]
)
def test_custom_role_refuses_a_built_in_role_name(name: str) -> None:
    """BACKLOG #5785: a custom role cannot be named like a built-in one."""
    with pytest.raises(ValidationError):
        _role(display_name=name)


def test_custom_role_refuses_a_control_character_in_the_description() -> None:
    with pytest.raises(ValidationError):
        _role(description="line one" + chr(10) + "line two")
    assert _role(description="Lab operations").description == "Lab operations"


def test_custom_role_keeps_a_repeated_permission_once() -> None:
    """BACKLOG #5785."""
    body = _role(permissions=["monitoring:read", "messages:read", "monitoring:read"])
    assert body.permissions == ["monitoring:read", "messages:read"]


def test_custom_role_takes_an_ordinary_name() -> None:
    assert _role(display_name="Administrators of lab").display_name == "Administrators of lab"
