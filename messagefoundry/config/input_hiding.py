# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A pydantic model whose validation errors never carry the value they refused (BACKLOG #296).

Apart from ``config.settings`` because ``config.models`` needs it too, and ``config.settings``
imports ``config.models``."""

from __future__ import annotations

from typing import Any, get_args

from pydantic import (
    BaseModel,
    ConfigDict,
    GetCoreSchemaHandler,
    ValidationError,
    ValidatorFunctionWrapHandler,
)
from pydantic_core import ErrorDetails, InitErrorDetails, PydanticCustomError, core_schema

#: What a settings validation error shows in place of the value it refused (BACKLOG #296).
HIDDEN_INPUT = "[not shown]"


#: Every error type pydantic-core knows. One of these is rebuilt from its own template and ``ctx``,
#: so the rendered message is never fed back in as a template, where a ``{error}`` the operator
#: wrote would be substituted again at each level.
_KNOWN_ERROR_TYPES = frozenset(get_args(core_schema.ErrorType))


def _without_input(err: ErrorDetails) -> InitErrorDetails:
    """One error, rebuilt with :data:`HIDDEN_INPUT` in place of its input."""
    if err["type"] in _KNOWN_ERROR_TYPES:
        detail = InitErrorDetails(type=err["type"], loc=err["loc"], input=HIDDEN_INPUT)
        if "ctx" in err:
            detail["ctx"] = err["ctx"]
        # A PydanticCustomError may reuse a known type name with another ctx (pydantic's own
        # EmailStr raises 'value_error' with a 'reason'), which the known template refuses.
        try:
            ValidationError.from_exception_data("probe", [detail])
        except (TypeError, ValueError, KeyError):
            pass
        else:
            return detail
    # A validator's own PydanticCustomError: keep its type and rendered message, with no context,
    # so the message is not formatted a second time.
    return InitErrorDetails(
        type=PydanticCustomError(err["type"], err["msg"]), loc=err["loc"], input=HIDDEN_INPUT
    )


def _refuse_without_input(value: Any, handler: ValidatorFunctionWrapHandler) -> Any:
    """Validate ``value``; on a refusal, re-raise every error with its input replaced.

    A refusal from an ``after``-mode model validator carries the whole section's input mapping as
    its ``input``, and ``str(exc)``, ``repr(exc)``, ``exc.errors()`` and ``exc.json()`` all render
    it. That mapping holds whatever secrets the section reads from the environment, so any caller
    that prints or logs the error would disclose them. ``hide_input_in_errors`` is not enough: it
    hides the input from ``str`` and ``repr`` only, and only on the outermost model.

    Each error keeps its location, type and message, and a known type keeps its ``ctx`` (a
    validator's own ``PydanticCustomError`` keeps its rendered message only). THIS HIDES THE INPUT
    ONLY. The message and ``ctx`` stay as raised, and they can quote the value: a validator that
    quotes what it refused still shows it there, and so does at least one error a library raised
    inside a validator. :func:`settings_error_detail` names at least the ones known. None is meant
    to hold a secret, but a URL can carry one, so a validator message must name the setting, never
    quote a secret value.
    """
    try:
        return handler(value)
    except ValidationError as exc:
        title, errors = exc.title, exc.errors(include_url=False)
    # Rebuilt OUTSIDE the handler: anything raised while rebuilding would otherwise carry the
    # original, input-bearing error on its __context__.
    raise ValidationError.from_exception_data(title, [_without_input(err) for err in errors])


class _InputHidingModel(BaseModel):
    """A model whose validation errors never carry the value they refused (BACKLOG #296).

    The wrap sits OUTSIDE the whole model schema, its own validators included, so it holds for
    direct construction and for the model nested in another one. A per-raise helper cannot, since
    the next plain ``ValueError`` added to a validator would bring the echo back.
    """

    # Keeps the placeholder, and its misleading input_type of str, out of str(exc); errors() and
    # json() still carry the placeholder. Inherited and merged into each subclass's own config.
    model_config = ConfigDict(hide_input_in_errors=True)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: type[BaseModel], handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        schema = handler(source)
        # A section nested in ServiceSettings hands back its own stored schema, already wrapped.
        if schema["type"] == "function-wrap" and schema["function"]["function"] is (
            _refuse_without_input
        ):
            return schema
        return core_schema.no_info_wrap_validator_function(_refuse_without_input, schema)
