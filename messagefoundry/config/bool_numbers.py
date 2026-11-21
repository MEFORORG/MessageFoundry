# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A pydantic model that refuses ``true``/``false`` where a number is meant (BACKLOG #5509).

Apart from ``config.settings`` because ``config.models`` needs it too, and ``config.settings``
imports ``config.models``. The settings sections and the connection policy models
(at least ``RetryPolicy``, the alert thresholds, ``ActiveWindow``, ``BatchConfig`` and
``Validation``) share this one guard."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from pydantic import (
    BaseModel,
    ValidationError,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    field_validator,
)

#: pydantic error types a number's own bound raises. One raised where a bool was given means the
#: bool was read as a number first, so the bool refusal names it instead (BACKLOG #5509).
_NUMBER_BOUND_ERRORS: Final = frozenset(
    {"greater_than", "greater_than_equal", "less_than", "less_than_equal", "multiple_of"}
)


def _bool_on_a_number_refusal(where: str) -> str:
    """The refusal of a bool on a number at ``where``. It quotes no value (BACKLOG #5509)."""
    return f"{where} expects a number, not a boolean (true or false); write a number in its place"


def _bool_at(given: Any, loc: tuple[int | str, ...], where: str) -> str | None:
    """The path of ``loc`` inside ``given`` when a bool sits there, or ``None`` (#5509).

    ``loc`` cannot tell a model field from a dict key, so a key that is not a plain identifier is
    left out of the path rather than echoed."""
    for part in loc:
        if isinstance(given, Mapping) and part in given:
            given = given[part]
            where = f"{where}.{part}" if isinstance(part, str) and part.isidentifier() else where
        elif isinstance(given, list | tuple) and isinstance(part, int) and part < len(given):
            given = given[part]
            where = f"{where}[{part}]"
        else:
            return None
    return where if isinstance(given, bool) else None


def _bool_read_as_number(given: Any, got: Any, where: str) -> str | None:
    """Where a bool in ``given`` came out of validation as a number in ``got``, or ``None`` (#5509).

    Read off the validated value rather than the annotation, so it holds for at least a constrained
    or optional int, an int subclass, a list, tuple, set or dict of numbers, and the fields of a
    nested model such as ``[[alerts.rules]]``. It misses at least a dict whose keys validation
    rewrites, a list an inner validator shortens, and a bool read as a ``timedelta`` or an enum
    member. A field that deliberately keeps a bool keeps it, since its validated value is still a
    bool. The path names model fields and list positions only, never a dict key the operator
    wrote."""
    if isinstance(given, bool):
        return where if isinstance(got, int | float) and not isinstance(got, bool) else None
    if isinstance(given, Mapping):
        if isinstance(got, BaseModel):
            fields = type(got).model_fields
            pairs = [(f"{where}.{k}", v, getattr(got, k)) for k, v in given.items() if k in fields]
        elif isinstance(got, Mapping):
            pairs = [(f"{where}[a key]", v, got[k]) for k, v in given.items() if k in got]
        else:
            return None
        for path, inner_given, inner_got in pairs:
            if found := _bool_read_as_number(inner_given, inner_got, path):
                return found
        return None
    if isinstance(given, list | tuple):
        if isinstance(got, list | tuple) and len(got) == len(given):
            for index, (inner_given, inner_got) in enumerate(zip(given, got, strict=True)):
                if found := _bool_read_as_number(inner_given, inner_got, f"{where}[{index}]"):
                    return found
        # A set reorders and merges, so no element pairs with its input: a bool given where none
        # survived was read as a number.
        elif (
            isinstance(got, set | frozenset)
            and any(isinstance(item, bool) for item in given)
            and not any(isinstance(item, bool) for item in got)
        ):
            return where
    return None


class NumbersRefuseBool(BaseModel):
    """A model whose every field refuses a bool that validation would read as a number (#5509)."""

    @field_validator("*", mode="wrap")
    @classmethod
    def _refuse_a_bool_on_a_number(
        cls, value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> Any:
        """Refuse ``true``/``false`` on a numeric key rather than read it as 1 or 0 (BACKLOG #5509).

        pydantic's lax mode coerces a bool to an int or float, so
        ``delete_message_bodies_after_days = false`` would read as 0, "keep indefinitely", and a
        byte cap set to ``true`` as one byte. Lax mode stays on for everything else, because the
        environment layer hands every value over as a string. A subclass ``before`` validator
        that turns a bool into a number itself runs ahead of this one and is not seen. On a model
        that validates assignment, an assigned bool is refused too."""
        where = str(info.field_name)
        try:
            validated = handler(value)
        except ValidationError as exc:
            # A bool read as 0 can then fail the number's own bound (``gt=0``), and that message
            # would hide the coercion: name the bool instead.
            found = next(
                (
                    path
                    for err in exc.errors(include_url=False)
                    if err["type"] in _NUMBER_BOUND_ERRORS
                    and (path := _bool_at(value, err["loc"], where))
                ),
                None,
            )
            if found is None:
                raise
        else:
            found = _bool_read_as_number(value, validated, where)
            if found is None:
                return validated
        # Raised outside the handler, so the bound error, whose input a nested plain model does not
        # hide, is not chained onto the refusal (BACKLOG #1796).
        raise ValueError(_bool_on_a_number_refusal(found))
