# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Fail-closed serialization gate for PHI-bearing response properties (BACKLOG #1045, ASVS 8.2.3).

:func:`~messagefoundry.api.field_authz.redact_unauthorized` masks a property exactly where it is
called, so the set of protected surfaces was only ever the set of call sites someone remembered to
write. A new PHI-returning route that forgot the call returned every field in full, and no map-level
test could see it — the coverage was pinned by an *enumeration* of routes, which by construction
cannot cover the route nobody has written yet.

This module inverts the default. A response model that carries PHI subclasses :class:`PhiGatedModel`
and names its PHI properties in ``phi_gated_properties``; those properties then serialize as ``None``
**until something explicitly releases them**. ``redact_unauthorized`` is that something: it releases
exactly the properties the caller's permissions unlock. A forgotten call therefore yields ``null`` —
a functional defect the author sees immediately — instead of a PHI leak nobody sees at all.

**Scope, stated honestly.** The gate is on **JSON** serialization (``when_used="json"``): FastAPI
response models, ``jsonable_encoder`` and ``model_dump_json`` all run in JSON mode, which is every
path by which one of these models reaches an HTTP client. A python-mode ``model_dump()`` is
deliberately *not* gated, because the engine composes internally through one — ``api/app.py`` builds
``MessageDetail`` from a ``MessageSummary`` dump *before* any authorization decision exists, so
gating that dump would blank the detail route for an authorized caller. Python-mode dumps stay a
server-side value-passing mechanism; they were never a response.

The gate is a **default**, not a second authorization decision: it decides *whether an authorization
decision was made*, never *what it should be*. The permission policy stays in one place,
:mod:`messagefoundry.api.field_authz`.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from pydantic import BaseModel, FieldSerializationInfo, PrivateAttr, field_serializer

__all__ = ["GATEABLE_PROPERTIES", "PhiGatedModel"]

#: Every property name a :class:`PhiGatedModel` may gate. The base class declares its field
#: serializer over exactly these names (``check_fields=False``, because no single model has them
#: all), so a gated property outside this set would never reach the serializer and would serialize
#: ungated — the one way this gate could go quietly inert. ``__pydantic_init_subclass__`` refuses
#: such a declaration at class-creation time rather than leaving it to review.
GATEABLE_PROPERTIES: frozenset[str] = frozenset(
    {"summary", "error", "metadata", "last_error", "detail"}
)


class PhiGatedModel(BaseModel):
    """A response model whose ``phi_gated_properties`` are withheld from JSON until released."""

    #: The PHI properties this model gates. Inherited by subclasses on purpose: a future subclass of
    #: a PHI-bearing model is gated by default rather than by remembering to re-declare it.
    phi_gated_properties: ClassVar[frozenset[str]] = frozenset()

    #: Which gated properties this *instance* is cleared to serialize. Empty is the default, and the
    #: default is the control: an instance nobody authorized emits ``null`` for every gated property.
    _phi_released: frozenset[str] = PrivateAttr(default=frozenset())

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        super().__pydantic_init_subclass__(**kwargs)
        declared = cls.phi_gated_properties
        uncovered = sorted(declared - GATEABLE_PROPERTIES)
        if uncovered:
            raise TypeError(
                f"{cls.__name__}.phi_gated_properties names {uncovered}, which "
                f"{__name__}.GATEABLE_PROPERTIES does not cover — the field serializer is declared "
                "over that set, so these properties would serialize UNGATED. Add them to "
                "GATEABLE_PROPERTIES in the same change."
            )
        missing = sorted(declared - set(cls.model_fields))
        if missing:
            raise TypeError(
                f"{cls.__name__}.phi_gated_properties names {missing}, which are not fields of "
                "the model — the declaration gates nothing."
            )

    def release_phi(self, properties: Iterable[str]) -> None:
        """Clear ``properties`` (intersected with this model's gate) for JSON serialization."""
        self._phi_released = frozenset(properties) & type(self).phi_gated_properties

    @field_serializer(*sorted(GATEABLE_PROPERTIES), when_used="json", check_fields=False)
    def _withhold_unreleased_phi(
        self, value: str | None, info: FieldSerializationInfo
    ) -> str | None:
        """Emit a gated property only once released. The return annotation is load-bearing: it is
        what keeps the OpenAPI response schema typed (an ``Any``-returning serializer collapses the
        property to an untyped one, and a model-level wrap serializer collapses the whole model)."""
        name = info.field_name
        if name not in type(self).phi_gated_properties:
            return value  # covered by the shared decorator, but not gated on this model
        return value if name in self._phi_released else None
