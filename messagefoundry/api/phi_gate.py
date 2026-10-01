# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
from typing import Any, ClassVar, get_args

from pydantic import BaseModel, FieldSerializationInfo, PrivateAttr, field_serializer

__all__ = ["GATEABLE_PROPERTIES", "PhiGatedModel"]

#: Every property name a :class:`PhiGatedModel` may gate: the reviewed vocabulary of PHI-bearing
#: response properties. ``__pydantic_init_subclass__`` refuses a declaration outside it at
#: class-creation time, so a new gated name is added here, in review, rather than in passing.
#:
#: **CORRECTED (BACKLOG #2443 step 4).** This comment used to say the base class declares ONE field
#: serializer over exactly these names, so a name outside the set would serialize ungated. That
#: shared serializer is gone. It covered every field with one of these names on EVERY subclass,
#: gated or not, and typed it ``str | None``, so a subclass with a non-string field of such a name
#: (``ConnectionMetadata.metadata``, a dict) could not be gated without breaking that field's
#: OpenAPI type and warning on every response. Each subclass now gets a serializer over its OWN
#: ``phi_gated_properties`` (:meth:`PhiGatedModel.__init_subclass__`), so a declared name is
#: covered by construction and an undeclared field is never touched.
GATEABLE_PROPERTIES: frozenset[str] = frozenset(
    # ``reason``: the connection-event and alert reasons (BACKLOG #2443).
    {"summary", "error", "metadata", "last_error", "detail", "reason"}
)


class PhiGatedModel(BaseModel):
    """A response model whose ``phi_gated_properties`` are withheld from JSON until released."""

    #: The PHI properties this model gates. Inherited by subclasses on purpose: a future subclass of
    #: a PHI-bearing model is gated by default rather than by remembering to re-declare it.
    phi_gated_properties: ClassVar[frozenset[str]] = frozenset()

    #: Which gated properties this *instance* is cleared to serialize. Empty is the default, and the
    #: default is the control: an instance nobody authorized emits ``null`` for every gated property.
    _phi_released: frozenset[str] = PrivateAttr(default=frozenset())

    #: Which released properties carry a display mask instead of the real value. Empty is the
    #: default and the safe one: an unmarked property counts as a real exposure, so forgetting to
    #: mark one OVER-reports the audit rather than hiding a disclosure.
    _phi_masked: frozenset[str] = PrivateAttr(default=frozenset())

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Give every gated subclass a serializer over its own ``phi_gated_properties``.

        Runs inside class creation, before pydantic collects the class's serializers, so the
        attribute set here is picked up like a decorated method. It reads the set as the class
        RESOLVES it, so a set declared on the class, inherited, or brought in by a mixin is
        covered alike. Set under one name, so each class replaces its parent's serializer rather
        than stacking a second one on a field. Only the gated fields are covered, so a non-string
        field that happens to share a gateable name is serialized by its own type, untouched.
        :meth:`__pydantic_init_subclass__` then proves the coverage rather than trusting this."""
        super().__init_subclass__(**kwargs)
        declared = cls.phi_gated_properties
        if declared:
            serializer = field_serializer(*sorted(declared), when_used="json", check_fields=False)
            setattr(cls, _SERIALIZER_ATTR, serializer(_withhold_unreleased_phi))

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        super().__pydantic_init_subclass__(**kwargs)
        declared = cls.phi_gated_properties
        uncovered = sorted(declared - GATEABLE_PROPERTIES)
        if uncovered:
            raise TypeError(
                f"{cls.__name__}.phi_gated_properties names {uncovered}, which are not in "
                f"{__name__}.GATEABLE_PROPERTIES, the reviewed vocabulary of PHI-bearing "
                "properties. Add them there in the same change, so the new name is reviewed."
            )
        missing = sorted(declared - set(cls.model_fields))
        if missing:
            raise TypeError(
                f"{cls.__name__}.phi_gated_properties names {missing}, which are not fields of "
                "the model — the declaration gates nothing."
            )
        # A subclass may add gated properties, never drop one: a dropped property would keep the
        # parent's serializer on it, published as ``str | None`` while no longer gated.
        for base in cls.__mro__[1:]:
            if isinstance(base, type) and issubclass(base, PhiGatedModel):
                dropped = sorted(base.phi_gated_properties - declared)
                if dropped:
                    raise TypeError(
                        f"{cls.__name__} ungates {dropped}, which {base.__name__} gates. A "
                        "subclass of a gated model may add gated properties, not remove them."
                    )
        # The serializer returns ``str | None``, so a gated field of any other type would be
        # published as a string and warn on every dump (the ConnectionMetadata.metadata hazard).
        untyped = sorted(
            name for name in declared if not _is_optional_str(cls.model_fields[name].annotation)
        )
        if untyped:
            raise TypeError(
                f"{cls.__name__}.phi_gated_properties names {untyped}, which are not "
                "``str | None`` fields; the gate's serializer is typed for those only."
            )
        # Coverage is PROVEN, not assumed: every gated property must reach the gate's serializer,
        # read back from what pydantic actually collected. A set assigned to the class AFTER
        # creation is outside this proof, as any monkeypatch of a built class is.
        covered: set[str] = set()
        for dec in cls.__pydantic_decorators__.field_serializers.values():
            if dec.func is _withhold_unreleased_phi:
                covered |= set(dec.info.fields)
        unserialized = sorted(declared - covered)
        if unserialized:
            raise TypeError(
                f"{cls.__name__}.phi_gated_properties names {unserialized}, which no gate "
                "serializer covers, so they would serialize UNGATED."
            )

    def release_phi(self, properties: Iterable[str]) -> None:
        """Clear ``properties`` (intersected with this model's gate) for JSON serialization."""
        self._phi_released = frozenset(properties) & type(self).phi_gated_properties

    def mark_phi_masked(self, properties: Iterable[str]) -> None:
        """Record which released properties carry a DISPLAY MASK rather than the real value.

        Serialization is unaffected -- a masked property is released and is emitted. This exists so
        the PHI-exposure audit can count what the caller could actually READ: a masked value is
        non-empty, so a counter keyed on emptiness alone reports an exposure for a row whose
        identifiers were never shown (ASVS 14.2.6, BACKLOG #1187).

        Recorded by the masker rather than inferred from the value, because inference cannot work:
        a real summary may legitimately contain the mask characters, so "looks masked" is not a
        decidable question at the point of counting.
        """
        self._phi_masked = frozenset(properties) & type(self).phi_gated_properties


def _is_optional_str(annotation: object) -> bool:
    """True for ``str`` or ``str | None``, the only field types the gate's serializer handles."""
    if annotation is str:
        return True
    return set(get_args(annotation)) == {str, type(None)}


#: The class attribute each gated subclass's serializer is set under (see
#: :meth:`PhiGatedModel.__init_subclass__`). One name, so a subclass replaces its parent's.
_SERIALIZER_ATTR = "_withhold_unreleased_phi"


def _withhold_unreleased_phi(
    self: PhiGatedModel, value: str | None, info: FieldSerializationInfo
) -> str | None:
    """Emit a gated property only once released. The return annotation is load-bearing: it is
    what keeps the OpenAPI response schema typed (an ``Any``-returning serializer collapses the
    property to an untyped one, and a model-level wrap serializer collapses the whole model). It is
    only ever attached over a model's own gated properties, all of which are ``str | None``."""
    return value if info.field_name in self._phi_released else None
