# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Lazy loaders for the optional ``[fhir]`` extra (``fhir.resources`` + ``fhirpathpy``).

The heavy, typed FHIR libraries live behind the ``messagefoundry[fhir]`` optional extra (ADR 0022 §6),
so they are imported **inside** these functions — never at module top. That keeps importing
:mod:`messagefoundry.parsing.fhir` (e.g. a console import for client-side rendering, or the bare
structural :class:`~messagefoundry.parsing.fhir.peek.FhirPeek` accessors) free of the extra: only
:meth:`FhirResource.parse` and :meth:`FhirPeek.evaluate` require it. A missing extra raises a clear,
actionable :class:`RuntimeError` (mirroring how the SQL-Server/Postgres store backends fail without
their driver extra), distinct from the :class:`ValueError`-rooted data errors in
:mod:`messagefoundry.parsing.fhir.errors`.

This module imports ``fhir.resources``/``fhirpathpy`` (third-party, not engine packages) and nothing
from ``messagefoundry.config``/``pipeline``/``store``/``transports`` — the codec's purity is preserved.
"""

from __future__ import annotations

from typing import Any, Callable

_SUPPORTED_VERSIONS = ("R4B", "R5", "STU3")


def _missing_extra(feature: str) -> RuntimeError:
    return RuntimeError(
        f"{feature} requires the optional 'fhir' extra: pip install 'messagefoundry[fhir]'"
    )


def load_fhirpathpy() -> Callable[..., list[Any]]:
    """The ``fhirpathpy.evaluate`` FHIRPath evaluator, or a clear error if the extra is absent."""
    try:
        from fhirpathpy import evaluate
    except ImportError as exc:  # pragma: no cover - exercised only without the [fhir] extra
        raise _missing_extra("FHIRPath evaluation") from exc
    return evaluate


def load_get_fhir_model_class(version: str) -> Callable[[str], Any]:
    """The version-specific ``get_fhir_model_class`` (R4B/R5/STU3 → resourceType → typed model class).

    ``version`` is validated by the caller; an unsupported value here is a defensive programming error,
    not a data error. Raises :class:`RuntimeError` if the ``[fhir]`` extra is absent."""
    try:
        if version == "R5":
            from fhir.resources import get_fhir_model_class
        elif version == "R4B":
            from fhir.resources.R4B import get_fhir_model_class
        elif version == "STU3":
            from fhir.resources.STU3 import get_fhir_model_class
        else:  # pragma: no cover - parse() validates version before calling
            raise RuntimeError(f"unsupported fhir_version {version!r}")
    except ImportError as exc:  # pragma: no cover - exercised only without the [fhir] extra
        raise _missing_extra(f"the FHIR {version} model") from exc
    return get_fhir_model_class
