# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Lazy loaders for the optional ``[xml]`` extra (``lxml`` + ``xmlschema`` + ``signxml``).

These third-party libraries live behind the ``messagefoundry[xml]`` optional extra (BACKLOG #31), so
they are imported **inside** these functions — never at module top. That keeps
``import messagefoundry.parsing.xml`` free of the extra until a parse/validate/sign path is actually
called. A missing extra raises a clear, actionable :class:`RuntimeError` (mirroring
:mod:`messagefoundry.parsing.fhir._deps` / :mod:`messagefoundry.parsing.x12._deps` and the
SQL-Server/Postgres store backends), **distinct** from the :class:`ValueError`-rooted data errors in
:mod:`messagefoundry.parsing.xml.errors` — so a Handler's ``except ValueError`` does **not** swallow a
deploy/config error.

This module imports ``lxml``/``xmlschema``/``signxml`` (third-party, not engine packages) and nothing
from ``messagefoundry.config``/``pipeline``/``store``/``transports`` — the codec's purity is preserved.

**Security note:** ``defusedxml`` does **not** cover ``lxml`` (and ``defusedxml.lxml`` is deprecated),
so the lxml parser is hardened **directly** in :mod:`messagefoundry.parsing.xml.harden` — these loaders
just return the libraries.
"""

from __future__ import annotations

from typing import Any


def _missing_extra(feature: str) -> RuntimeError:
    return RuntimeError(
        f"{feature} requires the optional 'xml' extra: pip install 'messagefoundry[xml]'"
    )


def load_lxml() -> Any:
    """The ``lxml.etree`` module, or a clear :class:`RuntimeError` if the ``[xml]`` extra is absent.
    The caller always builds parsers via :func:`messagefoundry.parsing.xml.harden.hardened_parser` —
    never lxml's permissive defaults."""
    try:
        import lxml.etree as etree
    except ImportError as exc:  # pragma: no cover - exercised only without the [xml] extra
        raise _missing_extra("XML parsing") from exc
    return etree


def load_xmlschema() -> Any:
    """The ``xmlschema`` module, or a clear :class:`RuntimeError` if the ``[xml]`` extra is absent.
    Callers disable remote ``schemaLocation`` fetching when constructing a schema (no network)."""
    try:
        import xmlschema
    except ImportError as exc:  # pragma: no cover - exercised only without the [xml] extra
        raise _missing_extra("XSD schema validation") from exc
    return xmlschema


def load_signxml() -> Any:
    """The ``signxml`` module, or a clear :class:`RuntimeError` if the ``[xml]`` extra is absent.
    ``signxml`` pulls in ``cryptography`` for XML-DSig — registered in the crypto inventory via the
    :mod:`messagefoundry.parsing.xml.signature` module path."""
    try:
        import signxml
    except ImportError as exc:  # pragma: no cover - exercised only without the [xml] extra
        raise _missing_extra("XML digital signature") from exc
    return signxml
