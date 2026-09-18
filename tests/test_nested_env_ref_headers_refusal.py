# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An env() reference nested in a headers table is REFUSED at the factory (BACKLOG #1649).

``resolve_env_settings`` walks only the TOP level of a settings map. That is a ruling, not an
oversight: ``_hoist_body_secrets`` and ``_reject_envref_odbc_params`` are both built on it and say so.
The cost is that every nested settings shape has to refuse a reference it cannot resolve, or ship it
unresolved -- and a ``headers`` table did the second thing. Every transport ``_build_headers`` does
``str(v)`` on each value, so an unresolved reference went on the wire to the partner as its repr,
``default=`` and all.

THE POSITIVE CONTROL COMES FIRST in this file, deliberately. A refusal test that never demonstrates
the thing being refused is a guard nobody has proved can see anything: it would pass identically
against a guard that fires on the wrong shape, or against a leak already closed somewhere downstream.
``test_the_repr_leak_this_refusal_exists_to_stop_is_real`` pins the hazard by driving
``_build_headers`` with a settings map built past the factory door.

TWO VALUE SHAPES REACH A FACTORY AND BOTH ARE REFUSED. Code-first authoring gives an ``EnvRef``
instance. ``connections.toml`` gives a RAW dict, because ``parse_env_setting`` decodes only top-level
values and does not descend into a nested table. An ``isinstance(..., EnvRef)`` test alone would
therefore refuse code-first while the TOML surface still shipped the default to the partner -- green
on the surface an operator is most likely to use for a partner key. Every case below runs twice, once
per shape.

THE DOMAIN IS DERIVED AND ITS COVERAGE IS ASSERTED, which is the standing lesson recorded in
``test_connection_factory_redaction_domain.py``: a hand-chosen list of factories is how the last three
guards in this class blinded themselves. The backlog row carried such a list and it was wrong in BOTH
directions -- it named ``Http``, which is inbound-only and has no ``headers`` parameter at all, and it
omitted ``DICOMweb`` and ``FhirLookup``, which both take one and both leaked.
``test_every_headers_taking_factory_is_covered`` fails if a sixth authoring factory grows a
``headers`` parameter without being wired in here.
"""

from __future__ import annotations

import ast
import pathlib
from typing import Any

import pytest

import messagefoundry
from messagefoundry.config import wiring
from messagefoundry.config.wiring import Registry, WiringError, parse_env_setting

PKG = pathlib.Path(messagefoundry.__file__).resolve().parent

#: A value this test invents. It stands in for the fallback partner key an author would write as
#: ``env("partner_key", default=...)`` -- the thing that must never reach a header.
SENTINEL = "MFTEST-NESTED-ENV-DEFAULT-MUST-NOT-SHIP"

#: The authoring surfaces that accept a ``headers`` mapping, each with the arguments it needs to
#: build. Derived-domain coverage is asserted separately; this map carries the per-factory call
#: shape, which an AST walk cannot invent.
HEADERS_FACTORIES: dict[str, Any] = {
    "Rest": lambda h: messagefoundry.Rest(url="https://example.invalid/x", headers=h),
    "FHIR": lambda h: messagefoundry.FHIR(url="https://example.invalid/fhir", headers=h),
    "DICOMweb": lambda h: messagefoundry.DICOMweb(url="https://example.invalid/stow", headers=h),
    "Soap": lambda h: messagefoundry.Soap(
        url="https://example.invalid/svc", soap_action="urn:probe", headers=h
    ),
    "FhirLookup": lambda h: messagefoundry.FhirLookup(
        "probe_lookup", url="https://example.invalid/fhir", headers=h
    ),
}

#: The two shapes a nested reference arrives in, by the surface that produces it.
NESTED_SHAPES: dict[str, Any] = {
    # env("partner_key", default=...) written in a config module.
    "code-first": messagefoundry.env("partner_key", default=SENTINEL),
    # An inline table under [settings.headers]. parse_env_setting returns a nested table verbatim, so
    # the factory sees this dict, NOT an EnvRef.
    "connections.toml": {"env": "partner_key", "default": SENTINEL},
}


@pytest.fixture(autouse=True)
def _registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """``FhirLookup`` self-registers, so it needs an active registry; the other four do not care."""
    monkeypatch.setattr(wiring, "_active", Registry())


# --- the hazard being refused ------------------------------------------------


def test_the_repr_leak_this_refusal_exists_to_stop_is_real() -> None:
    """The positive control. Without it, every assertion below could be passing vacuously.

    The settings map is built PAST the factory door on purpose -- that door is now shut, and shutting
    it is the fix. What this pins is that the door was worth shutting: a nested reference that gets
    through by any other route still stringifies onto the wire, so the refusal is load-bearing rather
    than belt-and-braces over some downstream scrub that would have caught it anyway.
    """
    from messagefoundry.transports.rest import RestDestination

    settings = dict(messagefoundry.Rest(url="https://example.invalid/x").settings)
    settings["headers"] = {"X-Partner-Key": messagefoundry.env("partner_key", default=SENTINEL)}
    built = RestDestination._build_headers(settings)
    # Not "a reference survives" -- the DEFAULT itself is in the outgoing header value.
    assert SENTINEL in built["X-Partner-Key"], built


# --- the refusal -------------------------------------------------------------


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
@pytest.mark.parametrize("shape", sorted(NESTED_SHAPES))
def test_a_nested_env_ref_in_headers_is_refused(factory: str, shape: str) -> None:
    with pytest.raises(WiringError) as excinfo:
        HEADERS_FACTORIES[factory]({"X-Partner-Key": NESTED_SHAPES[shape]})
    message = str(excinfo.value)
    assert factory in message, message
    # The offending header is NAMED. A refusal that says only "somewhere in headers" makes the author
    # hunt for it, and a headers table on a real feed is not two entries long.
    assert "X-Partner-Key" in message, message
    # The message points at the typed credential fields, which ARE env-resolved and redacted.
    assert "bearer_token" in message, message


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
@pytest.mark.parametrize("shape", sorted(NESTED_SHAPES))
def test_the_refusal_does_not_repeat_the_default_it_is_protecting(factory: str, shape: str) -> None:
    """A refusal that quotes the secret it refused has moved the leak, not closed it.

    This message reaches the operator log, ``messagefoundry check`` output, the IDE Problems panel and
    the support bundle. ``_cast_bool`` and ``resolve_env_settings`` both carry the same rule, written
    out at length, because the value leaked twice from one block there (BACKLOG #1183).
    """
    with pytest.raises(WiringError) as excinfo:
        HEADERS_FACTORIES[factory]({"X-Partner-Key": NESTED_SHAPES[shape]})
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


# --- controls: what must still build -----------------------------------------


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
def test_a_static_header_still_builds(factory: str) -> None:
    """The control that separates a working guard from one that refuses every headers table."""
    spec = HEADERS_FACTORIES[factory]({"X-Partner-Trace": "probe-1"})
    assert spec.settings["headers"] == {"X-Partner-Trace": "probe-1"}


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
def test_an_absent_headers_table_still_builds(factory: str) -> None:
    spec = HEADERS_FACTORIES[factory](None)
    assert spec.settings["headers"] == {}


def test_a_top_level_env_ref_is_still_decoded_and_still_allowed() -> None:
    """The refusal is about NESTING, not about env(). A top-level reference is the supported form and
    must keep decoding and keep resolving."""
    assert parse_env_setting({"env": "partner_key", "default": SENTINEL}) == messagefoundry.env(
        "partner_key", default=SENTINEL
    )
    spec = messagefoundry.Rest(
        url="https://example.invalid/x", bearer_token=messagefoundry.env("partner_key")
    )
    assert spec.settings["bearer_token"] == messagefoundry.env("partner_key")


def test_a_dict_that_only_looks_like_an_env_ref_is_left_alone() -> None:
    """The near-miss control. The refusal reuses the predicate ``parse_env_setting`` itself uses, so
    a table with an extra key is not an env marker to EITHER of them -- and a guard that fired on it
    would refuse ordinary configuration with a message about a reference the author never wrote."""
    lookalike = {"env": "partner_key", "not_an_envref_key": 1}
    assert parse_env_setting(lookalike) == lookalike
    spec = messagefoundry.Rest(url="https://example.invalid/x", headers={"X-Odd": lookalike})
    assert spec.settings["headers"]["X-Odd"] == lookalike


# --- coverage: is the guard pointed at the whole surface? --------------------


def _authoring_factories_taking_headers() -> set[str]:
    """Every public authoring factory in the package that accepts a ``headers`` mapping.

    Package-wide and annotation-based, NOT scoped to one file: scoping the walk to
    ``config/wiring.py`` would be a domain chosen by where the code happens to live today, which is
    the narrowing this repository has been bitten by three times. The filter is the RETURN type -- an
    authoring factory emits a ``ConnectionSpec`` or a ``FhirLookupSpec`` -- which excludes the several
    runtime helpers that also take a ``headers`` argument (``redirect_request``,
    ``ech_readdressed_request``, ``enforce_outbound_length_limits`` and friends). Those build a live
    request from already-resolved settings; there is no reference left to refuse by the time they run.
    """
    found: set[str] = set()
    for path in sorted(PKG.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover - a syntax error fails the rest of the suite anyway
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                and not node.name.startswith("_")
                and node.returns is not None
                and any(
                    shape in ast.unparse(node.returns)
                    for shape in ("ConnectionSpec", "FhirLookupSpec")
                )
            ):
                args = [a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs]
                if "headers" in args:
                    found.add(node.name)
    return found


def test_every_headers_taking_factory_is_covered() -> None:
    """The only assertion here that answers *is the instrument pointed at the whole thing*.

    A sixth factory growing a ``headers`` parameter fails THIS test rather than silently shipping an
    unrefused surface. The hand-written list in the backlog row was wrong in both directions, which
    is the whole argument for deriving the set instead of typing it.
    """
    derived = _authoring_factories_taking_headers()
    assert derived, "the AST walk found nothing -- the instrument is broken, not the code"
    assert derived == set(HEADERS_FACTORIES), (
        f"headers-taking factories not covered here: {sorted(derived - set(HEADERS_FACTORIES))}; "
        f"covered but no longer found: {sorted(set(HEADERS_FACTORIES) - derived)}"
    )
