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
per shape. ``test_the_toml_surface_really_does_hand_a_raw_dict_to_the_factory`` measures that claim
through ``load_connections_file`` rather than reasoning it, since only ``rest`` and ``soap`` of the
five have a TOML route at all.

BOTH AXES OF THE TABLE ARE COVERED, not only the value axis. Every ``_build_headers`` does ``str(k)``
as well as ``str(v)`` -- ``dicomweb`` even says so in a comment, "NAMES as well as values: both halves
land on the wire". A first cut of the guard scanned values only, and
``headers={env("hdr_name", default=...): "static"}`` built clean and put the dataclass repr on the
wire as the header NAME. Worse, the refusal itself then quoted that repr when the key was an
``EnvRef``, so the message carried the default it exists to protect.

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
from messagefoundry.config.wiring import (
    Registry,
    WiringError,
    parse_env_setting,
    resolve_env_settings,
)

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


def _build_headers_for(factory: str, settings: dict[str, Any]) -> dict[str, str]:
    """Run the ``_build_headers`` that ``factory``'s own connector runs.

    Keyed by the SAME names as :data:`HEADERS_FACTORIES`, so the positive control covers every
    refused surface rather than one of them. Each factory maps to exactly one implementation:
    ``RestDestination``, ``FhirDestination``, ``DicomWebDestination``, ``SoapDestination`` and
    ``FhirLookupExecutor``. Three are instance methods, and only ``soap`` actually reads ``self``
    (``self.version``), so each arm supplies what that implementation needs and nothing more --
    building a real connector would open sockets this test has no use for.
    """
    from types import SimpleNamespace

    from messagefoundry.transports.dicomweb import DicomWebDestination
    from messagefoundry.transports.fhir import FhirDestination, FhirLookupExecutor
    from messagefoundry.transports.rest import RestDestination
    from messagefoundry.transports.soap import SoapDestination

    match factory:
        case "Rest":
            return RestDestination._build_headers(settings)
        case "FHIR":
            return FhirDestination._build_headers(SimpleNamespace(), settings)  # type: ignore[arg-type]
        case "DICOMweb":
            return DicomWebDestination._build_headers(SimpleNamespace(), settings)  # type: ignore[arg-type]
        case "Soap":
            return SoapDestination._build_headers(SimpleNamespace(version="1.1"), settings)  # type: ignore[arg-type]
        case "FhirLookup":
            return FhirLookupExecutor._build_headers(settings)
    raise AssertionError(f"no _build_headers wired for {factory!r}")


#: The two shapes a nested reference arrives in, by the surface that produces it. Each entry BUILDS a
#: fresh object rather than being one: the code under test is a scrubber over exactly this shape, so
#: the day one of them normalises in place instead of returning a copy, a shared instance would make
#: every later case in the file pass vacuously -- in the one file whose stated purpose is not doing
#: that.
NESTED_SHAPES: dict[str, Any] = {
    # env("partner_key", default=...) written in a config module.
    "code-first": lambda: messagefoundry.env("partner_key", default=SENTINEL),
    # An inline table under [settings.headers]. parse_env_setting returns a nested table verbatim, so
    # the factory sees this dict, NOT an EnvRef.
    "connections.toml": lambda: {"env": "partner_key", "default": SENTINEL},
}


@pytest.fixture(autouse=True)
def _registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """``FhirLookup`` self-registers, so it needs an active registry; the other four do not care."""
    monkeypatch.setattr(wiring, "_active", Registry())


# --- the hazard being refused ------------------------------------------------


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
@pytest.mark.parametrize("shape", sorted(NESTED_SHAPES))
def test_the_repr_leak_this_refusal_exists_to_stop_is_real(factory: str, shape: str) -> None:
    """The positive control. Without it, every assertion below could be passing vacuously.

    The settings map is built PAST the factory door on purpose -- that door is now shut, and shutting
    it is the fix. What this pins is that the door was worth shutting: a nested reference that gets
    through by any other route still stringifies onto the wire, so the refusal is load-bearing rather
    than belt-and-braces over some downstream scrub that would have caught it anyway.

    IT RUNS ON ALL FIVE ``_build_headers``, not just REST. The module docstring claims the hazard for
    every transport; pinning it on one and asserting it for five is the reasoned domain this file is
    otherwise written against. If one implementation grows a scrub, the refusal on THAT factory
    quietly becomes belt-and-braces and this control is what says so.
    """
    settings = dict(HEADERS_FACTORIES[factory](None).settings)
    settings["headers"] = {"X-Partner-Key": NESTED_SHAPES[shape]()}
    built = _build_headers_for(factory, settings)
    # Not "a reference survives" -- the DEFAULT itself is in the outgoing header value.
    assert SENTINEL in built["X-Partner-Key"], built


def test_the_key_side_repr_leak_is_real_too() -> None:
    """The second positive control: the header NAME axis, which a value-only guard left open.

    Only an ``EnvRef`` can sit here -- the raw marker is a dict and a dict is unhashable -- so this
    control has one shape, not two.
    """
    settings = dict(messagefoundry.Rest(url="https://example.invalid/x").settings)
    settings["headers"] = {messagefoundry.env("hdr_name", default=SENTINEL): "static"}
    built = _build_headers_for("Rest", settings)
    assert any(SENTINEL in name for name in built), built


# --- the refusal -------------------------------------------------------------


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
@pytest.mark.parametrize("shape", sorted(NESTED_SHAPES))
def test_a_nested_env_ref_in_headers_is_refused(factory: str, shape: str) -> None:
    with pytest.raises(WiringError) as excinfo:
        HEADERS_FACTORIES[factory]({"X-Partner-Key": NESTED_SHAPES[shape]()})
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
        HEADERS_FACTORIES[factory]({"X-Partner-Key": NESTED_SHAPES[shape]()})
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
def test_an_env_ref_used_as_a_header_NAME_is_refused(factory: str) -> None:
    """The key axis. Every ``_build_headers`` does ``str(k)`` as well as ``str(v)``."""
    with pytest.raises(WiringError) as excinfo:
        HEADERS_FACTORIES[factory]({messagefoundry.env("hdr_name", default=SENTINEL): "static"})
    message = str(excinfo.value)
    assert factory in message, message
    # The env KEY is named, so the author can find it...
    assert "hdr_name" in message, message
    # ...and the position is named, because "hdr_name" alone reads as a value-side offender.
    assert "header name" in message, message


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
def test_the_refusal_does_not_repeat_a_default_on_the_KEY_side_either(factory: str) -> None:
    """The one the value-side twin cannot catch, because it only ever puts a literal in the key slot.

    ``str()`` on an ``EnvRef`` renders the whole dataclass, ``default=`` included. A guard that builds
    its message by stringifying the offending key therefore prints the secret into the operator log,
    ``messagefoundry check`` output, the IDE Problems panel and the support bundle -- moving the leak
    rather than closing it, which is the BACKLOG #1183 shape the value-side test cites.
    """
    with pytest.raises(WiringError) as excinfo:
        HEADERS_FACTORIES[factory](
            {
                messagefoundry.env("hdr_name", default=SENTINEL): messagefoundry.env(
                    "partner_key", default=SENTINEL
                )
            }
        )
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


def test_every_offender_is_named_and_the_static_headers_beside_them_are_not() -> None:
    """A real feed's table is neither one entry long nor all bad.

    Pins the join branch with more than one element, and pins that an innocent header is not swept in
    -- a guard narrowed to the FIRST offending entry, or widened to the whole table, passes every
    single-entry case in this file.
    """
    with pytest.raises(WiringError) as excinfo:
        messagefoundry.Rest(
            url="https://example.invalid/x",
            headers={
                "X-Partner-Trace": "probe-1",
                "X-Partner-Key": messagefoundry.env("partner_key", default=SENTINEL),
                "X-Partner-Alt": {"env": "partner_alt", "default": SENTINEL},
            },
        )
    message = str(excinfo.value)
    assert "X-Partner-Key" in message, message
    assert "X-Partner-Alt" in message, message
    assert "X-Partner-Trace" not in message, message
    assert SENTINEL not in message, message


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
def test_a_non_mapping_headers_fails_as_a_WiringError_not_a_traceback(factory: str) -> None:
    """``connections.toml`` is untyped input, so ``headers = "not-a-table"`` reaches the guard.

    Iterating it raises ``AttributeError``, which ``_build_spec`` does not catch -- it catches
    ``WiringError`` and ``(TypeError, ValueError)`` -- so the operator would get a bare traceback with
    no file, no connection name and no line, unlike every other malformed setting in that loader.
    ``_hoist_body_secrets`` raises ``WiringError`` on the same input; this matches it.
    """
    with pytest.raises(WiringError) as excinfo:
        HEADERS_FACTORIES[factory]("not-a-table")
    assert factory in str(excinfo.value), str(excinfo.value)


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


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
def test_an_env_ref_standing_for_the_WHOLE_table_is_allowed_and_resolves(factory: str) -> None:
    """The near-miss a type check on ``headers`` gets wrong, and it is a working form, not an edge.

    ``headers=env("all_headers")`` puts the reference at the TOP level of the settings map, which is
    exactly where ``resolve_env_settings`` reaches -- so it resolves to the real table before the
    connector runs, and it is the supported way to make a whole headers map per-environment. A guard
    that demands a Mapping refuses it with a message about nesting that does not describe it.
    """
    spec = HEADERS_FACTORIES[factory](messagefoundry.env("all_headers"))
    assert spec.settings["headers"] == messagefoundry.env("all_headers")
    resolved = resolve_env_settings(spec.settings, {"all_headers": {"X-A": "b"}})
    assert resolved["headers"] == {"X-A": "b"}, resolved["headers"]


@pytest.mark.parametrize(
    "label",
    ["marker in a list", "marker in a sub-table", "EnvRef in a list", "marker in a nested key"],
)
def test_a_reference_one_level_DEEPER_in_a_header_value_is_refused_too(label: str) -> None:
    """A top-level scan of the table is not enough, because ``str(v)`` renders a container whole.

    Measured before this scan existed, all three shipping to the partner intact:
    ``[{'env': 'partner_key', 'default': ...}]``, ``{'a': {'env': ..., 'default': ...}}`` and
    ``[EnvRef(key=..., default=...)]``. The guard's own premise applies unchanged one level down.
    """
    deep: dict[str, Any] = {
        "marker in a list": {"X-Partner-Key": [{"env": "partner_key", "default": SENTINEL}]},
        "marker in a sub-table": {
            "X-Partner-Key": {"a": {"env": "partner_key", "default": SENTINEL}}
        },
        "EnvRef in a list": {
            "X-Partner-Key": [messagefoundry.env("partner_key", default=SENTINEL)]
        },
        "marker in a nested key": {
            "X-Partner-Key": {messagefoundry.env("partner_key", default=SENTINEL): "v"}
        },
    }[label]
    with pytest.raises(WiringError) as excinfo:
        messagefoundry.Rest(url="https://example.invalid/x", headers=deep)
    assert "X-Partner-Key" in str(excinfo.value), str(excinfo.value)
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


def test_ordinary_nested_structure_under_a_header_value_is_left_alone() -> None:
    """The control that separates 'looks for references' from 'refuses nesting'.

    A header value is ultimately a string, so structure under one is unusual -- but it is the
    author's business, and a guard that refused all of it would be refusing configuration with a
    message about a reference nobody wrote.
    """
    spec = messagefoundry.Rest(
        url="https://example.invalid/x",
        headers={"X-Odd": {"a": ["b", {"c": "d"}]}},
    )
    assert spec.settings["headers"]["X-Odd"] == {"a": ["b", {"c": "d"}]}


def test_the_toml_surface_really_does_hand_a_raw_dict_to_the_factory(
    tmp_path: pathlib.Path,
) -> None:
    """Measure the claim the 'connections.toml' arm above rests on, instead of reasoning it.

    That arm hand-builds the raw dict. This one drives ``load_connections_file``, which is the only
    thing that establishes ``parse_env_setting`` does not descend into ``[settings.headers]`` -- the
    premise the whole second shape exists for. It also records that only ``rest`` and ``soap`` of the
    five factories have a TOML route at all (``_TRANSPORTS``); the other three are code-first, so
    their raw-dict arm covers a hand-built call rather than a file.
    """
    from messagefoundry.config.connections_file import _TRANSPORTS, load_connections_file

    assert {"rest", "soap"} <= set(_TRANSPORTS), sorted(_TRANSPORTS)
    assert not {"fhir", "dicomweb", "fhir_lookup"} & set(_TRANSPORTS), sorted(_TRANSPORTS)

    (tmp_path / "connections.toml").write_text(
        "[[outbound]]\n"
        'name = "OB_ACME_REST"\n'
        'transport = "rest"\n'
        "[outbound.settings]\n"
        'url = "https://example.invalid/x"\n'
        "[outbound.settings.headers]\n"
        f'X-Partner-Key = {{ env = "partner_key", default = "{SENTINEL}" }}\n',
        encoding="utf-8",
    )
    with pytest.raises(WiringError) as excinfo:
        load_connections_file(tmp_path / "connections.toml", Registry())
    assert "X-Partner-Key" in str(excinfo.value), str(excinfo.value)
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


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
    the narrowing this repository has been bitten by three times.

    THE RETURN FILTER IS ANY ``*Spec``, not a typed-out pair. Naming ``ConnectionSpec`` and
    ``FhirLookupSpec`` would have been a completeness claim (CLAUDE.md SDS-3.6) over a package that
    already has ``DatabaseLookupSpec``, ``ReferenceSpec`` and ``ReferenceSourceSpec``: a future
    HTTP-shaped lookup returning one of those with a ``headers`` parameter would be invisible to the
    one assertion claiming to see the whole surface. Widening costs nothing, because the ``headers``
    parameter below is what actually narrows the set -- it still excludes the runtime helpers that
    take a ``headers`` argument (``redirect_request``, ``ech_readdressed_request``,
    ``enforce_outbound_length_limits`` and friends), which build a live request from already-resolved
    settings and have no reference left to refuse by the time they run.

    ALL THREE PARAMETER KINDS ARE READ. Omitting ``posonlyargs`` would let
    ``def NewThing(name, headers, /, *, url) -> ConnectionSpec`` pass the coverage assertion while
    shipping an unguarded surface.
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
                and "Spec" in ast.unparse(node.returns)
            ):
                args = [
                    a.arg for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                ]
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
