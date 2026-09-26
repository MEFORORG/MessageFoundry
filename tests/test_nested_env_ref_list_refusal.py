# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An env() reference written as a LIST ITEM of a connection setting is refused (BACKLOG #1820).

The rule and its reasoning are stated once, on ``wiring._reject_envref_in_lists``. This file proves
it in four parts: the hazard is real (the positive controls come first, so no assertion below can
pass vacuously), both spellings are refused on both authoring surfaces, the refusal never repeats the
fallback ``default``, and the guard does not widen -- a static list, a whole-setting env() and a
lookalike table still build.

The factory domain is DERIVED from annotations, not typed out. The backlog row's own list named
settings no ``connections.toml`` transport can reach and was not claimed complete, which is the
argument for deriving it: ``test_every_list_valued_factory_setting_is_covered`` fails if a factory
grows a list-valued parameter this file does not exercise.
"""

from __future__ import annotations

import ast
import pathlib
from collections.abc import Callable
from typing import Any

import pytest

import messagefoundry
from messagefoundry.config import wiring
from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.wiring import EnvRef, Registry, WiringError, resolve_env_settings
from messagefoundry.transports.email import _as_recipients

PKG = pathlib.Path(messagefoundry.__file__).resolve().parent

#: Invented by this test. It stands in for a fallback an author would write as ``default=``.
SENTINEL = "MFTEST-LIST-ITEM-ENV-DEFAULT-MUST-NOT-SHIP"

#: ``(factory, setting)`` -> a call that builds that factory with ``value`` for that setting and
#: otherwise valid arguments. The derived-domain test below asserts this covers the whole surface.
LIST_SETTINGS: dict[tuple[str, str], Callable[[Any], Any]] = {
    ("Http", "intake_client_subjects"): lambda v: messagefoundry.Http(
        port=2575,
        tls=True,
        tls_cert_file="cert.pem",
        tls_key_file="key.pem",
        tls_ca_file="ca.pem",
        intake_auth="mtls_subject",
        intake_client_subjects=v,
    ),
    ("Rest", "capture_response_headers"): lambda v: messagefoundry.Rest(
        url="https://example.invalid/x", capture_response_headers=v
    ),
    ("Rest", "proxy_no_proxy"): lambda v: messagefoundry.Rest(
        url="https://example.invalid/x", proxy_no_proxy=v
    ),
    ("FHIR", "capture_response_headers"): lambda v: messagefoundry.FHIR(
        url="https://example.invalid/fhir", capture_response_headers=v
    ),
    ("FHIR", "proxy_no_proxy"): lambda v: messagefoundry.FHIR(
        url="https://example.invalid/fhir", proxy_no_proxy=v
    ),
    ("Email", "recipients"): lambda v: messagefoundry.Email(
        host="smtp.example.invalid", sender="mf@example.invalid", recipients=v
    ),
    ("Direct", "recipients"): lambda v: messagefoundry.Direct(
        host="smtp.example.invalid",
        sender="mf@example.invalid",
        recipients=v,
        signing_cert="signing.pem",
        signing_key="signing.key",
        recipient_cert="recipient.pem",
        trust_anchor="anchor.pem",
    ),
    ("DICOM", "presentation_contexts"): lambda v: messagefoundry.DICOM(
        ae_title="MF", presentation_contexts=v
    ),
    ("DICOM", "calling_ae_allowlist"): lambda v: messagefoundry.DICOM(
        ae_title="MF", calling_ae_allowlist=v
    ),
    ("DICOMweb", "proxy_no_proxy"): lambda v: messagefoundry.DICOMweb(
        url="https://example.invalid/stow", proxy_no_proxy=v
    ),
    ("Soap", "capture_response_headers"): lambda v: messagefoundry.Soap(
        url="https://example.invalid/svc", soap_action="urn:probe", capture_response_headers=v
    ),
    ("Soap", "proxy_no_proxy"): lambda v: messagefoundry.Soap(
        url="https://example.invalid/svc", soap_action="urn:probe", proxy_no_proxy=v
    ),
}

#: The two shapes a nested reference reaches a factory in. Code-first gives an ``EnvRef``;
#: ``connections.toml`` gives the raw marker, because ``parse_env_setting`` decodes top-level only.
NESTED_SHAPES: dict[str, Callable[[], Any]] = {
    "code-first": lambda: messagefoundry.env("partner_value", default=SENTINEL),
    "connections.toml": lambda: {"env": "partner_value", "default": SENTINEL},
}

#: The raw marker as a TOML inline table, for the tests that drive the file loader.
TOML_MARKER = f'{{ env = "partner_value", default = "{SENTINEL}" }}'


def _static(setting: str) -> str:
    """A static item the setting accepts; ``intake_client_subjects`` needs a qualified prefix."""
    return "CN:partner.example" if setting == "intake_client_subjects" else "static.example.invalid"


def _write(tmp_path: pathlib.Path, body: str) -> pathlib.Path:
    path = tmp_path / "connections.toml"
    path.write_text(body, encoding="utf-8")
    return path


# --- the hazard being refused ------------------------------------------------


@pytest.mark.parametrize("shape", sorted(NESTED_SHAPES))
def test_the_leak_this_refusal_exists_to_stop_is_real(shape: str) -> None:
    """Positive control, built past the factory door. ``resolve_env_settings`` leaves a list item
    alone, and Email's own coercion ``str()``s it, so the default lands in the To: list."""
    settings = {"recipients": ["ops@example.invalid", NESTED_SHAPES[shape]()]}
    resolved = resolve_env_settings(settings, {})
    assert resolved["recipients"][1] == settings["recipients"][1]
    assert any(SENTINEL in address for address in _as_recipients(resolved["recipients"]))


def test_an_existing_validator_would_echo_the_default_so_the_refusal_must_run_first() -> None:
    """Ordering control. ``Http``'s subject-prefix check quotes unqualified items, so if it ran
    before the list refusal, its OWN message would carry the default."""
    spec = LIST_SETTINGS["Http", "intake_client_subjects"](["CN:partner.example"])
    settings = dict(spec.settings)
    settings["intake_client_subjects"] = [NESTED_SHAPES["connections.toml"]()]
    with pytest.raises(WiringError) as excinfo:
        wiring._validate_intake_auth(settings)
    assert SENTINEL in str(excinfo.value)


# --- the refusal, both spellings, every list-valued setting ------------------


@pytest.mark.parametrize("target", sorted(LIST_SETTINGS))
@pytest.mark.parametrize("shape", sorted(NESTED_SHAPES))
def test_an_env_ref_list_item_is_refused_without_echoing_its_default(
    target: tuple[str, str], shape: str
) -> None:
    factory, setting = target
    with pytest.raises(WiringError) as excinfo:
        LIST_SETTINGS[target]([_static(setting), NESTED_SHAPES[shape]()])
    message = str(excinfo.value)
    assert f"{factory} {setting} item 1" in message, message
    assert SENTINEL not in message, message


def test_every_offender_is_named_and_the_static_items_beside_them_are_not() -> None:
    with pytest.raises(WiringError) as excinfo:
        messagefoundry.Rest(
            url="https://example.invalid/x",
            capture_response_headers=[NESTED_SHAPES["code-first"](), "x-static"],
            proxy_no_proxy=["a.example.invalid", "b.example.invalid", {"env": "np"}],
        )
    message = str(excinfo.value)
    assert "capture_response_headers item 0" in message, message
    assert "proxy_no_proxy item 2" in message, message
    assert "x-static" not in message, message
    assert "a.example.invalid" not in message, message


def test_a_reference_one_level_deeper_in_an_item_is_refused_too() -> None:
    """The scan reuses the headers guard's recursive one, so a marker inside a nested item is seen."""
    with pytest.raises(WiringError) as excinfo:
        messagefoundry.Rest(
            url="https://example.invalid/x",
            capture_response_headers=[["x-a", NESTED_SHAPES["connections.toml"]()]],
        )
    assert "capture_response_headers item 0" in str(excinfo.value)
    assert SENTINEL not in str(excinfo.value)


_OUTBOUND_HEAD = (
    "[[outbound]]\n"
    'name = "OB_ACME"\n'
    'transport = "{transport}"\n'
    "[outbound.settings]\n"
    'url = "https://example.invalid/x"\n'
)
_HTTP_INBOUND_HEAD = (
    "[[inbound]]\n"
    'name = "IB_ACME"\n'
    'transport = "http"\n'
    'router = "r"\n'
    "[inbound.settings]\n"
    "port = 8443\n"
    "tls = true\n"
    'tls_cert_file = "cert.pem"\n'
    'tls_key_file = "key.pem"\n'
    'tls_ca_file = "ca.pem"\n'
    'intake_auth = "mtls_subject"\n'
)
_SOAP_HEAD = _OUTBOUND_HEAD.format(transport="soap") + 'soap_action = "urn:probe"\n'


@pytest.mark.parametrize(
    ("head", "setting"),
    [
        (_OUTBOUND_HEAD.format(transport="rest"), "capture_response_headers"),
        (_OUTBOUND_HEAD.format(transport="rest"), "proxy_no_proxy"),
        (_SOAP_HEAD, "capture_response_headers"),
        (_SOAP_HEAD, "proxy_no_proxy"),
        (_HTTP_INBOUND_HEAD, "intake_client_subjects"),
    ],
)
def test_the_toml_surface_refuses_a_list_item(
    tmp_path: pathlib.Path, head: str, setting: str
) -> None:
    """Driven through ``load_connections_file``, which is the only thing that shows the raw marker
    really arrives undecoded -- the premise of the 'connections.toml' shape above."""
    path = _write(tmp_path, f'{head}{setting} = ["{_static(setting)}", {TOML_MARKER}]\n')
    with pytest.raises(WiringError) as excinfo:
        load_connections_file(path, Registry())
    assert f"{setting} item 1" in str(excinfo.value), str(excinfo.value)
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


# --- over-widening controls --------------------------------------------------


@pytest.mark.parametrize("target", sorted(LIST_SETTINGS))
def test_a_static_list_still_builds(target: tuple[str, str]) -> None:
    _factory, setting = target
    spec = LIST_SETTINGS[target]([_static(setting)])
    assert spec.settings[setting] == [_static(setting)]


#: ``Http`` copies ``intake_client_subjects`` with ``list(...)`` before anything resolves it, so a
#: whole-setting env() there raises TypeError at build. That predates BACKLOG #1820 and is not what
#: this file tests; the strict xfail pins it, and turns red the day someone fixes it.
_WHOLE_SETTING_TARGETS = [
    pytest.param(
        target,
        marks=pytest.mark.xfail(
            strict=True, raises=TypeError, reason="Http list()s the setting before resolution"
        ),
    )
    if target == ("Http", "intake_client_subjects")
    else target
    for target in sorted(LIST_SETTINGS)
]


@pytest.mark.parametrize("target", _WHOLE_SETTING_TARGETS)
def test_an_env_ref_standing_for_the_whole_setting_still_builds(target: tuple[str, str]) -> None:
    _factory, setting = target
    spec = LIST_SETTINGS[target](messagefoundry.env("whole_list"))
    assert isinstance(spec.settings[setting], EnvRef)
    resolved = resolve_env_settings(spec.settings, {"whole_list": [_static(setting)]})
    assert resolved[setting] == [_static(setting)]


def test_a_whole_setting_env_ref_in_toml_is_still_decoded_and_resolves(
    tmp_path: pathlib.Path,
) -> None:
    path = _write(
        tmp_path,
        "[[outbound]]\n"
        'name = "OB_ACME"\n'
        'transport = "rest"\n'
        "[outbound.settings]\n"
        'url = "https://example.invalid/x"\n'
        'capture_response_headers = { env = "capture_list" }\n',
    )
    registry = Registry()
    load_connections_file(path, registry)
    settings = registry.outbound["OB_ACME"].spec.settings
    assert isinstance(settings["capture_response_headers"], EnvRef)
    resolved = resolve_env_settings(settings, {"capture_list": ["content-type"]})
    assert resolved["capture_response_headers"] == ["content-type"]


def test_a_table_that_only_looks_like_an_env_ref_is_left_alone() -> None:
    """Near-miss control: an extra key makes it no marker to ``parse_env_setting`` either, so a guard
    firing on it would refuse ordinary data with a message about a reference nobody wrote."""
    lookalike = {"env": "partner_value", "not_an_envref_key": 1}
    spec = messagefoundry.Rest(
        url="https://example.invalid/x", capture_response_headers=["x-a", lookalike]
    )
    assert spec.settings["capture_response_headers"][1] == lookalike


# --- coverage: is the guard pointed at the whole surface? --------------------

_SEQUENCE_WORDS = ("list", "Sequence", "tuple", "set", "frozenset", "Iterable", "Collection")


def _union_names(annotation: ast.expr) -> list[str]:
    """The bare names in a return annotation's top-level union: ``ConnectionSpec | None`` gives
    both, while ``list[ShardSpec]`` gives none, since a subscript is not a bare name."""
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _union_names(annotation.left) + _union_names(annotation.right)
    return [annotation.id] if isinstance(annotation, ast.Name) else []


def _list_valued_factory_settings() -> set[tuple[str, str]]:
    """Every public function in the package that may return a ``*Spec`` and takes a parameter
    annotated as a sequence. Package-wide and annotation-based, like the headers guard's own
    coverage walk, so the domain is not chosen by where the code lives today. A function returning
    ``list[...Spec]`` builds several specs from engine state rather than authoring one, and
    :func:`_union_names` leaves it out."""
    found: set[tuple[str, str]] = set()
    for path in sorted(PKG.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover - a syntax error fails the rest of the suite anyway
            continue
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                and not node.name.startswith("_")
                and node.returns is not None
                and any(name.endswith("Spec") for name in _union_names(node.returns))
            ):
                continue
            for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                if arg.annotation is not None and any(
                    word in ast.unparse(arg.annotation) for word in _SEQUENCE_WORDS
                ):
                    found.add((node.name, arg.arg))
    return found


def test_every_list_valued_factory_setting_is_covered() -> None:
    derived = _list_valued_factory_settings()
    assert derived, "the AST walk found nothing -- the instrument is broken, not the code"
    assert derived == set(LIST_SETTINGS), (
        f"list-valued settings not covered here: {sorted(derived - set(LIST_SETTINGS))}; "
        f"covered but no longer found: {sorted(set(LIST_SETTINGS) - derived)}"
    )
