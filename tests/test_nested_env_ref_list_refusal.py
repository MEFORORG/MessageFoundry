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
from messagefoundry.transports.rest import _normalize_no_proxy

PKG = pathlib.Path(messagefoundry.__file__).resolve().parent

#: Invented by this test. It stands in for a fallback an author would write as ``default=``.
SENTINEL = "MFTEST-LIST-ITEM-ENV-DEFAULT-MUST-NOT-SHIP"

#: ``(factory, setting)`` -> a call that builds that factory with ``value`` for that setting and
#: otherwise valid arguments. The derived-domain test below asserts this covers the whole surface.
LIST_SETTINGS: dict[tuple[str, str], Callable[[Any], Any]] = {
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
    # vault BACKLOG #2804: both lists apply only to a transaction or batch connection.
    ("FHIR", "allowed_entry_methods"): lambda v: messagefoundry.FHIR(
        url="https://example.invalid/fhir", interaction="transaction", allowed_entry_methods=v
    ),
    ("FHIR", "allowed_entry_types"): lambda v: messagefoundry.FHIR(
        url="https://example.invalid/fhir",
        interaction="transaction",
        allowed_entry_methods=["POST"],
        allowed_entry_types=v,
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

#: ``Http``'s ``intake_client_subjects`` is a TABLE of lists, keyed by the issuing CA's DN (vault
#: BACKLOG #2287). The coverage walk still finds it, since its annotation names a sequence, so it is
#: covered here, by the tests under "a table of lists" below, which are parametrized over
#: ``TABLE_OF_LIST_SETTINGS`` as the list tests are over ``LIST_SETTINGS``.
PARTNER_CA = "CN=Partner CA"


def _http_subjects(value: Any) -> Any:
    """``Http`` built with ``value`` as its whole ``intake_client_subjects``."""
    return messagefoundry.Http(
        port=2575,
        tls=True,
        tls_cert_file="cert.pem",
        tls_key_file="key.pem",
        tls_ca_file="ca.pem",
        intake_auth="mtls_subject",
        intake_client_subjects=value,
    )


TABLE_OF_LIST_SETTINGS: dict[tuple[str, str], Callable[[Any], Any]] = {
    ("Http", "intake_client_subjects"): _http_subjects,
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
    """A static item the setting accepts; the FHIR Bundle entry lists take a verb and a resource
    type (vault BACKLOG #2804)."""
    return {
        "allowed_entry_methods": "POST",
        "allowed_entry_types": "Patient",
    }.get(setting, "static.example.invalid")


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
    spec = _http_subjects({PARTNER_CA: ["CN:partner.example"]})
    settings = dict(spec.settings)
    settings["intake_client_subjects"] = {PARTNER_CA: [NESTED_SHAPES["connections.toml"]()]}
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
            # A nested env-ref marker where a str belongs IS the input under test.
            proxy_no_proxy=["a.example.invalid", "b.example.invalid", {"env": "np"}],  # type: ignore[list-item]
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
            # A list nested inside the list IS the input under test.
            capture_response_headers=[["x-a", NESTED_SHAPES["connections.toml"]()]],  # type: ignore[list-item]
        )
    assert "capture_response_headers item 0" in str(excinfo.value)
    assert SENTINEL not in str(excinfo.value)


#: The refusal every ``env()`` default holding a reference gets when it is made (BACKLOG #2519).
DEFAULT_REFUSAL = "has an env() reference inside its default="


@pytest.mark.parametrize("target", sorted(LIST_SETTINGS))
@pytest.mark.parametrize("shape", sorted(NESTED_SHAPES))
def test_a_reference_past_the_defaults_scan_depth_is_refused_by_the_factory(
    shape: str, target: tuple[str, str]
) -> None:
    """``EnvRef``'s scan stops at ``_MAX_ENVREF_SCAN_DEPTH``, so a marker one list past it builds a
    reference. The factory's walk starts one level further in, at each item, and sees it, on every
    list setting. That is why the walk stayed when the first-link refusal moved into ``EnvRef``."""
    factory, setting = target
    deep: Any = NESTED_SHAPES[shape]()
    for _ in range(wiring._MAX_ENVREF_SCAN_DEPTH + 1):
        deep = [deep]
    assert not wiring._contains_envref(deep), "the premise: EnvRef's scan does not reach this"
    assert wiring._contains_envref(deep[0]), "the premise: the factory's walk does"
    whole = messagefoundry.env("whole_list", default=deep)
    with pytest.raises(WiringError) as excinfo:
        LIST_SETTINGS[target](whole)
    message = str(excinfo.value)
    assert f"{factory} {setting} env() default item 0" in message, message
    assert SENTINEL not in message, message


# --- a reference inside an env() default (BACKLOG #2519) ---------------------


def _past_the_refusal(default: Any) -> EnvRef:
    """A reference carrying ``default``, forged past ``EnvRef``'s refusal. It is frozen, so only
    ``object.__setattr__`` can do this, which is how the hazard stays measurable."""
    ref = messagefoundry.env("outer_list")
    object.__setattr__(ref, "default", default)
    return ref


#: A reference in a default, in every position it was measured reaching the connector from. Each
#: carries the sentinel, so the no-echo check can fail in each.
DEFAULTS_HOLDING_A_REFERENCE: dict[str, Callable[[], Any]] = {
    "EnvRef": NESTED_SHAPES["code-first"],
    "marker": NESTED_SHAPES["connections.toml"],
    "marker-with-a-list": lambda: {"env": "inner", "default": ["static.example.invalid", SENTINEL]},
    "EnvRef-in-a-table": lambda: {"X-Key": NESTED_SHAPES["code-first"]()},
    "marker-in-a-table": lambda: {"X-Key": NESTED_SHAPES["connections.toml"]()},
    "EnvRef-as-a-table-key": lambda: {NESTED_SHAPES["code-first"](): "static"},
    "EnvRef-in-a-list": lambda: ["x", NESTED_SHAPES["code-first"]()],
    "marker-in-a-list": lambda: ["x", NESTED_SHAPES["connections.toml"]()],
}

#: Every route that makes a reference from a key and a default.
CONSTRUCTION_ROUTES: dict[str, Callable[[str, Any], Any]] = {
    "env": lambda key, default: messagefoundry.env(key, default=default),
    "EnvRef": lambda key, default: EnvRef(key=key, default=default),
    "parse_env_setting": lambda key, default: wiring.parse_env_setting(
        {"env": key, "default": default}
    ),
}


@pytest.mark.parametrize("route", sorted(CONSTRUCTION_ROUTES))
@pytest.mark.parametrize("default", sorted(DEFAULTS_HOLDING_A_REFERENCE))
def test_a_reference_inside_a_default_is_refused_when_it_is_made(default: str, route: str) -> None:
    """Each route names the outer key and withholds the default."""
    with pytest.raises(WiringError) as excinfo:
        CONSTRUCTION_ROUTES[route]("outer", DEFAULTS_HOLDING_A_REFERENCE[default]())
    message = str(excinfo.value)
    assert f"env reference 'outer' {DEFAULT_REFUSAL}" in message, message
    assert SENTINEL not in message, message


def test_the_reported_code_first_shape_is_refused_at_load(tmp_path: pathlib.Path) -> None:
    """The row's own example, through a real config module: the raise is an import-time load error."""
    (tmp_path / "cfg.py").write_text(
        "from messagefoundry import Rest, env, outbound\n"
        'outbound("OB_ACME", Rest(url="https://example.invalid/x", bearer_token=env("tok", '
        f'default=env("tok2", default="{SENTINEL}"))))\n',
        encoding="utf-8",
    )
    with pytest.raises(WiringError) as excinfo:
        wiring.load_config(tmp_path)
    assert f"env reference 'tok' {DEFAULT_REFUSAL}" in str(excinfo.value), str(excinfo.value)
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


@pytest.mark.parametrize("spelling", ["env", "marker"])
def test_a_reference_valued_default_would_reach_the_connector_unresolved(spelling: str) -> None:
    """Positive control for the refusal, driven into a real sink. ``resolve_env_settings`` resolves
    one link, so with the outer key unset the INNER reference arrives unresolved -- even with the
    inner key set -- and Rest's proxy-bypass list reads it as empty. That is why a chain with a clean
    static list is refused too: its fallback link never works, so no version of it is clean."""
    items = ["bypass.example.invalid"]
    inner: Any = (
        messagefoundry.env("inner_list", default=items)
        if spelling == "env"
        else {"env": "inner_list", "default": items}
    )
    forged = _past_the_refusal(inner)
    resolved = resolve_env_settings(
        {"proxy_no_proxy": forged}, {"inner_list": ["set.example.invalid"]}
    )
    assert resolved["proxy_no_proxy"] is inner
    assert _normalize_no_proxy(resolved["proxy_no_proxy"]) == ()


@pytest.mark.parametrize("target", sorted(LIST_SETTINGS))
def test_a_default_turned_into_a_reference_after_it_was_made_is_refused_by_the_factory(
    target: tuple[str, str],
) -> None:
    """``EnvRef`` reads the default once. A table it took as clean can become a marker afterwards,
    and only the factory reads it again."""
    factory, setting = target
    default: dict[str, Any] = {}
    whole = messagefoundry.env("whole_list", default=default)
    default.update({"env": "inner", "default": [SENTINEL]})
    with pytest.raises(WiringError) as excinfo:
        LIST_SETTINGS[target](whole)
    message = str(excinfo.value)
    assert f"{factory} {setting} env() default may not be" in message, message
    assert "with a static default" in message, message
    assert SENTINEL not in message, message


@pytest.mark.parametrize(
    "marker",
    [
        pytest.param({"env": {"env": "inner", "default": SENTINEL}}, id="key"),
        pytest.param({"env": "outer", "cast": {"env": "inner", "default": SENTINEL}}, id="cast"),
    ],
)
def test_a_reference_in_the_key_or_cast_slot_is_named_by_type(marker: dict[str, Any]) -> None:
    """The same chain with its table one slot over. A refusal that printed the slot would carry the
    default the refusal above withholds."""
    with pytest.raises(WiringError) as excinfo:
        wiring.parse_env_setting(marker)
    assert "dict" in str(excinfo.value), str(excinfo.value)
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


def test_a_cast_that_is_not_text_says_so() -> None:
    """Type names of TOML scalars are valid cast names, so "unknown cast int" would contradict the
    list of casts printed beside it."""
    with pytest.raises(WiringError, match="it must be a string, got int"):
        wiring.parse_env_setting({"env": "t", "cast": 5})


def test_a_label_names_a_table_in_the_key_slot_by_type() -> None:
    label = wiring._envref_label({"env": {"env": "inner", "default": SENTINEL}})
    assert label == "env(<dict>)"


def test_a_reference_inside_a_table_default_would_reach_the_partner() -> None:
    """Positive control for the table shape: nothing reads inside a resolved default, so the header
    value holds the marker, default included, wherever the whole-table key is unset."""
    forged = _past_the_refusal({"X-Key": {"env": "inner", "default": SENTINEL}})
    resolved = resolve_env_settings({"headers": forged}, {"inner": "set"})
    assert SENTINEL in str(resolved["headers"]["X-Key"])


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(
            lambda: messagefoundry.env("outer", default=messagefoundry.env("inner"), cast=bool),
            id="code-first",
        ),
        pytest.param(
            lambda: wiring.parse_env_setting(
                {"env": "outer", "cast": "bool", "default": {"env": "inner"}}
            ),
            id="connections.toml",
        ),
    ],
)
def test_a_bool_cast_chain_hears_the_chain_refusal_not_the_boolean_one(
    make: Callable[[], Any],
) -> None:
    """Ahead of the bool read: a reference is not a bad boolean, and "not a boolean" would send the
    author looking for the wrong fix."""
    with pytest.raises(WiringError) as excinfo:
        make()
    assert DEFAULT_REFUSAL in str(excinfo.value), str(excinfo.value)
    assert "not a boolean" not in str(excinfo.value), str(excinfo.value)


def test_a_self_referential_default_is_refused_at_the_first_link() -> None:
    """A raw marker whose default list holds the sentinel and the marker itself. The refusal stops at
    the first link, so nothing walks the cycle, and the message withholds what the cycle holds."""
    loop: dict[str, Any] = {"env": "loop", "default": [SENTINEL]}
    loop["default"].append(loop)
    with pytest.raises(WiringError) as excinfo:
        messagefoundry.env("outer_list", default=loop)
    message = str(excinfo.value)
    assert DEFAULT_REFUSAL in message, message
    assert SENTINEL not in message, message


@pytest.mark.parametrize(
    "table", [{"env": "prod"}, {"env": "prod", "default": "x"}, {"env": "prod", "cast": "str"}]
)
def test_a_table_that_reads_as_a_reference_is_refused_in_a_default_by_decision(
    table: dict[str, str],
) -> None:
    """A real header table named ``env`` is refused here. TOML cannot tell it from the chain shape,
    so the message says so, and the same table written directly stays legal in code."""
    with pytest.raises(WiringError) as excinfo:
        messagefoundry.env("h", default=table)
    assert "counts as a reference" in str(excinfo.value), str(excinfo.value)
    spec = messagefoundry.Rest(url="https://example.invalid/x", headers={"env": "prod"})
    assert spec.settings["headers"] == {"env": "prod"}


@pytest.mark.parametrize(
    "default",
    [
        pytest.param("static", id="scalar"),
        pytest.param(5, id="int"),
        pytest.param(None, id="none"),
        pytest.param(["a", "b"], id="list"),
        pytest.param({"Accept": "application/fhir+json"}, id="table"),
        pytest.param({"env": "prod", "not_an_envref_key": 1}, id="near-miss-table"),
        pytest.param({"X": {"env": "prod", "not_an_envref_key": 1}}, id="near-miss-nested"),
    ],
)
def test_a_static_default_still_builds_and_resolves(default: Any) -> None:
    """Over-widening control. It resolves to the default with the key unset."""
    ref = messagefoundry.env("key", default=default)
    assert ref.default == default
    assert resolve_env_settings({"s": ref}, {})["s"] == default


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

#: ``(file head, setting)`` for each list-valued setting a ``connections.toml`` transport reaches.
_TOML_LIST_TARGETS = [
    (_OUTBOUND_HEAD.format(transport="rest"), "capture_response_headers"),
    (_OUTBOUND_HEAD.format(transport="rest"), "proxy_no_proxy"),
    (_SOAP_HEAD, "capture_response_headers"),
    (_SOAP_HEAD, "proxy_no_proxy"),
]


@pytest.mark.parametrize(("head", "setting"), _TOML_LIST_TARGETS)
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


def _toml_refusal(tmp_path: pathlib.Path, body: str) -> str:
    """The refusal ``body`` gets from the file loader, checked for what every one must hold."""
    with pytest.raises(WiringError) as excinfo:
        load_connections_file(_write(tmp_path, body), Registry())
    message = str(excinfo.value)
    assert "connection 'OB_ACME'" in message, message
    assert SENTINEL not in message, message
    return message


@pytest.mark.parametrize(("head", "setting"), _TOML_LIST_TARGETS)
def test_the_toml_surface_refuses_a_nested_env_default_when_it_decodes_it(
    tmp_path: pathlib.Path, head: str, setting: str
) -> None:
    """The file spelling of the nested shape never reaches the factory guard or the type check:
    ``parse_env_setting`` constructs the ``EnvRef``, which refuses it, and ``_build_spec`` adds the
    connection and the setting."""
    message = _toml_refusal(
        tmp_path,
        f'{head}{setting} = {{ env = "outer_list", default = '
        f'{{ env = "inner_list", default = ["{_static(setting)}", {TOML_MARKER}] }} }}\n',
    )
    assert f"'{setting}': env reference 'outer_list' {DEFAULT_REFUSAL}" in message, message


#: ``headers`` is the control-bearing TOML target: it alone passes the type check with a table
#: default, so these fail before the refusal. ``bearer_token`` and its kin are refused by that check
#: already, and would pass with no fix at all.
_TOML_HEADERS_HEADS = [
    pytest.param(_OUTBOUND_HEAD.format(transport="rest"), id="rest"),
    pytest.param(_SOAP_HEAD, id="soap"),
]


@pytest.mark.parametrize("head", _TOML_HEADERS_HEADS)
@pytest.mark.parametrize(
    "default",
    [
        pytest.param(TOML_MARKER, id="default-is-a-marker"),
        pytest.param(f"{{ X-Key = {TOML_MARKER} }}", id="table-default-holds-a-marker"),
    ],
)
def test_the_toml_surface_refuses_a_reference_in_a_headers_default(
    tmp_path: pathlib.Path, head: str, default: str
) -> None:
    message = _toml_refusal(
        tmp_path, f'{head}headers = {{ env = "all_headers", default = {default} }}\n'
    )
    assert f"'headers': env reference 'all_headers' {DEFAULT_REFUSAL}" in message, message


@pytest.mark.parametrize("head", _TOML_HEADERS_HEADS)
def test_the_toml_spelling_of_a_header_named_env_in_a_default_is_refused(
    tmp_path: pathlib.Path, head: str
) -> None:
    """The decision pinned above, in the spelling that forces it."""
    message = _toml_refusal(
        tmp_path, f'{head}headers = {{ env = "all_headers", default = {{ env = "prod" }} }}\n'
    )
    assert "counts as a reference" in message, message


@pytest.mark.parametrize("head", _TOML_HEADERS_HEADS)
def test_a_toml_headers_env_with_a_static_table_default_still_loads(
    tmp_path: pathlib.Path, head: str
) -> None:
    """Over-widening control on the surface the refusal runs on."""
    path = _write(
        tmp_path,
        f'{head}headers = {{ env = "all_headers", default = {{ Accept = "text/xml" }} }}\n',
    )
    registry = Registry()
    load_connections_file(path, registry)
    settings = registry.outbound["OB_ACME"].spec.settings
    assert resolve_env_settings(settings, {})["headers"] == {"Accept": "text/xml"}


# --- over-widening controls --------------------------------------------------


@pytest.mark.parametrize("target", sorted(LIST_SETTINGS))
def test_a_static_list_still_builds(target: tuple[str, str]) -> None:
    _factory, setting = target
    spec = LIST_SETTINGS[target]([_static(setting)])
    assert spec.settings[setting] == [_static(setting)]


_WHOLE_SETTING_TARGETS = sorted(LIST_SETTINGS)


@pytest.mark.parametrize("target", _WHOLE_SETTING_TARGETS)
def test_an_env_ref_standing_for_the_whole_setting_still_builds(target: tuple[str, str]) -> None:
    _factory, setting = target
    spec = LIST_SETTINGS[target](messagefoundry.env("whole_list"))
    assert isinstance(spec.settings[setting], EnvRef)
    resolved = resolve_env_settings(spec.settings, {"whole_list": [_static(setting)]})
    assert resolved[setting] == [_static(setting)]


@pytest.mark.parametrize("target", _WHOLE_SETTING_TARGETS)
def test_a_whole_setting_env_with_a_static_list_default_still_builds(
    target: tuple[str, str],
) -> None:
    """Over-widening control for the nested-default refusal: ONE link with a static list default is
    the legal shape. It resolves to the default with the key unset and to the environment's list with
    it set."""
    _factory, setting = target
    spec = LIST_SETTINGS[target](messagefoundry.env("whole_list", default=[_static(setting)]))
    assert resolve_env_settings(spec.settings, {})[setting] == [_static(setting)]
    from_env = resolve_env_settings(spec.settings, {"whole_list": ["env.example.invalid"]})
    assert from_env[setting] == ["env.example.invalid"]


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


# --- a table of lists: Http's intake_client_subjects (vault BACKLOG #2287) ----


@pytest.mark.parametrize("target", sorted(TABLE_OF_LIST_SETTINGS))
@pytest.mark.parametrize("shape", sorted(NESTED_SHAPES))
def test_an_env_ref_item_in_a_tables_list_is_refused_without_echoing_its_default(
    shape: str, target: tuple[str, str]
) -> None:
    factory, setting = target
    with pytest.raises(WiringError) as excinfo:
        TABLE_OF_LIST_SETTINGS[target]({PARTNER_CA: ["CN:partner.example", NESTED_SHAPES[shape]()]})
    message = str(excinfo.value)
    assert f"{factory} {setting} '{PARTNER_CA}' item 1 may not be" in message, message
    assert SENTINEL not in message, message


@pytest.mark.parametrize("target", sorted(TABLE_OF_LIST_SETTINGS))
@pytest.mark.parametrize("shape", sorted(NESTED_SHAPES))
def test_an_env_ref_standing_for_one_of_a_tables_lists_is_refused(
    shape: str, target: tuple[str, str]
) -> None:
    """One level down is never resolved, so it would reach the connector as the reference itself."""
    factory, setting = target
    with pytest.raises(WiringError) as excinfo:
        TABLE_OF_LIST_SETTINGS[target]({PARTNER_CA: NESTED_SHAPES[shape]()})
    message = str(excinfo.value)
    assert f"{factory} {setting} issuer '{PARTNER_CA}' may not" in message, message
    assert SENTINEL not in message, message


@pytest.mark.parametrize(
    "whole",
    [
        pytest.param(lambda: messagefoundry.env("whole_table"), id="no-default"),
        pytest.param(
            lambda: messagefoundry.env("whole_table", default={PARTNER_CA: [SENTINEL]}),
            id="static-default",
        ),
    ],
)
@pytest.mark.parametrize("target", sorted(TABLE_OF_LIST_SETTINGS))
def test_an_env_ref_standing_for_the_whole_table_is_refused(
    whole: Callable[[], Any], target: tuple[str, str]
) -> None:
    """An environment value is a string, never a table, so the whole-setting spelling the list
    settings take has no meaning here and is refused rather than resolved."""
    factory, setting = target
    with pytest.raises(WiringError) as excinfo:
        TABLE_OF_LIST_SETTINGS[target](whole())
    message = str(excinfo.value)
    assert f"{factory} {setting} may not be an env() reference" in message, message
    assert SENTINEL not in message, message


@pytest.mark.parametrize("target", sorted(TABLE_OF_LIST_SETTINGS))
def test_a_static_table_of_lists_still_builds(target: tuple[str, str]) -> None:
    _factory, setting = target
    spec = TABLE_OF_LIST_SETTINGS[target]({PARTNER_CA: ["CN:partner.example"]})
    assert spec.settings[setting] == {PARTNER_CA: ["CN:partner.example"]}


def test_the_toml_surface_refuses_an_env_ref_item_in_an_issuers_list(
    tmp_path: pathlib.Path,
) -> None:
    path = _write(
        tmp_path,
        f"{_HTTP_INBOUND_HEAD}[inbound.settings.intake_client_subjects]\n"
        f"'{PARTNER_CA}' = [\"CN:partner.example\", {TOML_MARKER}]\n",
    )
    with pytest.raises(WiringError) as excinfo:
        load_connections_file(path, Registry())
    assert f"'{PARTNER_CA}' item 1 may not be" in str(excinfo.value), str(excinfo.value)
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


def test_the_toml_surface_refuses_an_env_ref_for_an_issuers_list(tmp_path: pathlib.Path) -> None:
    path = _write(
        tmp_path,
        f"{_HTTP_INBOUND_HEAD}[inbound.settings.intake_client_subjects]\n"
        f"'{PARTNER_CA}' = {TOML_MARKER}\n",
    )
    with pytest.raises(WiringError) as excinfo:
        load_connections_file(path, Registry())
    assert "may not name its subjects with an env() reference" in str(excinfo.value)
    assert SENTINEL not in str(excinfo.value), str(excinfo.value)


def test_a_table_that_only_looks_like_an_env_ref_is_left_alone() -> None:
    """Near-miss control: an extra key makes it no marker to ``parse_env_setting`` either, so a guard
    firing on it would refuse ordinary data with a message about a reference nobody wrote."""
    lookalike = {"env": "partner_value", "not_an_envref_key": 1}
    spec = messagefoundry.Rest(
        url="https://example.invalid/x",
        capture_response_headers=["x-a", lookalike],  # type: ignore[list-item]  # the near-miss IS the input
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
    covered = set(LIST_SETTINGS) | set(TABLE_OF_LIST_SETTINGS)
    assert derived == covered, (
        f"list-valued settings not covered here: {sorted(derived - covered)}; "
        f"covered but no longer found: {sorted(covered - derived)}"
    )
