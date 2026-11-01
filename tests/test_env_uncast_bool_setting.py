# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An uncast or ``str``-cast ``env()`` on a boolean setting reads strictly (vault BACKLOG #3234).

Vault BACKLOG #3138 made ``env(key, cast=bool)`` strict. An ``env()`` with no cast, or with a
``str`` cast, still handed the setting TEXT, and the connectors read it with ``bool()`` or plain
truthiness, so ``MEFOR_VALUE_X=false`` on a ``tls_allow_expired`` or a ``trust_server_certificate``
would have read True on a first deployment. ``resolve_env_settings`` now reads a setting whose
factory parameter is annotated ``bool`` with the same strict spelling cast, on both authoring routes,
and refuses an unknown spelling with the same value-withheld diagnostic."""

from __future__ import annotations

import ast
import dataclasses
import importlib
import inspect
import textwrap
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.trust_anchors import registry_anchor_specs
from messagefoundry.config import wiring
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    _COMPOSER_BOOL_SETTINGS,
    Database,
    EnvRef,
    Ftp,
    Http,
    Rest,
    WiringError,
    _bool_settings,
    build_inbound_connection,
    build_outbound_connection,
    env,
    load_config,
    resolve_env_settings,
)
from messagefoundry.pipeline.wiring_runner import (
    _dest_config,
    build_check_registry,
    check_http_sync_reply,
)
from messagefoundry.transports.http_auth import oauth2_auth_configured
from messagefoundry.transports.smart import smart_auth_configured
from tests._ast_sites import calls_to, parse_source

SPELLINGS = [(s, False) for s in ["false", "0", "no", "off", "False", " OFF "]] + [
    (s, True) for s in ["true", "1", "yes", "on", "TRUE"]
]


@pytest.mark.parametrize("cast", [None, str], ids=["uncast", "str"])
@pytest.mark.parametrize(("spelling", "want"), SPELLINGS)
def test_an_uncast_or_str_cast_bool_setting_reads_strictly(
    spelling: str, want: bool, cast: Any
) -> None:
    # The FALSE spellings carry the guard: bool() already read every true spelling as True.
    out = resolve_env_settings(
        {"tls_allow_expired": env("x", cast=cast), "persistent": env("y", cast=cast)},
        {"x": spelling, "y": spelling},
    )
    assert out["tls_allow_expired"] is want  # `is`: 1 == True, so equality would not pin the type
    assert out["persistent"] is want


@pytest.mark.parametrize(("raw", "want"), [(True, True), (False, False), (1, True), (0, False)])
def test_a_typed_toml_value_passes_through(raw: object, want: bool) -> None:
    assert resolve_env_settings({"persistent": env("x")}, {"x": raw})["persistent"] is want


def test_an_uncast_str_setting_still_passes_text_through() -> None:
    # Only a setting a factory annotates bool is read strictly; text stays text everywhere else.
    out = resolve_env_settings(
        {"host": env("h"), "url": env("u", cast=str)}, {"h": "false", "u": "0"}
    )
    assert out == {"host": "false", "url": "0"}


@pytest.mark.parametrize("cast", [None, str], ids=["uncast", "str"])
@pytest.mark.parametrize("raw", ["maybe", "", "2", 2, 1.5])
def test_an_unknown_spelling_is_refused_like_the_cast_bool_route(raw: object, cast: Any) -> None:
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(
            {"trust_server_certificate": env("db_trust", cast=cast)}, {"db_trust": raw}
        )
    msg = str(ei.value)
    assert "setting 'trust_server_certificate' (env 'db_trust'): value is not a valid bool" in msg
    assert "value withheld" in msg


def test_the_refusal_never_names_the_value() -> None:
    planted = "-".join(["planted", "not", "a", "bool"])
    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"verify_tls": env("v")}, {"v": planted})
    assert planted not in str(ei.value)
    assert ei.value.__cause__ is None and ei.value.__context__ is None


def test_all_problems_are_still_batched_into_one_error() -> None:
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(
            {"verify_tls": env("v"), "port": env("p", cast=int), "host": env("gone")},
            {"v": "maybe", "p": "x"},
        )
    msg = str(ei.value)
    assert "'verify_tls'" in msg and "'port'" in msg and "missing: gone" in msg


@pytest.mark.parametrize(("default", "want"), [("false", False), ("on", True), (0, False)])
def test_an_uncast_default_on_a_bool_setting_is_read_strictly(default: object, want: bool) -> None:
    out = resolve_env_settings({"overwrite": env("o", default=default)}, {})
    assert out["overwrite"] is want


def test_an_unreadable_uncast_default_is_refused_value_withheld() -> None:
    planted = "".join(["may", "be"])
    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"overwrite": env("o", default=planted)}, {})
    msg = str(ei.value)
    assert "env() default(s) unusable, fix them in the config" in msg
    assert "setting 'overwrite' (env 'o'): default is not a valid bool" in msg
    assert planted not in msg
    assert "environment value(s) unusable" not in msg  # not sent to the environment for it


@pytest.mark.parametrize(
    ("key", "want"),
    [("verify_tls", True), ("tls_check_hostname", True), ("require_called_ae_title", True)]
    + [("tls_allow_expired", False), ("trust_server_certificate", False)],
)
def test_a_none_on_a_bool_setting_takes_the_setting_default(key: str, want: bool) -> None:
    # Vault BACKLOG #3234 item 2. At least dicom.py reads require_called_ae_title with plain bool(),
    # so a None left in place would turn that default-on check off. None now resolves to the default
    # every factory gives the setting. A literal None is not touched (see the next test).
    assert resolve_env_settings({key: env("k", default=None)}, {})[key] is want


def test_a_literal_is_not_read_here() -> None:
    # Every pre-resolve reader (the loosening registers, the build-time capture checks) reads the
    # spec's literal, so reading it differently in the resolved copy would split one setting.
    out = resolve_env_settings({"tls_allow_expired": "false", "verify_tls": None}, {})
    assert out == {"tls_allow_expired": "false", "verify_tls": None}


def test_every_bool_setting_name_is_bool_on_every_factory_that_declares_it() -> None:
    # The strict read keys on the setting NAME, so a name that is bool on one factory and anything
    # else on another, or that two factories default differently, would be read wrongly on one of
    # them. _bool_settings drops the first and gives the second no default; this pins that neither
    # exists, so adding one fails here rather than quietly losing the strict read.
    found = _bool_settings()
    assert found.dropped == frozenset()
    assert found.split_defaults == frozenset()
    names = set(found.defaults)
    assert {"verify_tls", "tls_verify", "tls_allow_expired", "trust_server_certificate"} <= names
    assert {"persistent", "no_ack", "encrypt", "overwrite", "use_tls", "tls"} <= names
    assert "host" not in names and "url" not in names


# --- EnvRef's repr is stable across runs ------------------------------------------------------------


def test_env_ref_repr_names_the_cast_and_the_unset_sentinel() -> None:
    assert repr(env("Flag", cast=bool)) == "EnvRef(key='flag', default=<unset>, cast=bool)"
    assert repr(env("p", default=5, cast=int)) == "EnvRef(key='p', default=5, cast=int)"
    assert repr(env("h", default=None)) == "EnvRef(key='h', default=None, cast=None)"
    assert "0x" not in repr(EnvRef(key="k", cast=lambda s: s))


# --- end to end, both authoring routes --------------------------------------------------------------

_MODULE = """
from messagefoundry import Database, Rest, env, outbound
outbound("OB_REST", Rest(url="https://partner.example.org/in",
                         tls_allow_expired=env("rest_allow_expired")))
outbound("OB_DB", Database(server="db.example.org", database="d", statement="SELECT 1",
                           trust_server_certificate=env("db_trust", cast=str)))
"""

_TOML = """
[[outbound]]
name = "OB_SYNTH_REST"
transport = "rest"
  [outbound.settings]
  url = "https://partner.example.org/in"
  tls_allow_expired = { env = "rest_allow_expired" }
"""


def _dest(reg: Any, name: str, values: dict[str, Any]) -> dict[str, Any]:
    settings: dict[str, Any] = _dest_config(
        reg.outbound[name], values, None, EgressSettings(deny_by_default=False)
    ).settings
    return settings


@pytest.mark.parametrize("spelling", ["false", "off"])
def test_code_first_uncast_false_turns_the_flags_off_end_to_end(
    tmp_path: Path, spelling: str
) -> None:
    (tmp_path / "cfg.py").write_text(textwrap.dedent(_MODULE), encoding="utf-8")
    reg = load_config(tmp_path)
    values = {"rest_allow_expired": spelling, "db_trust": spelling}
    assert _dest(reg, "OB_REST", values)["tls_allow_expired"] is False
    assert _dest(reg, "OB_DB", values)["trust_server_certificate"] is False


@pytest.mark.parametrize(("spelling", "want"), [("false", False), ("yes", True)])
def test_connections_toml_uncast_env_reads_strictly_end_to_end(
    tmp_path: Path, spelling: str, want: bool
) -> None:
    (tmp_path / "connections.toml").write_text(textwrap.dedent(_TOML), encoding="utf-8")
    reg = load_config(tmp_path, allow_empty=True)
    got = _dest(reg, "OB_SYNTH_REST", {"rest_allow_expired": spelling})
    assert got["tls_allow_expired"] is want


def test_connections_toml_uncast_unknown_spelling_is_refused_end_to_end(tmp_path: Path) -> None:
    (tmp_path / "connections.toml").write_text(textwrap.dedent(_TOML), encoding="utf-8")
    reg = load_config(tmp_path, allow_empty=True)
    with pytest.raises(WiringError) as ei:
        _dest(reg, "OB_SYNTH_REST", {"rest_allow_expired": "maybe"})
    msg = str(ei.value)
    assert "'tls_allow_expired'" in msg and "not a valid bool" in msg and "maybe" not in msg


# --- the composers' enabled flags (vault BACKLOG #3234 step 1, #3724 item 1) ------------------------
#
# A composer stores its flag under a key that is not its parameter's name, so the annotation scan
# alone never found ``smart_enabled``, ``oauth2_enabled`` or ``sign_enabled``. The SMART and OAuth2
# readers take the flag with plain bool(), so an uncast "false" left the token hop ON.

_COMPOSER_KEYS = tuple(_COMPOSER_BOOL_SETTINGS)

# The arguments each composer needs besides its bool flag. A new composer fails the census test
# below until it is listed here, and its flag in wiring._COMPOSER_BOOL_SETTINGS.
_COMPOSER_ARGS: dict[str, dict[str, Any]] = {
    "with_smart_backend": {"token_url": "https://t", "client_id": "c", "private_key": "k"},
    "with_oauth2_client_credentials": {
        "token_url": "https://t",
        "client_id": "c",
        "client_secret": "s",
    },
    "with_signing": {"private_key": "k"},
}


@pytest.mark.parametrize("cast", [None, str], ids=["uncast", "str"])
@pytest.mark.parametrize(("spelling", "want"), SPELLINGS)
def test_a_composer_enabled_flag_reads_strictly(spelling: str, want: bool, cast: Any) -> None:
    out = resolve_env_settings(
        {key: env(key, cast=cast) for key in _COMPOSER_KEYS},
        dict.fromkeys(_COMPOSER_KEYS, spelling),
    )
    assert all(out[key] is want for key in _COMPOSER_KEYS)


@pytest.mark.parametrize("key", _COMPOSER_KEYS)
def test_a_composer_flag_keeps_its_none_reading_and_refuses_an_unknown_spelling(key: str) -> None:
    # SMART and OAuth2: off, not the composer's default of on. Their readers' rule is that a falsy
    # flag is off, so a None that used to reach them as off must not now start a token hop. Signing
    # keeps the None, which OutboundSigning refuses, rather than silently stop signing.
    want = {"smart_enabled": False, "oauth2_enabled": False, "sign_enabled": None}[key]
    assert resolve_env_settings({key: env("k", default=None)}, {})[key] is want
    with pytest.raises(WiringError, match=f"setting '{key}' \\(env 'k'\\): value is not a valid"):
        resolve_env_settings({key: env("k")}, {"k": "maybe"})


def _names_bool(annotation: ast.expr | None) -> bool:
    """Whether an annotation is ``bool`` or a ``|`` union with ``bool`` as a member."""
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _names_bool(annotation.left) or _names_bool(annotation.right)
    return isinstance(annotation, ast.Name) and annotation.id == "bool"


def _composer_bool_params() -> set[tuple[str, str, str]]:
    """Every keyword parameter whose annotation names ``bool`` on a ``with_*`` function, sync or
    async, anywhere under ``messagefoundry/transports/``, read from the source so no composer is
    missed for not being imported: ``(module, composer, parameter)``."""
    import messagefoundry.transports as transports

    root = Path(transports.__file__).parent
    found: set[tuple[str, str, str]] = set()
    for path in sorted(root.rglob("*.py")):
        module = ".".join(
            ["messagefoundry", "transports", *path.relative_to(root).with_suffix("").parts]
        )
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
                "with_"
            ):
                found.update(
                    (module, node.name, arg.arg)
                    for arg in node.args.kwonlyargs
                    if _names_bool(arg.annotation)
                )
    return found


def test_every_composer_bool_parameter_writes_a_listed_key() -> None:
    # The census: a composer bool flag the strict read does not list would read "false" as True
    # again, silently. The key each flag writes is found by flipping it, so the table is checked
    # against what the composer does, not against a second copy of its key names.
    params = _composer_bool_params()
    assert params, "the census found no composer flag, so it is reading nothing"
    written: set[str] = set()
    for module, composer, param in params:
        fn = getattr(importlib.import_module(module), composer)
        default = inspect.signature(fn).parameters[param].default
        on = fn(Rest(url="https://partner.example.org/in"), **_COMPOSER_ARGS[composer])
        off = fn(
            Rest(url="https://partner.example.org/in"),
            **_COMPOSER_ARGS[composer],
            **{param: not default},
        )
        (key,) = [k for k in on.settings if on.settings[k] != off.settings.get(k)]
        written.add(key)
    assert written == set(_COMPOSER_BOOL_SETTINGS)
    assert {key: _bool_settings().defaults[key] for key in written} == _COMPOSER_BOOL_SETTINGS


_COMPOSER_MODULE = """
from messagefoundry import Rest, env, outbound
from messagefoundry.transports.http_auth import with_oauth2_client_credentials
from messagefoundry.transports.signing import with_signing
from messagefoundry.transports.smart import with_smart_backend
outbound("OB_SMART", with_smart_backend(Rest(url="https://partner.example.org/in"),
    token_url="https://auth.example.org/token", client_id="c", private_key="k",
    enabled=env("smart_on")))
outbound("OB_OAUTH", with_oauth2_client_credentials(Rest(url="https://partner.example.org/in"),
    token_url="https://auth.example.org/token", client_id="c", client_secret="s",
    enabled=env("oauth_on", cast=str)))
outbound("OB_SIGN", with_signing(Rest(url="https://partner.example.org/in"), private_key="k",
    enabled=env("sign_on")))
"""


@pytest.mark.parametrize(("spelling", "want"), [("false", False), ("off", False), ("yes", True)])
def test_code_first_composer_flags_turn_the_token_hops_off_end_to_end(
    tmp_path: Path, spelling: str, want: bool
) -> None:
    (tmp_path / "cfg.py").write_text(textwrap.dedent(_COMPOSER_MODULE), encoding="utf-8")
    reg = load_config(tmp_path)
    values = {"smart_on": spelling, "oauth_on": spelling, "sign_on": spelling}
    smart = _dest(reg, "OB_SMART", values)
    oauth = _dest(reg, "OB_OAUTH", values)
    assert smart["smart_enabled"] is want and smart_auth_configured(smart) is want
    assert oauth["oauth2_enabled"] is want and oauth2_auth_configured(oauth) is want
    assert _dest(reg, "OB_SIGN", values)["sign_enabled"] is want


# --- Ftp(tls=...), which the factory turns into the protocol (#3234 step 1, #3724 item 1) -----------


@pytest.mark.parametrize("cast", [None, str, bool], ids=["uncast", "str", "bool"])
@pytest.mark.parametrize(("spelling", "want"), SPELLINGS)
def test_an_env_ftp_tls_resolves_to_the_protocol_it_spells(
    spelling: str, want: bool, cast: Any
) -> None:
    # The ref used to be stored as it was, and `"ftps" if tls` read the ref object as True, so no
    # value, cast=bool included, could turn TLS off.
    spec = Ftp(host="ftp.example.org", remote_dir="/in", tls=env("ftp_tls", cast=cast))
    got = resolve_env_settings(spec.settings, {"ftp_tls": spelling})["protocol"]
    assert got == ("ftps" if want else "ftp")


@pytest.mark.parametrize("cast", [None, str, bool], ids=["uncast", "str", "bool"])
@pytest.mark.parametrize(
    ("default", "want"), [("false", "ftp"), ("on", "ftps"), (None, "ftps"), (True, "ftps")]
)
def test_an_env_ftp_tls_default_is_read_strictly(default: object, want: str, cast: Any) -> None:
    # A None default is FTPS, as every env() tls was before #3234 (_protocol_for_tls says why).
    spec = Ftp(host="ftp.example.org", remote_dir="/in", tls=env("t", default=default, cast=cast))
    assert resolve_env_settings(spec.settings, {})["protocol"] == want


def test_an_env_ftp_tls_whose_cast_returns_none_reads_ftps() -> None:
    def to_none(_raw: object) -> None:
        return None

    spec = Ftp(host="ftp.example.org", remote_dir="/in", tls=env("ftp_tls", cast=to_none))
    assert resolve_env_settings(spec.settings, {"ftp_tls": "anything"})["protocol"] == "ftps"


def test_a_ca_beside_an_env_ftp_tls_that_resolves_to_none_builds_as_ftps(tmp_path: Path) -> None:
    # The resolved-CA refusal reads the protocol, so a None read as plain ftp would refuse this hop.
    (tmp_path / "cfg.py").write_text(
        "from messagefoundry import Ftp, env, outbound\n"
        "outbound('OB_FTP', Ftp(host='ftp.example.org', remote_dir='/in', "
        "tls=env('ftp_tls', default=None), tls_ca_file='/ca.pem'))\n",
        encoding="utf-8",
    )
    reg = load_config(tmp_path)
    assert _dest(reg, "OB_FTP", {})["protocol"] == "ftps"


def test_an_env_ftp_tls_unknown_spelling_is_refused_value_withheld() -> None:
    planted = "-".join(["planted", "tls"])
    spec = Ftp(host="ftp.example.org", remote_dir="/in", tls=env("ftp_tls"))
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(spec.settings, {"ftp_tls": planted})
    msg = str(ei.value)
    assert "(env 'ftp_tls'): value is not a valid bool for tls" in msg
    assert planted not in msg
    with pytest.raises(WiringError, match="Ftp tls env 't': default= is not a boolean") as di:
        Ftp(host="ftp.example.org", remote_dir="/in", tls=env("t", default=planted))
    assert planted not in str(di.value)


def test_a_literal_ftp_tls_is_mapped_as_before() -> None:
    assert Ftp(host="h", remote_dir="/in", tls=True).settings["protocol"] == "ftps"
    assert Ftp(host="h", remote_dir="/in").settings["protocol"] == "ftp"


def test_the_derived_ftp_protocol_ref_has_a_stable_repr() -> None:
    ref = Ftp(host="h", remote_dir="/in", tls=env("T")).settings["protocol"]
    assert repr(ref) == "EnvRef(key='t', default=<unset>, cast=bool for tls)"


@pytest.mark.parametrize("cast", [None, str, bool], ids=["uncast", "str", "bool"])
def test_two_builds_of_one_env_ftp_tls_are_equal(cast: Any) -> None:
    # A reload decides whether a connection changed by comparing its prior spec with the new one.
    # A fresh closure per build compared unequal, so every reload read the connection as changed.
    # The control: a different key is a different spec.
    def build(key: str) -> Any:
        return Ftp(host="h", remote_dir="/in", tls=env(key, cast=cast))

    assert build("t") == build("t")
    assert build("t") != build("u")


_FTP_MODULE = """
from messagefoundry import Ftp, env, outbound
outbound("OB_FTP", Ftp(host="ftp.example.org", remote_dir="/in", tls=env("ftp_tls")))
"""

_FTP_TOML = """
[[outbound]]
name = "OB_SYNTH_FTP"
transport = "ftp"
  [outbound.settings]
  host = "ftp.example.org"
  remote_dir = "/in"
  tls = { env = "ftp_tls" }
"""


@pytest.mark.parametrize(
    ("filename", "body", "name"),
    [("cfg.py", _FTP_MODULE, "OB_FTP"), ("connections.toml", _FTP_TOML, "OB_SYNTH_FTP")],
    ids=["code-first", "connections.toml"],
)
@pytest.mark.parametrize(("spelling", "want"), [("false", "ftp"), ("0", "ftp"), ("on", "ftps")])
def test_ftp_tls_env_reads_strictly_end_to_end(
    tmp_path: Path, filename: str, body: str, name: str, spelling: str, want: str
) -> None:
    (tmp_path / filename).write_text(textwrap.dedent(body), encoding="utf-8")
    reg = load_config(tmp_path, allow_empty=True)
    assert _dest(reg, name, {"ftp_tls": spelling})["protocol"] == want


def test_a_pin_beside_a_ca_that_an_env_plain_ftp_never_reads_is_refused(tmp_path: Path) -> None:
    # Ftp() refuses a CA beside a literal tls=False. With an env() tls it cannot know, so the check
    # after resolution reads the resolved protocol. The control: the same graph with TLS on.
    (tmp_path / "cfg.py").write_text(
        "from messagefoundry import Ftp, env, outbound\n"
        "outbound('OB_FTP', Ftp(host='ftp.example.org', remote_dir='/in', tls=env('ftp_tls'), "
        f"tls_ca_file='/org/ca.pem', tls_ca_pin={'00' * 32!r}))\n",
        encoding="utf-8",
    )
    reg = load_config(tmp_path)
    with pytest.raises(ValueError, match="plain FTP \\(tls=False\\) builds no TLS context"):
        registry_anchor_specs(reg, {"ftp_tls": "false"})
    (spec,) = registry_anchor_specs(reg, {"ftp_tls": "true"})
    assert spec.label == "outbound:OB_FTP"


@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_a_ca_beside_an_env_plain_ftp_is_refused_once_resolved(
    tmp_path: Path, direction: str
) -> None:
    # Ftp(tls=False, tls_ca_file=...) is refused when built; with an env() tls the same CA, with no
    # pin, is refused when the connection's settings resolve, at start, check and dry run alike.
    # The control: TLS on builds.
    from messagefoundry.pipeline.wiring_runner import _source_config

    spec = (
        "Ftp(host='ftp.example.org', remote_dir='/in', tls=env('ftp_tls'), tls_ca_file='/ca.pem')"
    )
    if direction == "inbound":
        graph = f"inbound('X_FTP', {spec}, router='r')\n@router('r')\ndef r(msg):\n    return []\n"
    else:
        graph = f"outbound('X_FTP', {spec})\n"
    (tmp_path / "cfg.py").write_text(
        "from messagefoundry import Ftp, env, inbound, outbound, router\n" + graph,
        encoding="utf-8",
    )
    reg = load_config(tmp_path, allow_empty=True)

    def build(spelling: str) -> object:
        values = {"ftp_tls": spelling}
        if direction == "inbound":
            return _source_config(reg.inbound["X_FTP"], "127.0.0.1", values)
        return _dest(reg, "X_FTP", values)

    with pytest.raises(WiringError, match="Ftp tls_ca_file would never be read"):
        build("false")
    assert build("true") is not None


# --- the capture and no_ack checks, read on the resolved flag (#3724 item 2) ------------------------
#
# An EnvRef is truthy whatever it resolves to. So build_outbound_connection, which runs before any
# value is known, refused a graph whose flag resolved False, and passed a capture whose expect_reply
# resolved False. Each case below holds one flag behind env(): (factory, spec, the spelling that spec
# is refused on, what the refusal says). Both spellings are tried, because one carries the refusal
# the old read never made or the other carries the false refusal it did.

_OUTBOUND = "from messagefoundry import {factory}, env, outbound\noutbound('OB_X', {spec})\n"

_CAPTURE_CASES = [
    pytest.param(
        "MLLP",
        "MLLP(host='h.example.org', port=1, capture_response=True, no_ack=env('flag'))",
        "true",
        "no ACK to capture",
        id="mllp-no_ack-env",
    ),
    pytest.param(
        "MLLP",
        "MLLP(host='h.example.org', port=1, no_ack=True, capture_response=env('flag'))",
        "true",
        "no ACK to capture",
        id="mllp-capture-env",
    ),
    pytest.param(
        "MLLP",
        "MLLP(host='h.example.org', port=1, verify_ack_control_id=True, no_ack=env('flag'))",
        "true",
        "MSA-2 to match against the sent MSH-10",
        id="mllp-verify-no_ack-env",
    ),
    pytest.param(
        "Tcp",
        "Tcp(host='h.example.org', port=1, capture_response=True, expect_reply=env('flag'))",
        "false",
        "TCP capture_response=True requires expect_reply=True",
        id="tcp-expect_reply-env",
    ),
    pytest.param(
        "Tcp",
        "Tcp(host='h.example.org', port=1, capture_response=env('flag'))",
        "true",
        "TCP capture_response=True requires expect_reply=True",
        id="tcp-capture-env",
    ),
    pytest.param(
        "X12",
        "X12(host='h.example.org', port=1, capture_response=True, expect_reply=env('flag'))",
        "false",
        "X12 capture_response=True requires expect_reply=True",
        id="x12-expect_reply-env",
    ),
    pytest.param(
        "Database",
        "Database(server='db.example.org', database='d', statement='INSERT INTO t VALUES (1)', "
        "capture_response=env('flag'))",
        "true",
        "requires a RETURNING/OUTPUT clause",
        id="database-capture-env",
    ),
    pytest.param(
        "Database",
        "Database(server='db.example.org', database='d', statement='INSERT INTO t VALUES (1)', "
        "capture_out_params=env('flag'))",
        "true",
        "capture_out_params=True requires the statement to be a stored-procedure call",
        id="database-out-params-env",
    ),
]


def _outbound_graph(tmp_path: Path, factory: str, spec: str) -> Any:
    source = _OUTBOUND.format(factory=factory, spec=spec)
    (tmp_path / "cfg.py").write_text(source, encoding="utf-8")
    return load_config(tmp_path)


@pytest.mark.parametrize(("factory", "spec", "refused_on", "says"), _CAPTURE_CASES)
def test_a_capture_check_reads_the_flag_the_connector_will_read(
    tmp_path: Path, factory: str, spec: str, refused_on: str, says: str
) -> None:
    reg = _outbound_graph(tmp_path, factory, spec)  # loading decides nothing about an env() flag
    with pytest.raises(WiringError, match=says):
        _dest(reg, "OB_X", {"flag": refused_on})
    other = "false" if refused_on == "true" else "true"
    assert _dest(reg, "OB_X", {"flag": other}) is not None


def test_a_literal_conflict_is_still_refused_at_load(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="no ACK to capture"):
        _outbound_graph(
            tmp_path,
            "MLLP",
            "MLLP(host='h.example.org', port=1, no_ack=True, capture_response=True)",
        )


def test_a_batched_mllp_capture_reads_the_resolved_flag(tmp_path: Path) -> None:
    (tmp_path / "cfg.py").write_text(
        "from messagefoundry import MLLP, env, outbound\n"
        "from messagefoundry.config.models import BatchConfig\n"
        "outbound('OB_X', MLLP(host='h.example.org', port=1, capture_response=env('flag')), "
        "batch=BatchConfig(max_count=2, max_wait_ms=100))\n",
        encoding="utf-8",
    )
    reg = load_config(tmp_path)
    with pytest.raises(
        WiringError, match="batch aggregation is incompatible with capture_response"
    ):
        _dest(reg, "OB_X", {"flag": "true"})
    assert _dest(reg, "OB_X", {"flag": "false"}) is not None


def test_an_env_out_params_flag_that_resolves_false_does_not_force_capture(tmp_path: Path) -> None:
    # The build used to write a literal capture_response=True for any truthy flag, ref included, and
    # a literal has nothing left to resolve. The control: a literal flag still forces it.
    reg = _outbound_graph(
        tmp_path,
        "Database",
        "Database(server='db.example.org', database='d', statement='EXEC p', "
        "capture_out_params=env('flag'))",
    )
    off = _dest(reg, "OB_X", {"flag": "false"})
    assert off["capture_response"] is False and off["capture_out_params"] is False
    forced = Database(server="s", database="d", statement="EXEC p", capture_out_params=True)
    assert build_outbound_connection("OB_Y", forced).spec.settings["capture_response"] is True


@pytest.mark.parametrize(
    ("spec", "key"),
    [
        (Rest(url="https://partner.example.org/in"), "capture_response"),
        (
            Database(server="db.example.org", database="d", statement="EXEC p"),
            "capture_out_params",
        ),
    ],
    ids=["capture_response", "capture_out_params"],
)
def test_a_reply_from_target_is_read_by_its_resolved_flag(spec: Any, key: str) -> None:
    # An EnvRef was truthy here, so an outbound that captures nothing passed, and every HTTP call
    # would have blocked until reply_timeout. The control: the flag resolving True.
    settings = {**spec.settings, key: env("flag")}
    registry = wiring.Registry()
    registry.outbound["OB_X"] = build_outbound_connection(
        "OB_X", dataclasses.replace(spec, settings=settings)
    )
    listener = Http(port=0, reply_from="OB_X", reply_content_type="application/json")
    inbound = build_inbound_connection("IB_X", listener, router="r")
    with pytest.raises(WiringError, match="does not set capture_response=True"):
        check_http_sync_reply(inbound, registry, env_values={"flag": "false"})
    check_http_sync_reply(inbound, registry, env_values={"flag": "true"})


def test_a_set_capture_response_stays_beside_an_env_out_params_flag(tmp_path: Path) -> None:
    # Capture is on either way, so which statement rule applies follows the flag. The connector ORs
    # the two, so the proc-call rule applies only when the flag resolves True.
    reg = _outbound_graph(
        tmp_path,
        "Database",
        "Database(server='db.example.org', database='d', "
        "statement='INSERT INTO t OUTPUT INSERTED.id VALUES (1)', capture_response=True, "
        "capture_out_params=env('flag'))",
    )
    assert _dest(reg, "OB_X", {"flag": "false"})["capture_response"] is True
    with pytest.raises(WiringError, match="requires the statement to be a stored-procedure call"):
        _dest(reg, "OB_X", {"flag": "true"})


_CAPTURE_TOML = """
[[outbound]]
name = "OB_SYNTH_TCP"
transport = "tcp"
  [outbound.settings]
  host = "h.example.org"
  port = 1
  framing = "stx_etx"
  capture_response = true
  expect_reply = { env = "flag" }
"""


def test_connections_toml_reads_an_env_expect_reply_once_resolved(tmp_path: Path) -> None:
    (tmp_path / "connections.toml").write_text(textwrap.dedent(_CAPTURE_TOML), encoding="utf-8")
    reg = load_config(tmp_path, allow_empty=True)
    with pytest.raises(WiringError, match="requires expect_reply=True"):
        _dest(reg, "OB_SYNTH_TCP", {"flag": "false"})
    assert _dest(reg, "OB_SYNTH_TCP", {"flag": "true"}) is not None


def test_the_build_check_refuses_a_capture_with_no_reply_once_resolved(tmp_path: Path) -> None:
    # `messagefoundry check` reaches the second pass through build_check_registry.
    reg = _outbound_graph(
        tmp_path,
        "Tcp",
        "Tcp(host='h.example.org', port=1, capture_response=True, expect_reply=env('flag'))",
    )

    def check(spelling: str) -> None:
        build_check_registry(
            reg,
            inbound_bind_host="127.0.0.1",
            env_values={"flag": spelling},
            egress=EgressSettings(deny_by_default=False),
        )

    with pytest.raises(WiringError, match="requires expect_reply=True"):
        check("false")
    check("true")


# --- the factories the bool scan must find (#3724 item 3) -------------------------------------------


def _settings_spec_classes() -> set[str]:
    """Every dataclass in ``wiring`` that carries a ``settings`` mapping."""
    return {
        name
        for name, obj in vars(wiring).items()
        if dataclasses.is_dataclass(obj)
        and isinstance(obj, type)
        and obj.__module__ == wiring.__name__
        and "settings" in {field.name for field in dataclasses.fields(obj)}
    }


def _functions_building_a_settings_spec() -> set[str]:
    """Every module-level function under ``messagefoundry/`` that constructs one of those classes,
    read from the source, so a factory is found by what it builds and not by the annotation the scan
    keys on. Only a file that names a class is parsed."""
    specs = _settings_spec_classes()
    root = Path(wiring.__file__).parents[1]
    found: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if not any(f"{spec}(" in source for spec in specs):
            continue
        for node in parse_source(source).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and calls_to(
                node, specs, bare_only=True
            ):
                found.add(node.name)
    return found


def test_the_bool_scan_reads_every_function_that_builds_a_settings_spec() -> None:
    # The scan finds a factory by its return annotation, and a factory that scan misses reads its
    # flags as text again, with nothing reporting it. Reading the source instead finds a factory
    # with a new return annotation, one in another module, and a new spec class. The controls: the
    # census sees all four spec classes in use, a registering factory and a returning one.
    census = _functions_building_a_settings_spec()
    assert _settings_spec_classes() == {
        "ConnectionSpec",
        "DatabaseLookupSpec",
        "FhirLookupSpec",
        "ReferenceSourceSpec",
    }
    assert {"MLLP", "DatabaseLookup", "FhirLookup", "FileRef"} <= census
    assert _bool_settings().factories == census


def test_the_bool_scan_reads_every_connections_toml_transport() -> None:
    from messagefoundry.config.connections_file import _TRANSPORTS

    assert {factory.__name__ for factory in _TRANSPORTS.values()} <= _bool_settings().factories
