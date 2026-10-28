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
import importlib
import inspect
import textwrap
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.trust_anchors import registry_anchor_specs
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    _COMPOSER_BOOL_SETTINGS,
    EnvRef,
    Ftp,
    Rest,
    WiringError,
    _bool_settings,
    env,
    load_config,
    resolve_env_settings,
)
from messagefoundry.pipeline.wiring_runner import _dest_config
from messagefoundry.transports.http_auth import oauth2_auth_configured
from messagefoundry.transports.smart import smart_auth_configured

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
