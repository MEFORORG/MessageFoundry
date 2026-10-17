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

import textwrap
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    EnvRef,
    WiringError,
    _bool_settings,
    env,
    load_config,
    resolve_env_settings,
)
from messagefoundry.pipeline.wiring_runner import _dest_config

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
