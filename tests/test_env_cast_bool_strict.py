# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``env(key, cast=bool)`` reads a boolean strictly (vault BACKLOG #3138).

``env()`` used to store the builtin ``bool`` as its cast, and ``resolve_env_settings`` called it on the
raw value. Every ``MEFOR_VALUE_*`` variable is text, and ``bool("false")`` is True, so an operator who
wrote ``false`` would have got the insecure side of a code-first boolean setting, silently. Two
examples are ``tls_allow_expired`` and ``trust_server_certificate``; at least the Rest, FHIR, SOAP,
MLLP, DICOM and Ftp factories take the first, and the Database family the second.
``cast=bool`` now means the same strict spelling cast ``connections.toml``'s ``cast = "bool"`` uses.

The FALSE spellings are the half that carries the guard: the builtin ``bool`` reads every TRUE
spelling as True too, so those assertions pass on the old code and only pin that the fix kept them."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.environments import load_environment_values
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    EnvRef,
    WiringError,
    env,
    load_config,
    resolve_env_settings,
)
from messagefoundry.pipeline.wiring_runner import _dest_config

FALSE_SPELLINGS = ["false", "0", "no", "off", "False", "OFF", " false "]
TRUE_SPELLINGS = ["true", "1", "yes", "on", "TRUE", "On", " yes "]


@pytest.mark.parametrize("spelling", FALSE_SPELLINGS)
def test_env_cast_bool_reads_each_false_spelling_as_false(spelling: str) -> None:
    out = resolve_env_settings({"flag": env("flag", cast=bool)}, {"flag": spelling})
    assert out["flag"] is False


@pytest.mark.parametrize("spelling", TRUE_SPELLINGS)
def test_env_cast_bool_reads_each_true_spelling_as_true(spelling: str) -> None:
    out = resolve_env_settings({"flag": env("flag", cast=bool)}, {"flag": spelling})
    assert out["flag"] is True  # `is`: `1 == True`, so equality would not pin the type


@pytest.mark.parametrize(("raw", "want"), [(True, True), (False, False), (1, True), (0, False)])
def test_env_cast_bool_passes_a_typed_toml_value_through(raw: object, want: bool) -> None:
    # environments/<env>.toml is TOML, so `flag = false` arrives as a real bool. That route already
    # worked under the builtin and must not regress.
    assert resolve_env_settings({"flag": env("flag", cast=bool)}, {"flag": raw})["flag"] is want


@pytest.mark.parametrize("raw", ["maybe", "", "2", "y", 2, 1.5])
def test_env_cast_bool_refuses_an_unknown_spelling_naming_the_setting_and_key(raw: object) -> None:
    # The builtin read "maybe" and "2" as True and "" as False; none of them has an honest reading.
    with pytest.raises(WiringError) as ei:
        resolve_env_settings(
            {"tls_allow_expired": env("acme_expired", cast=bool)}, {"acme_expired": raw}
        )
    msg = str(ei.value)
    assert "'tls_allow_expired'" in msg and "'acme_expired'" in msg
    assert "not a valid bool" in msg and "value withheld" in msg


def test_env_cast_bool_refusal_never_names_the_value() -> None:
    secret = "s3cr3t-not-a-bool"
    with pytest.raises(WiringError) as ei:
        resolve_env_settings({"flag": env("flag", cast=bool)}, {"flag": secret})
    assert secret not in str(ei.value)


def test_an_env_ref_built_directly_with_the_builtin_bool_is_held_to_the_same_reading() -> None:
    ref = EnvRef(key="flag", cast=bool)
    assert ref.cast is not bool
    assert resolve_env_settings({"flag": ref}, {"flag": "off"})["flag"] is False


def test_a_cast_other_than_the_builtin_bool_is_left_alone() -> None:
    assert env("port", cast=int).cast is int
    assert env("host").cast is None


@pytest.mark.parametrize(
    ("default", "want"),
    [("false", False), ("off", False), (False, False), (0, False), ("true", True), (True, True)],
)
def test_a_cast_bool_default_is_read_strictly(default: object, want: bool) -> None:
    # A default is not cast at resolve time, so "false" used to reach the connector as text and read
    # True there. It is read once, when the reference is made.
    out = resolve_env_settings({"flag": env("flag", default=default, cast=bool)}, {})
    assert out["flag"] is want


def test_a_cast_bool_default_of_none_stays_none() -> None:
    assert resolve_env_settings({"flag": env("flag", default=None, cast=bool)}, {})["flag"] is None


@pytest.mark.parametrize("default", ["maybe", "", 2])
def test_an_unreadable_cast_bool_default_is_refused_naming_the_key(default: object) -> None:
    with pytest.raises(WiringError) as ei:
        env("acme_flag", default=default, cast=bool)
    msg = str(ei.value)
    assert "'acme_flag'" in msg and "default=" in msg and "value withheld" in msg
    assert "maybe" not in msg


# --- end to end: a code-first module, the instance's values, the outbound build choke point ---------

_MODULE = """
from messagefoundry import Database, Rest, env, outbound
outbound("OB_REST", Rest(url="https://partner.example.org/in",
                         tls_allow_expired=env("rest_allow_expired", cast=bool)))
outbound("OB_DB", Database(server="db.example.org", database="d", statement="SELECT 1",
                           trust_server_certificate=env("db_trust", cast=bool)))
"""


def _settings_for(
    tmp_path: Path, *, toml: str = "", environ: dict[str, str] | None = None
) -> tuple[dict[str, object], dict[str, object]]:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "cfg.py").write_text(textwrap.dedent(_MODULE), encoding="utf-8")
    envdir = tmp_path / "environments"
    envdir.mkdir()
    (envdir / "prod.toml").write_text(textwrap.dedent(toml), encoding="utf-8")
    values = load_environment_values(
        base_dir=tmp_path, dir_name="environments", environment="prod", environ=environ or {}
    )
    reg = load_config(cfg)
    egress = EgressSettings(deny_by_default=False)
    rest = _dest_config(reg.outbound["OB_REST"], values, None, egress).settings
    db = _dest_config(reg.outbound["OB_DB"], values, None, egress).settings
    return rest, db


@pytest.mark.parametrize("spelling", ["false", "0", "no", "off"])
def test_mefor_value_false_turns_both_tls_flags_off_end_to_end(
    tmp_path: Path, spelling: str
) -> None:
    rest, db = _settings_for(
        tmp_path,
        environ={"MEFOR_VALUE_REST_ALLOW_EXPIRED": spelling, "MEFOR_VALUE_DB_TRUST": spelling},
    )
    assert rest["tls_allow_expired"] is False
    assert db["trust_server_certificate"] is False


@pytest.mark.parametrize("spelling", ["true", "1", "yes", "on"])
def test_mefor_value_true_turns_both_tls_flags_on_end_to_end(tmp_path: Path, spelling: str) -> None:
    rest, db = _settings_for(
        tmp_path,
        environ={"MEFOR_VALUE_REST_ALLOW_EXPIRED": spelling, "MEFOR_VALUE_DB_TRUST": spelling},
    )
    assert rest["tls_allow_expired"] is True
    assert db["trust_server_certificate"] is True


def test_a_toml_boolean_still_resolves_end_to_end(tmp_path: Path) -> None:
    # The route that already worked: a real TOML boolean from environments/<env>.toml.
    rest, db = _settings_for(tmp_path, toml="rest_allow_expired = false\ndb_trust = true\n")
    assert rest["tls_allow_expired"] is False
    assert db["trust_server_certificate"] is True


def test_an_unknown_spelling_is_refused_end_to_end_naming_the_key(tmp_path: Path) -> None:
    with pytest.raises(WiringError) as ei:
        _settings_for(
            tmp_path,
            environ={"MEFOR_VALUE_REST_ALLOW_EXPIRED": "maybe", "MEFOR_VALUE_DB_TRUST": "false"},
        )
    msg = str(ei.value)
    assert "'tls_allow_expired'" in msg and "'rest_allow_expired'" in msg
    assert "maybe" not in msg


# --- a verify_tls that RESOLVES false meets the refusals its literal form meets at the factory ------
# The factories test the literal; an env() reference is truthy there, so they pass it. Now that "false"
# reads False, the resolved value can be the one they refuse.

_VERIFY_MODULE = """
from messagefoundry import DICOMweb, Soap, env, outbound
outbound("OB_DW", DICOMweb(url="https://pacs.example.org/dw", tls_ca_file="ca.pem",
                           verify_tls=env("dw_verify", cast=bool)))
outbound("OB_SOAP", Soap(url="https://ws.example.org/ws", client_cert_file="c.pem",
                         client_key_file="k.pem", verify_tls=env("soap_verify", cast=bool)))
"""


def _verify_dest(tmp_path: Path, name: str, values: dict[str, str]) -> Any:
    (tmp_path / "cfg.py").write_text(textwrap.dedent(_VERIFY_MODULE), encoding="utf-8")
    reg = load_config(tmp_path)
    return _dest_config(reg.outbound[name], values, None, EgressSettings(deny_by_default=False))


@pytest.mark.parametrize(
    ("name", "needle"),
    [("OB_DW", "tls_ca_file would never be read"), ("OB_SOAP", "client cert is incompatible")],
)
def test_a_verify_tls_that_resolves_false_is_refused(
    tmp_path: Path, name: str, needle: str
) -> None:
    with pytest.raises(WiringError, match=needle):
        _verify_dest(tmp_path, name, {"dw_verify": "false", "soap_verify": "false"})


@pytest.mark.parametrize("name", ["OB_DW", "OB_SOAP"])
def test_a_verify_tls_that_resolves_true_builds(tmp_path: Path, name: str) -> None:
    dest = _verify_dest(tmp_path, name, {"dw_verify": "true", "soap_verify": "true"})
    assert dest.settings["verify_tls"] is True
