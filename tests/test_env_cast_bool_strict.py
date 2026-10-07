# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``env(key, cast=bool)`` reads a boolean strictly (vault BACKLOG #3138).

``env()`` used to store the builtin ``bool`` as its cast, and ``resolve_env_settings`` called it on the
raw value. Every ``MEFOR_VALUE_*`` variable is text, and ``bool("false")`` is True, so an operator who
wrote ``false`` would have got the insecure side of a code-first boolean setting, silently:
``tls_allow_expired`` on a Rest, FHIR or SOAP hop, ``trust_server_certificate`` on a Database hop.
``cast=bool`` now means the same strict spelling cast ``connections.toml``'s ``cast = "bool"`` uses.

The FALSE spellings are the half that carries the guard: the builtin ``bool`` reads every TRUE
spelling as True too, so those assertions pass on the old code and only pin that the fix kept them."""

from __future__ import annotations

import textwrap
from pathlib import Path

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
