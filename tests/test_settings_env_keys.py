# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An unknown ``MEFOR_<SECTION>_<KEY>`` variable under a section with an env layer refuses the load
(vault BACKLOG #2600).

Three groups. The refusal itself, with the names it must spare as controls. A census of the
``MEFOR_*`` names the engine's own code spells, so a variable a module starts reading is either a
settings field or on the spared list. And a census of the names the shipped deployment files set.

Each census reads names that are SPELLED OUT. A name built at run time from pieces is outside both,
and nothing here would see it."""

from __future__ import annotations

import ast
import functools
import logging
import re
from pathlib import Path

import pytest

from messagefoundry.config import settings as settings_module
from messagefoundry.config.settings import (
    _OUT_OF_BAND_ENV,
    _reject_unknown_env_keys,
    load_settings,
)

_REPO = Path(__file__).resolve().parents[1]
_NAME = re.compile(r"MEFOR_[A-Z0-9_]*[A-Z0-9]")
#: A value no message may repeat. Synthetic.
_SENTINEL = "SYNTHETIC-VALUE-9f3c"


def _load(environ: dict[str, str]) -> object:
    return load_settings(environ=environ, default_file=False)


def _refusal(environ: dict[str, str]) -> str:
    with pytest.raises(ValueError, match="unrecognized environment variable") as caught:
        _load(environ)
    return str(caught.value)


# --- the refusal ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "MEFOR_STORE_REQUIRE_ENCRYPTON",  # a hardening, mistyped
        "MEFOR_AUTH_AD_BIND_PASSWROD",  # a secret, mistyped
        "MEFOR_EGRESS_ALLOWED",  # a prefix of real keys, not a key
        "MEFOR_CLUSTER_VIP_ENABLED",  # a sub-table key; the environment cannot set one
        "MEFOR_SANDBOX_MODEE",
    ],
)
def test_an_unknown_key_under_a_known_section_refuses_the_load(name: str) -> None:
    message = _refusal({name: _SENTINEL})
    assert name in message
    assert _SENTINEL not in message


def test_the_refusal_names_the_nearest_real_variable() -> None:
    message = _refusal({"MEFOR_STORE_REQUIRE_ENCRYPTON": "true"})
    assert "did you mean MEFOR_STORE_REQUIRE_ENCRYPTION?" in message
    message = _refusal({"MEFOR_STORE_VAULT_ADRR": "https://vault.example.org"})
    assert "did you mean MEFOR_STORE_VAULT_ADDR?" in message


def test_the_hint_is_matched_on_the_key_and_not_on_the_shared_prefix() -> None:
    """Every name in a section shares ``MEFOR_<SECTION>_``. A hint matched on the whole name
    offered ``MEFOR_STORE_PORT`` for the first of these. The second is the control."""
    assert "did you mean" not in _refusal({"MEFOR_STORE_ZZZZ": "1"})
    assert "did you mean MEFOR_STORE_PORT?" in _refusal({"MEFOR_STORE_PORTT": "1"})


def test_the_hint_never_offers_a_key_the_loader_refuses() -> None:
    """``[store].allow_unencrypted_phi`` moved to ``[security]``, so offering it would send the
    operator from one refusal into another."""
    message = _refusal({"MEFOR_STORE_ALLOW_UNENCRYPTED_PH": "true"})
    assert "MEFOR_STORE_ALLOW_UNENCRYPTED_PHI" not in message


def test_every_offender_is_named_in_one_refusal() -> None:
    message = _refusal(
        {"MEFOR_STORE_PATHH": "a", "MEFOR_API_PORTT": "1", "MEFOR_STORE_PATH": "ok.db"}
    )
    assert "MEFOR_STORE_PATHH" in message and "MEFOR_API_PORTT" in message


def test_a_typo_that_causes_a_validation_error_is_the_one_reported() -> None:
    """The check runs before the model is built. Otherwise the operator would see only "enabled
    requires a destination", and the mistyped variable that caused it would never be named."""
    message = _refusal({"MEFOR_BACKUP_ENABLED": "true", "MEFOR_BACKUP_DESTINATON": "D:/b"})
    assert "MEFOR_BACKUP_DESTINATON" in message
    assert "did you mean MEFOR_BACKUP_DESTINATION?" in message


def test_a_real_field_still_loads_from_the_environment() -> None:
    """The control for the refusal: the correct spelling of the first case above is applied."""
    loaded = load_settings(environ={"MEFOR_STORE_REQUIRE_ENCRYPTION": "true"}, default_file=False)
    assert loaded.store.require_encryption is True


def test_every_spared_name_loads() -> None:
    _load(dict.fromkeys(_OUT_OF_BAND_ENV, "1"))


def test_a_spared_name_is_spared_only_as_spelled() -> None:
    """On POSIX the modules read these names exactly, so another letter case is a variable nobody
    reads. It is refused, not spared."""
    with pytest.raises(ValueError, match="MEFOR_store_vault_addr"):
        _reject_unknown_env_keys({"MEFOR_store_vault_addr": "x"}, {})


@pytest.mark.parametrize(
    "name",
    [
        "MEFOR_ALLOW_INSECURE_TLS",  # a documented process-wide variable; "allow" is no section
        "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE",
        "MEFOR_CONNSCALE_COUNT",  # a harness variable
        "MEFOR_STOER_PATH",  # a typo in the SECTION: still dropped, and nothing said
        "MEFOR_SERVICE_NAME",  # [service] has no env layer, so nothing here reads it
        "MEFOR_CERT_MONITOR_ENABLED",  # splits to section "cert", which is not one
        "MEFOR_STORE",  # no key part
        "PATH",
    ],
)
def test_a_name_outside_every_section_with_an_env_layer_is_not_refused(name: str) -> None:
    """The stated limit: only a name whose section the env layer reads is checked."""
    _reject_unknown_env_keys({name: "x"}, {})


def test_a_security_typo_keeps_its_own_refusal() -> None:
    with pytest.raises(ValueError, match=r"\[security\]\.block_unlisted_outboud"):
        _load({"MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUD": "true"})


def test_a_relocated_and_a_removed_key_keep_their_own_messages() -> None:
    with pytest.raises(ValueError, match=r"moved to \[security\]"):
        _load({"MEFOR_EGRESS_DENY_BY_DEFAULT": "true"})
    with pytest.raises(ValueError, match="was REMOVED"):
        _load({"MEFOR_PIPELINE_REQUIRE_RCSI_FOR_POOLED": "false"})


def test_a_renamed_logging_key_keeps_the_message_that_names_its_replacement() -> None:
    with pytest.raises(ValueError, match="file_backup_count"):
        _load({"MEFOR_LOGGING_BACKUPS": "3"})


# --- operator-named secret variables ---------------------------------------------------------------

_SECRET_VAR = "MEFOR_ALERTS_SMTP_PASSWORD"


def test_a_variable_a_setting_names_as_a_secret_reference_is_spared() -> None:
    """``[secrets].provider = "env"`` reads a reference as an environment variable name the
    operator chooses. One that a setting names is in use, not a typo."""
    environ = {
        "MEFOR_SECRETS_PROVIDER": "env",
        "MEFOR_ALERTS_EMAIL_PASSWORD_SECRET": _SECRET_VAR,
        _SECRET_VAR: _SENTINEL,
    }
    loaded = load_settings(environ=environ, default_file=False)
    assert loaded.alerts.email_password_secret == _SECRET_VAR


def test_under_the_env_provider_an_unnamed_variable_is_warned_and_not_refused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A connection can carry a reference no setting names, and the loader cannot see the graph.
    So under that provider the unknown variable is named in a WARNING and the load continues."""
    environ = {"MEFOR_SECRETS_PROVIDER": "env", _SECRET_VAR: _SENTINEL}
    with caplog.at_level(logging.WARNING, logger=settings_module.__name__):
        _load(environ)
    warned = [r.getMessage() for r in caplog.records if _SECRET_VAR in r.getMessage()]
    assert len(warned) == 1
    assert _SENTINEL not in warned[0]


def test_without_the_env_provider_the_same_variable_is_refused() -> None:
    """The control for the two tests above: the shipped provider is ``none``."""
    assert _SECRET_VAR in _refusal({_SECRET_VAR: _SENTINEL})
    assert _SECRET_VAR in _refusal({"MEFOR_SECRETS_PROVIDER": "none", _SECRET_VAR: _SENTINEL})


# --- the census of names the engine's own code spells ----------------------------------------------

#: The trees whose Python is engine or operator-run code. ``tests/`` is left out on purpose: it
#: spells mistyped names to test this refusal.
_CODE_TREES = (
    "messagefoundry",
    "messagefoundry_webconsole",
    "messagefoundry_toolkit",
    "packaging",
    "harness",
    "scripts",
    "samples",
    "tee",
)
_SETTINGS_MODULE = "messagefoundry/config/settings.py"


@functools.cache
def _spelled_names(tree: str) -> dict[str, frozenset[str]]:
    """Every string constant under ``tree`` that is, whole, a ``MEFOR_*`` name -> the files."""
    found: dict[str, set[str]] = {}
    for path in sorted((_REPO / tree).rglob("*.py")):
        if ".venv" in path.parts or "node_modules" in path.parts:
            continue
        try:
            module = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(module):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and _NAME.fullmatch(node.value)
            ):
                found.setdefault(node.value, set()).add(path.relative_to(_REPO).as_posix())
    return {name: frozenset(files) for name, files in found.items()}


def _is_checked_and_unknown(name: str) -> bool:
    """Would :func:`_reject_unknown_env_keys` refuse ``name``?"""
    try:
        _reject_unknown_env_keys({name: "x"}, {})
    except ValueError:
        return True
    return False


def _moved_or_removed() -> set[str]:
    gone = {*settings_module._REMOVED_KEYS, *settings_module._RELOCATED_TO_SECURITY}
    return {f"MEFOR_{section}_{key}".upper() for section, key in gone}


def test_no_engine_code_spells_a_variable_the_loader_would_refuse() -> None:
    """A module that starts reading ``MEFOR_<known section>_<NEW>`` straight from the environment
    reds this until the name is a settings field or joins ``_OUT_OF_BAND_ENV``. Otherwise the
    documented way to set it would stop the engine from starting."""
    spelled: dict[str, set[str]] = {}
    for tree in _CODE_TREES:
        assert (_REPO / tree).is_dir(), tree
        for name, files in _spelled_names(tree).items():
            spelled.setdefault(name, set()).update(files)
    # The scanner must be seeing names at all, or an empty offender list means nothing.
    assert len(spelled) >= 20
    assert "MEFOR_STORE_VAULT_ADDR" in spelled
    assert "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE" in spelled
    offenders = {
        name: sorted(files)
        for name, files in spelled.items()
        if name not in _moved_or_removed() and _is_checked_and_unknown(name)
    }
    assert offenders == {}, (
        f"engine code names MEFOR_ variable(s) the settings loader would refuse: {offenders}. "
        "Make each a settings field, or add it to _OUT_OF_BAND_ENV in config/settings.py."
    )


def test_the_census_fires_on_a_made_up_name() -> None:
    """The control for the test above: a name no section defines is one it would report."""
    assert _is_checked_and_unknown("MEFOR_STORE_MADE_UP_KNOB")
    assert not _is_checked_and_unknown("MEFOR_STORE_PATH")


def _spelled_outside_the_settings_module() -> set[str]:
    return {
        name
        for name, files in _spelled_names("messagefoundry").items()
        if files - {_SETTINGS_MODULE}
    }


def test_every_spared_name_is_spelled_by_an_engine_module_other_than_settings() -> None:
    """A stale entry would spare a variable nothing reads, which is the silent drop again. The
    settings module is left out of the scan: it holds the list, so it spells every entry."""
    spelled = _spelled_outside_the_settings_module()
    assert len(spelled) >= 20
    assert sorted(_OUT_OF_BAND_ENV - spelled) == []


def test_the_stale_entry_scan_does_not_count_the_list_itself() -> None:
    """Why the scan above leaves the settings module out: every entry is spelled there, so a
    scan that counted that file could never find one stale."""
    in_settings = {
        name
        for name, files in _spelled_names("messagefoundry").items()
        if _SETTINGS_MODULE in files
    }
    assert in_settings >= _OUT_OF_BAND_ENV


def test_no_spared_name_is_also_a_settings_field() -> None:
    models = settings_module._section_models()
    for name in _OUT_OF_BAND_ENV:
        section, _, key = name[len("MEFOR_") :].lower().partition("_")
        assert section in settings_module._SECTIONS, name
        assert key not in models[section].model_fields, name


# --- the census of names the shipped deployment files set ------------------------------------------

_DEPLOY_GLOBS = (
    "docker/**/*",
    ".github/workflows/*.yml",
    "environments/*",
    "scripts/**/*.ps1",
    "scripts/**/*.sh",
)
#: A name followed by ``*`` or ``_*`` is a documented family (``MEFOR_EGRESS_ALLOWED_*``), not a name.
_FAMILY = re.compile(r"_?\*")


def _deployment_names() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for pattern in _DEPLOY_GLOBS:
        for path in sorted(_REPO.glob(pattern)):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for match in _NAME.finditer(text):
                if _FAMILY.match(text, match.end()):
                    continue
                found.setdefault(match.group(0), set()).add(path.relative_to(_REPO).as_posix())
    return found


def test_no_shipped_deployment_file_names_a_variable_the_loader_would_refuse() -> None:
    """The compose file, the Kubernetes manifests, the workflows and the service scripts set
    settings by environment. Every name they spell, in a value or in a comment, must load."""
    names = _deployment_names()
    assert len(names) >= 10
    assert "MEFOR_STORE_REQUIRE_ENCRYPTION" in names  # docker/compose.yaml sets it
    offenders = {
        name: sorted(files)
        for name, files in names.items()
        if name not in _moved_or_removed() and _is_checked_and_unknown(name)
    }
    assert offenders == {}, f"a shipped file names a variable the loader would refuse: {offenders}"
