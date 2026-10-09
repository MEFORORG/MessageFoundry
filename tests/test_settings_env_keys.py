# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An unknown ``MEFOR_<SECTION>_<KEY>`` variable under a modelled section refuses the load (vault
BACKLOG #2600).

Three groups. The refusal itself, with the names it must spare as controls. A census of the
``MEFOR_*`` names the engine's own code spells, so a variable a module starts reading is either a
settings field or on the spared list. And a census of the names the shipped deployment files set.

Each census reads names that are SPELLED OUT. A name built at run time from pieces is outside both,
and nothing here would see it."""

from __future__ import annotations

import ast
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
    with pytest.raises(ValueError, match="unrecognized environment variable") as caught:
        _load({name: _SENTINEL})
    message = str(caught.value)
    assert name in message
    assert _SENTINEL not in message


def test_the_refusal_names_the_nearest_real_variable() -> None:
    with pytest.raises(ValueError) as caught:
        _load({"MEFOR_STORE_REQUIRE_ENCRYPTON": "true"})
    assert "did you mean MEFOR_STORE_REQUIRE_ENCRYPTION?" in str(caught.value)
    with pytest.raises(ValueError) as caught:
        _load({"MEFOR_STORE_VAULT_ADRR": "https://vault.example.org"})
    assert "did you mean MEFOR_STORE_VAULT_ADDR?" in str(caught.value)


def test_every_offender_is_named_in_one_refusal() -> None:
    with pytest.raises(ValueError) as caught:
        _load({"MEFOR_STORE_PATHH": "a", "MEFOR_API_PORTT": "1", "MEFOR_STORE_PATH": "ok.db"})
    message = str(caught.value)
    assert "MEFOR_STORE_PATHH" in message and "MEFOR_API_PORTT" in message


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
        _reject_unknown_env_keys({"MEFOR_store_vault_addr": "x"})


@pytest.mark.parametrize(
    "name",
    [
        "MEFOR_ALLOW_INSECURE_TLS",  # a documented process-wide variable; "allow" is no section
        "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE",
        "MEFOR_CONNSCALE_COUNT",  # a harness variable
        "MEFOR_STOER_PATH",  # a typo in the SECTION: still dropped, and nothing said
        "MEFOR_STORE",  # no key part
        "PATH",
    ],
)
def test_a_name_outside_every_modelled_section_is_not_refused(name: str) -> None:
    """The stated limit: only a name whose section is modelled is checked."""
    _reject_unknown_env_keys({name: "x"})


def test_a_security_typo_keeps_its_own_refusal() -> None:
    with pytest.raises(ValueError, match=r"\[security\]\.block_unlisted_outboud"):
        _load({"MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUD": "true"})


def test_a_relocated_and_a_removed_key_keep_their_own_messages() -> None:
    with pytest.raises(ValueError, match=r"moved to \[security\]"):
        _load({"MEFOR_EGRESS_DENY_BY_DEFAULT": "true"})
    with pytest.raises(ValueError, match="was REMOVED"):
        _load({"MEFOR_PIPELINE_REQUIRE_RCSI_FOR_POOLED": "false"})


# --- the census of names the engine's own code spells ----------------------------------------------

#: The trees whose Python is engine or operator-run code. ``tests/`` is left out on purpose: it
#: spells mistyped names to test this refusal.
_CODE_TREES = ("messagefoundry", "packaging", "harness", "scripts", "samples", "tee")


def _spelled_names(tree: str) -> dict[str, set[str]]:
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
    return found


def _is_checked_and_unknown(name: str) -> bool:
    """Would :func:`_reject_unknown_env_keys` refuse ``name``?"""
    try:
        _reject_unknown_env_keys({name: "x"})
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
        for name, files in _spelled_names(tree).items():
            spelled.setdefault(name, set()).update(files)
    # The scanner must be seeing names at all, or an empty offender list means nothing.
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


def test_every_spared_name_is_one_the_engine_package_spells() -> None:
    """A stale entry would spare a variable nothing reads, which is the silent drop again."""
    spelled = _spelled_names("messagefoundry")
    assert sorted(_OUT_OF_BAND_ENV - set(spelled)) == []


def test_no_spared_name_is_also_a_settings_field() -> None:
    models = settings_module._section_models()
    for name in _OUT_OF_BAND_ENV:
        section, _, key = name[len("MEFOR_") :].lower().partition("_")
        assert section in models, name
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
    assert "MEFOR_STORE_REQUIRE_ENCRYPTION" in names  # docker/compose.yaml sets it
    offenders = {
        name: sorted(files)
        for name, files in names.items()
        if name not in _moved_or_removed() and _is_checked_and_unknown(name)
    }
    assert offenders == {}, f"a shipped file names a variable the loader would refuse: {offenders}"
