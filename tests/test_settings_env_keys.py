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
import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from messagefoundry.config import settings as settings_module
from messagefoundry.config.settings import (
    _OUT_OF_BAND_ENV,
    _reject_unknown_env_keys,
    _unread_env_notes,
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


@pytest.mark.parametrize(
    "name",
    [
        "MEFOR_STORE_ALLOW_UNENCRYPTED_PH",  # nearest is a key that MOVED to [security]
        "MEFOR_AUTH_REQUIRE_MFAA",  # the same
        "MEFOR_AUTH_ENABLE",  # nearest is a REMOVED key
        "MEFOR_CLUSTER_VIP_ENABLED",  # a sub-table key
        "MEFOR_CLUSTER_VIPP",  # nearest is the sub-table itself
    ],
)
def test_no_hint_is_given_when_the_nearest_key_is_one_the_environment_cannot_set(
    name: str,
) -> None:
    """The runner-up there is an unrelated switch (``MEFOR_CLUSTER_ENABLED`` for the VIP key, a
    different loosening for the moved ones), so the refusal offers nothing."""
    message = _refusal({name: "true"})
    assert name in message
    assert "did you mean" not in message


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
        "MEFOR_STOER_PATH",  # a typo in the SECTION: not refused, and warned about (below)
        "MEFOR_CERTIFICATE_PATH",  # near a section name, and names none
        "MEFOR_STORE",  # no key part
        "PATH",
    ],
)
def test_a_name_that_names_no_modelled_section_is_not_refused(name: str) -> None:
    """The stated limit: a name is refused only when it names a modelled section and a key."""
    _reject_unknown_env_keys({name: "x"}, {})


# --- the warning for a name the refusal lets through -----------------------------------------------


@pytest.mark.parametrize(
    ("name", "hint"),
    [
        ("MEFOR_STOER_PATH", "did you mean MEFOR_STORE_PATH?"),
        ("MEFOR_AUHT_LOCKOUT_MINUTES", "did you mean MEFOR_AUTH_LOCKOUT_MINUTES?"),
        ("MEFOR_SECURTY_REQUIRE_MFA", "did you mean MEFOR_SECURITY_REQUIRE_MFA?"),
        ("MEFOR_SECRET_PROVIDER", "did you mean MEFOR_SECRETS_PROVIDER?"),
        ("MEFOR_STOER_VAULT_ADDR", "did you mean MEFOR_STORE_VAULT_ADDR?"),  # a spared name
        ("MEFOR_CERT_MONITR_WARN_DAYS", "[cert_monitor].warn_days"),  # a file-only section
        (
            "MEFOR_STORE",
            "no setting in it, so nothing reads it (a setting in it is MEFOR_STORE_<KEY>)",
        ),
        (
            "MEFOR_UPDATE_CHECK",
            "[update_check] section and no setting in it, so nothing reads it (that section has no environment layer",
        ),
    ],
)
def test_a_name_that_looks_like_an_unread_setting_is_warned_about(name: str, hint: str) -> None:
    """Each loads, so nothing is refused, and each gets one note that names it and not its value."""
    _reject_unknown_env_keys({name: _SENTINEL}, {})
    notes = _unread_env_notes({name: _SENTINEL}, {})
    assert len(notes) == 1
    assert name in notes[0] and hint in notes[0]
    assert _SENTINEL not in notes[0]


@pytest.mark.parametrize(
    "name",
    [
        "MEFOR_STORE_PATH",  # a real setting
        "MEFOR_STORE_VAULT_ADDR",  # a spared name
        "MEFOR_ALLOW_INSECURE_TLS",  # a process-wide variable; close to no section
        "MEFOR_CONNSCALE_COUNT",  # a harness variable
        "MEFOR_CERTIFICATE_PATH",  # close to no section
        "MEFOR_STOER_PATHH",  # a typo in BOTH parts: still dropped with no message
        "MEFOR_STOER_ZZZZ",  # near a section, and the key is no setting of it
        # Near [cluster], and vip is a sub-table there. MEFOR_CLUSTER_VIP would fail validation,
        # so it is not offered.
        "MEFOR_CLUSTR_VIP",
        "MEFOR_PORT",  # what a Kubernetes Service named "mefor" injects
        "MEFOR_PORT_8765_TCP_ADDR",
        # The test suite's own switches (tests/conftest.py and ci.yml). TEST_FORCE is close to
        # "store" and aad_bind is a [store] setting, so only the part count keeps this one out.
        "MEFOR_TEST_FORCE_AAD_BIND",
        "MEFOR_TEST_SQLSERVER",
        "MEFOR_TEST_POSTGRES",
        "MEFOR_TEST_PORT_BASE",
        "PATH",
    ],
)
def test_a_name_that_does_not_look_like_an_unread_setting_gets_no_note(name: str) -> None:
    """The controls. The warning stays off real settings, spared names and other tools' names,
    and the last few rows are the stated limit: not every dropped variable is noticed."""
    assert _unread_env_notes({name: "x"}, {}) == []


def test_the_note_is_logged_at_warning_and_the_load_still_succeeds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING", logger="messagefoundry.config.settings"):
        loaded = load_settings(
            environ={"MEFOR_STOER_PATH": _SENTINEL, "MEFOR_UPDATE_CHECK": "false"},
            default_file=False,
        )
    assert loaded.update_check.enabled is True  # the variable changed nothing, as the note says
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "MEFOR_STOER_PATH" in text and "MEFOR_UPDATE_CHECK" in text
    assert "NOT applied" in text
    assert _SENTINEL not in text


def test_a_clean_environment_logs_no_such_warning(caplog: pytest.LogCaptureFixture) -> None:
    """The control for the test above."""
    with caplog.at_level("WARNING", logger="messagefoundry.config.settings"):
        _load({"MEFOR_STORE_PATH": "ok.db", "MEFOR_ALLOW_INSECURE_TLS": "1"})
    assert not [r for r in caplog.records if "NOT applied" in r.getMessage()]


def test_a_sub_table_is_not_offered_but_a_scalar_beside_it_is() -> None:
    """``[cluster].vip`` is a sub-table, so ``MEFOR_CLUSTER_VIP`` would fail validation. The
    control: a scalar of the same section is offered."""
    assert _unread_env_notes({"MEFOR_CLUSTR_VIP": "true"}, {}) == []
    (note,) = _unread_env_notes({"MEFOR_CLUSTR_ENABLED": "true"}, {})
    assert "did you mean MEFOR_CLUSTER_ENABLED?" in note


def test_a_refusal_does_not_hide_the_warning(caplog: pytest.LogCaptureFixture) -> None:
    """The warnings are logged before any refusal, so one refused variable does not hide a
    mistyped one until the next start."""
    environ = {"MEFOR_STORE_REQUIRE_ENCRYPTON": "true", "MEFOR_STOER_PATH": _SENTINEL}
    with (
        caplog.at_level("WARNING", logger="messagefoundry.config.settings"),
        pytest.raises(ValueError, match="MEFOR_STORE_REQUIRE_ENCRYPTON"),
    ):
        load_settings(environ=environ, default_file=False)
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "MEFOR_STOER_PATH" in text and "NOT applied" in text


def test_serve_can_log_the_warnings_again_once_logging_is_configured() -> None:
    """``serve`` loads before ``configure_logging``, so it logs these again afterwards from the
    loaded settings. They match what the load logged, the secret-reference spare included."""
    environ = {
        "MEFOR_STOER_PATH": _SENTINEL,
        "MEFOR_SECRETS_PROVIDER": "env",
        "MEFOR_ALERTS_EMAIL_PASSWORD_SECRET": "MEFOR_AUHT_LOCKOUT_MINUTES",
        "MEFOR_AUHT_LOCKOUT_MINUTES": _SENTINEL,
    }
    loaded = load_settings(environ=environ, default_file=False)
    lines = settings_module.unread_env_warnings(loaded, environ)
    assert lines == settings_module._unread_env_lines(
        environ, settings_module._env_overrides(environ)
    )
    assert len(lines) == 1 and "MEFOR_STOER_PATH" in lines[0]
    assert _SENTINEL not in lines[0]


def test_a_secret_reference_variable_is_not_warned_about() -> None:
    """A reference may name any variable, including one that looks like a section typo."""
    environ = {
        "MEFOR_SECRETS_PROVIDER": "env",
        "MEFOR_ALERTS_EMAIL_PASSWORD_SECRET": "MEFOR_STOER_PATH",
        "MEFOR_STOER_PATH": _SENTINEL,
    }
    data = {
        "secrets": {"provider": "env"},
        "alerts": {"email_password_secret": "MEFOR_STOER_PATH"},
    }
    assert _unread_env_notes(environ, data) == []
    assert len(_unread_env_notes(environ, {})) == 1  # the control: unreferenced, it is noted


@pytest.mark.parametrize(
    ("name", "section"),
    [
        ("MEFOR_SECRET_ROTATION_WARN_DAYS", "secret_rotation"),  # a REAL key of that section
        ("MEFOR_SECRET_ROTATION_ENFORCE_STORE_KEY_EXPIRY", "secret_rotation"),
        ("MEFOR_CERT_MONITOR_ENABLED", "cert_monitor"),
        ("MEFOR_UPDATE_CHECK_ENABLED", "update_check"),
        ("MEFOR_SERVICE_NAME", "service"),
    ],
)
def test_a_variable_for_a_section_with_no_env_layer_is_refused(name: str, section: str) -> None:
    """Nothing reads such a variable, real key or not, so it used to change nothing in silence.
    The refusal says the section is set in the file, and offers no variable name."""
    message = _refusal({name: _SENTINEL})
    assert name in message
    assert f"[{section}] has no environment layer" in message
    assert "did you mean" not in message
    assert _SENTINEL not in message


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


def _reference_environ(provider: str) -> dict[str, str]:
    return {
        "MEFOR_SECRETS_PROVIDER": provider,
        "MEFOR_ALERTS_EMAIL_PASSWORD_SECRET": _SECRET_VAR,
        _SECRET_VAR: _SENTINEL,
    }


def test_a_variable_a_setting_names_as_a_secret_reference_is_spared() -> None:
    """``[secrets].provider = "env"`` reads a reference as an environment variable name the
    operator chooses. One that a reference setting names is in use, not a typo."""
    loaded = load_settings(environ=_reference_environ("env"), default_file=False)
    assert loaded.alerts.email_password_secret == _SECRET_VAR


@pytest.mark.parametrize("provider", ["none", "vault", "ENV", " env "])
def test_the_reference_spare_needs_the_env_provider_spelled_exactly(provider: str) -> None:
    """The control for the test above. No other provider reads a reference from the environment,
    and the engine matches the provider name exactly, so the same variable is refused."""
    assert _SECRET_VAR in _refusal(_reference_environ(provider))


def _mixed_case_reference() -> dict[str, str]:
    """The reference is written in another letter case than the variable's name. On Windows the
    environment holds every name in upper case, so this is what a mixed-case reference meets."""
    environ = _reference_environ("env")
    environ["MEFOR_ALERTS_EMAIL_PASSWORD_SECRET"] = _SECRET_VAR.title()
    return environ


def test_where_names_ignore_case_a_reference_in_another_case_still_spares_its_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Windows ``os.environ.get`` finds a variable whatever case the reference is written in,
    so the ``env`` provider would read it. The spare matches the same way there."""
    monkeypatch.setattr(settings_module, "_ENV_NAMES_IGNORE_CASE", True)
    loaded = load_settings(environ=_mixed_case_reference(), default_file=False)
    assert loaded.alerts.email_password_secret == _SECRET_VAR.title()
    # Ignoring case spares no more than the one variable: a typo beside it is still refused.
    typo = {**_mixed_case_reference(), "MEFOR_STORE_REQUIRE_ENCRYPTON": "true"}
    message = _refusal(typo)
    assert "MEFOR_STORE_REQUIRE_ENCRYPTON" in message and _SECRET_VAR not in message


def test_where_names_keep_their_case_a_reference_in_another_case_spares_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control. On POSIX the provider reads the name exactly as the reference spells it, so a
    variable in another case is one nothing reads, and it is refused."""
    monkeypatch.setattr(settings_module, "_ENV_NAMES_IGNORE_CASE", False)
    assert _SECRET_VAR in _refusal(_mixed_case_reference())


def test_the_case_rule_follows_the_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    """The constant is the platform's own rule, and the provider's lookup agrees with it here."""
    assert settings_module._ENV_NAMES_IGNORE_CASE is (os.name == "nt")
    probe = "MEFOR_CASE_PROBE_SYNTHETIC"
    monkeypatch.setenv(probe, "1")
    assert (os.environ.get(probe.title()) == "1") is settings_module._ENV_NAMES_IGNORE_CASE


# --- Kubernetes service links ---------------------------------------------------------------------


def _service_links(service: str, port: int = 8765) -> dict[str, str]:
    """The variables a kubelet injects into a pod for a Service of this name, when
    ``enableServiceLinks`` is on (its default). All values are synthetic."""
    prefix = service.upper().replace("-", "_")
    base = f"{prefix}_PORT_{port}_TCP"
    return {
        f"{prefix}_SERVICE_HOST": "10.0.0.1",
        f"{prefix}_SERVICE_PORT": str(port),
        f"{prefix}_PORT": f"tcp://10.0.0.1:{port}",
        base: f"tcp://10.0.0.1:{port}",
        f"{base}_PROTO": "tcp",
        f"{base}_PORT": str(port),
        f"{base}_ADDR": "10.0.0.1",
    }


@pytest.mark.parametrize(
    ("service", "refused"),
    [
        ("mefor", "MEFOR_SERVICE_HOST"),  # reads as [service], which has no environment layer
        ("mefor-auth", "MEFOR_AUTH_SERVICE_HOST"),
        ("mefor-store", "MEFOR_STORE_SERVICE_HOST"),
        ("mefor-api", "MEFOR_API_SERVICE_HOST"),
    ],
)
def test_service_links_for_a_service_named_after_a_section_stop_the_load(
    service: str, refused: str
) -> None:
    """What docs/CONFIGURATION.md says of these Service names, measured."""
    assert refused in _refusal(_service_links(service))


@functools.cache
def _k8s_docs() -> tuple[tuple[str, dict[str, Any]], ...]:
    """``(file name, document)`` for each mapping document in the shipped Kubernetes manifests."""
    return tuple(
        (path.name, doc)
        for path in sorted((_REPO / "docker" / "k8s").glob("*.yaml"))
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict)
    )


def _shipped_service_names() -> list[str]:
    return [doc["metadata"]["name"] for _, doc in _k8s_docs() if doc.get("kind") == "Service"]


def test_service_links_for_the_shipped_service_names_load_and_draw_no_warning() -> None:
    """The shipped manifests turn service links off (below), and their Service names would be
    harmless with them on: nothing is refused and nothing is warned about."""
    names = _shipped_service_names()
    assert len(names) >= 4 and "mefor-engine" in names
    for name in names:
        environ = _service_links(name)
        _load(environ)
        assert _unread_env_notes(environ, {}) == [], name


def test_every_shipped_pod_spec_turns_service_links_off() -> None:
    """The engine reads no service-link variable, and one named like a setting stops the start or
    is read as that setting. Off at source in every shipped workload."""
    specs = [
        (name, doc["spec"]["template"]["spec"])
        for name, doc in _k8s_docs()
        if doc.get("kind") in {"Deployment", "StatefulSet"}
    ]
    assert len(specs) >= 2
    assert [name for name, spec in specs if spec.get("enableServiceLinks") is not False] == []


def test_no_shipped_file_reads_a_service_link_variable() -> None:
    """The premise for turning them off: nothing shipped under docker/ or in the engine reads a
    ``*_SERVICE_HOST`` or ``*_SERVICE_PORT`` variable. The second assertion is the control."""
    pattern = re.compile(r"[A-Z0-9_]+_SERVICE_(?:HOST|PORT)\b")
    readers = []
    for root in ("docker", "messagefoundry", "messagefoundry_webconsole"):
        for path in sorted((_REPO / root).rglob("*")):
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or path.suffix in {".pyc", ".png", ".ico", ".woff2"}
            ):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if pattern.search(text):
                readers.append(path.relative_to(_REPO).as_posix())
    assert readers == []
    assert pattern.search("host = os.environ['MEFOR_ENGINE_SERVICE_HOST']")


def test_under_the_env_provider_a_variable_no_reference_names_is_refused() -> None:
    """The second control: the provider alone spares nothing."""
    environ = {"MEFOR_SECRETS_PROVIDER": "env", _SECRET_VAR: _SENTINEL}
    assert _SECRET_VAR in _refusal(environ)
    typo = {"MEFOR_SECRETS_PROVIDER": "env", "MEFOR_STORE_REQUIRE_ENCRYPTON": "true"}
    assert "MEFOR_STORE_REQUIRE_ENCRYPTON" in _refusal(typo)


def test_a_setting_that_is_not_a_reference_spares_nothing() -> None:
    """Only the reference settings name a variable. Another setting whose value happens to be a
    variable's name does not spare it."""
    environ = {
        "MEFOR_SECRETS_PROVIDER": "env",
        "MEFOR_LOGGING_FORWARD_HOST": "MEFOR_STORE_REQUIRE_ENCRYPTON",
        "MEFOR_STORE_REQUIRE_ENCRYPTON": "true",
    }
    assert "MEFOR_STORE_REQUIRE_ENCRYPTON" in _refusal(environ)


def test_every_listed_reference_setting_is_a_real_field() -> None:
    models = settings_module._section_models()
    for section, key in settings_module._SECRET_REFERENCE_KEYS:
        assert key in models[section].model_fields, (section, key)


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
    """Every string constant under ``tree``, a directory or one file, that is, whole, a
    ``MEFOR_*`` name -> the files."""
    found: dict[str, set[str]] = {}
    root = _REPO / tree
    for path in [root] if root.is_file() else sorted(root.rglob("*.py")):
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


def test_no_name_the_project_spells_draws_the_unread_setting_warning() -> None:
    """The warning guesses. A name the engine, a harness, a script or a shipped deployment file
    really uses must never draw it, or a correct environment would log that a variable in use is
    not applied. The last line is the control that the same call does fire."""
    # tests/conftest.py too: the suite's own switches are set in a real environment. The rest of
    # tests/ spells mistyped names on purpose, so it is not scanned.
    spelled = {
        name for tree in (*_CODE_TREES, "tests/conftest.py") for name in _spelled_names(tree)
    }
    spelled |= set(_deployment_names())
    assert len(spelled) >= 100
    assert "MEFOR_CONNSCALE_COUNT" in spelled and "MEFOR_ALLOW_INSECURE_TLS" in spelled
    assert "MEFOR_TEST_FORCE_AAD_BIND" in spelled
    noted = {name: _unread_env_notes({name: "x"}, {}) for name in sorted(spelled)}
    assert {name: notes for name, notes in noted.items() if notes} == {}
    assert _unread_env_notes({"MEFOR_STOER_PATH": "x"}, {})


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
