# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The secrets directory and the one accessor (vault BACKLOG #2595, step 3 slice A; ADR 0214).

Three groups. The directory reader: what it reads, and what it refuses, each refusal beside a
control that passes. The readers moved behind the accessor: each still reads the environment, and
reads the directory's file in preference. And a census that the moved modules read no secret-class
variable straight from ``os.environ`` any more.

Every value here is synthetic.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from messagefoundry import serviceenv
from messagefoundry.config import environments
from messagefoundry.config.secretprovider import SecretProviderError
from messagefoundry.config.settings import load_settings
from messagefoundry.engine_secrets import (
    DIRECTORY_SETTING_NAMES,
    KEY_CLASS_NAMES,
    MAX_FILE_BYTES,
    SECRET_SETTING_NAMES,
    SECRETS_DIRECTORY_VARIABLE,
    SecretsDirectoryError,
    open_secrets_directory,
    secret_setting,
    secret_settings,
)
from messagefoundry.restricted_file import broad_access_problem, write_restricted_file
from messagefoundry.store import store as store_mod
from messagefoundry.store.keyprovider import KeyProviderError

_REPO = Path(__file__).resolve().parents[1]
_USERS = "S-1-5-32-545"
_FROM_FILE = "synthetic-value-from-the-directory"
_FROM_ENV = "synthetic-value-from-the-environment"


def _directory(tmp_path: Path) -> Path:
    """An empty secrets directory, open to its owner alone. The precondition is asserted, so a host
    whose temporary directory is broad fails here and not as a misleading refusal later."""
    directory = tmp_path / "secrets"
    directory.mkdir()
    if sys.platform != "win32":
        directory.chmod(0o700)
    assert broad_access_problem(directory) is None
    return directory


def _put(directory: Path, name: str, value: str | bytes) -> Path:
    path = directory / name
    write_restricted_file(path, value.encode("utf-8") if isinstance(value, str) else value)
    return path


def _broaden(path: Path) -> None:
    """Let accounts beyond the owner read ``path``, as a broad directory or a careless copy would."""
    if sys.platform == "win32":
        store_mod._grant_read(path, f"*{_USERS}")
    else:
        path.chmod(0o755 if path.is_dir() else 0o644)


def _env(directory: Path | None, **values: str) -> dict[str, str]:
    environ = dict(values)
    if directory is not None:
        environ[SECRETS_DIRECTORY_VARIABLE] = str(directory)
    return environ


# --- the one list -----------------------------------------------------------------------------------


def test_serviceenv_takes_its_lists_from_the_one_list() -> None:
    assert (*serviceenv.KEY_CLASS_NAMES, *serviceenv.LOOSENING_CLASS_NAMES) == SECRET_SETTING_NAMES
    assert set(KEY_CLASS_NAMES).isdisjoint(DIRECTORY_SETTING_NAMES)
    assert set(KEY_CLASS_NAMES) | set(DIRECTORY_SETTING_NAMES) == set(SECRET_SETTING_NAMES)


def test_the_rotation_watcher_fingerprints_every_secret_the_directory_supplies() -> None:
    """The rotation watcher keeps its own labelled list. It must name the same secrets."""
    from messagefoundry.pipeline.secret_rotation import _ENV_SECRET_CLASSES

    assert {name for name, _label in _ENV_SECRET_CLASSES} == set(DIRECTORY_SETTING_NAMES)


def test_a_name_that_is_not_a_secret_class_setting_is_a_caller_error() -> None:
    with pytest.raises(ValueError, match="MEFOR_STORE_PATH is not a secret-class setting"):
        secret_setting("MEFOR_STORE_PATH", environ={})


# --- the directory reader ---------------------------------------------------------------------------


def test_the_accessor_reads_a_file_in_the_directory(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE + "\r\n")
    environ = _env(directory, MEFOR_STORE_PASSWORD=_FROM_ENV)
    # The file wins over the variable, and the line break an editor adds is not part of the value.
    assert secret_setting("MEFOR_STORE_PASSWORD", environ=environ) == _FROM_FILE


def test_without_a_file_the_environment_is_read_as_it_is(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    environ = _env(directory, MEFOR_AUTH_AD_BIND_PASSWORD=_FROM_ENV, MEFOR_ALERTS_EMAIL_PASSWORD="")
    found = secret_settings(
        ("MEFOR_AUTH_AD_BIND_PASSWORD", "MEFOR_ALERTS_EMAIL_PASSWORD", "MEFOR_AI_API_KEY"),
        environ=environ,
    )
    # A blank variable comes back blank, and an unset one as None, as os.environ.get gave them.
    assert found == {
        "MEFOR_AUTH_AD_BIND_PASSWORD": _FROM_ENV,
        "MEFOR_ALERTS_EMAIL_PASSWORD": "",
        "MEFOR_AI_API_KEY": None,
    }
    # With no directory named at all, the same.
    assert secret_setting("MEFOR_AUTH_AD_BIND_PASSWORD", environ={"x": "y"}) is None


def test_a_broadly_readable_file_is_refused_and_a_restricted_one_is_read(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE)  # the control
    _broaden(_put(directory, "MEFOR_AUTH_AD_BIND_PASSWORD", _FROM_FILE))
    environ = _env(directory)
    assert secret_setting("MEFOR_STORE_PASSWORD", environ=environ) == _FROM_FILE
    with pytest.raises(
        SecretsDirectoryError, match="MEFOR_AUTH_AD_BIND_PASSWORD is not restricted"
    ):
        secret_setting("MEFOR_AUTH_AD_BIND_PASSWORD", environ=environ)


def test_a_broadly_readable_directory_is_refused(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE)
    environ = _env(directory)
    assert open_secrets_directory(environ) is not None  # the control, before it is broadened
    _broaden(directory)
    with pytest.raises(SecretsDirectoryError, match="the secrets directory .* is not restricted"):
        secret_setting("MEFOR_STORE_PASSWORD", environ=environ)


@pytest.mark.parametrize("named", ["relative/secrets", "missing"])
def test_a_directory_that_cannot_be_used_is_refused(tmp_path: Path, named: str) -> None:
    location = named if named.startswith("relative") else str(tmp_path / named)
    with pytest.raises(SecretsDirectoryError, match="absolute path|not a directory"):
        open_secrets_directory({SECRETS_DIRECTORY_VARIABLE: location})


def test_an_unset_or_blank_directory_variable_reads_no_directory() -> None:
    assert open_secrets_directory({}) is None
    assert open_secrets_directory({SECRETS_DIRECTORY_VARIABLE: "  "}) is None


def test_a_file_named_for_no_setting_is_refused(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWROD", _FROM_FILE)
    with pytest.raises(SecretsDirectoryError, match="'MEFOR_STORE_PASSWROD'.*names no setting"):
        open_secrets_directory(_env(directory))
    (directory / "MEFOR_STORE_PASSWROD").unlink()
    _put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE)  # the control: the right spelling opens
    assert open_secrets_directory(_env(directory)) is not None


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_the_store_key_is_never_read_from_the_directory(tmp_path: Path, key: str) -> None:
    directory = _directory(tmp_path)
    _put(directory, key, _FROM_FILE)
    with pytest.raises(SecretsDirectoryError, match="store key is not read from the secrets"):
        open_secrets_directory(_env(directory))
    # And with no such file, the accessor still reads the key from the environment alone.
    (directory / key).unlink()
    assert secret_setting(key, environ=_env(directory, **{key: _FROM_ENV})) == _FROM_ENV


@pytest.mark.parametrize(
    ("content", "why"),
    [
        (b"", "is empty"),
        (b"\n", "is empty"),
        (b"\xff\xfe\x00bad", "is not UTF-8"),
        (b"x" * (MAX_FILE_BYTES + 1), "is larger than"),
    ],
    ids=["empty", "line-break-only", "not-utf8", "too-large"],
)
def test_a_file_that_holds_no_usable_value_is_refused(
    tmp_path: Path, content: bytes, why: str
) -> None:
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWORD", content)
    with pytest.raises(SecretsDirectoryError, match=why) as caught:
        secret_setting("MEFOR_STORE_PASSWORD", environ=_env(directory))
    assert "bad" not in str(caught.value)


def test_a_space_is_kept_as_part_of_the_value(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWORD", " padded value \n")
    assert secret_setting("MEFOR_STORE_PASSWORD", environ=_env(directory)) == " padded value "


def test_no_refusal_carries_the_value(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _broaden(_put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE))
    with pytest.raises(SecretsDirectoryError) as caught:
        secret_setting("MEFOR_STORE_PASSWORD", environ=_env(directory))
    assert _FROM_FILE not in str(caught.value)


# --- the readers moved behind the accessor ----------------------------------------------------------


def _directory_in_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = _directory(tmp_path)
    monkeypatch.setenv(SECRETS_DIRECTORY_VARIABLE, str(directory))
    return directory


def test_the_store_vault_token_reads_the_environment_then_prefers_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.store.keyprovider_vault import store_token_setting, store_vault_token

    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _FROM_ENV)
    assert store_vault_token() == _FROM_ENV
    directory = _directory_in_process(tmp_path, monkeypatch)
    assert store_token_setting() == _FROM_ENV  # a directory with no file for it
    _put(directory, "MEFOR_STORE_VAULT_TOKEN", _FROM_FILE)
    assert store_vault_token() == _FROM_FILE
    _broaden(directory / "MEFOR_STORE_VAULT_TOKEN")
    with pytest.raises(KeyProviderError, match="is not restricted"):
        store_token_setting()


def test_the_transit_cipher_reads_its_token_through_the_accessor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.store import crypto_transit

    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", "synthetic-transit-key")
    seen: list[object] = []

    def _record(addr: object, token: object, **_kw: object) -> object:
        seen.append(token)
        raise RuntimeError("stop before any Vault call")

    monkeypatch.setattr(crypto_transit, "_build_client", _record)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _FROM_ENV)
    from messagefoundry.config.settings import StoreSettings

    with pytest.raises(RuntimeError, match="stop before"):
        crypto_transit.build_transit_cipher(StoreSettings())
    directory = _directory_in_process(tmp_path, monkeypatch)
    _put(directory, "MEFOR_STORE_VAULT_TOKEN", _FROM_FILE)
    with pytest.raises(RuntimeError, match="stop before"):
        crypto_transit.build_transit_cipher(StoreSettings())
    assert seen == [_FROM_ENV, _FROM_FILE]


def test_the_connector_vault_token_reads_the_environment_then_prefers_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.config.secretprovider_vault import secrets_vault_token

    monkeypatch.setenv("MEFOR_SECRETS_VAULT_TOKEN", _FROM_ENV)
    assert secrets_vault_token() == _FROM_ENV
    directory = _directory_in_process(tmp_path, monkeypatch)
    _put(directory, "MEFOR_SECRETS_VAULT_TOKEN", _FROM_FILE)
    assert secrets_vault_token() == _FROM_FILE
    _broaden(directory)
    with pytest.raises(SecretProviderError, match="is not restricted"):
        secrets_vault_token()


def test_env_values_read_the_environment_then_prefer_the_file(tmp_path: Path) -> None:
    def values(environ: dict[str, str]) -> dict[str, object]:
        return environments.load_environment_values(
            base_dir=tmp_path, dir_name="environments", environment="dev", environ=environ
        )

    environ = {"MEFOR_VALUE_EPIC_PASSWORD": _FROM_ENV, "MEFOR_VALUE_EPIC_HOST": "epic.example"}
    assert values(environ) == {"epic_password": _FROM_ENV, "epic_host": "epic.example"}
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_VALUE_EPIC_PASSWORD", _FROM_FILE)
    _put(directory, "MEFOR_VALUE_LAB_TOKEN", _FROM_FILE)
    assert values(_env(directory, **environ)) == {
        "epic_password": _FROM_FILE,
        "epic_host": "epic.example",
        "lab_token": _FROM_FILE,
    }


def test_the_settings_secrets_read_the_environment_then_prefer_the_file(tmp_path: Path) -> None:
    environ = {"MEFOR_STORE_PASSWORD": _FROM_ENV, "MEFOR_AUTH_AD_BIND_PASSWORD": _FROM_ENV}
    settings = load_settings(environ=environ, default_file=False)
    assert settings.store.password == _FROM_ENV
    assert settings.auth.ad_bind_password == _FROM_ENV
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE)
    settings = load_settings(environ=_env(directory, **environ), default_file=False)
    assert settings.store.password == _FROM_FILE  # the database password, from its file
    assert settings.auth.ad_bind_password == _FROM_ENV  # no file for it, so the environment


def test_every_settings_secret_the_directory_supplies_is_a_settings_field(tmp_path: Path) -> None:
    """A name the settings layer reads from the directory must land on a field, or the file would be
    read and its value dropped. The two Vault tokens are read by their own modules instead. Read at
    the layer, before the model's cross-field checks, which would want a whole configuration."""
    from messagefoundry.config.settings import _secrets_directory_overrides, _section_models

    directory = _directory(tmp_path)
    vault_tokens = {"MEFOR_STORE_VAULT_TOKEN", "MEFOR_SECRETS_VAULT_TOKEN"}
    for name in DIRECTORY_SETTING_NAMES:
        _put(directory, name, f"synthetic-{name.lower()}")
    layer = _secrets_directory_overrides(_env(directory))
    models = _section_models()
    written = {(section, key) for section, values in layer.items() for key in values}
    assert all(key in models[section].model_fields for section, key in written), sorted(written)
    landed = {f"MEFOR_{section.upper()}_{key.upper()}" for section, key in written}
    assert landed == set(DIRECTORY_SETTING_NAMES) - vault_tokens
    assert layer["store"]["password"] == "synthetic-mefor_store_password"


def test_a_settings_load_refuses_a_directory_it_cannot_use(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _broaden(_put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE))
    with pytest.raises(ValueError, match="MEFOR_STORE_PASSWORD is not restricted"):
        load_settings(environ=_env(directory), default_file=False)


def test_the_rotation_fingerprint_reads_the_file_too(tmp_path: Path) -> None:
    from messagefoundry.pipeline.secret_rotation import held_env_secret_values

    environ = {"MEFOR_STORE_PASSWORD": _FROM_ENV, "MEFOR_AI_API_KEY": ""}
    assert held_env_secret_values(environ) == {"MEFOR_STORE_PASSWORD": _FROM_ENV}
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_AI_API_KEY", _FROM_FILE)
    assert held_env_secret_values(_env(directory, **environ)) == {
        "MEFOR_STORE_PASSWORD": _FROM_ENV,
        "MEFOR_AI_API_KEY": _FROM_FILE,
    }


# --- no moved module reads a secret-class variable straight from the environment --------------------

_MOVED = (
    "messagefoundry/store/keyprovider_vault.py",
    "messagefoundry/store/crypto_transit.py",
    "messagefoundry/config/secretprovider_vault.py",
    "messagefoundry/pipeline/secret_rotation.py",
    "messagefoundry/config/environments.py",
)


def _direct_reads(source: str) -> list[str]:
    """The secret-class names ``source`` reads with ``os.environ.get``, ``os.environ[...]`` or
    ``os.getenv``, through a literal or a module-level constant."""
    tree = ast.parse(source)
    constants = {
        target.id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        for target in node.targets
        if isinstance(target, ast.Name) and isinstance(node.value.value, str)
    }

    def named(arg: ast.expr) -> object:
        if isinstance(arg, ast.Constant):
            return arg.value
        return constants.get(arg.id) if isinstance(arg, ast.Name) else None

    def is_environ(node: ast.expr) -> bool:
        return isinstance(node, ast.Attribute) and node.attr == "environ"

    found: list[str] = []
    for node in ast.walk(tree):
        arg: ast.expr | None = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args:
            if (
                node.func.attr == "get" and is_environ(node.func.value)
            ) or node.func.attr == "getenv":
                arg = node.args[0]
        elif isinstance(node, ast.Subscript) and is_environ(node.value):
            arg = node.slice
        value = named(arg) if arg is not None else None
        if value in SECRET_SETTING_NAMES:
            found.append(str(value))
    return found


@pytest.mark.parametrize("relative", _MOVED)
def test_a_moved_module_reads_no_secret_straight_from_the_environment(relative: str) -> None:
    assert _direct_reads((_REPO / relative).read_text(encoding="utf-8")) == []


def test_the_census_sees_a_direct_read() -> None:
    planted = '_T = "MEFOR_STORE_VAULT_TOKEN"\nimport os\nx = os.environ.get(_T)\n'
    assert _direct_reads(planted) == ["MEFOR_STORE_VAULT_TOKEN"]
