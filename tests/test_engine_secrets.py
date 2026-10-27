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
import builtins
import importlib
import io
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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
    with pytest.raises(
        SecretsDirectoryError, match="entry 1 of 1 in name order, which names no setting"
    ):
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


def test_a_hidden_file_is_ignored(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, ".MEFOR_STORE_PASSWORD.swp", _FROM_FILE)
    _put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE)
    assert secret_setting("MEFOR_STORE_PASSWORD", environ=_env(directory)) == _FROM_FILE


@pytest.mark.parametrize("name", ["MEFOR_VALUE_", "MEFOR_VALUE_a-b", "MEFOR_VALUE_x y"])
def test_a_value_file_name_that_is_not_a_variable_name_is_refused(
    tmp_path: Path, name: str
) -> None:
    directory = _directory(tmp_path)
    _put(directory, name, _FROM_FILE)
    with pytest.raises(SecretsDirectoryError, match="names no setting"):
        open_secrets_directory(_env(directory))


def test_two_value_files_that_differ_only_in_case_are_refused(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_VALUE_EPIC_PASSWORD", _FROM_FILE)
    if (directory / "MEFOR_VALUE_Epic_Password").exists():
        pytest.skip("this file system ignores case (Windows, default macOS), so no twin can exist")
    _put(directory, "MEFOR_VALUE_Epic_Password", _FROM_FILE)
    with pytest.raises(SecretsDirectoryError, match="which name one setting"):
        open_secrets_directory(_env(directory))


@pytest.mark.skipif(sys.platform == "win32", reason="a FIFO is a POSIX special file")
def test_a_file_that_is_not_regular_is_refused_and_never_opened(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    os.mkfifo(directory / "MEFOR_STORE_PASSWORD", 0o600)
    with pytest.raises(SecretsDirectoryError, match="is not a regular file"):
        secret_setting("MEFOR_STORE_PASSWORD", environ=_env(directory))


def test_a_link_on_windows_is_refused_before_anything_follows_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Windows a link in the directory is refused as itself. A stat that followed it first would
    open whatever it names as the engine's account, a planted UNC path included.

    Creating a symbolic link on Windows needs a privilege a test host may lack, so the Windows arm
    is forced on every platform instead: ``sys.platform`` reads ``win32``, ``os.lstat`` reports the
    file as a link, and at least these calls that would follow it are recorded: ``os.stat``, the
    ``os.path`` probes ``pathlib`` calls, and the opens. A ctypes call, such as the access-list
    read by name, is not. The directory is opened before the platform is forced, because its own
    access check would then need Windows calls, and the module the access check imports lazily is
    imported first, so it is never loaded under the forced platform."""
    directory = _directory(tmp_path)
    target = os.fspath(_put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE))
    secrets = open_secrets_directory(_env(directory))
    assert secrets is not None
    importlib.import_module("messagefoundry.config.wiring")

    followed: list[str] = []
    examined_as_itself: list[str] = []

    def _is_target(path: Any) -> bool:
        return isinstance(path, (str, os.PathLike)) and os.fspath(path) == target

    def _following(name: str, real: Any) -> Any:
        def _call(path: Any, *args: Any, **kwargs: Any) -> Any:
            if _is_target(path):
                followed.append(name)
            return real(path, *args, **kwargs)

        return _call

    real_stat, real_lstat = os.stat, os.lstat

    def _stat(path: Any, *, follow_symlinks: bool = True, **kwargs: Any) -> Any:
        if _is_target(path):
            if not follow_symlinks:
                return _lstat(path)
            followed.append("os.stat")
        return real_stat(path, follow_symlinks=follow_symlinks, **kwargs)

    def _lstat(path: Any, **kwargs: Any) -> Any:
        if _is_target(path):
            examined_as_itself.append(target)
            return SimpleNamespace(
                st_mode=stat.S_IFLNK | 0o777,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
            )
        return real_lstat(path, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "stat", _stat)
        patch.setattr(os, "lstat", _lstat)
        for probe in ("exists", "isfile", "isdir"):
            patch.setattr(os.path, probe, _following(f"os.path.{probe}", getattr(os.path, probe)))
        patch.setattr(io, "open", _following("io.open", io.open))
        patch.setattr(builtins, "open", _following("open", builtins.open))
        patch.setattr(os, "open", _following("os.open", os.open))
        patch.setattr(sys, "platform", "win32")
        # The access check's own wording, so the refusal is known to come from that check.
        with pytest.raises(SecretsDirectoryError, match="it is a link"):
            secrets.read("MEFOR_STORE_PASSWORD")
    # The control: the name was examined as itself, so the empty record below is not vacuous.
    assert examined_as_itself
    assert followed == []


@pytest.mark.skipif(sys.platform != "win32", reason="a directory junction is a Windows link")
def test_a_real_junction_on_windows_is_refused_as_a_link(tmp_path: Path) -> None:
    """The same refusal against a real link, so the real ``os.lstat`` is what reports it. A junction
    needs no privilege to create, unlike a symbolic link. Followed, it names a directory, and the
    refusal would say "is not a regular file" instead."""
    directory = _directory(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    if sys.platform == "win32":  # repeats the skip, for the type checker: _winapi is per platform
        import _winapi

        _winapi.CreateJunction(str(elsewhere), str(directory / "MEFOR_STORE_PASSWORD"))
    secrets = open_secrets_directory(_env(directory))
    assert secrets is not None
    with pytest.raises(SecretsDirectoryError, match="it is a link"):
        secrets.read("MEFOR_STORE_PASSWORD")


def test_a_byte_order_mark_is_not_part_of_the_value(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWORD", b"\xef\xbb\xbf" + _FROM_FILE.encode() + b"\r\n")
    assert secret_setting("MEFOR_STORE_PASSWORD", environ=_env(directory)) == _FROM_FILE


def test_a_settings_load_checks_a_file_nothing_else_would_read(tmp_path: Path) -> None:
    """A Vault token file on a site with no Vault is read by no provider, so the load checks it."""
    directory = _directory(tmp_path)
    _broaden(_put(directory, "MEFOR_SECRETS_VAULT_TOKEN", _FROM_FILE))
    with pytest.raises(ValueError, match="MEFOR_SECRETS_VAULT_TOKEN is not restricted"):
        load_settings(environ=_env(directory), default_file=False)
    (directory / "MEFOR_SECRETS_VAULT_TOKEN").unlink()
    load_settings(environ=_env(directory), default_file=False)  # the control


#: A synthetic value, joined to a name at run time so no source line reads as a credential.
_CANARY = "synthetic-canary-9f3c"


@pytest.mark.parametrize(
    ("before", "shown"),
    [
        ("MEFOR_STORE_PASSWORD" + "=", "entry 1 of 1 in name order (MEFOR_STORE_PASSWORD followed"),
        ("", "entry 1 of 1 in name order"),
        ("MEFOR_STORE_PASSWORD_", "entry 1 of 1 in name order"),
    ],
    ids=["env-line", "bare-value", "value-run-on"],
)
def test_a_misnamed_file_is_cited_without_any_value_in_its_name(
    tmp_path: Path, before: str, shown: str
) -> None:
    directory = _directory(tmp_path)
    _put(directory, before + _CANARY, _FROM_FILE)
    with pytest.raises(SecretsDirectoryError, match="names no setting") as caught:
        open_secrets_directory(_env(directory))
    assert shown in str(caught.value)
    assert "canary" not in str(caught.value)


def test_a_broad_right_to_delete_a_file_in_the_directory_is_refused() -> None:
    """FILE_DELETE_CHILD on the directory lets a broad group delete any setting's file, sending the
    setting back to the environment. Refused for a directory; the same entry on a file, where it
    means nothing, is the control. Synthetic access lists, so it runs on every platform."""
    from messagefoundry.config.wiring import _WinPathSecurity
    from messagefoundry.restricted_file import (
        _DIRECTORY_REACH_MASK,
        _REACH_MASK,
        _windows_access_problem,
    )

    delete_child = _WinPathSecurity(owner_sid="S-1-5-18", aces=((0, 0x40, _USERS),))
    assert "can read or change it" in str(
        _windows_access_problem(delete_child, _DIRECTORY_REACH_MASK)
    )
    assert _windows_access_problem(delete_child, _REACH_MASK) is None


@pytest.mark.skipif(sys.platform != "win32", reason="a Windows access list, set with icacls")
def test_a_directory_users_may_delete_files_in_is_refused(tmp_path: Path) -> None:
    import subprocess

    from messagefoundry.childenv import system_tool_environment
    from messagefoundry.service_status import _system_exe

    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE)
    assert open_secrets_directory(_env(directory)) is not None  # the control, before the grant
    subprocess.run(  # nosec B603 - a fixed system tool by absolute path, test-only
        [_system_exe("icacls.exe"), str(directory), "/grant", f"*{_USERS}:(DC)"],
        check=True,
        capture_output=True,
        env=system_tool_environment(),
    )
    with pytest.raises(SecretsDirectoryError, match="the secrets directory .* is not restricted"):
        open_secrets_directory(_env(directory))


async def test_a_directory_the_reconcile_cannot_use_refuses_the_start_as_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reconcile's blanket handler used to swallow it, leaving the stamps empty, so the start
    then failed as an undetermined store-key age. It now refuses as what it is."""
    from messagefoundry.config.settings import SecretRotationSettings
    from tests.test_secret_expiry_opt_in import _start_with_old_ad_stamp

    directory = _directory_in_process(tmp_path, monkeypatch)
    _broaden(_put(directory, "MEFOR_AUTH_AD_BIND_PASSWORD", _FROM_FILE))
    with pytest.raises(SecretsDirectoryError, match="is not restricted") as caught:
        await _start_with_old_ad_stamp(tmp_path, monkeypatch, SecretRotationSettings())
    assert "MEFOR_AUTH_AD_BIND_PASSWORD" in str(caught.value)


async def test_a_usable_directory_lets_the_same_start_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.config.settings import SecretRotationSettings
    from tests.test_secret_expiry_opt_in import _start_with_old_ad_stamp

    directory = _directory_in_process(tmp_path, monkeypatch)
    _put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE)  # the control: restricted
    engine = await _start_with_old_ad_stamp(tmp_path, monkeypatch, SecretRotationSettings())
    await engine.stop()


async def test_the_expiry_opt_in_read_refuses_the_start_as_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_expiry_enforced_held_ids` reads the directory outside the reconcile. With the reconcile
    stubbed, a directory it cannot use refuses the start naming the file."""
    from messagefoundry.config.settings import SecretRotationSettings
    from tests.test_secret_expiry_opt_in import _AD, _start_with_old_ad_stamp

    async def _no_stamps(*_a: object, **_k: object) -> dict[str, object]:
        return {}

    monkeypatch.setattr("messagefoundry.pipeline.engine.reconcile_rotation_meta", _no_stamps)
    directory = _directory_in_process(tmp_path, monkeypatch)
    _broaden(_put(directory, "MEFOR_STORE_PASSWORD", _FROM_FILE))
    with pytest.raises(SecretsDirectoryError, match="MEFOR_STORE_PASSWORD is not restricted"):
        await _start_with_old_ad_stamp(
            tmp_path,
            monkeypatch,
            SecretRotationSettings(
                enforce_secret_expiry_classes=[_AD], enforce_store_key_expiry=False
            ),
        )


def test_a_connection_edit_reports_a_directory_refusal_and_no_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    from messagefoundry.__main__ import main
    from tests.test_connections_cli import LOGIC

    config = tmp_path / "config"
    config.mkdir()
    (config / "logic.py").write_text(LOGIC, encoding="utf-8")
    directory = _directory_in_process(tmp_path, monkeypatch)
    _broaden(_put(directory, "MEFOR_VALUE_EPIC_PASSWORD", _FROM_FILE))
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    svc = config / "svc.toml"
    svc.write_text("", encoding="utf-8")
    obj = {
        "direction": "inbound",
        "name": "IB",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2600},
    }
    args = ["connection", "upsert", "--config", str(config), "--service-config", str(svc)]
    rc = main([*args, "--data", json.dumps(obj), "--json"])
    out = capsys.readouterr()
    assert rc != 0
    assert "MEFOR_VALUE_EPIC_PASSWORD is not restricted" in out.out + out.err
    assert "Traceback" not in out.out + out.err
    assert _FROM_FILE not in out.out + out.err


def test_a_connection_edit_reports_a_malformed_value_file_and_no_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The same arm as the directory refusal, for the value file it reads beside it."""
    import json

    from messagefoundry.__main__ import main
    from tests.test_connections_cli import LOGIC

    config = tmp_path / "config"
    config.mkdir()
    (config / "logic.py").write_text(LOGIC, encoding="utf-8")
    (tmp_path / "environments").mkdir()
    (tmp_path / "environments" / "dev.toml").write_text("a = [\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(SECRETS_DIRECTORY_VARIABLE, raising=False)
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    svc = config / "svc.toml"
    svc.write_text("", encoding="utf-8")
    obj = {"direction": "inbound", "name": "IB", "transport": "mllp", "router": "r"}
    args = ["connection", "upsert", "--config", str(config), "--service-config", str(svc)]
    rc = main([*args, "--data", json.dumps({**obj, "settings": {"port": 2600}}), "--json"])
    out = capsys.readouterr()
    assert rc != 0
    assert "could not read environment values" in out.out + out.err
    assert "Traceback" not in out.out + out.err


def test_a_name_that_is_not_ascii_is_refused_before_it_is_case_folded(tmp_path: Path) -> None:
    """``str.upper`` maps some non-ASCII letters onto ASCII ones, so an unchecked fold would read a
    long-s spelling as the store password on Windows."""
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_\u017fTORE_PASSWORD", _FROM_FILE)
    with pytest.raises(SecretsDirectoryError, match="entry 1 of 1 in name order"):
        open_secrets_directory(_env(directory))


def test_a_not_utf8_refusal_carries_no_chain_that_holds_the_bytes(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, "MEFOR_STORE_PASSWORD", b"p\xe4ss")
    with pytest.raises(SecretsDirectoryError, match="is not UTF-8") as caught:
        secret_setting("MEFOR_STORE_PASSWORD", environ=_env(directory))
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_a_vault_token_refusal_carries_no_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.config.secretprovider_vault import secrets_vault_token
    from messagefoundry.store.keyprovider_vault import store_token_setting

    directory = _directory_in_process(tmp_path, monkeypatch)
    _put(directory, "MEFOR_STORE_VAULT_TOKEN", b"t\xe4k")
    _put(directory, "MEFOR_SECRETS_VAULT_TOKEN", b"t\xe4k")
    with pytest.raises(KeyProviderError, match="is not UTF-8") as store_refusal:
        store_token_setting()
    with pytest.raises(SecretProviderError, match="is not UTF-8") as connector_refusal:
        secrets_vault_token()
    for caught in (store_refusal, connector_refusal):
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None


def test_a_store_key_read_does_not_open_the_directory(tmp_path: Path) -> None:
    directory = _directory(tmp_path)
    _put(directory, "notes", _FROM_FILE)  # a directory every other read refuses
    environ = _env(directory, MEFOR_STORE_ENCRYPTION_KEY=_FROM_ENV)
    assert secret_setting("MEFOR_STORE_ENCRYPTION_KEY", environ=environ) == _FROM_ENV
    with pytest.raises(SecretsDirectoryError):  # the control
        secret_setting("MEFOR_STORE_PASSWORD", environ=environ)


# --- no moved module reads a secret-class variable straight from the environment --------------------

_MOVED = (
    "messagefoundry/store/keyprovider_vault.py",
    "messagefoundry/store/crypto_transit.py",
    "messagefoundry/config/secretprovider_vault.py",
    "messagefoundry/pipeline/secret_rotation.py",
    "messagefoundry/config/environments.py",
)


def _direct_reads(source: str) -> list[str]:
    """The secret-class names ``source`` reads with ``<environ>.get(...)``, ``os.environ[...]`` or
    ``getenv(...)``, through a literal or a module-level constant (plain or annotated). An environ
    is ``*.environ``, a name ``environ``, or a name bound to an expression that mentions one.

    **Its reach, at least what it misses:** a name that is not a literal or a module constant, such
    as a loop variable over a list of names. The pre-slice ``held_env_secret_values`` read that way,
    so the per-reader tests above, not this census, are what pin each moved reader."""
    tree = ast.parse(source)
    constants: dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and isinstance(node.value, ast.Constant)
        ):
            constants[node.target.id] = node.value.value

    def named(arg: ast.expr) -> object:
        if isinstance(arg, ast.Constant):
            return arg.value
        return constants.get(arg.id) if isinstance(arg, ast.Name) else None

    # Names bound anywhere to an expression that mentions an environment, such as
    # ``env = os.environ if environ is None else environ``: a ``.get`` on one is an environment read.
    environ_aliases = {
        target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and "environ" in ast.unparse(node.value)
        for target in node.targets
        if isinstance(target, ast.Name)
    }

    def is_environ(receiver: ast.expr) -> bool:
        if isinstance(receiver, ast.Attribute):
            return receiver.attr == "environ"
        return isinstance(receiver, ast.Name) and (
            receiver.id == "environ" or receiver.id in environ_aliases
        )

    found: list[str] = []
    for item in ast.walk(tree):
        arg: ast.expr | None = None
        if isinstance(item, ast.Call) and item.args:
            func = item.func
            if (
                isinstance(func, ast.Attribute) and func.attr == "get" and is_environ(func.value)
            ) or (getattr(func, "attr", getattr(func, "id", None)) == "getenv"):
                arg = item.args[0]
        elif (
            isinstance(item, ast.Subscript)
            and isinstance(item.value, ast.Attribute)
            and item.value.attr == "environ"
        ):
            arg = item.slice
        value = named(arg) if arg is not None else None
        if value in SECRET_SETTING_NAMES:
            found.append(str(value))
    return found


@pytest.mark.parametrize("relative", _MOVED)
def test_a_moved_module_reads_no_secret_straight_from_the_environment(relative: str) -> None:
    assert _direct_reads((_REPO / relative).read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "planted",
    [
        '_T = "MEFOR_STORE_VAULT_TOKEN"\nimport os\nx = os.environ.get(_T)\n',
        'import os\nenv = os.environ\nx = env.get("MEFOR_STORE_VAULT_TOKEN")\n',
        'from os import getenv\n_T: str = "MEFOR_STORE_VAULT_TOKEN"\nx = getenv(_T)\n',
        'import os\nx = os.environ["MEFOR_STORE_VAULT_TOKEN"]\n',
    ],
    ids=["constant", "aliased-environ", "bare-getenv-annotated", "subscript"],
)
def test_the_census_sees_a_direct_read(planted: str) -> None:
    assert _direct_reads(planted) == ["MEFOR_STORE_VAULT_TOKEN"]
