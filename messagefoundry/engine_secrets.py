# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine's secret-class settings, and the one accessor that reads them (vault BACKLOG #2595).

Step 3 of #2595 is one protected channel for a Windows service's secrets. This module is its first
slice: a single list of the secret-class setting names, a **secrets directory** that holds one file
per setting, and one accessor, :func:`secret_settings` (:func:`secret_setting` for one name), that
the readers of those settings go through. The design is ADR 0214.

* **Where a value comes from.** The file named after the setting in the secrets directory, when the
  directory is configured and holds one; otherwise the environment variable of the same name. The
  directory wins, so a site can move a secret out of the environment one setting at a time.
* **Where the directory is.** ``MEFOR_SECRETS_DIRECTORY``, an absolute path. It names a directory,
  not a secret. Unset, no directory is read and every setting comes from the environment, as before
  this slice.
* **What is refused.** Every refusal raises :class:`SecretsDirectoryError`, at every enforcement
  setting, because a channel built to be protected has no reason to read an unprotected file: a
  relative path or one that is not a directory; a directory, or a file in it, that a known broad
  group can read or change (:func:`messagefoundry.restricted_file.broad_access_problem`, the check
  the store key file already gets); a file whose name is not a setting the directory supplies, so a
  mistyped name does not silently fall back to the environment; an empty file, one that is not
  UTF-8, or one over :data:`MAX_FILE_BYTES`.
* **The store key is not read from here.** Its protected channel on Windows is the DPAPI key file,
  ``[store].encryption_key_file``, and the key-custody design keeps it there. A file named for the
  store key, or for its retired keys, is refused.

**What this slice does not do**, at least: refuse a secret found in the environment (the NSSM
reading in :mod:`messagefoundry.serviceenv` still names a non-key secret and does not refuse it);
create the directory (no installer does yet); wrap a file with DPAPI (a plain file restricted by
its access list is the control, and whether a Windows file is also wrapped waits on a spike); and
read a variable a library reads for itself, such as ``VAULT_TOKEN`` or ``PGPASSWORD``.

Messages here name settings and file names, never a value.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "DIRECTORY_SETTING_NAMES",
    "KEY_CLASS_NAMES",
    "MAX_FILE_BYTES",
    "SECRETS_DIRECTORY_VARIABLE",
    "SECRET_SETTING_NAMES",
    "VALUE_PREFIX",
    "SecretsDirectory",
    "SecretsDirectoryError",
    "open_secrets_directory",
    "secret_setting",
    "secret_settings",
]

#: The variable that names the secrets directory. A path, not a secret.
SECRETS_DIRECTORY_VARIABLE: Final = "MEFOR_SECRETS_DIRECTORY"

#: The store key and its decrypt-only retired keys. Either one decrypts the store.
KEY_CLASS_NAMES: Final[tuple[str, ...]] = (
    "MEFOR_STORE_ENCRYPTION_KEY",
    "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
)

#: Every secret-class setting the engine reads, by its environment name. The one list:
#: :mod:`messagefoundry.serviceenv` takes its two lists from it, and
#: ``tests/test_service_env_secrets.py`` holds it to the settings' own lists of secrets. A
#: connection secret an operator names through ``env()`` is not here, because its name is the
#: operator's; the directory supplies those under :data:`VALUE_PREFIX`.
SECRET_SETTING_NAMES: Final[tuple[str, ...]] = (
    *KEY_CLASS_NAMES,
    "MEFOR_STORE_PASSWORD",
    "MEFOR_AUTH_AD_BIND_PASSWORD",
    "MEFOR_AUTH_OIDC_CLIENT_SECRET",
    "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",
    "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY_PASSWORD",
    "MEFOR_ALERTS_EMAIL_PASSWORD",
    "MEFOR_API_TLS_KEY_PASSWORD",
    "MEFOR_STORE_VAULT_TOKEN",
    "MEFOR_SECRETS_VAULT_TOKEN",
    "MEFOR_AI_API_KEY",
)

#: The settings the secrets directory may supply: every secret-class setting but the store key's.
DIRECTORY_SETTING_NAMES: Final[tuple[str, ...]] = tuple(
    name for name in SECRET_SETTING_NAMES if name not in KEY_CLASS_NAMES
)

#: The prefix of an ``env()`` value's variable, ``MEFOR_VALUE_<KEY>``. A file in the directory with
#: this prefix supplies that value. ``config.environments.VALUE_ENV_PREFIX`` is this constant.
VALUE_PREFIX: Final = "MEFOR_VALUE_"

#: The largest file the directory may hold. Room for a PEM private key; a password needs far less.
MAX_FILE_BYTES: Final = 64 * 1024

#: The remedy every access refusal ends with.
_REMEDY: Final = (
    "Restrict it to SYSTEM, Administrators and the account the engine runs as (POSIX: the "
    "engine's own account, mode 0700 for the directory and 0600 for a file)"
)


class SecretsDirectoryError(ValueError):
    """The secrets directory, or a file in it, cannot be used. Never carries a value.

    A ``ValueError``, so a settings load reports it the way it reports a bad setting."""


def _name_key(name: str) -> str:
    """``name`` as the platform compares file names: upper-cased on Windows, as written elsewhere."""
    return name.upper() if sys.platform == "win32" else name


def _is_value_name(key: str) -> bool:
    """Whether ``key`` names an ``env()`` value: the prefix and at least one character after it."""
    return key.startswith(VALUE_PREFIX) and len(key) > len(VALUE_PREFIX)


#: The file names the directory may hold, as the platform compares them, and the store key's.
_ALLOWED_KEYS: Final = frozenset(_name_key(name) for name in DIRECTORY_SETTING_NAMES)
_STORE_KEY_KEYS: Final = frozenset(_name_key(name) for name in KEY_CLASS_NAMES)


def _check(path: Path, what: str) -> None:
    """Refuse ``path`` when a known broad group can reach it: the rule key files get."""
    from messagefoundry.config.key_file_access import key_file_problem

    problem = key_file_problem(str(path), what=what, remedy=_REMEDY)
    if problem is not None:
        raise SecretsDirectoryError(problem)


@dataclass(frozen=True, slots=True)
class SecretsDirectory:
    """A secrets directory whose own access was checked when it was opened.

    Build one with :func:`open_secrets_directory`. Each read checks the file it reads, so a file
    changed after the open is judged as it is now."""

    path: Path
    #: The file names found when the directory was opened, as the platform compares them, mapped to
    #: the name as it is spelled on disk.
    names: Mapping[str, str]

    def read(self, name: str) -> str | None:
        """The value of setting ``name`` from its file, or ``None`` when the directory has none.

        ``name`` must be one of :data:`DIRECTORY_SETTING_NAMES` or start with :data:`VALUE_PREFIX`.
        Raises :class:`SecretsDirectoryError` for a file that cannot be used."""
        if name not in DIRECTORY_SETTING_NAMES and not _is_value_name(name):
            raise ValueError(f"{name} is not a setting the secrets directory supplies")
        on_disk = self.names.get(_name_key(name))
        if on_disk is None:
            return None
        return self._read_file(on_disk)

    def read_values(self) -> dict[str, str]:
        """Every ``env()`` value the directory supplies, keyed by its variable name as spelled on
        disk (``MEFOR_VALUE_<KEY>``)."""
        return {
            on_disk: self._read_file(on_disk)
            for key, on_disk in sorted(self.names.items())
            if _is_value_name(key)
        }

    def _read_file(self, on_disk: str) -> str:
        path = self.path / on_disk
        what = f"the secrets directory's file {on_disk}"
        _check(path, what)
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_FILE_BYTES + 1)
        except OSError as exc:
            raise SecretsDirectoryError(
                f"{what} could not be read ({exc.strerror or type(exc).__name__})"
            ) from exc
        if len(raw) > MAX_FILE_BYTES:
            raise SecretsDirectoryError(f"{what} is larger than {MAX_FILE_BYTES} bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise SecretsDirectoryError(f"{what} is not UTF-8 text") from None
        # A file written by an editor or `echo` ends with a line break nobody meant as part of the
        # value. Only line breaks are dropped: a space may be part of a password.
        text = text.removeprefix("﻿").rstrip("\r\n")
        if not text:
            raise SecretsDirectoryError(
                f"{what} is empty. Write the value into it, or remove the file to read the "
                "environment instead"
            )
        return text


def open_secrets_directory(environ: Mapping[str, str] | None = None) -> SecretsDirectory | None:
    """The secrets directory ``MEFOR_SECRETS_DIRECTORY`` names, checked, or ``None`` when unset.

    ``environ`` defaults to this process's environment. Raises :class:`SecretsDirectoryError` when
    the directory is named and cannot be used: a relative path, a path that is not a directory, a
    directory a known broad group can read or change, or a file in it whose name is not a setting
    the directory supplies."""
    environ = os.environ if environ is None else environ
    raw = environ.get(SECRETS_DIRECTORY_VARIABLE, "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        raise SecretsDirectoryError(
            f"{SECRETS_DIRECTORY_VARIABLE} must be an absolute path; a relative one would depend "
            "on the directory the engine starts in"
        )
    what = f"the secrets directory {SECRETS_DIRECTORY_VARIABLE} names"
    if not path.is_dir():
        raise SecretsDirectoryError(f"{what} is not a directory, or does not exist")
    # The directory first: a group that can add a file to it can supply a setting, whatever the
    # access list of the file it adds.
    _check(path, what)
    try:
        entries = sorted(os.listdir(path))
    except OSError as exc:
        raise SecretsDirectoryError(
            f"{what} could not be listed ({exc.strerror or type(exc).__name__})"
        ) from exc
    names: dict[str, str] = {}
    refused: list[str] = []
    for entry in entries:
        key = _name_key(entry)
        if key in _STORE_KEY_KEYS:
            raise SecretsDirectoryError(
                f"{what} holds a file named {entry}. The store key is not read from the secrets "
                "directory: keep it in a DPAPI-protected key file ([store].encryption_key_file, "
                "made with `messagefoundry protect-key`) and remove that file"
            )
        if key in _ALLOWED_KEYS or _is_value_name(key):
            names[key] = entry
        else:
            refused.append(ascii(entry))
    if refused:
        raise SecretsDirectoryError(
            f"{what} holds {', '.join(refused)}, which names no setting the directory supplies. "
            "Each file is named for one setting, exactly as its environment variable is spelled: "
            f"{', '.join(DIRECTORY_SETTING_NAMES)}, or {VALUE_PREFIX}<KEY> for an env() value. "
            "Rename or remove it"
        )
    return SecretsDirectory(path, names)


def secret_settings(
    names: Iterable[str], *, environ: Mapping[str, str] | None = None
) -> dict[str, str | None]:
    """The value of each secret-class setting in ``names``: its file in the secrets directory when
    there is one, otherwise the environment variable of that name, or ``None`` when neither is set.

    The one accessor (vault BACKLOG #2595), for a reader of several settings, so the directory is
    opened and checked once. ``environ`` defaults to this process's environment and is read for the
    directory's location too. The environment's value is returned as it is, blank included, so a
    reader moved behind this accessor behaves as it did when the directory has no file. A store-key
    name is read from the environment only; the module docstring says why. Raises
    :class:`SecretsDirectoryError` when the directory or a file cannot be used, and ``ValueError``
    for a name that is not a secret-class setting."""
    wanted = tuple(names)
    unknown = [name for name in wanted if name not in SECRET_SETTING_NAMES]
    if unknown:
        raise ValueError(f"{', '.join(unknown)} is not a secret-class setting")
    environ = os.environ if environ is None else environ
    directory = open_secrets_directory(environ)
    found: dict[str, str | None] = {}
    for name in wanted:
        value = None
        if directory is not None and name not in KEY_CLASS_NAMES:
            value = directory.read(name)
        found[name] = environ.get(name) if value is None else value
    return found


def secret_setting(name: str, *, environ: Mapping[str, str] | None = None) -> str | None:
    """The value of one secret-class setting, as :func:`secret_settings` reads it."""
    return secret_settings((name,), environ=environ)[name]
