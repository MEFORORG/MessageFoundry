# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Windows DPAPI secret-at-rest helper (WP-11d; ASVS 13.3.1/13.3.2).

The store encryption key is normally supplied as base64 via ``MEFOR_STORE_ENCRYPTION_KEY`` (the
cross-platform default). On Windows an operator may instead keep it in a **DPAPI-protected key file**
(``[store].encryption_key_file``): ``CryptProtectData`` binds the ciphertext to this machine
(``LOCAL_MACHINE`` scope), so a copied file is useless off the protecting host and the plaintext key
never sits in the service's environment block (readable by any local user: docs/SERVICE.md). At
startup the service account ``CryptUnprotectData``s the file back to the base64 key.

DPAPI is **Windows-only**. Every entry point raises :class:`DpapiUnavailable` elsewhere so callers
degrade gracefully to the env-var key — this module never imports anything Windows-specific at module
load, so it imports cleanly on Linux/macOS (CI lint leg) too. The ``ctypes.windll`` calls live behind
``sys.platform != "win32"`` guards; mypy treats the code after the guard as unreachable off Windows
(mirrors :mod:`messagefoundry.service`), so it type-checks on the Linux CI leg.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

_log = logging.getLogger(__name__)
#: Key files whose access this process has already checked, so a process that reads the key
#: many times (each DR backup pass does) checks, and warns, once.
_checked_key_files: set[str] = set()

# CryptProtectData flags. LOCAL_MACHINE: any principal on THIS machine can unprotect — required so the
# low-privilege *service account* (not just the installing admin) can read the key. UI_FORBIDDEN: never
# raise a prompt (the engine runs headless under a service).
_CRYPTPROTECT_UI_FORBIDDEN = 0x01
_CRYPTPROTECT_LOCAL_MACHINE = 0x04


class DpapiUnavailable(RuntimeError):
    """DPAPI was requested off Windows — there is no ``CryptProtectData`` to call."""


class DpapiError(RuntimeError):
    """A DPAPI operation (protect/unprotect or the backing file I/O) failed."""


def dpapi_available() -> bool:
    """Whether DPAPI can be used here (Windows only)."""
    return sys.platform == "win32"


class _DataBlob(ctypes.Structure):
    """The Win32 ``DATA_BLOB`` (cbData + pbData) passed to/from the CryptProtectData API."""

    _fields_ = (("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char)))


def _to_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    # Return the buffer alongside the blob so the caller keeps it referenced for the call's duration
    # (the blob only borrows the pointer; if the buffer is GC'd mid-call the read is use-after-free).
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def dpapi_protect(secret: bytes, *, machine_scope: bool = True) -> bytes:
    """DPAPI-encrypt ``secret``. ``machine_scope`` (default) ties it to the machine so the service
    account can decrypt; False ties it to the current user only. Raises :class:`DpapiUnavailable`
    off Windows, :class:`DpapiError` on a Win32 failure."""
    if sys.platform != "win32":
        raise DpapiUnavailable("DPAPI (CryptProtectData) is only available on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    in_blob, _keep = _to_blob(secret)
    out_blob = _DataBlob()
    flags = _CRYPTPROTECT_UI_FORBIDDEN | (_CRYPTPROTECT_LOCAL_MACHINE if machine_scope else 0)
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None, flags, ctypes.byref(out_blob)
    )
    if not ok:
        raise DpapiError(f"CryptProtectData failed (Win32 error {ctypes.get_last_error()})")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def dpapi_unprotect(blob: bytes) -> bytes:
    """DPAPI-decrypt a ciphertext produced by :func:`dpapi_protect` (on this machine/account).
    Raises :class:`DpapiUnavailable` off Windows, :class:`DpapiError` on a Win32 failure (wrong
    machine/account, or a corrupt/foreign blob)."""
    if sys.platform != "win32":
        raise DpapiUnavailable("DPAPI (CryptUnprotectData) is only available on Windows")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    in_blob, _keep = _to_blob(blob)
    out_blob = _DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise DpapiError(
            f"CryptUnprotectData failed (Win32 error {ctypes.get_last_error()}); the key file must be "
            "unprotected on the same machine that protected it — and, if it was protected with --user "
            "scope, by the same Windows user (machine scope, the default, lets any account on the host "
            "decrypt it)"
        )
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def protect_key_to_file(
    key_b64: str, path: Path, *, machine_scope: bool = True, read_grants: Sequence[str] = ()
) -> None:
    """DPAPI-protect a base64 store key and write the ciphertext to a NEW, restricted ``path``.

    The file is created restricted in the call that creates it, with read for each account in
    ``read_grants`` (``restricted_file.write_restricted_file`` states the access list). Machine
    scope lets any account on the host unprotect the blob, so the file's access list is what keeps
    the key from the others, and it must hold from the file's first moment (vault BACKLOG #2601).

    Raises :class:`DpapiUnavailable` off Windows and :class:`DpapiError` when the protect call
    fails. The write raises what :func:`write_restricted_file` raises: ``FileExistsError`` when
    ``path`` already exists (it is left untouched), and another ``OSError`` when the file cannot be
    created restricted or the write fails. After a failure there is no new file."""
    from messagefoundry.restricted_file import write_restricted_file

    blob = dpapi_protect(key_b64.strip().encode("ascii"), machine_scope=machine_scope)
    write_restricted_file(path, blob, read_grants=read_grants)


def load_protected_key(path: str | Path) -> str:
    """Read and DPAPI-decrypt a key file into its base64 store key. Raises :class:`DpapiUnavailable`
    off Windows or :class:`DpapiError` if the file is missing/unreadable/not decryptable here.

    Every command that opens the store reads the key here, so this is where a key file a broad
    group can read or change is WARNED about, whatever the command (vault BACKLOG #2601). Each file
    is checked once in a process, after the key has unprotected. ``serve`` and ``supervise`` know
    ``[security].enforcement``, so under ``enforce`` they refuse such a file before they open the
    store."""
    from messagefoundry.restricted_file import broad_access_problem

    p = Path(path)
    try:
        blob = p.read_bytes()
    except OSError as exc:
        raise DpapiError(f"cannot read encryption_key_file {p}: {exc}") from exc
    key = dpapi_unprotect(blob).decode("ascii").strip()
    if str(p) not in _checked_key_files:
        _checked_key_files.add(str(p))
        problem = broad_access_problem(p)
        if problem is not None:
            _log.warning(
                "the store key file named by [store].encryption_key_file is not restricted: %s. "
                "Restrict it to the account the engine runs as, SYSTEM and Administrators.",
                problem,
            )
    return key
