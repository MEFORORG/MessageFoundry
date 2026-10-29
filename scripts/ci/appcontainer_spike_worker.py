#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CPython in an AppContainer under a real Windows service: a spike that measures and builds nothing.

Vault BACKLOG #3411, wave 3.1 (one of the spikes drafts-index item 6 lists). The key-custody draft
plans a config worker that runs in an AppContainer under the SAME service account as the engine.
Whether that worker can reach the account's key material rests on behaviour nobody had run here,
so this script is the instrument that runs it, and ``.github/workflows/appcontainer-spike.yml``
(through ``scripts/ci/appcontainer_spike.ps1``) is the rig. The four questions are in that
workflow's header, and :func:`judge_reports` holds the rule for each answer.

Everything is the standard library: ``ctypes`` over userenv, kernel32, advapi32 and ncrypt. The
DPAPI calls are the engine's own ``messagefoundry/secrets_dpapi.py``, loaded by path, so what is
measured is the call the product makes. Only the synthetic constant :data:`PAYLOAD` is protected
or signed. No secret is read, made or printed: the CNG key is made for the run and deleted by it.

Modes:

``owner --dir DIR --shared DIR``
    Run AS the service ``NT SERVICE\\<name>``, registered the way ``install-service.ps1`` registers
    the engine. It protects :data:`PAYLOAD` in user scope and writes the blob twice: to ``DIR``,
    whose access list names the service and no package, and to ``--shared``, whose access list
    adds ALL APPLICATION PACKAGES. It makes a persisted CNG key in the account's key store and
    signs with it. It then starts this script in ``container`` mode inside an AppContainer, waits
    for it, checks the container's signature with its own key, tidies the key and the profile, and
    writes ``owner.json``.

``container --shared DIR [--blob-hex H --tampered-hex H --denied PATH --granted PATH]``
    Run INSIDE the AppContainer, started by ``owner`` or ``control``. It reads its own token, and
    when handed a blob tries the four things the questions ask: unprotect the bytes, read each
    file, open and sign with the account's key. It writes ``container.json`` to ``--shared``.

``control --dir DIR``
    Run by the rig, as the runner's administrator, before the service starts. It starts a
    container with the same launcher, under a profile of its own, and writes ``control.json``.
    It is the instrument's positive control: a launch that fails from the service and works from
    here is the service account's answer, not a defect in this script.

``judge --owner-dir D --shared-dir D --control-dir D --owner-sid S --owner-account A --privilege P``
``--image I [--summary F]``
    Run by the rig, elevated, once the service has reported. It reads the reports and the access
    lists the rig wrote, prints the four answers with their controls, and appends them to
    ``--summary`` when given.

Reading and judging are kept apart, as in ``dpapi_spike_worker.py``: the reading modes only
report, and :func:`judge_reports` is a plain function over the reports, so
``tests/test_appcontainer_spike_judge.py`` can hand it reports that must not pass.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import functools
import hashlib
import importlib.util
import json
import locale
import os
import re
import subprocess
import sys
import time
import traceback
import types
from collections.abc import Callable, Iterator
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The only bytes this spike protects and signs. Synthetic and constant: not a key, not a secret.
PAYLOAD = b"MessageFoundry AppContainer spike payload, synthetic, not a secret (BACKLOG #3411)"

#: The profile the service's container runs under, and the one the rig's control runs under.
PROFILE = "mefor.acspike.worker"
CONTROL_PROFILE = "mefor.acspike.control"
#: The persisted CNG key the owner makes, and a name no key store holds (the negative control).
KEY_NAME = "MeforAcSpikeKey"
ABSENT_KEY_NAME = "MeforAcSpikeKeyNeverMade"

OWNER_REPORT = "owner.json"
CONTAINER_REPORT = "container.json"
CONTROL_REPORT = "control.json"
ACL_REPORT = "acl.json"
DENIED_BLOB = "denied.blob"
GRANTED_BLOB = "granted.blob"
CONTAINER_LOG = "container.log"

YES, NO, NOT_RUN, UNANSWERED = "YES", "NO", "NOT RUN", "UNANSWERED"

#: The low integrity level every AppContainer token carries.
LOW_INTEGRITY = "S-1-16-4096"
_ADMINISTRATORS = "S-1-5-32-544"
_ERROR_ACCESS_DENIED = 5
_WAIT_SECONDS = 60
#: No call may wait on a prompt: a session-0 service and a container can show none, so a call that
#: wanted one would block until the owner's wait ran out, and read as a container that never ran.
_NCRYPT_SILENT_FLAG = 0x40
#: The statuses that are a REFUSAL of a key open or a signature. Any other non-zero status is a
#: failure the instrument cannot attribute, so it is UNANSWERED, as a read that fails with anything
#: but access denied is for Q3. 0x80070002 is what an AppContainer's open of an absent name
#: returned when this was first run, on Windows 11 build 26300.
_KEY_OPEN_REFUSALS = frozenset({0x80090016, 0x80070002, 0x80090011, 0x80090010, 0x80070005})
_SIGN_REFUSALS = frozenset({0x80090010, 0x80070005})
#: CreateProcessW failures that are a refusal of the launch: access denied, a privilege not held.
_LAUNCH_REFUSALS = frozenset({5, 1314})
#: The NTSTATUS exits the loader gives a process that died before its own code ran: a DLL or an
#: entry point not found, a DLL whose initialisation failed, a bad image, access denied. Any other
#: NTSTATUS exit, such as 0xC0000409 from an abort() inside CPython, is a crash, not one of these.
_LOADER_DEATHS = frozenset({0xC0000135, 0xC0000139, 0xC0000142, 0xC000007B, 0xC0000022})
#: CreateAppContainerProfile's HRESULT when the profile is there already.
_PROFILE_EXISTS = 0x800700B7
#: The digest the owner and the container sign, and the owner checks.
_DIGEST = hashlib.sha256(PAYLOAD).digest()

#: The NCrypt and Win32 status codes a reader is likely to meet here, named for the summary.
_STATUS_NAMES = {
    0x80090016: "NTE_BAD_KEYSET",
    0x80090010: "NTE_PERM",
    0x80090011: "NTE_NOT_FOUND",
    0x80090006: "NTE_BAD_SIGNATURE",
    0x8009000F: "NTE_EXISTS",
    0x80070005: "E_ACCESSDENIED",
    0x80090029: "NTE_NOT_SUPPORTED",
}


def status_text(code: int | None) -> str:
    if code is None:
        return "no status"
    code &= 0xFFFFFFFF
    name = _STATUS_NAMES.get(code)
    return f"0x{code:08X}" + (f" {name}" if name else "")


# --------------------------------------------------------------------------------- reading (inside)


def _repo_file(*parts: str) -> Path:
    return Path(__file__).resolve().parents[2].joinpath(*parts)


def _load_by_path(name: str, path: Path) -> Any:
    """A module loaded from one file. Inside the container no directory is listed, only this file
    read, because the rig grants the container read on the files it needs and nothing more."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.cache
def _dpapi() -> Any:
    # secrets_dpapi imports only the standard library at load.
    return _load_by_path("secrets_dpapi", _repo_file("messagefoundry", "secrets_dpapi.py"))


@functools.cache
def _token_probe() -> Any:
    """``service_token_probe.py``, beside this file. Loaded by the owner only, never inside."""
    return _load_by_path(
        "service_token_probe", _repo_file("scripts", "ci", "service_token_probe.py")
    )


@functools.cache
def _win() -> Any:
    """The Win32 entry points this script calls, with the argument types it relies on.

    userenv is None where the AppContainer profile API is missing, so the caller can say so.
    """
    w = wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    ncrypt = ctypes.WinDLL("ncrypt", use_last_error=True)
    userenv: Any = None
    try:
        userenv = ctypes.WinDLL("userenv", use_last_error=True)
        sid_out = ctypes.POINTER(ctypes.c_void_p)
        for name, args in {
            "CreateAppContainerProfile": (
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                sid_out,
            ),
            "DeriveAppContainerSidFromAppContainerName": (ctypes.c_wchar_p, sid_out),
            "DeleteAppContainerProfile": (ctypes.c_wchar_p,),
        }.items():
            fn = getattr(userenv, name)
            fn.argtypes = args
            fn.restype = ctypes.c_long
    except (OSError, AttributeError):
        userenv = None

    k32.InitializeProcThreadAttributeList.argtypes = (
        ctypes.c_void_p,
        w.DWORD,
        w.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    )
    k32.InitializeProcThreadAttributeList.restype = w.BOOL
    k32.UpdateProcThreadAttribute.argtypes = (
        ctypes.c_void_p,
        w.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    k32.UpdateProcThreadAttribute.restype = w.BOOL
    k32.DeleteProcThreadAttributeList.argtypes = (ctypes.c_void_p,)
    k32.CreateProcessW.argtypes = (
        w.LPCWSTR,
        w.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        w.BOOL,
        w.DWORD,
        ctypes.c_void_p,
        w.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    k32.CreateProcessW.restype = w.BOOL
    k32.WaitForSingleObject.argtypes = (w.HANDLE, w.DWORD)
    k32.WaitForSingleObject.restype = w.DWORD
    k32.GetExitCodeProcess.argtypes = (w.HANDLE, ctypes.POINTER(w.DWORD))
    k32.GetExitCodeProcess.restype = w.BOOL
    k32.TerminateProcess.argtypes = (w.HANDLE, ctypes.c_uint)
    k32.TerminateProcess.restype = w.BOOL
    k32.GetCurrentProcess.restype = w.HANDLE
    k32.CreateFileW.argtypes = (
        w.LPCWSTR,
        w.DWORD,
        w.DWORD,
        ctypes.c_void_p,
        w.DWORD,
        w.DWORD,
        w.HANDLE,
    )
    # Signed, so INVALID_HANDLE_VALUE reads as -1.
    k32.CreateFileW.restype = ctypes.c_ssize_t
    k32.CloseHandle.argtypes = (w.HANDLE,)
    k32.LocalFree.argtypes = (ctypes.c_void_p,)
    k32.LocalFree.restype = ctypes.c_void_p
    adv.OpenProcessToken.argtypes = (w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE))
    adv.OpenProcessToken.restype = w.BOOL
    adv.GetTokenInformation.argtypes = (
        w.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        w.DWORD,
        ctypes.POINTER(w.DWORD),
    )
    adv.GetTokenInformation.restype = w.BOOL
    adv.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(w.LPWSTR))
    adv.ConvertSidToStringSidW.restype = w.BOOL
    adv.FreeSid.argtypes = (ctypes.c_void_p,)
    adv.FreeSid.restype = ctypes.c_void_p

    handle = ctypes.c_size_t
    status = ctypes.c_long
    ncrypt_signatures: dict[str, tuple[Any, ...]] = {
        "NCryptOpenStorageProvider": (ctypes.POINTER(handle), w.LPCWSTR, w.DWORD),
        "NCryptCreatePersistedKey": (
            handle,
            ctypes.POINTER(handle),
            w.LPCWSTR,
            w.LPCWSTR,
            w.DWORD,
            w.DWORD,
        ),
        "NCryptFinalizeKey": (handle, w.DWORD),
        "NCryptOpenKey": (handle, ctypes.POINTER(handle), w.LPCWSTR, w.DWORD, w.DWORD),
        "NCryptSignHash": (
            handle,
            ctypes.c_void_p,
            ctypes.c_char_p,
            w.DWORD,
            ctypes.c_char_p,
            w.DWORD,
            ctypes.POINTER(w.DWORD),
            w.DWORD,
        ),
        "NCryptVerifySignature": (
            handle,
            ctypes.c_void_p,
            ctypes.c_char_p,
            w.DWORD,
            ctypes.c_char_p,
            w.DWORD,
            w.DWORD,
        ),
        "NCryptDeleteKey": (handle, w.DWORD),
        "NCryptFreeObject": (handle,),
    }
    for name, signature in ncrypt_signatures.items():
        fn = getattr(ncrypt, name)
        fn.argtypes = signature
        fn.restype = status
    return types.SimpleNamespace(w=w, k32=k32, adv=adv, ncrypt=ncrypt, userenv=userenv)


# winnt.h TOKEN_INFORMATION_CLASS numbers.
_TOKEN_USER = 1
_TOKEN_INTEGRITY_LEVEL = 25
_TOKEN_IS_APP_CONTAINER = 29
_TOKEN_APP_CONTAINER_SID = 31
_TOKEN_QUERY = 0x0008
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_INVALID_HANDLE = -1


def _sid_text(sid: int | None) -> str | None:
    if not sid:
        return None
    win = _win()
    text = win.w.LPWSTR()
    if not win.adv.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return str(text.value)
    finally:
        win.k32.LocalFree(text)


def _token_class(token: Any, info_class: int) -> Any:
    win = _win()
    needed = win.w.DWORD(0)
    win.adv.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
    if needed.value == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    buf = ctypes.create_string_buffer(needed.value)
    if not win.adv.GetTokenInformation(token, info_class, buf, needed.value, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buf


def read_container_facts() -> dict[str, Any]:
    """This process's token: its user, whether it is an AppContainer token, the package SID and
    the integrity level. The owner reads its own as well, which is the reader's control."""
    win = _win()
    token = win.w.HANDLE()
    if not win.adv.OpenProcessToken(win.k32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        return {"error": f"OpenProcessToken failed (win32 error {ctypes.get_last_error()})"}
    facts: dict[str, Any] = {}
    try:
        # Each of these classes opens with a SID pointer (NULL for a token that is no container).
        for key, info_class in (
            ("user", _TOKEN_USER),
            ("integrity", _TOKEN_INTEGRITY_LEVEL),
            ("is_appcontainer", _TOKEN_IS_APP_CONTAINER),
            ("package_sid", _TOKEN_APP_CONTAINER_SID),
        ):
            try:
                buf = _token_class(token, info_class)
                if info_class == _TOKEN_IS_APP_CONTAINER:
                    facts[key] = bool(win.w.DWORD.from_buffer(buf).value)
                else:
                    facts[key] = _sid_text(ctypes.c_void_p.from_buffer(buf).value)
            except OSError as exc:
                facts.setdefault("errors", {})[key] = f"{type(exc).__name__}: {exc}"
    finally:
        win.k32.CloseHandle(token)
    return facts


def _attempt(call: Callable[[], bytes]) -> tuple[dict[str, Any], bytes | None]:
    """One DPAPI call. The record never holds the bytes, only whether the call worked.

    Only what secrets_dpapi raises for a failed call is a measurement. Anything else is a defect in
    this instrument, so it propagates and main() writes the traceback beside the reports.
    """
    dpapi = _dpapi()
    try:
        out = call()
    except (dpapi.DpapiError, dpapi.DpapiUnavailable) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}, None
    return {"ok": True, "error": None}, out


def _unprotect(blob: bytes) -> dict[str, Any]:
    record, out = _attempt(lambda: _dpapi().dpapi_unprotect(blob))
    record["matches"] = out == PAYLOAD
    return record


def _read(path: Path, expected: bytes) -> dict[str, Any]:
    """Open ``path`` for reading. ``win32`` 5 is a refusal; anything else is not.

    The open is CreateFileW itself, because Python's own open() goes through the C runtime, which
    maps a refusal and a sharing violation alike to errno 13 and keeps no Win32 code.
    """
    win = _win()
    handle = win.k32.CreateFileW(
        str(path), _GENERIC_READ, _FILE_SHARE_READ, None, _OPEN_EXISTING, 0, None
    )
    if handle == _INVALID_HANDLE:
        code = ctypes.get_last_error()
        return {"ok": False, "error": f"CreateFileW failed (win32 error {code})", "win32": code}
    win.k32.CloseHandle(handle)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "win32": None}
    return {"ok": True, "error": None, "win32": None, "matches": data == expected}


class _NCrypt:
    """The few NCrypt calls the questions need, each returning a record, never raising for a
    status the call itself returns."""

    def __init__(self) -> None:
        self.win = _win()

    def _call(self, name: str, *args: Any) -> int:
        return int(getattr(self.win.ncrypt, name)(*args)) & 0xFFFFFFFF

    @contextlib.contextmanager
    def provider(self) -> Iterator[tuple[int, int | None]]:
        prov = ctypes.c_size_t(0)
        status = self._call(
            "NCryptOpenStorageProvider",
            ctypes.byref(prov),
            "Microsoft Software Key Storage Provider",
            0,
        )
        try:
            yield status, (prov.value if status == 0 else None)
        finally:
            if status == 0:
                self._call("NCryptFreeObject", prov)

    def create(self, prov: int, name: str | None) -> tuple[int, int | None]:
        """A P-256 signing key: persisted under ``name``, or ephemeral when ``name`` is None."""
        key = ctypes.c_size_t(0)
        status = self._call(
            "NCryptCreatePersistedKey", prov, ctypes.byref(key), "ECDSA_P256", name, 0, 0
        )
        if status:
            return status, None
        status = self._call("NCryptFinalizeKey", key, _NCRYPT_SILENT_FLAG)
        if status:
            self._call("NCryptFreeObject", key)
            return status, None
        return 0, key.value

    def open(self, prov: int, name: str) -> tuple[int, int | None]:
        key = ctypes.c_size_t(0)
        status = self._call("NCryptOpenKey", prov, ctypes.byref(key), name, 0, _NCRYPT_SILENT_FLAG)
        return status, (key.value if status == 0 else None)

    def sign(self, key: int) -> tuple[int, bytes | None]:
        out = ctypes.create_string_buffer(256)
        size = self.win.w.DWORD(0)
        status = self._call(
            "NCryptSignHash",
            key,
            None,
            _DIGEST,
            len(_DIGEST),
            out,
            len(out),
            ctypes.byref(size),
            _NCRYPT_SILENT_FLAG,
        )
        return status, (out.raw[: size.value] if status == 0 else None)

    def verify(self, key: int, signature: bytes) -> int:
        return self._call(
            "NCryptVerifySignature", key, None, _DIGEST, len(_DIGEST), signature, len(signature), 0
        )

    def free(self, key: int) -> None:
        self._call("NCryptFreeObject", key)

    def delete(self, key: int) -> int:
        return self._call("NCryptDeleteKey", key, _NCRYPT_SILENT_FLAG)


def _record(status: int, **extra: Any) -> dict[str, Any]:
    return {"ok": status == 0, "status": status, "status_text": status_text(status), **extra}


def _key_trial(nc: _NCrypt, prov: int, name: str) -> dict[str, Any]:
    """Open the persisted key ``name`` in a fresh handle and sign with it."""
    status, key = nc.open(prov, name)
    record: dict[str, Any] = {"open": _record(status)}
    if key is not None:
        try:
            sign_status, signature = nc.sign(key)
            record["sign"] = _record(
                sign_status, signature_hex=signature.hex() if signature else None
            )
            if signature:
                record["self_verify"] = _record(nc.verify(key, signature))
        finally:
            nc.free(key)
    return record


def _ephemeral_trial(nc: _NCrypt, prov: int) -> dict[str, Any]:
    """CNG works at all in this process: an ephemeral key, made, signed with and checked."""
    status, key = nc.create(prov, None)
    if key is None:
        return {"ok": False, "stage": "create", "status_text": status_text(status)}
    try:
        sign_status, signature = nc.sign(key)
        if signature is None:
            return {"ok": False, "stage": "sign", "status_text": status_text(sign_status)}
        verify_status = nc.verify(key, signature)
        return {
            "ok": verify_status == 0,
            "stage": "verify",
            "status_text": status_text(verify_status),
        }
    finally:
        nc.free(key)


# ---------------------------------------------------------------------- the AppContainer launcher


class _SecurityCapabilities(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", ctypes.c_void_p),
        ("Capabilities", ctypes.c_void_p),
        ("CapabilityCount", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class _StartupInfoW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _StartupInfoExW(ctypes.Structure):
    _fields_ = [("StartupInfo", _StartupInfoW), ("lpAttributeList", ctypes.c_void_p)]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_NO_WINDOW = 0x08000000
_STARTF_USESTDHANDLES = 0x00000100
_WAIT_TIMEOUT = 0x00000102


class _TrusteeW(ctypes.Structure):
    _fields_ = [
        ("pMultipleTrustee", ctypes.c_void_p),
        ("MultipleTrusteeOperation", ctypes.c_int),
        ("TrusteeForm", ctypes.c_int),
        ("TrusteeType", ctypes.c_int),
        ("ptstrName", ctypes.c_void_p),
    ]


class _ExplicitAccessW(ctypes.Structure):
    _fields_ = [
        ("grfAccessPermissions", wintypes.DWORD),
        ("grfAccessMode", ctypes.c_int),
        ("grfInheritance", wintypes.DWORD),
        ("Trustee", _TrusteeW),
    ]


_UOI_NAME = 2
_SE_WINDOW_OBJECT = 7
_DACL_SECURITY_INFORMATION = 0x00000004
_LABEL_SECURITY_INFORMATION = 0x00000010
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_GRANT_ACCESS = 1
_TRUSTEE_IS_SID = 0
_SDDL_REVISION_1 = 1
#: WinSta0 and WinSta0\Default both carry this label (read on Windows 11 build 26300). Without it
#: an object counts as medium integrity, and a container's low token is refused every write-class
#: right, whatever the DACL grants.
_LOW_LABEL_SDDL = "S:(ML;;NW;;;LW)"
#: Enumerate desktops, read attributes, global atoms, enumerate, read control. WinSta0 grants ALL
#: APPLICATION PACKAGES these and the clipboard and read-screen rights too (0x00020327, read on
#: Windows 11 build 26300); those two are left out, as nothing user32 needs to start.
_WINSTA_CONTAINER_RIGHTS = 0x00020123
#: Read and enumerate objects, create a window or a menu, write objects, read control. Narrower than
#: what WinSta0\Default grants ALL APPLICATION PACKAGES: no hook, journal, switch, delete or DACL
#: right, so the container cannot hook or record input on the service's desktop.
_DESKTOP_CONTAINER_RIGHTS = 0x000200C7
#: The interactive window station, which grants ALL APPLICATION PACKAGES and carries the low label
#: already, so the launcher changes nothing there.
_INTERACTIVE_STATION = "WinSta0"


@functools.cache
def _window_api() -> Any:
    """user32's window station and desktop calls, and advapi32's object-security calls."""
    w = wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    adv = _win().adv
    user32.GetProcessWindowStation.restype = w.HANDLE
    user32.GetThreadDesktop.argtypes = (w.DWORD,)
    user32.GetThreadDesktop.restype = w.HANDLE
    user32.GetUserObjectInformationW.argtypes = (
        w.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        w.DWORD,
        ctypes.POINTER(w.DWORD),
    )
    user32.GetUserObjectInformationW.restype = w.BOOL
    user32.OpenWindowStationW.argtypes = (w.LPCWSTR, w.BOOL, w.DWORD)
    user32.OpenWindowStationW.restype = w.HANDLE
    user32.OpenDesktopW.argtypes = (w.LPCWSTR, w.DWORD, w.BOOL, w.DWORD)
    user32.OpenDesktopW.restype = w.HANDLE
    user32.CloseWindowStation.argtypes = (w.HANDLE,)
    user32.CloseWindowStation.restype = w.BOOL
    user32.CloseDesktop.argtypes = (w.HANDLE,)
    user32.CloseDesktop.restype = w.BOOL
    pointer_out = ctypes.POINTER(ctypes.c_void_p)
    adv.GetSecurityInfo.argtypes = (
        w.HANDLE,
        ctypes.c_int,
        w.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        pointer_out,
        ctypes.c_void_p,
        pointer_out,
    )
    adv.GetSecurityInfo.restype = w.DWORD
    adv.SetEntriesInAclW.argtypes = (
        w.ULONG,
        ctypes.POINTER(_ExplicitAccessW),
        ctypes.c_void_p,
        pointer_out,
    )
    adv.SetEntriesInAclW.restype = w.DWORD
    adv.SetSecurityInfo.argtypes = (
        w.HANDLE,
        ctypes.c_int,
        w.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    adv.SetSecurityInfo.restype = w.DWORD
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        w.LPCWSTR,
        w.DWORD,
        pointer_out,
        ctypes.c_void_p,
    )
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    adv.GetSecurityDescriptorSacl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(w.BOOL),
        pointer_out,
        ctypes.POINTER(w.BOOL),
    )
    adv.GetSecurityDescriptorSacl.restype = w.BOOL
    return types.SimpleNamespace(user32=user32, adv=adv, k32=_win().k32)


def _object_name(handle: int) -> tuple[str | None, int]:
    api = _window_api()
    needed = wintypes.DWORD(0)
    buf = ctypes.create_unicode_buffer(256)
    if not api.user32.GetUserObjectInformationW(
        handle, _UOI_NAME, buf, ctypes.sizeof(buf), ctypes.byref(needed)
    ):
        return None, ctypes.get_last_error()
    return buf.value, 0


#: Opens a window station or desktop by name with the access given; returns 0 on failure.
Opener = Callable[[str, int], int]


def _grant_dacl(
    name: str, open_object: Opener, close: Callable[[int], Any], rights: int, sid: int
) -> tuple[bool, str]:
    """Merge one allow ace for ``sid`` into the object's DACL."""
    api = _window_api()
    with contextlib.ExitStack() as stack:
        handle = open_object(name, _READ_CONTROL | _WRITE_DAC)
        if not handle:
            return False, f"open for the DACL failed (win32 error {ctypes.get_last_error()})"
        stack.callback(close, handle)
        dacl, sd = ctypes.c_void_p(), ctypes.c_void_p()
        info = _DACL_SECURITY_INFORMATION
        rc = int(
            api.adv.GetSecurityInfo(
                handle,
                _SE_WINDOW_OBJECT,
                info,
                None,
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(sd),
            )
        )
        if rc != 0:
            return False, f"GetSecurityInfo failed (win32 error {rc})"
        stack.callback(api.k32.LocalFree, sd)
        if dacl.value is None:
            # A NULL DACL grants everyone already. Merging into it would make a DACL holding the
            # one new ace, which takes the object away from everyone else, the service included.
            return True, "ok, a NULL DACL left as it was"
        entry = _ExplicitAccessW(
            rights, _GRANT_ACCESS, 0, _TrusteeW(None, 0, _TRUSTEE_IS_SID, 0, sid)
        )
        merged = ctypes.c_void_p()
        rc = int(api.adv.SetEntriesInAclW(1, ctypes.byref(entry), dacl, ctypes.byref(merged)))
        if rc != 0:
            return False, f"SetEntriesInAclW failed (win32 error {rc})"
        stack.callback(api.k32.LocalFree, merged)
        rc = int(api.adv.SetSecurityInfo(handle, _SE_WINDOW_OBJECT, info, None, None, merged, None))
        return (True, "ok") if rc == 0 else (False, f"SetSecurityInfo failed (win32 error {rc})")


def _label_low(name: str, open_object: Opener, close: Callable[[int], Any]) -> tuple[bool, str]:
    """Give the object the low mandatory label WinSta0 carries, so a container's DACL grant of a
    write-class right is not refused by the integrity check."""
    api = _window_api()
    with contextlib.ExitStack() as stack:
        handle = open_object(name, _READ_CONTROL | _WRITE_OWNER)
        if not handle:
            return False, f"open for the label failed (win32 error {ctypes.get_last_error()})"
        stack.callback(close, handle)
        sd = ctypes.c_void_p()
        if not api.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _LOW_LABEL_SDDL, _SDDL_REVISION_1, ctypes.byref(sd), None
        ):
            return False, f"the label did not parse (win32 error {ctypes.get_last_error()})"
        stack.callback(api.k32.LocalFree, sd)
        present, defaulted, sacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if (
            not api.adv.GetSecurityDescriptorSacl(
                sd, ctypes.byref(present), ctypes.byref(sacl), ctypes.byref(defaulted)
            )
            or not present.value
        ):
            return False, "the label's SACL could not be read back"
        info = _LABEL_SECURITY_INFORMATION
        rc = int(api.adv.SetSecurityInfo(handle, _SE_WINDOW_OBJECT, info, None, None, None, sacl))
        return (True, "ok") if rc == 0 else (False, f"SetSecurityInfo failed (win32 error {rc})")


def grant_window_object(
    name: str, open_object: Opener, close: Callable[[int], Any], rights: int, sid: int
) -> dict[str, Any]:
    """Grant ``sid`` ``rights`` on the named window station or desktop, and label it low."""
    dacl_ok, dacl = _grant_dacl(name, open_object, close, rights, sid)
    label_ok, label = _label_low(name, open_object, close)
    return {
        "name": name,
        "rights": f"0x{rights:08X}",
        "dacl": dacl,
        "label": label,
        "ok": dacl_ok and label_ok,
        "error": None if dacl_ok and label_ok else f"DACL {dacl}; label {label}",
    }


def grant_window_station_and_desktop(sid: int) -> dict[str, Any]:
    """Let the container ``sid`` connect to this process's window station and desktop.

    A container inherits both, and user32 fails to initialise in a process that cannot open them,
    so any DLL that pulls user32 in fails with ERROR_DLL_INIT_FAILED. WinSta0, an interactive
    user's, grants ALL APPLICATION PACKAGES and carries a low label already. On the first hosted
    run the control's container ran and the service's died importing ``_ctypes`` with that error,
    which this grant is the reading of: that a service's window station has neither. The next run
    confirms it or not.

    The grant names the one package SID, never the group, and is left in place: the service's
    window station goes when its logon session does. On WinSta0 nothing is changed, so a run from
    an interactive session leaves that session's objects as they were.
    """
    api = _window_api()
    station, code = _object_name(api.user32.GetProcessWindowStation())
    if station is None:
        failed = {"ok": False, "error": f"no window station name (win32 error {code})"}
        return {"window_station": failed, "desktop": failed}
    if station == _INTERACTIVE_STATION:
        skipped = {"ok": True, "skipped": f"{station} grants ALL APPLICATION PACKAGES already"}
        return {"window_station": skipped, "desktop": skipped}
    out: dict[str, Any] = {
        "window_station": grant_window_object(
            station,
            lambda name, access: api.user32.OpenWindowStationW(name, False, access),
            api.user32.CloseWindowStation,
            _WINSTA_CONTAINER_RIGHTS,
            sid,
        )
    }
    desktop, code = _object_name(api.user32.GetThreadDesktop(api.k32.GetCurrentThreadId()))
    if desktop is None:
        out["desktop"] = {"ok": False, "error": f"no desktop name (win32 error {code})"}
    else:
        out["desktop"] = grant_window_object(
            desktop,
            lambda name, access: api.user32.OpenDesktopW(name, 0, False, access),
            api.user32.CloseDesktop,
            _DESKTOP_CONTAINER_RIGHTS,
            sid,
        )
    return out


def appcontainer_profile(name: str) -> tuple[dict[str, Any], int | None]:
    """The profile's SID, made with CreateAppContainerProfile, or derived from the name when the
    profile exists already or cannot be made. The caller frees the SID with FreeSid.

    A launch needs only the SID; the profile gives the container its own folders. So a profile
    that cannot be made is recorded, and the launch still goes ahead on the derived SID.
    """
    record: dict[str, Any] = {"name": name}
    userenv = _win().userenv
    if userenv is None:
        record["error"] = "the AppContainer profile API is missing from userenv.dll"
        return record, None
    sid = ctypes.c_void_p()
    hr = int(
        userenv.CreateAppContainerProfile(
            name, name, "MessageFoundry AppContainer spike", None, 0, ctypes.byref(sid)
        )
    )
    # 0x800700B7 is the profile existing already.
    record["create"] = status_text(hr)
    record["created"] = hr == 0
    if hr != 0:
        sid = ctypes.c_void_p()
        hr = int(userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(sid)))
        record["derive"] = status_text(hr)
        if hr != 0:
            record["error"] = (
                f"no AppContainer SID: create and derive both failed ({status_text(hr)})"
            )
            return record, None
    record["sid"] = _sid_text(sid.value)
    return record, sid.value


def delete_appcontainer_profile(name: str) -> str:
    userenv = _win().userenv
    if userenv is None:
        return "the AppContainer profile API is missing from userenv.dll"
    return status_text(int(userenv.DeleteAppContainerProfile(name)))


def launch_in_appcontainer(sid: int, argv: list[str], cwd: Path, log: Path) -> dict[str, Any]:
    """Start ``argv`` inside the AppContainer ``sid``, with no capabilities, and wait for it.

    Its stdout and stderr go to ``log`` through a handle this process opened, the only handle it
    inherits, so the log needs no grant and a container that dies early still says why.
    """
    import msvcrt

    k32 = _win().k32
    record: dict[str, Any] = {}
    size = ctypes.c_size_t(0)
    k32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
    attrs = ctypes.create_string_buffer(size.value)
    if not k32.InitializeProcThreadAttributeList(attrs, 2, 0, ctypes.byref(size)):
        record["error"] = (
            f"InitializeProcThreadAttributeList failed (win32 error {ctypes.get_last_error()})"
        )
        return record
    try:
        with open(log, "wb") as fh:
            out = msvcrt.get_osfhandle(fh.fileno())
            os.set_handle_inheritable(out, True)
            caps = _SecurityCapabilities(sid, None, 0, 0)
            handles = (wintypes.HANDLE * 1)(out)
            for attribute, value, length in (
                (
                    _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    ctypes.byref(caps),
                    ctypes.sizeof(caps),
                ),
                (_PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, ctypes.sizeof(handles)),
            ):
                if not k32.UpdateProcThreadAttribute(
                    attrs, 0, attribute, value, length, None, None
                ):
                    record["error"] = (
                        f"UpdateProcThreadAttribute(0x{attribute:X}) failed "
                        f"(win32 error {ctypes.get_last_error()})"
                    )
                    return record
            info = _StartupInfoExW()
            info.StartupInfo.cb = ctypes.sizeof(_StartupInfoExW)
            info.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
            info.StartupInfo.hStdOutput = out
            info.StartupInfo.hStdError = out
            info.lpAttributeList = ctypes.cast(attrs, ctypes.c_void_p)
            proc = _ProcessInformation()
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            ok = k32.CreateProcessW(
                None,
                command,
                None,
                None,
                True,
                _EXTENDED_STARTUPINFO_PRESENT | _CREATE_NO_WINDOW,
                None,
                str(cwd),
                ctypes.byref(info),
                ctypes.byref(proc),
            )
            if not ok:
                code = ctypes.get_last_error()
                record.update(
                    started=False, error=f"CreateProcessW failed (win32 error {code})", win32=code
                )
                return record
            try:
                record.update(started=True, pid=int(proc.dwProcessId))
                waited = int(k32.WaitForSingleObject(proc.hProcess, _WAIT_SECONDS * 1000))
                record["timed_out"] = waited == _WAIT_TIMEOUT
                if waited != 0:
                    # A timeout or a failed wait: either way the container may still run, so it
                    # is stopped before anything reads what it wrote.
                    record["wait_status"] = status_text(waited)
                    k32.TerminateProcess(proc.hProcess, 1)
                    k32.WaitForSingleObject(proc.hProcess, 5000)
                code_out = wintypes.DWORD(0)
                if k32.GetExitCodeProcess(proc.hProcess, ctypes.byref(code_out)):
                    record["exit_code"] = int(code_out.value)
                    record["exit_text"] = status_text(int(code_out.value))
            finally:
                k32.CloseHandle(proc.hThread)
                k32.CloseHandle(proc.hProcess)
    finally:
        k32.DeleteProcThreadAttributeList(attrs)
    return record


def _launch(profile: str, shared: Path, extra: list[str]) -> dict[str, Any]:
    """Make or derive ``profile``, start ``container`` mode in it, and read back its report."""
    win = _win()
    out: dict[str, Any] = {}
    out["profile"], sid = appcontainer_profile(profile)
    if sid is None:
        return out
    try:
        # Before the launch, and for the control too, so both launches are the same procedure.
        out["window_grant"] = grant_window_station_and_desktop(sid)
        argv = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "container"]
        argv += ["--shared", str(shared), *extra]
        out["launch"] = launch_in_appcontainer(sid, argv, shared, shared / CONTAINER_LOG)
        out["launch"]["log_tail"] = _log_tail(shared / CONTAINER_LOG)
    finally:
        win.adv.FreeSid(sid)
    return out


def _log_tail(path: Path) -> str | None:
    """The last line the container printed, for the judge's detail: a traceback ends with its cause."""
    try:
        # CPython writes redirected stderr in the ANSI code page unless UTF-8 mode is on.
        text = path.read_text(encoding=locale.getencoding(), errors="replace")
    except OSError:
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1][:300] if lines else None


def _write_report(path: Path, report: dict[str, Any]) -> None:
    # Written whole and then renamed, so no reader sees half a report.
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _load(path: Path) -> dict[str, Any] | None:
    try:
        # utf-8-sig: a report the rig wrote under Windows PowerShell 5.1 may open with a mark.
        loaded = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _header(role: str) -> dict[str, Any]:
    return {"role": role, "pid": os.getpid(), "facts": read_container_facts()}


def container_args(blob: bytes, denied: Path, shared: Path) -> list[str]:
    """What the owner hands ``container`` mode after ``--shared``. The test parses it with
    :func:`build_parser`, since a container that cannot parse its arguments writes no report."""
    # One byte changed near the end, where the blob's integrity check sits.
    tampered = blob[:-1] + bytes([blob[-1] ^ 0x01])
    return [
        *("--blob-hex", blob.hex(), "--tampered-hex", tampered.hex()),
        *("--denied", str(denied), "--granted", str(shared / GRANTED_BLOB)),
    ]


def _check_signature(nc: _NCrypt, prov: int, container: dict[str, Any] | None) -> Any:
    """The container's signature, checked with the service's own key, or None with none to check."""
    signature = _get(container, "key", "sign", "signature_hex")
    if not isinstance(signature, str):
        return None
    try:
        raw = bytes.fromhex(signature)
    except ValueError:
        return {"ok": False, "status_text": "the container's signature is not hex"}
    status, key = nc.open(prov, KEY_NAME)
    if key is None:
        return _record(status, stage="reopen")
    try:
        return _record(nc.verify(key, raw))
    finally:
        nc.free(key)


def run_owner(folder: Path, shared: Path) -> dict[str, Any]:
    report = _header("owner")
    try:
        report["token"] = _token_probe().read_token()
    except OSError as exc:
        report["token"] = {"error": f"{type(exc).__name__}: {exc}"}

    # The blob: user scope, written to a file that names no package and to one that does.
    protect, blob = _attempt(lambda: _dpapi().dpapi_protect(PAYLOAD, machine_scope=False))
    report["protect"] = protect
    if blob is not None:
        report["blob_sha256"] = hashlib.sha256(blob).hexdigest()
        (folder / DENIED_BLOB).write_bytes(blob)
        (shared / GRANTED_BLOB).write_bytes(blob)
        report["owner_unprotect"] = _unprotect(blob)
        report["owner_read_denied"] = _read(folder / DENIED_BLOB, blob)

    nc = _NCrypt()
    with nc.provider() as (prov_status, prov):
        report["provider"] = _record(prov_status)
        made = False
        try:
            if prov is not None:
                status, key = nc.create(prov, KEY_NAME)
                report["key_create"] = _record(status)
                made = key is not None
                if key is not None:
                    nc.free(key)
                    # Reopened by name in a fresh handle: the same call the container makes.
                    report["owner_key"] = _key_trial(nc, prov, KEY_NAME)
                report["owner_absent_key"] = {"open": _record(nc.open(prov, ABSENT_KEY_NAME)[0])}
            if blob is not None:
                report.update(
                    _launch(PROFILE, shared, container_args(blob, folder / DENIED_BLOB, shared))
                )
                report["container_fatal"] = (shared / "container-fatal.txt").is_file()
            if made and prov is not None:
                report["container_signature_verified"] = _check_signature(
                    nc, prov, _load(shared / CONTAINER_REPORT)
                )
        finally:
            # Whatever happened above, the key the run made does not outlive it.
            if made and prov is not None:
                status, key = nc.open(prov, KEY_NAME)
                report["key_delete"] = status_text(nc.delete(key) if key is not None else status)
            report["profile_delete"] = delete_appcontainer_profile(PROFILE)
    _write_report(folder / OWNER_REPORT, report)
    return report


def run_container(args: argparse.Namespace) -> dict[str, Any]:
    out = Path(args.shared) / CONTAINER_REPORT
    # Written first and again after each step, so a step that hangs or crashes still leaves the
    # proof that the script ran in here, which is Q1, and the steps that finished before it.
    report = _header("container")
    _write_report(out, report)
    if args.blob_hex:
        blob = bytes.fromhex(args.blob_hex)
        report["given_sha256"] = hashlib.sha256(blob).hexdigest()
        steps: list[tuple[str, Callable[[], Any]]] = [
            ("unprotect_given", lambda: _unprotect(blob)),
            ("unprotect_tampered", lambda: _unprotect(bytes.fromhex(args.tampered_hex))),
            ("own_roundtrip", _own_roundtrip),
            ("read_denied", lambda: _read(Path(args.denied), blob)),
            ("read_granted", lambda: _read(Path(args.granted), blob)),
        ]
        for key, step in steps:
            report[key] = step()
            _write_report(out, report)
        nc = _NCrypt()
        with nc.provider() as (prov_status, prov):
            report["provider"] = _record(prov_status)
            if prov is not None:
                report["key"] = _key_trial(nc, prov, KEY_NAME)
                _write_report(out, report)
                report["absent_key"] = {"open": _record(nc.open(prov, ABSENT_KEY_NAME)[0])}
                report["ephemeral"] = _ephemeral_trial(nc, prov)
        _write_report(out, report)
    return report


def _own_roundtrip() -> dict[str, Any]:
    """DPAPI works at all in this process: a user-scope blob of its own, made and opened."""
    record, blob = _attempt(lambda: _dpapi().dpapi_protect(PAYLOAD, machine_scope=False))
    if blob is None:
        return {**record, "stage": "protect"}
    return {**_unprotect(blob), "stage": "unprotect"}


def run_control(folder: Path) -> dict[str, Any]:
    report = _header("control")
    report.update(_launch(CONTROL_PROFILE, folder, []))
    report["container"] = _load(folder / CONTAINER_REPORT)
    report["profile_delete"] = delete_appcontainer_profile(CONTROL_PROFILE)
    _write_report(folder / CONTROL_REPORT, report)
    return report


def _hold(seconds: int) -> None:
    """Keep the service running until the rig stops it. NSSM stops it with Ctrl+C.

    This rig never restarts the service. The hold is kept so the service stops by the path the
    dpapi spike ran on the runners; an owner that exits at once under NSSM was not run.
    """
    deadline = time.monotonic() + seconds
    with contextlib.suppress(KeyboardInterrupt):
        while time.monotonic() < deadline:
            time.sleep(1)


# ------------------------------------------------------------------------------ judging (the rig)

Control = tuple[str, bool, str]


@dataclass(frozen=True)
class Answer:
    key: str
    question: str
    answer: str
    controls: tuple[Control, ...]
    detail: str


def _get(report: dict[str, Any] | None, *path: str) -> Any:
    node: Any = report
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _ok(record: Any) -> bool:
    return isinstance(record, dict) and record.get("ok") is True


def _why(record: Any) -> str:
    if not isinstance(record, dict):
        return "no record"
    if record.get("ok") is True:
        return "ok"
    return str(record.get("error") or record.get("status_text") or "failed")


def _dpapi_refused(record: Any) -> bool:
    """DPAPI itself refused the bytes: secrets_dpapi raises DpapiError then."""
    return (
        isinstance(record, dict)
        and record.get("ok") is False
        and str(record.get("error") or "").startswith("DpapiError:")
    )


_GRANT_KINDS = ("window_station", "desktop")


def _grant_held(owner: dict[str, Any]) -> bool:
    """The launcher's window station and desktop grant both went through, or were not needed."""
    return all(_ok(_get(owner, "window_grant", kind)) for kind in _GRANT_KINDS)


def _grant_text(owner: dict[str, Any]) -> str:
    """What the launcher's window station and desktop grant to the package came to."""
    parts = []
    for kind in _GRANT_KINDS:
        record = _get(owner, "window_grant", kind)
        skipped = _get(record, "skipped")
        why = f"skipped, {skipped}" if skipped and _ok(record) else _why(record)
        parts.append(f"{kind.replace('_', ' ')} grant {why}")
    return ", ".join(parts)


def _exited_on_its_own(launch: dict[str, Any]) -> bool:
    """The container's process ended by itself with a non-zero code: started, waited on to the
    end, never timed out or killed after a failed wait."""
    return (
        launch.get("started") is True
        and launch.get("timed_out") is False
        and "wait_status" not in launch
        and isinstance(launch.get("exit_code"), int)
        and launch["exit_code"] != 0
    )


def _held(controls: list[Control]) -> bool:
    return all(held for _, held, _ in controls)


_ACE = re.compile(r"\(([A-Z]+);[^;()]*;[^;()]*;[^;()]*;[^;()]*;([^;()]+)\)")


def sddl_trustees(sddl: Any) -> list[str] | None:
    """The trustee of each ALLOW ace in the DACL of ``sddl``; None when there is no DACL to read.

    Only the ``D:`` part is read, up to an ``S:`` part, so an audit or label ace never counts as a
    grant.
    """
    if not isinstance(sddl, str) or "D:" not in sddl:
        return None
    dacl = sddl.split("D:", 1)[1].split("S:", 1)[0]
    return [trustee for kind, trustee in _ACE.findall(dacl) if kind == "A"]


def _is_package(trustee: str) -> bool:
    # AC is ALL APPLICATION PACKAGES; S-1-15-2-* is a package, S-1-15-3-* a capability.
    return trustee == "AC" or trustee.startswith("S-1-15-")


def _service_token(owner: dict[str, Any], sid: str, privileges: list[str]) -> Control:
    """The installer's hardened service token, by the windows-service-smoke leg's own rule."""
    label = "the launcher held the installer's hardened service token"
    token = owner.get("token")
    if not isinstance(token, dict):
        return (label, False, "no token was read")
    problems = _token_probe().token_problems(token, service_sid=sid, privileges=privileges)
    return (label, not problems, "; ".join(problems) or "ok")


def _not_elevated(owner: dict[str, Any]) -> Control:
    groups = _get(owner, "token", "groups")
    found = (
        None
        if not isinstance(groups, list)
        else any(
            g.get("sid") == _ADMINISTRATORS and g.get("enabled") and not g.get("deny_only")
            for g in groups
            if isinstance(g, dict)
        )
    )
    return ("the launcher was not elevated", found is False, f"Administrators enabled={found}")


def _container_identity(
    container: dict[str, Any] | None, *, user: str | None, package: str | None, label: str
) -> list[Control]:
    """What makes a report a container's: an AppContainer token, under the expected package SID,
    for the expected user, at low integrity."""
    facts = _get(container, "facts") or {}
    return [
        (
            f"{label} ran on an AppContainer token",
            facts.get("is_appcontainer") is True,
            f"is_appcontainer={facts.get('is_appcontainer')}",
        ),
        (
            f"{label} ran under the profile's package SID",
            package is not None and facts.get("package_sid") == package,
            f"{facts.get('package_sid')} vs {package}",
        ),
        (
            f"{label} ran as the launcher's user",
            user is not None and facts.get("user") == user,
            f"{facts.get('user')} vs {user}",
        ),
        (
            f"{label} ran at low integrity",
            facts.get("integrity") == LOW_INTEGRITY,
            f"integrity={facts.get('integrity')}",
        ),
    ]


def judge_reports(
    *,
    owner: dict[str, Any] | None,
    container: dict[str, Any] | None,
    control: dict[str, Any] | None,
    acl: dict[str, Any] | None,
    owner_sid: str,
    privileges: list[str],
) -> list[Answer]:
    """The four answers. A control that does not hold makes its answer UNANSWERED, never NO.

    ``owner_sid`` is the service's own SID and ``privileges`` the list install-service.ps1 gives
    every service. NO is said only of a refusal the system gave the container while every control
    held. When Q1 is NO no container ran, so Q2 to Q4 are NOT RUN.
    """
    o = owner or {}
    c = container or {}
    package = _get(o, "profile", "sid")

    # ---- Q1: CPython starts and runs a script in an AppContainer the service launched.
    interpreter = sddl_trustees(_get(acl, "interpreter"))
    control_container = _get(control, "container")
    q1_controls: list[Control] = [
        _service_token(o, owner_sid, privileges),
        _not_elevated(o),
        (
            "the token reader tells a container apart: the launcher's own token is not one",
            _get(o, "facts", "is_appcontainer") is False,
            f"is_appcontainer={_get(o, 'facts', 'is_appcontainer')}",
        ),
        (
            "the rig granted ALL APPLICATION PACKAGES on the interpreter",
            "AC" in (interpreter or []),
            f"allow trustees {interpreter}",
        ),
        (
            "the same launcher started a container from the runner's administrator, which reported",
            isinstance(control_container, dict),
            f"launch {_get(control, 'launch', 'error') or 'ok'}",
        ),
    ]
    q1_controls += _container_identity(
        control_container,
        user=_get(control, "facts", "user"),
        package=_get(control, "profile", "sid"),
        label="the control's container",
    )
    launch = _get(o, "launch") or {}
    if not owner:
        q1, q1_detail = UNANSWERED, "the service wrote no report"
    elif not _ok(_get(o, "protect")):
        q1, q1_detail = UNANSWERED, f"no blob to hand the container: {_why(_get(o, 'protect'))}"
    elif package is None:
        q1 = UNANSWERED
        q1_detail = f"no AppContainer SID: {_get(o, 'profile', 'error') or 'no profile record'}"
    elif not _held(q1_controls):
        q1, q1_detail = (
            UNANSWERED,
            "a control did not hold, so no launch result would be the account's",
        )
    elif container:
        identity = _container_identity(
            container, user=owner_sid, package=package, label="the container"
        )
        q1_controls += identity
        if _held(identity):
            q1 = YES
            q1_detail = (
                f"the container ran this script and reported, exit {launch.get('exit_text')}; "
                f"profile created={_get(o, 'profile', 'created')}; {_grant_text(o)}"
            )
        else:
            q1, q1_detail = (
                UNANSWERED,
                "a report came back, but not from a container of this profile",
            )
    elif not _grant_held(o):
        # With no report, a launch whose window station or desktop grant failed may have died of
        # that, which is the launcher's own failure and not the account's answer.
        q1 = UNANSWERED
        q1_detail = (
            f"no report, and the launcher's own grant failed: {_grant_text(o)}; exit "
            f"{launch.get('exit_text')}; last line: {launch.get('log_tail') or 'none'}"
        )
    elif launch.get("started") is False and launch.get("win32") in _LAUNCH_REFUSALS:
        q1, q1_detail = NO, f"the service could not start the container: {launch.get('error')}"
    elif launch.get("started") is False:
        q1 = UNANSWERED
        q1_detail = f"the launch failed, but not as a refusal: {launch.get('error')}"
    elif o.get("container_fatal") is not False:
        # The container writes its report before anything else, so a crash file with no report is
        # this script failing inside the container, not the account refusing to run it.
        q1 = UNANSWERED
        q1_detail = (
            "no report, and the worker crashed inside the container or its crash file was not "
            f"looked for (container_fatal={o.get('container_fatal')}); read container-fatal.txt"
        )
    elif _exited_on_its_own(launch) and int(launch["exit_code"]) in _LOADER_DEATHS:
        # The loader's own statuses: the process died before CPython could run anything. Any other
        # NTSTATUS exit, such as the fail-fast an abort() inside CPython ends in, is a crash below.
        q1 = NO
        q1_detail = (
            f"the container started and died before CPython ran: exit {launch.get('exit_text')}; "
            f"last line: {launch.get('log_tail') or 'none'}; {_grant_text(o)}"
        )
    elif _exited_on_its_own(launch):
        # The process ended by itself, before the report the script writes first: it crashed while
        # loading, in this script's imports or earlier. Not the account's NO.
        q1 = UNANSWERED
        q1_detail = (
            f"the container crashed before its first report: it exited {launch.get('exit_text')} "
            f"on its own, with no timeout and no failed wait; its last line: "
            f"{launch.get('log_tail') or 'none'}; {_grant_text(o)}; the whole of {CONTAINER_LOG} "
            "is in the job log, and in the step summary after these lines"
        )
    elif launch.get("started") is True:
        q1 = UNANSWERED
        q1_detail = (
            f"the container started and wrote no report: exit {launch.get('exit_text')}, "
            f"timed out={launch.get('timed_out')}, wait {launch.get('wait_status') or 'ok'}; its "
            f"output is in {CONTAINER_LOG}"
        )
    else:
        q1, q1_detail = (
            UNANSWERED,
            f"the launch did not run: {launch.get('error') or 'no launch record'}",
        )

    def gated(answer: str, detail: str) -> tuple[str, str]:
        if q1 == NO:
            return NOT_RUN, "Q1 is NO, so no container ran to ask"
        if q1 != YES:
            return UNANSWERED, "Q1 is not YES, so there is no container to ask"
        return answer, detail

    # ---- Q2: the container can CryptUnprotectData the bytes it was handed.
    given = c.get("unprotect_given")
    q2_controls: list[Control] = [
        (
            "the service itself opened these bytes",
            _ok(_get(o, "owner_unprotect")) and _get(o, "owner_unprotect", "matches") is True,
            _why(_get(o, "owner_unprotect")),
        ),
        (
            "the container was handed the service's exact bytes",
            o.get("blob_sha256") is not None and c.get("given_sha256") == o.get("blob_sha256"),
            f"sha256 {c.get('given_sha256')} vs {o.get('blob_sha256')}",
        ),
        (
            "the container was refused one changed byte, by DPAPI",
            _dpapi_refused(c.get("unprotect_tampered")),
            _why(c.get("unprotect_tampered")),
        ),
        (
            "DPAPI works inside the container: a user-scope blob of its own, made and opened",
            _ok(c.get("own_roundtrip")) and _get(c, "own_roundtrip", "matches") is True,
            f"stage {_get(c, 'own_roundtrip', 'stage')}, {_why(c.get('own_roundtrip'))}",
        ),
    ]
    if not _held(q2_controls):
        q2, q2_detail = UNANSWERED, "a control did not hold"
    elif _ok(given) and _get(given, "matches") is True:
        q2, q2_detail = YES, "the container unprotected the service's user-scope blob to PAYLOAD"
    elif _dpapi_refused(given):
        q2, q2_detail = NO, f"DPAPI refused the container: {_why(given)}"
    else:
        q2, q2_detail = UNANSWERED, f"the attempt failed outside DPAPI: {_why(given)}"
    q2, q2_detail = gated(q2, q2_detail)

    # ---- Q3: the container is refused READ of the blob file that names no package.
    denied_trustees = sddl_trustees(_get(acl, "denied"))
    granted_trustees = sddl_trustees(_get(acl, "granted"))
    read_denied = c.get("read_denied") or {}
    q3_controls: list[Control] = [
        (
            "the service itself read the file",
            _ok(_get(o, "owner_read_denied")) and _get(o, "owner_read_denied", "matches") is True,
            _why(_get(o, "owner_read_denied")),
        ),
        (
            "the file's access list grants the service and names no package or capability",
            denied_trustees is not None
            and owner_sid in denied_trustees
            and not any(_is_package(t) for t in denied_trustees),
            f"allow trustees {denied_trustees}",
        ),
        (
            "the container read the same bytes from a file that adds ALL APPLICATION PACKAGES",
            granted_trustees is not None
            and "AC" in granted_trustees
            and _ok(c.get("read_granted"))
            and _get(c, "read_granted", "matches") is True,
            f"allow trustees {granted_trustees}; {_why(c.get('read_granted'))}",
        ),
    ]
    if not _held(q3_controls):
        q3, q3_detail = UNANSWERED, "a control did not hold"
    elif _ok(read_denied):
        q3, q3_detail = NO, "the container READ the file that names no package"
    elif read_denied.get("win32") == _ERROR_ACCESS_DENIED:
        q3, q3_detail = YES, f"refused: {_why(read_denied)}"
    else:
        q3, q3_detail = UNANSWERED, f"the read failed, but not as a refusal: {_why(read_denied)}"
    q3, q3_detail = gated(q3, q3_detail)

    # ---- Q4: the container can open the account's persisted CNG key, and sign with it.
    key_open = _get(c, "key", "open")
    key_sign = _get(c, "key", "sign")
    absent_status = _get(c, "absent_key", "open", "status")
    q4_controls: list[Control] = [
        (
            "the service made the key, reopened it by name and signed with it",
            _ok(_get(o, "key_create"))
            and _ok(_get(o, "owner_key", "open"))
            and _ok(_get(o, "owner_key", "sign"))
            and _ok(_get(o, "owner_key", "self_verify")),
            f"create {_why(_get(o, 'key_create'))}, open {_why(_get(o, 'owner_key', 'open'))}, "
            f"sign {_why(_get(o, 'owner_key', 'sign'))}",
        ),
        (
            "opening a key name nobody made fails for the service",
            isinstance(_get(o, "owner_absent_key", "open"), dict)
            and not _ok(_get(o, "owner_absent_key", "open")),
            _why(_get(o, "owner_absent_key", "open")),
        ),
        (
            "CNG works inside the container: an ephemeral key signed and checked",
            _ok(c.get("ephemeral")),
            f"provider {_why(c.get('provider'))}; stage {_get(c, 'ephemeral', 'stage')}, "
            f"{_get(c, 'ephemeral', 'status_text')}",
        ),
        (
            "the container's AppContainer profile exists, made now or already there",
            _get(o, "profile", "created") is True
            or str(_get(o, "profile", "create")).startswith(status_text(_PROFILE_EXISTS)),
            f"create {_get(o, 'profile', 'create')}",
        ),
    ]
    same_as_absent = (
        isinstance(key_open, dict)
        and key_open.get("status") is not None
        and key_open.get("status") == absent_status
    )
    if not _held(q4_controls):
        q4, q4_detail = UNANSWERED, "a control did not hold"
    elif _ok(key_open) and _ok(key_sign):
        if _ok(o.get("container_signature_verified")):
            q4 = YES
            q4_detail = (
                "the container opened the account's key and signed; the service's key checks it"
            )
        else:
            q4 = UNANSWERED
            q4_detail = (
                "the container signed with a key of that name, but the service's key does not check "
                f"it: {_why(o.get('container_signature_verified'))}"
            )
    elif isinstance(key_open, dict) and key_open.get("status") in _KEY_OPEN_REFUSALS:
        q4 = NO
        q4_detail = (
            f"open refused: {key_open.get('status_text')}"
            + (
                "; the same status as a name nobody made, so the container's key store does not "
                "hold it"
                if same_as_absent
                else ""
            )
            + f"; profile created={_get(o, 'profile', 'created')}"
        )
    elif _ok(key_open) and isinstance(key_sign, dict) and key_sign.get("status") in _SIGN_REFUSALS:
        q4, q4_detail = NO, f"opened, but signing refused: {key_sign.get('status_text')}"
    elif isinstance(key_open, dict) and not _ok(key_open):
        q4, q4_detail = (
            UNANSWERED,
            f"open failed, but not as a refusal: {key_open.get('status_text')}",
        )
    elif isinstance(key_sign, dict) and not _ok(key_sign):
        q4 = UNANSWERED
        q4_detail = f"signing failed, but not as a refusal: {key_sign.get('status_text')}"
    else:
        q4, q4_detail = (
            UNANSWERED,
            f"no key trial in the container report: {_why(c.get('provider'))}",
        )
    q4, q4_detail = gated(q4, q4_detail)

    return [
        Answer(
            "Q1",
            "CPython starts and runs a script in an AppContainer the service account launched",
            q1,
            tuple(q1_controls),
            q1_detail,
        ),
        Answer(
            "Q2",
            "the container can CryptUnprotectData the service's user-scope blob bytes",
            q2,
            tuple(q2_controls),
            q2_detail,
        ),
        Answer(
            "Q3",
            "the container is refused read of the blob file whose access list names no package",
            q3,
            tuple(q3_controls),
            q3_detail,
        ),
        Answer(
            "Q4",
            "the container can open the account's persisted CNG key and sign with it",
            q4,
            tuple(q4_controls),
            q4_detail,
        ),
    ]


def render(answers: list[Answer], *, image: str, os_build: str, account: str) -> str:
    """Plain lines, one prefix, so a reader greps ``APPCONTAINER-SPIKE`` and gets every answer."""
    lines = [
        f"## AppContainer spike, {image} (vault BACKLOG #3411 wave 3.1)",
        "",
        f"OS build: {os_build}. Service {account}. Spike only: it builds nothing and gates nothing.",
        "",
        "```",
    ]
    for a in answers:
        lines.append(f"APPCONTAINER-SPIKE {image} {a.key} {a.question}: {a.answer}")
        lines.append(f"APPCONTAINER-SPIKE {image} {a.key} detail: {a.detail}")
        # A NOT RUN answer was never measured, so its controls would read as failures that are not.
        for name, held, why in () if a.answer == NOT_RUN else a.controls:
            lines.append(
                f"APPCONTAINER-SPIKE {image} {a.key} control {'HELD' if held else 'FAILED'}: "
                f"{name} ({why})"
            )
    lines.extend(["```", ""])
    # The summary is read on Windows consoles too, so nothing in it may need more than cp1252.
    return "\n".join(lines).encode("cp1252", "replace").decode("cp1252")


def judge_files(owner_dir: Path, shared_dir: Path, control_dir: Path) -> dict[str, Path]:
    """Every file the judge reads, and the two blobs whose access lists the rig reads for it. The
    rig waits on the reports and writes the access lists, so it names each of these, and no other
    report or blob; the judge loads the four reports, never the blobs."""
    return {
        "owner": owner_dir / OWNER_REPORT,
        "container": shared_dir / CONTAINER_REPORT,
        "control": control_dir / CONTROL_REPORT,
        "acl": owner_dir / ACL_REPORT,
        "denied": owner_dir / DENIED_BLOB,
        "granted": shared_dir / GRANTED_BLOB,
    }


def run_judge(args: argparse.Namespace) -> int:
    files = judge_files(Path(args.owner_dir), Path(args.shared_dir), Path(args.control_dir))
    answers = judge_reports(
        owner=_load(files["owner"]),
        container=_load(files["container"]),
        control=_load(files["control"]),
        acl=_load(files["acl"]),
        owner_sid=args.owner_sid,
        privileges=args.privilege,
    )
    build = "not Windows"
    if sys.platform == "win32":
        build = str(sys.getwindowsversion().build)
    text = render(
        answers,
        image=args.image,
        os_build=build,
        account=f"{args.owner_account} ({args.owner_sid})",
    )
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    # A NO is a finding and the spike did its job. Only an answer the instrument could not give
    # turns the job red, and with its own code: CPython exits 1 on a traceback.
    return EXIT_UNANSWERED if any(a.answer == UNANSWERED for a in answers) else 0


#: The judge's exit code when an answer is UNANSWERED. The rig reads it.
EXIT_UNANSWERED = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("owner")
    p.add_argument("--dir", required=True)
    p.add_argument("--shared", required=True)
    p.add_argument("--hold-seconds", type=int, default=1800)
    p = sub.add_parser("container")
    p.add_argument("--shared", required=True)
    for name in ("--blob-hex", "--tampered-hex", "--denied", "--granted"):
        p.add_argument(name)
    p = sub.add_parser("control")
    p.add_argument("--dir", required=True)
    j = sub.add_parser("judge")
    for name in ("--owner-dir", "--shared-dir", "--control-dir", "--owner-sid", "--image"):
        j.add_argument(name, required=True)
    j.add_argument("--owner-account", required=True, help="for the summary only")
    j.add_argument("--privilege", action="append", required=True)
    j.add_argument("--summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "judge":
        return run_judge(args)

    folder = Path(args.shared if args.mode == "container" else args.dir)
    try:
        if args.mode == "owner":
            report = run_owner(folder, Path(args.shared))
        elif args.mode == "container":
            report = run_container(args)
        else:
            report = run_control(folder)
    except Exception:  # a crash is written down beside the reports, then re-raised
        with contextlib.suppress(OSError):
            (folder / f"{args.mode}-fatal.txt").write_text(traceback.format_exc(), encoding="utf-8")
        raise
    print(json.dumps(report, sort_keys=True), flush=True)
    if args.mode == "owner":
        _hold(args.hold_seconds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
