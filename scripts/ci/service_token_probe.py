#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read a Windows process token, and try writes from inside one (vault BACKLOG #2702).

``install-service.ps1`` gives the engine service a restricted service SID and a short
``RequiredPrivileges`` list. Both are settings on the registration. Neither one proves what token
the running engine holds, and a smoke leg that never looks is green whether the token is restricted
or not. This script is the instrument that looks. ``windows-service-smoke`` in
``.github/workflows/ci.yml`` runs it in two ways:

``check-read --service-sid S --privilege P --control-pid C --pid N``
    Run by the leg, elevated. Opens each process and prints its token as JSON: the user, the
    groups, the privileges, the restricting SIDs and the token flags. The leg hands it the
    ``python.exe`` the service started. Each ``--pid`` must hold the hardened token. The
    ``--control-pid`` is the leg's own shell, and it must NOT: a reader that calls every token
    hardened would otherwise pass.

``inside --report FILE --granted-dir DIR --denied-dir DIR``
    Run AS the service, in place of the engine, under the registration the installer wrote. It
    reads its own token, tries one write in each directory and in the temporary directory, runs
    one call through ``messagefoundry.transports.wincred`` and writes what happened to ``FILE``.
    A write that is refused, and a credential logon that needs no privilege, can only be seen
    from inside.

``check-inside --report FILE --service-sid S --privilege P``
    Run by the leg on that report.

Reading and judging are kept apart. :func:`read_token` and the ``inside`` mode only report.
:func:`token_problems` and :func:`inside_problems` hold the whole rule for what passes, as plain
functions over the reports, so the tests can hand them a token that must fail.

Windows only. ``tests/test_service_token_hardening.py`` starts a child process under a
write-restricted token and an ordinary one, and checks that the reader and the rule tell them
apart.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ctypes
import json
import os
import sys
import tempfile
import time
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any

# winnt.h. TokenAccessInformation carries the token flags, and TOKEN_WRITE_RESTRICTED is the one a
# restricted service SID sets. A token can carry restricting SIDs and still not be
# write-restricted: a fully restricted token checks them on every access, a write-restricted one on
# write access only. The _CLASS_ names are TOKEN_INFORMATION_CLASS numbers.
TOKEN_QUERY = 0x0008
TOKEN_WRITE_RESTRICTED = 0x0008
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_REMOVED = 0x00000004
SE_GROUP_ENABLED = 0x00000004
SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010
SE_GROUP_LOGON_ID = 0xC0000000
TOKEN_ADJUST_PRIVILEGES = 0x0020

_CLASS_USER = 1
_CLASS_GROUPS = 2
_CLASS_PRIVILEGES = 3
_CLASS_IMPERSONATION_LEVEL = 9
_CLASS_RESTRICTED_SIDS = 11
_CLASS_ACCESS_INFORMATION = 22

_ERROR_NO_TOKEN = 1008


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID), ("Attributes", wintypes.DWORD)]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TOKEN_ACCESS_INFORMATION(ctypes.Structure):
    # Only the leading fields, up to Flags. The structure grew after Flags in later Windows
    # versions, and nothing here reads past it.
    _fields_ = [
        ("SidHash", ctypes.c_void_p),
        ("RestrictedSidHash", ctypes.c_void_p),
        ("Privileges", ctypes.c_void_p),
        ("AuthenticationId", _LUID),
        ("TokenType", ctypes.c_int),
        ("ImpersonationLevel", ctypes.c_int),
        ("MandatoryPolicy", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
    ]


def _require_windows() -> None:
    if sys.platform != "win32":
        raise SystemExit("service_token_probe.py reads Windows tokens; this host is not Windows")


def _dlls() -> tuple[Any, Any]:
    """advapi32 and kernel32 with the argument types this file relies on."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentThread.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenThreadToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.BOOL,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.OpenThreadToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.LookupPrivilegeNameW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.POINTER(_LUID),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.LookupPrivilegeNameW.restype = wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(_LUID),
    )
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi32.AdjustTokenPrivileges.argtypes = (
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
    return advapi32, kernel32


def _win_error(what: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{what} failed (win32 error {code})")


def _token_info(advapi32: Any, token: Any, info_class: int) -> Any:
    """One GetTokenInformation class, as a ctypes buffer sized by the call itself."""
    needed = wintypes.DWORD(0)
    advapi32.GetTokenInformation(token, info_class, None, 0, ctypes.byref(needed))
    if needed.value == 0:
        raise _win_error(f"GetTokenInformation({info_class}) sizing")
    buf = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetTokenInformation(token, info_class, buf, needed.value, ctypes.byref(needed)):
        raise _win_error(f"GetTokenInformation({info_class})")
    return buf


def _sid_text(advapi32: Any, kernel32: Any, sid: int | None) -> str:
    if not sid:
        return ""
    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise _win_error("ConvertSidToStringSidW")
    try:
        return str(text.value)
    finally:
        kernel32.LocalFree(text)


def _sid_list(advapi32: Any, kernel32: Any, buf: Any) -> list[dict[str, Any]]:
    """A TOKEN_GROUPS buffer as [{sid, attributes}]. TokenRestrictedSids has the same layout."""
    count = wintypes.DWORD.from_buffer(buf).value
    # The array starts at the first pointer-aligned offset after the count.
    offset = ctypes.sizeof(ctypes.c_void_p)
    entries = (_SID_AND_ATTRIBUTES * count).from_buffer(buf, offset)
    return [
        {"sid": _sid_text(advapi32, kernel32, e.Sid), "attributes": int(e.Attributes)}
        for e in entries
    ]


def _describe_token(advapi32: Any, kernel32: Any, token: Any) -> dict[str, Any]:
    user = _SID_AND_ATTRIBUTES.from_buffer(_token_info(advapi32, token, _CLASS_USER))
    groups = _sid_list(advapi32, kernel32, _token_info(advapi32, token, _CLASS_GROUPS))
    restricting = _sid_list(
        advapi32, kernel32, _token_info(advapi32, token, _CLASS_RESTRICTED_SIDS)
    )
    priv_buf = _token_info(advapi32, token, _CLASS_PRIVILEGES)
    priv_count = wintypes.DWORD.from_buffer(priv_buf).value
    entries = (_LUID_AND_ATTRIBUTES * priv_count).from_buffer(
        priv_buf, ctypes.sizeof(wintypes.DWORD)
    )
    # A privilege that is only switched off is still held, and the process can switch it back on,
    # so it is listed. One marked removed is gone for good, so it is not.
    privileges = []
    for entry in entries:
        if entry.Attributes & SE_PRIVILEGE_REMOVED:
            continue
        size = wintypes.DWORD(128)
        name = ctypes.create_unicode_buffer(size.value)
        if not advapi32.LookupPrivilegeNameW(
            None, ctypes.byref(entry.Luid), name, ctypes.byref(size)
        ):
            raise _win_error("LookupPrivilegeNameW")
        privileges.append(name.value)
    flags = _TOKEN_ACCESS_INFORMATION.from_buffer(
        _token_info(advapi32, token, _CLASS_ACCESS_INFORMATION)
    ).Flags
    return {
        "user": _sid_text(advapi32, kernel32, user.Sid),
        "groups": [
            {
                "sid": g["sid"],
                "enabled": bool(g["attributes"] & SE_GROUP_ENABLED),
                "deny_only": bool(g["attributes"] & SE_GROUP_USE_FOR_DENY_ONLY),
                "logon_id": (g["attributes"] & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID,
            }
            for g in groups
        ],
        "privileges": sorted(privileges),
        "restricting_sids": [r["sid"] for r in restricting],
        # The raw flags are kept for the log. TOKEN_IS_RESTRICTED (0x10) without the bit below is a
        # FULLY restricted token, which is a different thing and must not pass as this one.
        "flags": int(flags),
        "write_restricted": bool(flags & TOKEN_WRITE_RESTRICTED),
    }


def _enable_debug_privilege(advapi32: Any, kernel32: Any) -> None:
    """Switch SeDebugPrivilege on for this process when it is held. Best-effort.

    An elevated administrator holds it disabled. Without it, OpenProcess on a service that runs as
    another account is refused by the process's own permissions. Nothing is returned: when this did
    not work, the OpenProcess that follows fails and says so.
    """
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ctypes.byref(token)
    ):
        return
    try:
        luid = _LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return

        class _TOKEN_PRIVILEGES_ONE(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", _LUID_AND_ATTRIBUTES)]

        state = _TOKEN_PRIVILEGES_ONE(1, _LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED))
        advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(state), 0, None, None)
    finally:
        kernel32.CloseHandle(token)


def read_token(pid: int | None = None) -> dict[str, Any]:
    """The primary token of process ``pid``, or of this process when ``pid`` is None."""
    _require_windows()
    advapi32, kernel32 = _dlls()
    if pid is None:
        process = kernel32.GetCurrentProcess()
    else:
        _enable_debug_privilege(advapi32, kernel32)
        process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not process:
            raise _win_error(f"OpenProcess({pid})")
    try:
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
            raise _win_error(f"OpenProcessToken({pid if pid is not None else 'self'})")
        try:
            described = _describe_token(advapi32, kernel32, token)
        finally:
            kernel32.CloseHandle(token)
    finally:
        if pid is not None:  # GetCurrentProcess is a pseudo-handle and is not closed
            kernel32.CloseHandle(process)
    described["pid"] = os.getpid() if pid is None else pid
    return described


def read_thread_token() -> dict[str, Any] | None:
    """This thread's impersonation token, with its level, or None when the thread has none.

    ``impersonation_level`` is 0 anonymous, 1 identification, 2 impersonation, 3 delegation.
    Windows answers a refused impersonation by handing the thread an identification-level token,
    and the call that asked for it still reports success. So the level has to be read, not
    inferred from that call.
    """
    _require_windows()
    advapi32, kernel32 = _dlls()
    token = wintypes.HANDLE()
    if not advapi32.OpenThreadToken(
        kernel32.GetCurrentThread(), TOKEN_QUERY, True, ctypes.byref(token)
    ):
        if ctypes.get_last_error() == _ERROR_NO_TOKEN:
            return None
        raise _win_error("OpenThreadToken")
    try:
        described = _describe_token(advapi32, kernel32, token)
        described["impersonation_level"] = int(
            ctypes.c_int.from_buffer(_token_info(advapi32, token, _CLASS_IMPERSONATION_LEVEL)).value
        )
        return described
    finally:
        kernel32.CloseHandle(token)


def _write_result(directory: Path | None, exc: OSError | None = None) -> dict[str, Any]:
    """One write attempt as a report entry: ``wrote`` is true exactly when nothing was raised."""
    return {
        "directory": None if directory is None else str(directory),
        "wrote": exc is None,
        "errno": None if exc is None else exc.errno,
        "error": None if exc is None else f"{type(exc).__name__}: {exc}",
    }


def try_write(directory: Path) -> dict[str, Any]:
    """Create and delete one file in ``directory``. Reports what happened; never raises."""
    target = directory / f"token-probe-{os.getpid()}.tmp"
    try:
        with open(target, "xb") as handle:
            handle.write(b"probe")
    except OSError as exc:
        return _write_result(directory, exc)
    with contextlib.suppress(OSError):
        target.unlink()
    return _write_result(directory)


def try_alternate_credential(granted: Path, denied: Path) -> dict[str, Any]:
    """One call through the engine's own alternate-credential path, with a made-up credential.

    ``wincred`` logs on with LOGON32_LOGON_NEW_CREDENTIALS, which Windows does not check until the
    thread reaches a network share. So a made-up user is enough to run the two calls the token
    could break: LogonUserW and ImpersonateLoggedOnUser. One file is written to each local
    directory while impersonating. The write to the granted one fails if the thread was handed an
    identification-level token. The thread's token is reported too, and the write to the other
    directory shows by behaviour whether that token is still write-restricted.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    try:
        from messagefoundry.transports import wincred
    except Exception as exc:  # the engine may not be importable where this runs
        return {"ran": False, "error": f"{type(exc).__name__}: {exc}"}

    def under_credential() -> dict[str, Any]:
        return {
            "thread_token": read_thread_token(),
            "granted": try_write(granted),
            "denied": try_write(denied),
        }

    async def run() -> dict[str, Any]:
        # A value made up on the spot. Nobody holds it, and no account is named by it.
        ctx = wincred.CredentialContext(
            username="mefor-token-probe", password=uuid.uuid4().hex, domain="MEFOR-PROBE"
        )
        try:
            return await ctx.run(under_credential)
        finally:
            await ctx.close()

    try:
        inner = asyncio.run(run())
    except OSError as exc:
        return {"ran": True, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"ran": True, "ok": True, "error": None, **inner}


def try_temp_write() -> dict[str, Any]:
    """One write to the directory Python picks for temporary files. Never raises.

    Python raises when no candidate is writable, and that is a reading too: it is what the engine
    would meet the first time it asked for a temporary file.
    """
    try:
        return try_write(Path(tempfile.gettempdir()))
    except OSError as exc:
        return _write_result(None, exc)


#: The readings an ``inside`` report holds. A report without one of them is not a pass.
INSIDE_STEPS = ("token", "granted", "denied", "temp", "wincred")


def _inside(args: argparse.Namespace) -> int:
    granted, denied = Path(args.granted_dir), Path(args.denied_dir)
    report: dict[str, Any] = {}
    steps = {
        "token": lambda: read_token(None),
        "granted": lambda: try_write(granted),
        "denied": lambda: try_write(denied),
        "temp": try_temp_write,
        "wincred": lambda: try_alternate_credential(granted, denied),
    }
    for name in INSIDE_STEPS:
        # One step's failure must not cost the others, so each is caught and named on its own.
        try:
            report[name] = steps[name]()
        except Exception as exc:
            report[name] = None
            report.setdefault("probe_errors", {})[name] = f"{type(exc).__name__}: {exc}"
    # Written under a temporary name and renamed, so the leg never reads half a report.
    out = Path(args.report)
    staged = out.with_name(out.name + ".part")
    staged.write_text(json.dumps(report, indent=2), encoding="utf-8")
    os.replace(staged, out)
    # Stay up, so the service that ran this is still running when the leg stops it. A program that
    # exits by itself leaves the leg's own stop step to fail on a service that is already stopped.
    time.sleep(args.hold_seconds)
    return 0


#: Groups a service account belongs to that a restricted service SID stops counting for a write.
#: The directory the leg expects a refusal on grants these two and nothing in the restricting list.
BROAD_GROUPS = ("S-1-5-32-545", "S-1-5-11")  # BUILTIN\Users, Authenticated Users

#: SecurityImpersonation. Below it a thread can be identified but cannot act as the token.
_SECURITY_IMPERSONATION = 2


def token_problems(token: dict[str, Any], *, service_sid: str, privileges: list[str]) -> list[str]:
    """Why ``token`` is not the token a hardened service holds. Empty when it is.

    Three things, each checked on its own so a red says which one failed: the token is
    write-restricted, its restricting list names the service SID, and it holds exactly
    ``privileges``. A privilege that is held but switched off still counts as held.
    """
    if token.get("error"):
        return [f"its token could not be read: {token['error']}"]
    problems = []
    if not token["write_restricted"]:
        problems.append("it is not write-restricted")
    if service_sid not in token["restricting_sids"]:
        shown = ", ".join(token["restricting_sids"]) or "nothing"
        problems.append(f"its restricting list holds {shown}, not the service SID {service_sid}")
    if sorted(token["privileges"]) != sorted(privileges):
        problems.append(
            f"it holds {', '.join(token['privileges']) or 'no privilege'}, "
            f"not exactly {', '.join(sorted(privileges))}"
        )
    return problems


def inside_problems(
    report: dict[str, Any], *, service_sid: str, privileges: list[str]
) -> list[str]:
    """Why the report ``inside`` wrote does not show a hardened service that still works.

    Every step must be in the report. One that is missing was never run, and is not a pass.
    """
    problems = [
        f"the report has no {step} reading" for step in INSIDE_STEPS if not report.get(step)
    ]
    problems += [
        f"the {step} step failed: {why}" for step, why in report.get("probe_errors", {}).items()
    ]
    token = report.get("token")
    if token:
        problems += token_problems(token, service_sid=service_sid, privileges=privileges)
        # THE CONTROL FOR THE REFUSAL. The refused directory grants only the broad groups. If the
        # token is in neither, an unrestricted token would be refused there too, and the refusal
        # would say nothing about the restriction.
        enabled = {g["sid"] for g in token["groups"] if g["enabled"] and not g["deny_only"]}
        if not enabled.intersection(BROAD_GROUPS):
            problems.append(
                "CONTROL FAILED: the token is in neither Users nor Authenticated Users, so a "
                "refused write to a directory that grants only those proves nothing"
            )
    granted, denied, temp = report.get("granted"), report.get("denied"), report.get("temp")
    if granted and not granted["wrote"]:
        problems.append(f"it could not write {granted['directory']}, which names it in a grant")
    if denied and denied["wrote"]:
        problems.append(
            f"it wrote {denied['directory']}, which grants only Users and Authenticated Users: "
            "the token is not restricted to the service's own grants"
        )
    if temp and not temp["wrote"]:
        problems.append(
            f"it could not write its temporary directory ({temp['directory']}): {temp['error']}"
        )
    cred = report.get("wincred")
    if cred:
        if not cred.get("ran"):
            problems.append(f"the alternate-credential call could not be run: {cred.get('error')}")
        elif not cred.get("ok"):
            problems.append(f"the alternate-credential logon failed: {cred.get('error')}")
        else:
            thread = cred.get("thread_token")
            level = thread["impersonation_level"] if thread else None
            if level is None or level < _SECURITY_IMPERSONATION:
                problems.append(
                    f"the alternate-credential thread ran at impersonation level {level}, below "
                    f"{_SECURITY_IMPERSONATION}: Windows refused the impersonation"
                )
            if not cred["granted"]["wrote"]:
                problems.append("a write under the alternate credential failed")
    return problems


def _report_problems(subject: str, problems: list[str]) -> None:
    for problem in problems:
        print(f"FAIL: {subject}: {problem}")


def _check_read(args: argparse.Namespace) -> int:
    rule = {"service_sid": args.service_sid, "privileges": args.privilege}
    failed = False
    for pid in args.pid:
        # A process that cannot be read is judged like any other reading, and fails. Raising here
        # would hide every reading this call did get.
        try:
            token = read_token(pid)
        except OSError as exc:
            token = {"pid": pid, "error": str(exc)}
        print(json.dumps(token, indent=2))
        problems = token_problems(token, **rule)
        _report_problems(f"process {pid}", problems)
        failed = failed or bool(problems)
    control = read_token(args.control_pid)
    print(json.dumps(control, indent=2))
    if not token_problems(control, **rule):
        print(
            f"FAIL: CONTROL: process {args.control_pid} is not the service and still reads as "
            "hardened, so this reader cannot tell a hardened token from any other"
        )
        failed = True
    if not failed:
        print(
            f"OK: {len(args.pid)} service process(es) hold the hardened token; the control does not"
        )
    return 1 if failed else 0


def _check_inside(args: argparse.Namespace) -> int:
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    print(json.dumps(report, indent=2))
    problems = inside_problems(report, service_sid=args.service_sid, privileges=args.privilege)
    _report_problems("the service", problems)
    if not problems:
        cred = report["wincred"]
        print(
            "OK: the service token is restricted, wrote where it is granted and was refused "
            "where it is not. Under the alternate credential the thread token read "
            f"write_restricted={cred['thread_token']['write_restricted']} and a write to the "
            f"ungranted directory returned wrote={cred['denied']['wrote']}."
        )
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    _require_windows()
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    read = sub.add_parser("check-read", help="read each process's token and judge it")
    read.add_argument("--pid", type=int, action="append", required=True)
    read.add_argument("--control-pid", type=int, required=True)
    read.set_defaults(run=_check_read)
    inside = sub.add_parser("inside", help="report this process's token and what it can write")
    inside.add_argument("--report", required=True)
    inside.add_argument("--granted-dir", required=True)
    inside.add_argument("--denied-dir", required=True)
    inside.add_argument("--hold-seconds", type=float, default=0.0)
    inside.set_defaults(run=_inside)
    judged = sub.add_parser("check-inside", help="judge a report the inside mode wrote")
    judged.add_argument("--report", required=True)
    judged.set_defaults(run=_check_inside)
    for rule in (read, judged):
        rule.add_argument("--service-sid", required=True)
        rule.add_argument("--privilege", action="append", required=True)
    args = parser.parse_args(argv)
    return int(args.run(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
