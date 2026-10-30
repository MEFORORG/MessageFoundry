# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The AppContainer spike's judge may not turn a broken instrument into an answer (vault BACKLOG
#3411, wave 3.1).

``scripts/ci/appcontainer_spike_worker.py`` runs as a Windows service on a hosted runner, starts
itself inside an AppContainer, and reports what the system allowed. :func:`judge_reports` turns
those reports into the four answers. The danger in a spike is an answer the instrument never
earned: a "refused" read of a file that was never there, a container that was not one, a key
store that refuses every name. So every case below hands the judge reports where one control
fails and checks the answer becomes UNANSWERED, and the all-good case is the positive control that
the judge can say YES at all.

These run anywhere: the judge reads dictionaries and files, and no case calls Windows.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[1]
_WORKER = _REPO / "scripts" / "ci" / "appcontainer_spike_worker.py"
_RIG = _REPO / "scripts" / "ci" / "appcontainer_spike.ps1"
OWNER_SID = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-555555555"
ADMIN_SID = "S-1-5-21-1000000001-1000000002-1000000003-500"
PACKAGE = "S-1-15-2-1-2-3-4-5-6-7"
CONTROL_PACKAGE = "S-1-15-2-7-6-5-4-3-2-1"
ADMINS = "S-1-5-32-544"
PRIVILEGES = ["SeChangeNotifyPrivilege"]
BLOB_SHA = "ab" * 32


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("appcontainer_spike_worker", _WORKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["appcontainer_spike_worker"] = module
    spec.loader.exec_module(module)
    return module


W = _load()


def _status(code: int) -> dict[str, Any]:
    """A status record, by the worker's own writer, so a fixture cannot drift from a report."""
    return dict(W._record(code))


OK = _status(0)
BAD_KEYSET = 0x80090016
NOT_FOUND = 0x80070002


def _token() -> dict[str, Any]:
    """The installer's hardened service token, in the shape service_token_probe.read_token returns."""
    return {
        "user": OWNER_SID,
        "groups": [
            {"sid": "S-1-5-32-545", "enabled": True, "deny_only": False, "logon_id": False},
            {"sid": ADMINS, "enabled": False, "deny_only": True, "logon_id": False},
        ],
        "privileges": list(PRIVILEGES),
        "restricting_sids": [OWNER_SID, "S-1-1-0"],
        "flags": 8,
        "write_restricted": True,
    }


def _facts(user: str, package: str | None) -> dict[str, Any]:
    return {
        "user": user,
        "is_appcontainer": package is not None,
        "package_sid": package,
        "integrity": W.LOW_INTEGRITY if package else "S-1-16-12288",
    }


def _sddl(*trustees: str) -> str:
    aces = "".join(f"(A;ID;0x1200a9;;;{t})" for t in trustees)
    return f"O:BAG:SYD:AI{aces}"


def _good() -> dict[str, Any]:
    owner = {
        "role": "owner",
        "facts": _facts(OWNER_SID, None),
        "token": _token(),
        "protect": {"ok": True, "error": None},
        "blob_sha256": BLOB_SHA,
        "owner_unprotect": {"ok": True, "error": None, "matches": True},
        "owner_read_denied": {"ok": True, "error": None, "win32": None, "matches": True},
        "provider": OK,
        "key_create": OK,
        "owner_key": {"open": OK, "sign": {**OK, "signature_hex": "01"}, "self_verify": OK},
        "owner_absent_key": {"open": _status(BAD_KEYSET)},
        "profile": {"name": W.PROFILE, "created": True, "sid": PACKAGE},
        "launch": {"started": True, "pid": 7, "exit_code": 0, "exit_text": "0x00000000"},
        "window_grant": {
            "window_station": {"ok": True, "error": None, "dacl": "ok", "label": "ok"},
            "desktop": {"ok": True, "error": None, "dacl": "ok", "label": "ok"},
        },
        "container_fatal": False,
        "container_signature_verified": OK,
    }
    container = {
        "role": "container",
        "facts": _facts(OWNER_SID, PACKAGE),
        "given_sha256": BLOB_SHA,
        "unprotect_given": {"ok": True, "error": None, "matches": True},
        "unprotect_tampered": {
            "ok": False,
            "matches": False,
            "error": "DpapiError: CryptUnprotectData failed (Win32 error 13)",
        },
        "own_roundtrip": {"ok": True, "error": None, "matches": True, "stage": "unprotect"},
        "read_denied": {"ok": False, "error": "CreateFileW failed (win32 error 5)", "win32": 5},
        "read_granted": {"ok": True, "error": None, "win32": None, "matches": True},
        "provider": OK,
        "key": {"open": OK, "sign": {**OK, "signature_hex": "02"}, "self_verify": OK},
        "absent_key": {"open": _status(NOT_FOUND)},
        "ephemeral": {"ok": True, "stage": "verify", "status_text": "0x00000000"},
    }
    control = {
        "role": "control",
        "facts": _facts(ADMIN_SID, None),
        "profile": {"name": W.CONTROL_PROFILE, "created": True, "sid": CONTROL_PACKAGE},
        "launch": {"started": True, "exit_code": 0},
        "container": {"role": "container", "facts": _facts(ADMIN_SID, CONTROL_PACKAGE)},
    }
    acl = {
        "denied": _sddl("SY", "BA", OWNER_SID),
        "granted": _sddl("SY", "BA", OWNER_SID, "AC"),
        "interpreter": _sddl("SY", "BA", "AC"),
    }
    return {
        "owner": owner,
        "container": container,
        "control": control,
        "acl": acl,
        "owner_sid": OWNER_SID,
        "privileges": list(PRIVILEGES),
    }


def _judge(case: dict[str, Any]) -> dict[str, Any]:
    return {a.key: a for a in W.judge_reports(**case)}


def _answers(case: dict[str, Any]) -> dict[str, str]:
    return {key: a.answer for key, a in _judge(case).items()}


_DELETE = object()


def _mutate(path: str, value: Any) -> dict[str, Any]:
    # A deep copy, so no case can edit a record that _good() shares, such as OK.
    case = copy.deepcopy(_good())
    *parents, leaf = path.split(".")
    node = case
    for key in parents:
        node = node[key]
    if value is _DELETE:
        del node[leaf]
    else:
        node[leaf] = value
    return case


ALL_YES = {"Q1": "YES", "Q2": "YES", "Q3": "YES", "Q4": "YES"}


def test_the_all_good_reports_answer_yes_four_times() -> None:
    # The positive control: a judge that can only say UNANSWERED would pass every case below.
    assert _answers(_good()) == ALL_YES


@pytest.mark.parametrize(
    ("path", "value", "key", "detail"),
    [
        # Each question measured NO: a finding, beside every control.
        (
            "container.unprotect_given",
            {"ok": False, "error": "DpapiError: x"},
            "Q2",
            "DPAPI refused",
        ),
        (
            "container.read_denied",
            {"ok": True, "win32": None, "matches": True},
            "Q3",
            "READ the file",
        ),
        ("container.key", {"open": _status(NOT_FOUND)}, "Q4", "nobody made"),
        ("container.key", {"open": _status(0x80090010)}, "Q4", "NTE_PERM"),
        ("container.key", {"open": _status(0x80070005)}, "Q4", "E_ACCESSDENIED"),
        ("container.key", {"open": OK, "sign": _status(0x80090010)}, "Q4", "signing refused"),
    ],
)
def test_a_refusal_beside_every_control_is_a_no(
    path: str, value: Any, key: str, detail: str
) -> None:
    judged = _judge(_mutate(path, value))
    assert {k: a.answer for k, a in judged.items()} == {**ALL_YES, key: "NO"}
    assert detail in judged[key].detail
    if value.get("open", {}).get("status") in (0x80090010, 0x80070005):
        # A status the absent name did not give is not the "store does not hold it" reading.
        assert "nobody made" not in judged[key].detail


@pytest.mark.parametrize(
    ("launch", "detail"),
    [
        (
            {"started": False, "error": "CreateProcessW failed (win32 error 5)", "win32": 5},
            "could not start",
        ),
        # STATUS_DLL_NOT_FOUND: the interpreter itself did not load.
        (
            {
                "started": True,
                "exit_code": 0xC0000135,
                "exit_text": "0xC0000135",
                "timed_out": False,
            },
            "died before CPython ran",
        ),
    ],
)
def test_a_container_the_service_could_not_run_is_a_no_and_the_rest_are_not_run(
    launch: dict[str, Any], detail: str
) -> None:
    case = _mutate("owner.launch", launch)
    case["container"] = None
    judged = _judge(case)
    assert {k: a.answer for k, a in judged.items()} == {
        "Q1": "NO",
        "Q2": "NOT RUN",
        "Q3": "NOT RUN",
        "Q4": "NOT RUN",
    }
    assert detail in judged["Q1"].detail


@pytest.mark.parametrize(
    ("launch", "fatal"),
    [
        # The script crashed inside the container: an instrument defect, not the account's answer.
        ({"started": True, "exit_code": 1, "timed_out": False}, True),
        # The owner never looked for a crash file, so a missing report cannot be read either way.
        ({"started": True, "exit_code": 1, "timed_out": False}, _DELETE),
        # The launcher failed before CreateProcessW: no "started" at all.
        ({"error": "UpdateProcThreadAttribute(0x20009) failed (win32 error 87)"}, False),
        # CreateProcessW failed, but not as a refusal: a bad parameter is the launcher's own.
        ({"started": False, "error": "CreateProcessW failed (win32 error 87)", "win32": 87}, False),
        # CPython's own exit codes: it started, so a missing report is not the account's NO.
        ({"started": True, "exit_code": 2, "exit_text": "0x00000002", "timed_out": False}, False),
        ({"started": True, "exit_code": 1, "timed_out": False}, False),
        # A container that hung until the owner killed it may or may not have started CPython.
        ({"started": True, "exit_code": 0xC0000135, "timed_out": True}, False),
    ],
)
def test_a_missing_report_the_instrument_explains_is_unanswered(
    launch: dict[str, Any], fatal: Any
) -> None:
    case = _mutate("owner.container_fatal", fatal)
    case["owner"]["launch"] = launch
    case["container"] = None
    assert _answers(case) == dict.fromkeys(ALL_YES, "UNANSWERED")


@pytest.mark.parametrize(
    ("code", "text"),
    [
        # The first hosted run: CPython started in the service's container, died importing _ctypes.
        (1, "0x00000001"),
        # 0xC0000409, the fail-fast an abort() inside CPython ends in: NTSTATUS, but not the loader.
        (0xC0000409, "0xC0000409"),
        # 0xC0000142, a DLL whose start-up failed: what a process unable to attach to its desktop gets.
        (0xC0000142, "0xC0000142"),
    ],
)
def test_a_crash_before_the_first_report_is_named_with_its_last_line(code: int, text: str) -> None:
    tail = "ImportError: DLL load failed while importing _ctypes: initialization routine failed."
    launch = {
        "started": True,
        "exit_code": code,
        "exit_text": text,
        "timed_out": False,
        "log_tail": tail,
    }
    case = _mutate("owner.launch", launch)
    case["container"] = None
    judged = _judge(case)
    assert {k: a.answer for k, a in judged.items()} == dict.fromkeys(ALL_YES, "UNANSWERED")
    detail = judged["Q1"].detail
    assert "crashed before its first report" in detail and text in detail, detail
    assert tail in detail and W.CONTAINER_LOG in detail, detail
    assert "window station grant ok, desktop grant ok" in detail, detail


@pytest.mark.parametrize(
    "launch",
    [
        # A timeout is not a crash: the owner killed it.
        {"started": True, "exit_code": 1, "exit_text": "0x00000001", "timed_out": True},
        # A failed wait: the owner killed it with exit 1, CPython's own code.
        {
            "started": True,
            "exit_code": 1,
            "exit_text": "0x00000001",
            "timed_out": False,
            "wait_status": "0xFFFFFFFF",
        },
        # No timed_out key: the launcher's wait never ran, so nothing says how it ended.
        {"started": True, "exit_code": 1, "exit_text": "0x00000001"},
        # Exit 0 with no report is not a crash either.
        {"started": True, "exit_code": 0, "exit_text": "0x00000000", "timed_out": False},
    ],
)
def test_only_an_exit_of_its_own_reads_as_a_crash(launch: dict[str, Any]) -> None:
    case = _mutate("owner.launch", launch)
    case["container"] = None
    judged = _judge(case)
    assert judged["Q1"].answer == "UNANSWERED"
    assert "crashed" not in judged["Q1"].detail, judged["Q1"].detail


@pytest.mark.parametrize(
    "launch",
    [
        {"started": False, "error": "CreateProcessW failed (win32 error 5)", "win32": 5},
        {"started": True, "exit_code": 0xC0000135, "exit_text": "0xC0000135", "timed_out": False},
    ],
)
@pytest.mark.parametrize(
    "grant",
    [
        {"ok": False, "error": "DACL SetSecurityInfo failed (win32 error 5); label ok"},
        None,
    ],
)
def test_a_no_needs_the_launchers_own_grant_to_have_held(
    launch: dict[str, Any], grant: Any
) -> None:
    # Without the grant, a container that could not start or load is the launcher's failure.
    case = _mutate("owner.launch", launch)
    case["owner"]["window_grant"]["desktop"] = grant
    case["container"] = None
    judged = _judge(case)
    assert {k: a.answer for k, a in judged.items()} == dict.fromkeys(ALL_YES, "UNANSWERED")
    assert "the launcher's own grant failed" in judged["Q1"].detail, judged["Q1"].detail


def test_a_crash_file_is_named_before_a_failed_grant() -> None:
    # The worker raised inside the container, so CPython ran: the crash file is the cause to read.
    case = _mutate("owner.container_fatal", True)
    case["owner"]["launch"] = {"started": True, "exit_code": 1, "timed_out": False}
    case["owner"]["window_grant"]["desktop"] = {"ok": False, "error": "label refused"}
    case["container"] = None
    assert "container-fatal.txt" in _judge(case)["Q1"].detail


@pytest.mark.parametrize(
    ("mode", "env", "user", "refused"),
    [
        ("control", {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}, None, False),
        ("control", {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}, None, True),
        ("control", {}, None, True),
        ("owner", {}, OWNER_SID, False),
        (
            "owner",
            {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"},
            ADMIN_SID,
            True,
        ),
        ("owner", {}, None, True),
        ("container", {}, None, False),
        ("judge", {}, None, False),
    ],
)
def test_the_modes_that_change_the_host_refuse_off_the_runner(
    mode: str, env: dict[str, str], user: str | None, refused: bool
) -> None:
    refusal = W.off_runner_refusal(mode, env, lambda: {"user": user})
    assert (refusal is not None) == refused, refusal
    if refusal:
        assert refusal.startswith("STOP ") and refusal.endswith("nothing ran"), refusal


@pytest.mark.skipif(sys.platform != "win32", reason="window stations are Windows objects")
def test_the_grant_adds_one_ace_and_the_low_label_to_a_private_desktop() -> None:
    # A desktop made for this test and destroyed when its last handle closes: no live session's
    # object is touched. The SID is derived from a name; no AppContainer profile is made.
    import ctypes
    from ctypes import wintypes

    api = W._window_api()
    api.user32.CreateDesktopW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    api.user32.CreateDesktopW.restype = wintypes.HANDLE
    name = f"MeforAcSpikeTest{os.getpid()}"
    desktop = api.user32.CreateDesktopW(name, None, None, 0, 0x000F01FF, None)
    if not desktop:
        pytest.skip("CreateDesktopW refused here")
    sid = ctypes.c_void_p()
    try:
        derived = W._win().userenv.DeriveAppContainerSidFromAppContainerName(
            "mefor.acspike.test", ctypes.byref(sid)
        )
        assert derived == 0, hex(derived & 0xFFFFFFFF)
        record = W.grant_window_object(
            name,
            lambda n, access: api.user32.OpenDesktopW(n, 0, False, access),
            api.user32.CloseDesktop,
            W._DESKTOP_CONTAINER_RIGHTS,
            sid.value,
            label=True,
        )
        assert record["ok"] is True and record["error"] is None, record
        assert W._grant_held({"window_grant": {"window_station": record, "desktop": record}})
        api.adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.c_void_p,
        )
        sd, text = ctypes.c_void_p(), wintypes.LPWSTR()
        info = W._DACL_SECURITY_INFORMATION | W._LABEL_SECURITY_INFORMATION
        assert (
            api.adv.GetSecurityInfo(desktop, 7, info, None, None, None, None, ctypes.byref(sd)) == 0
        )
        try:
            assert api.adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, 1, info, ctypes.byref(text), None
            )
            sddl = str(text.value)
            api.k32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        finally:
            api.k32.LocalFree(sd)
        package = W._sid_text(sid.value)
        assert package in (W.sddl_trustees(sddl) or []), sddl
        assert "S:(ML;;NW;;;LW)" in sddl, sddl
    finally:
        if sid.value:
            W._win().adv.FreeSid(sid)
        api.user32.CloseDesktop(desktop)


def test_the_grant_reads_into_the_detail_skipped_ok_or_missing() -> None:
    assert "window station grant ok, desktop grant ok" in _judge(_good())["Q1"].detail
    skipped = {"ok": True, "skipped": "WinSta0 grants ALL APPLICATION PACKAGES already"}
    case = _good()
    case["owner"]["window_grant"] = {"window_station": skipped, "desktop": skipped}
    judged = _judge(case)
    assert judged["Q1"].answer == "YES"
    assert "desktop grant skipped, WinSta0 grants" in judged["Q1"].detail, judged["Q1"].detail
    # A report from before the grant existed still answers a container that ran.
    del case["owner"]["window_grant"]
    judged = _judge(case)
    assert judged["Q1"].answer == "YES"
    assert "window station grant no record" in judged["Q1"].detail


def test_the_log_tail_is_the_last_line_the_container_printed(tmp_path: Path) -> None:
    log = tmp_path / W.CONTAINER_LOG
    assert "not read: FileNotFoundError" in str(W._log_tail(log))
    log.write_bytes(b"Traceback (most recent call last):\r\n  File x\r\nImportError: no\r\n\r\n")
    assert W._log_tail(log) == "ImportError: no"
    log.write_bytes(b"")
    assert W._log_tail(log) is None


def test_the_rig_puts_the_log_of_a_container_with_no_report_in_the_summary() -> None:
    rig = _RIG.read_text(encoding="utf-8")
    # The gate: a summary to write to, no report, and a log to put in it.
    gate = (
        'if ($Summary -and -not (Test-Path -LiteralPath (Join-Path $SharedDir "container.json"))'
        " -and\n            (Test-Path -LiteralPath $containerLog)) {"
    )
    assert gate in rig
    after = rig.split(gate, 1)[1]
    assert after.index("$logCap = 65536") < after.index("[IO.File]::AppendAllText($Summary,")


def test_a_profile_that_was_there_already_still_counts() -> None:
    case = _mutate("owner.profile", {"created": False, "create": "0x800700B7", "sid": PACKAGE})
    assert _answers(case) == ALL_YES


def test_the_arguments_the_owner_hands_the_container_parse() -> None:
    # A container that cannot parse its arguments exits before it writes a report, which would
    # read as the account's NO; this runs the same parser on the owner's own argument list.
    extra = W.container_args(b"\x01\x02\x03", Path("o") / W.DENIED_BLOB, Path("s"))
    args = W.build_parser().parse_args(["container", "--shared", "s", *extra])
    assert bytes.fromhex(args.blob_hex) == b"\x01\x02\x03"
    assert bytes.fromhex(args.tampered_hex) == b"\x01\x02\x02"
    assert Path(args.denied).name == W.DENIED_BLOB and Path(args.granted).name == W.GRANTED_BLOB


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        # Q1: the launcher must be the installer's service, and the instrument must work at all.
        ("owner.token.user", ADMIN_SID, "Q1"),
        ("owner.token.write_restricted", False, "Q1"),
        ("owner.token.privileges", [*PRIVILEGES, "SeImpersonatePrivilege"], "Q1"),
        ("owner.token", {"error": "OSError: access denied"}, "Q1"),
        ("owner.token.groups", [{"sid": ADMINS, "enabled": True, "deny_only": False}], "Q1"),
        # The reader's own control: the launcher's token must not read as a container.
        ("owner.facts.is_appcontainer", True, "Q1"),
        ("owner.facts.is_appcontainer", None, "Q1"),
        ("acl.interpreter", _sddl("SY", "BA"), "Q1"),
        ("acl.interpreter", None, "Q1"),
        ("control", None, "Q1"),
        ("control.container", None, "Q1"),
        ("control.container.facts.is_appcontainer", False, "Q1"),
        ("control.container.facts.package_sid", PACKAGE, "Q1"),
        ("control.container.facts.integrity", "S-1-16-8192", "Q1"),
        ("owner.profile.sid", None, "Q1"),
        ("owner.protect", {"ok": False, "error": "DpapiError: x"}, "Q1"),
        ("owner", None, "Q1"),
        # A report that came back, but not from a container of this profile, for this account.
        ("container.facts.is_appcontainer", False, "Q1"),
        ("container.facts.package_sid", CONTROL_PACKAGE, "Q1"),
        ("container.facts.user", ADMIN_SID, "Q1"),
        ("container.facts.integrity", "S-1-16-8192", "Q1"),
        ("container.facts", None, "Q1"),
        # Q2: a refusal counts only beside the service opening the same bytes and a tamper refused.
        ("owner.owner_unprotect", {"ok": True, "matches": False}, "Q2"),
        ("container.given_sha256", "cd" * 32, "Q2"),
        ("container.unprotect_tampered", {"ok": True, "matches": False, "error": None}, "Q2"),
        ("container.unprotect_tampered", {"ok": False, "error": "MemoryError: "}, "Q2"),
        ("container.unprotect_given", {"ok": False, "error": "MemoryError: "}, "Q2"),
        ("container.unprotect_given", {"ok": True, "matches": False, "error": None}, "Q2"),
        # DPAPI that fails for every input would refuse the tamper too; its own blob shows it works.
        (
            "container.own_roundtrip",
            {"ok": False, "error": "DpapiError: x", "stage": "protect"},
            "Q2",
        ),
        ("container.own_roundtrip", {"ok": True, "matches": False, "stage": "unprotect"}, "Q2"),
        ("container.own_roundtrip", None, "Q2"),
        # Q3: a refusal counts only beside a granted read and the access lists it rests on.
        ("owner.owner_read_denied", {"ok": False, "win32": 5}, "Q3"),
        ("acl.denied", _sddl("SY", OWNER_SID, "AC"), "Q3"),
        ("acl.denied", _sddl("SY", OWNER_SID, "S-1-15-2-9-9"), "Q3"),
        ("acl.denied", _sddl("SY", OWNER_SID, "S-1-15-3-1"), "Q3"),
        ("acl.denied", _sddl("SY", "BA"), "Q3"),
        ("acl.denied", None, "Q3"),
        ("acl.granted", _sddl("SY", OWNER_SID), "Q3"),
        ("container.read_granted", {"ok": False, "win32": 5}, "Q3"),
        ("container.read_granted", {"ok": True, "matches": False}, "Q3"),
        # A file that is missing, or shared away, is not a refusal.
        ("container.read_denied", {"ok": False, "win32": 2, "error": "not found"}, "Q3"),
        ("container.read_denied", {"ok": False, "win32": 32, "error": "sharing"}, "Q3"),
        ("container.read_denied", {"ok": False, "win32": None, "error": "OSError"}, "Q3"),
        # Q4: a refusal counts only beside the service using the key and CNG working in the container.
        ("owner.key_create", _status(0x8009000F), "Q4"),
        ("owner.owner_key.open", _status(BAD_KEYSET), "Q4"),
        ("owner.owner_key.sign", _status(0x80090010), "Q4"),
        ("owner.owner_key.self_verify", _status(0x80090006), "Q4"),
        ("owner.owner_absent_key.open", OK, "Q4"),
        ("owner.owner_absent_key", None, "Q4"),
        ("container.ephemeral", {"ok": False, "stage": "create", "status_text": "x"}, "Q4"),
        ("container.ephemeral", None, "Q4"),
        # A signature the service's own key does not check came from some other key.
        ("owner.container_signature_verified", _status(0x80090006), "Q4"),
        ("owner.container_signature_verified", _DELETE, "Q4"),
        ("container.key", None, "Q4"),
        ("container.key", {"open": OK}, "Q4"),
        # A container on a derived SID with no profile has no key store of its own to ask.
        (
            "owner.profile",
            {"created": False, "create": "0x80070005 E_ACCESSDENIED", "sid": PACKAGE},
            "Q4",
        ),
        # A failure that is not a refusal is not a NO: a bad parameter, or an RPC that went away.
        ("container.key", {"open": _status(0x80090027)}, "Q4"),
        ("container.key", {"open": _status(0x800706BA)}, "Q4"),
        ("container.key", {"open": OK, "sign": _status(0x80090028)}, "Q4"),
    ],
)
def test_one_broken_input_makes_only_its_answer_unanswered(
    path: str, value: Any, expected: str
) -> None:
    answers = _answers(_mutate(path, value))
    if expected == "Q1":
        # Q2 to Q4 rest on Q1: with no container known to be one, none of them is answered.
        assert answers == dict.fromkeys(ALL_YES, "UNANSWERED"), path
    else:
        assert answers == {**ALL_YES, expected: "UNANSWERED"}, path


def test_every_control_case_above_starts_from_a_case_where_it_held() -> None:
    # A control that never held in the all-good case would make every mutation of it vacuous.
    answers = W.judge_reports(**_good())
    assert {a.key for a in answers if a.controls} == set(ALL_YES), [a.key for a in answers]
    rows = [(a.key, name, held) for a in answers for name, held, _ in a.controls]
    assert len(rows) >= 20, rows
    failed = [row for row in rows if not row[2]]
    assert not failed, failed


@pytest.mark.parametrize(
    ("sddl", "expected"),
    [
        ("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;;0x1200a9;;;AC)", ["SY", "AC"]),
        # A deny ace is not a grant.
        ("O:BAG:SYD:(D;;FA;;;AC)(A;;FA;;;SY)", ["SY"]),
        # An audit ace or the integrity label sits in the SACL and is never read as a grant.
        ("O:BAG:SYD:(A;;FA;;;SY)S:(AU;SA;FA;;;AC)(ML;;NW;;;LW)", ["SY"]),
        ("O:BAG:SY", None),
        (None, None),
        (7, None),
    ],
)
def test_the_sddl_reader_returns_allow_trustees_of_the_dacl_only(sddl: Any, expected: Any) -> None:
    assert W.sddl_trustees(sddl) == expected


def test_the_status_reader_names_known_codes_and_unsigned_negatives() -> None:
    # SECURITY_STATUS is signed, so NTE_BAD_KEYSET can arrive negative.
    assert W.status_text(-2146893802) == "0x80090016 NTE_BAD_KEYSET"
    assert W.status_text(0) == "0x00000000"
    assert W.status_text(None) == "no status"


def test_the_render_prints_every_answer_and_control_and_is_cp1252_safe() -> None:
    answers = W.judge_reports(**_good())
    text = W.render(answers, image="windows-2022", os_build="20348", account="NT SERVICE\\x")
    lines = [
        line for line in text.splitlines() if line.startswith("APPCONTAINER-SPIKE windows-2022 ")
    ]
    for key in ("Q1", "Q2", "Q3", "Q4"):
        assert any(
            line.startswith(f"APPCONTAINER-SPIKE windows-2022 {key} ") and line.endswith(": YES")
            for line in lines
        ), key
    held = sum(" control HELD: " in line for line in lines)
    assert held == sum(len(a.controls) for a in answers) and held >= 20, held
    assert not any(" control FAILED: " in line for line in lines)
    text.encode("cp1252")
    # A character cp1252 cannot hold, from a Win32 message, is replaced rather than raised later.
    case = _mutate(
        "container.unprotect_given", {"ok": False, "error": "DpapiError: " + chr(0x2192) + " no"}
    )
    W.render(W.judge_reports(**case), image="x", os_build="1", account="a").encode("cp1252")


def test_a_not_run_answer_prints_no_control_lines() -> None:
    case = _mutate("owner.launch", {"started": False, "error": "refused", "win32": 5})
    case["container"] = None
    text = W.render(W.judge_reports(**case), image="w", os_build="1", account="a")
    assert sum(line.endswith(": NOT RUN") for line in text.splitlines()) == 3, text
    assert not any(
        re.match(r"APPCONTAINER-SPIKE w Q[234] control", line) for line in text.splitlines()
    )


def _write_tree(tmp_path: Path, case: dict[str, Any]) -> dict[str, Path]:
    dirs = {name: tmp_path / name for name in ("owner", "shared", "control")}
    for path in dirs.values():
        path.mkdir()
    files = W.judge_files(dirs["owner"], dirs["shared"], dirs["control"])
    for key in ("owner", "container", "control", "acl"):
        if case[key] is not None:
            files[key].write_text(json.dumps(case[key]), encoding="utf-8")
    return dirs


def _run_main(dirs: dict[str, Path], summary: Path) -> int:
    argv = ["judge", "--owner-dir", str(dirs["owner"]), "--shared-dir", str(dirs["shared"])]
    argv += ["--control-dir", str(dirs["control"]), "--owner-sid", OWNER_SID]
    argv += ["--owner-account", "NT SERVICE\\MeforAcSpikeA", "--privilege", PRIVILEGES[0]]
    argv += ["--image", "windows-2025", "--summary", str(summary)]
    return int(W.main(argv))


def test_the_judge_reads_the_files_and_a_no_is_still_a_green_run(tmp_path: Path) -> None:
    case = _mutate("container.key", {"open": _status(NOT_FOUND)})
    summary = tmp_path / "summary.md"
    summary.write_text("earlier step\n", encoding="utf-8")
    assert _run_main(_write_tree(tmp_path, case), summary) == 0
    text = summary.read_text(encoding="utf-8")
    assert text.startswith("earlier step\n"), "the summary must be appended to, not replaced"
    assert re.search(r"APPCONTAINER-SPIKE windows-2025 Q4 .*: NO$", text, re.M), text


def test_an_unanswered_question_makes_the_run_red(tmp_path: Path) -> None:
    case = _good()
    case["acl"] = None
    # Its own code, not 1, which CPython exits with on a traceback.
    assert _run_main(_write_tree(tmp_path, case), tmp_path / "summary.md") == W.EXIT_UNANSWERED == 3
    assert "($judged -eq 3)" in _RIG.read_text(encoding="utf-8")
    assert ": UNANSWERED" in (tmp_path / "summary.md").read_text(encoding="utf-8")


def test_a_report_with_a_byte_order_mark_still_reads(tmp_path: Path) -> None:
    # Windows PowerShell 5.1 writes one with -Encoding UTF8, and the rig writes acl.json.
    dirs = _write_tree(tmp_path, _good())
    acl = W.judge_files(dirs["owner"], dirs["shared"], dirs["control"])["acl"]
    acl.write_bytes(b"\xef\xbb\xbf" + acl.read_bytes())
    assert W._load(acl) == _good()["acl"]


def test_the_rig_names_exactly_the_files_the_judge_reads() -> None:
    # The rig is PowerShell and cannot import the worker's names, so the two sets are compared here.
    worker = {p.name for p in W.judge_files(Path("o"), Path("s"), Path("c")).values()}
    assert worker, "CONTROL FAILED: judge_files() names no file"
    rig = set(re.findall(r'"([\w-]+\.(?:json|blob))"', _RIG.read_text(encoding="utf-8")))
    assert rig == worker, f"rig only: {sorted(rig - worker)}; worker only: {sorted(worker - rig)}"
