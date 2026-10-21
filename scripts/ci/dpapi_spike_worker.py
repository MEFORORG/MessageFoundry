#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""User-scope DPAPI under a real Windows service: a spike that measures and builds nothing.

Vault BACKLOG #3411, wave 3.0 (the Windows half of drafts-index item 6). The key-custody draft makes
user-scope DPAPI, performed by the service account itself, the Windows default wrap for the master
key. That rests on behaviour nobody had run here. This script is the instrument that runs it, and
``.github/workflows/dpapi-spike.yml`` (through ``scripts/ci/dpapi_spike.ps1``) is the rig.

It calls the engine's own ``messagefoundry.secrets_dpapi.dpapi_protect(machine_scope=False)`` and
``dpapi_unprotect``, so what it measures is the call the product makes, not a copy of it. Only the
synthetic constant :data:`PAYLOAD` is ever protected. No secret is read, made or printed. Each
process's token is read with ``service_token_probe.read_token``, the reader the windows-service-smoke
leg reads the engine's token with, and judged with that module's ``token_problems``.

Modes:

``owner --dir DIR``
    Run AS the service ``NT SERVICE\\<name>``, registered the way ``install-service.ps1`` registers
    the engine. On the first start it protects :data:`PAYLOAD` in user scope and in machine scope,
    then unprotects the user-scope blob it wrote. On every later start it unprotects that blob
    again. Each start writes ``owner-start-<n>.json``.

``other --dir DIR``
    Run AS a second, non-elevated local account, under a service of its own. It tries the owner's
    user-scope blob (the question), the owner's machine-scope blob (a control: this account can
    open the owner's blobs when the scope allows it), and a user-scope round trip of its own (a
    control: DPAPI works for this account at all). It writes ``other.json``.

``judge --owner-dir D --other-dir D --owner-sid S --other-sid S --owner-account A``
``--other-account B --privilege P --image I [--summary F]``
    Run by the rig, elevated, once both services have reported. It reads the reports and prints
    the three answers with their controls, and appends them to ``--summary`` when given.

Reading and judging are kept apart, as in ``service_token_probe.py``: the two service modes only
report, and :func:`judge_reports` holds the whole rule as a plain function over the reports, so
``tests/test_dpapi_spike_judge.py`` can hand it reports that must not pass.

The reboot arm of the draft's third question is NOT run. A hosted runner cannot reboot inside a
job, and the summary says so on every run.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import importlib.util
import json
import os
import re
import sys
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The only bytes this spike protects. Synthetic and constant: not a key, not a secret.
PAYLOAD = b"MessageFoundry DPAPI spike payload, synthetic, not a secret (BACKLOG #3411)"

USER_BLOB = "user.blob"
MACHINE_BLOB = "machine.blob"
OWN_USER_BLOB = "own-user.blob"
#: The names the rig gives its byte-for-byte copies of the owner's blobs in the other account's
#: folder. The other account reads only these copies, never the owner's folder.
FOREIGN_USER_BLOB = "owner-user.blob"
FOREIGN_MACHINE_BLOB = "owner-machine.blob"
OTHER_REPORT = "other.json"


def owner_report(start: int | str) -> str:
    return f"owner-start-{start}.json"


YES, NO, NOT_RUN, INCONCLUSIVE = "YES", "NO", "NOT RUN", "INCONCLUSIVE"

# secrets_dpapi.DpapiError carries the code only in its message, and this spike changes no product
# code. If that wording changes, the code reads as None and the detail line still has the message.
# ctypes.get_last_error() is signed, so an HRESULT such as NTE_BAD_KEY_STATE prints negative.
_WIN32_CODE = re.compile(r"Win32 error (-?\d+)")
_ADMINISTRATORS = "S-1-5-32-544"


# --------------------------------------------------------------------------------- reading (inside)


@functools.cache
def _dpapi() -> Any:
    # The service runs this with -I, so the checkout is not on sys.path. secrets_dpapi imports only
    # the standard library at load, and the package's __init__ imports nothing at run time.
    root = str(Path(__file__).resolve().parents[2])
    if root not in sys.path:
        sys.path.insert(0, root)
    from messagefoundry import secrets_dpapi

    return secrets_dpapi


@functools.cache
def _token_probe() -> Any:
    """``service_token_probe.py``, beside this file, loaded by path: scripts/ci is not a package."""
    path = Path(__file__).resolve().with_name("service_token_probe.py")
    spec = importlib.util.spec_from_file_location("service_token_probe", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _attempt(call: Callable[[], bytes]) -> tuple[dict[str, Any], bytes | None]:
    """Run one DPAPI call. The record never holds the bytes, only whether the call worked.

    Only what secrets_dpapi raises for a failed call is a measurement. Anything else is a defect in
    this instrument, so it propagates and main() writes the traceback beside the reports.
    """
    dpapi = _dpapi()
    try:
        out = call()
    except (dpapi.DpapiError, dpapi.DpapiUnavailable) as exc:
        text = f"{type(exc).__name__}: {exc}"
        found = _WIN32_CODE.search(text)
        code = int(found.group(1)) & 0xFFFFFFFF if found else None
        return {"ok": False, "error": text, "win32": code}, None
    return {"ok": True, "error": None, "win32": None}, out


def _unprotect(blob_path: Path) -> dict[str, Any]:
    try:
        blob = blob_path.read_bytes()
    except OSError as exc:
        return {"ok": False, "read": False, "error": f"could not read {blob_path}: {exc}"}
    record, out = _attempt(lambda: _dpapi().dpapi_unprotect(blob))
    record["read"] = True
    record["blob_len"] = len(blob)
    record["matches"] = out == PAYLOAD
    return record


def _protect(path: Path, *, machine_scope: bool) -> dict[str, Any]:
    record, blob = _attempt(lambda: _dpapi().dpapi_protect(PAYLOAD, machine_scope=machine_scope))
    if blob is not None:
        record["blob_len"] = len(blob)
        path.write_bytes(blob)
    return record


def _facts() -> dict[str, Any]:
    """This process and its token, as read; the judge derives everything it checks from them.

    APPDATA is informational: where DPAPI keeps this account's master keys, if its profile is
    loaded.
    """
    appdata = os.environ.get("APPDATA")
    facts: dict[str, Any] = {
        "pid": os.getpid(),
        "appdata": appdata,
        "protect_dir_exists": appdata is not None
        and (Path(appdata) / "Microsoft" / "Protect").is_dir(),
    }
    try:
        facts["token"] = _token_probe().read_token()
    except OSError as exc:
        facts["token"] = {"error": f"{type(exc).__name__}: {exc}"}
    return facts


def _write_report(path: Path, report: dict[str, Any]) -> None:
    # Written whole and then renamed, so the rig never reads half a report.
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def run_owner(folder: Path) -> dict[str, Any]:
    start = len(list(folder.glob(owner_report("*")))) + 1
    report: dict[str, Any] = {"role": "owner", "start": start, **_facts()}
    user_blob = folder / USER_BLOB
    if not user_blob.exists():
        report["user_protect"] = _protect(user_blob, machine_scope=False)
        report["machine_protect"] = _protect(folder / MACHINE_BLOB, machine_scope=True)
    # Read back from the file, so the bytes unprotected are the bytes the other account is given.
    report["user_unprotect"] = _unprotect(user_blob)
    _write_report(folder / owner_report(start), report)
    return report


def run_other(folder: Path) -> dict[str, Any]:
    report: dict[str, Any] = {"role": "other", **_facts()}
    report["foreign_user_blob"] = _unprotect(folder / FOREIGN_USER_BLOB)
    report["foreign_machine_blob"] = _unprotect(folder / FOREIGN_MACHINE_BLOB)
    report["own_protect"] = _protect(folder / OWN_USER_BLOB, machine_scope=False)
    report["own_unprotect"] = _unprotect(folder / OWN_USER_BLOB)
    _write_report(folder / OTHER_REPORT, report)
    return report


def _hold(seconds: int) -> None:
    """Keep the service running until the rig stops it. NSSM stops it with Ctrl+C."""
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


def _ok(record: dict[str, Any] | None) -> bool:
    return isinstance(record, dict) and record.get("ok") is True


def _opened(record: dict[str, Any] | None) -> bool:
    return _ok(record) and record is not None and record.get("matches") is True


def _why(record: dict[str, Any] | None) -> str:
    if not record:
        return "no record"
    return str(record.get("error") or "ok")


def _dpapi_refused(record: dict[str, Any] | None) -> bool:
    """The bytes were read and DPAPI itself refused them: secrets_dpapi raises DpapiError then."""
    return (
        isinstance(record, dict)
        and record.get("read", True) is True
        and record.get("ok") is False
        and str(record.get("error") or "").startswith("DpapiError:")
    )


def _held(controls: list[Control]) -> bool:
    return all(held for _, held, _ in controls)


def _groups(report: dict[str, Any]) -> list[dict[str, Any]] | None:
    token = report.get("token")
    groups = token.get("groups") if isinstance(token, dict) else None
    return groups if isinstance(groups, list) else None


def _elevated(report: dict[str, Any]) -> bool | None:
    """Administrators in the token enabled, not deny-only. A standard user lacks it; a filtered
    admin token holds it deny-only. None when no token was read."""
    groups = _groups(report)
    if groups is None:
        return None
    return any(
        g.get("sid") == _ADMINISTRATORS and g.get("enabled") and not g.get("deny_only")
        for g in groups
    )


def _logon_sid(report: dict[str, Any]) -> str | None:
    """The token's logon SID, which a new logon session changes."""
    found = [g.get("sid") for g in _groups(report) or [] if g.get("logon_id")]
    return str(found[0]) if found else None


def _not_elevated(report: dict[str, Any], label: str) -> Control:
    found = _elevated(report)
    return (f"{label} was not elevated", found is False, f"Administrators enabled={found}")


def _account_token(report: dict[str, Any], sid: str, privileges: list[str]) -> Control:
    """The token the installer gives a service run as another account (SID type none)."""
    label = f"the other report ran as {sid} with the installer's token for such an account"
    token = report.get("token")
    if not isinstance(token, dict):
        return (label, False, "no token was read")
    problems = _token_probe().privilege_problems(token, account_sid=sid, privileges=privileges)
    return (label, not problems, "; ".join(problems) or "ok")


def _service_token(report: dict[str, Any], label: str, sid: str, privileges: list[str]) -> Control:
    """The installer's hardened service token, by the windows-service-smoke leg's own rule."""
    token = report.get("token")
    if not isinstance(token, dict):
        return (f"{label} held the hardened service token", False, "no token was read")
    problems = _token_probe().token_problems(token, service_sid=sid, privileges=privileges)
    return (f"{label} held the hardened service token", not problems, "; ".join(problems) or "ok")


def judge_reports(
    *,
    start1: dict[str, Any] | None,
    start2: dict[str, Any] | None,
    other: dict[str, Any] | None,
    owner_sid: str,
    other_sid: str,
    privileges: list[str],
    user_copy_identical: bool,
    machine_copy_identical: bool,
) -> list[Answer]:
    """The three answers. A control that does not hold makes its answer INCONCLUSIVE, never NO.

    ``owner_sid`` is the owner service's own SID, ``other_sid`` the second account's, and
    ``privileges`` the list install-service.ps1 gives every service. NO is said only of a refusal
    DPAPI itself gave (:func:`_dpapi_refused`); a file that could not be read, or any other
    failure, is INCONCLUSIVE. When Q1 is NO there is no valid blob, so Q2 and Q3 are NOT RUN.
    """
    s1 = start1 or {}
    s2 = start2 or {}
    o = other or {}

    q1_controls = [
        _service_token(s1, "start 1", owner_sid, privileges),
        _not_elevated(s1, "start 1"),
    ]
    protect, unprotect1 = s1.get("user_protect"), s1.get("user_unprotect")
    if not start1:
        q1, q1_detail = INCONCLUSIVE, "the owner service wrote no report at its first start"
    elif not _held(q1_controls):
        q1, q1_detail = INCONCLUSIVE, "the service did not run with the token the question names"
    elif protect is None:
        q1 = INCONCLUSIVE
        q1_detail = (
            "the report numbered 1 did not protect: an earlier start left the blob unreported"
        )
    elif not _ok(protect):
        q1 = NO if _dpapi_refused(protect) else INCONCLUSIVE
        q1_detail = f"protect failed: {_why(protect)}"
    elif _opened(unprotect1):
        q1 = YES
        q1_detail = "user-scope protect, then unprotect of the written file, gave PAYLOAD back"
    else:
        q1 = NO if _dpapi_refused(unprotect1) or _ok(unprotect1) else INCONCLUSIVE
        q1_detail = f"protect worked, unprotect did not give PAYLOAD back: {_why(unprotect1)}"
    no_blob = "Q1 is NO, so there is no valid blob to test"

    q2_controls = [
        (
            "the same service opened these exact bytes (Q1 is YES)",
            q1 == YES and user_copy_identical,
            f"Q1={q1}, copy byte-identical={user_copy_identical}",
        ),
        (
            "the other account is not the owner",
            other_sid != owner_sid,
            f"{other_sid} vs {owner_sid}",
        ),
        _account_token(o, other_sid, privileges),
        _not_elevated(o, "the other account"),
        (
            "the other account opened the owner's MACHINE-scope blob",
            machine_copy_identical and _opened(o.get("foreign_machine_blob")),
            f"copy byte-identical={machine_copy_identical}, {_why(o.get('foreign_machine_blob'))}",
        ),
        (
            "the other account round-tripped a user-scope blob of its own",
            _ok(o.get("own_protect")) and _opened(o.get("own_unprotect")),
            f"{_why(o.get('own_protect'))}; {_why(o.get('own_unprotect'))}",
        ),
    ]
    foreign = o.get("foreign_user_blob")
    if q1 == NO:
        q2, q2_detail = NOT_RUN, no_blob
    elif not other:
        q2, q2_detail = INCONCLUSIVE, "the other account wrote no report"
    elif not _held(q2_controls):
        q2 = INCONCLUSIVE
        q2_detail = "a control did not hold, so a refusal here would not be the scope's"
    elif _ok(foreign):
        q2 = NO
        q2_detail = "the other account OPENED the owner's user-scope blob"
    elif _dpapi_refused(foreign):
        q2 = YES
        q2_detail = f"DPAPI refused it: {_why(foreign)}"
    else:
        q2, q2_detail = INCONCLUSIVE, f"the attempt failed outside DPAPI: {_why(foreign)}"

    unprotect2 = s2.get("user_unprotect") or {}
    q3_controls = [
        ("the blob was valid at start 1 (Q1 is YES)", q1 == YES, f"Q1={q1}"),
        ("start 2 is the second start", s2.get("start") == 2, f"start={s2.get('start')}"),
        # A new logon session, not only a new process id (ids are reused): the same session could
        # answer from a master key it already holds, which would not show a restart.
        (
            "start 2 is a new logon session",
            _logon_sid(s1) is not None
            and _logon_sid(s2) is not None
            and _logon_sid(s1) != _logon_sid(s2),
            f"logon SID {_logon_sid(s1)} then {_logon_sid(s2)}, "
            f"pid {s1.get('pid')} then {s2.get('pid')}",
        ),
        (
            "start 2 read the blob start 1 wrote, and protected nothing new",
            "user_protect" not in s2
            and unprotect2.get("blob_len") is not None
            and unprotect2.get("blob_len") == (unprotect1 or {}).get("blob_len"),
            f"length {(unprotect1 or {}).get('blob_len')} then {unprotect2.get('blob_len')}, "
            f"protected again={'user_protect' in s2}",
        ),
        _service_token(s2, "start 2", owner_sid, privileges),
    ]
    if q1 == NO:
        q3, q3_detail = NOT_RUN, no_blob
    elif not start2:
        q3, q3_detail = INCONCLUSIVE, "the owner service wrote no report after its restart"
    elif not _held(q3_controls):
        q3, q3_detail = INCONCLUSIVE, "a control did not hold"
    elif _opened(unprotect2):
        q3 = YES
        q3_detail = "the restarted service, in a new logon session, opened the blob"
    elif _dpapi_refused(unprotect2) or _ok(unprotect2):
        q3 = NO
        q3_detail = f"the restarted service did not get PAYLOAD back: {_why(unprotect2)}"
    else:
        q3, q3_detail = INCONCLUSIVE, f"the attempt failed outside DPAPI: {_why(unprotect2)}"

    return [
        Answer(
            "Q1",
            f"user-scope CryptProtectData, then CryptUnprotectData, as the service {owner_sid}",
            q1,
            tuple(q1_controls),
            q1_detail,
        ),
        Answer(
            "Q2",
            "a second, non-elevated local account is refused the owner's user-scope blob",
            q2,
            tuple(q2_controls),
            q2_detail,
        ),
        Answer(
            "Q3",
            "the owner's user-scope blob opens after a service restart",
            q3,
            tuple(q3_controls),
            q3_detail,
        ),
    ]


def render(answers: list[Answer], *, image: str, os_build: str, accounts: str) -> str:
    """Plain lines, one prefix, so a reader greps ``DPAPI-SPIKE`` and gets every answer."""
    lines = [
        f"## DPAPI user-scope spike, {image} (vault BACKLOG #3411 wave 3.0)",
        "",
        f"OS build: {os_build}. {accounts}. Spike only: it builds nothing and gates nothing.",
        "",
        "```",
    ]
    for a in answers:
        lines.append(f"DPAPI-SPIKE {image} {a.key} {a.question}: {a.answer}")
        lines.append(f"DPAPI-SPIKE {image} {a.key} detail: {a.detail}")
        # A NOT RUN answer was never measured, so its controls would read as failures that are not.
        for name, held, why in () if a.answer == NOT_RUN else a.controls:
            lines.append(
                f"DPAPI-SPIKE {image} {a.key} control {'HELD' if held else 'FAILED'}: {name} ({why})"
            )
    lines.append(
        f"DPAPI-SPIKE {image} REBOOT arm: NOT RUN. Out of scope on hosted runners, which cannot "
        "reboot inside a job."
    )
    lines.extend(["```", ""])
    return "\n".join(lines)


def _load(path: Path) -> dict[str, Any] | None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _identical(a: Path, b: Path) -> bool:
    try:
        return a.read_bytes() == b.read_bytes()
    except OSError:
        return False


def judge_files(owner_dir: Path, other_dir: Path) -> dict[str, Path]:
    """Every file the judge reads. The rig waits on the reports and makes the copies, so it names
    each of these, and no other report or blob."""
    return {
        "start1": owner_dir / owner_report(1),
        "start2": owner_dir / owner_report(2),
        "other": other_dir / OTHER_REPORT,
        "user": owner_dir / USER_BLOB,
        "user_copy": other_dir / FOREIGN_USER_BLOB,
        "machine": owner_dir / MACHINE_BLOB,
        "machine_copy": other_dir / FOREIGN_MACHINE_BLOB,
    }


def run_judge(args: argparse.Namespace) -> int:
    files = judge_files(Path(args.owner_dir), Path(args.other_dir))
    answers = judge_reports(
        start1=_load(files["start1"]),
        start2=_load(files["start2"]),
        other=_load(files["other"]),
        owner_sid=args.owner_sid,
        other_sid=args.other_sid,
        privileges=args.privilege,
        user_copy_identical=_identical(files["user"], files["user_copy"]),
        machine_copy_identical=_identical(files["machine"], files["machine_copy"]),
    )
    build = "not Windows"
    if sys.platform == "win32":
        build = str(sys.getwindowsversion().build)
    accounts = (
        f"Owner {args.owner_account} ({args.owner_sid}), other {args.other_account} "
        f"({args.other_sid})"
    )
    text = render(answers, image=args.image, os_build=build, accounts=accounts)
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    # A NO is a finding and the spike did its job. Only an answer the instrument could not give
    # turns the job red.
    return 1 if any(a.answer == INCONCLUSIVE for a in answers) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    sub = parser.add_subparsers(dest="mode", required=True)
    for role in ("owner", "other"):
        p = sub.add_parser(role)
        p.add_argument("--dir", required=True)
        p.add_argument("--hold-seconds", type=int, default=1800)
    j = sub.add_parser("judge")
    j.add_argument("--owner-dir", required=True)
    j.add_argument("--other-dir", required=True)
    j.add_argument("--owner-sid", required=True)
    j.add_argument("--other-sid", required=True)
    j.add_argument("--owner-account", required=True, help="for the summary only")
    j.add_argument("--other-account", required=True, help="for the summary only")
    j.add_argument("--privilege", action="append", required=True)
    j.add_argument("--image", required=True)
    j.add_argument("--summary")
    args = parser.parse_args(argv)
    if args.mode == "judge":
        return run_judge(args)

    folder = Path(args.dir)
    try:
        report = run_owner(folder) if args.mode == "owner" else run_other(folder)
    except Exception:  # a crash is written down beside the reports, then re-raised
        with contextlib.suppress(OSError):
            (folder / f"{args.mode}-fatal.txt").write_text(traceback.format_exc(), encoding="utf-8")
        raise
    print(json.dumps(report, sort_keys=True), flush=True)
    _hold(args.hold_seconds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
