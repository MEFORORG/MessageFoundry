# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runbook take prompt: a Stop hook that prints ``read_batch.py --take`` for a held batch.

Owner decision 2026-11-27 ("Stop hook + Lander"). The hook is ``scripts/hooks/runbook-take-prompt.ps1``
over ``scripts/hooks/runbook_take_prompt.py``, and its installer row is ``mefor-runbook`` in
``scripts/coord/install-coordination.ps1``.

Three layers. The helper's decision runs on injected parsed data everywhere, because the project venv
has no openpyxl. The wiring and the always-exit-0 runs need pwsh on Windows. The end-to-end warn and
quiet runs also need an interpreter WITH openpyxl, to build the .xlsx fixture and to run the helper;
they take ``MEFOR_RUNBOOK_PYTHON`` or the tools interpreter, and skip when neither exists.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts" / "hooks" / "runbook-take-prompt.ps1"
HELPER = ROOT / "scripts" / "hooks" / "runbook_take_prompt.py"
INSTALLER = ROOT / "scripts" / "coord" / "install-coordination.ps1"
HOOK_REL = "scripts/hooks/runbook-take-prompt.ps1"
MARKER = "mefor-runbook"
# Below pyproject.toml's --timeout=60 so a hung child fails THIS test by name.
TIMEOUT = 45

_WINDOWS_PWSH = shutil.which("pwsh") is not None and os.name == "nt"
needs_pwsh = pytest.mark.skipif(not _WINDOWS_PWSH, reason="the hook needs pwsh on Windows")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("runbook_take_prompt_under_test", HELPER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolve their module by name
    spec.loader.exec_module(mod)
    return mod


rt = _load()


def _book(queue: dict[int, tuple[str, str, str]], rows: dict[int, list[tuple[int, str]]]) -> object:
    return rt.Book({b: rt.QueueEntry(*v) for b, v in queue.items()}, rows)


WT = "agent-abc123"
NAMES = (WT, "sess1234")


# --------------------------------------------------------------------------------------------------
# The decision, on injected parsed data.
# --------------------------------------------------------------------------------------------------


def test_a_claimed_row_in_a_free_batch_is_pending() -> None:
    book = _book({501: ("FREE", "FREE", "")}, {9001: [(501, "Not started")]})
    (p,) = rt.pending_batches(["9001"], book, NAMES)
    assert (p.batch, p.holder, p.rows, p.named_us) == (501, "", (9001,), False)


def test_a_batch_the_workbook_records_for_this_worktree_is_not_pending() -> None:
    book = _book(
        {502: ("TAKEN", "TAKEN -- x", f"Manager {WT} (abcd1234)")},
        {9002: [(502, "In progress -- x")]},
    )
    assert rt.pending_batches(["9002"], book, NAMES) == []


def test_a_batch_held_by_someone_else_is_pending_and_names_them() -> None:
    book = _book({503: ("TAKEN", "TAKEN", "Manager other-wt (ffff)")}, {9003: [(503, "")]})
    (p,) = rt.pending_batches(["9003-b"], book, NAMES)
    assert p.holder == "Manager other-wt (ffff)" and not p.named_us


def test_our_name_with_a_free_state_is_still_pending() -> None:
    book = _book({504: ("FREE", "FREE", f"Manager {WT} (x)")}, {9004: [(504, "Not started")]})
    (p,) = rt.pending_batches(["9004"], book, NAMES)
    assert p.named_us


def test_a_holder_naming_this_session_id_is_ours_and_a_longer_worktree_name_is_not() -> None:
    by_session = _book({509: ("TAKEN", "T", "Manager sess1234")}, {9009: [(509, "")]})
    assert rt.pending_batches(["9009"], by_session, NAMES) == []
    longer = _book({509: ("TAKEN", "T", f"Builder {WT}b2 (x)")}, {9009: [(509, "")]})
    assert [p.batch for p in rt.pending_batches(["9009"], longer, NAMES)] == [509]


def test_session_names_match_what_holder_text_prints() -> None:
    names = rt.session_names("C:/wt/my wt+1", "0123456789")
    holder = rt.holder_text("manager", "my wt+1", "0123456789")
    assert names == ("mywt1", "01234567", "0123456789") and rt.names_us(holder, names)


@pytest.mark.parametrize(
    ("state", "status", "row_status"),
    [
        ("MERGED", "MERGED -- PR 1", "Not started"),
        ("TAKEN", "DONE-B505 2026-11-01", "Not started"),
        ("FREE", "FREE", "Built in PR 3366"),
    ],
)
def test_finished_batches_and_closed_rows_are_skipped(
    state: str, status: str, row_status: str
) -> None:
    book = _book({505: (state, status, "")}, {9005: [(505, row_status)]})
    assert rt.pending_batches(["9005"], book, NAMES) == []


def test_a_row_shared_by_two_batches_is_satisfied_by_either() -> None:
    rows = {9006: [(506, "Not started"), (507, "Not started")]}
    taken = _book({506: ("FREE", "FREE", ""), 507: ("TAKEN", "T", f"M {WT} (s)")}, rows)
    assert rt.pending_batches(["9006"], taken, NAMES) == []
    free = _book({506: ("FREE", "FREE", ""), 507: ("FREE", "FREE", "")}, rows)
    assert [p.batch for p in rt.pending_batches(["9006"], free, NAMES)] == [506, 507]


def test_key_readings() -> None:
    assert rt.key_targets("3765") == ({3765}, set())
    assert rt.key_targets("3765-b") == ({3765}, set())
    assert rt.key_targets("batch-472") == (set(), {472})
    assert rt.key_targets("b472-3765-b") == ({3765}, {472})
    assert rt.key_targets("npm-audit-brace-expansion") == (set(), set())
    assert rt.key_targets("1234567") == (set(), set())
    assert rt.key_targets("batches-462-465") == (set(), {462, 463, 464, 465})
    assert rt.key_targets("2026-11-27-notes") == ({2026}, set())
    assert rt.key_targets("1719-items-22-35") == ({1719}, set())
    assert rt.key_targets("batch-472-2026-11-27") == (set(), {472})


def test_a_holder_cell_with_the_full_session_id_is_ours() -> None:
    sid = "bb735675-ef99-4846-ae70-f3e56da8e810"
    names = rt.session_names("C:/x/manager-wt", sid)
    book = _book({510: ("TAKEN", "T", f"Manager {sid}")}, {9010: [(510, "")]})
    assert rt.pending_batches(["9010"], book, names) == []


def test_a_shared_row_held_under_our_batch_past_open_is_still_satisfied() -> None:
    rows = {9006: [(507, "PR open in 3400"), (506, "Not started")]}
    book = _book({506: ("FREE", "FREE", ""), 507: ("PR OPEN", "PR OPEN", f"M {WT} (s)")}, rows)
    assert rt.pending_batches(["9006"], book, NAMES) == []


def test_a_batch_key_names_its_batch() -> None:
    book = _book({508: ("FREE", "FREE", "")}, {})
    assert [p.batch for p in rt.pending_batches(["batch-508"], book, NAMES)] == [508]


def test_the_message_carries_the_exact_take_command_and_the_done_reminder() -> None:
    holder = rt.holder_text("manager", WT, "0123456789abcdef")
    assert holder == f"Manager {WT} (01234567)"
    p = rt.Pending(501, "", (9001,))
    text = rt.message(
        [p], r"C:\py\python.exe", r"C:\skills\batch\read_batch.py", r"C:\w.xlsx", holder
    )
    assert (
        r"C:\py\python.exe C:\skills\batch\read_batch.py --workbook C:\w.xlsx --take 501 "
        f'--holder "{holder}"' in text
    )
    assert "reads FREE" in text and "--done" in text and "merges" in text
    assert "--force-take" not in text


def test_our_own_older_holder_text_gets_force_take_in_the_command() -> None:
    p = rt.Pending(504, f"Manager {WT} (oldsid12)", (9004,), named_us=True, state="FREE")
    text = rt.message([p], "py", "rb.py", "w.xlsx", f"Manager {WT} (sess1234)")
    assert f'--take 504 --holder "Manager {WT} (sess1234)" --force-take' in text
    assert "names another holder" not in text


def test_a_path_with_a_space_is_quoted_and_called() -> None:
    text = rt.message([rt.Pending(1, "", ())], r"C:\P F\py.exe", "rb.py", "w.xlsx", "M w (s)")
    assert r'& "C:\P F\py.exe" rb.py' in text


def test_a_missing_seat_is_flagged() -> None:
    text = rt.message([rt.Pending(1, "", ())], "py", "rb.py", "w.xlsx", "<seat> w (s)")
    assert "replace <seat>" in text


def test_a_hostile_holder_cell_is_shown_as_data() -> None:
    p = rt.Pending(503, 'evil"\n--force-take\x07\u2028x\u202e', ())
    text = rt.message([p], "py", "rb.py", "w.xlsx", "Manager wt (s)")
    assert '"\n--force-take' not in text
    assert not any(c in text for c in "\x07\u2028\u202e")
    assert "--force-take" in text  # the advice line, which names the flag for a real other holder


def test_holder_text_drops_what_is_not_a_plain_label() -> None:
    assert rt.holder_text("", "w t;&", "s$1") == "<seat> wt (s1)"


# --------------------------------------------------------------------------------------------------
# run(): cache, rate limit and the quiet paths, with read_book replaced so no openpyxl is needed.
# --------------------------------------------------------------------------------------------------


def _claims(tmp_path: Path, worktree: Path, *keys: str) -> Path:
    d = tmp_path / "claims"
    d.mkdir(exist_ok=True)
    for k in keys:
        (d / f"{k}.json").write_text(json.dumps({"key": k, "worktree": str(worktree)}), "utf-8")
    return d


def _args(
    tmp_path: Path, worktree: Path, claims: Path, workbook: Path, now: float, *extra: str
) -> list[str]:
    return [
        "--worktree", str(worktree), "--session", "sess-1", "--seat", "manager",
        "--workbook", str(workbook), "--python", "py", "--read-batch", "rb.py",
        *extra,
        "--claims-dir", str(claims), "--state-dir", str(tmp_path / "state"), "--now", str(now),
    ]  # fmt: skip


def test_run_warns_once_per_cooldown_and_caches_the_workbook_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    wt = tmp_path / WT
    wt.mkdir()
    workbook = tmp_path / "wb.xlsx"
    workbook.write_bytes(b"not read")
    claims = _claims(tmp_path, wt, "9001")
    reads: list[Path] = []

    def fake(path: Path) -> object:
        reads.append(path)
        return _book({501: ("FREE", "FREE", "")}, {9001: [(501, "Not started")]})

    monkeypatch.setattr(rt, "read_book", fake)
    assert rt.main(_args(tmp_path, wt, claims, workbook, 1000.0)) == 0
    out = json.loads(capsys.readouterr().out)
    assert list(out) == ["systemMessage"] and "--take 501" in out["systemMessage"]
    assert rt.main(_args(tmp_path, wt, claims, workbook, 1000.0 + 60)) == 0
    assert capsys.readouterr().out == ""
    assert len(reads) == 1, "an unchanged workbook and claims directory must not be re-read"
    assert rt.main(_args(tmp_path, wt, claims, workbook, 1000.0 + rt.COOLDOWN_SECONDS + 1)) == 0
    assert "--take 501" in capsys.readouterr().out
    assert len(reads) == 1
    # A clock set back leaves a stamp in the future, which must not silence the warning.
    assert rt.main(_args(tmp_path, wt, claims, workbook, 10.0)) == 0
    assert "--take 501" in capsys.readouterr().out


def test_an_unreadable_claim_is_reported_and_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """claim.ps1 creates a claim file before it writes it, and the write moves no directory
    mtime, so a scan that met an empty file must not be cached against the directory."""
    wt = tmp_path / WT
    wt.mkdir()
    workbook = tmp_path / "wb.xlsx"
    workbook.write_bytes(b"x")
    claims = _claims(tmp_path, wt)
    (claims / "9001.json").write_text("", "utf-8")
    monkeypatch.setattr(
        rt, "read_book", lambda path: _book({501: ("FREE", "FREE", "")}, {9001: [(501, "")]})
    )
    mtime = claims.stat().st_mtime_ns
    assert rt.main(_args(tmp_path, wt, claims, workbook, 1.0)) == 0
    first = capsys.readouterr()
    assert first.out == "" and "unreadable" in first.err
    (claims / "9001.json").write_text(json.dumps({"key": "9001", "worktree": str(wt)}), "utf-8")
    os.utime(claims, ns=(mtime, mtime))
    assert rt.main(_args(tmp_path, wt, claims, workbook, 2.0)) == 0
    assert "--take 501" in capsys.readouterr().out


@pytest.mark.parametrize("seat", ["builder", "lander", "watchdog"])
def test_a_seat_that_never_takes_a_batch_is_never_warned(
    seat: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    wt = tmp_path / WT
    wt.mkdir()
    workbook = tmp_path / "wb.xlsx"
    workbook.write_bytes(b"x")
    claims = _claims(tmp_path, wt, "9001")
    monkeypatch.setattr(
        rt, "read_book", lambda path: _book({501: ("FREE", "FREE", "")}, {9001: [(501, "")]})
    )
    assert rt.main(_args(tmp_path, wt, claims, workbook, 1.0, "--seat", seat)) == 0
    assert capsys.readouterr().out == ""
    # The control: the same state under a Manager warns.
    assert rt.main(_args(tmp_path, wt, claims, workbook, 1.0, "--seat", "manager")) == 0
    assert "--take 501" in capsys.readouterr().out


def test_run_is_quiet_with_no_claims_for_this_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    wt = tmp_path / WT
    wt.mkdir()
    workbook = tmp_path / "wb.xlsx"
    workbook.write_bytes(b"x")
    claims = _claims(tmp_path, tmp_path / "someone-else", "9001")

    def boom(path: Path) -> object:
        raise AssertionError("no claim of ours, so the workbook must not be read")

    monkeypatch.setattr(rt, "read_book", boom)
    assert rt.main(_args(tmp_path, wt, claims, workbook, 1.0)) == 0
    assert capsys.readouterr().out == ""


def test_run_is_quiet_on_a_missing_workbook_and_on_a_read_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    wt = tmp_path / WT
    wt.mkdir()
    claims = _claims(tmp_path, wt, "9001")
    assert rt.main(_args(tmp_path, wt, claims, tmp_path / "absent.xlsx", 1.0)) == 0
    assert capsys.readouterr().out == ""

    def locked(path: Path) -> object:
        raise PermissionError("locked by Excel")

    workbook = tmp_path / "wb.xlsx"
    workbook.write_bytes(b"x")
    monkeypatch.setattr(rt, "read_book", locked)
    assert rt.main(_args(tmp_path, wt, claims, workbook, 1.0)) == 0
    assert capsys.readouterr().out == ""
    assert rt.main(["--bogus"]) == 0


# --------------------------------------------------------------------------------------------------
# Wiring.
# --------------------------------------------------------------------------------------------------


_SRC = INSTALLER.read_text(encoding="utf-8")


def test_the_installer_wires_the_hook_as_a_stop_notice_row() -> None:
    assert f'$RUNBOOK_MARKER = "{MARKER}"' in _SRC
    rows = [ln for ln in _SRC.splitlines() if f'Script = "{HOOK_REL}"' in ln]
    assert len(rows) == 1
    assert '@{ Event = "Stop"' in rows[0]
    assert "Marker = $RUNBOOK_MARKER" in rows[0] and 'Shim = "notice"' in rows[0]
    assert HOOK.is_file() and HELPER.is_file()
    assert "runbook-take-prompt.ps1" in _SRC.split("#>", 1)[0], "the header table names it"


def test_the_hook_never_prints_a_block_decision() -> None:
    for path in (HOOK, HELPER):
        text = path.read_text(encoding="utf-8")
        assert "'block'" not in text and '"block"' not in text


@pytest.fixture
def settings(tmp_path: Path) -> Path:
    p = tmp_path / "settings.json"
    foreign = {"hooks": [{"type": "command", "command": "echo foreign-stop"}]}
    p.write_text(json.dumps({"hooks": {"Stop": [foreign]}}), encoding="utf-8")
    return p


def _run_installer(settings: Path, *args: str) -> None:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALLER),
         "-SettingsPath", str(settings), *args],
        capture_output=True, text=True, timeout=TIMEOUT, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr


def _stop_entries(settings: Path) -> list[dict[str, object]]:
    data = json.loads(settings.read_text(encoding="utf-8-sig"))
    return [h for g in data["hooks"].get("Stop", []) for h in g["hooks"]]


@needs_pwsh
def test_install_adds_one_runbook_stop_entry_and_uninstall_removes_only_it(settings: Path) -> None:
    _run_installer(settings)
    ours = [h for h in _stop_entries(settings) if MARKER in str(h["command"])]
    assert len(ours) == 1
    assert f"'{HOOK_REL}'" in str(ours[0]["command"]) and ours[0]["timeout"] == 20
    assert "async" not in ours[0]
    first = settings.read_text(encoding="utf-8-sig")
    _run_installer(settings)
    assert settings.read_text(encoding="utf-8-sig") == first
    before = [h["command"] for h in _stop_entries(settings)]
    _run_installer(settings, "-Script", "runbook-take-prompt", "-Uninstall")
    after = [h["command"] for h in _stop_entries(settings)]
    assert after == [c for c in before if MARKER not in str(c)]
    assert "echo foreign-stop" in after


# --------------------------------------------------------------------------------------------------
# The real script, end to end.
# --------------------------------------------------------------------------------------------------


def _git_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "-C", str(path), "init", "-q"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(path), "-c", "user.email=t@example.invalid", "-c", "user.name=t",
         "commit", "-q", "--allow-empty", "-m", "init"],
        check=True, capture_output=True,
    )  # fmt: skip
    return path


def _linked_worktree(tmp_path: Path) -> tuple[Path, Path]:
    """A primary checkout and a linked worktree of it named WT, as a fleet session has. The claims
    live in the primary's registry and name the linked worktree."""
    primary = _git_repo(tmp_path / "primary")
    wt = tmp_path / WT
    subprocess.run(
        ["git", "-C", str(primary), "worktree", "add", "-q", "--detach", str(wt)],
        check=True, capture_output=True,
    )  # fmt: skip
    (primary / ".git" / "mefor-coord" / "claims").mkdir(parents=True)
    return primary, wt


def _claim(primary: Path, key: str, worktree: Path) -> None:
    claims = primary / ".git" / "mefor-coord" / "claims"
    (claims / f"{key}.json").write_text(
        json.dumps({"key": key, "worktree": str(worktree)}), "utf-8"
    )


def _env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("MEFOR_", "CLAUDE_", "KORUS_"))}
    env.update(extra)
    return env


def _hook(
    payload: str, env: dict[str, str], cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    # The hook answers only for a cwd inside the checkout it started in (_hookinput.ps1, rule 4),
    # so a run that should warn starts in the fixture worktree, as the shim starts in the session's.
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(HOOK)],
        input=payload, capture_output=True, text=True, timeout=TIMEOUT, env=env, check=False,
        cwd=cwd,
    )  # fmt: skip


def _payload(cwd: Path, session: str = "sess-e2e-1") -> str:
    return json.dumps({"session_id": session, "cwd": str(cwd), "hook_event_name": "Stop"})


@needs_pwsh
@pytest.mark.parametrize(
    "stdin", ["", "not json", "[1,2]", '{"session_id": "../x"}', '{"session_id": "abc\\n"}']
)
def test_the_hook_exits_0_and_prints_nothing_on_bad_input(stdin: str) -> None:
    proc = _hook(stdin, _env())
    assert proc.returncode == 0 and proc.stdout == ""


@needs_pwsh
def test_the_hook_is_quiet_when_the_workbook_is_missing(tmp_path: Path) -> None:
    """With a negative control: the same run with a workbook present reaches the helper, which
    says on stderr why it printed nothing (this venv has no openpyxl, or the file is no xlsx)."""
    primary, wt = _linked_worktree(tmp_path)
    _claim(primary, "9001", wt)
    present = tmp_path / "present.xlsx"
    present.write_bytes(b"not a workbook")
    reached = _hook(
        _payload(wt),
        _env(MEFOR_RUNBOOK_PYTHON=sys.executable, MEFOR_RUNBOOK_WORKBOOK=str(present)),
        cwd=wt,
    )
    assert reached.returncode == 0 and reached.stdout == ""
    assert "runbook-take-prompt: nothing printed" in reached.stderr, reached.stderr
    missing = _hook(
        _payload(wt),
        _env(MEFOR_RUNBOOK_PYTHON=sys.executable, MEFOR_RUNBOOK_WORKBOOK=str(tmp_path / "no.xlsx")),
        cwd=wt,
    )
    assert missing.returncode == 0 and missing.stdout == "" and missing.stderr == ""


def _openpyxl_python() -> str | None:
    for cand in (
        os.environ.get("MEFOR_RUNBOOK_PYTHON", ""),
        str(Path.home() / ".claude-tools" / "py" / "Scripts" / "python.exe"),
    ):
        if cand and Path(cand).is_file():
            probe = subprocess.run(
                [cand, "-c", "import openpyxl"], capture_output=True, check=False
            )
            if probe.returncode == 0:
                return cand
    return None


_FIXTURE = r"""
import sys, openpyxl
wb = openpyxl.Workbook()
q = wb.active
q.title = "Batch queue"
q.append(["Batch", "Subsystem", "State", "Status", "Manager / session", "Handed out"])
q.append([501, "x", "FREE", "FREE", None, None])
q.append([502, "y", "TAKEN", "TAKEN -- me", sys.argv[2], "2026-11-27"])
r = wb.create_sheet("Rows")
r.append(["Batch", "Row", "Status", "Builder / session"])
r.append([501, 9001, "Not started", None])
r.append([502, 9002, "In progress", None])
wb.save(sys.argv[1])
"""


@needs_pwsh
@pytest.mark.parametrize(("key", "warns"), [("9001", True), ("9002", False)])
def test_the_hook_end_to_end_on_a_real_workbook(tmp_path: Path, key: str, warns: bool) -> None:
    py = _openpyxl_python()
    if py is None:
        pytest.skip("no interpreter with openpyxl (set MEFOR_RUNBOOK_PYTHON)")
    primary, wt = _linked_worktree(tmp_path)
    workbook = tmp_path / "wb.xlsx"
    subprocess.run(
        [py, "-c", _FIXTURE, str(workbook), f"Manager {WT} (sess-e2e)"], check=True, timeout=TIMEOUT
    )
    _claim(primary, key, wt)
    _claim(primary, "9001-primary", primary)
    env = _env(
        MEFOR_RUNBOOK_PYTHON=py,
        MEFOR_RUNBOOK_WORKBOOK=str(workbook),
        MEFOR_RUNBOOK_READ_BATCH=r"C:\skills\batch\read_batch.py",
    )
    # Started in ANOTHER repository, the resolver refuses the cwd, and the hook must not follow it.
    elsewhere = _git_repo(tmp_path / "elsewhere")
    refused = _hook(_payload(wt), env, cwd=elsewhere)
    assert refused.returncode == 0 and refused.stdout == "", refused.stdout
    # The primary checkout is shared by unrelated sessions, so its own claims prompt nobody.
    in_primary = _hook(_payload(primary, "sess-primary"), env, cwd=primary)
    assert in_primary.returncode == 0 and in_primary.stdout == "", in_primary.stdout
    proc = _hook(_payload(wt), env, cwd=wt)
    assert proc.returncode == 0, proc.stderr
    if not warns:
        assert proc.stdout == "", proc.stdout
        return
    msg = json.loads(proc.stdout)["systemMessage"]
    want = (
        f"{py} C:\\skills\\batch\\read_batch.py --workbook {workbook} --take 501 "
        f'--holder "<seat> {WT} (sess-e2e)"'
    )
    assert want in msg, msg
    again = _hook(_payload(wt), env, cwd=wt)
    assert again.returncode == 0 and again.stdout == "", (
        "a second Stop inside the cooldown is quiet"
    )
