# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runbook done prompt: a PostToolUse hook that hands a session the read_batch.py --done command
when a command it ran opened a pull request naming a runbook batch (owner instruction 2026-11-28).

The hook runs end to end through pwsh, as the installed shim runs it, with the hook input on stdin.
The helper's claim reading is tested directly, since a real claims registry is shared state."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts" / "hooks" / "runbook-done-prompt.ps1"
HELPER = ROOT / "scripts" / "hooks" / "runbook_done_prompt.py"
INSTALLER = ROOT / "scripts" / "coord" / "install-coordination.ps1"
HOOK_REL = "scripts/hooks/runbook-done-prompt.ps1"
TIMEOUT = 60


def _need_pwsh() -> None:
    # Per test, not per module: the helper tests below run on every platform.
    if shutil.which("pwsh") is None or os.name != "nt":
        pytest.skip("the hook and the installer need pwsh on Windows")


_SRC = INSTALLER.read_text(encoding="utf-8")
_m = re.search(r"\$BATCH_DONE_MARKER\s*=\s*\"([^\"]+)\"", _SRC)
assert _m, "the installer lost $BATCH_DONE_MARKER"
MARKER = _m.group(1)


def _helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("runbook_done_prompt_under_test", HELPER)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "wt"
    r.mkdir()
    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
        ["config", "commit.gpgsign", "false"],
    ):
        subprocess.run(["git", "-C", str(r), *args], check=True, capture_output=True)
    (r / "f.txt").write_text("x", encoding="utf-8")
    subprocess.run(["git", "-C", str(r), "add", "f.txt"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(r), "commit", "-qm", "init"],
        check=True,
        capture_output=True,
    )
    return r


def _env(tmp_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_CODE_REMOTE",)}
    env["MEFOR_RUNBOOK_PROMPT"] = "on"
    env["MEFOR_RUNBOOK_PYTHON"] = sys.executable
    env["MEFOR_RUNBOOK_READ_BATCH"] = r"C:\skills\batch\read_batch.py"
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    env["TMP"] = env["TEMP"] = str(temp)
    return env


def payload(repo: Path, command: str, response: object, tool: str = "Bash", **extra: Any) -> str:
    return json.dumps(
        {
            "session_id": "sess-1234abcd",
            "hook_event_name": "PostToolUse",
            "cwd": str(repo),
            "tool_name": tool,
            "tool_input": {"command": command},
            "tool_response": response,
            **extra,
        }
    )


def run_hook(
    repo: Path, tmp_path: Path, stdin: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    _need_pwsh()
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(HOOK)],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=repo,
        env=env or _env(tmp_path),
        timeout=TIMEOUT,
        check=False,
    )


def context(proc: subprocess.CompletedProcess[str]) -> str:
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert set(out) == {"hookSpecificOutput"}, "a decision key or anything else would be a block"
    spec = out["hookSpecificOutput"]
    assert spec["hookEventName"] == "PostToolUse"
    text: str = spec["additionalContext"]
    return text


def ok(url: str = "https://github.com/MEFORORG/MessageFoundry/pull/3410") -> dict[str, Any]:
    return {"stdout": url + "\n", "stderr": "", "interrupted": False}


def test_gh_pr_create_naming_batch_20014_prints_the_done_reminder(
    repo: Path, tmp_path: Path
) -> None:
    cmd = 'gh pr create --title "Batch 20014: runbook done hook (BACKLOG #5850, #5851)" --body x'
    text = context(run_hook(repo, tmp_path, payload(repo, cmd, ok())))
    print(text)
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--short=11", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert "--done 20014 " in text
    assert '--state "PR OPEN"' in text
    assert f'--note "engine PR 3410 ({sha}) open"' in text
    assert '--row 5850="In engine PR 3410 (batch 20014)"' in text
    assert '--holder "<the text you gave --take>"' in text
    # A Bash tool call: paths single-quoted, since bash eats an unquoted backslash.
    assert r" 'C:\skills\batch\read_batch.py' --done 20014 " in text
    assert "--state MERGED" in text and "PARTIAL" in text


def test_a_rest_create_is_recognised(repo: Path, tmp_path: Path) -> None:
    cmd = (
        "gh api -X POST repos/MEFORORG/MessageFoundry/pulls -f title='batch 20014 hooks' "
        "-f head=nosuchbranch -f base=main"
    )
    body = json.dumps(
        {"number": 3411, "html_url": "https://github.com/MEFORORG/MessageFoundry/pull/3411"}
    )
    text = context(run_hook(repo, tmp_path, payload(repo, cmd, {"stdout": body, "stderr": ""})))
    assert "--done 20014 " in text
    assert "engine PR 3411 (<head sha>) open" in text


def test_a_rest_create_with_fields_and_no_method_is_a_post(repo: Path, tmp_path: Path) -> None:
    cmd = "gh api repos/{owner}/{repo}/pulls -f title='Batch 77 work' -f head=x -f base=main"
    body = json.dumps({"number": 12, "html_url": "https://github.com/MEFORORG/korus/pull/12"})
    text = context(run_hook(repo, tmp_path, payload(repo, cmd, {"stdout": body})))
    assert "--done 77 " in text and "korus PR 12" in text


@pytest.mark.parametrize(
    "cmd",
    [
        "git status",
        "gh pr view 3410 --json title",
        "gh api repos/MEFORORG/MessageFoundry/pulls --jq '.[].number'",
        "gh api -X GET repos/MEFORORG/MessageFoundry/pulls -f state=open",
        "echo 'batch 20014'",
    ],
)
def test_a_non_pr_command_prints_nothing(repo: Path, tmp_path: Path, cmd: str) -> None:
    proc = run_hook(repo, tmp_path, payload(repo, cmd, ok()))
    assert proc.returncode == 0
    assert proc.stdout == ""


@pytest.mark.parametrize(
    "response",
    [
        {"stdout": "", "stderr": "pull request create failed: GraphQL error", "interrupted": False},
        {
            "stdout": "",
            "stderr": "a pull request for branch x into branch main already exists:\n"
            "https://github.com/MEFORORG/MessageFoundry/pull/3300",
        },
        {"stdout": "https://github.com/MEFORORG/MessageFoundry/pull/3410", "interrupted": True},
        {"stdout": "https://github.com/MEFORORG/MessageFoundry/pull/3410", "exitCode": 1},
    ],
)
def test_a_failed_create_prints_nothing(repo: Path, tmp_path: Path, response: object) -> None:
    cmd = 'gh pr create --title "Batch 20014" --body x'
    proc = run_hook(repo, tmp_path, payload(repo, cmd, response))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""


def test_a_body_file_in_the_worktree_is_read(repo: Path, tmp_path: Path) -> None:
    (repo / "body.md").write_text("Closes rows for batch 20014.\n", encoding="utf-8")
    cmd = 'gh pr create --title "hooks" --body-file body.md'
    text = context(run_hook(repo, tmp_path, payload(repo, cmd, ok())))
    assert "--done 20014 " in text


def test_a_body_file_in_the_sessions_scratchpad_is_read(repo: Path, tmp_path: Path) -> None:
    pad = tmp_path / "temp" / "claude" / "h4sh" / "sess-1234abcd" / "scratchpad"
    pad.mkdir(parents=True)
    body = pad / "body.md"
    body.write_text("batch 20014\n", encoding="utf-8")
    cmd = f'gh pr create --title "hooks" -F "{body}"'
    text = context(run_hook(repo, tmp_path, payload(repo, cmd, ok())))
    assert "--done 20014 " in text


@pytest.mark.parametrize("where", ["outside", "other-session-pad"])
def test_a_body_file_outside_the_worktree_is_not_read(
    repo: Path, tmp_path: Path, where: str
) -> None:
    if where == "outside":
        body = tmp_path / "elsewhere" / "body.md"
    else:
        body = tmp_path / "temp" / "claude" / "h4sh" / "someone-else" / "scratchpad" / "body.md"
    body.parent.mkdir(parents=True)
    body.write_text("batch 20014\n", encoding="utf-8")
    cmd = f'gh pr create --title "hooks" --body-file "{body}"'
    proc = run_hook(repo, tmp_path, payload(repo, cmd, ok()))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "", "a file outside the worktree and the session's scratchpad was read"


@pytest.mark.parametrize(
    "stdin",
    [
        "",
        "not json at all, pr create",
        '[1, 2, 3, "/pulls"]',
        json.dumps({"hook_event_name": "PostToolUse", "tool_input": "gh pr create"}),
        json.dumps(
            {
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "gh pr create --title 'batch 20014'"},
                "tool_response": ["https://github.com/a/b/pull/1"],
            }
        ),
    ],
)
def test_the_hook_always_exits_0(repo: Path, tmp_path: Path, stdin: str) -> None:
    proc = run_hook(repo, tmp_path, stdin)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""


def test_a_missing_interpreter_still_exits_0(repo: Path, tmp_path: Path) -> None:
    env = _env(tmp_path)
    env["MEFOR_RUNBOOK_PYTHON"] = str(tmp_path / "no" / "python.exe")
    env["PATH"] = str(tmp_path / "empty")
    proc = run_hook(repo, tmp_path, payload(repo, 'gh pr create -t "batch 20014"', ok()), env)
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert "no interpreter at" in proc.stderr, "the missing-interpreter branch did not run"


def test_a_multi_line_create_and_a_powershell_call_are_read(repo: Path, tmp_path: Path) -> None:
    cmd = 'gh pr create \\\n  --title "Batch 52: x (BACKLOG #5850)" \\\n  --body x'
    text = context(run_hook(repo, tmp_path, payload(repo, cmd, ok())))
    assert "--done 52 " in text and "--row 5850=" in text
    ps = 'gh pr create `\n  --title "Batch 7: y" `\n  --body x'
    text = context(run_hook(repo, tmp_path, payload(repo, ps, ok(), tool="PowerShell")))
    assert "--done 7 " in text
    assert r" C:\skills\batch\read_batch.py --done 7 " in text, "PowerShell paths stay bare"


def test_the_off_switch_silences_it(repo: Path, tmp_path: Path) -> None:
    env = _env(tmp_path)
    env["MEFOR_RUNBOOK_PROMPT"] = " OFF "
    proc = run_hook(repo, tmp_path, payload(repo, 'gh pr create -t "batch 20014"', ok()), env)
    assert proc.returncode == 0
    assert proc.stdout == ""


def test_held_backlog_rows_with_no_batch_print_the_lookup_hint(repo: Path, tmp_path: Path) -> None:
    mod = _helper()
    claims = tmp_path / "claims"
    claims.mkdir()
    (claims / "5850.json").write_text(json.dumps({"worktree": str(repo)}), encoding="utf-8")
    (claims / "5851.json").write_text(json.dumps({"worktree": "D:/other"}), encoding="utf-8")
    raw = payload(repo, 'gh pr create -t "Hooks (BACKLOG #5850, #5851)"', ok())
    args = mod.argparse.Namespace(
        worktree=str(repo),
        session="sess-1234abcd",
        python="py.exe",
        read_batch="rb.py",
        temp_dir=str(tmp_path),
        claims_dir=str(claims),
    )
    text = mod.run(args, raw)
    print(text)
    assert text is not None
    assert "names no runbook batch" in text and "BACKLOG #5850," in text
    assert "#5851" not in text, "a row held by another worktree was named"
    assert "Rows tab" in text and "--done <NN>" in text
    (claims / "5850.json").unlink()
    assert mod.run(args, raw) is None, "no batch and no held row must print nothing"


def test_the_helper_names_several_batches_and_ignores_pr_numbers() -> None:
    mod = _helper()
    assert mod.batches_in("Batches 20014 and 20015; batch #52, batch-mode") == [20014, 20015, 52]
    assert mod.backlog_rows_in("BACKLOG #5973, #5936 and PR #3383") == [5973, 5936]


def test_flags_are_read_from_the_create_segment_only() -> None:
    mod = _helper()
    # rm's -f is no gh api field, so a GET listing followed by it is no create.
    listing = "gh api repos/MEFORORG/MessageFoundry/pulls --jq 'length' ; rm -f tmp.txt"
    assert mod.find_create(listing) is None
    # A GET on another call does not hide the create after it.
    found = mod.find_create(
        "gh api -X GET repos/o/r/pulls/5 && gh api repos/o/r/pulls -f title='batch 20014' -f head=x"
    )
    assert found is not None and found[0] == "rest" and "pulls/5" not in found[1]
    # A curl -H before the create is not the PR head.
    assert (
        mod.CLI_HEAD.search(mod.find_create('curl -H "Accept: x" u && gh pr create -t t')[1])
        is None
    )
    # head= inside a title is not the head field.
    seg = "gh api -X POST repos/o/r/pulls -f title='move head=main' -f head=builder/x"
    m = mod.API_HEAD.search(seg)
    assert m is not None and m.group(1) == "builder/x"


def test_a_mention_in_another_programs_argument_is_not_the_create() -> None:
    mod = _helper()
    found = mod.find_create(
        'git commit -m "docs: explain gh pr create" && git push && gh pr create -t "Batch 52"'
    )
    assert found is not None and "Batch 52" in found[1] and "commit" not in found[1]


def test_batches_take_ranges_and_several_batches_fill_in_no_rows() -> None:
    mod = _helper()
    assert mod.batches_in("Batches 118-120") == [118, 119, 120]
    assert mod.batches_in("Batch 7: x") == [7]
    pr = mod.Created("MEFORORG", "MessageFoundry", 1)
    text = mod.message(pr, [20014, 20015], [], [5850, 5851], None, "py", "rb.py")
    assert text is not None and "--row 5850" not in text and "--row <ROW>=" in text


def test_a_rest_head_sha_comes_from_the_response() -> None:
    mod = _helper()
    body = json.dumps({"number": 1, "head": {"sha": "0123456789abcdef0123456789abcdef01234567"}})
    assert mod.head_sha("rest", "gh api -X POST repos/o/r/pulls", None, body) == "0123456789a"
    assert mod.head_sha("rest", "gh api -X POST repos/o/r/pulls", None, "{}") is None


def test_gh_called_by_path_is_recognised() -> None:
    mod = _helper()
    assert mod.find_create('& "C:\\Program Files\\GitHub CLI\\gh.exe" pr create -t x') is not None
    assert mod.find_create("/usr/bin/gh pr create -t x") is not None


def test_a_rest_create_whose_body_says_already_exists_is_still_a_create() -> None:
    mod = _helper()
    body = json.dumps(
        {
            "number": 9,
            "html_url": "https://github.com/MEFORORG/MessageFoundry/pull/9",
            "body": "Refuses when the claim file already exists.",
        }
    )
    pr = mod.created_pr("rest", "gh api -X POST repos/o/r/pulls", body)
    assert pr is not None and pr.number == 9


def test_a_quoted_rest_body_file_with_a_space_is_read_whole() -> None:
    mod = _helper()
    m = mod.API_BODY_FILE.search('gh api -X POST repos/o/r/pulls -F "body=@C:\\My Files\\b.md"')
    assert m is not None
    assert next(g for g in m.groups() if g) == "C:\\My Files\\b.md"


def test_a_body_file_is_not_read_without_a_worktree_or_from_a_unc_path(tmp_path: Path) -> None:
    mod = _helper()
    pad = tmp_path / "claude" / "h" / "sess-1" / "scratchpad"
    pad.mkdir(parents=True)
    (pad / "b.md").write_text("batch 20014", encoding="utf-8")
    body = str(pad / "b.md")
    assert mod.allowed_body_file(body, None, str(tmp_path), "sess-1", str(tmp_path)) is not None
    assert mod.allowed_body_file(body, None, None, "sess-1", str(tmp_path)) is None
    assert (
        mod.allowed_body_file(r"\\host\share\b.md", None, str(tmp_path), "s", str(tmp_path)) is None
    )


def test_the_primary_checkout_holds_no_session_claims(tmp_path: Path) -> None:
    mod = _helper()
    primary = tmp_path / "repo"
    linked = tmp_path / "repo-wt"
    own = primary / ".git" / "mefor-coord"
    assert mod.is_primary(own, str(primary)) is True
    assert mod.is_primary(own, str(linked)) is False
    assert mod.is_primary(None, str(linked)) is True


def test_a_singular_batch_takes_one_number_and_a_spaced_python_gets_the_call_operator() -> None:
    mod = _helper()
    assert mod.batches_in("batch 20014, 5850 and 5851") == [20014]
    pr = mod.Created("MEFORORG", "MessageFoundry", 1)
    cmd = mod.done_command(r"C:\Program Files\py\python.exe", r"C:\rb.py", "52", pr, None, [])
    assert cmd.startswith(r'& "C:\Program Files\py\python.exe" C:\rb.py --done 52 ')


# ---------------------------------------------------------------------------- the installer row


def _install(settings: Path, *args: str) -> None:
    _need_pwsh()
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALLER)]
        + ["-SettingsPath", str(settings), *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def _post(settings: Path) -> list[dict[str, Any]]:
    data = json.loads(settings.read_text(encoding="utf-8-sig"))
    groups: list[dict[str, Any]] = data["hooks"].get("PostToolUse", [])
    return groups


def test_the_installer_row_exists_and_installs_idempotently(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    foreign = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo foreign-post"}]}
    settings.write_text(json.dumps({"hooks": {"PostToolUse": [foreign]}}), encoding="utf-8")
    _install(settings)
    first = settings.read_text(encoding="utf-8-sig")
    ours = [g for g in _post(settings) if MARKER in g["hooks"][0]["command"]]
    assert len(ours) == 1
    assert ours[0]["matcher"] == "Bash|PowerShell"
    assert f"'{HOOK_REL}'" in ours[0]["hooks"][0]["command"]
    assert "async" not in ours[0]["hooks"][0]
    _install(settings)
    assert settings.read_text(encoding="utf-8-sig") == first
    _install(settings, "-Script", "runbook-done-prompt", "-Uninstall")
    assert _post(settings) == [foreign]


def test_the_row_is_listed_in_the_header_table() -> None:
    assert "PostToolUse Bash|PowerShell" in _SRC and HOOK_REL in _SRC
