# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The fleet wiki write prompt: a Stop hook that asks for one note after substantive work.

Owner decision 2026-09-26. The hook is ``scripts/hooks/wiki-write-prompt.ps1`` and the installer row is
``mefor-wiki`` in ``scripts/coord/install-coordination.ps1``. Every test drives the real script with a
synthetic Stop payload and a synthetic transcript in a throwaway git repository, so the coordination
directory it writes is ``<tmp repo>/.git/mefor-coord`` and nothing on the real box is touched.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts" / "hooks" / "wiki-write-prompt.ps1"

# Below pyproject.toml's --timeout=60 so a hung child fails THIS test by name.
TIMEOUT = 45

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the hook and its installer need pwsh on Windows",
)


def _threshold(name: str) -> int:
    """Read a threshold out of the hook, so the tests follow a tuning change instead of pinning it."""
    m = re.search(rf"^\${name}\s*=\s*(\d+)\s*$", HOOK.read_text(encoding="utf-8"), re.MULTILINE)
    assert m, f"could not find ${name} in {HOOK}"
    return int(m.group(1))


MIN_TOOLS = _threshold("MinToolUses")
COOLDOWN = _threshold("CooldownMinutes")


# --------------------------------------------------------------------------------------------------
# Fixtures and helpers
# --------------------------------------------------------------------------------------------------


def _clean_env() -> dict[str, str]:
    """The fixture decides what the hook reads, not whoever runs the suite. A GIT_DIR inherited from
    a git hook would point `git -C <tmp>` at the REAL repository and its live coordination tree."""
    scrub = {"MEFOR_WIKI_PROMPT", "KORUS_SEAT", "KORUS_AGENT", "KORUS_STATE_REL"}
    return {k: v for k, v in os.environ.items() if k not in scrub and not k.startswith("GIT_")}


class Env:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.repo = base / "primary"
        self.repo.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(self.repo)], check=True, capture_output=True, env=_clean_env()
        )
        common = subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=_clean_env(),
        ).stdout.strip()
        self.coord = Path(common) / "mefor-coord"
        self.prompt_dir = self.coord / "wiki-prompt"
        self.transcript = base / "transcript.jsonl"
        self.transcript.write_text("", encoding="utf-8")
        self.session = "sess-0001"

    def append(self, entries: list[dict[str, Any]]) -> None:
        with self.transcript.open("a", encoding="utf-8", newline="\n") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def run(
        self,
        *,
        active: bool = False,
        stdin: str | None = None,
        env: dict[str, str] | None = None,
        transcript: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        payload = stdin
        if payload is None:
            payload = json.dumps(
                {
                    "session_id": self.session,
                    "transcript_path": transcript or str(self.transcript),
                    "cwd": str(self.repo),
                    "hook_event_name": "Stop",
                    "stop_hook_active": active,
                },
                # Raw UTF-8, as Claude Code sends it, not ASCII escapes: a non-ASCII path must
                # survive the hook's stdin decoding.
                ensure_ascii=False,
            )
        full_env = _clean_env()
        full_env.update(env or {})
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(HOOK)],
            input=payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=TIMEOUT,
            env=full_env,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        return proc

    @property
    def state_path(self) -> Path:
        return self.prompt_dir / "state" / f"{self.session}.json"

    def logs(self) -> list[dict[str, Any]]:
        lines: list[dict[str, Any]] = []
        for p in sorted(self.prompt_dir.glob("log-*.jsonl")):
            lines += [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x]
        return lines


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def tool_use(
    name: str = "Read", command: str | None = None, file_path: str = "x.py"
) -> dict[str, Any]:
    inp: dict[str, Any] = {"file_path": file_path} if command is None else {"command": command}
    return {
        "type": "assistant",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "toolu_1", "name": name, "input": inp}],
        },
    }


def tool_result() -> dict[str, Any]:
    return {
        "type": "user",
        "message": {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}],
        },
    }


def tools(n: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for _ in range(n):
        out += [tool_use(), tool_result()]
    return out


def blocked(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert proc.stdout.strip(), "expected a block decision, got no output"
    out: dict[str, Any] = json.loads(proc.stdout)
    assert out["decision"] == "block"
    return out


def silent(proc: subprocess.CompletedProcess[str]) -> None:
    assert proc.stdout == "", f"expected no output, got {proc.stdout!r}"


def backdate(env: Env, minutes: int) -> None:
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    state["lastPromptUnix"] = int((datetime.now(UTC) - timedelta(minutes=minutes)).timestamp())
    env.state_path.write_text(json.dumps(state), encoding="utf-8")


# --------------------------------------------------------------------------------------------------
# The hook
# --------------------------------------------------------------------------------------------------


def test_stop_hook_active_never_blocks(env: Env) -> None:
    env.append(tools(MIN_TOOLS + 5))
    silent(env.run(active=True))
    # Positive control: the same transcript does fire once the loop guard is off.
    blocked(env.run())


def test_below_threshold_is_silent(env: Env) -> None:
    env.append(tools(MIN_TOOLS - 1))
    silent(env.run())


def test_threshold_tool_uses_block_with_the_resolved_state_root(env: Env) -> None:
    env.append(tools(MIN_TOOLS))
    reason = blocked(env.run())["reason"]
    coord = str(env.coord).replace("\\", "/")
    assert f'-StateRoot "{coord}"' in reason
    assert "wiki: nothing to record" in reason
    assert "write.ps1" in reason
    assert "query.ps1" in reason
    assert reason.isascii()
    # No korus checkout beside the primary in this fixture, so the placeholder stays.
    assert "<korus checkout>/scripts/wiki/write.ps1" in reason
    # No seat resolved, so -Seat is left for write.ps1 to resolve rather than filled with a
    # placeholder that both shells would misparse.
    assert "-Seat" not in reason
    # The evidence form korus write.ps1 accepts is ref:path, not path@ref.
    assert "ref:path" in reason


def test_the_korus_path_and_seat_resolve_when_present(env: Env) -> None:
    korus_write = env.base / "korus" / "scripts" / "wiki" / "write.ps1"
    korus_write.parent.mkdir(parents=True)
    korus_write.write_text("# stub\n", encoding="utf-8")
    (env.repo / ".claude").mkdir()
    (env.repo / ".claude" / "seat.local.txt").write_text("manager", encoding="utf-8")
    env.append(tools(MIN_TOOLS))
    reason = blocked(env.run())["reason"]
    korus = str(env.base / "korus").replace("\\", "/")
    assert f'"{korus}/scripts/wiki/write.ps1"' in reason
    assert "-Seat manager" in reason
    assert env.logs()[-1]["seat"] == "manager"


@pytest.mark.parametrize(
    "command",
    [
        'git commit -m "x"',
        "git -C C:/some/worktree commit -F msg.txt",
        "git push -u origin claude/branch",
    ],
)
def test_a_commit_or_push_alone_triggers(env: Env, command: str) -> None:
    env.append([tool_use("Bash", command), tool_result()])
    blocked(env.run())
    assert env.logs()[-1]["trigger"] == "commit"


@pytest.mark.parametrize(
    "command",
    [
        "git status",
        "git log --oneline -5",
        "git commit-tree HEAD^{tree}",
        "git commit-graph write",
        'grep -rn "git push" docs/',
        "rg -n 'git commit' scripts",
        'echo "then git push it"',
    ],
)
def test_a_git_verb_that_is_not_commit_or_push_does_not_trigger(env: Env, command: str) -> None:
    env.append([tool_use("Bash", command)])
    silent(env.run())


@pytest.mark.parametrize(
    "command",
    [
        "cd C:/wt && git commit -m x",
        "git --git-dir /x/.git --work-tree /y commit -m x",
        'git -C "C:/a b" push',
    ],
)
def test_a_commit_in_a_compound_or_optioned_command_triggers(env: Env, command: str) -> None:
    env.append([tool_use("Bash", command)])
    blocked(env.run())


@pytest.mark.parametrize(
    "command",
    [
        "git " + "--ab " * 60 + "status",
        "git " + "-c -c " * 40 + "status",
        "git " + '-C "x" ' * 40 + "status",
    ],
)
def test_a_long_run_of_options_does_not_stall_the_hook(env: Env, command: str) -> None:
    """Options that could be matched two ways made the commit regex exponential. The regex has a
    1 s timeout as well, so one command would hide the defect; thirty of them would not."""
    env.append([tool_use("Bash", command)] * 30)
    start = time.monotonic()
    proc = env.run()
    elapsed = time.monotonic() - start
    blocked(proc)
    assert env.logs()[-1]["trigger"] == "tools"
    assert elapsed < 15, f"hook took {elapsed:.1f}s over 30 option-heavy commands"


@pytest.mark.parametrize(
    "command",
    [
        "git show origin/main:scripts/wiki/write.ps1",
        "grep -n wiki/write.ps1 docs/METHOD.md",
        "pwsh -File C:/korus/scripts/wiki/write.ps1 -CheckOnly -Type lesson -Key a/b",
        "Select-String -Path C:/korus/scripts/wiki/write.ps1 -Pattern '-Type'",
    ],
)
def test_a_command_that_only_names_write_ps1_is_not_a_write(env: Env, command: str) -> None:
    env.append(tools(MIN_TOOLS - 1))
    env.append([tool_use("Bash", command)])
    blocked(env.run())


def test_a_relative_write_from_the_wiki_directory_is_a_write(env: Env) -> None:
    env.append(tools(MIN_TOOLS + 1))
    env.append(
        [tool_use("PowerShell", "cd C:/korus/scripts/wiki; pwsh -File ./write.ps1 -Type lesson")]
    )
    silent(env.run())


def test_a_wiki_write_suppresses_the_prompt(env: Env) -> None:
    env.append(tools(MIN_TOOLS + 3))
    env.append(
        [
            tool_use("Bash", 'git commit -m "x"'),
            tool_use(
                "PowerShell",
                "pwsh -NoProfile -File C:\\korus\\scripts\\wiki\\write.ps1 -StateRoot x -Type lesson",
            ),
            tool_result(),
        ]
    )
    silent(env.run())


def test_a_read_of_write_ps1_is_not_a_write(env: Env) -> None:
    env.append(tools(MIN_TOOLS - 1))
    env.append([tool_use("Read", file_path="C:/korus/scripts/wiki/write.ps1")])
    blocked(env.run())


def test_the_prompt_text_in_the_transcript_is_not_a_write(env: Env) -> None:
    """The reason the hook emits names write.ps1 and lands in the transcript. It must not read as a
    write, or every prompt would suppress the next one."""
    env.append(tools(MIN_TOOLS))
    reason = blocked(env.run())["reason"]
    env.append([{"type": "user", "message": {"role": "user", "content": reason}}])
    env.append(tools(MIN_TOOLS))
    backdate(env, COOLDOWN + 1)
    blocked(env.run())


def test_the_cooldown_holds(env: Env) -> None:
    env.append(tools(MIN_TOOLS))
    blocked(env.run())
    env.append(tools(MIN_TOOLS))
    env.append([tool_use("Bash", 'git commit -m "y"')])
    silent(env.run())
    backdate(env, COOLDOWN - 1)
    silent(env.run())
    backdate(env, COOLDOWN + 1)
    blocked(env.run())
    assert len(env.logs()) == 2


def test_the_hooks_own_timestamp_expires_on_time(env: Env) -> None:
    """The cooldown must run from the time the hook itself wrote, not only from a backdated one.
    An ISO string once came back through ConvertFrom-Json shifted by the local UTC offset."""
    env.append(tools(MIN_TOOLS))
    blocked(env.run())
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    age = datetime.now(UTC).timestamp() - state["lastPromptUnix"]
    assert 0 <= age < 120
    state["lastPromptUnix"] -= (COOLDOWN + 1) * 60
    env.state_path.write_text(json.dumps(state), encoding="utf-8")
    env.append(tools(MIN_TOOLS))
    blocked(env.run())


def test_the_offset_does_not_recount_old_lines(env: Env) -> None:
    env.append(tools(MIN_TOOLS - 5))
    silent(env.run())
    # Re-reading from the start would count twice past the threshold and fire.
    silent(env.run())
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state["tools"] == MIN_TOOLS - 5
    assert state["offset"] == env.transcript.stat().st_size
    # New lines are still counted on top.
    env.append(tools(5))
    blocked(env.run())


def test_a_partial_last_line_waits_for_its_newline(env: Env) -> None:
    env.append(tools(MIN_TOOLS - 1))
    half = json.dumps(tool_use())
    with env.transcript.open("a", encoding="utf-8", newline="\n") as f:
        f.write(half[:20])
    silent(env.run())
    with env.transcript.open("a", encoding="utf-8", newline="\n") as f:
        f.write(half[20:] + "\n")
    blocked(env.run())


def test_env_opt_out(env: Env) -> None:
    env.append(tools(MIN_TOOLS))
    silent(env.run(env={"MEFOR_WIKI_PROMPT": "off"}))
    assert not env.state_path.exists()


def test_file_opt_out(env: Env) -> None:
    env.prompt_dir.mkdir(parents=True)
    (env.prompt_dir / "OFF").write_text("", encoding="utf-8")
    env.append(tools(MIN_TOOLS))
    silent(env.run())
    assert not env.state_path.exists()


@pytest.mark.parametrize("stdin", ["", "not json", "[1,2]", '{"session_id": "../../x"}'])
def test_bad_stdin_is_silent(env: Env, stdin: str) -> None:
    silent(env.run(stdin=stdin))


def test_a_missing_transcript_is_silent(env: Env) -> None:
    silent(env.run(transcript=str(env.base / "nope.jsonl")))


@pytest.mark.parametrize(
    "bad",
    [
        "{ not json",
        "",
        "null",
        "[]",
        '{"offset": "abc"}',
        '{"offset": -5}',
        '{"tools": "x"}',
        '{"lastPromptUnix": "yesterday"}',
    ],
)
def test_unreadable_state_fails_open_and_heals(env: Env, bad: str) -> None:
    env.state_path.parent.mkdir(parents=True)
    env.state_path.write_text(bad, encoding="utf-8")
    env.append(tools(MIN_TOOLS))
    silent(env.run())
    # Rewritten from the transcript's end, so the old lines are not counted again...
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state["offset"] == env.transcript.stat().st_size
    # ...and new work still prompts once the fresh cooldown has run.
    backdate(env, COOLDOWN + 1)
    env.append(tools(MIN_TOOLS))
    blocked(env.run())


def test_first_sight_of_a_long_transcript_reads_only_its_tail(env: Env) -> None:
    """Work from before the hook saw the session is old history, not a reason to prompt."""
    env.append(tools(MIN_TOOLS * 2))
    pad = {"type": "user", "message": {"content": [{"type": "text", "text": "x" * 100_000}]}}
    env.append([pad] * 90)  # about 9 MB, past the 8 MB read cap
    assert env.transcript.stat().st_size > 8 * 1024 * 1024
    silent(env.run())
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state["tools"] == 0
    assert state["offset"] == env.transcript.stat().st_size


def test_a_non_ascii_path_survives(tmp_path: Path) -> None:
    base = tmp_path / "José"
    base.mkdir()
    env = Env(base)
    env.append(tools(MIN_TOOLS))
    reason = blocked(env.run())["reason"]
    assert f'-StateRoot "{str(env.coord).replace(chr(92), "/")}"' in reason
    assert env.state_path.is_file()


def test_a_shrunk_transcript_restarts_its_counts(env: Env) -> None:
    env.append(tools(MIN_TOOLS - 5))
    silent(env.run())
    env.transcript.write_text("", encoding="utf-8")
    env.append(tools(MIN_TOOLS - 5))
    silent(env.run())
    state = json.loads(env.state_path.read_text(encoding="utf-8"))
    assert state["tools"] == MIN_TOOLS - 5


def test_the_log_line_is_written_when_it_fires(env: Env) -> None:
    env.append(tools(MIN_TOOLS - 1))
    silent(env.run())
    assert env.logs() == []
    env.append(tools(1))
    blocked(env.run())
    (line,) = env.logs()
    assert line["session_id"] == env.session
    assert line["trigger"] == "tools"
    assert line["tools"] == MIN_TOOLS
    assert line["seat"] == ""
    datetime.fromisoformat(line["utc"])
    # Never under the wiki scripts' own tree.
    assert not (env.coord / "wiki").exists()
