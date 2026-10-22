# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A fake ``gh api`` for the AFK-autonomy script tests (ADR 0211), and the sandbox they run in.

Run as a script, it answers the few REST routes the scripts use from a JSON state file named by
``FAKE_GH_STATE``: a repository Actions variable, the vault's issues and labels, and an issue's
comments. Every call is appended to the state's ``calls``, so a test can prove a path made none.
State knobs: ``fail`` (every call exits 1, a network failure), ``fail_post`` (only POSTs fail),
``hang`` (sleep that many seconds before answering).

``Sandbox`` puts a ``gh.ps1`` shim first on PATH. PowerShell resolves a ``.ps1`` on PATH itself and
passes argv through untouched, so the scripts under test call it exactly as they call the real gh.
The scripts anchor on where they live, so each sandbox is a fresh git repository holding its own
copy of scripts/coord and scripts/hooks, and every ``.git/mefor-coord`` write lands there and never
in the real registry.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
VAULT = "MEFORORG/MessageFoundry-vault"
ENGINE = "MEFORORG/MessageFoundry"


# _decisionlog.ps1's Get-DecisionIdDay pattern: a decision id carries its UTC day.
_DECISION_ID = re.compile(r"d(\d{4})(\d{2})(\d{2})T\d{9}-[0-9a-f]{6}")

# The room utc_day_with_room() keeps before UTC midnight, and the per-test timeout a test that
# calls it must carry: the wait can reach MIDNIGHT_ROOM_S + 1 seconds, and the runs after it get
# the rest, where a Windows tooling leg has been measured starving one pwsh launch past 45 s.
MIDNIGHT_ROOM_S = 120.0
GUARDED_TIMEOUT_S = 360


def id_day(decision_id: str) -> str:
    """The UTC day a decision id carries; refuses a string that is not a decision id."""
    m = _DECISION_ID.fullmatch(decision_id)
    assert m is not None, f"not a decision id: {decision_id!r}"
    return "-".join(m.groups())


def utc_day_now() -> str:
    return datetime.now(UTC).date().isoformat()


def utc_day_with_room(seconds: float = MIDNIGHT_ROOM_S) -> str:
    """Today's UTC day, first waiting out midnight if fewer than ``seconds`` of it remain.

    decision.ps1 mints a record's id, and so its day, from the wall clock and has no seam for it.
    A test whose script runs must all land on one day calls this first, so the runs that follow
    it land on the day it returns rather than straddling UTC midnight. The wait outlasts the
    60-second per-test timeout, so a caller carries ``@pytest.mark.timeout(GUARDED_TIMEOUT_S)``.
    """
    now = datetime.now(UTC)
    midnight = datetime(now.year, now.month, now.day, tzinfo=UTC) + timedelta(days=1)
    left = (midnight - now).total_seconds()
    if left < seconds:
        time.sleep(left + 1)
    return utc_day_now()


def with_default(args: tuple[str, ...], name: str, value: str) -> tuple[str, ...]:
    """``args`` led by ``name value``, unless the test names that parameter itself.

    Matched as PowerShell binds a full name: any case, bare or as ``-Name:value``.
    """
    lower = name.lower()
    named = any(a.lower() == lower or a.lower().startswith(lower + ":") for a in args)
    return args if named else (name, value, *args)


def _answer(state: dict[str, Any], argv: list[str]) -> tuple[int, str, str]:
    if state.get("hang"):
        time.sleep(float(state["hang"]))
    if state.get("fail"):
        return 1, "", "error connecting to api.github.com"
    if not argv or argv[0] != "api":
        return 2, "", f"fake gh: unsupported {argv}"
    method, path, body, slurp = "GET", "", None, False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "-X":
            method, i = argv[i + 1], i + 2
        elif a == "--input":
            body, i = json.loads(Path(argv[i + 1]).read_text(encoding="utf-8")), i + 2
        elif a == "--slurp":
            slurp, i = True, i + 1
        elif a.startswith("-"):
            i += 1
        else:
            path, i = a, i + 1
    if method == "POST" and state.get("fail_post"):
        return 1, "", "HTTP 502: Bad Gateway"
    url = urllib.parse.urlsplit(path)
    parts = url.path.strip("/").split("/")
    query = urllib.parse.parse_qs(url.query)
    if len(parts) < 3 or parts[0] != "repos":
        return 1, "", "gh: Not Found (HTTP 404)"
    repo = f"{parts[1]}/{parts[2]}"
    rest = parts[3:]
    store = state.setdefault("repos", {}).setdefault(repo, {"issues": [], "labels": []})
    if rest[:2] == ["actions", "variables"] and len(rest) == 3 and method == "GET":
        value = state.get("variables", {}).get(rest[2])
        if value is None:
            return 1, "", "gh: Not Found (HTTP 404)"
        return 0, json.dumps({"name": rest[2], "value": value}), ""
    if rest == ["labels"] and method == "POST":
        assert body is not None
        if body["name"] in store["labels"]:
            return 1, "", "gh: Validation Failed (HTTP 422)"
        store["labels"].append(body["name"])
        return 0, json.dumps(body), ""
    if rest == ["issues"] and method == "GET":
        label = query.get("labels", [""])[0]
        found = [
            {"number": x["number"], "title": x["title"]}
            for x in sorted(store["issues"], key=lambda x: -int(x["number"]))
            if not label or label in x["labels"]
        ]
        return 0, json.dumps([found] if slurp else found), ""
    if rest == ["issues"] and method == "POST":
        assert body is not None
        issue = {
            "number": len(store["issues"]) + 1,
            "title": body["title"],
            "labels": [lb for lb in body.get("labels", []) if lb in store["labels"]],
            "comments": [],
        }
        store["issues"].append(issue)
        return 0, json.dumps({"number": issue["number"]}), ""
    if len(rest) == 3 and rest[0] == "issues" and rest[2] == "comments":
        match: dict[str, Any] | None = next(
            (x for x in store["issues"] if x["number"] == int(rest[1])), None
        )
        if match is None:
            return 1, "", "gh: Not Found (HTTP 404)"
        issue = match
        if method == "POST":
            assert body is not None
            issue["comments"].append({"id": len(issue["comments"]) + 1, "body": body["body"]})
            return 0, json.dumps(issue["comments"][-1]), ""
        page = [{"id": c["id"], "body": c["body"]} for c in issue["comments"]]
        return 0, json.dumps([page] if slurp else page), ""
    return 1, "", "gh: Not Found (HTTP 404)"


def main(argv: list[str]) -> int:
    state_path = Path(os.environ["FAKE_GH_STATE"])
    state: dict[str, Any] = (
        json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    )
    state.setdefault("calls", []).append(argv)
    code, out, err = _answer(state, argv)
    state_path.write_text(json.dumps(state), encoding="utf-8")
    sys.stdout.write(out)
    sys.stderr.write(err)
    return code


@dataclass
class Sandbox:
    """A git repository to run in, and a fake gh first on PATH with its state file."""

    repo: Path
    shim: Path
    state_path: Path

    @property
    def state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {}
        loaded: dict[str, Any] = json.loads(self.state_path.read_text(encoding="utf-8"))
        return loaded

    def set_state(self, **knobs: Any) -> None:
        state = self.state
        state.update(knobs)
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

    @property
    def calls(self) -> list[list[str]]:
        calls: list[list[str]] = self.state.get("calls", [])
        return calls

    def issues(self, repo: str = VAULT) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = self.state.get("repos", {}).get(repo, {}).get("issues", [])
        return issues

    @property
    def coord(self) -> Path:
        return self.repo / ".git" / "mefor-coord"

    def spool(self) -> list[Path]:
        d = self.coord / "decisions" / "spool"
        return sorted(d.iterdir()) if d.is_dir() else []

    def env(self, **extra: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k not in {"CLAUDE_CODE_REMOTE"}}
        env["PATH"] = str(self.shim) + os.pathsep + env.get("PATH", "")
        env["FAKE_GH_STATE"] = str(self.state_path)
        env["CLAUDE_CODE_SESSION_ID"] = "sess-test-0001"
        env.update(extra)
        return env

    def run(
        self, script: Path, *args: str, stdin: str = "", **extra: str
    ) -> subprocess.CompletedProcess[str]:
        """Run a script by its real-tree path; the sandbox's own copy is what runs."""
        local = self.repo / script.resolve().relative_to(ROOT)
        return subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(local), *args],
            cwd=str(self.repo),
            env=self.env(**extra),
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
        )


def make_sandbox(tmp_path: Path) -> Sandbox:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True, timeout=60)
    # The scripts anchor on where they live, so each sandbox runs its own copy of them.
    for sub in ("coord", "hooks"):
        shutil.copytree(ROOT / "scripts" / sub, repo / "scripts" / sub)
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "gh.ps1").write_text(
        f"& '{sys.executable}' '{Path(__file__).resolve()}' @args\nexit $LASTEXITCODE\n",
        encoding="utf-8",
    )
    return Sandbox(repo=repo, shim=shim, state_path=tmp_path / "gh-state.json")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
