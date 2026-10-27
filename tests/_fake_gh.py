# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A fake ``gh api`` for the AFK-autonomy script tests (ADR 0211), and the sandbox they run in.

Run as a script, it answers the few REST routes the scripts use from a JSON state file named by
``FAKE_GH_STATE``: a repository Actions variable, the vault's issues and labels, and an issue's
comments. Every call is appended to the state's ``calls``, so a test can prove a path made none.
State knobs: ``fail`` (every call exits 1, a network failure), ``fail_post`` (only POSTs fail),
``fail_match`` (a call with an argument containing that text fails), ``hang`` (sleep that many
seconds before answering), ``after_match`` (once a call with an argument containing its
``match`` has answered, post its ``record`` to the vault and delete the file ``remove``: a
concurrent flusher posting a spooled record), ``snapshot_spool`` (a directory whose file names
each comment POST appends to ``snapshots``, as the spool stood while the post was in flight) and
``hold_spool`` (``{"dir", "stop"}``: on a comment POST, every ``*.json`` file in ``dir`` is made
undeletable until the test writes ``stop``; Windows holds each open without delete sharing,
elsewhere the directory is made read-only and the test restores it).

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


# The marker decision.ps1 starts each vault comment with (_decisionlog.ps1 DecisionMarker).
DECISION_MARKER = "<!-- mefor-decision v1 -->"


def seed_vault(sb: Sandbox, records: list[dict[str, Any]]) -> None:
    """Post records straight into the fake vault, as decision.ps1 would: one issue per UTC day."""
    state = sb.state
    _post_records(state, records)
    sb.state_path.write_text(json.dumps(state), encoding="utf-8")


def _post_records(state: dict[str, Any], records: list[dict[str, Any]]) -> None:
    store = state.setdefault("repos", {}).setdefault(VAULT, {"issues": [], "labels": []})
    for r in records:
        title = f"decision-log {id_day(r['id'])}"
        issue = next((i for i in store["issues"] if i["title"] == title), None)
        if issue is None:
            issue = {
                "number": len(store["issues"]) + 1,
                "title": title,
                "labels": ["decision-log"],
                "comments": [],
            }
            store["issues"].append(issue)
        body = f"{DECISION_MARKER}\nheader\n\n```json\n{json.dumps(r, indent=2)}\n```"
        issue["comments"].append({"id": len(issue["comments"]) + 1, "body": body})


def no_host_usage(sb: Sandbox, args: tuple[str, ...]) -> tuple[str, ...]:
    """``args`` pointing the cost rung at the stand-in usage reader beside the sandbox state file
    and at a thresholds file there, unless the test names either itself. Without them the gate and
    the digest would read the host account's own usage files."""
    folder = sb.state_path.parent
    args = with_default(args, "-UsageScript", str(folder / "usage.ps1"))
    return with_default(args, "-ThresholdsFile", str(folder / "thresholds.json"))


def write_fake_usage(
    path: Path, doc: dict[str, Any] | str, code: int = 0, prelude: str = ""
) -> Path:
    """A stand-in for usage.ps1 that prints ``doc`` as its -Json answer and exits ``code``.

    decision.ps1 and digest.ps1 take it as -UsageScript, so a test never reads the host account's
    real usage files, and the cost rung answers what the test wrote. ``prelude`` is PowerShell run
    first, for a test that acts while the gate waits on the reader.
    """
    text = doc if isinstance(doc, str) else json.dumps(doc)
    # A literal here-string, so nothing in the JSON is expanded.
    path.write_text(f"{prelude}Write-Output @'\n{text}\n'@\nexit {code}\n", encoding="utf-8")
    return path


def _answer(state: dict[str, Any], argv: list[str]) -> tuple[int, str, str]:
    if state.get("hang"):
        time.sleep(float(state["hang"]))
    if state.get("fail"):
        return 1, "", "error connecting to api.github.com"
    if state.get("fail_match") and any(state["fail_match"] in a for a in argv):
        return 1, "", "HTTP 503: Service Unavailable"
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


def _hold_spool(hold: dict[str, str]) -> None:
    folder, stop = Path(hold["dir"]), Path(hold["stop"])
    if sys.platform != "win32":
        folder.chmod(0o555)
        return
    ready = stop.with_name(stop.name + ".ready")
    holder = (
        "import sys, time, pathlib\n"
        "d, stop, ready = (pathlib.Path(a) for a in sys.argv[1:4])\n"
        "held = [p.open('rb') for p in d.glob('*.json')]\n"
        "ready.write_text('ready')\n"
        "end = time.monotonic() + 120\n"
        "while not stop.exists() and time.monotonic() < end:\n"
        "    time.sleep(0.05)\n"
    )
    subprocess.Popen(
        [sys.executable, "-c", holder, str(folder), str(stop), str(ready)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    end = time.monotonic() + 30
    while not ready.exists() and time.monotonic() < end:
        time.sleep(0.05)


def main(argv: list[str]) -> int:
    state_path = Path(os.environ["FAKE_GH_STATE"])
    state: dict[str, Any] = (
        json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    )
    state.setdefault("calls", []).append(argv)
    code, out, err = _answer(state, argv)
    posts_comment = "POST" in argv and any(a.endswith("/comments") for a in argv)
    if posts_comment and state.get("snapshot_spool"):
        state.setdefault("snapshots", []).append(sorted(os.listdir(state["snapshot_spool"])))
    if posts_comment and state.get("hold_spool"):
        _hold_spool(state.pop("hold_spool"))
    hook = state.get("after_match")
    if hook and any(hook["match"] in a for a in argv):
        # A concurrent flusher, once this call has answered: it posts the spooled record and only
        # then deletes its spool file, as Send-DecisionSpool does. It fires once.
        del state["after_match"]
        _post_records(state, [hook["record"]])
        Path(hook["remove"]).unlink()
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

    @property
    def spool_dir(self) -> Path:
        """_decisionlog.ps1's Get-DecisionSpoolDir in the sandbox."""
        return self.coord / "decisions" / "spool"

    def spool(self) -> list[Path]:
        d = self.spool_dir
        return sorted(d.iterdir()) if d.is_dir() else []

    def env(self, **extra: str) -> dict[str, str]:
        # MEFOR_COORD_ROOT would point a child at a real shared root, and KORUS_AGENT=codex would
        # move its seat lookup to the Codex box. A test that wants either passes it in `extra`.
        dropped = {"CLAUDE_CODE_REMOTE", "MEFOR_COORD_ROOT", "KORUS_AGENT"}
        env = {k: v for k, v in os.environ.items() if k not in dropped}
        env["PATH"] = str(self.shim) + os.pathsep + env.get("PATH", "")
        env["FAKE_GH_STATE"] = str(self.state_path)
        env["CLAUDE_CODE_SESSION_ID"] = "sess-test-0001"
        env.update(extra)
        return env

    def argv(self, script: Path, *args: str) -> list[str]:
        """The pwsh command line for a script by its real-tree path; the sandbox's copy runs."""
        local = self.repo / script.resolve().relative_to(ROOT)
        return ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(local), *args]

    def run(
        self, script: Path, *args: str, stdin: str = "", **extra: str
    ) -> subprocess.CompletedProcess[str]:
        """Run a script by its real-tree path; the sandbox's own copy is what runs."""
        return subprocess.run(
            self.argv(script, *args),
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
