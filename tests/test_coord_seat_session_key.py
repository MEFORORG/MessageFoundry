# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A CLI ``-Declare`` must land on the SAME record the hooks write, not beside it.

``seat.ps1`` keys one record per (worktree, session). The two hooks read ``session_id`` off their
stdin payload and pass it as ``-SessionId``. The CLI path -- the one the SessionStart banner prints
and tells every seat to run -- has no payload and no id a person could type, so it fell through to
the literal string ``nosid``.

Both records were valid, which is why nothing reported it. Measured 2026-08-21 across the live
seats directory:

    21 declarations total
    18 in nosid.json, attributable to no session
     3 on a session-keyed record
    18 of 18 boxes ALSO held a session-keyed record reading seat=null, goal=null

``fleet.ps1`` rendered each of those boxes twice, once declared and once NOT-DECLARED. So the fleet
could see a goal and could see a live session and could not join them -- which is the question the
declaration exists to answer.

This is the hollow-record failure CLAUDE.md section 5 describes, one layer further in.
test_coord_seat_prompt.py established that a DERIVED label may never read as a DECLARED one; the
property here is the other half. **A declaration must attach to the session that made it.** A goal
in an unattributable record is not a weaker declaration, it is a record that looks declared and
cannot be acted on.

Note what let it survive: every test in test_coord_seat_prompt.py passes ``-SessionId`` explicitly,
so the suite was green and blind to the invocation the banner actually prints.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SEAT = ROOT / "scripts" / "coord" / "seat.ps1"
MAILKEY = ROOT / "scripts" / "coord" / "mail-key.ps1"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway checkout carrying its OWN copy of the script under test.

    seat.ps1 anchors on where it LIVES, so copying it in is what keeps a stray record out of the
    real registry -- the sandbox lesson test_coord_claim_refresh.py records.
    """
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    shutil.copy2(SEAT, r / "scripts" / "coord" / "seat.ps1")
    shutil.copy2(MAILKEY, r / "scripts" / "coord" / "mail-key.ps1")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def seat(cwd: Path, *args: str, session_env: str | None) -> subprocess.CompletedProcess[str]:
    """Run seat.ps1 with CLAUDE_CODE_SESSION_ID set, or explicitly ABSENT.

    The env is built from scratch rather than mutated, because the suite itself runs inside a
    Claude Code session that sets this variable -- inheriting it would make the negative control
    silently untestable, which is the exact shape of blindness this module is about.
    """
    env = dict(os.environ)
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    if session_env is not None:
        env["CLAUDE_CODE_SESSION_ID"] = session_env
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(cwd / "scripts" / "coord" / "seat.ps1"),
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )


def records(repo: Path) -> dict[str, dict[str, object]]:
    """Every record in the box, keyed by file stem -- the reader's view, not one blessed file."""
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    found = sorted(Path(common).joinpath("mefor-coord", "seats").rglob("*.json"))
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in found}


class TestTheCliDeclarationAttachesToItsSession:
    def test_declare_without_SessionId_uses_the_env_session(self, repo: Path) -> None:
        """The defect, stated directly: this is the invocation the banner prints."""
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", session_env="sess-abc")
        recs = records(repo)
        assert "sess-abc" in recs, f"declaration did not attach to the session: {sorted(recs)}"
        assert recs["sess-abc"]["seat"] == "lander"
        assert recs["sess-abc"]["goal"] == "g"

    def test_the_env_derived_key_is_labelled_env(self, repo: Path) -> None:
        """A reader must be able to tell where the identity came from, as with seatSource."""
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", session_env="sess-abc")
        assert records(repo)["sess-abc"]["sessionIdSource"] == "env"

    def test_no_nosid_record_is_left_beside_it(self, repo: Path) -> None:
        """The split IS the bug. One session must not render as two seats."""
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", session_env="sess-abc")
        assert "nosid" not in records(repo)

    def test_a_hook_record_and_a_cli_declaration_land_on_ONE_record(self, repo: Path) -> None:
        """The live failure, reproduced end to end.

        The hook path passes -SessionId; the CLI path passes nothing. Before the env rung these
        produced two records in one box: one carrying the session and no goal, one carrying the
        goal and no session.
        """
        seat(repo, "-Record", "-SessionId", "sess-abc", session_env="sess-abc")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", session_env="sess-abc")
        recs = records(repo)
        assert sorted(recs) == ["sess-abc"], f"expected one record, got {sorted(recs)}"
        assert recs["sess-abc"]["seat"] == "lander"
        assert recs["sess-abc"]["sessionId"] == "sess-abc"


class TestPrecedence:
    def test_an_explicit_SessionId_outranks_the_env(self, repo: Path) -> None:
        """A test or a cross-cwd declare names the session on purpose; env must not override it."""
        seat(
            repo,
            "-Declare",
            "-Seat",
            "lander",
            "-Goal",
            "g",
            "-SessionId",
            "explicit",
            session_env="from-env",
        )
        recs = records(repo)
        assert "explicit" in recs and "from-env" not in recs
        assert recs["explicit"]["sessionIdSource"] == "param"

    def test_without_an_env_session_it_still_falls_back_to_nosid(self, repo: Path) -> None:
        """The negative control, and it is what proves the env rung is doing the work.

        Without it a passing suite would be consistent with seat.ps1 ignoring the variable and
        every record simply being named by something else.
        """
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", session_env=None)
        recs = records(repo)
        assert sorted(recs) == ["nosid"]
        assert recs["nosid"]["sessionId"] is None
        assert recs["nosid"]["sessionIdSource"] == "absent"

    def test_the_host_session_id_is_NOT_used(self, repo: Path) -> None:
        """CLAUDE_CODE_HOST_SESSION_ID is the `local_` MCP namespace, a different identifier.

        Keying on it would re-split every box, so it must not be read even when it is the only
        session variable present.
        """
        env_proc = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(repo / "scripts" / "coord" / "seat.ps1"),
                "-Declare",
                "-Seat",
                "lander",
                "-Goal",
                "g",
            ],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            env={
                **{k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_SESSION_ID"},
                "CLAUDE_CODE_HOST_SESSION_ID": "local_should-not-be-used",
            },
        )
        assert env_proc.returncode == 0, env_proc.stderr
        recs = records(repo)
        assert sorted(recs) == ["nosid"], f"host id must not key a record: {sorted(recs)}"
