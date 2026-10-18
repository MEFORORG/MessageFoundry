# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3236: two engine processes race repeat requests over ONE store.

``_assert_repeat_request_contract`` races repeats inside one process, where the SQLite and SQL
Server stores' in-process lock already serializes them, so it cannot show the serialization that
has to hold between engine shards or cluster nodes. That rests on each backend's own SQL: SQLite's
one ``INSERT ... WHERE NOT EXISTS`` under its write lock, SQL Server's read under the audit applock.

Here two child processes each open their own store over the same database and file the same
sequence of requests: round ``k`` carries the same params in both. Round ``k`` starts at the same
wall-clock instant in both children, a schedule the parent hands them once both stores are open,
so each round is a race between two processes rather than a repeat of a request that already
committed. The rig measures how many rounds really started together and fails when too few did.
The caller then checks each round holds ONE request, which both processes were answered with.

Every wait is bounded well under the suite's 60 s per-test timeout, so a hung child fails here,
with its stderr, rather than being cut off by pytest-timeout with nothing to read.

Extra-free, like the contract it sits beside: the children import the backend they are told to,
so the SQL Server leg can call this from inside a gated test.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]

#: The gap between two rounds' scheduled starts. Longer than two request writes in a row, so a
#: round that runs long does not push the next round's two starts apart: on SQL Server the losing
#: child waits on the winner's audit applock, so one round costs two serialized writes on a shared
#: CI container. 25 rounds take 5 s, well inside every wait below.
_ROUND_PERIOD_S = 0.2
#: Two starts closer than this count as one race. A request write takes milliseconds.
_TOGETHER_S = 0.004
#: The share of rounds that must start together for the run to count as a race at all.
_MIN_TOGETHER = 0.5

#: What each child runs. ``argv``: the target (``sqlserver``, or a SQLite file path), the run's
#: nonce, the round count and the start-signal file. It prints ``READY`` once its store is open,
#: reads the first round's start time from the signal file, and prints ``HELD <json>`` with the id
#: each round was answered with and the time each round started.
_CHILD = r"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from uuid import uuid4


async def _open(target):
    if target == "sqlserver":
        from messagefoundry.config.settings import load_settings
        from messagefoundry.config.tls_policy import HopPosture
        from messagefoundry.store.sqlserver import SqlServerStore

        # The parent's warn posture is a contextvar (tests/conftest.py,
        # _warn_posture_for_the_server_db_legs), which a child does not inherit. Without it the
        # CI container's self-signed certificate is refused as weakened TLS, so state it here, as
        # the applock child in test_sqlserver_store.py does. It is not inert on its own: since vault
        # BACKLOG #2223 it also turns a broadly writable [store].ssl_root_cert pin from a refusal
        # into a warning. The weakened-TLS cross the container needs still requires the
        # MEFOR_ALLOW_INSECURE_TLS escape as well.
        return await SqlServerStore.open(
            load_settings(environ=os.environ).store, posture=HopPosture(enforcing=False)
        )
    from messagefoundry.store.store import MessageStore

    return await MessageStore.open(Path(target))


async def main():
    from messagefoundry.store.store import AuditAppend

    target, nonce, rounds, go = sys.argv[1], sys.argv[2], int(sys.argv[3]), Path(sys.argv[4])
    period = float(sys.argv[5])
    store = await _open(target)
    held, starts = [], []
    try:
        print("READY", flush=True)
        deadline = time.monotonic() + 20.0
        while not go.exists():
            if time.monotonic() > deadline:
                raise SystemExit("no start signal within 20 s")
            await asyncio.sleep(0.005)
        first = float(go.read_text(encoding="utf-8"))
        for k in range(rounds):
            await asyncio.sleep(max(0.0, first + k * period - time.time()))
            starts.append(time.time())
            approval_id = uuid4().hex
            held.append(
                str(
                    await store.create_pending_approval(
                        approval_id=approval_id,
                        operation="dead_letter_replay",
                        params=json.dumps({"race": nonce, "round": k}, sort_keys=True),
                        requester="race-requester",
                        requester_user_id="race-requester-id",
                        requested_at=1000.0,
                        expires_at=None,
                        audit=AuditAppend(
                            "approval.requested",
                            actor="race-requester",
                            detail=json.dumps({"approval_id": approval_id}),
                        ),
                        on_repeat=lambda existing: AuditAppend(
                            "approval.request_repeated",
                            actor="race-requester",
                            detail=json.dumps({"approval_id": existing}),
                        ),
                    )
                )
            )
    finally:
        await store.close()
    print("HELD " + json.dumps({"held": held, "starts": starts}), flush=True)


asyncio.run(main())
"""


def race_repeat_requests(
    target: str, signal_dir: Path, nonce: str, *, rounds: int = 25
) -> list[list[str]]:
    """Run two children against ``target`` and return each one's answers, round by round.

    ``nonce`` goes into every request's params, so the caller can find and clean up what a failed
    run filed. Blocking, so an async test calls it through ``asyncio.to_thread``. A child that
    fails, or never opens its store, fails the call with its stderr."""
    go = signal_dir / f"race-go-{nonce}"
    argv = [sys.executable, "-c", _CHILD, target, nonce, str(rounds), str(go), str(_ROUND_PERIOD_S)]
    procs: list[subprocess.Popen[str]] = []
    # Each child's stderr goes to a file, never a pipe: a pipe nobody reads fills and blocks the
    # child, and the wait for READY below would then never end.
    errs = [signal_dir / f"race-err-{nonce}-{n}.txt" for n in range(2)]
    try:
        for err_path in errs:
            with err_path.open("w", encoding="utf-8") as err_file:
                procs.append(
                    subprocess.Popen(
                        argv,
                        cwd=_REPO_ROOT,
                        stdout=subprocess.PIPE,
                        stderr=err_file,
                        text=True,
                    )
                )
        for proc, err_path in zip(procs, errs, strict=True):
            ready, killed = _readline_within(proc, 20.0)
            if ready.strip() != "READY":
                # Said in words: a kill's exit code can match a crash's (1 on Windows).
                try:
                    code: int | None = proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    code = None
                raise AssertionError(
                    f"a child never opened its store: {ready!r}, "
                    f"{'killed after hanging' if killed else 'exited'} with code {code}; "
                    f"its stderr:\n{_tail(err_path)}"
                )
        # Both stores are open. The first round starts a little ahead, so both children have
        # read the schedule by then. Written whole and renamed, so no child reads half of it.
        staged = go.with_suffix(".tmp")
        staged.write_text(repr(time.time() + 0.5), encoding="utf-8")
        os.replace(staged, go)
        outs = [proc.communicate(timeout=20)[0] for proc in procs]
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
    answers: list[list[str]] = []
    starts: list[list[float]] = []
    for proc, out, err_path in zip(procs, outs, errs, strict=True):
        assert proc.returncode == 0, f"a child exited {proc.returncode}: {_tail(err_path)}"
        [line] = [each for each in out.splitlines() if each.startswith("HELD ")]
        report = json.loads(line.removeprefix("HELD "))
        answers.append([str(each) for each in report["held"]])
        starts.append([float(each) for each in report["starts"]])
    # Liveness: enough rounds started together to be races. Rounds that ran one after the other
    # would pass every check the caller makes with no race at all.
    together = sum(abs(a - b) < _TOGETHER_S for a, b in zip(*starts, strict=True))
    assert together >= _MIN_TOGETHER * rounds, (
        f"only {together} of {rounds} rounds started within {_TOGETHER_S}s of each other"
    )
    return answers


def _readline_within(proc: subprocess.Popen[str], timeout: float) -> tuple[str, bool]:
    """The child's next stdout line, or ``""`` when none comes within ``timeout`` seconds, and
    whether the child was killed for it. A child that dies first closes stdout, so the read ends;
    one that hangs is killed, which ends it too."""
    stdout = proc.stdout
    assert stdout is not None
    line: list[str] = []
    reader = threading.Thread(target=lambda: line.append(stdout.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    killed = reader.is_alive()
    if killed:
        proc.kill()
        reader.join(5.0)
    return (line[0] if line else ""), killed


def _tail(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-4000:]
    except OSError as exc:
        return f"(stderr unreadable: {exc})"


async def assert_one_request_per_round(store: Any, answers: list[list[str]]) -> set[str]:
    """Both processes were answered with the same id in every round, and the store holds that one
    request per round, each with one ``approval.requested`` row and one repeat row. Returns the
    held ids."""
    first, second = answers
    assert len(first) == len(second) > 0
    split = [k for k, (a, b) in enumerate(zip(first, second, strict=True)) if a != b]
    assert not split, f"rounds answered with two different requests: {split}"
    held = set(first)
    assert len(held) == len(first), "two rounds were answered with one request"
    for action in ("approval.requested", "approval.request_repeated"):
        named = Counter(
            json.loads(str(r["detail"])).get("approval_id")
            for r in await store.list_audit(action=action, limit=10_000)
        )
        assert {i: named[i] for i in held} == dict.fromkeys(held, 1), action
    # Every held id is still pending, and nothing else was filed for this run: the open requests
    # carrying its nonce are exactly these.
    one = await store.get_pending_approval(first[0])
    assert one is not None
    assert filed_for(json.loads(str(one["params"]))["race"], await open_requests(store)) == held
    return held


async def open_requests(store: Any) -> list[Any]:
    return list(await store.list_pending_approvals(now=0.0, limit=10_000))


def filed_for(nonce: str, rows: list[Any]) -> set[str]:
    """The ids among ``rows`` that a run with ``nonce`` filed."""
    return {str(r["id"]) for r in rows if nonce in str(r["params"])}
