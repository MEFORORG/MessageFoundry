# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One engine-shard stand-in for ``tests/test_sqlserver_audit_applock.py`` (BACKLOG #1605).

Run as a SEPARATE OS PROCESS, which is the whole point. ``SqlServerStore._audit_lock`` is an
``asyncio.Lock``, so any rig that stays inside one interpreter is protected by it and passes
against the unpatched code. Two of these processes hold two unrelated locks over one chain, which
is what ``serve --shard`` does.

Argv: ``<tag> <count> <ready-file> <go-file>``. The process opens a store, touches the ready file,
waits for the go file, appends ``count`` audit rows, and exits 0. The two-file barrier exists
because store open is far slower than one append: without it a fast worker can finish its whole
run before its peer connects, and the appends never overlap at all.

Not collected by pytest: the leading underscore keeps it out of the ``test_*.py`` pattern.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

#: The peer is one store-open away, never minutes. Kept under the parent's own barrier budget so a
#: stuck worker surfaces as this process exiting non-zero, which the parent reports with its stderr.
_BARRIER_TIMEOUT_SECONDS = 15.0
_BARRIER_POLL_SECONDS = 0.005


def _wait_for(path: Path) -> None:
    deadline = time.monotonic() + _BARRIER_TIMEOUT_SECONDS
    while not path.exists():
        if time.monotonic() > deadline:
            raise TimeoutError(f"barrier file never appeared: {path}")
        time.sleep(_BARRIER_POLL_SECONDS)


async def _append(tag: str, count: int, ready: Path, go: Path) -> None:
    # Imported inside the coroutine so an import failure still reaches the parent as a non-zero exit
    # with a readable traceback on stderr, rather than as a silent barrier timeout.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    store = await SqlServerStore.open(load_settings(environ=os.environ).store)
    try:
        ready.write_text(str(os.getpid()), encoding="utf-8")
        _wait_for(go)
        for i in range(count):
            await store.record_audit(
                "test.audit_append",  # synthetic marker action, never a real audited operation
                actor=f"shard-{tag}",
                detail=f"{tag}:{i}",
            )
    finally:
        await store.close()


def main(argv: list[str]) -> int:
    tag, count, ready, go = argv[0], int(argv[1]), Path(argv[2]), Path(argv[3])
    asyncio.run(_append(tag, count, ready, go))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
