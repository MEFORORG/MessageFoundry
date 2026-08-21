# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A pid whose DEADNESS HOLDS -- BACKLOG #1303.

THE DEFECT THIS REPLACES. Three test files each carried their own copy of::

    proc = subprocess.Popen(["cmd", "/c", "exit"], ...)
    proc.wait(timeout=30)
    time.sleep(0.3)   # let the OS reap it before we claim the pid is gone
    return proc.pid

It spawns a process, waits for it to EXIT, and returns its pid as "free". The pid is free at the
moment it returns and **nothing keeps it free**: between that return and the moment the tool under
test reads the record, the OS may hand the pid to a new process.

**THE COMMENT STATES THE INTENT AND THE MECHANISM DOES THE OPPOSITE.** Reaping does not RESERVE a pid,
it RELEASES it for reuse -- so the sleep widens the window it appears to guard. The hazard was
reasoned about and the direction was inverted, which is why this is a defect rather than an oversight.

HOW IT SURFACED. `Test-RecordLiveness` (`scripts/coord/session-registry.ps1:181`) reads
`Get-Process -Id <pid>`: not running is **DEAD**, which vetoes nothing. But a REUSED pid IS running,
and a test record carries no ``startedAt`` for the reuse fence to check, so the verdict becomes
**UNVERIFIED** -- and UNVERIFIED *does* veto. The occupant list then comes back non-empty and an
assertion that a dead record is "not a veto" fails. Observed on `windows-2025`, run `32268545492`::

    assert d["Occupants"] == []
    AssertionError: assert [{'Short': 'e...-clean', ...}] == []

`cmd /c exit` is Windows-only, which matches where it was seen. Pid reuse needs pid churn, and that
tier spawns pwsh/git children constantly, on a runner whose pid space recycles far faster than a
developer box -- which is why it reproduces there and not locally.

WHY THIS VALUE. ``2147483647`` is ``Int32.MaxValue``. It is:

* **within ``[int]``**, which `Test-RecordLiveness` casts to (``$procId = [int]$Record.pid``);
* **non-zero**, so it takes the liveness path rather than the ``UNREADABLE`` shortcut that a falsy
  pid triggers -- a record with no pid is deliberately NOT dead there;
* **structurally unassignable**: Linux caps pids at ``/proc/sys/kernel/pid_max`` (default 4194304,
  ceiling ~2^22) and Windows pids are multiples of 4 far below 2^31.

So it is dead **by construction rather than by timing**, and it stays dead however loaded the host is.

WHAT THIS DELIBERATELY DOES *NOT* DO, and it is the point. It does not stub, mock or force the
liveness verdict. The real `Get-Process` call still runs and still returns "not running" on its own.
A remedy that short-circuited the verdict would make every caller pass while testing NOTHING -- and
the assertions this feeds exist to prove that a dead record is *neither* a veto *nor* a permission
(``Occupants == []`` AND ``Decision == "SKIP"``). Converting a loud false-failure into a quiet
always-pass would be worse than the flake it replaces.
"""

from __future__ import annotations

from typing import Final

#: See the module docstring for why this specific value, and why it is not merely "a big number".
NEVER_LIVE_PID: Final = 2147483647


def never_live_pid() -> int:
    """A pid no process can hold, so a record written with it reads DEAD at any later moment.

    Callable rather than a bare constant so call sites read as an intent ("give me a pid that cannot
    be alive") rather than as a magic literal, and so a future platform that needs a different value
    has one place to change.
    """
    return NEVER_LIVE_PID
