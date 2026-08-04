# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shape-pin: neither server-DB runbook may instruct an operator to over-grant the engine login.

ASVS 13.2.2 scores least-privilege backend-component accounts, and ``docs/AOAG-DEPLOYMENT.md``
shipped a "grant the engine login ``db_owner`` on the ``mefor`` database" instruction on the premise
that the real set was an open *filled-by-staging* question. It is not open — it is derivable from the
store: ``db_datareader`` + ``db_datawriter`` + ``db_ddladmin``, with ``EXECUTE`` needed only under
``[store].fifo_claim_proc`` (SQL Server only, default off). There is no engine code path here, so the
guard is a structural assertion over the two Markdown runbooks.

The mutation this must catch: re-adding an over-grant instruction — e.g. "use this known-good interim
posture: grant the engine login **``db_owner`` on the ``mefor`` database only**" — to either runbook
without a prohibition beside it. Verified failing against the pre-fix text of AOAG-DEPLOYMENT.md.

⛔ This file must stay under ``tests/``. ``scripts/asvs/scorecard.py::_python_sources`` scans
``messagefoundry``, ``messagefoundry_webconsole``, ``harness`` and ``scripts`` — moving it into any of
those would flip ASVS cell 13.2.2's absence claim
(``pattern = "IS_SRVROLEMEMBER|IS_ROLEMEMBER|db_owner|sysadmin"``) to FALSE, because this file names
every one of those tokens on purpose.

⚠️ The ±2-line prohibition window has ONE line of margin, by measurement rather than by design:
``AOAG-DEPLOYMENT.md``'s "the engine login never needs ``ALTER DATABASE`` rights" sits exactly three
lines from the defect it must not be allowed to excuse. Do not widen the window.
"""

from __future__ import annotations

from pathlib import Path

from messagefoundry.config.settings import StoreSettings

_ROOT = Path(__file__).resolve().parent.parent
_RUNBOOKS = (_ROOT / "docs" / "AOAG-DEPLOYMENT.md", _ROOT / "docs" / "DEPLOY-SERVER-DB.md")
# Grants nobody may prescribe for the engine's own database principal.
_OVER_GRANTS = ("db_owner", "sysadmin")
# The derived least-privilege set both runbooks must keep agreeing on (see the module docstring).
_LEAST_PRIVILEGE = ("db_datareader", "db_datawriter", "db_ddladmin")


def test_runbooks_never_prescribe_an_over_grant() -> None:
    """Every over-grant mention must sit in a prohibiting context, never as an instruction.

    Deliberately NOT a marker like "no server-level role" — the defective text contained that exact
    phrase, so accepting it would have made the gate green on the very defect it exists to catch.
    """
    prohibitions = ("never", "not sysadmin/db_owner", "not `db_owner`")
    for path in _RUNBOOKS:
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if not any(grant in line.lower() for grant in _OVER_GRANTS):
                continue
            window = " ".join(lines[max(0, i - 2) : i + 3]).lower()
            assert any(marker in window for marker in prohibitions), (
                f"{path.name}:{i + 1} names an over-grant with no prohibition beside it: {line!r}"
            )


def test_both_runbooks_name_the_same_least_privilege_set() -> None:
    """The two files contradicted each other once; each must name all three fixed database roles."""
    for path in _RUNBOOKS:
        text = path.read_text(encoding="utf-8")
        missing = [role for role in _LEAST_PRIVILEGE if role not in text]
        assert not missing, f"{path.name} omits {missing} from the engine-login grant set"


def test_execute_grant_is_documented_as_conditional_not_baseline() -> None:
    """``EXECUTE`` rides a flag, so the runbooks must name the flag, not list it as a flat grant."""
    # Derived, not pinned: if the default ever flips, the conditional prose is wrong and must be re-read.
    assert StoreSettings().fifo_claim_proc is False, (
        "[store].fifo_claim_proc default moved — re-read the EXECUTE prose in both runbooks"
    )
    joined = "\n".join(path.read_text(encoding="utf-8") for path in _RUNBOOKS)
    assert "fifo_claim_proc" in joined, (
        "the EXECUTE grant must be tied to [store].fifo_claim_proc, never listed as baseline"
    )
