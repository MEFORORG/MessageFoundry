# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The operator documents describe no first-run account (ADR 0183 Amendment A, Wave 4, BACKLOG #1136).

The engine creates no account on its own since Wave 2, and Wave 3 removed the two settings and the
alert that timed that account. Wave 4 rewrote the operator documents to match. This guard keeps them
that way in three directions:

- no operator document names the retired lifecycle: the account, its WP-3 retirement, its two
  timer settings, its alert event or its audit event;
- ``docs/SECURITY.md`` states the replacement: the engine creates no account on its own, and the
  first Administrator comes from ``messagefoundry provision-admin``;
- each install walkthrough puts ``provision-admin`` in its steps. Three of the four never named the
  first-run account at all; their defect was leaving the command out, which the first check cannot
  see.

**The needles are phrases, not the bare word.** ``bootstrap`` is still one of the twelve
context words a password may not contain, and ``SECURITY.md`` lists that set in full; ADR 0164's
file name also carries it. ``bootstrap-admin.txt`` is allowed on purpose: the scaffold still
ignores that file, and the documents may say so and tell a developer to delete an old copy.

**A planted control proves the scanner fires.** A needle list that matches nothing anywhere looks
exactly like a clean tree, so each needle is also checked against a string known to hold it.
Severity is conditional (CLAUDE.md section 0): there are no deployments, so a stale sentence here
would mislead a deploying site, not a live one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

#: The operator documents Wave 4 rewrote, plus CONFIGURATION.md, which Wave 3 rewrote.
_OPERATOR_DOCS = (
    "README.md",
    "docs/SECURITY.md",
    "docs/EARLY-ADOPTER-GUIDE.md",
    "docs/INSTALL-GUIDE.md",
    "docs/SERVICE.md",
    "docs/DEPLOYMENT.md",
    "docs/ANTIVIRUS-FIREWALL.md",
    "docs/PHI.md",
    "docs/VERSION-CONTROL.md",
    "docs/CONFIGURATION.md",
)

#: Phrases that describe the retired first-run account as a thing that exists. Matched
#: case-insensitively. Each names the account, its lifecycle, or a setting or event that timed it.
_RETIRED = (
    "bootstrap admin",
    "bootstrap account",
    "bootstrap administrator",
    "first-run bootstrap",
    "bootstrap-admin handoff",
    "bootstrap-admin timer",
    "bootstrap-admin claim",
    "auto-retirement",
    "bootstrap_expiry_hours",
    "bootstrap_warn_hours",
    "bootstrap_admin_expiring",
    "bootstrap_admin_retired",
    "bootstrap_admin_created",
)

#: One planted line per needle, in the shape the old documents used, so every needle is proved live.
_CONTROL = (
    "The first-run bootstrap admin, the bootstrap account or bootstrap administrator, auto-retirement "
    "and the bootstrap-admin handoff, the bootstrap-admin timer, the bootstrap-admin claim state, "
    "`[auth].bootstrap_expiry_hours`, `bootstrap_warn_hours`, `bootstrap_admin_expiring`, "
    "`auth.bootstrap_admin_retired` and `auth.bootstrap_admin_created`."
)


def _hits(text: str) -> list[str]:
    lowered = text.lower()
    return [needle for needle in _RETIRED if needle in lowered]


def test_the_commands_the_docs_name_are_registered() -> None:
    """The documents send an operator to two host commands; both must exist under those names.

    Read from the CLI's own dispatch table, so a rename there fails here rather than leaving every
    install walkthrough pointing at a command argparse rejects.
    """
    from messagefoundry.__main__ import _DISPATCH

    for command in ("provision-admin", "admin-set-notify-email"):
        assert command in _DISPATCH, f"the docs name `{command}`, which the CLI no longer registers"


def test_every_needle_fires_on_the_planted_control() -> None:
    assert _hits(_CONTROL) == list(_RETIRED), "a needle no longer matches its planted control"


@pytest.mark.parametrize("doc", _OPERATOR_DOCS)
def test_operator_doc_describes_no_first_run_account(doc: str) -> None:
    path = _ROOT / doc
    lines = path.read_text(encoding="utf-8").splitlines()
    found = [
        f"{doc}:{number}: {needle!r}"
        for number, line in enumerate(lines, start=1)
        for needle in _hits(line)
    ]
    assert not found, (
        "these lines describe the first-run account ADR 0183 Amendment A retired; the engine now "
        "creates no account, and the first Administrator comes from `provision-admin`:\n"
        + "\n".join(found)
    )


#: The install walkthroughs. Each must put `provision-admin` in its steps, because a reader who
#: follows one of them to the letter otherwise reaches a sign-in page nobody can pass.
_INSTALL_WALKTHROUGHS = (
    "README.md",
    "docs/INSTALL-GUIDE.md",
    "docs/SERVICE.md",
    "docs/EARLY-ADOPTER-GUIDE.md",
)


@pytest.mark.parametrize("doc", _INSTALL_WALKTHROUGHS)
def test_install_walkthrough_provisions_the_first_administrator(doc: str) -> None:
    text = (_ROOT / doc).read_text(encoding="utf-8")
    assert "provision-admin --username <name> --email <address>" in text, (
        f"{doc} walks an install through without `provision-admin`; the engine creates no account "
        "on its own, so the reader could not sign in"
    )


def test_security_doc_states_how_the_first_administrator_is_made() -> None:
    text = (_ROOT / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    heading = "### Provisioning the first administrator (ASVS 6.3.2)"
    start = text.find(heading)
    assert start != -1, f"{heading!r} is missing from docs/SECURITY.md"
    end = text.find("\n### ", start + len(heading))
    section = text[start:] if end == -1 else text[start:end]
    for phrase in (
        "The engine creates no account on its own.",
        "messagefoundry provision-admin --username <name> --email <address>",
        "There is no default account: `--username` is required",
        "No start writes a password file.",
        "admin-set-notify-email",
    ):
        assert phrase in section, f"the provisioning section no longer says {phrase!r}"
