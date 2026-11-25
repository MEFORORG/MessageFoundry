# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What ``provision-admin`` tells the operator once its post-grant revoke was given up on (vault
BACKLOG #3023 items 16, 31 and 39).

The recovery step names ``admin-revoke-sessions``, so it says what that command does in the
command's own words, which end the sessions it finds rather than every session. The give-up
names the re-run budget rather than a duration: an attempt is unbounded, and a re-run can start
one pause past the budget, so "for up to 5 minutes" was not a bound the code keeps.
"""

from __future__ import annotations

import argparse

from messagefoundry.__main__ import _build_parser
from messagefoundry.auth import service as service_module


def _subcommand_help(name: str) -> str:
    parser, _dispatch = _build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for choice in action._choices_actions:
                if choice.dest == name:
                    return str(choice.help)
    raise AssertionError(f"no subcommand named {name!r}")


def test_the_recovery_step_says_what_admin_revoke_sessions_says_it_does() -> None:
    """RED when: the recovery text claims more than the command's own help, such as ending every
    account's sessions."""
    scope = "the sessions it finds, of any account"
    assert scope in _subcommand_help("admin-revoke-sessions")
    text = service_module._PROVISION_REVOKE_RECOVERY
    assert scope in text
    assert "every account" not in text


def test_the_give_up_names_the_budget_not_a_duration() -> None:
    """RED when: the give-up text states the budget as an upper bound on how long the revoke ran."""
    budget = service_module._PROVISION_REVOKE_RETRY.budget_seconds
    text = service_module._PROVISION_REVOKE_GAVE_UP
    assert f"{budget / 60:g}-minute budget" in text
    assert "up to" not in text
