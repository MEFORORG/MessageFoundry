# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every registered message type generates a conformant message for each of its triggers."""

from __future__ import annotations

import pytest

from messagefoundry.parsing import Peek
from messagefoundry.generators import _core
from messagefoundry.generators import all_types  # noqa: F401  (registers every built-in type)

_CASES = [(code, trigger) for code in _core.message_codes() for trigger in _core.triggers_for(code)]


def test_expected_types_are_registered() -> None:
    expected = {
        "ADT",
        "ORM",
        "ORU",
        "DFT",
        "SIU",
        "OML",
        "ORL",
        "MDM",
        "VXU",
        "BAR",
        "RDE",
        "RAS",
        "MFN",
    }
    assert expected <= set(_core.message_codes())


@pytest.mark.parametrize("code,trigger", _CASES)
def test_generated_message_is_conformant(code: str, trigger: str) -> None:
    msg = _core.generate_message(code, trigger, 1)
    peek = Peek.parse(msg)
    assert peek.message_code == code
    assert peek.trigger_event == trigger
    ok, errors = _core.gate(code, msg, _core.structure_for(code, trigger))
    assert ok, f"{code}^{trigger}: {errors}"
