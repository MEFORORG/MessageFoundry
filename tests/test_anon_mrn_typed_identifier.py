# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``_has_mrn_typed_identifier`` does what its docstring says, in both copies (vault BACKLOG
#5533 item 20 and the filing review's finding 1).

Each value the docstring names as counting, or as not counting, is checked here directly on the
detector, under the default delimiters, so the docstring cannot drift from the code unseen. A
bare ``MR`` or ``MRN`` with nothing after it counts too: the docstring says component 1 counts as
an id type, and such a value has a non-empty component 1. Whether it should is item 20's open
question; this pins what the code does today, so a change to it is a visible decision.

Every value here is synthetic.
"""

from __future__ import annotations

from types import ModuleType

import pytest

from messagefoundry_toolkit.anon import leak as engine_leak
from messagefoundry_toolkit.anon.surrogates import Seps
from tee.anon import leak as tee_leak
from tee.anon.surrogates import Seps as TeeSeps

_LEAKS = pytest.mark.parametrize("leak", [engine_leak, tee_leak], ids=["engine", "tee"])


def _seps(leak: ModuleType) -> Seps | TeeSeps:
    return Seps() if leak is engine_leak else TeeSeps()


@_LEAKS
@pytest.mark.parametrize(
    "value",
    [
        "12345^MR",
        "MRN^12345",
        "12345^MR&L",
        "1234^DOE^JOHN^^^MR",
        "ID^^^AUTH^MR&local",
        "ACME^L^^^^AUTH^X&MR",
        "1234^DOE^JOHN^^^^^^AUTH^^^^X&MR",
        "\\Z98765\\^^^H^MR",  # an id that decodes to nothing still counts
        "OTHER~12345^MR",  # any repetition
        "MR",  # component 1 is read as an id type too
        "MRN",
    ],
)
def test_each_value_the_docstring_counts_is_counted(leak: ModuleType, value: str) -> None:
    assert leak._has_mrn_typed_identifier(value, _seps(leak), "|")


@_LEAKS
@pytest.mark.parametrize(
    "value",
    [
        "70553^PET&MR",  # an MR subcomponent past the first, in a component that is not 5, 7 or 13
        "70553^PET\\T\\MR",  # a decoded part is never split again
        "70553^X\\S\\MR",
        "^^^H^MR",  # no component 1
        "12345^MRI",
    ],
)
def test_each_value_the_docstring_does_not_count_is_not_counted(
    leak: ModuleType, value: str
) -> None:
    assert not leak._has_mrn_typed_identifier(value, _seps(leak), "|")
