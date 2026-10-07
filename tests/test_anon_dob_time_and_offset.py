# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A surrogate date of birth keeps a time's shape and none of its value (vault BACKLOG #2767, step 2).

``surrogate_dob`` used to append the real time of birth and the real UTC offset after the
fabricated date. Both are date details below the day, and the offset shows whether daylight saving
time was in effect, which is why ``surrogate_date`` writes ``+0000`` for one. Now the time digits are
zero-filled at their width and any offset is ``+0000``. Both copies, engine and tee, are run. The
values are synthetic, and the salt is a test salt.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from messagefoundry.anon import keying as engine_keying
from messagefoundry.anon import surrogates as engine_surrogates
from tee.anon import keying as tee_keying
from tee.anon import surrogates as tee_surrogates

_SALT = "dob-time-test-salt-Wq83nZr1vLp6Ty"

_Dob = Callable[[str], str]


def _engine(rep: str) -> str:
    return engine_surrogates.surrogate_dob(
        rep, engine_keying.Keyer(_SALT), engine_surrogates.Seps()
    )


def _tee(rep: str) -> str:
    return tee_surrogates.surrogate_dob(rep, tee_keying.Keyer(_SALT), tee_surrogates.Seps())


_EACH_COPY = pytest.mark.parametrize("dob", [_engine, _tee], ids=["engine", "tee"])

#: A date of birth with a time, and what must follow the fabricated eight-digit date.
_SHAPES = {
    "hour": ("1980050512", "00"),
    "minute": ("198005051230", "0000"),
    "second": ("19800505123017", "000000"),
    "fraction": ("19800505123017.1234", "000000.0000"),
    "offset only": ("19800505-0500", "+0000"),
    "minute and offset": ("198005051230+0530", "0000+0000"),
    "second and offset": ("19800505123017-0500", "000000+0000"),
    "every part": ("19800505123017.12-0500", "000000.00+0000"),
}


@_EACH_COPY
@pytest.mark.parametrize("case", sorted(_SHAPES))
def test_a_time_after_the_date_keeps_its_shape_and_none_of_its_value(dob: _Dob, case: str) -> None:
    value, tail = _SHAPES[case]
    out = dob(value)
    assert out[:8].isdigit() and out[8:] == tail, out


@_EACH_COPY
@pytest.mark.parametrize(("value", "width"), [("1980", 4), ("198005", 6), ("19800505", 8)])
def test_control_a_plain_date_keeps_its_width_and_gains_no_tail(
    dob: _Dob, value: str, width: int
) -> None:
    out = dob(value)
    assert len(out) == width and out.isdigit() and out != value


def test_the_engine_and_tee_copies_agree() -> None:
    for value, _ in _SHAPES.values():
        assert _engine(value) == _tee(value)
