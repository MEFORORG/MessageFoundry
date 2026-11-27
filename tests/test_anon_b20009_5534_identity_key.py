# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An identifier surrogate stays keyed on the whole repetition (BACKLOG #5534, #5533 item 9).

#5533 item 9 named "surrogates seed on the whole repetition": an id written with and without a
blanked check digit or date gets two unrelated surrogates. Keying instead on the id and the
components the surrogate keeps was built and withdrawn under BACKLOG #5534, because the ``id``
kind also rewrites values that are not a CX. An overlay can send an EI order number to ``id``,
where EI.2, the namespace, is part of the identity but sits at a position the CX rule blanks.
Re-keyed, ``ORD1^EPIC`` and ``ORD1^CERNER`` came out as one surrogate: two real identifiers
joined in the de-identified data. A split link loses a join; a false one invents a join the
source never held. These tests pin the whole-repetition key, so that change cannot return
without meeting them. Each compares the fabricated id alone, because the kept components
differ in the output whatever the key is.

Every value here is synthetic.
"""

from __future__ import annotations

from types import ModuleType

import pytest

from messagefoundry_toolkit.anon import keying as engine_keying
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from tee.anon import keying as tee_keying
from tee.anon import surrogates as tee_surrogates

_SALT = "b20009-5534-salt-0123456789abcdef-0123456789"
_MODULES = pytest.mark.parametrize(
    ("surrogates", "keying"),
    [(engine_surrogates, engine_keying), (tee_surrogates, tee_keying)],
    ids=["engine", "tee"],
)


def _fabricated(surrogates: ModuleType, keying: ModuleType, name: str, rep: str) -> str:
    """The fabricated id, component 1 of the surrogate, apart from the components it keeps."""
    seps = surrogates.Seps()
    out: str = getattr(surrogates, name)(rep, keying.Keyer(_SALT), seps)
    return out.split(seps.component, 1)[0]


# (surrogate, one real identifier, another that differs only at a position the surrogate blanks)
_DIFFERENT_IDENTIFIERS = [
    pytest.param("surrogate_id", "ORD1^EPIC^1.2.3^ISO", "ORD1^CERNER^1.2.3^ISO", id="ei-namespace"),
    pytest.param("surrogate_id", "1001^EPIC", "1001^LAB", id="placer-and-filler"),
    pytest.param("surrogate_id", "D1234567^CA", "D1234567^NV", id="dln-under-id"),
    pytest.param("surrogate_mrn", "A0049^^^HOSP^MR^^^^^^X1", "A0049^^^HOSP^MR^^^^^^X2", id="cx-11"),
    pytest.param("surrogate_ssn", "123456789^1", "123456789^2", id="ssn-cx-2"),
]


@_MODULES
@pytest.mark.parametrize(("name", "one", "other"), _DIFFERENT_IDENTIFIERS)
def test_a_blanked_position_still_keys_the_surrogate(
    surrogates: ModuleType, keying: ModuleType, name: str, one: str, other: str
) -> None:
    """The surrogate blanks the second value's distinguishing component, so only the key keeps
    the two apart. With it dropped from the key, both would read as one identifier."""
    fabricated = [_fabricated(surrogates, keying, name, rep) for rep in (one, other)]
    assert fabricated[0] != fabricated[1], fabricated


@_MODULES
def test_the_same_repetition_keeps_one_surrogate(
    surrogates: ModuleType, keying: ModuleType
) -> None:
    """The control: what the key covers is deterministic, so the test above measures the key."""
    rep = "ORD1^EPIC^1.2.3^ISO"
    assert _fabricated(surrogates, keying, "surrogate_id", rep) == _fabricated(
        surrogates, keying, "surrogate_id", rep
    )
