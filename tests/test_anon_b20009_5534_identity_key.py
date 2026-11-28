# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``id`` kind must not join two identifiers that differ only at a position it blanks
(BACKLOG #5534, #5533 item 9).

#5533 item 9 named "surrogates seed on the whole repetition": a CX id written with and without
a blanked check digit or date gets two unrelated surrogates, a split link. Keying instead on
the id and the components the surrogate keeps was built and withdrawn under BACKLOG #5534. The
``id`` kind also rewrites values that are not a CX: an overlay can send an EI order number to
it, and EI.2, the namespace, sits at a position the CX rule blanks. With EI.3 and EI.4 empty,
re-keyed, ``1001^NS_A`` and ``1001^NS_B`` came out as one surrogate, a join the source never
held. These tests pin only that false join, through the dispatch both adapters use. They do not
pin the split link for a true CX: an EI-aware kind, as ``dln`` is for PID-20, would let a CX
kind drop its blanked components from the key without this harm, and nothing here stops that.

Every value here is synthetic.
"""

from __future__ import annotations

from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry_toolkit.anon import keying as engine_keying
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from tee.anon import keying as tee_keying
from tee.anon import surrogates as tee_surrogates

_SALT = "b20009-5534-salt-0123456789abcdef-0123456789"
_MODULES = pytest.mark.parametrize(
    ("anon", "surrogates", "keying"),
    [
        (engine_anon, engine_surrogates, engine_keying),
        (tee_anon, tee_surrogates, tee_keying),
    ],
    ids=["engine", "tee"],
)

# Pairs of identifiers that differ only at EI.2 or DLN.2, a position the ``id`` kind blanks as
# CX.2. The ids are long enough that two different keys colliding by chance is negligible.
_PAIRS = [
    pytest.param("ORD100200300^NS_A", "ORD100200300^NS_B", id="ei-namespace-only"),
    pytest.param("100200300400^NS_A", "100200300400^NS_B", id="placer-and-filler"),
    pytest.param("D12345678901^ST_A", "D12345678901^ST_B", id="dln-under-id"),
]


def _fabricated(anon: ModuleType, surrogates: ModuleType, keying: ModuleType, rep: str) -> str:
    """The fabricated id, component 1 of what the ``id`` kind writes through ``surrogate_field``."""
    seps = surrogates.Seps()
    out: str = surrogates.surrogate_field(anon.SurrogateKind.ID, rep, keying.Keyer(_SALT), seps)
    return out.split(seps.component, 1)[0]


@_MODULES
@pytest.mark.parametrize(("one", "other"), _PAIRS)
def test_two_identifiers_differing_at_a_blanked_position_stay_apart(
    anon: ModuleType, surrogates: ModuleType, keying: ModuleType, one: str, other: str
) -> None:
    """The surrogate blanks the distinguishing component in both, so the key alone keeps the two
    apart. Dropped from the key, both would read as one identifier."""
    fabricated = [_fabricated(anon, surrogates, keying, rep) for rep in (one, other)]
    assert fabricated[0] != fabricated[1], fabricated


@_MODULES
@pytest.mark.parametrize(("one", "other"), _PAIRS)
def test_each_identifier_keeps_one_surrogate(
    anon: ModuleType, surrogates: ModuleType, keying: ModuleType, one: str, other: str
) -> None:
    """The control: each value's surrogate is deterministic and is not the real id, so the test
    above measures the key and not a random or copied draw."""
    for rep in (one, other):
        first = _fabricated(anon, surrogates, keying, rep)
        assert first == _fabricated(anon, surrogates, keying, rep)
        assert first != rep.split("^", 1)[0]
