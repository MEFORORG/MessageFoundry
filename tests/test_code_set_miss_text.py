# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5320: a code-set or reference-set lookup miss never puts the looked-up key into the
error text, nor on an attribute of the error.

The key is usually a message field, so it may carry PHI. A raised error's text goes at least to the
store's error columns and message events, ciphered at rest only when a store key is set, and to the
log and the alert sinks, which are outside the secured store (CLAUDE.md section 9). Both code-set
misses keep the code set's name on ``.code_set``. Synthetic data only.
"""

from __future__ import annotations

import copy
import traceback
from collections.abc import Callable

import pytest

from messagefoundry.config.code_sets import CodeSet, CodeSetKeyError, CodeSetMissError
from messagefoundry.config.reference import ReferenceSet
from messagefoundry.redaction import safe_exc

MRN = "SYN900003"


def _texts(exc: BaseException) -> list[str]:
    """Every rendering a stored error or a log line could take of ``exc``, and its attributes."""
    return [
        str(exc),
        repr(exc),
        safe_exc(exc),
        "".join(traceback.format_exception(exc)),
        repr(vars(exc)),
    ]


def test_translate_miss_names_the_set_and_never_the_key() -> None:
    cs = CodeSet("epic_diets", {"A": "Apple"})
    with pytest.raises(CodeSetMissError) as caught:
        cs.translate(MRN)
    exc = caught.value
    assert exc.code_set == "epic_diets" and not hasattr(exc, "key")
    assert "epic_diets" in str(exc) and f"a key of {len(MRN)} characters" in str(exc)
    assert "no unmapped_policy is declared" in str(exc)
    for text in _texts(exc):
        assert MRN not in text


def test_item_lookup_miss_names_the_set_and_never_the_key() -> None:
    cs = CodeSet("epic_diets", {"A": "Apple"})
    with pytest.raises(KeyError) as caught:
        _ = cs[MRN]
    exc = caught.value
    assert isinstance(exc, CodeSetKeyError)
    assert exc.code_set == "epic_diets" and not hasattr(exc, "key")
    assert "epic_diets" in str(exc)
    for text in _texts(exc):
        assert MRN not in text
    # The dict's own KeyError, whose text is the key, is on neither link of the chain.
    assert exc.__cause__ is None and exc.__context__ is None
    # get() still returns the default on a miss.
    assert cs.get(MRN, "d") == "d"


def test_a_non_string_key_is_described_by_its_type() -> None:
    cs = CodeSet("epic_diets", {"A": "Apple"})
    with pytest.raises(CodeSetMissError, match="a key of type NoneType is not in code set"):
        cs.translate(None)  # type: ignore[arg-type]
    with pytest.raises(KeyError, match="a key of type int is not in code set 'epic_diets'"):
        _ = cs[900003]  # type: ignore[index]


@pytest.mark.parametrize(
    ("lookup", "error"),
    [(CodeSet.translate, CodeSetMissError), (CodeSet.__getitem__, CodeSetKeyError)],
    ids=["translate", "item"],
)
def test_a_copied_miss_keeps_its_attributes(
    lookup: Callable[[CodeSet, str], object], error: type[CodeSetMissError | CodeSetKeyError]
) -> None:
    # A copy rebuilds the error from its message alone, then restores the attributes.
    with pytest.raises(error) as caught:
        lookup(CodeSet("epic_diets", {}), MRN)
    dup = copy.copy(caught.value)
    assert type(dup) is error and str(dup) == str(caught.value)
    assert dup.code_set == "epic_diets" and not hasattr(dup, "key")


def test_a_one_character_key_reads_in_the_singular() -> None:
    with pytest.raises(CodeSetKeyError, match="a key of 1 character is not in code set 'sex'"):
        _ = CodeSet("sex", {"F": "Female"})["X"]


def test_reference_set_miss_names_the_set_and_never_the_key() -> None:
    rs = ReferenceSet("provider_npi", {"1234567893": "Synthetic Clinic"})
    with pytest.raises(KeyError) as caught:
        _ = rs[MRN]
    exc = caught.value
    assert exc.args == (f"a key of {len(MRN)} characters is not in reference set 'provider_npi'",)
    for text in _texts(exc):
        assert MRN not in text
    # The dict's own KeyError, whose text is the key, is on neither link of the chain.
    assert exc.__cause__ is None and exc.__context__ is None
    assert rs.get(MRN, "d") == "d"
