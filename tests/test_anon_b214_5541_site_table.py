# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A publish-guard reload does not reach the site-code check's own table (vault BACKLOG #5541,
#5533 items 32, 41 and 48).

Both leak-check module docstrings say the site-code check reads the table ``surrogates.py``
loads, apart from the guard, and that a report calls the denylist live only when that table holds
the guard's two-digit ``[site_prefix]`` entries. ``tests/test_anon_wave2_residuals.py`` pins the
second half, the report's liveness. This pins the first, in both copies: after a reload of the
guards alone, the site-code check and the scrub still use the prefixes of the last
``reload_site_prefixes``, and they use the new ones only after it runs.

The prefix and the code are made up.
"""

from __future__ import annotations

from types import ModuleType

import pytest

from messagefoundry_toolkit.anon import leak as engine_leak
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from messagefoundry_toolkit.anon.keying import Keyer
from tee.anon import leak as tee_leak
from tee.anon import surrogates as tee_surrogates
from tests.test_anon_core import _NO_SCANNER
from tests.test_anon_wave2_residuals import _HEAD, _token_source

_SALT = "b214-5541-site-salt-0123456789abcdef"
#: A whole component that is a site code under the made-up prefix ``97`` alone.
_CODED = f"{_HEAD}\rZPD|1|971234"
_PAIRS = pytest.mark.parametrize(
    ("leak", "surrogates"),
    [(engine_leak, engine_surrogates), (tee_leak, tee_surrogates)],
    ids=["engine", "tee"],
)


@_NO_SCANNER
@_PAIRS
def test_a_guard_reload_alone_leaves_the_site_code_table_as_it_was(
    leak: ModuleType, surrogates: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = surrogates._SITE_PREFIXES
    if "97" in before:
        pytest.skip("the real token source already loads this made-up prefix")
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=False):
        # The guard counts the new prefix; the site-code check never loaded it.
        assert before == surrogates._SITE_PREFIXES
        assert not surrogates.message_has_site_code(_CODED)
        assert surrogates.scrub_site_codes("971234", Keyer(_SALT), surrogates.Seps()) == "971234"
        # So the report does not call the denylist live.
        report = leak.leak_report(f"{_HEAD}\rPV2|1")
        assert not leak.denylist_is_live(report)


@_NO_SCANNER
@_PAIRS
def test_the_site_code_table_follows_only_its_own_reload(
    leak: ModuleType, surrogates: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with ``reload_site_prefixes`` too, the check matches the code and scrubs it."""
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=True):
        assert "97" in surrogates._SITE_PREFIXES
        assert surrogates.message_has_site_code(_CODED)
        assert surrogates.scrub_site_codes("971234", Keyer(_SALT), surrogates.Seps()) != "971234"
