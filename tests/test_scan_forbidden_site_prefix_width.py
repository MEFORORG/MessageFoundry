# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5366: the publish guard and the anonymizer agree on which ``[site_prefix]`` entries are
live. Both ``surrogates.py`` copies load two-digit prefixes only. The guard still matches a wider
entry, so it loses no detector, but names it and refuses the source on a required-token run, where
it used to count it live while the site-code scrub and its leak check matched nothing for it. Every
prefix here is made up."""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry_toolkit.anon import surrogates as toolkit_surrogates
from tee.anon import surrogates as tee_surrogates

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "security"))

import scan_forbidden as sfm  # noqa: E402

pytestmark = pytest.mark.tooling

_SECTIONS = "[names]\n\\bZqwidthsynth\\b | synthetic | i\n[estate]\nzqwidthestate\n"
_BOTH = pytest.mark.parametrize(
    "module", [toolkit_surrogates, tee_surrogates], ids=["toolkit", "tee"]
)


@pytest.fixture
def load(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[str], None]]:
    def _loader(source: str) -> None:
        monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", source)
        sfm.reload_tokens()
        for module in (toolkit_surrogates, tee_surrogates):
            module.reload_site_prefixes()

    yield _loader
    monkeypatch.undo()
    sfm.reload_tokens()
    for module in (toolkit_surrogates, tee_surrogates):
        module.reload_site_prefixes()


@_BOTH
def test_the_guard_width_is_the_anonymizer_width(
    load: Callable[[str], None], module: ModuleType
) -> None:
    """The guard's one width constant agrees with what each anonymizer copy actually loads."""
    load(f"{_SECTIONS}[site_prefix]\n7\n73\n731\n7310\n")
    assert module._SITE_PREFIXES == ("73",)
    assert {len(p) for p in module._SITE_PREFIXES} == {sfm._SITE_PREFIX_WIDTH}


def test_a_wide_prefix_refuses_a_required_token_run(
    load: Callable[[str], None], capsys: pytest.CaptureFixture[str]
) -> None:
    load(f"{_SECTIONS}[site_prefix]\n73\n731\n")
    err = capsys.readouterr().err
    assert "not exactly 2 ASCII digits" in err
    why = sfm.token_floor_failure()
    assert why is not None and "1 [site_prefix] entry is not exactly 2" in why
    assert "731" not in err and "731" not in why, "a site prefix must never be echoed"


def test_an_empty_section_is_named_before_a_wide_prefix(load: Callable[[str], None]) -> None:
    """The width reason means a source that loaded, so a mangled one is named as mangled."""
    load("[names]\n\\bZqwidthsynth\\b | synthetic | i\n[estate]\n[site_prefix]\n73\n731\n")
    why = sfm.token_floor_failure()
    assert why is not None and "EMPTY" in why
    assert toolkit_surrogates.SITE_PREFIX_WIDTH_MARK not in why


def test_a_wide_prefix_still_arms_the_file_scan(load: Callable[[str], None]) -> None:
    """The refusal is the fix; narrowing detection is not."""
    load(f"{_SECTIONS}[site_prefix]\n73\n731\n")
    assert sfm._SITE_CODE_FILE.search("PT_7310000_ADT") is not None
    report, failures = sfm.self_test()
    assert failures == [], failures


def test_the_control_two_digit_prefixes_pass_the_floor(
    load: Callable[[str], None], capsys: pytest.CaptureFixture[str]
) -> None:
    load(f"{_SECTIONS}[site_prefix]\n73\n74\n")
    assert sfm.token_floor_failure() is None
    assert "ASCII digits" not in capsys.readouterr().err
