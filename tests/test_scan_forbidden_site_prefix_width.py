# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5366: the publish guard counts a ``[site_prefix]`` entry as live only when the anonymizer
loads it too. Both ``surrogates.py`` copies load two-digit prefixes only, so a guard that counted a
wider one called the site-code scrub and its leak check live while they matched nothing. Every
prefix here is made up."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry_toolkit.anon import surrogates as toolkit_surrogates
from tee.anon import surrogates as tee_surrogates

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "security"))

import scan_forbidden as sfm  # noqa: E402

pytestmark = pytest.mark.tooling

_NAMES = "[names]\n\\bZqwidthsynth\\b | synthetic | i\n"


@pytest.fixture
def load(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
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


@pytest.mark.parametrize("module", [toolkit_surrogates, tee_surrogates], ids=["toolkit", "tee"])
def test_a_wide_prefix_alone_does_not_read_as_live(
    load, module: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    load(f"{_NAMES}[site_prefix]\n731\n")
    assert not module.site_prefixes_loaded()
    assert sfm.loaded_token_counts()["site_prefixes"] == 0
    err = capsys.readouterr().err
    assert "NOT COUNTED" in err
    assert "731" not in err, "the warning must not echo the prefix"
    # Detection is not narrowed: the file scan still matches the wide prefix.
    assert sfm._SITE_CODE_FILE.search("PT_7310000_ADT") is not None


def test_a_wide_prefix_alone_leaves_no_token_source(load) -> None:
    """With no other section, a wide prefix no longer makes ``TOKENS_PRESENT`` true, so
    ``MEFOR_REQUIRE_TOKENS`` refuses rather than passing a structural-only run."""
    load("[site_prefix]\n731\n")
    assert not sfm.TOKENS_PRESENT


@pytest.mark.parametrize("module", [toolkit_surrogates, tee_surrogates], ids=["toolkit", "tee"])
def test_the_guard_counts_what_the_anonymizer_loads(load, module: ModuleType) -> None:
    load(f"{_NAMES}[site_prefix]\n73\n731\n")
    assert module._SITE_PREFIXES == ("73",)
    assert sfm.loaded_token_counts()["site_prefixes"] == len(module._SITE_PREFIXES)
    assert sfm.TOKENS_PRESENT


def test_the_control_a_two_digit_prefix_counts(load, capsys: pytest.CaptureFixture[str]) -> None:
    load(f"{_NAMES}[site_prefix]\n73\n")
    assert sfm.loaded_token_counts()["site_prefixes"] == 1
    assert "NOT COUNTED" not in capsys.readouterr().err
    report, failures = sfm.self_test()
    assert failures == [], failures
