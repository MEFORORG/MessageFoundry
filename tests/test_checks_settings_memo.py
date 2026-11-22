# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One ``run_checks`` resolves and loads the service settings once, not once per settings leg
(vault BACKLOG #2950 added items 6 and 13), and a refusal reaches every leg the same way.

The counts are read by wrapping the two uncached functions, so what is pinned is how often the
gate reads the settings, not what any one leg does with them."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.checks as checks
from messagefoundry.checks import run_checks

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


@pytest.fixture(autouse=True)
def _hermetic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test runs in an empty working directory with no ``MEFOR_*`` variables, so neither a
    ``./messagefoundry.toml`` where pytest was started nor a variable the shell exports reaches
    what the legs grade."""
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    for name in list(os.environ):
        if name.upper().startswith("MEFOR_"):
            monkeypatch.delenv(name)


def _count_reads(monkeypatch: pytest.MonkeyPatch) -> Counter[str]:
    calls: Counter[str] = Counter()
    real_load = checks._load_check_settings_uncached
    real_source = checks._settings_source_uncached

    def load(*args: Any, **kwargs: Any) -> Any:
        calls["load"] += 1
        return real_load(*args, **kwargs)

    def source(*args: Any, **kwargs: Any) -> Any:
        calls["source"] += 1
        return real_source(*args, **kwargs)

    monkeypatch.setattr(checks, "_load_check_settings_uncached", load)
    monkeypatch.setattr(checks, "_settings_source_uncached", source)
    return calls


def test_a_run_reads_refused_settings_once_and_every_leg_fails_alike(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the settings are resolved more than once in a run, loaded more than once per
    distinct argument set, or a refusal stops reaching a leg after the first. ``build-check`` loads
    with its own CLI override, so a run may load twice, never once per leg. Control: the run has
    more refused settings legs than loads, so a per-leg load could not pass."""
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text("[auth\nnot toml", encoding="utf-8")
    calls = _count_reads(monkeypatch)
    report = run_checks(SAMPLES_CONFIG, run_lint=False, service_config=toml)
    refused = [r for r in report.results if "settings did not load" in r.detail]
    assert calls["source"] == 1
    assert 1 <= calls["load"] <= 2
    assert len(refused) > calls["load"], [r.name for r in refused]
    assert all(not r.ok for r in refused)
    assert len({r.detail for r in refused}) == 1, {r.name: r.detail for r in refused}
    # The memo is the run's alone: the next run reads the file again.
    run_checks(SAMPLES_CONFIG, run_lint=False, service_config=toml)
    assert calls["source"] == 2


def test_a_run_loads_good_settings_once_and_hands_each_leg_its_own_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: an environment-declared instance's settings load more than once in a run, or two
    legs get the same model object, so one leg's change to it would reach the next. Control: legs
    graded those settings, so the single load was used."""
    calls = _count_reads(monkeypatch)
    handed: list[object] = []
    real = checks._load_check_settings

    def spy(*args: Any, **kwargs: Any) -> Any:
        settings = real(*args, **kwargs)
        handed.append(settings)
        return settings

    monkeypatch.setattr(checks, "_load_check_settings", spy)
    report = run_checks(
        SAMPLES_CONFIG, run_lint=False, env="dev", suppress_service_toml_search=True
    )
    graded = [r for r in report.results if "settings from environment only" in r.detail]
    assert graded, [r.name for r in report.results]
    assert calls["load"] == 1
    assert len(handed) > 1
    assert len({id(s) for s in handed}) == len(handed)


def test_a_leg_called_outside_a_run_reads_afresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the memo outlives ``run_checks``, so a leg called on its own, as the tests and
    ``verify`` call them, gets an earlier run's answer."""
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text("[auth\nnot toml", encoding="utf-8")
    run_checks(SAMPLES_CONFIG, run_lint=False, service_config=toml)
    assert checks._RUN_MEMO.get() is None
    calls = _count_reads(monkeypatch)
    for _ in range(2):
        checks._settings_source(
            SAMPLES_CONFIG, service_config=toml, suppress_search=False, env=None
        )
        with pytest.raises(checks._SETTINGS_LOAD_ERRORS):
            checks._load_check_settings(toml)
    assert calls["source"] == 2
    assert calls["load"] == 2


def test_a_change_to_the_environment_or_working_directory_during_a_run_reads_afresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the memo key leaves out the environment or the working directory, so a change to
    either during a run gets the answer to the question asked before it. Control: the same call
    with neither changed is answered from the memo."""
    calls = _count_reads(monkeypatch)
    token = checks._RUN_MEMO.set({})
    try:

        def source() -> tuple[Path | None, bool]:
            return checks._settings_source(
                SAMPLES_CONFIG, service_config=None, suppress_search=False, env=None
            )

        assert source() == (None, False)
        assert source() == (None, False)
        assert calls["source"] == 1
        # The environment now declares an instance, which the bare dir's SKIP must not hide.
        monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
        assert source() == (None, True)
        assert calls["source"] == 2
        # A messagefoundry.toml in the new working directory is what the search now finds.
        other = tmp_path / "other"
        other.mkdir()
        (other / "messagefoundry.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(other)
        found, _ = source()
        assert found is not None and found.resolve() == (other / "messagefoundry.toml").resolve()
        assert calls["source"] == 3
    finally:
        checks._RUN_MEMO.reset(token)
