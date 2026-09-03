# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1438 (ASVS 6.2.4): the BUNDLED breach corpus must fail closed, not screen nothing.

Its own module rather than a section of `test_auth_core.py`, for two reasons. The subject is one
mechanism with one fixture, and `test_auth_core.py` is contested by concurrent work restructuring the
per-number corpus gates that live there. `test_auth_core.py` keeps the BUILD-time bar (BACKLOG #1134:
at least 3000 corpus entries clear the shipped policy); this file holds the RUNTIME guard that the
same number implies. Read them together.

The shape being defended is the one this project keeps rediscovering: **an empty result and a good
result rendering identically.** `violations` returned `[]` whether the corpus screened the password or
had silently failed to load, and `[]` is the success value, so nothing anywhere could report the
difference. Every arm below therefore has a stated failure reading -- see the table in the #1438 row.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest

from messagefoundry.auth import PasswordPolicy
from messagefoundry.auth import policy as policy_module
from messagefoundry.auth.policy import ASVS_6_2_4_MIN_CORPUS_ENTRIES, BreachCorpusUnavailable


@pytest.fixture
def bundled_corpus(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[Callable[[Sequence[str] | None], None]]:
    """Point the loader at a stand-in bundled corpus holding exactly the entries you pass.

    `policy_module.files` is the module-level name the loader calls, and a `pathlib.Path` already
    satisfies the `/` + `read_bytes()` shape of an `importlib.resources` Traversable, so no fake class
    is needed. The `lru_cache` is cleared on BOTH sides: a truncated corpus left cached would disarm
    every later test in the session, which is the same silent-no-op failure this section exists over.
    """

    def use(entries: Sequence[str] | None) -> None:
        """A sequence writes exactly those entries; `None` leaves the file absent entirely."""
        root = tmp_path / "pkg"
        (root / "data").mkdir(parents=True, exist_ok=True)
        if entries is not None:
            (root / "data" / "common_passwords.txt").write_text(
                "\n".join(entries), encoding="utf-8"
            )
        monkeypatch.setattr(policy_module, "files", lambda _package: root)
        policy_module._common_passwords.cache_clear()

    yield use
    policy_module._common_passwords.cache_clear()


def test_a_truncated_bundled_corpus_refuses_a_password_instead_of_accepting_it(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """THE POSITIVE CONTROL for #1438: delete the guard in `_common_passwords` and this test fails.

    `correct-horse-battery-staple-xyz` is asserted ACCEPTED against the real corpus by
    `test_breach_corpus_growth_did_not_over_block_or_regress` above, so it clears every other clause
    and isolates the breach clause. Against a five-entry corpus the pre-#1438 loader returned an empty
    `frozenset`, `violations` returned `[]`, and that is byte-identical to a password which really was
    screened. An exception is the only outcome a test can tell apart from that silence.
    """
    bundled_corpus(["123456", "password", "qwerty", "letmein", "dragon"])
    with pytest.raises(BreachCorpusUnavailable, match="below the floor"):
        PasswordPolicy().violations("correct-horse-battery-staple-xyz")


def test_an_empty_bundled_corpus_refuses(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """Truncation to zero bytes is the cheapest way to disable the screen, so it gets its own arm."""
    bundled_corpus([])
    with pytest.raises(BreachCorpusUnavailable, match="0 entries"):
        PasswordPolicy().violations("correct-horse-battery-staple-xyz")


def test_a_missing_bundled_corpus_refuses(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """Deleting the file must not read as `nothing is breached` either. A distinct cause from the two
    arms above, and a distinct message: the read failed rather than returning too little."""
    bundled_corpus(None)
    with pytest.raises(BreachCorpusUnavailable, match="could not be read"):
        PasswordPolicy().violations("correct-horse-battery-staple-xyz")


def test_the_shipped_bundled_corpus_clears_the_runtime_floor() -> None:
    """The arm that keeps the three above honest.

    A guard wired to fire unconditionally would pass every one of them, so the shipped corpus has to
    be asserted through the SAME call path and come back clean. Measured at the time of writing:
    15,045 entries against a floor of 3,000.
    """
    assert len(policy_module._common_passwords()) >= ASVS_6_2_4_MIN_CORPUS_ENTRIES
    assert PasswordPolicy().violations("correct-horse-battery-staple-xyz") == []


def test_the_guard_stays_out_of_the_way_when_screening_is_turned_off(
    bundled_corpus: Callable[[Sequence[str] | None], None],
) -> None:
    """`check_breached=False` is a deliberate operator choice, so a corpus nobody consults is not a
    defect. This also pins that the guard did not become an unconditional import-time assertion."""
    bundled_corpus([])
    assert PasswordPolicy(check_breached=False).violations("correct-horse-battery-staple-xyz") == []


def test_startup_reports_an_unusable_bundled_corpus_as_an_error(
    bundled_corpus: Callable[[Sequence[str] | None], None], caplog: pytest.LogCaptureFixture
) -> None:
    """The loud half. Without this the operator meets the defect as a 500 on a password change, which
    is a window the eager load closes (the loader is `lru_cache`d and otherwise read lazily)."""
    from messagefoundry.auth.service import _error_if_bundled_corpus_unusable

    bundled_corpus([])
    with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
        _error_if_bundled_corpus_unusable(True)
    assert [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR], (
        "an unusable bundled corpus logged nothing at startup"
    )
    assert "REFUSED" in caplog.records[0].getMessage()


def test_startup_is_silent_when_screening_is_turned_off(
    bundled_corpus: Callable[[Sequence[str] | None], None], caplog: pytest.LogCaptureFixture
) -> None:
    from messagefoundry.auth.service import _error_if_bundled_corpus_unusable

    bundled_corpus([])
    with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
        _error_if_bundled_corpus_unusable(False)
    assert caplog.records == []
