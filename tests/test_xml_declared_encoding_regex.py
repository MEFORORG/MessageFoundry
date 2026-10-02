# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The XML declaration's ``encoding=`` regex is linear and matches what it always matched (BACKLOG #2561).

``harden._DECLARED_ENCODING`` runs before every ``str`` parse by the lxml codec. Its shipped-before
head, ``<\\?xml\\b[^>]*?``, could end anywhere inside a whitespace run, and the ``\\s+`` after it then
re-walked the rest of the run from each of those ends. 16,000 spaces inside one declaration cost about
0.2 s, fourfold per doubling. The fix adds ``(?<!\\s)``, so the head may not end on whitespace. Two
properties have to hold, and each has its own arm here:

* **Growth.** Only a stopwatch sees a growth property, so the arm compares a RATIO across two sizes
  rather than an absolute time, and it runs the shipped-before pattern in the same run as its positive
  control. Without that control a fast box passes whatever the pattern does.
* **Same match.** The fix must find the same declared encodings: BOM-led, single and double quotes.
  A fixed table covers the named shapes and a seeded fuzz compares the two patterns on short inputs,
  where the old one is still cheap.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable

import pytest

from messagefoundry.parsing.xml import harden

# The span, the threshold and the minimum-of-rounds timer are that file's, reused so the two growth
# arms cannot drift apart: 8x the input, where linear reads about 8x and quadratic about 64x.
from tests.test_log_redaction_secret_domain import _GROWTH_LENGTHS, _MAX_GROWTH, _fastest

_BOM = chr(0xFEFF)

#: The pattern this module replaced, kept as the reference the new one must agree with.
_SHIPPED_BEFORE = re.compile(
    r"\A(" + _BOM + r"?<\?xml\b[^>]*?)\s+encoding\s*=\s*(\"[^\"]*\"|'[^']*')"
)

#: Probe shapes of ``n`` characters. Each runs the scan to failure, the worst case, not a lucky one.
_PROBES: dict[str, Callable[[int], str]] = {
    # The audit's shape: a declaration with a long run before its own ``?>``.
    "declaration, run, close": lambda n: '<?xml version="1.0"' + " " * n + "?><r/>",
    # No ``>`` at all, so nothing ends the scan early.
    "bare <?xml then run": lambda n: "<?xml" + " " * n,
    # The run sits between ``encoding`` and a missing ``=``.
    "encoding then run": lambda n: '<?xml version="1.0" encoding' + "\t" * n + "x?><r/>",
    # Many short runs: the most places the fixed head may still stop. The old pattern is linear here
    # too, so this row guards the fixed pattern's own worst case, not against a revert.
    "many short runs": lambda n: "<?xml" + " a" * (n // 2),
}


def _growth(pattern: re.Pattern[str], probe: Callable[[int], str], *, rounds: int) -> float:
    small, large = (
        _fastest(lambda text: pattern.sub(r"\1", text, count=1), probe(n), rounds)
        for n in _GROWTH_LENGTHS
    )
    return large / small


def test_the_declared_encoding_scan_grows_linearly_in_a_whitespace_run() -> None:
    """A run inside the declaration costs ``_DECLARED_ENCODING`` linear time, and the shipped-before
    pattern, as the positive control, proves the instrument can see the difference on this box."""
    control = _growth(_SHIPPED_BEFORE, _PROBES["declaration, run, close"], rounds=3)
    assert control > _MAX_GROWTH, (
        f"the shipped-before pattern grew only {control:.1f}x across {_GROWTH_LENGTHS}, under the "
        f"{_MAX_GROWTH}x threshold. This box or this probe is not exercising the scan, so the "
        "assertions below cannot fail -- fix the fixture, do not raise the bar."
    )
    for name, probe in _PROBES.items():
        growth = _growth(harden._DECLARED_ENCODING, probe, rounds=7)
        assert growth < _MAX_GROWTH, (
            f"{name}: _DECLARED_ENCODING grew {growth:.1f}x across {_GROWTH_LENGTHS}, over "
            f"{_MAX_GROWTH}x -- the scan is super-linear in a whitespace run again (BACKLOG #2561)"
        )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('<?xml version="1.0" encoding="iso-8859-1"?><r/>', '<?xml version="1.0"?><r/>'),
        ("<?xml version='1.0' encoding='utf-16'?><r/>", "<?xml version='1.0'?><r/>"),
        (_BOM + '<?xml version="1.0" encoding="utf-16"?><r/>', _BOM + '<?xml version="1.0"?><r/>'),
        ('<?xml encoding="utf-8"?><r/>', "<?xml?><r/>"),
        (
            '<?xml version="1.0"\n\t encoding = "utf-8" standalone="yes"?><r/>',
            '<?xml version="1.0" standalone="yes"?><r/>',
        ),
        # The probe shape itself, with a claim after the run: still found, and the run goes with it.
        (
            '<?xml version="1.0"' + " " * 5000 + 'encoding="utf-8"?><r/>',
            '<?xml version="1.0"?><r/>',
        ),
        # Not a declaration, or no whitespace before the name: left alone, as before.
        ('<r encoding="utf-8"/>', '<r encoding="utf-8"/>'),
        ('<?xmlx encoding="utf-8"?><r/>', '<?xmlx encoding="utf-8"?><r/>'),
        ('<?xml version="1.0"encoding="utf-8"?><r/>', '<?xml version="1.0"encoding="utf-8"?><r/>'),
        (
            '<?xml version="1.0" xencoding="a" encoding="b"?><r/>',
            '<?xml version="1.0" xencoding="a"?><r/>',
        ),
        # A claim whose name sits past the first ``>`` is not in the declaration. (A quoted value
        # may still run past it, in both patterns alike, on input that was already malformed.)
        (
            '<?xml version="1.0"?><r encoding="utf-8"/>',
            '<?xml version="1.0"?><r encoding="utf-8"/>',
        ),
        ("  <?xml encoding='utf-8'?><r/>", "  <?xml encoding='utf-8'?><r/>"),
    ],
)
def test_the_declared_encoding_is_dropped_exactly_as_before(text: str, expected: str) -> None:
    assert harden._without_declared_encoding(text) == expected
    assert _SHIPPED_BEFORE.sub(r"\1", text, count=1) == expected


_FUZZ_TOKENS = (
    "<?xml", "<?xml", " ", " ", "\t", "\n", "encoding", "encoding", "=", '"', "'", ">", "?", "a",
    "x", "1.0", _BOM, "version=", '"utf-8"', "'latin1'",
    # Whole and broken claims, so a useful share of inputs reaches the match and its edges.
    ' encoding="a"', "\tencoding='b'", " encoding =", ' encoding= "c"', '="', "  ",
)  # fmt: skip


def test_the_new_pattern_matches_the_shipped_one_on_seeded_fuzz() -> None:
    """Same span and same groups on every input. Inputs stay short, where the old pattern is cheap."""
    rng = random.Random(2561)
    matched = 0
    for _ in range(20_000):
        head = rng.choice(("<?xml", _BOM + "<?xml", ""))
        text = head + "".join(rng.choice(_FUZZ_TOKENS) for _ in range(rng.randint(0, 14)))
        old = _SHIPPED_BEFORE.match(text)
        new = harden._DECLARED_ENCODING.match(text)
        assert (old is None) == (new is None), repr(text)
        if old is not None and new is not None:
            matched += 1
            assert (old.span(), old.groups()) == (new.span(), new.groups()), repr(text)
    # A fuzz that never produces a match compares nothing; this proves it reached the interesting case.
    assert matched > 500, matched


def test_a_long_run_before_the_claim_still_reads_the_strs_own_characters() -> None:
    """End to end through ``parse_bytes``: the stale ``iso-8859-1`` claim after a long run is dropped,
    so lxml reads ``café`` rather than decoding the UTF-8 bytes a second time."""
    pytest.importorskip("lxml")
    body = '<?xml version="1.0"' + " " * 20_000 + 'encoding="iso-8859-1"?><r>café</r>'
    assert harden.parse_bytes(body).text == "café"
