# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The widened DSN reading on every path of ``secretscrub._union``, and its growth (BACKLOG #5386).

Synthetic values only. ``_union`` runs two readings of a line and has at least these ways out: the
merged output, the reading before whole where the shipped one would hide a member key's ";", and
the reading before alone where a replacement is untraceable. The reading before ran with
``wide=False``, so on the last two the widened pass never ran and a password-only DSN, or the tail
of a password holding an "@", printed. The first two tests fail on that code; the growth tests
hold a property that code already had, and had no stopwatch for.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import pytest

from messagefoundry import secretscrub as scrub_mod
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials
from messagefoundry.support.redact import redact_log_line
from tests._growth import _growth_between

#: Lines ``_union`` returns its reading before for, whole: ``userPwd`` is camelCase, so the line
#: takes the union, and the shipped reading hides the ``;`` of ``;PWD=``, a member key the reading
#: before prints. Each pairs the line with a value that must not print.
_MEMBER_KEY_LINES = (
    ("connect redis://:Zq-Pw_1@h failed; userPwd='a;PWD=b c'", "Zq-Pw_1"),
    ("connect postgres://svc:Kv9x@Zq7_Tail@h failed; userPwd='a;PWD=b c'", "Zq7_Tail"),
)


@pytest.mark.parametrize(("line", "secret"), _MEMBER_KEY_LINES)
def test_the_reading_before_kept_whole_still_runs_the_widened_pass(
    line: str, secret: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The line leaves ``_union`` by its member-key branch, and the widened pass ran on it."""
    results: list[str] = []
    real_run = scrub_mod._run

    def spy(*args: object, **kwargs: object) -> str:
        out = real_run(*args, **kwargs)  # type: ignore[arg-type]
        results.append(out)
        return out

    monkeypatch.setattr(scrub_mod, "_run", spy)
    out = scrub_credentials(line)
    # Control: what came back is a reading that printed the ``;PWD=`` member key, and another
    # reading of the line hid it, which is what sends the line down this branch rather than the
    # merged one.
    assert out in results and ";PWD=" in out, (results, out)
    assert any(";PWD=" not in result for result in results), results
    assert secret not in out, out
    assert CREDENTIAL_PLACEHOLDER in out


def test_an_untraceable_line_still_runs_the_widened_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fallback for a replacement ``_Trace`` cannot read is the reading before alone. Forced
    here, since no shipped replacement reaches it; the control shows the fallback is what ran."""
    calls: list[bool] = []

    def untraceable(self: object, *args: object) -> str:
        calls.append(True)
        raise scrub_mod._Untraceable("forced")

    monkeypatch.setattr(scrub_mod._Trace, "sub", untraceable)
    for line, secret in (
        ("connect redis://:Zq-Pw_2@h failed password=x userPwd=x", "Zq-Pw_2"),
        ("connect postgres://svc:Kv9y@Zq8_Tail@h failed password=x userPwd=x", "Zq8_Tail"),
    ):
        calls.clear()
        out = scrub_credentials(line)
        assert calls, "the line did not take the union, so the fallback is not what ran"
        assert secret not in out, out


def test_the_reading_before_differs_only_by_the_widened_pass() -> None:
    """The pre-camelCase reading, as ``_union``'s fallback runs it, prints the residual line's
    password with ``wide=False`` and hides it without, so the flag is what the tests above turn on."""
    line, secret = _MEMBER_KEY_LINES[0]
    folded = scrub_mod._gate_fold(line)
    before = scrub_mod._pre_camel_sub
    assert secret in scrub_mod._run(line, CREDENTIAL_PLACEHOLDER, folded, before, wide=False)
    assert secret not in scrub_mod._run(line, CREDENTIAL_PLACEHOLDER, folded, before)


# --- GROWTH OF THE WIDENED PATTERN ITSELF ---------------------------------------------------------
#
# ``tests/test_security_static.py`` cannot resolve ``_WIDE_DSN_PASSWORD``, since it splices
# ``_DSN_RUN_STOP``, so its ReDoS gate holds the shape by inspection only. This is the stopwatch for
# it. The ratio and the bar are ``tests/test_log_redaction_secret_domain.py``'s, at half its
# lengths so the quadratic control stays cheap: 8x the length, linear near 8x, a bar of 24x,
# quadratic near 64x.

_LENGTHS = (1024, 8192)
_MAX_GROWTH = 24.0

#: Adversarial shapes, each a function of the run length. The first three reach no "@" the match
#: could end at, so the scan walks the whole run and fails, which is the worst case. The fourth
#: matches, over a run holding many "@"; the fifth packs scheme heads, each a match attempt. The
#: sixth is the "%" alternative added item 3 put in an empty user's first segment, the seventh its
#: bracket alternative, and the eighth the ";"-split tail after a user's placeholder.
_WIDE_SHAPES: tuple[tuple[str, Callable[[int], str]], ...] = (
    # An empty user's first segment over a run both of its classes take: the split the possessive
    # quantifier exists to refuse.
    ("empty user, one class", lambda n: "redis://:" + "a" * n),
    # The first segment stops at once, at "=", and the run after it walks and backs off.
    ("empty user, run only", lambda n: "redis://:" + "=" * n),
    # A user's first segment, the atomic group, over a run the run after it also takes.
    ("user, one class", lambda n: "postgres://svc:" + "a" * n),
    # A placeholder as the user's first segment, then a run of "@" and letters to back off over.
    ("user, at-sign run", lambda n: "postgres://svc:<redacted>" + ("@a" * n)[:n] + " "),
    # Many scheme heads glued together, so the scan starts a match at every one of them.
    ("glued scheme heads", lambda n: ("a.b-://:" * n)[:n]),
    # An empty user's first segment over "%", each a fixed-width lookahead (added item 3).
    ("empty user, percent run", lambda n: "redis://:" + ("%a" * n)[:n]),
    # An empty user's first segment over brackets that open no placeholder (the bracket half of
    # added item 3), each "[" a lookahead.
    ("empty user, bracket run", lambda n: "redis://:" + ("[9]" * n)[:n]),
    # The ";"-split tail after a user's placeholder (added item 4), each repeat led by a ";",
    # reaching no "@" it could end at.
    ("user, semicolon tail", lambda n: "postgres://svc:<redacted>@" + ("a;" * n)[:n] + " "),
)


def _growth(call: Callable[[str], object], shape: Callable[[int], str], *, rounds: int) -> float:
    return _growth_between(call, shape(_LENGTHS[0]), shape(_LENGTHS[1]), rounds=rounds)


#: The widened pattern's skeleton with its first segments backtracking rather than possessive, and
#: without its label stops and placeholder alternatives. The comment on ``_WIDE_DSN_PASSWORD``
#: names backtracking there as the quadratic shape; this is the positive control below, and shows
#: only that the bar catches a quadratic pattern on this box.
_BACKTRACKING_WIDE = re.compile(
    r"(?i)(?<![a-z0-9+.\-])([a-z0-9+.\-]+://[^\s:/@]*):"
    r"(?:(?<=//:)[^\s/@?#&=;,()|^~{}<>\[\]%\x27\x22]*|(?<!//:)[^\s/@<>\[\]]+)"
    r"[^\s/;?#&,()|^~{}<>\[\]%\x27\x22]*@"
)


def test_the_widened_dsn_pattern_grows_linearly_in_line_length() -> None:
    """``_WIDE_DSN_PASSWORD`` on each adversarial shape, and through the support bundle's last pass.

    POSITIVE CONTROL FIRST, in this run on this box: the same skeleton with backtracking first
    segments grows past the bar on the one-class shapes, so a bar this subject passes is one a
    quadratic pattern fails. Without it a fast box would pass anything."""
    for label in ("empty user, one class", "user, one class"):
        shape = dict(_WIDE_SHAPES)[label]
        control = _growth(lambda text: _BACKTRACKING_WIDE.sub("x", text), shape, rounds=2)
        assert control > _MAX_GROWTH, (
            f"the backtracking control grew only {control:.1f}x on {label!r}; this input or box is "
            "not exercising the scan, so the assertions below prove nothing"
        )
    wide = scrub_mod._WIDE_DSN_PASSWORD
    for label, shape in _WIDE_SHAPES:
        ratio = _growth(lambda text: wide.sub("x", text), shape, rounds=5)
        assert ratio <= _MAX_GROWTH, (
            f"_WIDE_DSN_PASSWORD grew {ratio:.1f}x on {label!r} for 8x the length, over the "
            f"{_MAX_GROWTH}x bar: a repetition in it has lost its containment"
        )
    # The bundle runs the widened pass only on a line holding "@" and "://"; the leading "@" opens it.
    for label, shape in _WIDE_SHAPES:
        ratio = _growth(lambda text: redact_log_line("@ " + text), shape, rounds=3)
        assert ratio <= _MAX_GROWTH, f"redact_log_line grew {ratio:.1f}x on {label!r}"


def test_the_growth_shapes_reach_the_widened_pattern() -> None:
    """The shapes above are only evidence if the pattern reads them: each opens a scheme head the
    pattern starts on. The first three match once the run ends in "@"; the fourth matches as it
    stands; the fifth starts a match at each of its heads; the sixth and the seventh match once the
    run ends in "@", and the eighth's tail is taken whole once it does."""
    wide = scrub_mod._WIDE_DSN_PASSWORD
    shapes = dict(_WIDE_SHAPES)
    for label, shape in _WIDE_SHAPES[:3]:
        assert wide.search(shape(64) + "@h") is not None, label
    assert wide.search(shapes["user, at-sign run"](64)) is not None
    glued = shapes["glued scheme heads"](64)
    assert len(wide.findall(glued.replace("://:", "://:x@"))) >= 4
    assert wide.search(shapes["empty user, percent run"](64) + "@h") is not None
    bracket = wide.search(shapes["empty user, bracket run"](64) + "@h")
    assert bracket is not None and bracket.end() == len(shapes["empty user, bracket run"](64)) + 1
    tail = shapes["user, semicolon tail"](64).rstrip() + "a@h"
    match = wide.search(tail)
    assert match is not None and match.end() == len(tail) - 1, (match, tail)


def test_both_readings_apply_the_same_widened_pattern() -> None:
    """``_run``'s docstring rests on this: ``_pre_camel`` leaves the widened pattern unchanged."""
    wide = scrub_mod._WIDE_DSN_PASSWORD
    assert scrub_mod._pre_camel(wide).pattern == wide.pattern
