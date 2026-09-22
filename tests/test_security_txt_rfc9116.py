# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``.well-known/security.txt`` stays conformant to RFC 9116 (BACKLOG #277, Lane 2).

RFC 9116 makes exactly two fields REQUIRED -- ``Contact`` and ``Expires`` -- and an
expired file is not a stale file but a useless one: section 2.5.5 says a reader
should not use data past ``Expires``. So the failure this guard exists for is silent
by construction. Nothing else in the tree reads this file: it ships in no wheel
(``pyproject.toml`` ``only-include`` is an allowlist), no test digests its bytes, and
the doc guards that do reach it check control bytes and forbidden content rather than
field grammar.

**The tracked-ness assertion is not ceremony.** ``.gitignore`` carries a root-anchored
``/*.txt`` rule, so the same file one directory up would be silently untracked --
present on the author's disk, absent from the repository, and absent from every clone.
Measured 2026-09-22: ``git check-ignore`` reports ``security.txt`` ignored by
``.gitignore`` line 132 and ``.well-known/security.txt`` not ignored. The RFC requires
the ``/.well-known/`` path anyway; this arm pins that the requirement and the ignore
rule keep agreeing.

**Two arms are deliberately asymmetric about time, and neither is the other's
duplicate.** ``test_expires_has_not_passed`` is the only dated assertion here and it
WILL go red when the published date arrives -- that is the renewal reminder, and its
remedy is one line in one file. ``test_expires_is_not_more_than_a_year_out`` cannot go
red with the passage of time, because the gap it measures only shrinks; it catches an
author who renews by reaching for a far-future date, which defeats the field.

**A Canonical arm that demanded absence would punish the right change.** No
``Canonical`` is published today, deliberately -- section 2.5.2 tells a reader to
distrust a file whose ``Canonical`` does not match where it was fetched from, so
naming a URI nobody serves is worse than naming none. The arm below is therefore
conditional: it stays silent until someone adds the field and then checks the path,
so starting to serve the file passes rather than fails.
"""

from __future__ import annotations

import datetime as dt
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_RELPATH = ".well-known/security.txt"
_FILE = _ROOT / ".well-known" / "security.txt"

#: The URI schemes RFC 9116 section 2.5.3 names for a ``Contact`` value. A bare email
#: address or a hostname is a formatting error a conforming parser may reject, and that
#: is the mistake most easily made by hand.
_CONTACT_SCHEMES = ("https://", "mailto:", "tel:")

#: RFC 9116 section 2.5.5 recommends a value less than a year out. A year plus a day of
#: slack keeps a deliberate "one year from today" from failing on leap-year arithmetic.
_MAX_LIFETIME = dt.timedelta(days=366)


def _fields(text: str) -> list[tuple[str, str]]:
    """Return ``(lowercased name, value)`` for each field line in ``text``.

    Comments (``#``) and blank lines are dropped, per RFC 9116 section 4. Takes text
    rather than reading the file so the control below can drive it over a planted
    string -- a parser that silently returned nothing would otherwise satisfy every
    arm here while reporting nothing about the real file.
    """
    pairs: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition(":")
        pairs.append((name.strip().lower(), value.strip()))
    return pairs


def _values(name: str) -> list[str]:
    """Every value published for field ``name``, in file order."""
    return [value for field, value in _fields(_FILE.read_text(encoding="utf-8")) if field == name]


def test_the_parser_reads_fields_and_skips_comments() -> None:
    """Positive control: without this, an empty parse would pass the arms below."""
    planted = "# a comment: with a colon\n\nContact: mailto:a@example.com\nExpires: 2030-01-01T00:00:00Z\n"
    assert _fields(planted) == [
        ("contact", "mailto:a@example.com"),
        ("expires", "2030-01-01T00:00:00Z"),
    ]
    assert _fields("# only a comment\n") == []


def test_the_file_sits_where_rfc9116_requires() -> None:
    assert _FILE.is_file(), (
        f"{_RELPATH} is missing. RFC 9116 section 3 requires the file under /.well-known/."
    )


def test_the_file_is_tracked_and_not_swallowed_by_the_root_txt_ignore_rule() -> None:
    """A copy one directory up would be ignored by `.gitignore`'s `/*.txt` and vanish."""
    tracked = subprocess.run(
        ["git", "ls-files", "--", _RELPATH],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert tracked == [_RELPATH], (
        f"{_RELPATH} is not tracked by git. A security.txt at the REPOSITORY ROOT is "
        "silently ignored by .gitignore's root-anchored /*.txt rule, so it would be "
        "absent from every clone. Keep the file under .well-known/, which the RFC "
        "requires in any case."
    )


def test_every_non_comment_line_is_a_field() -> None:
    """A line with no colon is neither a comment nor a field, and stops some parsers."""
    text = _FILE.read_text(encoding="utf-8")
    bad = [
        line
        for line in (raw.strip() for raw in text.splitlines())
        if line and not line.startswith("#") and ":" not in line
    ]
    assert bad == [], f"{_RELPATH} carries lines that are neither a comment nor a field: {bad}"


def test_contact_is_present_and_every_value_is_a_uri() -> None:
    contacts = _values("contact")
    assert contacts, f"{_RELPATH} publishes no Contact. RFC 9116 section 2.5.3 requires one."
    offenders = [c for c in contacts if not c.startswith(_CONTACT_SCHEMES)]
    assert offenders == [], (
        f"{_RELPATH} Contact values must be URIs beginning with one of {_CONTACT_SCHEMES} "
        f"-- a bare address is not one: {offenders}"
    )


def test_expires_appears_exactly_once() -> None:
    expires = _values("expires")
    assert len(expires) == 1, (
        f"{_RELPATH} must publish exactly one Expires (RFC 9116 section 2.5.5); found "
        f"{len(expires)}: {expires}"
    )


def _expires_at() -> dt.datetime:
    """The published ``Expires``, parsed, with its offset resolved."""
    raw = _values("expires")[0]
    # `fromisoformat` accepts the trailing `Z` from Python 3.11 on, which is the spelling
    # RFC 3339 recommends and the one every published security.txt uses.
    parsed = dt.datetime.fromisoformat(raw)
    assert parsed.tzinfo is not None, (
        f"{_RELPATH} Expires must carry a UTC offset (RFC 3339): {raw!r}"
    )
    return parsed


def test_expires_parses_as_an_rfc3339_timestamp() -> None:
    raw = _values("expires")[0]
    try:
        _expires_at()
    except ValueError as exc:  # pragma: no cover -- the message is the point
        pytest.fail(
            f"{_RELPATH} Expires is not an RFC 3339 timestamp ({raw!r}): {exc}. "
            "Use a form like 2027-09-01T00:00:00.000Z."
        )


def test_expires_has_not_passed() -> None:
    """The renewal reminder. This arm is dated on purpose -- see the module docstring."""
    expires = _expires_at()
    now = dt.datetime.now(dt.UTC)
    assert expires > now, (
        f"{_RELPATH} expired on {expires.isoformat()}. RFC 9116 section 2.5.5 says a "
        "reader should not use data past Expires, so the published file is now inert. "
        "Remedy: raise the Expires line to a date less than a year out, and re-check "
        "that both Contact channels still reach a maintainer."
    )


def test_expires_is_not_more_than_a_year_out() -> None:
    """Cannot go red with time: the gap only shrinks. Catches renewal by far-future date."""
    expires = _expires_at()
    horizon = dt.datetime.now(dt.UTC) + _MAX_LIFETIME
    assert expires <= horizon, (
        f"{_RELPATH} Expires is {expires.isoformat()}, more than a year out. RFC 9116 "
        "section 2.5.5 recommends less than a year, because the field's value is that "
        "it forces a re-check of the contact channels."
    )


def test_a_canonical_if_present_names_the_well_known_path() -> None:
    """Silent until someone serves the file, then checks the path the RFC requires."""
    for value in _values("canonical"):
        assert value.startswith("https://"), f"{_RELPATH} Canonical must be an https URI: {value!r}"
        assert value.endswith("/.well-known/security.txt"), (
            f"{_RELPATH} Canonical must name the /.well-known/security.txt path so a "
            f"reader can compare it against where the file was fetched from: {value!r}"
        )


def test_the_policy_field_points_at_the_repository_disclosure_policy() -> None:
    """The file carries contacts only; the terms live in one place and are linked, not copied."""
    policies = _values("policy")
    assert policies, f"{_RELPATH} publishes no Policy link to the disclosure policy."
    assert any("SECURITY.md" in p for p in policies), (
        f"{_RELPATH} Policy should point at the project's SECURITY.md, which carries the "
        f"authorization and safe-harbor terms: {policies}"
    )
