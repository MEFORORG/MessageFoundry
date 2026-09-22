# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``.well-known/security.txt`` stays conformant to RFC 9116 (BACKLOG #277, Lane 2).

RFC 9116 makes exactly two fields REQUIRED -- ``Contact`` and ``Expires`` -- and an
expired file is not a stale file but a useless one: section 2.5.5 says a reader should
not use data past ``Expires``. So the failure this guard exists for is silent by
construction. Nothing else in the tree reads the file: it ships in no wheel
(``pyproject.toml`` ``only-include`` is an allowlist), no test digests its bytes, and
the doc guards that do reach it check control bytes and forbidden content rather than
field grammar.

**The tracked-ness arm is not ceremony.** ``.gitignore`` carries a root-anchored
``/*.txt`` rule, so the same file one directory up would be silently untracked --
present on the author's disk, absent from the repository, and absent from every clone.
Measured 2026-09-22: ``git check-ignore`` reports ``security.txt`` ignored by
``.gitignore`` line 132 and ``.well-known/security.txt`` not ignored. The RFC requires
the ``/.well-known/`` path in any case; this arm pins that the requirement and the
ignore rule keep agreeing.

**THERE IS DELIBERATELY NO "HAS NOT EXPIRED" ARM, and the omission is the considered
half of this module.** One was written and removed. A blocking assertion dated to the
expiry instant is an outage alarm rather than a reminder: it first reds on the day the
published file has already gone inert, it reds every unrelated pull request and every
merge-queue batch until someone bumps a date, it recurs annually by construction
because ``_MAX_LIFETIME`` forces the next value under a year out, and it lands the
remediation on whoever's pull request is red rather than on whoever owns the policy --
who is the only person able to do the half that matters, which is re-checking that both
contact channels still reach a maintainer.

The right home is a non-blocking lane with lead time.
``.github/workflows/quality-advisory.yml`` is the repository's one place a check can
report without being able to gate, so that is where such an arm belongs. **It is NOT
enough on its own, and saying so is the point of this paragraph.** Measured 2026-09-22:
``nightly-notice.yml`` watches ``["CI", "Security", "DAST", "Stalled PRs", "Required
workflow state"]`` and names ``quality-advisory`` nowhere, and that file's own header
warns that several scheduled workflows here are unwatched. A reminder added to the
advisory lane and not to that watch list reports into nothing, which would be a
compensating control resting on a false premise (SDS-3.7). Both halves are filed, not
built here: wiring a workflow is Lane 1's and outside this brief. Until they exist,
renewal rests on the note in the file itself and on nothing else -- which is a real gap,
not a covered one.

``test_expires_is_not_more_than_a_year_out`` is what remains, and it cannot go red with
the passage of time, because the gap it measures only shrinks. It catches an author who
renews by reaching for a far-future date, which defeats the field.

**A Canonical arm that demanded absence would punish the right change.** No
``Canonical`` is published today, deliberately -- section 2.5.2 tells a reader to
distrust a file whose ``Canonical`` does not match where it was fetched from, so naming
a URI nobody serves is worse than naming none. The arm below is therefore conditional:
it stays silent until someone adds the field and then checks the path, so starting to
serve the file passes rather than fails.

**Two arms bind the file to the policy page instead of trusting a substring.** The
contacts are re-typed here from ``.github/SECURITY.md``, which is a second copy of a
load-bearing fact (SDS-3.5), and the machine-readable copy is the one no human reads
often enough to notice going stale. So one arm requires every published ``Contact`` to
still appear in the policy page, and another resolves the ``Policy`` URL's own path
against ``git ls-files`` -- a substring check would stay green while the published URI
404s for every researcher who fetched it.
"""

from __future__ import annotations

import datetime as dt
import re
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RELPATH = ".well-known/security.txt"
_FILE = _ROOT / ".well-known" / "security.txt"

#: The disclosure policy the `Policy` field points at, and the source of record for the
#: contact channels this file republishes.
_POLICY_RELPATH = ".github/SECURITY.md"
_POLICY = _ROOT / ".github" / "SECURITY.md"

#: The URI schemes RFC 9116 section 2.5.3 names for a ``Contact`` value. A bare email
#: address or a hostname is a formatting error a conforming parser may reject, and it is
#: the mistake most easily made by hand.
_CONTACT_SCHEMES = ("https://", "mailto:", "tel:")

#: RFC 9116 section 2.5.5 recommends a value less than a year out. A year plus a day of
#: slack keeps a deliberate "one year from today" from failing on leap-year arithmetic.
_MAX_LIFETIME = dt.timedelta(days=366)

#: A GitHub blob URL, captured so the arm below can resolve the path it publishes against
#: the tree rather than trusting that the URL contains a plausible-looking filename. The
#: ref is `.+?` and not `[^/]+` because a branch name may contain a slash
#: (`release/1.0`), and the path capture stops at `#` or `?` so a deep link to a heading
#: resolves to the file rather than to a name git cannot possibly track.
_BLOB_URL = re.compile(r"^https://github\.com/[^/]+/[^/]+/blob/.+?/(?P<path>[^#?\s]+)")

#: RFC 9116's grammar is ``field-name ":" SP value``: a token name, then a colon, then one
#: space. Anchored at the line start, so an indented line fails, and the name class is
#: explicit, so a bare pasted URL does not parse as a field called ``https``.
_FIELD_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*: \S")


def _significant_lines(text: str) -> list[str]:
    """Lines that are neither blank nor a comment, per RFC 9116's grammar.

    Shared with the field parser so the comment convention is defined once. Kept
    separate from ``_fields`` because ``partition(":")`` cannot answer the malformed-line
    question: on a colon-less line it yields ``(line, "", "")``, which is indistinguishable
    from a real field with an empty value.

    **Only the trailing newline is stripped, deliberately.** RFC 9116's grammar is
    ``field-name ":" SP value`` with no leading whitespace, so an indented field line is
    one a conforming researcher-side parser may reject. Stripping the left side here
    would hide exactly that from ``test_every_significant_line_is_a_well_formed_field``,
    which is the arm that exists to catch it.
    """
    return [
        line
        for line in (raw.rstrip() for raw in text.splitlines())
        if line and not line.startswith("#")
    ]


def _fields(text: str) -> list[tuple[str, str]]:
    """Return ``(lowercased name, value)`` for each field line in ``text``.

    Takes text rather than reading the file so the control below can drive it over a
    planted string -- a parser that silently returned nothing would otherwise satisfy
    every arm here while reporting nothing about the real file.
    """
    pairs: list[tuple[str, str]] = []
    for line in _significant_lines(text):
        name, _, value = line.partition(":")
        pairs.append((name.strip().lower(), value.strip()))
    return pairs


def _values(name: str) -> list[str]:
    """Every value published for field ``name``, in file order."""
    return [value for field, value in _fields(_FILE.read_text(encoding="utf-8")) if field == name]


def _tracked(relpath: str) -> list[str]:
    """What ``git ls-files`` names for ``relpath`` -- empty when git does not track it."""
    return subprocess.run(
        ["git", "ls-files", "--", relpath],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
        # `splitlines`, never `split`: git separates paths by newline, and a path
        # containing a space would otherwise come back as two entries and read as untracked.
    ).stdout.splitlines()


def test_the_parser_reads_fields_and_skips_comments() -> None:
    """Positive control: without this, an empty parse would pass the arms below."""
    planted = "# a comment: with a colon\n\nContact: mailto:a@example.com\nExpires: 2030-01-01T00:00:00Z\n"
    assert _fields(planted) == [
        ("contact", "mailto:a@example.com"),
        ("expires", "2030-01-01T00:00:00Z"),
    ]
    assert _fields("# only a comment\n") == []
    # Leading whitespace SURVIVES, so the well-formed-field arm can see and reject it.
    assert _significant_lines("# c\n\n  Contact: x\n") == ["  Contact: x"]
    assert not _FIELD_LINE.match("  Contact: x")
    assert not _FIELD_LINE.match("https://example.com/report")
    assert not _FIELD_LINE.match("Contact:mailto:a@b.c")
    assert _FIELD_LINE.match("Contact: mailto:a@b.c")


def test_the_file_sits_where_rfc9116_requires() -> None:
    assert _FILE.is_file(), (
        f"{_RELPATH} is missing. RFC 9116 requires the file under the /.well-known/ path."
    )


def test_the_file_is_tracked_and_not_swallowed_by_the_root_txt_ignore_rule() -> None:
    """A copy one directory up would be ignored by `.gitignore`'s `/*.txt` and vanish."""
    assert _tracked(_RELPATH) == [_RELPATH], (
        f"{_RELPATH} is not tracked by git. A security.txt at the REPOSITORY ROOT is "
        "silently ignored by .gitignore's root-anchored /*.txt rule, so it would be "
        "absent from every clone. Keep the file under .well-known/, which the RFC "
        "requires in any case."
    )


def test_every_significant_line_is_a_well_formed_field() -> None:
    """Rejects the malformed shapes a hand edit actually produces.

    A colon-only check was the first version of this arm and was not enough: a pasted
    contact URL that lost its ``Contact: `` prefix contains a colon, so it passed while
    parsing as a field named ``https`` that ``_values("contact")`` never sees. An
    indented field and a missing space after the colon slipped through the same way.
    """
    bad = [
        line
        for line in _significant_lines(_FILE.read_text(encoding="utf-8"))
        if not _FIELD_LINE.match(line)
    ]
    assert bad == [], (
        f"{_RELPATH} carries lines that are neither a comment nor a well-formed field: "
        f"{bad}. RFC 9116's grammar is `field-name: value` -- a token name, a colon, one "
        "space -- with no leading whitespace and no bare values."
    )


def test_contact_is_present_and_every_value_is_a_uri() -> None:
    contacts = _values("contact")
    assert contacts, f"{_RELPATH} publishes no Contact. RFC 9116 section 2.5.3 requires one."
    offenders = [c for c in contacts if not c.startswith(_CONTACT_SCHEMES)]
    assert offenders == [], (
        f"{_RELPATH} Contact values must be URIs beginning with one of {_CONTACT_SCHEMES} "
        f"-- a bare address is not one: {offenders}"
    )


def test_every_contact_channel_still_appears_in_the_disclosure_policy() -> None:
    """The contacts are a second copy; this is what stops the machine-readable one rotting."""
    policy = _POLICY.read_text(encoding="utf-8")
    missing = [
        contact
        for contact in _values("contact")
        if contact.removeprefix("mailto:").removeprefix("tel:") not in policy
    ]
    assert missing == [], (
        f"{_RELPATH} publishes contact channels that {_POLICY_RELPATH} no longer names: "
        f"{missing}. The policy page is the source of record and is the copy a human "
        "edits, so a channel changed there and not here leaves the machine-readable file "
        "pointing somewhere nobody reads."
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
    try:
        # `fromisoformat` accepts the trailing `Z` from Python 3.11 on, which is the
        # spelling RFC 3339 recommends and the one every published security.txt uses.
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError as exc:
        raise AssertionError(
            f"{_RELPATH} Expires is not an RFC 3339 timestamp ({raw!r}): {exc}. "
            "Use a form like 2027-09-01T00:00:00.000Z."
        ) from exc
    assert parsed.tzinfo is not None, (
        f"{_RELPATH} Expires must carry a UTC offset (RFC 3339): {raw!r}"
    )
    return parsed


def test_expires_is_not_more_than_a_year_out() -> None:
    """Cannot go red with time: the gap only shrinks. Catches renewal by far-future date."""
    expires = _expires_at()
    horizon = dt.datetime.now(dt.UTC) + _MAX_LIFETIME
    assert expires <= horizon, (
        f"{_RELPATH} Expires is {expires.isoformat()}, more than a year out. RFC 9116 "
        "section 2.5.5 recommends less than a year, because the field's value is that it "
        "forces a re-check of the contact channels."
    )


def test_a_canonical_if_present_names_the_well_known_path() -> None:
    """Silent until someone serves the file, then checks the path the RFC requires."""
    for value in _values("canonical"):
        assert value.startswith("https://"), f"{_RELPATH} Canonical must be an https URI: {value!r}"
        assert value.endswith("/.well-known/security.txt"), (
            f"{_RELPATH} Canonical must name the /.well-known/security.txt path so a reader "
            f"can compare it against where the file was fetched from: {value!r}"
        )


def test_a_policy_is_published_and_a_blob_link_resolves_to_a_tracked_file() -> None:
    """A substring check would stay green while the published URI 404s for every reader.

    **Requiring a GitHub blob URL would punish the right change**, which is the trap the
    Canonical arm above is shaped to avoid and which the first version of this arm walked
    straight into: the day the policy is served from the project's own domain, a
    hard requirement reds CI for doing the correct thing. So the resolution is
    conditional on the URL being a blob link, and what is unconditional is only that a
    `Policy` exists and is an https URI.
    """
    policies = _values("policy")
    assert policies, f"{_RELPATH} publishes no Policy link to the disclosure policy."

    offenders = [p for p in policies if not p.startswith("https://")]
    assert offenders == [], f"{_RELPATH} Policy must be an https URI: {offenders}"

    blobs = [matched for matched in (_BLOB_URL.match(p) for p in policies) if matched]
    for matched in blobs:
        path = matched.group("path")
        assert _tracked(path) == [path], (
            f"{_RELPATH} Policy points at {path!r}, which git does not track. The "
            "published URI would 404 for every researcher who fetched this file. Move "
            "the link with the file."
        )

    # Only meaningful while the policy IS a blob link. Once it is served elsewhere there
    # is no tree path to compare, and the arm above has already stopped applying.
    if blobs:
        resolved = [matched.group("path") for matched in blobs]
        assert _POLICY_RELPATH in resolved, (
            f"{_RELPATH} Policy should point at {_POLICY_RELPATH}, which carries the "
            f"authorization and safe-harbor terms: {resolved}"
        )


def test_the_advisory_channel_is_published_first() -> None:
    """The file declares its Contact order load-bearing, so something must hold it.

    RFC 9116 reads `Contact` in decreasing order of preference, and
    `.github/SECURITY.md` designates the private advisory the recommended channel while
    warning that ordinary email is not end-to-end encrypted. Swap the two lines -- a
    plausible edit when alphabetizing or adding a channel -- and every other arm here
    stays green while researcher tooling starts preferring the unencrypted route.
    """
    contacts = _values("contact")
    assert contacts and contacts[0].startswith("https://"), (
        f"{_RELPATH} must publish the private advisory channel as its FIRST Contact, "
        f"because RFC 9116 reads the order as decreasing preference and the policy page "
        f"makes the advisory the recommended route: {contacts}"
    )
