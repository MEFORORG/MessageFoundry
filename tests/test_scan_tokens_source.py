# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Self-tests for the externalized forbidden-content token source.

These assert the two things the cutover depends on for scripts/security/scan_forbidden.py:

  1. the COMMITTED source carries ZERO real tokens -- with no external source it degrades to
     structural-only (empty name/estate/site tables) yet still flags a routable IP; and scanning the
     committed scanner + its .example finds no routable IP of its own; and

  2. the committed scan-tokens.local.txt.example is SYNTHETIC -- it parses to exactly the ACME/EXAMPLE
     placeholders and the non-real ``99`` site prefix, so any real token slipping into it fails here.

A later group, marked by its own section banner below, pins something adjacent rather than part of the
cutover: the PLACEHOLDER-GUIDANCE prose that the same token list configures, which is self-colliding
for authors and had no guard at all.

The scanner is loaded by path (scripts/ is not a package). Every routable test IP is assembled from
octets at runtime so THIS test file contains no literal routable dotted-quad of its own to trip the
gate that scans it.
"""

from __future__ import annotations

import importlib.util
import itertools
import re
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCANNER = _ROOT / "scripts" / "security" / "scan_forbidden.py"
_EXAMPLE = _ROOT / "scripts" / "security" / "scan-tokens.local.txt.example"
_CONTRIBUTING = _ROOT / "CONTRIBUTING.md"
_SETUP_SCRIPT = _ROOT / "scripts" / "dev" / "setup-leak-gate.ps1"

#: The non-numeric stand-in this project tells contributors to use for a site code in tracked prose.
#: Written here as a plain word on purpose: a stand-in that is itself a digit run would recreate the
#: collision the convention exists to avoid.
_STANDIN = "SITEA"

# A routable probe IP, built from parts so no literal dotted-quad appears in this tracked file --
# including in this comment, which is scanned like any other line.
_ROUTABLE_IP = ".".join(["8", "8", "8", "8"])
# Non-routable examples (RFC1918 + RFC5737) that must NOT be flagged.
_ALLOWED_IPS = (".".join(["10", "0", "0", "5"]), ".".join(["192", "0", "2", "9"]))

_counter = itertools.count()


def _load(source: str | Path | None, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load a FRESH scanner instance and force a deterministic token source.

    ``source=None`` -> structural-only (env cleared, local file pointed at a nonexistent path).
    ``source=<path>`` -> that token file via MEFOR_FORBIDDEN_TOKENS.
    """
    spec = importlib.util.spec_from_file_location(f"sf_{next(_counter)}", _SCANNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # runs reload_tokens() once against the ambient env
    if source is None:
        monkeypatch.delenv("MEFOR_FORBIDDEN_TOKENS", raising=False)
        mod.LOCAL_TOKEN_FILE = _ROOT / "does-not-exist-scan-tokens.local.txt"  # type: ignore[attr-defined]
    else:
        monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", str(source))
    mod.reload_tokens()  # type: ignore[attr-defined]
    return mod


def test_committed_files_exist() -> None:
    assert _SCANNER.is_file(), "relocated scanner missing at scripts/security/"
    assert _EXAMPLE.is_file(), "synthetic token template missing"


def test_structural_only_has_no_baked_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load(None, monkeypatch)
    assert mod.TOKENS_PRESENT is False  # type: ignore[attr-defined]
    # No customer/vendor tokens are compiled into the committed source.
    assert mod.FORBIDDEN == []  # type: ignore[attr-defined]
    assert mod.ESTATE_TOKENS == ()  # type: ignore[attr-defined]
    # The site-code detector is OFF with no prefix loaded (would-be code does not match).
    assert mod.SITE_CODE_RE.search("990123") is None  # type: ignore[attr-defined]


def test_structural_only_still_flags_routable_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load(None, monkeypatch)
    assert "routable IP address" in mod.scan_text(f"host {_ROUTABLE_IP}")  # type: ignore[attr-defined]
    # Private / documentation IPs are not flagged.
    for ip in _ALLOWED_IPS:
        assert mod.scan_text(f"host {ip}") == []  # type: ignore[attr-defined]


def test_structural_only_scan_file_flags_routable_ip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    mod = _load(None, monkeypatch)
    f = tmp_path / "cfg.txt"
    f.write_text(f"server = {_ROUTABLE_IP}\nprivate = {_ALLOWED_IPS[0]}\n", encoding="utf-8")
    hits = mod.scan_file(f)  # type: ignore[attr-defined]
    assert any("routable IP address" in h for h in hits)
    # Reasons-only by default: the matched value is NOT echoed.
    assert all(_ROUTABLE_IP not in h for h in hits)
    # ...but --show-context (local only) does include it.
    ctx = mod.scan_file(f, show_context=True)  # type: ignore[attr-defined]
    assert any(_ROUTABLE_IP in h for h in ctx)


def test_committed_files_contain_no_routable_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Scan the committed scanner + its .example with the structural detector: any routable IP baked
    # into them would surface here. (Their only IPs are RFC5737/RFC1918 allow-listed prefixes.)
    mod = _load(None, monkeypatch)
    for path in (_SCANNER, _EXAMPLE):
        assert mod.scan_file(path) == [], f"{path.name} carries structural forbidden content"  # type: ignore[attr-defined]


def test_example_is_synthetic(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load(_EXAMPLE, monkeypatch)
    assert mod.TOKENS_PRESENT is True  # type: ignore[attr-defined]
    # Estate tokens are exactly the synthetic placeholders -- a real token here fails this equality.
    assert set(mod.ESTATE_TOKENS) == {"acme", "exampleco", "examplevendor"}  # type: ignore[attr-defined]
    assert mod.FORBIDDEN, "example [names] section should compile at least one pattern"  # type: ignore[attr-defined]
    # The site prefix is the NON-REAL 99xxxx.
    assert mod.SITE_CODE_RE.search("990123") is not None  # type: ignore[attr-defined]


def test_example_tokens_match_as_specified(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load(_EXAMPLE, monkeypatch)
    # Case-insensitive name.
    assert mod.scan_text("welcome to ACME today")  # type: ignore[attr-defined]
    assert mod.scan_text("acme corp")  # type: ignore[attr-defined]
    # Case-sensitive adopter repo: matches uppercase, not lowercase.
    assert mod.scan_text("repo ACMECORP")  # type: ignore[attr-defined]
    assert mod.scan_text("repo acmecorp") == []  # type: ignore[attr-defined]
    # Estate substring inside a field-like body.
    assert any("estate token" in r for r in mod.scan_text("PID|exampleco|x", include_estate=True))  # type: ignore[attr-defined]
    # Boundary-aware site-code file detector.
    assert mod._SITE_CODE_FILE.search("PT_990123_ADT") is not None  # type: ignore[attr-defined]
    assert mod._SITE_CODE_FILE.search("ab990123cd") is None  # type: ignore[attr-defined]


def test_estate_token_butted_against_word_characters_is_file_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hole that let a real customer org name sit in a tracked test and pass every gate.

    ``[names]`` patterns are word-boundary anchored and ``_`` is a word character, so a token inside
    ``OB_<TOKEN>_ORU`` is invisible to them — and the estate set used to be BODY-only, so nothing else
    looked either. The scanner reported the repo clean on a real leak.
    """
    mod = _load(_EXAMPLE, monkeypatch)
    p = tmp_path / "test_lanes.py"
    p.write_text('lanes = {"OB_ACME_ORU"}\n', encoding="utf-8")
    hits = mod.scan_file(p, "tests/test_lanes.py")  # type: ignore[attr-defined]
    assert hits, "the identifier form must be caught"
    # Reason-only by default: this gate fails into a world-readable Actions log on the public repo.
    assert not any("ACME" in h for h in hits)

    # NB: WHICH detector catches this changed. The token is in BOTH [names] and [estate], so the
    # single-token identifier pass now fires the NAME detector directly and the estate file scan
    # (gated on "nothing else flagged this line") is correctly suppressed. The estate path is covered
    # on its own by test_estate_only_token_still_caught_by_the_file_scan, which builds a source where
    # a token is in [estate] and NOT in [names] -- this fixture contains no such token.


def test_estate_token_inside_a_longer_word_is_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Substring matching's false-positive class — a token that is merely a run of letters inside an
    unrelated identifier (real case: the WebAuthn exception name ``InvalidCBORData``)."""
    mod = _load(_EXAMPLE, monkeypatch)
    p = tmp_path / "webauthn.py"
    p.write_text('raise InvalidACMEData("bad attestation")\n', encoding="utf-8")
    assert mod.scan_file(p, "messagefoundry/webauthn.py") == []  # type: ignore[attr-defined]


def test_body_only_estate_tokens_are_excluded_from_the_file_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``[estate_body_only]`` keeps dictionary-ish tokens out of the FILE scan while leaving them in
    the body scan, where a fail-closed false positive is the safer error."""
    mod = _load(_EXAMPLE, monkeypatch)
    body_only = next(iter(mod._ESTATE_BODY_ONLY))  # type: ignore[attr-defined]
    p = tmp_path / "doc.md"
    p.write_text(f'row = db_lookup("{body_only}", "SELECT 1")\n', encoding="utf-8")
    assert mod.scan_file(p, "docs/doc.md") == []  # type: ignore[attr-defined]
    assert mod.scan_text(f"a {body_only} value", include_estate=True)  # type: ignore[attr-defined]


def test_site_code_pattern_written_out_is_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The PREFIX is the secret, so writing the PATTERN leaks it as surely as writing a code.

    ADR 0030's de-identification pass certified a file clean by grepping one form while three
    occurrences of the other survived — one on the line adjacent to a line it had just fixed.
    """
    mod = _load(_EXAMPLE, monkeypatch)
    for body in (f"a bare `99{chr(92)}d{{4}}` substring", "the `99xxxx` pattern"):
        p = tmp_path / "NEW.md"
        p.write_text(body + "\n", encoding="utf-8")
        hits = mod.scan_file(p, "docs/NEW.md")  # type: ignore[attr-defined]
        assert any("site-code pattern" in h for h in hits), body
    # ...but an incidental digit run that merely starts with the prefix is not a disclosure.
    p = tmp_path / "d.md"
    p.write_text("dob = 19990123\nratio = 75.995512\n", encoding="utf-8")
    assert mod.scan_file(p, "docs/d.md") == []  # type: ignore[attr-defined]


# --------------------------------------------------------------------------------------------------
# The convention is self-colliding for its SECOND audience. `[site_prefix]` guidance is written for
# the person filling in the TOKEN LIST, where naming a prefix shape is necessary. Read as guidance for
# placeholder VALUES it is a trap: a placeholder built from a configured prefix and written into
# TRACKED prose is then scanned by the very gate that list configures. The prefix compiles into two
# detectors, but they catch DIFFERENT constructs -- the concrete code and the pattern written out --
# and no single string is both, so clearing one form does NOT clear the other. That is the ADR 0030
# miss pinned by test_site_code_pattern_written_out_is_flagged above. The tests below pin the guidance
# text and the header's own arithmetic.
# --------------------------------------------------------------------------------------------------


def test_guidance_prose_does_not_self_collide_with_the_synthetic_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The GUIDANCE files must not perform the construct they forbid.

    Two tiers, because the files differ in what they are allowed to contain:

    * CONTRIBUTING.md and the setup script are pure prose. They must be COMPLETELY clean under the
      synthetic set -- not merely free of site codes. Measured while writing this: naming the
      synthetic placeholders outright, to explain why they false-positive, blocks a fork contributor
      on the very file that tells them the gate exists. Describe them, do not spell them.
    * The .example necessarily carries the token list itself, so it matches its own [names] entries by
      construction. Only the site-code classes are assertable there.

    Deliberately not widened to the tree. A DETECTOR test has to contain matching fixtures to be
    evidence at all -- this module does so above, and tests/test_scan_forbidden.py does so throughout
    -- and unrelated tracked files carry incidental delimited digit runs that begin with the synthetic
    prefix. A tree-wide version would be permanently red and therefore worthless as a signal.
    """
    mod = _load(_EXAMPLE, monkeypatch)
    # With no prefix loaded every site-code regex falls back to the always-failing _NEVER sentinel and
    # the emptiness below would be vacuous -- passing while seeing nothing, the exact failure this
    # module exists to prevent. Pin the precondition here rather than lean on a sibling test.
    assert mod.loaded_token_counts()["site_prefixes"] > 0, (  # type: ignore[attr-defined]
        "precondition: the site-code detectors are armed"
    )
    # Pass the REPO-RELATIVE display path: a hit string carries it, and these assertion messages land
    # in a world-readable Actions log. The absolute form would put the checkout's own user-home path
    # there -- a disclosure the scanner has a dedicated detector for.
    for path in (_CONTRIBUTING, _SETUP_SCRIPT):
        hits = mod.scan_file(path, path.relative_to(_ROOT).as_posix())  # type: ignore[attr-defined]
        assert hits == [], f"{path.name} trips the gate it documents: {hits}"
    example_hits = mod.scan_file(_EXAMPLE, _EXAMPLE.relative_to(_ROOT).as_posix())  # type: ignore[attr-defined]
    offending = [h for h in example_hits if "site code" in h or "site-code pattern" in h]
    assert offending == [], f"{_EXAMPLE.name} spells a site code / its pattern: {offending}"


def test_example_header_counts_match_what_it_compiles_to(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The header's stated counts must equal what the file compiles to, with nothing quietly dropped.

    This is the structural guard for the mistake the guidance block is one edit away from: prose
    dropped INSIDE a section body is parsed as token data (``_parse_tokens`` skips only blank and
    ``#``-prefixed lines). Counts alone cover only HALF of that. Prose that COMPILES as a regex
    becomes a detector and breaks the arithmetic; prose that does NOT compile is discarded with a
    stderr warning and leaves the counts identical, so the count assertion would read green over a
    file that had silently lost a line. The warning assertion is the missing half. Between them it
    fails from every side -- an entry added, an entry lost, or a header edited to claim a count the
    sections do not produce.
    """
    claimed = re.search(
        r"names=(\d+), estate=(\d+), site_prefix=(\d+)", _EXAMPLE.read_text("utf-8")
    )
    assert claimed is not None, "the .example header no longer states its own detector counts"
    mod = _load(_EXAMPLE, monkeypatch)
    # Drain first, then re-parse, so the captured stderr is THIS file's parse and nothing else: the
    # first load inside ``_load`` runs against the ambient token source, which differs between a
    # maintainer checkout, a fork and CI, and would make the assertion environment-dependent.
    capsys.readouterr()
    mod.reload_tokens()  # type: ignore[attr-defined]
    err = capsys.readouterr().err
    # Every ``_parse_tokens`` path that DISCARDS an entry says "ignoring"/"IGNORED"; the paths that
    # keep one (a malformed CASE flag, a REASON that echoes its own token) do not. So this fires
    # exactly when the file lost content -- the case the counts are blind to.
    assert "ignor" not in err.lower(), f"the .example lost an entry while parsing: {err}"
    counts = mod.loaded_token_counts()  # type: ignore[attr-defined]
    assert (int(claimed[1]), int(claimed[2]), int(claimed[3])) == (
        counts["names"],
        counts["estate"],
        counts["site_prefixes"],
    ), "the .example header's counts disagree with what it compiles to"


def test_placeholder_guidance_is_mirrored_in_contributing() -> None:
    """The stand-in convention is stated in the .example and mirrored where a reader meets it.

    Honestly, a PRESENCE guard only: it cannot tell whether the texts still SAY the same thing, only
    that no mirror silently vanished. Nothing else in the tree holds these three files together.
    """
    assert _STANDIN in _SETUP_SCRIPT.read_text("utf-8"), (
        f"{_SETUP_SCRIPT.name} no longer names the non-numeric stand-in"
    )
    assert _STANDIN in _EXAMPLE.read_text("utf-8"), (
        f"{_EXAMPLE.name} no longer names the non-numeric stand-in"
    )
    assert _STANDIN in _CONTRIBUTING.read_text("utf-8"), (
        "CONTRIBUTING.md no longer mirrors the non-numeric stand-in"
    )


@pytest.mark.parametrize(
    "mangled",
    [
        pytest.param("[na", id="truncated-paste"),
        pytest.param("# only comments\n# no sections\n", id="comments-only"),
        pytest.param("acme\nexampleco\n", id="section-headers-lost"),
    ],
)
def test_present_but_unusable_token_source_fails_closed(
    mangled: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TOKENS_PRESENT must mean USABLE, not merely non-None.

    Derived from ``text is not None`` alone, a mangled secret yielded ZERO detectors while still
    reporting "tokens present" — so MEFOR_REQUIRE_TOKENS=1 passed and the gate ran structural-only
    behind a green required check. Runbook step C.2 has the owner paste a whole sectioned file into a
    GitHub secret box, which is precisely the mangling case.
    """
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", mangled)
    spec = importlib.util.spec_from_file_location(f"sf_{next(_counter)}", _SCANNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.reload_tokens()  # type: ignore[attr-defined]
    assert mod.TOKENS_PRESENT is False  # type: ignore[attr-defined]
    assert sum(mod.loaded_token_counts().values()) == 0  # type: ignore[attr-defined]


def test_inline_env_token_content(monkeypatch: pytest.MonkeyPatch) -> None:
    # MEFOR_FORBIDDEN_TOKENS may carry the content inline (CI secret form), not only a path.
    inline = "[names]\n\\bwidgetco\\b | vendor (WIDGET) | i\n[site_prefix]\n88\n"
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", inline)
    spec = importlib.util.spec_from_file_location(f"sf_{next(_counter)}", _SCANNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.reload_tokens()  # type: ignore[attr-defined]
    assert mod.TOKENS_PRESENT is True  # type: ignore[attr-defined]
    assert mod.scan_text("a widgetco b")  # type: ignore[attr-defined]
    assert mod.SITE_CODE_RE.search("880001") is not None  # type: ignore[attr-defined]


def test_require_tokens_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # With MEFOR_REQUIRE_TOKENS=1 and no source, the CLI refuses (exit 2) rather than under-scanning.
    spec = importlib.util.spec_from_file_location(f"sf_{next(_counter)}", _SCANNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.LOCAL_TOKEN_FILE = tmp_path / "absent.txt"  # type: ignore[attr-defined]
    monkeypatch.delenv("MEFOR_FORBIDDEN_TOKENS", raising=False)
    monkeypatch.setenv("MEFOR_REQUIRE_TOKENS", "1")
    assert mod.main([str(tmp_path)]) == 2  # type: ignore[attr-defined]


# --------------------------------------------------------------------------------------------------
# Partial-load floor. TOKENS_PRESENT is an OR across sections, so a source that lost SOME of its
# tokens satisfied "fail-closed" while loading as few as 1 of 21 detectors -- printing no
# structural-only warning and passing with a green tick. Every token below is SYNTHETIC.
# --------------------------------------------------------------------------------------------------

_SYNTH_NAMES = (
    "[names]\n"
    + r"ACME\s+Health | customer organisation name | i"
    + "\nEXAMPLECORP | partner name | i\n"
)
_SYNTH_ESTATE = "[estate]\nacmelab\nexamplenet\n"
_SYNTH_PREFIX = "[site_prefix]\n99\n"
# names=2 + estate=2 + site_prefixes=1 == 5 floor detectors
_SYNTH_FULL = f"{_SYNTH_NAMES}\n{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
_SYNTH_TOTAL = 5


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "tokens.txt"
    p.write_text(content, encoding="utf-8")
    return p


def _tree(tmp_path: Path) -> Path:
    """A scannable directory holding one innocuous file.

    It must NOT be empty: the scanner separately refuses a ``--path`` that examined zero files, which
    would make every "this passes" assertion below succeed for entirely the wrong reason -- the same
    can't-fail trap the floor itself exists to close.
    """
    d = tmp_path / "tree"
    d.mkdir(exist_ok=True)
    (d / "note.md").write_text("nothing to see here\n", encoding="utf-8")
    return d


@pytest.mark.parametrize(
    ("label", "content"),
    [
        # The likeliest paste error is losing the TAIL -- and [site_prefix] is the LAST section, so
        # dropping one line silently disables every site-code detector.
        ("lost the trailing site_prefix", f"{_SYNTH_NAMES}\n{_SYNTH_ESTATE}"),
        ("only site_prefix survived", _SYNTH_PREFIX),
        ("only names survived", _SYNTH_NAMES),
        ("only estate survived", _SYNTH_ESTATE),
        # A typo'd header drops that section into the section=None void with no diagnostic at all.
        (
            "names header typo'd",
            f"[naems]\nACME | x | i\n\n{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}",
        ),
    ],
)
def test_partially_loaded_source_fails_closed(
    label: str, content: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A source that loads only SOME sections must refuse, not pass.

    Before the floor these all exited 0: TOKENS_PRESENT was satisfied by any single surviving
    section, so the run reported 'fail-closed' while most detectors were off.
    """
    scan_dir = _tree(tmp_path)
    mod = _load(_write(tmp_path, content), monkeypatch)
    assert mod.TOKENS_PRESENT is True, f"{label}: precondition -- a source WAS found"  # type: ignore[attr-defined]
    monkeypatch.setenv("MEFOR_REQUIRE_TOKENS", "1")
    assert mod.main(["--path", str(scan_dir)]) == 2, f"{label}: partial load must fail closed"  # type: ignore[attr-defined]


def test_fully_loaded_source_passes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Control for the parametrised case above: a COMPLETE source must still pass.

    Without this, a floor that rejected everything would look identical to a working one.
    """
    scan_dir = _tree(tmp_path)
    mod = _load(_write(tmp_path, _SYNTH_FULL), monkeypatch)
    monkeypatch.setenv("MEFOR_REQUIRE_TOKENS", "1")
    # Clear any ambient floor: inheriting one from the developer's shell would turn this control RED
    # for a reason unrelated to what it asserts.
    monkeypatch.delenv("MEFOR_MIN_DETECTORS", raising=False)
    assert mod.main(["--path", str(scan_dir)]) == 0  # type: ignore[attr-defined]


def test_min_detectors_catches_loss_within_a_section(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The section check cannot see 2 names becoming 1; the numeric floor can."""
    scan_dir = _tree(tmp_path)
    monkeypatch.setenv("MEFOR_REQUIRE_TOKENS", "1")

    mod = _load(_write(tmp_path, _SYNTH_FULL), monkeypatch)
    monkeypatch.setenv("MEFOR_MIN_DETECTORS", str(_SYNTH_TOTAL))
    assert mod.main(["--path", str(scan_dir)]) == 0, "the floor must admit an intact source"  # type: ignore[attr-defined]

    # One name lost: every section is still non-empty, so ONLY the total can catch it.
    thinned = (
        "[names]\n"
        + r"ACME\s+Health | customer organisation name | i"
        + f"\n\n{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
    )
    mod2 = _load(_write(tmp_path, thinned), monkeypatch)
    assert all(mod2.loaded_token_counts()[s] for s in ("names", "estate", "site_prefixes"))  # type: ignore[attr-defined]
    assert mod2.main(["--path", str(scan_dir)]) == 2, "below-floor total must fail closed"  # type: ignore[attr-defined]


def test_floor_permits_growth(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """It is a FLOOR, not an equality -- adding a token must not break CI."""
    scan_dir = _tree(tmp_path)
    grown = f"{_SYNTH_NAMES}THIRDCO | another partner | i\n\n{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
    mod = _load(_write(tmp_path, grown), monkeypatch)
    monkeypatch.setenv("MEFOR_REQUIRE_TOKENS", "1")
    monkeypatch.setenv("MEFOR_MIN_DETECTORS", str(_SYNTH_TOTAL))
    counts = mod.loaded_token_counts()  # type: ignore[attr-defined]
    total = counts["names"] + counts["estate"] + counts["site_prefixes"]
    # Without this precondition the test cannot tell a FLOOR from an EQUALITY: if the "grown" source
    # happened to total exactly the configured number it would pass under either semantics.
    assert total > _SYNTH_TOTAL, "precondition: the source really did grow past the floor"
    assert mod.main(["--path", str(scan_dir)]) == 0  # type: ignore[attr-defined]
    # ...and the floor still bites once raised above the grown total, so "passes" is not unconditional.
    monkeypatch.setenv("MEFOR_MIN_DETECTORS", str(total + 1))
    assert mod.main(["--path", str(scan_dir)]) == 2  # type: ignore[attr-defined]


def test_site_prefix_count_is_a_count_not_a_presence_bit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """loaded_token_counts reported 0-or-1, so losing one of two prefixes was invisible.

    Any floor built on that number would have inherited the blindness.
    """
    two = f"{_SYNTH_NAMES}\n{_SYNTH_ESTATE}\n[site_prefix]\n99\n88\n"
    mod = _load(_write(tmp_path, two), monkeypatch)
    assert mod.loaded_token_counts()["site_prefixes"] == 2  # type: ignore[attr-defined]


def test_require_tokens_cli_flag_fails_closed_without_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """pre-commit can pass ARGS but cannot set env for a hook, so the flag is the local gate."""
    scan_dir = _tree(tmp_path)
    monkeypatch.delenv("MEFOR_REQUIRE_TOKENS", raising=False)
    monkeypatch.delenv("MEFOR_MIN_DETECTORS", raising=False)

    mod = _load(_write(tmp_path, _SYNTH_PREFIX), monkeypatch)
    assert mod.main(["--require-tokens", "--path", str(scan_dir)]) == 2  # type: ignore[attr-defined]

    mod2 = _load(_write(tmp_path, _SYNTH_FULL), monkeypatch)
    assert mod2.main(["--require-tokens", "--path", str(scan_dir)]) == 0  # type: ignore[attr-defined]
    assert mod2.main([f"--require-tokens={_SYNTH_TOTAL + 1}", "--path", str(scan_dir)]) == 2  # type: ignore[attr-defined]


def test_min_detectors_implies_require(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A floor set WITHOUT the require flag must not be silently inert."""
    scan_dir = _tree(tmp_path)
    monkeypatch.delenv("MEFOR_REQUIRE_TOKENS", raising=False)
    mod = _load(_write(tmp_path, _SYNTH_PREFIX), monkeypatch)
    monkeypatch.setenv("MEFOR_MIN_DETECTORS", str(_SYNTH_TOTAL))
    assert mod.main(["--path", str(scan_dir)]) == 2  # type: ignore[attr-defined]
    # Exit 2 arrives from several branches (usage error, zero files examined, absent source), so pin
    # the REASON as well -- otherwise this passes for the wrong cause and stops being evidence.
    why = mod.token_floor_failure(_SYNTH_TOTAL)  # type: ignore[attr-defined]
    assert why is not None and "EMPTY" in why, why


# --------------------------------------------------------------------------------------------------
# Corruption-in-place. The count floor above defeats LINE LOSS, but it counts entries that PARSE, not
# detectors that can FIRE -- so a token corrupted in place kept the counts identical while detection
# silently flipped off. Measured before the fix: one zero-width space inside a token left TOTAL
# unchanged and stopped the token matching. Zero-width chars are not str.isspace() and survive
# str.strip() (unlike NBSP, which strips to empty), which is exactly what a paste through a rendering
# surface produces at the runbook's C.2 step.
# --------------------------------------------------------------------------------------------------

_ZWSP = "\u200b"


def test_zero_width_char_inside_a_token_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The entry must be DROPPED, so the floor can see the loss it previously could not."""
    honest = _load(_write(tmp_path, _SYNTH_FULL), monkeypatch)
    baseline = honest.loaded_token_counts()["estate"]  # type: ignore[attr-defined]

    corrupt = _SYNTH_FULL.replace("acmelab", f"acme{_ZWSP}lab")
    mod = _load(_write(tmp_path, corrupt), monkeypatch)
    assert mod.loaded_token_counts()["estate"] == baseline - 1  # type: ignore[attr-defined]
    # ...and with the floor set to the honest total the run now refuses.
    assert mod.token_floor_failure(_SYNTH_TOTAL) is not None  # type: ignore[attr-defined]


def test_clean_token_containing_a_space_is_still_accepted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Control: the invisible-char check must not reject ordinary printable content.

    A plain space IS printable; without this, a rule that rejected everything would look identical
    to a working one.
    """
    src = f"{_SYNTH_NAMES}\n[estate]\nacme lab\nexamplenet\n\n{_SYNTH_PREFIX}"
    mod = _load(_write(tmp_path, src), monkeypatch)
    assert mod.loaded_token_counts()["estate"] == 2  # type: ignore[attr-defined]
    assert mod.token_floor_failure(_SYNTH_TOTAL) is None  # type: ignore[attr-defined]


def test_never_matching_pattern_cannot_pad_the_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``(?!)`` is the module's own detector-off sentinel; accepted as a token it would count but
    never fire, letting filler reach the floor while real detection stayed degraded."""
    thinned_padded = (
        "[names]\n"
        + r"ACME\s+Health | customer organisation name | i"
        + "\n(?!) | pad | i\n(?!) | pad | i\n\n"
        + f"{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
    )
    mod = _load(_write(tmp_path, thinned_padded), monkeypatch)
    assert mod.loaded_token_counts()["names"] == 1, "padding must not inflate the count"  # type: ignore[attr-defined]
    assert mod.token_floor_failure(_SYNTH_TOTAL) is not None  # type: ignore[attr-defined]


def test_non_ascii_digit_site_prefix_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """str.isdigit() is True for non-ASCII digits, which would compile in and never match a site code."""
    src = f"{_SYNTH_NAMES}\n{_SYNTH_ESTATE}\n[site_prefix]\n\u0669\u0669\n"
    mod = _load(_write(tmp_path, src), monkeypatch)
    assert mod.loaded_token_counts()["site_prefixes"] == 0  # type: ignore[attr-defined]
    assert mod.token_floor_failure() is not None, "an empty floor section must refuse"  # type: ignore[attr-defined]


def test_duplicate_entries_do_not_inflate_the_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A double-pasted section would otherwise read as twice the detectors and mask real loss."""
    doubled = f"{_SYNTH_NAMES}\n{_SYNTH_ESTATE}\n{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
    mod = _load(_write(tmp_path, doubled), monkeypatch)
    assert mod.loaded_token_counts()["estate"] == 2, "duplicates must not count twice"  # type: ignore[attr-defined]


def test_unknown_flag_is_refused_not_treated_as_a_filename(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An unrecognised flag used to land at rest[0], defeating the --path test and scanning nothing."""
    scan_dir = _tree(tmp_path)
    mod = _load(_write(tmp_path, _SYNTH_FULL), monkeypatch)
    monkeypatch.setenv("MEFOR_REQUIRE_TOKENS", "1")
    assert mod.main(["--reqire-tokens", "--path", str(scan_dir)]) == 2  # type: ignore[attr-defined]


def test_unrecognised_require_value_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An exact '=="1"' compare meant MEFOR_REQUIRE_TOKENS=true silently disabled the gate."""
    scan_dir = _tree(tmp_path)
    mod = _load(_write(tmp_path, _SYNTH_PREFIX), monkeypatch)
    monkeypatch.setenv("MEFOR_REQUIRE_TOKENS", "yes")
    assert mod.main(["--path", str(scan_dir)]) == 2, "'yes' must engage the gate, not bypass it"  # type: ignore[attr-defined]
    monkeypatch.setenv("MEFOR_REQUIRE_TOKENS", "maybe")
    assert mod.main(["--path", str(scan_dir)]) == 2, "an unrecognised value must refuse"  # type: ignore[attr-defined]


def test_parse_warnings_never_echo_token_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """These warnings land in a world-readable Actions log on the PUBLIC repo."""
    secret = "SUPERSECRETCUSTOMERNAME"
    src = f"[names]\n{secret}( | bad regex | i\n\n{_SYNTH_ESTATE}\n[site_prefix]\n{secret}\n"
    _load(_write(tmp_path, src), monkeypatch)
    err = capsys.readouterr().err
    assert "ignoring an uncompilable" in err, "precondition: the warning fired"
    assert secret not in err, "the warning must NOT echo the token"


# --------------------------------------------------------------------------------------------------
# Internal-environment disclosure detectors. These are SHAPE-based, not token-based, so no token list
# can catch them and they must stay live even in structural-only / fork runs. Both were present in the
# retired scanner and absent from the relocated one -- a silent loss of coverage at cutover (10 real
# hit locations across 5 files on the tree at the time).
# --------------------------------------------------------------------------------------------------

_BS = chr(92)  # a literal backslash, kept out of string literals to avoid escape confusion


def test_worktree_slug_is_flagged_without_any_token_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A branch/worktree slug names the TASK, which can name a prospect, engagement or competitor.

    Unbounded by nature, so there is no list to add it to -- shape is the only control that scales,
    and it must work with the token tables empty.
    """
    mod = _load(None, monkeypatch)
    assert mod.TOKENS_PRESENT is False, "precondition: structural-only"  # type: ignore[attr-defined]
    f = tmp_path / "notes.md"
    # Split so no single SOURCE line here is itself a full match: this file is scanned by the gate it
    # tests, and a literal probe makes the suite trip its own detector.
    f.write_text("see .claude/work" + "trees/some-task-name-a1b2c3 for details\n", encoding="utf-8")
    hits = mod.scan_file(f, "docs/notes.md")  # type: ignore[attr-defined]
    assert any("worktree/branch slug" in h for h in hits)
    # Reason-only: the slug IS the disclosure, so it must not be echoed into a public CI log.
    assert not any("some-task-name" in h for h in hits)


def test_absolute_home_path_is_flagged_but_placeholders_are_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An absolute home path carries the OS account name; documented stand-ins must not fire."""
    mod = _load(None, monkeypatch)
    real = tmp_path / "real.md"
    # The POSIX arm is split for the same reason as the slug probe above -- the Windows arm already
    # avoids a literal via _BS.
    real.write_text(
        f"C:{_BS}Users{_BS}Alice{_BS}Code{_BS}thing\n" + "/ho" + "me/bob/src\n", encoding="utf-8"
    )
    hits = mod.scan_file(real, "docs/real.md")  # type: ignore[attr-defined]
    assert sum("absolute user-home path" in h for h in hits) == 2
    assert not any("Alice" in h or "bob" in h for h in hits), "must not echo the account name"

    ok = tmp_path / "ok.md"
    ok.write_text(
        f"C:{_BS}Users{_BS}<you>{_BS}Code\n/home/runner/work/repo\n/Users/user/project\n"
        f"/home/me/notes\nC:{_BS}Users{_BS}Public{_BS}Shared\n",
        encoding="utf-8",
    )
    assert not any(
        "absolute user-home path" in h
        for h in mod.scan_file(ok, "docs/ok.md")  # type: ignore[attr-defined]
    ), "placeholders / CI / shared accounts must not fire"


def test_home_path_casing_variants_all_fire_but_the_posix_users_route_does_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Windows paths are case-INSENSITIVE: all four spellings name the SAME account.

    The ``/users/`` non-match at the end is asserted deliberately, not incidentally -- it pins the
    asymmetry that keeps the case-fold scoped to the drive-letter arm, so the next reader cannot
    quietly widen it to a whole-pattern ``re.I``. The scanner's ``_HOME_PATH`` comment says why.
    """
    mod = _load(None, monkeypatch)
    variants = tmp_path / "variants.md"
    # Assembled like the fixtures above so no SOURCE line here is itself a match -- this file is
    # scanned by the gate it tests.
    variants.write_text(
        f"c:{_BS}users{_BS}Carol{_BS}Code\n"
        f"C:{_BS}USERS{_BS}Dave{_BS}Code\n" + "c:/" + "users/Erin/Code\n",
        encoding="utf-8",
    )
    hits = mod.scan_file(variants, "docs/variants.md")  # type: ignore[attr-defined]
    assert sum("absolute user-home path" in h for h in hits) == 3
    assert not any(n in h for h in hits for n in ("Carol", "Dave", "Erin"))

    route = tmp_path / "route.md"
    route.write_text("/users/list\nGET /ui/users/{id}/roles\n", encoding="utf-8")
    assert not any(
        "absolute user-home path" in h
        for h in mod.scan_file(route, "docs/route.md")  # type: ignore[attr-defined]
    ), "a lower-cased POSIX /users/ segment is a REST route, not a home path"


def test_worktree_slug_casing_variant_is_flagged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An upper-cased slug is reachable, so it must not slip the gate.

    ``scripts/worktree/new.ps1`` hands ``-Branch`` to ``git worktree add -b`` after validating it
    with ``git check-ref-format`` (which permits mixed case), and ``-Name`` reaches the worktree
    DIRECTORY verbatim. Nothing lowercases anywhere on either path.
    """
    mod = _load(None, monkeypatch)
    f = tmp_path / "notes.md"
    # Split for the same reason as the fixtures above.
    f.write_text("see .claude/work" + "trees/Some-Task-Name-a1b2c3 for details\n", encoding="utf-8")
    hits = mod.scan_file(f, "docs/notes.md")  # type: ignore[attr-defined]
    assert any("worktree/branch slug" in h for h in hits)
    assert not any("Some-Task-Name" in h for h in hits)


# --------------------------------------------------------------------------------------------------
# BACKLOG #1083: the slug detector required a ``claude/`` / ``worktrees/`` PATH PREFIX, so the same
# slug written bare in prose matched the shape and not the pattern. Assembled from parts, like the
# fixtures above, so no SOURCE line here is itself a match -- this file is scanned by the gate it
# tests. Every hex below is invented and names no real session.
# --------------------------------------------------------------------------------------------------

#: A bare slug whose hex is NOT one of the documentation stand-ins, so the bare arm may fire on it.
_BARE_SLUG = "quiet-" + "harbour-" + "7c4e91"
#: Same shape, but the hand-written stand-in hex this repo uses when it writes ABOUT slugs.
_PLACEHOLDER_SLUG = "some-" + "task-" + "a1b2c3"


@pytest.mark.parametrize(
    ("body", "why"),
    [
        (f"raised by session `{_BARE_SLUG}` while sweeping the citations", "backticked + lead-in"),
        (f"see `{_BARE_SLUG}` for the banked patch", "backticked, no lead-in word"),
        (f"the roster label is worktree: {_BARE_SLUG} and not an address", "lead-in, no backticks"),
        (f"handed back to lane {_BARE_SLUG}", "a different lead-in word"),
        (f"branch {_BARE_SLUG.upper()} was never pushed", "upper-cased, as the prefixed arm folds"),
    ],
)
def test_a_bare_slug_with_no_path_prefix_is_flagged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: str, why: str
) -> None:
    """The negative control this defect WAS the absence of.

    The existing fixtures all carry a ``worktrees/`` prefix, so the suite could not tell "no slug
    present" from "slug present in a shape I do not match" -- the same blindness as the guard. A
    bare slug reached ``origin`` for two days under a green gate.
    """
    mod = _load(None, monkeypatch)
    assert mod.TOKENS_PRESENT is False, "precondition: structural-only"  # type: ignore[attr-defined]
    f = tmp_path / "notes.md"
    f.write_text(body + "\n", encoding="utf-8")
    hits = mod.scan_file(f, "docs/notes.md")  # type: ignore[attr-defined]
    assert any("worktree/branch slug" in h for h in hits), why
    # Reason-only: the slug IS the disclosure, so it must not be echoed into a public CI log.
    assert not any("harbour" in h.lower() for h in hits)


@pytest.mark.parametrize(
    "body",
    [
        # A bare slug shape with NO context at all. Deliberately NOT flagged: measured over the
        # tracked tree, an ungated bare shape matched 116 lines, of which the overwhelming majority
        # were ordinary prose. A guard that fires on healthy content gets allowlisted into
        # uselessness, which is worse than the leak.
        f"the value {_BARE_SLUG} is returned verbatim",
        # The English words that are also six hex digits. These are why the shape alone cannot work.
        "the FHIR-facade and the server-facade share a per-facade cache",
        # A short hex written in ordinary prose, which this repo does constantly.
        "re-measured against 780ee1d9 with a self-test",
        # A dotted namespace that merely ends in six hex-ish characters.
        "xmlns:wsu=oasis-200401-wss-wssecurity-utility",
    ],
)
def test_ordinary_prose_carrying_the_bare_shape_does_not_fire(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: str
) -> None:
    """The false-positive control, and it is the half that keeps the guard usable.

    #1083 asked for the widening to be assessed for false-positive cost BEFORE taking it, and the
    answer was to narrow by CONTEXT (a backticked token, or a session/worktree/branch lead-in)
    rather than by widening the shape.
    """
    mod = _load(None, monkeypatch)
    f = tmp_path / "prose.md"
    f.write_text(body + "\n", encoding="utf-8")
    hits = mod.scan_file(f, "docs/prose.md")  # type: ignore[attr-defined]
    assert not any("worktree/branch slug" in h for h in hits), body


def test_a_stand_in_hex_is_exempt_bare_but_a_PREFIXED_stand_in_still_fires(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pinned deliberately, not incidentally -- it is an asymmetry a later reader could 'tidy' away.

    Prose ABOUT this detector uses hand-written stand-in hex (``a1b2c3``), and a guard that fires on
    its own documentation is exactly the pressure that gets a guard allowlisted off. The bare arm
    therefore exempts that closed set. The PREFIXED arm must NOT: the ``worktrees/`` prefix is its
    own evidence, and lifting the exemption there would silently retire the two casing fixtures
    above -- both of which use a stand-in hex.
    """
    mod = _load(None, monkeypatch)
    bare = tmp_path / "bare.md"
    bare.write_text(f"raised by session `{_PLACEHOLDER_SLUG}` in the write-up\n", encoding="utf-8")
    assert not any(
        "worktree/branch slug" in h
        for h in mod.scan_file(bare, "docs/bare.md")  # type: ignore[attr-defined]
    ), "a stand-in hex written bare is documentation, not a disclosure"

    prefixed = tmp_path / "prefixed.md"
    prefixed.write_text("see .claude/work" + f"trees/{_PLACEHOLDER_SLUG} now\n", encoding="utf-8")
    assert any(
        "worktree/branch slug" in h
        for h in mod.scan_file(prefixed, "docs/prefixed.md")  # type: ignore[attr-defined]
    ), "the prefix is its own evidence -- the stand-in exemption must not reach this arm"


@pytest.mark.parametrize(
    ("body", "fires", "why"),
    [
        # A LONGER hex run is a blob id, not a slug suffix. Without the trailing guard the pattern
        # would take its first six characters and call it a slug.
        ("reviewed on branch foo-bar-1234567890ab today", False, "12-hex tail is a blob id"),
        ("reviewed on branch foo-bar-7c4e91a today", False, "7-hex tail is not a slug suffix"),
        # There is deliberately NO leading guard. A symmetric one suppressed exactly this line while
        # changing the tracked-corpus hit set by nothing, so it was measured out rather than kept.
        # Interpolated, not written out: spelled literally this line trips the gate that scans it --
        # which it duly did on the first run, and is the positive control for the case.
        (f"handed to session -{_BARE_SLUG} yesterday", True, "hyphen separator, still a slug"),
    ],
)
def test_the_bare_tail_is_bounded_but_the_head_is_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: str, fires: bool, why: str
) -> None:
    """The two guards are asymmetric on purpose; this pins which one exists and which does not."""
    mod = _load(None, monkeypatch)
    f = tmp_path / "probe.md"
    f.write_text(body + "\n", encoding="utf-8")
    hits = mod.scan_file(f, "docs/probe.md")  # type: ignore[attr-defined]
    assert any("worktree/branch slug" in h for h in hits) is fires, why


def test_a_ONE_WORD_head_fires_only_with_a_path_prefix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The second deliberate asymmetry, and the one a later reader is most likely to "tidy" away.

    Arm 1 accepts a one-word head; the bare arm requires two. A one-word head plus a six-letter tail
    is just a hyphenated English word -- ``per-facade``, ``FHIR-facade`` -- and backticked prose is
    full of them. The tracked corpus reported ZERO cost for allowing one word, which was luck rather
    than evidence: no such token happened to be backticked anywhere in the tree until the fix's own
    comment block wrote three, and they tripped the detector they described. The accepted price is
    pinned here: a genuine one-word bare slug is MISSED.
    """
    mod = _load(None, monkeypatch)
    one_word = "harbour-" + "7c4e91"

    bare = tmp_path / "bare.md"
    bare.write_text(f"raised by session `{one_word}` today\n", encoding="utf-8")
    assert not any(
        "worktree/branch slug" in h
        for h in mod.scan_file(bare, "docs/bare.md")  # type: ignore[attr-defined]
    ), "accepted gap: one word plus a six-hex tail is indistinguishable from a hyphenated word"

    prefixed = tmp_path / "prefixed.md"
    prefixed.write_text("see .claude/work" + f"trees/{one_word} now\n", encoding="utf-8")
    assert any(
        "worktree/branch slug" in h
        for h in mod.scan_file(prefixed, "docs/prefixed.md")  # type: ignore[attr-defined]
    ), "arm 1 has always accepted a one-word head and must keep doing so"


def test_a_line_carrying_both_forms_is_reported_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``worktrees/`` is itself a lead-in word, so a prefixed path satisfies BOTH arms.

    Double-reporting one line adds noise rather than information -- the same reasoning the estate
    pass already applies a few lines below the call site.
    """
    mod = _load(None, monkeypatch)
    f = tmp_path / "both.md"
    f.write_text("see .claude/work" + f"trees/{_BARE_SLUG} for details\n", encoding="utf-8")
    hits = mod.scan_file(f, "docs/both.md")  # type: ignore[attr-defined]
    assert sum("worktree/branch slug" in h for h in hits) == 1


# --------------------------------------------------------------------------------------------------
# Round-3 hardening: parser diagnostics, allowlist breadth, and per-section floors.
# --------------------------------------------------------------------------------------------------


def test_unknown_section_header_warns_instead_of_silently_dropping(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A typo'd header dropped a whole section with NO diagnostic at all."""
    src = f"[naems]\nwidgetco | n | i\n\n{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
    mod = _load(_write(tmp_path, src), monkeypatch)
    assert mod.loaded_token_counts()["names"] == 0  # type: ignore[attr-defined]
    assert "unknown section header" in capsys.readouterr().err


def test_bom_before_first_header_no_longer_voids_the_section(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A UTF-8 BOM defeated the startswith('[') test, silently voiding that section."""
    mod = _load(_write(tmp_path, chr(0xFEFF) + _SYNTH_FULL), monkeypatch)
    assert mod.loaded_token_counts()["names"] == 2, "BOM must be stripped, not swallow the section"  # type: ignore[attr-defined]


def test_spaced_alternation_is_refused_not_silently_truncated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The delimiter is a space-pipe-space, so `a | b` inside a pattern truncated it to `a`.

    The truncated pattern still compiles, so the re.error handler never fired and the count was
    unchanged -- a silent narrowing. Ambiguity is now refused.
    """
    src = f"[names]\nfoo | bar | baz | i\n\n{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
    mod = _load(_write(tmp_path, src), monkeypatch)
    assert mod.loaded_token_counts()["names"] == 0  # type: ignore[attr-defined]
    err = capsys.readouterr().err
    assert "expected at most 3" in err
    assert "foo" not in err and "bar" not in err, "must not echo the entry"


def test_overbroad_allowlist_entry_is_rejected(tmp_path: Path) -> None:
    """One degenerate allowlist line vetoes every line BEFORE any detector runs, disabling the whole
    gate -- while the loaded-counts diagnostic still reports full tables, so the log looks healthy."""
    import importlib.util
    import shutil

    src = _ROOT / "scripts" / "security"
    dst = tmp_path / "security"
    shutil.copytree(src, dst)
    for degenerate in (".", ".*", "^", "[0-9]*"):
        (dst / "scan-allowlist.txt").write_text(degenerate + "\n", encoding="utf-8")
        spec = importlib.util.spec_from_file_location(
            f"al_{next(_counter)}", dst / "scan_forbidden.py"
        )
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.ALLOWLIST == [], f"{degenerate!r} must be rejected"  # type: ignore[attr-defined]


def test_shipped_allowlist_survives_its_own_validator() -> None:
    """Control: the committed entries must still LOAD.

    Without this, a validator that rejected everything would look identical to a working one.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(f"al_{next(_counter)}", _SCANNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    committed = [
        ln.strip()
        for ln in (_ROOT / "scripts" / "security" / "scan-allowlist.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert len(mod.ALLOWLIST) == len(committed)  # type: ignore[attr-defined]


def test_per_section_floor_catches_what_a_total_cannot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A bare total is a SUM: growth in one section masks collapse in another."""
    masked = (
        "[names]\nwidgetco | n | i\n\n[estate]\nacmelab\nzorpnet\nthirdnet\n\n[site_prefix]\n99\n"
    )
    mod = _load(_write(tmp_path, masked), monkeypatch)
    c = mod.loaded_token_counts()  # type: ignore[attr-defined]
    total = c["names"] + c["estate"] + c["site_prefixes"]
    assert total == 5, "precondition: the total is unchanged"
    assert mod.token_floor_failure(5) is None, "a total floor cannot see this"  # type: ignore[attr-defined]
    assert mod.token_floor_failure({"names": 2, "estate": 2, "site_prefixes": 1}) is not None  # type: ignore[attr-defined]


def test_min_spec_parsing_rejects_nonsense(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    mod = _load(_write(tmp_path, _SYNTH_FULL), monkeypatch)
    assert mod.parse_min_spec("21") == 21  # type: ignore[attr-defined]
    assert mod.parse_min_spec("names=7,estate=13") == {"names": 7, "estate": 13}  # type: ignore[attr-defined]
    for bad in ("names", "bogus=3", "names=x", ""):
        with pytest.raises(ValueError):
            mod.parse_min_spec(bad)  # type: ignore[attr-defined]


def test_bad_case_field_keeps_the_detector_and_widens_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An invalid CASE flag must NOT drop the entry.

    Dropping loses a detector, and under-detection is the dangerous direction. Case-insensitive is
    strictly broader than case-sensitive, so falling back can only over-match -- never under-match.
    """
    src = f"[names]\nWIDGETCO | n | X\n\n{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
    mod = _load(_write(tmp_path, src), monkeypatch)
    assert mod.loaded_token_counts()["names"] == 1, "the detector must survive a bad CASE flag"  # type: ignore[attr-defined]
    err = capsys.readouterr().err
    assert "defaulting to case-INSENSITIVE" in err
    assert "WIDGETCO" not in err, "must not echo the entry"
    # And it really is case-insensitive now.
    assert mod.scan_text("we use widgetco here")  # type: ignore[attr-defined]


# --------------------------------------------------------------------------------------------------
# Identifier pass. `_` is a WORD character, so a \b-anchored name pattern cannot see its token inside
# `OB_TOKEN_ORU`. A second pass over the line with `_` neutralised closes that for every name pattern
# rather than only for tokens someone remembered to duplicate into [estate].
# --------------------------------------------------------------------------------------------------

_B = chr(92) + "b"  # a literal \b, built so no shell/heredoc can collapse it to a backspace


def test_single_token_pattern_sees_the_identifier_form(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The G19 shape: a \b-anchored pattern whose token has NO [estate] counterpart."""
    src = (
        "[names]\n" + _B + "widgetco" + _B + " | partner name | i\n\n"
        "[estate]\nsomethingelse\n\n[site_prefix]\n99\n"
    )
    mod = _load(_write(tmp_path, src), monkeypatch)
    assert mod.loaded_token_counts()["names"] == 1, "precondition: the pattern compiled"  # type: ignore[attr-defined]

    f = tmp_path / "feed.py"
    for content, expected in (
        ("we work with widgetco daily\n", True),
        ('lanes = {"OB_WIDGETCO_ORU"}\n', True),
        ("conn = ib_widgetco_adt\n", True),
        ("widgetcofactory is a different word\n", False),
        ("nothing to see here\n", False),
    ):
        f.write_text(content, encoding="utf-8")
        hits = mod.scan_file(f, "tests/feed.py")  # type: ignore[attr-defined]
        assert bool(hits) is expected, content
        assert not any("idgetco" in h for h in hits), "reason-only: must not echo the token"


def test_multi_word_pattern_does_not_match_snake_case(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The false positive that made the first version of this unusable.

    Neutralising `_` for a PHRASE pattern makes it match ordinary snake_case. Measured on the real
    tree, a two-word pattern hit 9 occurrences of a generic Python identifier across two files --
    every one a false positive, and enough to block the cutover PR on its own required gate. Only
    single-token patterns get the second pass.
    """
    src = (
        "[names]\n" + _B + "action" + chr(92) + "s+list" + _B + " | source-system artifact | i\n\n"
        f"{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
    )
    mod = _load(_write(tmp_path, src), monkeypatch)
    assert mod.loaded_token_counts()["names"] == 1  # type: ignore[attr-defined]

    f = tmp_path / "mod.py"
    f.write_text("for i, action_list in enumerate(lists):\n", encoding="utf-8")
    assert mod.scan_file(f, "messagefoundry/mod.py") == [], (  # type: ignore[attr-defined]
        "an ordinary snake_case identifier must NOT trip a multi-word pattern"
    )
    # ...but the real phrase in prose still does. Split for the same reason as the probes above: the
    # phrase is itself a live detector, so a literal here would trip the gate on this very file.
    f.write_text("exported from the " + "action" + " list\n", encoding="utf-8")
    assert mod.scan_file(f, "docs/x.md")  # type: ignore[attr-defined]


def test_reason_that_names_its_own_token_is_neutralised(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A REASON is printed verbatim on every hit, into a world-readable Actions log.

    A reason naming its own token therefore publishes the token on the first match -- the same
    defect as echoing it in a parse warning, but on the success path. The DETECTOR must survive:
    dropping the entry would trade a disclosure for under-detection, which is worse.
    """
    src = f"[names]\nwidgetco | the widgetco partner | i\n\n{_SYNTH_ESTATE}\n{_SYNTH_PREFIX}"
    mod = _load(_write(tmp_path, src), monkeypatch)
    assert mod.loaded_token_counts()["names"] == 1, "the detector must survive"  # type: ignore[attr-defined]
    assert "would echo the token" in capsys.readouterr().err

    f = tmp_path / "x.md"
    f.write_text("we use widgetco here\n", encoding="utf-8")
    hits = mod.scan_file(f, "docs/x.md")  # type: ignore[attr-defined]
    assert hits, "still detected"
    assert not any("widgetco" in h for h in hits), "the hit must not carry the token"


def test_estate_only_token_still_caught_by_the_file_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The estate file-scan path must keep working independently of the identifier pass.

    For a token in BOTH [names] and [estate] the name detector now fires first and suppresses the
    estate scan, so that path needs its own coverage: a token in [estate] and NOT in [names].
    Without this, the original test's coverage would have silently migrated to a different mechanism.
    """
    src = f"{_SYNTH_NAMES}\n[estate]\nzorpnet\n\n{_SYNTH_PREFIX}"
    mod = _load(_write(tmp_path, src), monkeypatch)
    assert not any(pat.search("zorpnet") for pat, _ in mod.FORBIDDEN), (  # type: ignore[attr-defined]
        "precondition: the token is estate-only"
    )
    assert "zorpnet" in [tok for tok, _ in mod._ESTATE_FILE_RES], (  # type: ignore[attr-defined]
        "precondition: it is file-scanned, not body-only"
    )
    f = tmp_path / "lanes.py"
    f.write_text('lane = "OB_ZORPNET_ORU"\n', encoding="utf-8")
    hits = mod.scan_file(f, "tests/lanes.py")  # type: ignore[attr-defined]
    assert any("estate token" in h for h in hits)
    assert not any("zorpnet" in h.lower() for h in hits), "reason-only"
