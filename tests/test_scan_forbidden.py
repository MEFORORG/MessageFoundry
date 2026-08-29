# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The forbidden-content scanner (scripts/security/scan_forbidden.py).

Covers the detection mechanisms — customer/partner/vendor names (word-boundary, with a case-sensitive
bare code), the routable-IP check with its private/documentation allow-set, and the field-scan site-code
detector — that the pre-commit hook and the CI leak-gate (.github/workflows/security.yml) run.

The scanner's real customer/vendor token list is *externalized* (a git-ignored local file for pre-commit
and the ``MEFOR_FORBIDDEN_TOKENS`` Actions secret for CI), so it loads EMPTY on a fork/no-secret checkout
and this module carries **no real token**. Every test here injects **synthetic** placeholder patterns via
the ``sf`` fixture (below) instead of relying on the real list — so the detection mechanism is exercised
identically with or without the secret, and this file is itself safe to scan (it is no longer skipped).

The scanner lives under scripts/ (not an installed package), so it is loaded by path."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCANNER_PATH = _REPO_ROOT / "scripts" / "security" / "scan_forbidden.py"


def _load_scanner():
    spec = importlib.util.spec_from_file_location("scan_forbidden", _SCANNER_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- synthetic token set (never a real customer/vendor token) ----------------------------------------
# Mirrors the SHAPE of the real externalized list so the same code paths are exercised: a word-boundary
# case-insensitive name, a partner/vendor name, a case-SENSITIVE bare code (an uppercase code is flagged,
# a lowercase same-spelling schema/identifier is intentionally NOT), and an any-case adopter-repo token.
_SYNTH_FORBIDDEN = [
    (re.compile(r"\bACME\b", re.I), "customer name (ACME)"),
    (re.compile(r"\bWIDGETCO\b", re.I), "partner name (WIDGETCO)"),
    (re.compile(r"\bXMPL\b"), "customer (Example Medical Center / XMPL)"),
    (re.compile(r"\bXMPLREPO\b", re.I), "customer adopter repo (XMPLREPO)"),
]
_SYNTH_ESTATE = ("acmecorp", "widgetco", "examplevendor")

# A non-real site-code prefix (99xxxx) stands in for the real one, injected into both the field-scan
# detector and the in-memory SITE_CODE_RE so no real site code appears in this now-scanned file.
_SYNTH_SITE_CODE_RE = re.compile(r"99\d{4}")
_SYNTH_SITE_CODE_FILE = re.compile(r"(?<![A-Za-z0-9.])99\d{4}(?![A-Za-z0-9.])")


@pytest.fixture
def sf(monkeypatch: pytest.MonkeyPatch):
    """The relocated scanner with SYNTHETIC token patterns injected in place of the externalized real
    list. ``scan_file``/``scan_text`` read these as module globals at call time (the same contract the
    engine/tee ``leak.py`` modules depend on), so patching the module attributes redirects detection onto
    the synthetic set. ``ALLOWLIST`` is emptied so a vetted-false-positive line can't mask a synthetic
    hit."""
    mod = _load_scanner()
    monkeypatch.setattr(mod, "FORBIDDEN", list(_SYNTH_FORBIDDEN))
    monkeypatch.setattr(mod, "ESTATE_TOKENS", _SYNTH_ESTATE)
    monkeypatch.setattr(mod, "ALLOWLIST", [])
    monkeypatch.setattr(mod, "SITE_CODE_RE", _SYNTH_SITE_CODE_RE)
    monkeypatch.setattr(mod, "_SITE_CODE_FILE", _SYNTH_SITE_CODE_FILE)
    return mod


def _routable_ip() -> str:
    # A routable IP is any address OUTSIDE the scanner's allow-set (loopback/RFC1918/RFC5737/multicast).
    # The probe IP is a globally shared public resolver -- never a customer host -- and is assembled
    # from octets at runtime so this comment carries no literal dotted-quad of its own.
    # at runtime so no literal routable dotted-quad ever sits in this (now-scanned) source file. The
    # documentation ranges (192.0.2.x etc.) are ALLOWED and so cannot exercise the "flag routable" path.
    return ".".join(("8", "8", "8", "8"))


# --- forbidden-content detection ---------------------------------------------------------------------


def test_scan_file_flags_customer_name(sf, tmp_path: Path) -> None:
    p = tmp_path / "doc.md"
    p.write_text("This note mentions ACME here.\n", encoding="utf-8")
    hits = sf.scan_file(p)
    assert len(hits) == 1
    assert "customer name (ACME)" in hits[0]


def test_scan_file_flags_case_sensitive_code(sf, tmp_path: Path) -> None:
    # Uppercase "XMPL" (the customer code) and "XMPLREPO" (adopter repo) are caught; a lowercase "xmpl"
    # schema/identifier is intentionally NOT flagged (case-sensitive bare code — avoids identifier churn).
    p = tmp_path / "doc.md"
    p.write_text(
        "Deploy notes for XMPL, from the XMPLREPO repo.\n"
        "The xmpl.Provider_GetNpi proc is a fine lowercase schema.\n",
        encoding="utf-8",
    )
    hits = sf.scan_file(p)
    reasons = " ".join(hits)
    assert "Example Medical Center / XMPL" in reasons  # uppercase code caught
    assert "XMPLREPO" in reasons  # adopter repo caught
    assert not any("xmpl.Provider_GetNpi" in h for h in hits)  # lowercase schema not flagged


def test_scan_file_flags_routable_ip_address(sf, tmp_path: Path) -> None:
    ip = _routable_ip()
    p = tmp_path / "hosts.txt"
    p.write_text(f"forward to {ip} on the wire\n", encoding="utf-8")
    # show_context=True: scan_file is REASON-ONLY by default, so a hit report is safe to print in a
    # public CI log. This test is specifically about naming the offending VALUE, so it opts in — which
    # also keeps the show_context path covered. Without it the assertion cannot pass.
    hits = sf.scan_file(p, show_context=True)
    assert any(f"routable IP address ({ip})" in h for h in hits)


def test_scan_file_allows_private_and_doc_ips(sf, tmp_path: Path) -> None:
    # Loopback / RFC1918 / TEST-NET (RFC5737) addresses never identify a real host — must not trip. These
    # literals are in the allow-set, so they are also safe against the real scanner reading this file.
    p = tmp_path / "net.txt"
    p.write_text("127.0.0.1 10.0.0.4 192.168.1.9 172.16.5.5 192.0.2.10\n", encoding="utf-8")
    assert sf.scan_file(p) == []


def test_scan_file_flags_site_code(sf, tmp_path: Path) -> None:
    # A synthetic 99xxxx site code left in source/docs — the shape of the gap that let a real site-coded
    # connection name reach the mirror. The ``_``-delimited code is caught even though a bare ``\b``
    # boundary would miss it.
    p = tmp_path / "wiring.py"
    p.write_text("re-routes deeper (e.g. ``PT_990210_ADT_2``)\n", encoding="utf-8")
    hits = sf.scan_file(p, show_context=True)  # reason-only by default; see the IP test above
    assert any("site code (990210)" in h for h in hits)


def test_scan_file_site_code_ignores_embedded_digit_runs(sf, tmp_path: Path) -> None:
    # A 99xxxx run embedded in a longer alphanumeric/decimal token is NOT a site code: a hex hash, a
    # digit-prefixed run, a password, a decimal fraction, and a dotted version must all pass (the
    # boundary excludes alphanumerics AND ``.``), or the check would false-positive across the whole tree.
    p = tmp_path / "noise.txt"
    p.write_text(
        "hash aff07c990210ff\n"  # hex-embedded
        "dob 20990210\n"  # digit-prefixed
        "pw 9876990210\n"  # digit-embedded
        "ratio 75.990210\n"  # decimal fraction
        "ver 1.990210.2\n",  # dotted version
        encoding="utf-8",
    )
    assert sf.scan_file(p) == []


def test_scan_file_site_code_skips_noisy_file_types(sf, tmp_path: Path) -> None:
    # Lock / SVG / password-list files are dense with incidental standalone 6-digit runs — skipped by file
    # type so a benign coordinate or hash line does not fail closed (a standalone 990210 WOULD otherwise
    # match; the skip, not a boundary, is what saves these).
    for name in ("requirements.lock", "art.svg", "common_passwords.txt"):
        p = tmp_path / name
        p.write_text("standalone 990210 here\n", encoding="utf-8")
        assert sf.scan_file(p) == [], name


def test_scan_file_skips_binary(sf, tmp_path: Path) -> None:
    # NUL in the head => treated as binary, not scanned. The ACME token (which the fixture WOULD flag as
    # text) and the address are ignored. The address is a TEST-NET (allowed) literal, so this source line
    # is clean even under the real scanner.
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00\x01\x02 ACME 203.0.113.9")
    assert sf.scan_file(p) == []


def test_scan_file_clean_text_has_no_hits(sf, tmp_path: Path) -> None:
    p = tmp_path / "ok.md"
    p.write_text("A generic engine doc about HL7 routing. Corepoint is fine in prose.\n", "utf-8")
    assert sf.scan_file(p) == []  # bare competitor name is intentionally allowed


# --- LOCATION detector: a file judged by where it sits, not by its bytes -----------------------------
# The private security corpus is prose ABOUT this repo -- threat models, ASVS assessments, remediation
# plans -- so it carries no customer name, no site code, no IP and no secret. Every content detector
# above reports it clean by working correctly. These tests cover the only rule that can see it.


def test_a_file_under_docs_security_is_flagged_by_its_path_alone(sf, tmp_path: Path) -> None:
    """Content is deliberately innocuous: the PATH is the entire finding."""
    p = tmp_path / "threat-model.md"
    p.write_text("A generic engine doc about HL7 routing.\n", "utf-8")
    assert sf.scan_file(p) == []  # same bytes, ordinary location -> clean

    hits = sf.scan_file(p, "docs/security/threat-model.md")
    assert len(hits) == 1, hits
    assert "docs/security/" in hits[0]
    assert ":0:" in hits[0], "a path-level finding has no line to point at and must say so"


def test_the_path_detector_fires_on_a_binary_file_too(sf, tmp_path: Path) -> None:
    """The interaction with ``test_scan_file_skips_binary``, which is why the check runs BEFORE the read.

    A PDF or a diagram under docs/security/ is exactly as much of a leak as the markdown beside it, and
    the content scanner drops binaries unread. Ordering the location rule after that read would have
    made every non-text file in the corpus invisible -- the widest possible hole in a leak gate.
    """
    p = tmp_path / "diagram.pdf"
    p.write_bytes(b"\x00\x01\x02 not text at all")
    assert sf.scan_file(p) == []  # binary in an ordinary location is still skipped
    assert len(sf.scan_file(p, "docs/security/diagram.pdf")) == 1


def test_a_relocated_copy_under_docs_security_is_still_flagged(sf, tmp_path: Path) -> None:
    """Unanchored by design: a vendored or moved copy is the same leak as the top-level one."""
    p = tmp_path / "x.md"
    p.write_text("clean\n", "utf-8")
    assert len(sf.scan_file(p, "ide/docs/security/x.md")) == 1


def test_the_path_detector_does_not_flag_ordinary_paths(sf, tmp_path: Path) -> None:
    """NEGATIVE CONTROL. A rule that flagged everything would pass every test above and be useless.

    ``scripts/security/`` is the sharp one: the scanner's own source and this test file both live
    under a directory whose name contains "security", and a rule written as a bare substring would
    flag the gate itself on every run -- the kind of self-trip that gets a detector deleted.
    """
    p = tmp_path / "x.md"
    p.write_text("clean\n", "utf-8")
    for rel in (
        "scripts/security/scan_forbidden.py",
        "tests/test_scan_forbidden.py",
        "docs/SECURITY.md",
        "docs/securityish/x.md",
        "docs/reviews/x.md",
        "messagefoundry/auth/security.py",
    ):
        assert sf.scan_file(p, rel) == [], f"{rel} must not be flagged by the location rule"
        assert sf.forbidden_path_reason(rel) is None, rel


def test_the_location_rule_list_is_not_empty(sf) -> None:
    """Guard the rule source. An empty FORBIDDEN_PATHS makes every assertion above vacuous, and unlike
    the token list this one is NOT externalized -- it ships in the file, so absence is a defect."""
    print(f"location rules: {[p.pattern for p, _ in sf.FORBIDDEN_PATHS]}")
    assert sf.FORBIDDEN_PATHS, "no location rules compiled -- the path detector is decoration"
    assert sf.forbidden_path_reason("docs/security/x.md"), (
        "the shipped rule set does not flag docs/security, which is the class it exists for"
    )


# --- reasons-only in-memory scan (the importable scan_text contract) ---------------------------------


def test_scan_text_returns_reasons_without_matched_context(sf) -> None:
    # scan_text is the importable single source of truth the anonymizer leak-check reuses; it returns
    # REASONS ONLY (never the matched text), so a caller may raise/log the result without leaking content.
    reasons = sf.scan_text(f"mentions ACME and {_routable_ip()}")
    assert "customer name (ACME)" in reasons
    assert "routable IP address" in reasons
    assert not any("ACME and" in r for r in reasons)  # the matched line is never echoed


# --- scan coverage invariant (lockstep with the SKIP_PATHS narrowing) --------------------------------


def test_scanner_no_longer_skips_its_own_token_bearing_tests(sf) -> None:
    # These two tests were rewritten to SYNTHETIC tokens so they can be scanned on the public tree — they
    # are no longer in SKIP_PATHS. If a real token were ever added here it MUST be caught, not silently
    # shipped. This pins that invariant (lockstep with the SKIP_PATHS narrowing in scan_forbidden.py).
    assert sf._is_skipped("tests/test_scan_forbidden.py") is False
    assert sf._is_skipped("tests/test_anon_core.py") is False
    assert sf._is_skipped("messagefoundry/__init__.py") is False


# --- synthetic-vs-real token set ---------------------------------------------------------------------
#
# Copying scan-tokens.local.txt.example is the supported way an outside contributor satisfies the
# pre-commit hook (the real list is private and undistributable). The danger is that the example
# POPULATES every section, so it clears the count floor while matching nothing real — a maintainer who
# copied it instead of installing the real list would get a green, blind gate, and the floor could not
# tell. Distinguishing the two is therefore the only thing standing between "exit 0" and false clean.

_EXAMPLE = _REPO_ROOT / "scripts" / "security" / "scan-tokens.local.txt.example"


def _scanner_with_tokens(monkeypatch: pytest.MonkeyPatch, text: str | None):
    """A FRESH scanner module whose tokens came from ``text`` (inline content, or None for no source)."""
    if text is None:
        monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", "")
    else:
        monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", text)
    return _load_scanner()


def test_the_shipped_example_is_recognised_as_synthetic(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _scanner_with_tokens(monkeypatch, _EXAMPLE.read_text(encoding="utf-8"))
    assert mod.TOKENS_PRESENT is True
    assert mod.is_synthetic_token_set() is True
    # The trap this guards: every floor section is non-empty, so counts alone look like a real install.
    counts = mod.loaded_token_counts()
    assert all(counts[s] > 0 for s in ("names", "estate", "site_prefixes"))


def test_a_reformatted_copy_of_the_example_still_reads_synthetic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compared on PARSED content, not bytes — otherwise adding one comment line would silently
    reclassify a synthetic set as real, which is the direction that fails open."""
    noisy = "# a local note\n\n" + _EXAMPLE.read_text(encoding="utf-8") + "\n\n# trailing note\n"
    mod = _scanner_with_tokens(monkeypatch, noisy)
    assert mod.is_synthetic_token_set() is True


def test_a_real_shaped_token_set_is_NOT_flagged_synthetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control. Without this, a function that returned True unconditionally would look correct."""
    mod = _scanner_with_tokens(
        monkeypatch,
        "[names]\n\\bNOTREAL\\b | customer | i\n\n[estate]\nnotrealvendor\n\n[site_prefix]\n77\n",
    )
    assert mod.TOKENS_PRESENT is True
    assert mod.is_synthetic_token_set() is False


def test_no_token_source_is_absent_rather_than_synthetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """'Nothing loaded' and 'the example loaded' are different failures with different fixes, and the
    run banner names them differently — so the predicate must not conflate them."""
    mod = _scanner_with_tokens(monkeypatch, None)
    assert mod.TOKENS_PRESENT is False
    assert mod.is_synthetic_token_set() is False


# --- --path coverage: every named path is scanned, and a file is scanned as itself -------------------
# Regression tests for a gate that reported CLEAN over content it never opened. These drive `main()`
# end-to-end rather than `_candidate_files` directly, because the defect was only observable through the
# exit code: the ZERO-files refusal fires on the TOTAL, so one real directory masked every dropped path.


@pytest.fixture
def sf_main(sf, monkeypatch: pytest.MonkeyPatch):
    """``sf`` patches the detection globals, but ``main()`` calls ``reload_tokens()`` as its first act and
    would overwrite them with the externalized real set (or an empty one on a fork). Neutralise the
    reload so ``main()`` is exercised against the SYNTHETIC tokens.

    Without this the tests below would silently assert nothing: on a box with real tokens loaded the
    synthetic "ACME" is not forbidden, so a dirty tree would exit 0 and the test would fail for a reason
    unrelated to what it is checking. The require/floor env vars are cleared for the same reason -- an
    inherited MEFOR_REQUIRE_TOKENS would make every call below return 2."""
    monkeypatch.setattr(sf, "reload_tokens", lambda: None)
    monkeypatch.delenv("MEFOR_REQUIRE_TOKENS", raising=False)
    monkeypatch.delenv("MEFOR_MIN_DETECTORS", raising=False)
    return sf


def _clean_and_dirty(tmp_path: Path) -> tuple[Path, Path]:
    """A clean directory, and a separate directory holding one file with a synthetic forbidden token."""
    clean = tmp_path / "clean"
    (clean / "sub").mkdir(parents=True)
    (clean / "sub" / "ok.md").write_text("nothing to see here\n", encoding="utf-8")
    dirty = tmp_path / "dirty"
    dirty.mkdir()
    (dirty / "leak.md").write_text("contact ACME about this\n", encoding="utf-8")
    return clean, dirty


def test_a_forbidden_token_in_the_SECOND_named_path_is_still_caught(
    sf_main, tmp_path: Path
) -> None:
    """The defect, stated as a test. Only ``argv[1]`` was read, so every path after the first was dropped
    with no message. Measured 2026-08-04: a four-path audit reported clean having examined ONE of the
    four, and nothing in the output revealed it.

    A leak gate whose green means "the first argument was clean" is worse than no gate: the caller reads
    it as "all of these are clean" and stops looking."""
    clean, dirty = _clean_and_dirty(tmp_path)
    assert sf_main.main(["--path", str(clean), str(dirty)]) == 1


def test_a_forbidden_token_in_a_named_FILE_is_caught(sf_main, tmp_path: Path) -> None:
    """``rglob()`` on a non-directory yields nothing, so naming a file scanned exactly zero of it. Alone
    that surfaced as the ZERO-files refusal (exit 2), which at least fails closed; mixed with a scannable
    directory it disappeared into a clean exit 0."""
    _clean, dirty = _clean_and_dirty(tmp_path)
    assert sf_main.main(["--path", str(dirty / "leak.md")]) == 1


def test_a_named_FILE_mixed_with_a_clean_DIRECTORY_is_not_swallowed(
    sf_main, tmp_path: Path
) -> None:
    """The exact invocation shape that produced the false clean."""
    clean, dirty = _clean_and_dirty(tmp_path)
    assert sf_main.main(["--path", str(clean), str(dirty / "leak.md")]) == 1


def test_all_clean_named_paths_still_pass(sf_main, tmp_path: Path) -> None:
    """The control. Without it, a fix that returned 1 unconditionally would satisfy every test above."""
    clean, _dirty = _clean_and_dirty(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    (other / "fine.md").write_text("all good\n", encoding="utf-8")
    assert sf_main.main(["--path", str(clean), str(other), str(other / "fine.md")]) == 0


def test_the_run_reports_how_many_files_it_examined(
    sf_main, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Coverage has to be visible without suspecting an under-scan. Exit 0 plus a token-count line could
    not distinguish "scanned what you named" from "scanned one of the four you named"."""
    clean, _dirty = _clean_and_dirty(tmp_path)
    assert sf_main.main(["--path", str(clean)]) == 0
    err = capsys.readouterr().err
    assert "examined 1 file(s)" in err
    assert "1 named path(s)" in err


def test_zero_examined_still_refuses_rather_than_reporting_clean(sf_main, tmp_path: Path) -> None:
    """The pre-existing fail-closed behaviour must survive the fix: an empty tree is not a pass."""
    empty = tmp_path / "empty"
    empty.mkdir()
    assert sf_main.main(["--path", str(empty)]) == 2


# --- security-record content: a requirement id BESIDE a verdict (BACKLOG #1337) ----------------------

# THE TWO CONTROLS ARE BOTH REQUIRED AND NEITHER MAY BE DELETED WITHOUT THE OTHER.
#
# A screen with only the fire-case is indistinguishable from one that matches everything; a screen
# with only the quiet-case is indistinguishable from one that matches nothing. The row filing this
# reached BOTH failures in ten minutes while deriving the spec, which is why they are gates here
# rather than advice.
#
# WHY THE DETECTOR IS A PAIR AND NOT A SHAPE. A requirement identifier and a semantic version are
# the same shape, and this repository is full of versions. Measured over 2045 tracked files: the
# bare dotted-triple appears 8018 times across 649 files. Proximity does not rescue it either --
# "within 120 characters of a verdict word" still scores 1028 across 119 files, and adding an ASVS
# context marker leaves 548 across 50, mostly the backlog's own legitimate citations. Only the tight
# pair discriminates, and it scores ZERO over the same corpus.

# THE FIXTURES ARE STORED AS PARTS AND JOINED AT RUNTIME, and that is not styling.
# A literal `<id><sep><verdict>` written into this file IS the shape the detector hunts, so the gate
# would fire on the test that proves the gate works -- and a control that reds CI on its own test
# data is exactly how a control gets switched off. Keeping the identifier and the verdict as
# separate literals means the source carries no pair, the scanner is silent on this file, and no
# allowlist entry or reserved-placeholder exemption is needed. Both of those alternatives were
# tried; this one leaves no standing bypass.
_RECORD_PARTS: list[tuple[str, str, str]] = [
    ("1.2.2", ": ", "pass"),
    ("11.4.1", " | ", "fail"),
    ("3.5.5", " = ", "partial"),
    ("16.2.2", " -> ", "needs-review"),
    ("7.5.1", " -- ", "n/a"),
]
# The OTHER direction, verdict first. Both arms of the detector are real code and a fixture list
# covering only one would leave half of it unexercised while the count looked healthy.
_RECORD_PARTS_VERDICT_FIRST: list[tuple[str, str, str]] = [
    ("fail", ": ", "12.1.5"),
    ("partial", " <- ", "4.2.1"),
]
_RECORD_CONTENT_MUST_FIRE = [f"{a}{s}{b}" for a, s, b in _RECORD_PARTS] + [
    f"{a}{s}{b}" for a, s, b in _RECORD_PARTS_VERDICT_FIRST
]

_RECORD_CONTENT_MUST_STAY_QUIET = [
    # Lockfile dependency versions -- the collision the whole design is shaped around.
    "pyside6==6.11.1",
    "ruff==0.15.22",
    'version = "0.11.25"',
    # A BARE CITATION is a forward reference, not an assessment, and is legitimately public. This is
    # the exact shape of the backlog's own item titles.
    "#1107 ASVS 1.2.2 -- apiclient path encoding and URL scheme allow-list",
    "a bare citation: ASVS 1.2.2 applies to this module",
    # Prose where a verdict word happens to be near a version. `pass` is unavoidable in a test repo.
    "the suite will pass; see 1.2.2 later for the rationale",
    "requires 3.14.6 to pass the collection step",
]


@pytest.mark.parametrize("line", _RECORD_CONTENT_MUST_FIRE)
def test_a_requirement_id_beside_a_verdict_is_flagged(sf, tmp_path: Path, line: str) -> None:
    """CONTROL 1. Without this, a screen that matches nothing looks identical to a correct one."""
    p = tmp_path / "note.md"
    p.write_text(f"context above\n{line}\ncontext below\n", encoding="utf-8")
    hits = sf.scan_file(p)
    assert any("security-record content" in h for h in hits), (
        f"{line!r} pairs an identifier with a verdict -- that pair IS the assessment, and the "
        f"assessment is vaulted. hits={hits}"
    )


@pytest.mark.parametrize("line", _RECORD_CONTENT_MUST_STAY_QUIET)
def test_a_version_or_a_bare_citation_is_not_record_content(sf, tmp_path: Path, line: str) -> None:
    """CONTROL 2. Without this, a screen that matches everything looks identical to a correct one.

    A gate firing on ordinary text gets allowlisted into uselessness, and the pipeline keeps showing
    a passing step while nothing is being checked.
    """
    p = tmp_path / "note.md"
    p.write_text(f"context above\n{line}\ncontext below\n", encoding="utf-8")
    hits = [h for h in sf.scan_file(p) if "security-record content" in h]
    assert not hits, (
        f"{line!r} is a dependency version or a bare forward citation, not an assessment. "
        f"Flagging it is how this gate gets switched off. hits={hits}"
    )


def test_the_record_detector_reports_no_value(sf, tmp_path: Path) -> None:
    """The pair IS the disclosure, so the reason must never echo it into a public CI log.

    Same rule the worktree-slug and home-path detectors already follow, asserted here because this
    detector is the one whose matched text is itself the vaulted content.
    """
    p = tmp_path / "note.md"
    # Reuses a joined fixture rather than writing a second literal pair into this file. Every such
    # literal is itself the shape the detector hunts, so one source of fixtures means one place that
    # has to stay split.
    identifier, sep, verdict = _RECORD_PARTS[1]
    p.write_text(f"{identifier}{sep}{verdict}\n", encoding="utf-8")
    hits = [h for h in sf.scan_file(p) if "security-record content" in h]
    assert hits, "the fixture line must fire, or this asserts nothing"
    for h in hits:
        assert identifier not in h, f"the reason echoed the identifier it exists to keep out: {h!r}"
        assert verdict not in h.split("security-record content")[0], (
            f"reason leaked the verdict: {h!r}"
        )


# --------------------------------------------------------------------------------------------------
# BACKLOG #1368 / SEC-04 -- is the FLOOR still tracking the list it guards?
#
# `token_floor_failure` asks whether the LIST fell below the FLOOR. This asks the opposite: whether the
# floor fell behind the list. A floor of 7 against a list of 40 is satisfied by any 7 detectors
# surviving, so the gate goes green while constraining almost nothing -- and nothing anywhere noticed,
# because the counts print and nothing compares them.
#
# EVERY TEST HERE INJECTS COUNTS. No token source is loaded, so these run identically on a fork with no
# secret, and this file continues to carry no real token.
# --------------------------------------------------------------------------------------------------

#: The shape measured against the LIVE list on 2026-08-26, recorded so the tests below are anchored to a
#: real observation rather than to invented numbers. Counts only; the list itself is a secret.
_LIVE_2026_08_26 = {"names": 8, "estate": 14, "site_prefixes": 2}
_FLOOR_IN_CI = {"names": 7, "estate": 13, "site_prefixes": 1}


def test_the_floor_CI_pins_today_is_still_fresh_against_the_live_shape(sf) -> None:
    """The rule must not fail on the day it lands. If this reds, the floor needs raising and that is a
    decision for a human, not a test to be relaxed."""
    assert sf.floor_freshness_failure(_FLOOR_IN_CI, _LIVE_2026_08_26) is None


def test_THE_80_PERCENT_RATIO_ALONE_WOULD_HAVE_FAILED_site_prefixes(sf) -> None:
    """WHY THE RULE IS SPLIT, pinned as a test rather than left in a comment.

    site_prefixes is floor 1 against 2 loaded. As a ratio that is 50% and always will be -- ANY growth
    from 1 to 2 scores 50%, however healthy. At that size a ratio measures the SECTION'S SIZE, not the
    floor's staleness, so a flat 80% rule would red the gate on its first real run while nothing is
    wrong.
    """
    floor, loaded = _FLOOR_IN_CI["site_prefixes"], _LIVE_2026_08_26["site_prefixes"]
    assert floor / loaded < sf._MIN_FLOOR_RATIO, "the premise of the split rule stopped holding"
    # ...and the shipped rule passes it anyway, via the absolute arm.
    assert sf.floor_freshness_failure({"site_prefixes": floor}, {"site_prefixes": loaded}) is None


def test_a_small_section_fails_on_an_ABSOLUTE_lag(sf) -> None:
    """1 against 3 is drift; 1 against 2 is not. The rule has to separate them."""
    assert sf.floor_freshness_failure({"site_prefixes": 1}, {"site_prefixes": 2}) is None
    why = sf.floor_freshness_failure({"site_prefixes": 1}, {"site_prefixes": 3})
    assert why and "site_prefixes" in why and "lags" in why, why


def test_a_large_section_fails_on_the_RATIO(sf) -> None:
    why = sf.floor_freshness_failure({"names": 2}, {"names": 8})
    assert why and "names" in why and "25%" in why, why
    assert sf.floor_freshness_failure({"names": 7}, {"names": 8}) is None


def test_the_message_names_the_section_AND_BOTH_NUMBERS(sf) -> None:
    """A drift warning that does not say which section, and by how much, sends the reader to grep."""
    why = sf.floor_freshness_failure({"estate": 6}, {"estate": 14})
    assert why is not None
    for fragment in ("estate", "6", "14"):
        assert fragment in why, f"{fragment!r} missing from: {why}"


def test_a_section_AT_OR_BELOW_its_floor_is_not_this_function_s_question(sf) -> None:
    """That is `token_floor_failure`'s job -- the list falling below the floor. Answering it here too
    would double-report one defect and, worse, imply this check covers it when it does not."""
    assert sf.floor_freshness_failure({"names": 9}, {"names": 8}) is None
    assert sf.floor_freshness_failure({"names": 8}, {"names": 8}) is None


def test_no_floor_configured_is_not_a_freshness_failure(sf) -> None:
    """Absence of a floor is `MEFOR_REQUIRE_TOKENS`'s question. Failing here would make the gate fire
    on every contributor machine, and a gate that fires on everyone gets switched off."""
    assert sf.floor_freshness_failure(None, _LIVE_2026_08_26) is None
    assert sf.floor_freshness_failure({}, _LIVE_2026_08_26) is None


def test_THE_COUNTS_CANNOT_DISCRIMINATE_SYNTHETIC_FROM_REAL_BUT_THE_MODE_CAN(
    sf, monkeypatch
) -> None:
    """THE FINDING THAT SHAPED THIS ITEM, pinned so nobody verifies a floor from counts alone.

    On 2026-08-26 the SYNTHETIC example set and the REAL list both reported 8/14/2. Three identical
    numbers from two tables, one of which matches nothing real. A caller checking counts would assert a
    floor against a set that cannot fire, and read the pass as evidence.

    `mode` is the only field that separates them, so the report must carry it.
    """
    counts = dict(_LIVE_2026_08_26)
    monkeypatch.setattr(sf, "TOKENS_PRESENT", True)
    monkeypatch.setattr(sf, "is_synthetic_token_set", lambda: True)
    synthetic = sf._detector_count_report(counts)
    monkeypatch.setattr(sf, "is_synthetic_token_set", lambda: False)
    real = sf._detector_count_report(counts)

    assert "mode=synthetic" in synthetic and "mode=real" in real
    # ...and the COUNT lines are byte-identical between them, which is the whole point.
    assert [x for x in synthetic if not x.startswith("mode=")] == [
        x for x in real if not x.startswith("mode=")
    ], "if the counts ever differ here, this test has stopped demonstrating the hazard"


def test_no_token_source_reports_mode_none_rather_than_a_clean_zero(sf, monkeypatch) -> None:
    """ "loaded nothing" and "loaded a real list that happens to be small" must not render alike."""
    monkeypatch.setattr(sf, "TOKENS_PRESENT", False)
    assert "mode=none" in sf._detector_count_report({"names": 0})
