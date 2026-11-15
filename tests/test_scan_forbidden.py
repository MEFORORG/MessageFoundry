# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import hashlib
import importlib.util
import io
import json
import re
import subprocess
import time
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
#: A synthetic code, assembled rather than written whole. A probe of the form ``PT_<digits>_ADT`` is a
#: live match for the scanner's own prefix-free ``_ESTATE_ID_SHAPE`` detector, and this file is scanned
#: by the gate it tests -- so a literal here would make the suite trip its own detector. Same defusal
#: as ``_routable_ip`` below.
_SYNTH_CODE = "99" + "0210"


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
    p.write_text(f"re-routes deeper (e.g. ``PT_{_SYNTH_CODE}_ADT_2``)\n", encoding="utf-8")
    hits = sf.scan_file(p, show_context=True)  # reason-only by default; see the IP test above
    assert any(f"site code ({_SYNTH_CODE})" in h for h in hits)


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


# --------------------------------------------------------------------------------------------------
# BACKLOG #3364 -- the same record content in a PULL REQUEST BODY, where it is written as prose.
#
# THE SAME TWO CONTROLS AS #1337 ABOVE, AND THE SAME RULE THAT NEITHER GOES WITHOUT THE OTHER: each
# owner-ruled kind (verdict, gap, code map) has fixtures that must fire, and ordinary PR text must pass.
#
# THE IDENTIFIERS ARE DELIBERATELY ONES NO REQUIREMENT CARRIES. A fixture reading "<id> stays <verdict>"
# with a real identifier would itself publish a verdict-shaped sentence, so these use a real chapter and
# the section number nine with a requirement number in the nineties: the detector's shape, and nobody's
# assessment. The paths are invented for the same reason. The identifier and the verdict also stay
# separate literals joined at runtime, as above, so this source carries no pair for the tree scan.
# --------------------------------------------------------------------------------------------------

_REQ = "16.9.97"
_REQ_B = "9.9.98"
_PARTIAL, _PASS, _FAIL, _NA = "partial", "pass", "fail", "na"

_PR_VERDICT_MUST_FIRE = [
    f"After this merges, {_REQ} stays {_PARTIAL} until the follow-up lands.",
    f"ASVS {_REQ} stays **`{_FAIL}`** -- none of this changes the ceiling.",
    f"The vault re-score held {_REQ} at {_PARTIAL} on one ground.",
    f"The re-read of {_REQ} held the cell at {_PARTIAL} on four sentences.",
    f"It does not move the ASVS {_REQ} cell to {_PASS}, and nothing here claims it does.",
    f"A single-limb requirement gets `{_NA}` ({_REQ}), while a multi-limb one cannot.",
    f"| #1 | {_REQ} | Stay **{_PARTIAL}**. The row's basis is replaced. |",
    f"| {_REQ} | the outbound limb | {_PASS} |",
    f"{_REQ}{': '}{_FAIL}",
    f"Assessed as ASVS {_REQ} (`{_PARTIAL}`, the control covers only bound accounts).",
    f"ASVS {_REQ} \u2192 {_PASS}",
    f"ASVS {_REQ} remains at {_PARTIAL} for now.",
    f"A vault re-read moved {_REQ} from {_PASS} to {_PARTIAL} on item 1.",
    # The tree scan's tight pair, behind words the version filter would otherwise read as a lead.
    f"Applies to {_REQ}{': '}{_PARTIAL}",
    f"The follow-up {_REQ}{' = '}{_FAIL}",
    # Markdown around the identifier or the verdict: emphasis, a link, a wrapped quote, an en dash.
    f"ASVS _{_REQ}_ stays __{_PARTIAL}__.",
    f"[ASVS {_REQ}](https://example.org/asvs/v16) stays {_PARTIAL}.",
    f"> The vault re-read held ASVS {_REQ}\n> at {_PARTIAL} on review.",
    f"> ASVS {_REQ} stays\n> {_PARTIAL} until the re-read.",
    f"ASVS {_REQ} \u2013 {_PARTIAL}",
    # A record verb binds even where the word before the identifier reads as a version lead.
    f"Applies to {_REQ} which stays {_PARTIAL}.",
    f"Cross-cutting {_REQ} stays {_PARTIAL}.",
    f"Downgrades ASVS {_REQ} to {_PARTIAL}.",
    f"ASVS {_REQ} now passes.",
]
_PR_GAP_MUST_FIRE = [
    # Sentence-final: the identifier's own full stop must not hide it.
    f"The shortfall is tracked under ASVS {_REQ}.",
    f"BACKLOG #1, one limb: the unvalidated input residual (ASVS {_REQ}).",
    f"It is the gap that keeps ASVS {_REQ} open on the record.",
    f"## #1 (ASVS {_REQ}) -- verified, and deliberately not built",
]
_PR_MAP_MUST_FIRE = [
    f"`pkg/example_module.py` states the ASVS {_REQ} guarantee for every caller.",
    f"| `tests/test_example_widget.py` | {_REQ} | extracts one shared helper |",
    f"Vault cell {_REQ} anchors on the `pkg/example.py:12` citation.",
    f"ASVS {_REQ} is enforced at https://github.com/example/repo/blob/main/pkg/example_guard.py#L40",
]

#: Ordinary pull request text with NO requirement number at all -- the Lander's negative control. It
#: carries every word the detector keys on (verdict words, gap words, code paths, versions) so a pass
#: here means the binding held, not that the words were absent.
_PR_CLEAN_BODY = "\n".join(
    [
        "## What this changes",
        "",
        "Adds a bounded retry to the outbound sender in `pkg/example_sender.py`, so a refused",
        "connection is retried before the row dead-letters. The gap between attempts doubles.",
        "",
        "- Tests: 412 passed, 3 skipped; the new case would fail without the fix.",
        "- Python 3.14.6, OpenSSL 3.5.7; bumps lxml from 6.1.1 to 6.1.2 in passing.",
        "- `ruff==0.15.22`, js-yaml 4.3.1 in `ide/package-lock.json`, ldap3 2.9.1 in core/connection.py.",
        "- It requires 3.14.6 to pass the collection step; no residual risk is introduced.",
        "",
        "| check | result |",
        "| --- | --- |",
        "| pytest | pass |",
        "| mypy | fail before, pass after |",
    ]
)
#: Text where a dotted triple is a version or an HL7 field, beside the words a record line would use.
_PR_VERSION_MUST_STAY_QUIET = [
    "Bumps lxml from 6.1.1 to 6.1.2 in `requirements.lock`.",
    "Local CPython 3.14.6, OpenSSL 3.5.7: `tests/test_example_tls.py` gave 8 passed and 1 skipped.",
    # A bump whose OLD side follows punctuation, so only the "<version> to <version>" tail marks it.
    "One lockfile entry, 1.2.1 to 1.2.2, read by `pkg/example_client.py`.",
    "| `gitleaks` | `v8.1.4` | `security.yml` `VER=8.1.4` | same |",
    "E    MSH|^~\\&|SAPP|FAC|RAPP|RFAC|20260101||ADT^A01|C1|P|2.5.1  at pkg/example_parser.py:40",
    "the suite will pass; see 1.2.2 later for the rationale",
    "requires 3.14.6 to pass the collection step",
    # An id-SHAPED version before a bare "to <verdict>": only the move-verb guard keeps this quiet.
    "requires 6.1.1 to pass the collection step",
    "Parses a 2.5.1 ADT^A01 in tests/test_example_parse.py without the strict validator.",
    "This uncovered a bug in 1.2.3 handling, now fixed.",
    "Parses HL7 V2.5.1 ADT messages in pkg/example_peek.py.",
    "Adds HL7 V2.3.1 support; the gap in segment handling is closed.",
    f"- Python 3.14.6{': '}{_PASS}",
    "Per RFC 6455 section 5.5.1, ping handling lives in pkg/example_ws.py.",
    "<p>Changes in 7.1.2: fix</p><p>the residual leak in pkg/example_linux.py</p>",
    # A heading is its own unit, so the next paragraph's identifier is not beside the heading's path.
    f"## Changes to pkg/example_app.py\nContext: ASVS {_REQ} is cited in the brief.",
    # The failure MODE of a control is not a verdict.
    f"ASVS {_REQ} is now fail closed on a bad input.",
]


#: BACKLOG #3364's residue, "some prose phrasings are missed": each line is a phrasing engine PR 2448's
#: detector let through, taken from the shapes merged engine PR bodies use and rebuilt with the synthetic
#: identifiers and invented names above. Each must fire with the kind it is listed under.
_PR_RESIDUE_MUST_FIRE: list[tuple[str, str]] = [
    # A passive auxiliary or a hedging adverb between the identifier and its record verb.
    ("verdict", f"ASVS {_REQ} was held at {_PARTIAL} by two shipped docs."),
    ("verdict", f"{_REQ} likely stays {_PARTIAL}, because it needs a second signal."),
    ("verdict", f"On this platform {_REQ} is capped at {_PARTIAL}."),
    ("verdict", f"After review {_REQ} has been met."),
    ("verdict", f"ASVS {_REQ} is likely {_PARTIAL} on review."),
    ("verdict", f"ASVS {_REQ} probably passes now."),
    # A modal or a negation bound to a bare verdict verb that ends its clause.
    ("verdict", f"## Why {_REQ} still cannot {_PASS}"),
    ("verdict", f"ASVS {_REQ} could have been met."),
    ("verdict", f"After this merges, the {_REQ} re-read should reach {_PASS}."),
    # The verdict held with a pronoun, or with no object at all.
    ("verdict", f"A re-read of ASVS cell {_REQ} held it at {_PARTIAL} on review."),
    ("verdict", f"The {_REQ} re-read, at engine abc1234, held {_PARTIAL} on seven sentences."),
    ("verdict", f"Cell {_REQ} names those accounts as what holds it {_PARTIAL}."),
    # "as" a verdict, and a row moved "to" one by "update".
    ("verdict", f"The owner ruled to sign ASVS {_REQ} as a recorded {_PARTIAL}."),
    ("verdict", f"These commits update the {_REQ} row to `{_NA}` under rule 1."),
    # A verb stating the verdict before the identifier, and the record's "honest pass" idiom.
    ("verdict", f"It does not satisfy vault cell {_REQ}."),
    ("verdict", f"BACKLOG #1: research an honest {_PASS} for ASVS {_REQ}."),
    # A table row listing several identifiers, with a cell that opens with the verdict.
    ("verdict", f"| #1, #2 | {_REQ}, {_REQ_B} | unchanged, `{_PARTIAL}`. |"),
    ("verdict", f"| #1, #2 | {_REQ}, and {_REQ_B}, | unchanged, `{_PARTIAL}`. |"),
    # Gap words the record uses that are also ordinary English, so they bind only a marked
    # identifier: omits, omissions, lacks, incomplete, ground, still short.
    ("gap", f"So cell {_REQ} omits it, rather than the record lacking it."),
    ("gap", f"| #1 | ASVS {_REQ} | at least four more | 9 open omissions |"),
    ("gap", f"ASVS {_REQ} lacks a row-completeness pin."),
    ("gap", f"Incomplete {_REQ} row: the source cells do not list the claim."),
    ("gap", f"That limit is the one ground holding ASVS {_REQ} today."),
    ("gap", f"A re-read today would read cell {_REQ} as still short on one arm."),
    # A module as a regular expression escapes it is a path-strength map.
    ("map", f"Cell {_REQ}'s `messagefoundry\\.example` absence pattern matches nothing."),
    # A code symbol in backticks rather than a path binds only a marked identifier: a call, a
    # private name, a class attribute, a dotted name with an underscore, and a snake_case name.
    (
        "map",
        f"The store passes `example_aad(...)` on every call; the ASVS {_REQ} binding needs it.",
    ),
    ("map", f"It is the carve-out on the ASVS {_REQ} expiry inside `_example_login`."),
    ("map", f"The engine masks `ExampleDetail.error` until a reveal (ASVS {_REQ})."),
    ("map", f"`_example_helper` was renamed, so a re-anchor is likely needed on cell {_REQ}."),
    ("map", f"`shared_example.read_example_log` reads through a cap (cell {_REQ})."),
    ("map", f"`example_setting` covers the {_REQ} requirement."),
    ("map", f"`EXAMPLE_CHANGED` is an account notice under ASVS {_REQ}."),
    # "ASVS" marks an identifier however it is set off from it.
    ("gap", f"ASVS V{_REQ} lacks a row-completeness pin."),
    ("gap", f"ASVS `{_REQ}` lacks a row-completeness pin."),
    ("gap", f"ASVS: {_REQ} lacks a row-completeness pin."),
    ("gap", f"asvs {_REQ} lacks a row-completeness pin."),
    ("verdict", f"It satisfies ASVS `{_REQ}`."),
    # A modal binds a marked identifier whatever follows the verdict, and chains into a record verb.
    ("verdict", f"ASVS {_REQ} would not be met by this change."),
    ("verdict", f"ASVS {_REQ} cannot {_PASS} at present."),
    ("verdict", f"ASVS {_REQ} will remain {_PARTIAL}."),
    ("verdict", f"ASVS {_REQ} will stay {_PARTIAL} after this."),
    # Markdown `_` emphasis does not unbind a word, and a typographic apostrophe is a contraction.
    ("gap", f"ASVS {_REQ} _lacks_ a row-completeness pin."),
    ("gap", f"_cell_ {_REQ} omits it."),
    ("verdict", f"It _satisfies_ cell {_REQ}."),
    ("verdict", f"Cell {_REQ}: the re-read _held_ it at {_PARTIAL} near the limb."),
    ("verdict", f"ASVS {_REQ} doesn’t {_PASS}."),
    # An identifier cell listed with "&", "+", a space or "And", or with its lead set off by markup.
    ("verdict", f"| {_REQ} & {_REQ_B} | the outbound limb | {_PARTIAL} |"),
    ("verdict", f"| {_REQ} + {_REQ_B} | the outbound limb | {_PARTIAL} |"),
    ("verdict", f"| {_REQ} {_REQ_B} | the outbound limb | {_PARTIAL} |"),
    ("verdict", f"| {_REQ} And {_REQ_B} | the outbound limb | {_PARTIAL} |"),
    ("verdict", f"| ASVS `{_REQ}` | the outbound limb | {_PARTIAL} |"),
    ("verdict", f"| **ASVS** {_REQ} | the outbound limb | {_PARTIAL} |"),
    ("verdict", f"| ASVS V{_REQ} | the outbound limb | {_PARTIAL} |"),
    # A verdict cell set off by a colon, a parenthesis or a dash: bare, beside a marked identifier;
    # after "unchanged", beside any.
    ("verdict", f"| ASVS {_REQ} | the outbound limb | {_PARTIAL}: no build reaches it |"),
    ("verdict", f"| ASVS {_REQ} | the outbound limb | {_PARTIAL} (no build reaches it) |"),
    ("verdict", f"| ASVS {_REQ} | the outbound limb | {_PARTIAL} -- no build |"),
    ("verdict", f"| {_REQ} | the outbound limb | unchanged - {_PARTIAL}. |"),
    ("verdict", f"| {_REQ} | unchanged, {_PARTIAL} |"),
    # A modal chained into a record verb is as strong as the verb, even beside a version.
    ("verdict", f"Applies to {_REQ} which will stay {_PARTIAL}."),
    ("verdict", f"{_REQ} should stay {_PARTIAL} after this merges."),
    # A negated auxiliary, a passive with a state verdict ending its clause, and a past-tense gap.
    ("verdict", f"ASVS {_REQ} isn't met."),
    ("verdict", f"ASVS {_REQ} has not been met."),
    ("verdict", f"ASVS {_REQ} is no longer met."),
    ("gap", f"ASVS {_REQ} lacked a pin."),
    ("gap", f"The ASVS {_REQ} evidence omitted the outbound limb."),
    # A nested or chained call in backticks is a code symbol.
    ("map", f"The ASVS {_REQ} binding needs `example_aad(key())` on every call."),
    ("map", f"The ASVS {_REQ} binding needs `load_example(path).routers` on every call."),
]
#: The negative controls for the residue rules: the same shapes beside a version or a plain number.
_PR_RESIDUE_MUST_STAY_QUIET = [
    # A plain snake_case name beside a number the text does not mark as a requirement.
    f"The advisory's own `first_patched_version` field says **{_REQ_B}**, and {_REQ_B} is published.",
    f"Old rule ({_REQ_B}, checked here): `revoked` gets in and `delta_revoked` is refused.",
    # A domain and a documentation file name in backticks are not code.
    f"`resolved` points at `registry.example.org`; {_REQ_B} was published last week.",
    f"`EXAMPLE.md` names {_REQ_B} in its heading.",
    # A modal after a version is not a verdict.
    f"ldap3 2.9.1 cannot {_PASS} the probe without the patch.",
    f"Python 3.14.6 would {_FAIL} the collection step.",
    # Hold and omit without a requirement number.
    f"The buffer holds {_PARTIAL} frames until the reader drains them; the parser omits blank lines.",
    # An HL7 version has the requirement shape and no lead in engine prose. Beside it, "pass" and
    # "fail" are verbs with an object, CI prose keeps failing, a helper is code but no map, and
    # "incomplete" or "omits" is no gap.
    "Callers can pass 2.9.1 explicitly when the version field is blank.",
    "The parser will pass 2.9.2 through unchanged.",
    "It could fail 2.9.1 inputs that carry no version field.",
    "Clients on 9.9.98 will fail the handshake without this.",
    "Hosts still on 2.9.1 would fail to parse the batch.",
    "Updates 2.9.1 to pass Z-segments through unchanged.",
    "Treat 2.9.1 as na when the field is empty.",
    "The 2.9.1 batch test kept failing on Windows until the fix.",
    "Accepts 2.9.1 and 2.9.2; `parse_example(...)` reads the version field.",
    "| 2.9.1 | `_split_example_batch` | covered |",
    "Fixes incomplete reads in the framer for 2.9.1 batches.",
    "Messages on 2.9.1 lack the Z segment, so the router omits it.",
    "Bumps `example_pkg` from V2.9.1 to V2.9.2.",
    # A hold verb before an ordinary noun, a preposition after a verdict verb, and a modal before a
    # verdict that does not end its clause, beside an HL7 version, are engine prose.
    f"For 2.5.1 batches the framer holds {_PARTIAL} frames until EOF.",
    f"On 2.3.1 feeds the store kept {_PARTIAL} batches for replay.",
    f"Messages tagged 2.5.1 will {_FAIL} on the strict validator.",
    f"Messages tagged 2.5.1 would {_FAIL} under the strict profile.",
    f"Support for 2.5.1 will be {_PARTIAL} in this release.",
    # A hedge, a passive or "are now" before a CI verb, a hold "at" before an ordinary noun, a
    # possessive version, and a conformance table opening a cell with a bare verdict.
    f"Messages tagged 2.5.1 still {_FAIL} strict validation.",
    f"Inputs on 2.3.1 already {_PASS} the strict profile.",
    "Batches tagged 2.5.1 were failing on Windows.",
    "Batches tagged 2.5.1 have been failing on Windows.",
    "Batches tagged 2.5.1 are now passing.",
    f"For 2.5.1 feeds the parser is capped at {_NA} fields.",
    f"The 2.5.1 batch was held at {_PASS} 2 of the reader.",
    "Adds 2.5.1's `ADT_A01` and `ORU_R01` structures.",
    "Updates the parser to satisfy 2.5.1's MSH-12 rule.",
    "The 2.5.1's segment grammar lacks ZPD, so the router omits it.",
    f"| 2.5.1 | ADT^A01 | {_PASS.title()} (12 messages) |",
    f"| 2.5.1 | ADT^A01 | {_FAIL}: segment order |",
    # A file name in backticks is not code, whatever its case.
    f"The `example_a01.hl7` sample and `README.MD` are read under ASVS {_REQ}.",
]


@pytest.mark.parametrize(("kind", "line"), _PR_RESIDUE_MUST_FIRE)
def test_a_pr_body_phrasing_the_first_detector_missed_is_flagged(sf, kind: str, line: str) -> None:
    """BACKLOG #3364's residue: each phrasing went through engine PR 2448's detector unflagged."""
    assert kind in _pr_kinds(sf, f"Context above.\n\n{line}\n\nContext below."), line


#: Table cells with markup or an apostrophe inside them. Engine PR 2448's detector flags the first six
#: rows, so a cell read only with its markup deleted ("stayspartial") was a regression against it; the
#: rest are this detector's own shapes, which a cell read only one way loses.
_PR_CELL_MARKUP_MUST_FIRE = [
    f"| ASVS {_REQ} | the outbound limb | stays`{_PARTIAL}` |",
    f"| {_REQ} | the outbound limb | stays`{_PARTIAL}` |",
    f"| {_REQ} | the outbound limb | stays'{_PARTIAL} |",
    f'| {_REQ} | the outbound limb | "stays"{_PARTIAL} |',
    f"| {_REQ} | the outbound limb | stays_{_PARTIAL}_ |",
    f"| {_REQ} | the outbound limb | stays*{_PARTIAL}* |",
    f"| ASVS {_REQ} | the outbound limb | isn't met |",
    f"| ASVS {_REQ} | it's {_PARTIAL} |",
    f"| V'{_REQ} | the outbound limb | {_PARTIAL} |",
    f"| #1, #2 | {_REQ}, {_REQ_B} | unchanged, `{_PARTIAL}`. |",
]


@pytest.mark.parametrize("row", _PR_CELL_MARKUP_MUST_FIRE)
def test_a_table_cell_is_read_both_trimmed_and_with_its_markup_deleted(sf, row: str) -> None:
    """A cell is read with its markup trimmed from its ends, as engine PR 2448 read it, and again with
    all of it deleted, so neither reading loses what the other catches."""
    assert "verdict" in _pr_kinds(sf, row), row


#: BACKLOG #3364 step 4: the prose phrasings engine PR 2845's detector still missed, one group per lettered
#: item of that step. Each fires with the kind it is listed under. The step lists them as examples, so
#: the group is a sample of each shape, not the set of every phrasing of it.
_MET = "met"
_PR_STEP4_MUST_FIRE: list[tuple[str, str, str]] = [
    # (a) A cell whose closing markup sits before a full stop.
    ("a", "verdict", f"| {_REQ} | the outbound limb | stays`{_PARTIAL}`. |"),
    ("a", "verdict", f"| ASVS {_REQ} | the outbound limb | isn't **{_MET}**. |"),
    # (b) A cell padded with a tab or a no-break space, behind a spacer cell.
    ("b", "verdict", f"| {_REQ} | the limb |\tisn't {_MET}\t|"),
    ("b", "verdict", f"| {_REQ} | the limb |\u00a0isn't {_MET}\u00a0|"),
    ("b", "verdict", f"| {_REQ} | the limb |\tisn't **{_MET}**\t|"),
    ("b", "verdict", f"| {_REQ} | the limb |\tstays`{_PARTIAL}`\t|"),
    # (c) An ASVS version between "ASVS" and the identifier, and the version-prefixed form.
    ("c", "gap", f"ASVS 5.0 {_REQ} lacks a row-completeness pin."),
    ("c", "verdict", f"ASVS v5.0.0 V{_REQ} would not be {_MET} by this change."),
    ("c", "gap", f"v5.0.0-{_REQ} lacks a row-completeness pin."),
    # (d) The second identifier of a list.
    ("d", "verdict", f"ASVS {_REQ} and {_REQ_B} cannot {_PASS} under this design."),
    ("d", "verdict", f"ASVS {_REQ}, {_REQ_B} or {_REQ} would not be {_MET} here."),
    # (e) A hedge word one list takes and another does not, and a word inside "has ... been".
    ("e", "verdict", f"ASVS {_REQ} will likely stay {_PARTIAL}."),
    ("e", "verdict", f"ASVS {_REQ} was never {_MET}."),
    ("e", "verdict", f"ASVS {_REQ} has since been {_MET}."),
    ("e", "verdict", f"ASVS {_REQ} has still been {_MET}."),
    ("e", "verdict", f"ASVS {_REQ} has now been {_MET}."),
    ("e", "verdict", f"ASVS {_REQ} has never been {_MET}."),
    ("e", "verdict", f"ASVS {_REQ} has not yet been {_MET}."),
    ("e", "verdict", f"ASVS {_REQ} has already been {_MET}."),
    ("e", "verdict", f"ASVS {_REQ} will probably remain {_PARTIAL}."),
    # (f) The written-out negation.
    ("f", "verdict", f"ASVS {_REQ} is not {_PARTIAL}."),
    ("f", "verdict", f"ASVS {_REQ} was not {_PARTIAL}."),
    # (g) Underscore emphasis on a move verb.
    ("g", "verdict", f"_Downgrades_ ASVS {_REQ} to {_PARTIAL}."),
    ("g", "verdict", f"__Moves__ the ASVS {_REQ} cell to {_PASS}."),
    # (h) A cell that opens with a verdict and goes on in words.
    ("h", "verdict", f"| ASVS {_REQ} | the outbound limb | stays {_PARTIAL} until #1 |"),
    ("h", "verdict", f"| ASVS {_REQ} | the outbound limb | {_PARTIAL} pending the follow-up |"),
    ("h", "verdict", f"| ASVS {_REQ} | the outbound limb | {_PARTIAL} because of #1 |"),
    ("h", "verdict", f"| ASVS {_REQ} | the outbound limb | is {_PARTIAL} for now |"),
    # (i) A comma before "which stays partial": the case the _PR_STRONG_VERB comment names.
    ("i", "verdict", f"Applies to {_REQ}, which stays {_PARTIAL}."),
    ("i", "verdict", f"ASVS {_REQ}, which is {_PARTIAL} today."),
    # (j) A header row that names the column ASVS marks the column under it.
    (
        "j",
        "verdict",
        f"| ASVS | Note | Result |\n| --- | --- | --- |\n| {_REQ} | the limb | {_PASS.title()} (12 messages) |",
    ),
    (
        "j",
        "verdict",
        f"| Test | ASVS ID | Note | Result |\n|:--|:--|:--|:--|\n| a | {_REQ} | x | {_PASS.title()} (12 messages) |",
    ),
]
#: The quiet controls for step 4: each is the shape above with the part that made it a record taken out
#: or put beside a version, so a rule widened until it flagged everything would fail here.
_PR_STEP4_MUST_STAY_QUIET: list[tuple[str, str]] = [
    ("a", f"| 2.5.1 | ADT^A01 | **{_PASS.title()}**. |"),
    ("b", f"| {_REQ} | the limb |\tneeds a second signal\t|"),
    ("b", f"| 2.5.1 | ADT^A01 |\u00a0{_PASS.title()} (12 messages)\u00a0|"),
    ("c", f"Python 3.14 {_REQ_B} lacks wheels for this platform."),
    ("c", f"ASVS 5.0 is the new baseline; {_REQ_B} ships with next week's release."),
    ("d", f"Python 2.9.1 and {_REQ_B} cannot {_PASS} the probe without the patch."),
    ("e", f"Inputs on 2.5.1 will likely {_FAIL} the strict profile."),
    ("e", "Batches tagged 2.5.1 have since been failing on Windows."),
    ("e", "Batches tagged 2.5.1 were never failing before this."),
    ("f", "Batches on 2.5.1 are not failing."),
    ("g", "_Updates_ 2.9.1 to pass Z-segments through unchanged."),
    ("h", f"| 2.5.1 | ADT^A01 | {_PASS.title()} for 12 messages |"),
    ("h", f"| 2.5.1 | the parser | is {_PARTIAL} frames until EOF |"),
    # A cell that goes on in words after a state verb is CI prose beside an unmarked HL7 version.
    ("h", "| 2.5.1 | ADT^A01 | is passing for the nightly |"),
    ("h", "| 2.5.1 | the strict suite | was failing since the last merge |"),
    ("h", f"| 3.2.1 | lxml | stays {_PARTIAL} for now |"),
    ("i", "Updates 2.9.1, which is pass-through for Z segments."),
    ("i", "Bumps lxml to 5.1.2, which passes the strict suite."),
    (
        "j",
        f"| Version | Note | Result |\n| --- | --- | --- |\n| 2.5.1 | the limb | {_PASS.title()} (12 messages) |",
    ),
    (
        "j",
        f"| Test | ASVS | Result |\n|---|---|---|\n| 2.5.1 | the limb | {_PASS.title()} (12 messages) |",
    ),
    (
        "j",
        f"| ASVS | Note |\n|---|---|\n| a | b |\n\nA second table:\n\n| 2.5.1 | the limb | {_PASS.title()} (12 messages) |",
    ),
]


@pytest.mark.parametrize(
    ("item", "kind", "body"),
    _PR_STEP4_MUST_FIRE,
    ids=[f"{item}-{i}" for i, (item, _, _) in enumerate(_PR_STEP4_MUST_FIRE)],
)
def test_a_pr_body_phrasing_step_four_listed_is_flagged(
    sf, item: str, kind: str, body: str
) -> None:
    """BACKLOG #3364 step 4, items (a) to (j): each phrasing went through engine PR 2845's detector."""
    assert kind in _pr_kinds(sf, body), (item, body)


@pytest.mark.parametrize(
    ("item", "body"),
    _PR_STEP4_MUST_STAY_QUIET,
    ids=[f"{item}-{i}" for i, (item, _) in enumerate(_PR_STEP4_MUST_STAY_QUIET)],
)
def test_the_step_four_rules_leave_versions_and_other_tables_alone(
    sf, item: str, body: str
) -> None:
    assert sf.scan_pr_body(body) == [], (item, body)


_HEADER_TABLE_ROW = f"| {_REQ} | the limb | {_PASS.title()} (12 messages) |"
_HEADER_TABLE_ONE = f"| ASVS | Note | Result |\n| --- | --- | --- |\n{_HEADER_TABLE_ROW}"
#: The bodies of the header-table test below, by name, so the frozen-main guard reads them too.
_PR_HEADER_TABLE_BODIES = {
    "one": _HEADER_TABLE_ONE,
    "two": _HEADER_TABLE_ONE
    + "\n\n| Version | Note | Result |\n| --- | --- | --- |\n"
    + _HEADER_TABLE_ROW,
    "placeholder": f"| ASVS | Note | Result |\n|---|---|---|\n| - | - | - |\n{_HEADER_TABLE_ROW}",
    "wrong-column": (
        f"| ASVS | Note |\n| --- | --- |\n| the limb | {_REQ} | x | {_PASS.title()} (12 messages) |"
    ),
}


def test_a_header_row_marks_only_its_own_table_and_column(sf) -> None:
    """The ASVS header of one table must not mark the identifiers of the next one, or of prose below."""
    bodies = _PR_HEADER_TABLE_BODIES
    assert sf.scan_pr_body(bodies["one"]), "the control must fire, or the next two assert nothing"
    assert sf.scan_pr_body(bodies["two"]) == [f"pr-body:3: {sf.PR_BODY_REASONS['verdict']}"]
    # A placeholder row of dashes is data, not a delimiter, and must not wipe the marked column.
    assert sf.scan_pr_body(bodies["placeholder"]) == [f"pr-body:4: {sf.PR_BODY_REASONS['verdict']}"]
    assert sf.scan_pr_body(bodies["wrong-column"]) == []


#: BACKLOG #3364 steps 5 to 12, engine PR 2893's open review findings. Every body fires with the kind
#: it is listed under. Most steps have a quiet control below: the same shape with what made it a record
#: taken out. Step 8 has none: the loose column reading, which keeps main's column marks, still
#: shifts a column at an escaped pipe where main did.
_HEAD = "| ASVS | Note | Result |\n|---|---|---|\n"
_ROW = f"| {_REQ} | the limb | {_PASS.title()} (12 messages) |"
_PR_FINDINGS_MUST_FIRE: list[tuple[str, str, str]] = [
    # Step 5: a dash-only placeholder row after the first data row is data, not a delimiter, so the
    # row above it is not re-read as a header and the ASVS column stays marked.
    ("5", "verdict", f"{_HEAD}| a | b | c |\n| - | - | - |\n{_ROW}"),
    ("5", "verdict", f"{_HEAD}| a | b | c |\n|---|---|---|\n{_ROW}"),
    # Step 6: a rule or a dash-only paragraph after a table is not a delimiter, so the table's last row
    # is not read as a header.
    ("6", "verdict", f"{_HEAD}{_ROW}\n---"),
    ("6", "verdict", f"{_HEAD}{_ROW}\n- - -"),
    ("6", "verdict", f"{_HEAD}{_ROW}\n\n---"),
    # Step 8: an escaped pipe inside a cell is not a cell edge, in the header or in the row.
    # A spacer cell keeps the verdict away from the identifier, so only the column can mark it.
    ("8", "verdict", f"| a \\| b | ASVS | Note | Result |\n|---|---|---|---|\n| x {_ROW}"),
    ("8", "verdict", f"| x | ASVS | Note | Result |\n|---|---|---|---|\n| a \\| b {_ROW}"),
    # Step 10's must-fire controls: the shapes of the six bodies engine PR 2893's review named, beside
    # a marked identifier. Step 10 is open (_PR_2893_FALSE_POSITIVE_BODIES says why).
    ("10", "verdict", f"| ASVS {_REQ} | the parser | never fails |"),
    ("10", "verdict", f"ASVS {_REQ} is cited; the row is not failing now."),
    ("10", "verdict", f"| ASVS {_REQ} | the parser | has never been failing |"),
    # Step 11: emphasis on the relative pronoun after a comma.
    ("11", "verdict", f"ASVS {_REQ}, _which_ stays {_PARTIAL}."),
    ("11", "verdict", f"ASVS {_REQ}, **that** is {_PARTIAL}."),
    # Step 11: an ASVS major version between "ASVS" and the identifier.
    ("11", "gap", f"ASVS v5 {_REQ} lacks a row-completeness pin."),
    ("11", "gap", f"ASVS 5 {_REQ} lacks a row-completeness pin."),
    # Step 11: header spellings that name the column ASVS.
    ("11", "verdict", f"| ASVS: | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", "verdict", f"| ASVS reference | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", "verdict", f"| Requirement (ASVS) | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", "verdict", f"| OWASP ASVS | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", "verdict", f"| ASVS_ID | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", "verdict", f"| ASVS-ID | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", "verdict", f"| ASVS # | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", "verdict", f"| Control (ASVS) | Note | Result |\n|---|---|---|\n{_ROW}"),
    # "No." before "ASVS" is the abbreviation for "number", not a disclaimer.
    ("11", "verdict", f"| Ref No. (ASVS) | Note | Result |\n|---|---|---|\n{_ROW}"),
    # Step 11: underscore emphasis at the word-boundary sites that bind.
    ("11", "verdict", f"_{_PARTIAL}_: {_REQ}"),
    ("11", "verdict", f"For {_REQ} the _cell_ stays {_PARTIAL}."),
    ("11", "verdict", f"For {_REQ} the vault _re-score_ to {_PASS} landed."),
    ("11", "gap", f"The _gap_ keeps {_REQ} open."),
    ("11", "map", f"{_REQ} is enforced in _pkg/example_guard.py_."),
    ("11", "map", f"{_REQ} is enforced in _messagefoundry.example_guard_."),
    ("11", "map", f"{_REQ} is enforced at _github.com/example/repo/blob/main/x.txt_"),
    ("11", "map", f"{_REQ} is enforced in _scripts/example_guard_ now."),
    # Step 11: a zero-width character around a cell, around the verdict or the identifier.
    ("11", "verdict", f"| ASVS {_REQ} | the limb |\u200bisn't {_MET}\u200b|"),
    ("11", "verdict", f"| ASVS {_REQ} | the limb |\ufeff{_PARTIAL}\u2060|"),
    # Any invisible format character, not only a zero-width one: a left-to-right mark.
    ("11", "verdict", f"| ASVS {_REQ} | the limb |{chr(0x200E)}stays {_PARTIAL}{chr(0x200E)}|"),
    ("11", "verdict", f"| {chr(0x200B)}ASVS `{_REQ}`{chr(0x200B)} | the limb | {_PARTIAL} |"),
    ("11", "verdict", f"|\u200b{_REQ}\u200b| the limb | stays {_PARTIAL} |"),
    # A tag character from outside the Basic Multilingual Plane, and invisible characters inside a
    # cell, a header cell or a prose word rather than around them.
    ("11", "verdict", f"| ASVS {_REQ} | the limb |{chr(0xE0020)}stays {_PARTIAL}{chr(0xE0020)}|"),
    ("11", "verdict", f"| ASVS{chr(0x200B)}{_REQ} | the limb | {_PASS.title()} (12 messages) |"),
    ("11", "verdict", f"| AS{chr(0x200B)}VS | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", "gap", f"AS{chr(0x200D)}VS {_REQ} lacks a row-completeness pin."),
    # Default-ignorable characters outside the format category: a combining grapheme joiner and
    # variation selectors, inside a word.
    ("11", "gap", f"AS{chr(0x034F)}VS {_REQ} lacks a row-completeness pin."),
    ("11", "verdict", f"| ASVS {_REQ} | the limb | stays par{chr(0xFE0F)}tial |"),
    ("11", "verdict", f"| ASVS {_REQ} | the limb | stays par{chr(0xE0100)}tial |"),
    # Step 5: a pipe line above the header renders as a paragraph, and the table starts at the header.
    ("5", "verdict", f"| Summary |\n{_HEAD}{_ROW}"),
    # Step 8: a header whose first cell is empty keeps its columns where they render.
    ("8", "verdict", f"|| ASVS | Note | Result |\n|---|---|---|---|\n| x {_ROW}"),
    # An unmarked verdict-state cell after "never", and "row" before a verdict state, bind.
    ("10", "verdict", f"| {_REQ} | the parser | never {_MET} |"),
    ("10", "verdict", f"The row stays {_PARTIAL} for {_REQ}."),
    ("10", "verdict", f"The row is not {_PARTIAL} for {_REQ}."),
    # Review round 3's three losses against main, each flagged by main. A header and delimiter pair
    # GFM rejects (a cell-count mismatch, a delimiter cell that is not dashes) renders no table, so the
    # valid ASVS header below it in the same run still marks its column.
    ("5", "verdict", f"| Version | Note |\n|---|---|---|\n| a | b | c |\n{_HEAD}{_ROW}"),
    (
        "5",
        "verdict",
        f"| Version | Note | Result |\n| - - | - - | - - |\n| a | b | c |\n{_HEAD}{_ROW}",
    ),
    # A line holding only an invisible character is not blank, and one before "- " or "#" starts no
    # list item or heading, so the paragraph stays whole.
    ("11", "map", f"{_REQ} is enforced in\n{chr(0x200B)}\npkg/example_guard.py."),
    ("11", "map", f"{_REQ} is enforced\n{chr(0x200B)}- in pkg/example_guard.py."),
    ("11", "map", f"{_REQ} is enforced\n{chr(0x200B)}# in pkg/example_guard.py."),
    # "the row" then a CI verb that is not negated binds an unmarked identifier too, so this body would
    # bind with no mark and does not test _PR_MARK_AFTER; the negated body after it does.
    ("10", "verdict", f"{_REQ}: the row is failing."),
    # Punctuation binding the identifier to "the row" marks it (_PR_MARK_AFTER). Nothing exempts this
    # body unmarked either, so it pins only that the marked form still binds.
    ("10", "verdict", f"{_REQ}: the row is not failing."),
    # Review pass 3's new loss: with no GFM-valid pair in the run, a mistyped delimiter under an
    # ASVS header still marks the column, as main read it.
    ("5", "verdict", f"| ASVS | Note | Result |\n|---|---|\n{_ROW}"),
    ("5", "verdict", f"| ASVS | Note | Result |\n| - - | - - | - - |\n{_ROW}"),
    # Review round-edb619bb's losses against main, restored by uniting each GFM reading with main's: an invisible
    # character that is the only separator, a no-break-space line inside a table, and an ASVS table
    # stacked under another with no blank line.
    ("11", "map", f"{_REQ}{chr(0x200B)}is enforced in pkg/example_guard.py."),
    ("11", "verdict", f"{_REQ}: {_PARTIAL}{chr(0x200B)}pending review."),
    ("9", "verdict", f"{_HEAD}{chr(0xA0)}\n{_ROW}"),
    ("5", "verdict", f"| Version | Note | Result |\n|---|---|---|\n| a | b | c |\n{_HEAD}{_ROW}"),
    # A record verb after "the row" names a verdict even where the first one is a CI verb.
    ("10", "verdict", f"{_REQ} is listed here; the row went from failing to {_PARTIAL}."),
    ("10", "verdict", f"{_REQ} is listed here; the row re-scored as failing."),
    # A cell opening with "unchanged" or a record verb states a verdict, "never" or not.
    ("10", "verdict", f"| {_REQ} | x | unchanged, never failing. |"),
    ("10", "verdict", f"| {_REQ} | x | stays never failing |"),
    # A version-lead word in underscore emphasis is no lead, as main reads it, so the id stays one.
    ("11", "gap", f"This applies _to_ {_REQ}, which is not yet implemented."),
    ("11", "gap", f"_Section_ {_REQ} is not yet implemented."),
    # Review round-6565ebbf's new loss: "row" with a CI verb that is not negated still binds an
    # unmarked id, whether "the row" follows the id directly or a clause away.
    ("10", "verdict", f"For {_REQ} the row is failing."),
    ("10", "verdict", f"{_REQ} was reviewed; the row is still failing."),
    # A blank line is a whole GFM line, between "\n", "\r\n" or "\r": a form feed or a line separator at
    # a row's end opens no blank line, so the table stays whole. A ">" then a no-break space is a quoted
    # line, not a blank one.
    ("9", "verdict", f"{_HEAD}| a | b | c |{chr(0x0C)}\n{_ROW}"),
    ("9", "verdict", f"{_HEAD}| a | b | c |{chr(0x2028)}\n{_ROW}"),
    (
        "9",
        "verdict",
        f"> {_HEAD.replace(chr(10), chr(10) + '> ')}| a | b | c |\n>{chr(0xA0)}\n> {_ROW}",
    ),
    # Review round-35a5429f's new loss: a table whose lines a bare separator joins, with no "\n", is
    # still read as main read it, a line per separator.
    ("5", "verdict", _HEAD.replace(chr(10), chr(0x2028)) + _ROW),
    ("5", "verdict", _HEAD.replace(chr(10), chr(0x0C)) + _ROW),
    # Review round-23e833d96f's new loss: two separators in a row open an empty line inside a GFM line
    # with content, which is not a blank line, so the table is not ended there.
    (
        "9",
        "verdict",
        _HEAD.replace(chr(10), chr(0x2028)) + f"| a | b | c |{chr(0x0C)}{chr(0x2028)}{_ROW}",
    ),
    ("9", "verdict", f"Intro.{chr(0x85) * 2}" + _HEAD.replace(chr(10), chr(0x85) * 2) + _ROW),
    # Review round-6926d71d81 finding 1, each flagged by main: a quote-marker-only line under a quoted
    # row inside an unquoted ASVS table is not a blank line, lone, padded or doubled, with the row
    # below it unquoted or quoted. Only a quoted table ends at one.
    *(
        ("9", "verdict", f"{_HEAD}> | a | b | c |\n{marker}\n{below}{_ROW}")
        for marker in (">", "  >  ", "> >")
        for below in ("", "> ")
    ),
    # A quoted table whose row below the quote-marker-only line is unquoted keeps the mark too.
    ("9", "verdict", f"> {_HEAD.replace(chr(10), chr(10) + '> ')}| a | b | c |\n>\n{_ROW}"),
    # Finding 3, each flagged by main: a blank line between an ASVS header and its delimiter, or
    # between the delimiter and the first data row, lone, padded or doubled, ends nothing, unquoted or
    # quoted.
    *(
        ("9", "verdict", body)
        for blank in ("", "  ", "\n")
        for body in (
            f"| ASVS | Note | Result |\n{blank}\n|---|---|---|\n{_ROW}",
            f"{_HEAD}{blank}\n{_ROW}",
        )
    ),
    ("9", "verdict", f"> | ASVS | Note | Result |\n>\n> |---|---|---|\n> {_ROW}"),
    ("9", "verdict", f"> {_HEAD.replace(chr(10), chr(10) + '> ')}\n> {_ROW}"),
    # Review round-b3037cd314's losses, each flagged by main: a quote-marker-only line ends a table
    # only where every row since the last non-row unit is quoted. An unquoted header above a blank
    # line, an unquoted header under a quoted pipe line, an unquoted delimiter or data row, and a
    # ">" behind four spaces or a tab (a code line, not a quote) each keep the mark.
    ("9", "verdict", f"{_HEAD}\n> | a | b | c |\n>\n> {_ROW}"),
    ("9", "verdict", f"| ASVS | Note | Result |\n\n> |---|---|---|\n> | a | b | c |\n>\n> {_ROW}"),
    ("9", "verdict", f"> | Summary |\n{_HEAD}> | a | b | c |\n>\n> {_ROW}"),
    ("9", "verdict", f"> | ASVS | Note | Result |\n|---|---|---|\n> | a | b | c |\n>\n> {_ROW}"),
    (
        "9",
        "verdict",
        f"> | ASVS | Note | Result |\n> |---|---|---|\n| a | b | c |\n> | d | e | f |\n>\n> {_ROW}",
    ),
    *(
        (
            "9",
            "verdict",
            f"{lead}> | ASVS | Note | Result |\n{lead}> |---|---|---|\n{lead}> | a | b | c |\n"
            f"{lead}>\n{lead}> {_ROW}",
        )
        for lead in ("    ", "\t")
    ),
    # Review round-25a1cb2995's losses, each flagged by main. A ">" after a separator only
    # str.splitlines ends a line at lies inside a GFM line, so it is content, not a quote marker, and
    # the table is not a quoted one, whether the separator leads the row below or the header.
    *(
        (
            "9",
            "verdict",
            f"> {_HEAD.replace(chr(10), chr(10) + '> ')}| a | b | c |\n>\n{chr(code)}> {_ROW}",
        )
        for code in (0x0C, 0x85, 0x2028)
    ),
    *(
        (
            "9",
            "verdict",
            f"Intro{chr(code)}> {_HEAD.replace(chr(10), chr(10) + '> ')}| a | b | c |\n>\n> {_ROW}",
        )
        for code in (0x0C, 0x85, 0x2028)
    ),
    # A cell that goes on past "never failing" keeps the row bound.
    ("10", "verdict", f"| {_REQ_B} | x | is never failing; {_PARTIAL} |"),
    ("10", "verdict", f"| {_REQ} | the parser | is never failing; stays failing |"),
    ("10", "verdict", f"| {_REQ} | the parser | is never failing; re-scored as failing |"),
    # Review round-4aa302cd29's losses, each flagged by main: a verdict that never needed the clause
    # stays, beside a version-lead word, "HL7" or a tight pair.
    (
        "10",
        "verdict",
        "| Tool | Check | Requirement | Verdict |\n|---|---|---|---|\n| uv | never fails | 1.2.3 | met |",
    ),
    (
        "10",
        "verdict",
        "| Job | CI | Req | Result |\n|---|---|---|---|\n| smoke-test | never passing | 1.2.3 | not met |",
    ),
    ("10", "verdict", "| unchanged, partial | na | smoke-test | never fails; | 1.2.4 |"),
    ("10", "verdict", "Per Python row is not failing 1.2.3 is met."),
    ("10", "verdict", "HL7 row is not failing V1.2.3 is met."),
    ("10", "verdict", "Build 3.14.0 | row is not failing pass, and\n1.2.3: fail closed."),
    ("10", "verdict", "[1.2.4] row is not failing pass and\n1.2.3: fail closed."),
    # A marked identifier is never exempt.
    ("10", "verdict", f"ASVS {_REQ}: the row is not failing but stays {_PARTIAL}."),
    ("10", "verdict", f"| ASVS {_REQ} | the parser | is never failing; the cell is failing |"),
]
#: The six bodies engine PR 2893's review named as false positives: CI prose and a component row about
#: HL7 v2.5.1. Main flags each. Step 10, which an earlier head of this branch built to drop them, was
#: removed, because it dropped a verdict only from a body exactly equal to one of the six, which no
#: real pull request body is. So each fires here as on main, and quieting them stays open on #3364.
_PR_2893_FALSE_POSITIVE_BODIES = (
    "| 2.5.1 | parser | never fails |",
    "The row is not failing for 2.5.1 batches.",
    "The row isn't passing for 2.5.1 batches.",
    "| 2.5.1 | parser | is never failing. |",
    "| 2.5.1 | parser | has never been failing |",
    "Since 2.5.1 the row is not failing.",
)
#: Bodies main flags through a "row is not failing" or "never fails" clause, or beside one. Each must
#: fire on main and on head, at main's lines, and a future repair of the PR 2893 false positives must
#: not drop them. The first ten are the Lander's hold on engine PR 2980 (blocking points 1 to 3); the
#: next nineteen are the bodies review rounds 4f580a28dd and b628ef8690 listed (the first two of them
#: say "tests pass" or "will fail" after the clause); then review rounds cc2be34b's and df2d868b's;
#: then the final round's on head 28bcdc34ef; then the six PR 2893 bodies, one-step edits of them,
#: and tables whose last row is one of them.
_PR_ROW_CLAUSE_MUST_FIRE: list[str] = [
    f"The row is not failing: {_REQ} here.",
    f"| never fails: {_REQ} |",
    f"| {_REQ} | x | never failing: {_REQ} |",
    f"For {_REQ} the row is not failing, it is {_PARTIAL}.",
    f"For {_REQ} the row is not failing, it is {_NA}.",
    f"For {_REQ} the row is not failing; ASVS score is {_PARTIAL}.",
    f"{_REQ} (the row is not failing) stays {_PARTIAL}.",
    f"{_REQ}, where the row is not failing, stays {_PARTIAL}.",
    f"{_REQ} -> the row is not failing.",
    f"{_REQ} | the row is not failing.",
    "The row is not failing for 2.5.1 batches; all twelve tests pass.",
    "The row is not failing for 2.5.1 batches and the gate will fail.",
    f"For {_REQ} the row is not failing but stays {_PARTIAL}.",
    f"For {_REQ} the row is not failing: {_PARTIAL}.",
    f"For {_REQ} the row is not passing yet, it remains {_PARTIAL}.",
    f"For {_REQ} the row is not failing yet and remains at failing in the vault.",
    f"| {_REQ} | parser | is never failing; remains at failing |",
    f"| {_REQ} | x | has never been failing, remains at failing |",
    f"| {_REQ} | the parser | is never failing; re-scored to failing |",
    f"| {_REQ} | the parser | is never failing; the cell is failing |",
    f"| {_REQ} | the parser | is never failing; the row is failing |",
    f"| {_REQ} | is never failing | re-scored to failing |",
    f"It stays {_PARTIAL} for now; see {_REQ}, where the row is not failing.",
    f"{_PARTIAL.title()} - for {_REQ} the row is not failing.",
    f"For {_REQ} the row is not failing on the nightly runner for the reasons in the follow-up"
    f" thread, but it stays {_PARTIAL}.",
    f"For {_REQ} the row is not failing: stays: failing.",
    f"For {_REQ} the row is not failing - stays - failing.",
    f"For {_REQ} the row is not failing -> failing.",
    f"For {_REQ} the row is not failing; it reads failing.",
    # Review round-cc2be34b: emphasis, a second sentence or line, record words that carry no verdict
    # word, a second identifier on a later line, and a record word in a shape's free slot.
    f"For {_REQ} the row is not failing, it is ___{_PARTIAL}___.",
    f"| {_REQ} | never fails | it is ___{_PARTIAL}___ |",
    f"For {_REQ} the row is not failing. It stays {_PARTIAL}.",
    f"For {_REQ} the row is not failing.\nIt stays {_PARTIAL}.",
    f"- For {_REQ} the row is not failing.\n  It stays {_PARTIAL}.",
    "The row is not failing for 2.5.1 batches.\nAll twelve tests pass.",
    f"For {_REQ} the row is not failing; it passed.",
    f"For {_REQ} the row is not failing (re-scored last week).",
    f"For {_REQ} the row is not failing; the verdict is unchanged.",
    f"| {_REQ} | never fails | stays at the same grade |",
    f"For {_REQ} the row is not failing for\nASVS 1.2.3.",
    "Since 2.5.1 the row is not failing for\nASVS 1.2.3.",
    f"For {_REQ} the row is not failing:\n1.2.3 here.",
    f"| {_REQ} | unchanged | never fails |",
    f"| {_REQ} | {_PARTIAL} | never fails |",
    f"| {_REQ} | graded | never fails |",
    f"The row is not failing for {_REQ} {_PARTIAL}.",
    f"The row is not failing for {_REQ} unchanged.",
    f"The row is not failing for ASVS {_REQ} batches.",
    f"The row is not failing for {_REQ}: batches.",
    f"Since {_REQ} the row is not failing: {_PARTIAL}.",
    f"Since **{_REQ}** the row is not failing.",
    # Review round-df2d868b: a requirement-shaped number other than 2.5.1, a gap or record word in
    # the component cell or after the number, and the shapes' near variants.
    "| 14.2.1 | logging | never passes |",
    "| 8.3.1 | session | is never passing |",
    "The row is not passing for 14.2.1 yet.",
    "The row is no longer failing for 8.3.1.",
    "Since 6.1.1, the row is not failing.",
    "| 8.3.1 | gap | never fails |",
    "The row is not failing for 2.5.1 gaps.",
    "| 6.1.1 | residual | is never passing |",
    "| 6.1.1 | rescore | never fails |",
    "| 6.1.1 | regraded | never fails |",
    "| 6.1.1 | vault | never passes |",
    "The row is not passing for 6.1.1 regrade.",
    "| 2.5.1 | satisfied | never fails |",
    "| 2.5.1 | meets | never fails |",
    "The row is no longer passing for 2.5.1 batches.",
    "Since 2.5.1, the row isn’t passing.",
    "| 2.5.1 | parser | never passes |",
    "| 2.5.1 | parser | is never passing |",
    "The row is not failing for 2.5.1.",
    "The row is not failing for 2.5.1 batches either.",
    # The last, unrepaired review round on head 28bcdc34ef: an earlier draft matched the PR 2893
    # shapes as two case-insensitive regular expressions against one rendered unit, so it dropped
    # bodies not among the six. A cross product of the shapes' alternatives, other case, a heading or
    # another unit around the shape, and rendering (a quote marker, an indent, a link, a wrapped line,
    # surrounding whitespace).
    "The row isn't failing for 2.5.1 batches.",
    "The row is not passing for 2.5.1 batches.",
    "Since 2.5.1 the row isn't failing.",
    "the row is not failing for 2.5.1 batches.",
    "THE ROW IS NOT FAILING FOR 2.5.1 BATCHES.",
    "since 2.5.1 the row is not failing.",
    "| 2.5.1 | Parser | never fails |",
    "| 2.5.1 | PARSER | NEVER FAILS |",
    f"## ASVS {_REQ}\n\nThe row is not failing for {_REQ} batches.",
    f"ASVS {_REQ}\n\n| {_REQ} | parser | never fails |",
    "> The row is not failing for 2.5.1 batches.",
    "    The row is not failing for 2.5.1 batches.",
    "> | 2.5.1 | parser | never fails |",
    "  | 2.5.1 | parser | never fails |",
    f"| [{_REQ}](https://example.com/asvs#{_REQ}) | parser | never fails |",
    "The row is not failing\nfor 2.5.1 batches.",
    "The row is not failing for 2.5.1 batches.\n",
    " The row is not failing for 2.5.1 batches.",
    *_PR_2893_FALSE_POSITIVE_BODIES,
    # One-step edits of each PR 2893 body: case, a lead or trailing character, a quote marker, an
    # indent, a second paragraph.
    *sorted(
        {
            edit
            for body in _PR_2893_FALSE_POSITIVE_BODIES
            for edit in (
                body.lower(),
                body.upper(),
                body.swapcase(),
                f" {body}",
                f"{body} ",
                f"{body}\n",
                f"\n{body}",
                f"> {body}",
                f"    {body}",
                f"{body}\n\nMore.",
                f"Intro.\n\n{body}",
            )
        }
        - set(_PR_2893_FALSE_POSITIVE_BODIES)
    ),
    # A PR 2893 row as a table's last row, under a header (a Requirement or Cell header, ASVS in
    # another column, or ASVS over the row's own column), or after a blank line that ends an ASVS
    # table (step 9), so the row reads unmarked, as the bare body does.
    *(
        f"{header}\n|---|---|---|\n| 2.5.1 | parser | never fails |"
        for header in (
            "| Requirement | Component | Result |",
            "| Cell | Component | Result |",
            "| Version | Component | ASVS |",
            "| ASVS | Component | Result |",
        )
    ),
    f"{_HEAD}| a | b | c |\n\n| 2.5.1 | parser | never fails |",
]
#: Step 9's deliberate drop: a blank line ends an ASVS-headed table, so a headerless pipe block after
#: it is unmarked.
_STEP9_QUIET_BODY = f"{_HEAD}| a | b | c |\n\n{_ROW}"
_PR_FINDINGS_MUST_STAY_QUIET: list[tuple[str, str]] = [
    # Step 5: the same placeholder rows under a header that does not name the column ASVS.
    ("5", f"| Version | Note | Result |\n|---|---|---|\n| a | b | c |\n| - | - | - |\n{_ROW}"),
    # Step 6: the same rules after a table whose header does not name the column ASVS.
    ("6", f"| Version | Note | Result |\n|---|---|---|\n{_ROW}\n---"),
    ("9", _STEP9_QUIET_BODY),
    ("9", f"{_HEAD}| a | b | c |\n\n| Version | Note | Result |\n|---|---|---|\n{_ROW}"),
    # Step 11: "ASVS" followed by a version and then a clause boundary marks nothing after it.
    ("11", f"ASVS 5; {_REQ_B} lacks wheels for this platform."),
    # Step 11: a header naming a requirement but not ASVS, or disclaiming ASVS, marks no column.
    ("11", f"| Requirement | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", f"| Version (not ASVS) | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", f"| Non-ASVS ref | Note | Result |\n|---|---|---|\n{_ROW}"),
    # Step 11: a snake_case join is not emphasis, so these words stay inside their names.
    ("11", "The `retry_gap` setting is read for 2.5.1 batches."),
    ("11", "The example_row_is_failing flag is set for 2.5.1 batches."),
    # Step 11: zero-width characters around a cell beside an unmarked HL7 version.
    ("11", f"| 2.5.1 | ADT^A01 |\u200b{_PASS.title()} (12 messages)\u200b|"),
    # Review round-23e833d96f's false positives against main, quiet on main: an emphasis underscore
    # after "/" starts no code root mid-path, and a negation before "ASVS" in a header cell, however
    # it is marked up or spaced, names no column.
    ("11", f"ASVS {_REQ} notes live in site/_tests/notes for reviewers."),
    ("11", f"{_REQ} notes: see site/_tests/notes."),
    ("11", f"| Version (**not** ASVS) | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", f"| Version (not an ASVS id) | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", f"| Version (not  ASVS) | Note | Result |\n|---|---|---|\n{_ROW}"),
    ("11", f"| Not in ASVS | Note | Result |\n|---|---|---|\n{_ROW}"),
]


@pytest.mark.parametrize(
    ("step", "kind", "body"),
    _PR_FINDINGS_MUST_FIRE,
    ids=[f"step{step}-{i}" for i, (step, _, _) in enumerate(_PR_FINDINGS_MUST_FIRE)],
)
def test_a_pr_body_shape_engine_pr_2893_review_found_is_flagged(
    sf, step: str, kind: str, body: str
) -> None:
    """BACKLOG #3364 steps 5 to 12. Most bodies went through engine PR 2893's detector unflagged. The
    rest are regression pins that main flags and an earlier round of this branch lost, or controls
    beside a marked identifier; each is commented where it is listed."""
    assert kind in _pr_kinds(sf, body), (step, body)


@pytest.mark.parametrize("body", _PR_ROW_CLAUSE_MUST_FIRE)
def test_a_row_clause_body_main_flags_fires_at_mains_lines(sf, sf_frozen_main, body: str) -> None:
    """Each body fires on main and on head, and head reports every hit main reports, at main's line.
    The six PR 2893 bodies are among them: nothing quiets them (_PR_2893_FALSE_POSITIVE_BODIES)."""
    main_hits = set(sf_frozen_main.scan_pr_body(body))
    assert main_hits, body
    assert main_hits <= set(sf.scan_pr_body(body)), body


def test_the_pr_2893_false_positive_bodies_fire_as_on_main(sf, sf_frozen_main) -> None:
    """Step 10 is removed, so each of the six bodies reports exactly what main reports."""
    assert len(set(_PR_2893_FALSE_POSITIVE_BODIES)) == 6
    assert not hasattr(sf, "_PR_STEP10_BODIES")
    for body in _PR_2893_FALSE_POSITIVE_BODIES:
        main_hits = sf_frozen_main.scan_pr_body(body)
        assert main_hits, body
        assert sf.scan_pr_body(body) == main_hits, body


@pytest.mark.parametrize(
    ("step", "body"),
    _PR_FINDINGS_MUST_STAY_QUIET,
    ids=[f"step{step}-{i}" for i, (step, _) in enumerate(_PR_FINDINGS_MUST_STAY_QUIET)],
)
def test_the_review_finding_repairs_leave_versions_and_other_tables_alone(
    sf, step: str, body: str
) -> None:
    assert sf.scan_pr_body(body) == [], (step, body)


# --- the frozen-main superset guard ------------------------------------------------------------------
#: origin/main's scanner before BACKLOG #3364's repairs, vendored byte for byte: blob 0c6e6127 of
#: scripts/security/scan_forbidden.py, last changed at main 0e10fb14c8. A vendored copy, not ``git show
#: origin/main``: once this branch merges, origin/main IS the head, and a CI checkout need not hold that
#: ref. Never edited; the blob id below pins it.
_FROZEN_MAIN_PATH = (
    Path(__file__).parent / "fixtures" / "scan_forbidden" / "scan_forbidden_main.py.txt"
)
_FROZEN_MAIN_BLOB = "0c6e61278ae36990232a06cf6d88dd2561ec65a0"
#: The separators str.splitlines ends a line at and GFM does not. GFM's own ("\r" twice is a blank
#: line) are step 9's to end a table at.
_SPLITLINES_ONLY = (0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029)
#: The bodies main flags that the repairs quiet ON PURPOSE, keyed by the body itself, each with its
#: ruled step. Every other hit main reports in the constructed set and the tracked corpus, head must
#: report too, at the same line.
_SUPERSET_EXCEPTIONS = {
    _STEP9_QUIET_BODY: "9",
}


def _frozen_main_bytes() -> bytes:
    # A Windows checkout may hold the fixture with CRLF; git stores it with LF.
    return _FROZEN_MAIN_PATH.read_bytes().replace(b"\r\n", b"\n")


@pytest.fixture(scope="module")
def sf_frozen_main():
    spec = importlib.util.spec_from_loader("scan_forbidden_frozen_main", loader=None)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    # Its module-level paths resolve against the scanner's own location, as they did on main.
    module.__file__ = str(_SCANNER_PATH)
    exec(compile(_frozen_main_bytes(), str(_FROZEN_MAIN_PATH), "exec"), module.__dict__)  # noqa: S102
    return module


def _superset_bodies() -> dict[str, str]:
    """The clean body, the bodies of every PR-body must-fire and must-stay-quiet list above (verdict,
    gap, map, version, residue, cell markup, step 4, steps 5 to 12, and the row-clause list)
    and of the header-table test,
    the review rounds' bodies, and tables whose lines each separator joins, one and two in a row, with
    and without a line ending after them. Bodies other tests build inline are not in it."""
    bodies: dict[str, str] = {"clean": _PR_CLEAN_BODY}
    plain = [
        *_PR_VERDICT_MUST_FIRE,
        *_PR_GAP_MUST_FIRE,
        *_PR_MAP_MUST_FIRE,
        *_PR_VERSION_MUST_STAY_QUIET,
        *(body for _, body in _PR_RESIDUE_MUST_FIRE),
        *_PR_RESIDUE_MUST_STAY_QUIET,
        *_PR_CELL_MARKUP_MUST_FIRE,
    ]
    bodies.update({f"plain-{i}": body for i, body in enumerate(plain)})
    bodies.update(
        {f"step4-fire-{i}-{item}": body for i, (item, _, body) in enumerate(_PR_STEP4_MUST_FIRE)}
    )
    bodies.update(
        {
            f"step4-quiet-{i}-{item}": body
            for i, (item, body) in enumerate(_PR_STEP4_MUST_STAY_QUIET)
        }
    )
    bodies.update({f"header-table-{name}": body for name, body in _PR_HEADER_TABLE_BODIES.items()})
    bodies.update({f"row-clause-{i}": body for i, body in enumerate(_PR_ROW_CLAUSE_MUST_FIRE)})
    bodies.update(
        {f"must-fire-{i}-step{s}": body for i, (s, _, body) in enumerate(_PR_FINDINGS_MUST_FIRE)}
    )
    bodies.update(
        {
            f"stay-quiet-{i}-step{s}": body
            for i, (s, body) in enumerate(_PR_FINDINGS_MUST_STAY_QUIET)
        }
    )
    marked_head = "| x | ASVS | Note | Result |\n|---|---|---|---|\n"
    bodies.update(
        {
            "reviewer-numbering": f"Intro{chr(0x2028)}more\n\n{_REQ} stays {_PARTIAL}.",
            "reviewer-numbering-invisible": (
                f"Intro{chr(0x2028)}more\n\n{_REQ} stays {_PARTIAL}.\n\n"
                f"ASVS {_REQ} stays{chr(0x200B)} {_PARTIAL}."
            ),
            "reviewer-row-not-passing": f"{_REQ} is listed; the row is not passing yet.",
            "reviewer-invisible-row": f"{marked_head}{chr(0x200B)}| {_REQ} | x | y | {_PASS} |",
            # Review round-a924aac4a5: a tag right after a split's trailing space, and an earlier
            # identifier a repair made bind in a hard-wrapped sentence.
            "reviewer-tag-space-tag": (
                f"<ul><li>Intro</li> <li>{_REQ} is not yet implemented</li></ul>"
            ),
            "reviewer-tag-space-tag-verdict": f"a -> b</p> <p>{_REQ} is {_PARTIAL}.",
            "reviewer-wrapped-gap": (
                f"This updates ASVS v5 {_REQ} and\n{_REQ_B}, which are not yet implemented."
            ),
            "reviewer-wrapped-verdict": (
                f"{_REQ}, _which_ stays {_PARTIAL}, and\n{_REQ_B} stays {_PARTIAL}."
            ),
            # A quote-marker-only line inside an unquoted ASVS table is not a blank line: main read
            # none, so it keeps the column marked, between rows, between the header and its
            # delimiter, and padded with spaces.
            "reviewer-quote-marker-line": f"{_HEAD}| a | b | c |\n>\n{_ROW}",
            "reviewer-quote-marker-header": f"| ASVS | Note | Result |\n>\n|---|---|---|\n{_ROW}",
            "reviewer-quote-marker-padded": f"{_HEAD}| a | b | c |\n  >  \n{_ROW}",
            "reviewer-escaped-pipe": (
                f"| Note | Version | ASVS | Result |\n|---|---|---|---|\n"
                f"| x \\| y | {_REQ} | z | {_PASS.title()} (12 messages) |"
            ),
        }
    )
    table = f"{_HEAD}| a | b | c |\n{_ROW}"
    for code in _SPLITLINES_ONLY:
        for count in (1, 2):
            join = chr(code) * count
            name = f"join-{code:04X}x{count}"
            bodies[name] = table.replace("\n", join)
            bodies[f"{name}-intro"] = f"Intro.{join}" + table.replace("\n", join)
            bodies[f"{name}-newline"] = table.replace("\n", join + "\n")
            bodies[f"{name}-crlf"] = table.replace("\n", join + "\r\n")
    return bodies


_SUPERSET_BODIES = _superset_bodies()


def test_the_frozen_main_scanner_is_the_vendored_blob() -> None:
    data = _frozen_main_bytes()
    blob = hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()
    assert blob == _FROZEN_MAIN_BLOB


def test_every_superset_exception_names_a_body_main_flags_and_head_drops(
    sf, sf_frozen_main
) -> None:
    """An exception that names no body, a body main does not flag, or a body where head now reports
    every hit main reports, excuses nothing and is stale."""
    listed = set(_SUPERSET_BODIES.values())
    for body in _SUPERSET_EXCEPTIONS:
        assert body in listed, body
        main_hits = set(sf_frozen_main.scan_pr_body(body))
        assert main_hits, body
        assert main_hits - set(sf.scan_pr_body(body)), body


@pytest.mark.parametrize("name", sorted(_SUPERSET_BODIES))
def test_the_head_reports_every_hit_main_reports_in_a_constructed_body(
    sf, sf_frozen_main, name: str
) -> None:
    """BACKLOG #3364: on each constructed body, head reports every hit main reports, at main's line
    number, except the deliberate step 9 drop named in _SUPERSET_EXCEPTIONS. A finite
    set: it pins these bodies, and a loss on a body outside it is not caught here."""
    body = _SUPERSET_BODIES[name]
    if body in _SUPERSET_EXCEPTIONS:
        pytest.skip(f"step {_SUPERSET_EXCEPTIONS[body]} drops this body's hits on purpose")
    lost = set(sf_frozen_main.scan_pr_body(body)) - set(sf.scan_pr_body(body))
    assert not lost, (name, sorted(lost))


def test_the_head_reports_every_hit_main_reports_in_the_tracked_markdown(
    sf, sf_frozen_main
) -> None:
    """The same superset over every tracked Markdown file, read as a pull request body: its bytes
    decoded with no newline translation, so a "\\r\\n" or "\\r" line ending reaches the scanner."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],  # noqa: S607
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    paths = [_REPO_ROOT / p.decode() for p in listed if p]
    # A positive control: an empty listing would pass the loop below vacuously.
    assert len(paths) > 100
    main_hits = 0
    lost: list[tuple[str, str]] = []
    unread: list[str] = []
    for path in paths:
        try:
            body = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            unread.append(str(path.relative_to(_REPO_ROOT)))
            continue
        before = set(sf_frozen_main.scan_pr_body(body))
        main_hits += len(before)
        lost += [
            (str(path.relative_to(_REPO_ROOT)), h) for h in before - set(sf.scan_pr_body(body))
        ]
    # A second control: main flags the docs' ASVS tables, so a corpus main reads clean measured nothing.
    assert main_hits > 0
    # Every tracked Markdown file is read: a file skipped here would be a body the guard never read.
    assert not unread, unread
    assert not lost, lost[:20]


#: Review round-7bf3e998ba's bodies, from an earlier windowed draft of the removed step 10, kept as
#: regression pins: each is slid across every offset of the 80-character window, and head must report
#: every hit main reports. Main flags each, through "failing: <id>" or "<id> stays partial".
_WINDOW_EDGE_SHAPES = [
    "Then narrow is not{pad}failing: 1.2.3 here.",
    "See `retry_row` is not{pad}failing: 1.2.3 here.",
    "See x__row is not{pad}failing: 1.2.3 here.",
    "The nar**row** is not failing:{pad}1.2.3 today.",
    "The nar`row` is not failing:{pad}1.2.3 today.",
    "The narrow is not failing: 1.2.3 and then\nwe keep the outbound path under watch while{pad}"
    "1.2.4 stays partial.",
    # Review round-e784ff8b27: a clause one candidate's window cuts before " over" is no clause in
    # another candidate's window, which reads on, so it must not unbind that candidate's "is met".
    "Python 3.1.2, _which_ stays partial, as {pad}\nand 1.2.3 is met row is not failing over to"
    " the backup.",
    "ASVS:{pad}v5 3.1.2 x "
    + "y" * 37
    + "\nand 1.2.3 is met row is not failing over to the backup.",
    "Python 3.1.2, _which_ stays partial, as {pad}\nso 1.2.3 x the cell is partial row is not"
    " failing over to the backup.",
]


@pytest.mark.parametrize("shape", _WINDOW_EDGE_SHAPES)
def test_no_hit_main_reports_is_lost_wherever_a_window_edge_falls(
    sf, sf_frozen_main, shape: str
) -> None:
    lost = {}
    for fill in (" ", "y"):
        for size in range(0, 100):
            body = shape.format(pad=fill * (size + 1))
            missing = set(sf_frozen_main.scan_pr_body(body)) - set(sf.scan_pr_body(body))
            if missing:
                lost[(fill, size)] = sorted(missing)
    # A positive control: main flags the shape, or the loop compared nothing.
    assert sf_frozen_main.scan_pr_body(shape.format(pad=" "))
    assert not lost, lost


def test_a_pr_body_hit_is_reported_once_at_mains_line_number(sf) -> None:
    """Review round-23e833d96f: a separator only str.splitlines ends a line at no longer reports one
    finding twice under two numberings, and every reading's hits come back in line order."""
    body = f"Intro{chr(0x2028)}more\n\n{_REQ} stays {_PARTIAL}."
    assert sf.scan_pr_body(body) == [f"pr-body:4: {sf.PR_BODY_REASONS['verdict']}"]
    hits = sf.scan_pr_body(f"{body}\n\nASVS {_REQ} stays{chr(0x200B)} {_PARTIAL}.")
    assert hits == sorted(hits, key=lambda h: int(h.split(":")[1])) and len(hits) == len(set(hits))


_CELL_CONNECTIVES = [
    "until",
    "pending",
    "because",
    "since",
    "while",
    "unless",
    "once",
    "after",
    "awaiting",
    "but",
    "due",
    "for",
    "per",
    "as",
    "at",
]


@pytest.mark.parametrize("word", _CELL_CONNECTIVES)
def test_every_cell_connective_binds_a_marked_row_only(sf, word: str) -> None:
    """Step 12: each of _PR_CELL_GOES_ON's connectives, not a sample of them."""
    marked = f"| ASVS {_REQ} | the outbound limb | {_PARTIAL} {word} the follow-up |"
    assert "verdict" in _pr_kinds(sf, marked), marked
    unmarked = f"| 2.5.1 | ADT^A01 | {_PASS.title()} {word} the nightly |"
    assert sf.scan_pr_body(unmarked) == [], unmarked


def test_the_cell_connective_list_is_the_one_tested(sf) -> None:
    """Step 12: a connective added to _PR_CELL_GOES_ON without a case above fails here."""
    assert sorted(sf._PR_CELL_GOES_ON.split("|")) == sorted(_CELL_CONNECTIVES)


@pytest.mark.parametrize("line", _PR_RESIDUE_MUST_STAY_QUIET)
def test_the_residue_rules_leave_versions_and_plain_numbers_alone(sf, line: str) -> None:
    assert sf.scan_pr_body(line) == [], line


@pytest.mark.parametrize(
    "row",
    [
        # Searching a row once per identifier made this take about 80 seconds.
        "| " + ", ".join([_REQ] * 8000) + " | the outbound limb |",
        # An argument list that could overlap the "->" tail of a code symbol backtracks on this.
        f"| {_REQ} | `a(" + ")->" * 21000 + " |",
        # A list separator pattern with "\s*" around it backtracks on a long run of spaces in a cell
        # read before the identifier cell: about 3.5 seconds at 20000 spaces, so about 55 at 80000.
        "| x" + " " * 80000 + f"y | {_REQ} |",
        # A markup class overlapping the separator after an identifier backtracks on a markup run.
        f"| {_REQ}" + "*" * 80000 + " | `_x` |",
        # Step 4: a header that marks a column, a run of dashes in a delimiter row, and a long list.
        "| ASVS | x |\n|---|---|\n| " + ", ".join([_REQ] * 8000) + " | the outbound limb |",
        "| ASVS | x |\n|" + "-" * 80000 + "x|\n| 1 | 2 |",
        # Step 12: the same dash run in a GFM-valid delimiter row for the two-cell header, which the
        # case above is not, so the strict header check times its delimiter-cell match over the run.
        "| ASVS | x |\n|" + "-" * 80000 + "|---|\n| 1 | 2 |",
        "| ASVS | x |\n|:" + "-" * 80000 + ":|:---:|\n| 1 | 2 |",
        # Emphasis underscores inside one long word run: a code-path match may start only after a
        # non-word character, not at every "messagefoundry" in the run.
        f"| {_REQ} | " + "__messagefoundry" * 5000 + " |",
        f"| {_REQ} | " + ("messagefoundry" + chr(0xE9)) * 5000 + " |",
        # Identifiers split by a word, so each one takes the column lookup.
        "| ASVS | x |\n|---|---|\n| " + " x ".join([_REQ] * 16000) + " |",
        "ASVS " + " and ".join([_REQ] * 8000) + " cannot pass",
        # Review round-23e833d96f: an invisible character and a line separator, which once added
        # two whole readings, and a long run of spaces, which the sentence split rescanned per space.
        "ASVS " + " and ".join([_REQ] * 8000) + " cannot pass" + chr(0x200B) + chr(0x2028),
        _REQ + " " * 60000 + ": the row" + chr(0x200B) + chr(0x2028),
        # A cell that goes on past "never failing", over a markup run.
        f"| {_REQ} | x | is never failing; stays" + "*" * 80000 + " |",
        f"| {_REQ} | x | is never failing; stays" + " " * 80000 + " |",
    ],
)
def test_a_long_table_row_scans_in_linear_time(sf, row: str) -> None:
    """A row is one window for every identifier in it and has no length limit, so each search over it
    must run once and in linear time. Each row scans in well under a second here, against about 80
    seconds, 7, 55 and 90 before, in order; the bound is loose for a slow runner."""
    began = time.perf_counter()
    sf.scan_pr_body(row)
    assert time.perf_counter() - began < 10


@pytest.mark.parametrize(
    "body",
    [
        "1.2.3 is partial and the row is not " + "_" * 16000,
        "1.2.3 is partial and the row is not " + "*" * 16000,
        "1.2.3 is partial and the row was " + "`" * 16000,
        "1.2.3 is partial and the cell is " + "_" * 16000,
    ],
    ids=["underscore", "star", "backtick", "cell-underscore"],
)
def test_a_long_markup_run_after_a_verdict_clause_scans_in_linear_time(sf, body: str) -> None:
    """No reading may search _PR_PROSE_VERDICT over a whole sentence, where it backtracks
    quadratically on a markup run: an earlier draft of the removed step 10 took 12 to 23 seconds on
    these bodies. The bound is 1 second, loose for a slow runner."""
    began = time.perf_counter()
    sf.scan_pr_body(body)
    assert time.perf_counter() - began < 1


def test_a_hard_wrapped_paragraph_reports_every_identifier_line_in_linear_time(sf) -> None:
    """A hard-wrapped paragraph is one unit with a line mark per line, and every binding identifier is
    reported at its own line, so finding that line must not scan every mark once per identifier.
    24000 lines, one binding identifier each: about 1.4 seconds here, against about 25 seconds when
    each lookup scanned every mark. The bound is 10 seconds, loose for a slow runner."""
    lines = 24000
    body = "\n".join([f"{_REQ} stays {_PARTIAL}"] * lines)
    began = time.perf_counter()
    hits = sf.scan_pr_body(body)
    elapsed = time.perf_counter() - began
    # A positive control: each line's identifier is reported at its own line, so the lookup ran.
    assert len(hits) == lines
    assert elapsed < 10


def _pr_kinds(sf, body: str) -> set[str]:
    hits = sf.scan_pr_body(body)
    return {kind for kind, reason in sf.PR_BODY_REASONS.items() if any(reason in h for h in hits)}


@pytest.mark.parametrize("line", _PR_VERDICT_MUST_FIRE)
def test_a_pr_body_stating_a_requirement_verdict_is_flagged(sf, line: str) -> None:
    """CONTROL 1, verdicts: prose binding ("stays", "held at", "cell to") as well as punctuation."""
    assert "verdict" in _pr_kinds(sf, f"Context above.\n\n{line}\n\nContext below."), line


@pytest.mark.parametrize("line", _PR_GAP_MUST_FIRE)
def test_a_pr_body_stating_a_requirement_gap_is_flagged(sf, line: str) -> None:
    """CONTROL 1, gaps: a requirement beside a gap, residual or not-built claim."""
    assert "gap" in _pr_kinds(sf, line), line


@pytest.mark.parametrize("line", _PR_MAP_MUST_FIRE)
def test_a_pr_body_mapping_a_requirement_to_code_is_flagged(sf, line: str) -> None:
    """CONTROL 1, code maps: a requirement beside the source path that implements it."""
    assert "map" in _pr_kinds(sf, line), line


def test_a_clean_pr_body_with_no_requirement_number_passes(sf) -> None:
    """CONTROL 2. Without it, a detector that flags every body looks identical to a correct one."""
    assert sf.scan_pr_body(_PR_CLEAN_BODY) == []


@pytest.mark.parametrize("line", _PR_VERSION_MUST_STAY_QUIET)
def test_a_version_beside_verdict_or_path_words_is_not_record_content(sf, line: str) -> None:
    """Versions next to test counts and code paths were the dominant false positive when measured."""
    assert sf.scan_pr_body(line) == [], line


def test_a_bare_requirement_number_is_not_flagged_while_that_is_unruled(sf) -> None:
    """Whether a bare number with no verdict, gap or code path beside it should pass is an OPEN owner
    decision. Until it is ruled the detector must not decide it, so this pins the pass. If the owner
    rules the other way, this test is the one to change, deliberately."""
    body = (
        f"BACKLOG #1 (ASVS {_REQ}). Adds an input bound to the intake path.\n\nSee also {_REQ_B}."
    )
    assert sf.scan_pr_body(body) == []


def test_a_hard_wrapped_sentence_is_read_whole_and_reported_at_the_identifier_line(sf) -> None:
    body = f"Intro line.\n\nThe control for ASVS {_REQ} is the one\nthat `pkg/example_module.py` enforces."
    hits = sf.scan_pr_body(body)
    assert hits == [f"pr-body:3: {sf.PR_BODY_REASONS['map']}"], hits


def test_one_line_restating_a_verdict_reports_it_once(sf) -> None:
    body = (
        f"{_REQ} stays {_PARTIAL}. It stays {_PARTIAL}: {_REQ} again. Again {_REQ} is {_PARTIAL}."
    )
    assert sf.scan_pr_body(body) == [f"pr-body:1: {sf.PR_BODY_REASONS['verdict']}"]


def test_the_pr_body_detector_reports_no_value(sf) -> None:
    """The identifier beside its verdict IS the disclosure; a public CI log must not repeat it."""
    residue = [line for _, line in _PR_RESIDUE_MUST_FIRE]
    body = "\n".join(_PR_VERDICT_MUST_FIRE + _PR_GAP_MUST_FIRE + _PR_MAP_MUST_FIRE + residue)
    hits = sf.scan_pr_body(body)
    assert hits, "the fixtures must fire, or this asserts nothing"
    for h in hits:
        for leaked in (_REQ, "example_module", "example.py", "example_aad", f" {_PARTIAL} "):
            assert leaked not in h, f"the reason echoed {leaked!r}: {h!r}"


def test_the_pr_body_mode_exit_codes(sf, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """1 on a hit, 0 on a clean body, 2 when the instrument cannot read -- never 0 for "could not look"."""
    dirty = tmp_path / "dirty.md"
    dirty.write_text(_PR_VERDICT_MUST_FIRE[0], encoding="utf-8")
    clean = tmp_path / "clean.md"
    clean.write_text(_PR_CLEAN_BODY, encoding="utf-8")
    assert sf.main(["--pr-body", str(dirty)]) == 1
    assert sf.main(["--pr-body", str(clean)]) == 0
    assert sf.main(["--pr-body"]) == 2
    assert sf.main(["--pr-body", str(tmp_path / "absent.md")]) == 2
    monkeypatch.setattr("sys.stdin", io.StringIO(_PR_GAP_MUST_FIRE[0]))
    assert sf.main(["--pr-body", "-"]) == 1
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert sf.main(["--pr-body", "-"]) == 0
    # The flag form a typo produces must refuse, not scan nothing and pass.
    assert sf.main([f"--pr-body={dirty}"]) == 2


def test_the_pr_body_event_mode_reads_the_webhook_payload(sf, tmp_path: Path) -> None:
    """CI's form. A payload with no pull request is a misrouted run and refuses; a null body is empty."""

    def event(name: str, payload: object) -> str:
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)

    assert (
        sf.main(["--pr-body-event", event("a", {"pull_request": {"body": _PR_MAP_MUST_FIRE[0]}})])
        == 1
    )
    assert sf.main(["--pr-body-event", event("b", {"pull_request": {"body": _PR_CLEAN_BODY}})]) == 0
    assert sf.main(["--pr-body-event", event("c", {"pull_request": {"body": None}})]) == 0
    assert sf.main(["--pr-body-event", event("d", {"push": {}})]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert sf.main(["--pr-body-event", str(bad)]) == 2


def test_a_staged_file_named_like_the_flag_does_not_switch_the_commit_gate(
    sf, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """pre-commit passes ``--require-tokens`` and then the staged names, so the body modes only count as
    the WHOLE command line. Anywhere else the TREE scan's own argument handling owns the flag and refuses
    it as an unknown option. Both paths exit 2, so the assertion is on which one spoke."""
    monkeypatch.setattr(sf, "LOCAL_TOKEN_FILE", tmp_path / "absent-tokens.txt")
    monkeypatch.delenv("MEFOR_FORBIDDEN_TOKENS", raising=False)
    assert sf.main(["--require-tokens", "--pr-body", str(tmp_path / "x.md")]) == 2
    err = capsys.readouterr().err
    assert "unknown option" in err, err
    assert "usage" not in err and "pull request body" not in err, err


def test_the_pr_body_workflow_reads_the_body_safely_and_is_not_required() -> None:
    """The body is attacker-controlled. The scanner must read it from the event payload file, so no
    Actions expression carries it anywhere in the workflow, and the job must run on an edit as well as
    a push. The job is not a required context: making it one is a separate branch-protection decision."""
    # Imported here, not at module scope: the helper skips its importer when PyYAML is absent, and that
    # must skip this one test rather than every scanner test in the file.
    from tests._workflow_contexts import (
        WORKFLOWS,
        context_of,
        jobs_of,
        required_contexts,
        step_script,
        triggers_of,
    )

    workflow = "pr-body-leak-scan.yml"
    types = triggers_of(workflow)["pull_request"]["types"]
    assert set(types) == {"opened", "edited", "reopened", "synchronize"}
    ((key, job),) = jobs_of(workflow).items()
    for step in job["steps"]:
        assert "${{" not in step.get("run", ""), (
            "no Actions expression may sit inside a run: script"
        )
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    assert "pull_request.body" not in text, "the body must not pass through an Actions expression"
    _, script = step_script(workflow, key, "Scan the pull request body")
    assert '--pr-body-event "$GITHUB_EVENT_PATH"' in script
    assert context_of(key, job) not in required_contexts()
