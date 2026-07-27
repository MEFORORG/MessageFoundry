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
