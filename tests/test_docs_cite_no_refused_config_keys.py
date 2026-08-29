# SPDX-License-Identifier: AGPL-3.0-or-later
"""No shipped document may present a config key the loader REFUSES as a key to write.

BACKLOG #1383. `_RELOCATED_TO_SECURITY` maps 15 legacy `[section] key` spellings to their
`[security]` replacements, and `_reject_relocated_keys` RAISES on any of them. It is called at
settings.py:4588, BEFORE `_desugar_security` at :4592, so a legacy spelling never reaches the
desugarer -- refusing is the whole behaviour, not a fallback. A document that quotes one as
config is telling a reader to write something that fails at load.

THE TABLE IS THE SINGLE SOURCE OF TRUTH AND THIS TEST IMPORTS IT. A hand-copied key list would
be a second definition that silently drifts the day someone relocates a sixteenth key -- the
same rule `ledger_check.py` states for `PUBLIC_BACKLOG_FLOOR`.

WHAT COUNTS AS A CITATION, AND WHY IT IS NARROWER THAN "THE KEY APPEARS":
  * Only an ASSIGNMENT shape (`key = value`) counts. Prose that merely NAMES a key is
    descriptive and harmless.
  * TOML booleans are LOWERCASE. `serve_ui=True` is a Python keyword argument to `create_app`,
    not config, and capitalised `True`/`False` is what separates the two. That one character is
    what stops this test flagging the API surface.
  * A line that DOCUMENTS the refusal is exempt. docs/SECURITY.md says the
    `[diagnostics].audit_all_authz` TOML spelling "is refused at load" -- the one place the
    document is already right. A scan without this exemption reports that line as a defect, and
    the ASVS tracker's own scan did exactly that. Its words: the item "would have had a builder
    FIX IT INTO BEING WRONG."
"""

from __future__ import annotations

import pathlib
import re

import pytest

from messagefoundry.config.settings import _RELOCATED_TO_SECURITY

REPO = pathlib.Path(__file__).resolve().parents[1]
DOCS = REPO / "docs"

# A line is exempt when it is talking ABOUT the refusal rather than instructing the reader.
_DISCLAIMS = re.compile(r"refus|relocat|moved to|no longer|rejected|\[security\]", re.IGNORECASE)
# TOML values only: quoted string, LOWERCASE bool, or bare number. Capitalised True is Python.
_VALUE = r'("[^"]*"|true|false|\d+)(?![\w])'


def _citations(text: str) -> list[tuple[int, str, str]]:
    """Every line presenting a refused key as config, with the fragment that made it match."""
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if _DISCLAIMS.search(line):
            continue
        for section, key in _RELOCATED_TO_SECURITY:
            match = re.search(rf"(?<![\w.]){re.escape(key)}\s*=\s*{_VALUE}", line)
            if match:
                hits.append((lineno, f"[{section}].{key}", match.group(0)))
    return hits


def test_the_relocated_table_is_populated() -> None:
    """The scan is worthless against an empty table, so prove the import found one.

    Without this, deleting or renaming _RELOCATED_TO_SECURITY makes every test below pass
    vacuously -- a green suite over nothing, which is the failure this whole item is about.
    """
    assert len(_RELOCATED_TO_SECURITY) >= 15, _RELOCATED_TO_SECURITY


def test_the_scanner_catches_a_deliberately_bad_line() -> None:
    """POSITIVE CONTROL. A scanner that finds nothing anywhere is indistinguishable from a
    clean corpus, so make it fire on purpose before trusting a zero."""
    section, key = next(iter(_RELOCATED_TO_SECURITY))
    planted = f"Set `[{section}] {key} = true` in your config.\n"
    assert _citations(planted), f"the scanner did not catch a planted citation of {key}"


def test_the_scanner_does_not_flag_a_line_documenting_the_refusal() -> None:
    """NEGATIVE CONTROL, and it is the one that has already burned somebody. Flagging this
    line would send a builder to 'fix' the only place the doc states the rule correctly."""
    section, key = next(iter(_RELOCATED_TO_SECURITY))
    documented = f"The `[{section}].{key} = true` TOML spelling is refused at load.\n"
    assert not _citations(documented)


def test_the_scanner_does_not_flag_a_python_keyword_argument() -> None:
    """NEGATIVE CONTROL: `create_app(serve_ui=True)` is an API reference, not config.
    Capitalisation is the whole discriminator -- TOML booleans are lowercase."""
    assert not _citations("`create_app(serve_ui=True)` yields the console plane.\n")


# THE MEASURED BASELINE, AND WHY THIS IS A RATCHET RATHER THAN A CLEAN GATE.
#
# 27 documents carry 58 of these citations. BACKLOG #1383's agreed scope is docs/SECURITY.md ONLY
# -- the ASVS tracker recommended that scope, the Liaison endorsed it unaltered, and widening it
# here would be a scope decision nobody made. SECURITY.md is now 0 and is absent from this table.
#
# A gate that only watched one file would let the other 26 spread. A repo-wide gate would land
# RED and get disabled. So this is a RATCHET: no file may exceed its measured count, and a file
# absent from the table must be at zero. New docs and new citations fail immediately.
#
# IT SELF-PRUNES, WHICH IS WHAT KEEPS A BASELINE FROM ROTTING INTO A SUPPRESSION LIST: fixing a
# file below its number FAILS until you lower the number, and fixing it entirely FAILS until you
# delete the row. The list can only shrink, and it cannot silently stop matching reality.
_BASELINE: dict[str, int] = {
    "docs/adr/0014-alerting-rules-engine.md": 1,
    "docs/adr/0022-fhir-resource-codec-rest-client.md": 1,
    "docs/adr/0027-per-connection-retention.md": 1,
    "docs/adr/0049-turnkey-dr-backup-restore-verify.md": 1,
    "docs/adr/0056-engine-managed-vip-failover.md": 1,
    "docs/adr/0096-cluster-leader-preference-and-non-promotable-standby.md": 1,
    "docs/adr/0115-asvs-l3-drive-to-pass-secure-by-default-flips-and-residual-closure.md": 1,
    "docs/adr/0118-secure-by-default-security-configuration-section.md": 2,
    "docs/adr/0135-engine-brokered-ai-assistance-customer-managed-llm-egress-with-per-use-audit.md": 1,
    "docs/adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md": 2,
    "docs/adr/0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md": 1,
    "docs/adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md": 2,
    "docs/archive/backlog/BACKLOG-CLOSED.md": 2,
    "docs/BACKLOG.md": 2,
    "docs/CLOUD-PHI-HIPAA.md": 1,
    "docs/CLUSTERING.md": 1,
    "docs/CONFIGURATION.md": 3,
    "docs/CONNECTIONS.md": 9,
    "docs/CONTAINER-EXPOSURE-EVALUATION.md": 3,
    "docs/EARLY-ADOPTER-GUIDE.md": 1,
    "docs/MENTAL-MODEL.md": 1,
    "docs/REMOTE-CONSOLE-CUSTOMER-GUIDE.md": 2,
    "docs/REMOTE-CONSOLE.md": 1,
    "docs/SECURITY-LOOSENING.md": 3,
    "docs/testing/master-test-plan/03-store-and-data-lifecycle.md": 12,
    "docs/testing/master-test-plan/16-security-phi-and-supply-chain.md": 2,
    "docs/TRAY.md": 1,
}


def test_the_baseline_is_exact_and_self_pruning() -> None:
    """A baseline row that no longer matches is a lie about the corpus, so fail on it.

    This is the half that stops a ratchet decaying into a permanent allowlist: you cannot fix a
    document and leave its old number behind, and you cannot list a file that is already clean.
    """
    stale = []
    for rel, expected in _BASELINE.items():
        path = REPO / rel
        if not path.exists():
            stale.append(f"{rel}: listed but missing")
            continue
        actual = len(_citations(path.read_text(encoding="utf-8")))
        if actual != expected:
            verb = "now clean -- delete this row" if actual == 0 else f"now {actual} -- lower it"
            stale.append(f"{rel}: baseline says {expected}, {verb}")
    assert not stale, "the baseline no longer matches the corpus:\n    " + "\n    ".join(stale)


@pytest.mark.parametrize(
    "doc", sorted(DOCS.rglob("*.md")), ids=lambda p: str(p.relative_to(REPO)).replace("\\", "/")
)
def test_no_doc_presents_a_refused_config_key_as_config(doc: pathlib.Path) -> None:
    rel = str(doc.relative_to(REPO)).replace("\\", "/")
    allowed = _BASELINE.get(rel, 0)
    hits = _citations(doc.read_text(encoding="utf-8"))
    if len(hits) > allowed:
        shown = "\n".join(f"    line {n}: {k} -- {frag}" for n, k, frag in hits)
        pytest.fail(
            f"{rel} presents {len(hits)} key(s) the loader REFUSES as config to write, "
            f"baseline allows {allowed}.\n"
            f"A reader who copies these gets a ValueError at load.\n{shown}\n"
            f"Use the [security] spelling from _RELOCATED_TO_SECURITY instead."
        )
