# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
  * TWO BRANCHES match, and only one of them reads the section. `[section].key = value` is
    matched with the section ANCHORED; everything else is matched by a BARE `key = value` that
    ignores any bracket on the line. The dotted branch is new on 2026-09-20 -- before it, the
    spelling documents here actually write matched nothing at all.
  * SO THE BARE BRANCH IS SECTION-BLIND, and `[cluster] enabled = true` is still reported as a
    citation of the refused `[auth].enabled`. That is a KNOWN GAP, not a claim of correctness;
    `test_the_bare_branch_is_still_section_blind` pins it and the `_BASELINE` comment says what
    it means for the rows below.
  * Python ATTRIBUTE ACCESS still does not count -- `settings.api.public_origin = "..."` is
    read, not written. `_assignment` holds how the two are told apart, and what excluding
    attribute access cost for as long as it also excluded the dotted spelling.
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
import warnings

import pytest

from messagefoundry.config.settings import _RELOCATED_TO_SECURITY, _REMOVED_KEYS

#: Every key the loader refuses, whichever way it got there. BACKLOG #1279 added the second
#: table: a REMOVED key fails at load exactly like a relocated one, and its message cannot name a
#: replacement spelling, so a doc that presents one is strictly worse to copy from.
_REFUSED_KEYS: tuple[tuple[str, str], ...] = tuple(_RELOCATED_TO_SECURITY) + tuple(_REMOVED_KEYS)

REPO = pathlib.Path(__file__).resolve().parents[1]
DOCS = REPO / "docs"

# A line is exempt when it is talking ABOUT the refusal rather than instructing the reader.
# `removed|retired` joined the list with BACKLOG #1279: a key that went away is documented in the
# past tense, and those are the two words that tense reaches for.
_DISCLAIMS = re.compile(
    r"refus|relocat|moved to|no longer|rejected|removed|retired|\[security\]", re.IGNORECASE
)
# TOML values only: quoted string, LOWERCASE bool, or bare number. Capitalised True is Python.
_VALUE = r'("[^"]*"|true|false|\d+)(?![\w])'


def _assignment(section: str, key: str) -> str:
    r"""The citation pattern for one refused ``[section] key``.

    IT HAS TWO BRANCHES AND ONLY THE DOTTED ONE READS THE SECTION. The optional
    `[section].` prefix is anchored; drop into the bare alternative and the pattern matches
    `key = value` anywhere, with no idea what section it sits under. `[auth] enabled = true`
    therefore matches through the BARE branch -- the bracket is not part of the match -- and so
    does `[cluster] enabled = true`, which is a false positive this scanner cannot see.
    `test_the_bare_branch_is_still_section_blind` pins that gap so it stays visible; closing it
    means dropping the bare branch, which would discard most of the corpus and is a separate,
    larger change (see the fence-scoping note below).

    THE `(?<![\w.])` GUARD IS WHAT KEEPS PYTHON ATTRIBUTE ACCESS OUT, and it is why the dotted
    TOML spelling was excluded by ACCIDENT for as long as it was. `settings.api.public_origin =`
    and `self.public_origin =` reach the key through an identifier and a dot, so rejecting a
    preceding dot rejects them -- and it rejected `[api].public_origin = "..."` with exactly the
    same character. The guard stays; the optional `[section].` prefix in front of it is what
    lets the TOML spelling through, because that prefix ends in `].` rather than in an
    identifier. Measured 2026-09-20 over docs/**/*.md: 45 citations before, 52 after.

    THE PREFIX IS ANCHORED TO THE KEY'S OWN SECTION, and a generic `[\w+]\.` is measurably
    wrong. `enabled` is refused under `[auth]` and is ordinary LIVE config under at least
    `[cluster]`, `[backup]`, `[approvals]`, `[update_check]` and `[integrity]`. Measured the
    same day, an unanchored prefix added 14 hits and every one of them was a correct line of
    supported config -- a gate that reports those sends a builder to break working examples,
    which is the failure `test_the_scanner_does_not_flag_a_line_documenting_the_refusal` exists
    to name. `test_the_dotted_form_is_anchored_to_the_keys_own_section` holds this line.

    The BRACKETLESS dotted path (`api.host = "..."`) is deliberately NOT matched: it is
    indistinguishable from attribute access ON A BARE LINE, and it occurs zero times in
    docs/**/*.md, so admitting the ambiguity would buy nothing.

    SCOPING TO TOML CODE FENCES IS THE ALTERNATIVE THAT WAS NOT TAKEN, and it is this
    directory's house pattern: `tests/test_runbook_proxy_tls_floor.py` and
    `tests/test_off_loopback_runbook.py` both scope their scans by fence language. Tracking the
    fence and the `[section]` header in force would make the section readable on EVERY branch,
    which collapses the section-blindness above and the bracketless case with it. It is not a
    drop-in swap: most of the citations here are PROSE outside any fence, so fence scoping
    would drop them and force a full re-baseline. It is worth its own item, not this one.
    """
    return rf"(?<![\w.])(?:\[{re.escape(section)}\]\.)?{re.escape(key)}\s*=\s*{_VALUE}"


#: Built once. `_citations` runs this inner loop per surviving line, so the corpus pass makes
#: about 1.4 million of them; rebuilding the pattern string each time cost a measured 3.37s
#: against 2.26s compiled at import.
_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
    (section, key, re.compile(_assignment(section, key))) for section, key in _REFUSED_KEYS
)


def _citations(text: str) -> list[tuple[int, str, str]]:
    """Every line presenting a refused key as config, with the fragment that made it match."""
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        # Every pattern embeds a literal `=`, so a line without one cannot match any of the 16.
        # 94 percent of docs/**/*.md is such a line, and skipping them before the regexes run
        # took a measured corpus pass from 3.0s to 0.33s. `test_every_pattern_needs_an_equals`
        # is what keeps the shortcut honest if the pattern ever widens.
        if "=" not in line or _DISCLAIMS.search(line):
            continue
        for section, key, pattern in _PATTERNS:
            match = pattern.search(line)
            if match:
                hits.append((lineno, f"[{section}].{key}", match.group(0)))
    return hits


def test_the_relocated_table_is_populated() -> None:
    """The scan is worthless against an empty table, so prove the import found one.

    Without this, deleting or renaming _RELOCATED_TO_SECURITY makes every test below pass
    vacuously -- a green suite over nothing, which is the failure this whole item is about.
    """
    # 15 until BACKLOG #1279 moved ([ai], data_class) out of the relocation table and into
    # _REMOVED_KEYS -- it relocated to nothing. The COMBINED floor is what the scan depends on, so
    # that is what is asserted; both tables are required to be non-empty so neither can vanish.
    assert len(_RELOCATED_TO_SECURITY) >= 14, _RELOCATED_TO_SECURITY
    assert len(_REMOVED_KEYS) >= 2, _REMOVED_KEYS
    assert len(_REFUSED_KEYS) >= 16, _REFUSED_KEYS


@pytest.mark.parametrize("spelling", ["bare", "space", "dotted"])
def test_the_scanner_catches_a_deliberately_bad_line(spelling: str) -> None:
    """POSITIVE CONTROL, one case per spelling a DOCUMENT may use.

    A scanner that finds nothing anywhere is indistinguishable from a clean corpus, so make it
    fire on purpose before trusting a zero. EACH SPELLING NEEDS ITS OWN CASE: this was a single
    test planting `[section] key`, and that spelling kept working throughout the window in which
    `[section].key = value` matched nothing at all. A control that can only exercise the working
    path reports a clean scan and a broken scan identically, which is what happened here.

    THESE ARE THREE SPELLINGS, NOT THREE BRANCHES. Only `dotted` exercises the anchored branch;
    `bare` and `space` both match through the bare alternative, and `space` would pass even if
    the bracket were garbage. See `_assignment`.
    """
    section, key = next(iter(_RELOCATED_TO_SECURITY))
    prefix = {"bare": "", "space": f"[{section}] ", "dotted": f"[{section}]."}[spelling]
    planted = f"Set `{prefix}{key} = true` in your config.\n"
    assert _citations(planted), f"the scanner did not catch a {spelling} citation of {key}"


def test_the_bare_branch_is_still_section_blind() -> None:
    """KNOWN GAP, pinned so it cannot be mistaken for correctness.

    The anchored prefix guards the DOTTED spelling only. Written with a space, a foreign
    section still reaches the bare alternative and is reported as a citation of the refused
    key -- the matched fragment is `enabled = true`, with the bracket outside the match.
    Measured 2026-09-20 over docs/**/*.md, 10 of the 52 baselined hits sit under a section
    header that is not the refused key's; the `_BASELINE` comment breaks them down.

    THIS ASSERTS THE WRONG ANSWER ON PURPOSE. Closing the gap means dropping the bare branch or
    tracking the section header, which re-baselines the whole corpus; until then, a test that
    FAILS when someone fixes it is how the next person finds the note instead of the surprise.
    """
    assert ("auth", "enabled") in _REFUSED_KEYS, _REFUSED_KEYS
    hits = _citations("Under `[cluster]`, `enabled = true` starts the coordinator.\n")
    assert hits == [(1, "[auth].enabled", "enabled = true")], hits


def test_every_pattern_needs_an_equals() -> None:
    """`_citations` skips any line with no `=`, leaving 94 percent of the corpus unscanned.

    That is sound only while every pattern requires one. A future widening that admitted a
    citation shape without `=` would silently under-report -- the same blind-spot shape the
    dotted spelling had, found the same way it was: by checking the claim instead of the code.
    """
    for section, key in _REFUSED_KEYS:
        assert "=" in _assignment(section, key), (section, key)


def test_the_dotted_form_is_anchored_to_the_keys_own_section() -> None:
    """NEGATIVE CONTROL, PAIRED with a positive arm so it cannot pass by matching nothing.

    `_assignment` records why the `[section].` prefix is anchored and what an unanchored one
    measured; this is the test that holds that line. The FIRES arm proves the scanner is live on
    this key, so a regression that broke dotted matching outright could not turn MISSES green.
    """
    assert ("auth", "enabled") in _REFUSED_KEYS, _REFUSED_KEYS
    assert _citations("Set `[auth].enabled = true` in your config.\n")
    assert not _citations("Set `[cluster].enabled = true` in your config.\n")


def test_the_scanner_does_not_flag_python_attribute_access() -> None:
    """NEGATIVE CONTROL: admitting the dotted form must not admit attribute access with it.

    Every probe here carries a LOWERCASE TOML value, so the `_VALUE` capitalisation rule cannot
    rescue it -- the lookbehind in `_assignment` is the only thing rejecting these, and this
    test fails the moment it is dropped.
    """
    for line in (
        '`settings.api.public_origin = "https://ops.example.com"` reads the loaded model.\n',
        '`self.public_origin = "https://ops.example.com"` assigns the field.\n',
        "`cfg.store.allow_unencrypted_phi = true` is a dotted path, not a `[store].` prefix.\n",
    ):
        assert not _citations(line), line


def test_the_scanner_does_not_flag_a_line_documenting_the_refusal() -> None:
    """NEGATIVE CONTROL, and it is the one that has already burned somebody. Flagging this
    line would send a builder to 'fix' the only place the doc states the rule correctly.

    IT ONLY STARTED TESTING THAT ON 2026-09-20. The line it plants uses the DOTTED spelling,
    which matched nothing at all until the dotted branch was admitted -- so it passed whether
    or not `_DISCLAIMS` existed, and the exemption it exists to protect was never exercised.
    Measured that day against both patterns: the planted line matches the new one with the
    disclaim filter removed, and did not match the old one. This control was vacuous; the
    widening is what made `_DISCLAIMS` load-bearing here.
    """
    section, key = next(iter(_REFUSED_KEYS))
    documented = f"The `[{section}].{key} = true` TOML spelling is refused at load.\n"
    assert not _citations(documented)


def test_the_scanner_does_not_flag_a_python_keyword_argument() -> None:
    """NEGATIVE CONTROL: `create_app(serve_ui=True)` is an API reference, not config.
    Capitalisation is the whole discriminator -- TOML booleans are lowercase."""
    assert not _citations("`create_app(serve_ui=True)` yields the console plane.\n")


# THE MEASURED BASELINE, AND WHY THIS IS A RATCHET RATHER THAN A CLEAN GATE.
#
# 28 documents carry 66 of these "citations" -- the row count and the sum of the table below,
# pinned by test_the_header_count_matches_the_table, because two drafts of this line have already
# drifted from the dict they describe: one said 58 against a sum of 59, and the document count
# read 27 against 26 rows. BACKLOG #1383's agreed scope is docs/SECURITY.md ONLY
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
#
# BACKLOG #1279 WIDENED THE SCAN to `_REMOVED_KEYS` and the count went UP, which is the ratchet
# working rather than failing. The rows it added are all HISTORICAL: an accepted ADR that records
# what a since-removed key did, and closed ledger rows quoting the same. Those cannot be rewritten
# to a live spelling, because there is no live spelling -- the key relocated to nothing. A ratchet
# whose only remedy is to delete a decision record is the wrong instrument, so they are baselined.
# What the widening DOES catch is the case it was added for: a NEW doc telling a reader to write
# one, which fails immediately, at zero, like any other new citation.
#
# ADMITTING THE DOTTED `[section].key` SPELLING (post-merge review of PR #1364) took the on-disk
# count from 45 to 52 and added two rows, for the same reason #1279 did: the ratchet went UP
# because the INSTRUMENT got better, not because a document got worse. All seven new citations
# are ADR prose recording what a since-removed or since-relocated key did, so they are baselined
# rather than rewritten -- there is no live spelling to rewrite `[ai].data_class` to, and
# rewriting a decision record is the wrong remedy for a scan finding.
#
# THE TWO WITHHELD ROWS BELOW COULD NOT BE RE-MEASURED, AND NO CHECKOUT CAN DETECT THAT. Their
# documents are in no clone (see _WITHHELD_FROM_PUBLIC_CHECKOUTS), and widening can only ever
# RAISE a count, so those two rows are now LOWER BOUNDS carried over from the narrower scan
# rather than measurements of this one. Whoever holds those documents must re-measure them with
# the dotted branch admitted. Note that both sibling guards this exemption was borrowed from
# ship an env override letting the holder point the guard at their own copy and enforce it;
# this file has none, so re-measuring here means editing the table by hand.
#
# "CITATION" IS THE INSTRUMENT'S WORD, NOT A VERDICT ON THE LINE. The bare branch is
# section-blind (see `_assignment`), so some rows below count lines that are CORRECT config.
# Measured 2026-09-20, by tracking the fence language and the `[section]` header in force, all
# 52 on-disk hits fall out as:
#
#     7  dotted, section anchored                      -- right by construction
#     1  bare, under its OWN section header            -- a true citation
#     7  bare, under a FOREIGN header ([cluster], [backup], [inbound], ...)    WRONG
#     3  bare, under [security] -- the very replacement spelling this gate     WRONG
#        exists to steer readers toward
#    34  bare, no header in force (prose, or an unheaded fence)  -- a line scanner cannot say,
#        and 6 of those are Python keyword arguments in a `python` fence, which lowercase
#        string values slip past because `_VALUE` only separates `True` from `true`
#
# The 3 are the sharp case: `_DISCLAIMS` exempts `[security]` per LINE, and a section header is
# per BLOCK, so the exemption never reaches those key lines. That is the "would have had a
# builder FIX IT INTO BEING WRONG" failure the module docstring cites, sitting in this table.
#
# SO A ROW GOING DOWN IS NOT ALWAYS A DOCUMENT BEING FIXED -- it may be the instrument learning
# to read. Do not treat this table as a list of defects, and do not edit a document because it
# appears here without reading the line first.
_BASELINE: dict[str, int] = {
    # Dotted branch, PR #1364 review: was 1, the added one is `[ai].data_class`.
    "docs/adr/0014-alerting-rules-engine.md": 2,
    # Dotted branch, PR #1364 review: a NEW row, both hits `[ai].data_class` in this ADR's prose.
    "docs/adr/0019-pluggable-keyprovider-hsm-kms-vault.md": 2,
    "docs/adr/0022-fhir-resource-codec-rest-client.md": 1,
    "docs/adr/0027-per-connection-retention.md": 1,
    "docs/adr/0049-turnkey-dr-backup-restore-verify.md": 1,
    "docs/adr/0056-engine-managed-vip-failover.md": 1,
    "docs/adr/0096-cluster-leader-preference-and-non-promotable-standby.md": 1,
    # #1279: was 2. The three added are the retired posture lever, quoted in this ADR's own
    # amendment banner and in the two config blocks that show what the section looked like.
    # Dotted branch, PR #1364 review: was 5, the added one is the `# was [ai].data_class = "phi"`
    # migration note. Two of this row's six are the section-blind `[security]`-block case above.
    "docs/adr/0118-secure-by-default-security-configuration-section.md": 6,
    # Dotted branch, PR #1364 review: a NEW row -- three `[store].allow_unencrypted_phi=true`,
    # all of them this ADR stating what the audited opt-out did, including its acceptance
    # criterion.
    "docs/adr/0109-at-rest-encryption-fail-closed-on-an-undeclared-phi-posture.md": 3,
    # #1279 rows below: each records what the removed key did, in a decision record.
    "docs/adr/0115-asvs-l3-drive-to-pass-secure-by-default-flips-and-residual-closure.md": 1,
    "docs/adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md": 2,
    "docs/adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md": 2,
    # The owner's ruling, quoted verbatim in the status line. CLAUDE.md forbids rewriting a
    # quotation, and the sentence retiring the key necessarily contains the key.
    "docs/adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md": 1,
    "docs/adr/0135-engine-brokered-ai-assistance-customer-managed-llm-egress-with-per-use-audit.md": 1,
    "docs/adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md": 2,
    "docs/adr/0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md": 1,
    # #1279: was 2. The two added are in item 1279 itself -- the row that ASKED for the removal,
    # naming the key it wanted gone, and the closing banner recording that it went.
    "docs/CLOUD-PHI-HIPAA.md": 1,
    "docs/CLUSTERING.md": 1,
    "docs/CONFIGURATION.md": 3,
    "docs/CONNECTIONS.md": 9,
    "docs/CONTAINER-EXPOSURE-EVALUATION.md": 3,
    "docs/EARLY-ADOPTER-GUIDE.md": 1,
    "docs/MENTAL-MODEL.md": 1,
    "docs/REMOTE-CONSOLE.md": 1,
    "docs/SECURITY-LOOSENING.md": 3,
    "docs/testing/master-test-plan/03-store-and-data-lifecycle.md": 12,
    "docs/testing/master-test-plan/16-security-phi-and-supply-chain.md": 2,
    "docs/TRAY.md": 1,
}

# THE ONLY ROWS A CLONE MAY LEGITIMATELY LACK, and naming them is the point: an exemption that
# said "any missing file is fine" would delete the self-pruning property this baseline exists to
# have. Both of these are UNTRACKED -- `git ls-files` does not report them, they sit on a
# maintainer's disk, and no checkout anywhere carries them. They were measured where they exist,
# so their counts are right; CI simply cannot see the documents. Failing on that made this test
# unpassable on every runner while the baseline was correct about the corpus it describes.
# tests/test_threat_model_doc_drift.py and tests/test_crit2_inline_doc_drift.py make the same
# call for their own withheld documents: warn that the assertion is inert, do not fail.
# A row here that IS present on disk is still enforced exactly, so the ratchet holds locally.
_WITHHELD_FROM_PUBLIC_CHECKOUTS = frozenset(
    {
        "docs/testing/master-test-plan/03-store-and-data-lifecycle.md",
        "docs/testing/master-test-plan/16-security-phi-and-supply-chain.md",
    }
)


class BaselineRowUnenforced(UserWarning):
    """A baseline row names a document this checkout does not carry."""


def test_the_header_count_matches_the_table() -> None:
    """The comment above `_BASELINE` states a row count and a sum. Pin both.

    That sentence has drifted twice already: one draft read 58 against a sum of 59, another read
    27 documents against 26 rows. This file's whole argument is that the table is the single
    source of truth, and that is worth nothing while the sentence introducing it can quietly
    disagree. Change a row, change the header -- this is what makes you.
    """
    assert (len(_BASELINE), sum(_BASELINE.values())) == (28, 66)


def test_every_withheld_row_is_still_a_baseline_row() -> None:
    """The exemption must not outlive the rows it exempts.

    Delete a row from _BASELINE and leave its name here, and this file starts carrying a
    permanent licence for a path nothing measures -- a suppression list growing in the one place
    the ratchet cannot see. Tie the two together so that cannot happen quietly.
    """
    orphans = sorted(_WITHHELD_FROM_PUBLIC_CHECKOUTS - set(_BASELINE))
    assert not orphans, f"exempted paths that are no longer baseline rows: {orphans}"


def test_the_baseline_is_exact_and_self_pruning() -> None:
    """A baseline row that no longer matches is a lie about the corpus, so fail on it.

    This is the half that stops a ratchet decaying into a permanent allowlist: you cannot fix a
    document and leave its old number behind, and you cannot list a file that is already clean.

    ABSENT IS NOT STALE. A row whose document this checkout does not carry is UNENFORCED, not
    wrong, and only the paths named in _WITHHELD_FROM_PUBLIC_CHECKOUTS get that reading. Any
    other missing file is still a hard failure -- deleting or renaming a document you have not
    de-listed is exactly the drift this test is for.
    """
    stale = []
    enforced = 0
    for rel, expected in _BASELINE.items():
        path = REPO / rel
        if not path.exists():
            if rel in _WITHHELD_FROM_PUBLIC_CHECKOUTS:
                warnings.warn(
                    f"{rel} is absent from this checkout, so its baseline of {expected} is "
                    f"INERT in this run. It is enforced wherever the document exists.",
                    BaselineRowUnenforced,
                    stacklevel=2,
                )
                continue
            stale.append(f"{rel}: listed but missing")
            continue
        enforced += 1
        actual = len(_citations(path.read_text(encoding="utf-8")))
        if actual != expected:
            verb = "now clean -- delete this row" if actual == 0 else f"now {actual} -- lower it"
            stale.append(f"{rel}: baseline says {expected}, {verb}")
    assert not stale, "the baseline no longer matches the corpus:\n    " + "\n    ".join(stale)
    # A baseline whose every row was absent would clear the loop above having read nothing -- the
    # vacuous green that test_the_relocated_table_is_populated already guards against upstream.
    # Only the withheld rows may ever be skipped, so the floor is exact rather than a fraction.
    floor = len(_BASELINE) - len(_WITHHELD_FROM_PUBLIC_CHECKOUTS)
    assert enforced >= floor, (
        f"only {enforced} of {len(_BASELINE)} baseline rows were read in this checkout, "
        f"expected at least {floor}; the baseline is measuring almost nothing"
    )


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
