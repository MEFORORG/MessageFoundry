# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No shipped document may present a config key the loader REFUSES as a key to write.

BACKLOG #1383. `_RELOCATED_TO_SECURITY` maps the legacy `[section] key` spellings to their
`[security]` replacements, and `_reject_relocated_keys` RAISES on any of them. `load_settings`
calls it BEFORE `_desugar_security`, so a legacy spelling never reaches the desugarer --
refusing is the whole behaviour, not a fallback. A document that quotes one as config is
telling a reader to write something that fails at load.

(That ordering used to be written here as "settings.py:4588, BEFORE ... at :4592". Both anchors
had drifted about 900 lines by 2026-09-20 -- the calls are adjacent statements in one function,
so naming the function locates them and the numerals only went stale. CLAUDE.md section 5:
line numbers are navigation aids and never evidence.)

THE TABLE IS THE SINGLE SOURCE OF TRUTH AND THIS TEST IMPORTS IT. A hand-copied key list would
be a second definition that silently drifts the day someone relocates another key -- the
same rule `ledger_check.py` states for `PUBLIC_BACKLOG_FLOOR`. That rule applies to a hand-
written COUNT too, which is why this docstring no longer carries one: it read "maps 15" while
the floor below had already been corrected to 14 for BACKLOG #1279, and nothing reported the
contradiction between two lines of one file (BACKLOG #1361).

WHAT COUNTS AS A CITATION, AND WHY IT IS NARROWER THAN "THE KEY APPEARS":
  * Only an ASSIGNMENT shape (`key = value`) counts. Prose that merely NAMES a key is
    descriptive and harmless.
  * TWO SPELLINGS match. `[section].key = value` is matched with the section ANCHORED and counts
    wherever it appears, because it carries its own section. A BARE `key = value` carries none, so
    it is read against the `[section]` header and the code fence in force on that line -- see
    `_citations` for the three-way decision and what each arm measured.
  * Python ATTRIBUTE ACCESS still does not count -- `settings.api.public_origin = "..."` is
    read, not written. `_dotted_assignment` holds how the two are told apart, and what excluding
    attribute access cost for as long as it also excluded the dotted spelling.
  * TOML booleans are LOWERCASE. `serve_ui=True` is a Python keyword argument to `create_app`,
    not config, and capitalised `True`/`False` is what separates the two. That one character is
    what stops this test flagging the API surface on a line no fence marks as Python.
  * A line that DOCUMENTS the refusal is exempt. docs/SECURITY.md says the
    `[diagnostics].audit_all_authz` TOML spelling "is refused at load" -- the one place the
    document is already right. A scan without this exemption reports that line as a defect, and
    the ASVS tracker's own scan did exactly that. Its words: the item "would have had a builder
    FIX IT INTO BEING WRONG."
"""

from __future__ import annotations

import os
import pathlib
import re
import warnings
from collections.abc import Mapping
from typing import Final

import pytest
from _docs_toml import TOML_FENCE_RE, line_contexts

from messagefoundry.config.settings import _RELOCATED_TO_SECURITY, _REMOVED_KEYS

#: Every key the loader refuses, whichever way it got there. BACKLOG #1279 added the second
#: table: a REMOVED key fails at load exactly like a relocated one, and its message cannot name a
#: replacement spelling, so a doc that presents one is strictly worse to copy from.
_REFUSED_KEYS: tuple[tuple[str, str], ...] = tuple(_RELOCATED_TO_SECURITY) + tuple(_REMOVED_KEYS)

REPO = pathlib.Path(__file__).resolve().parents[1]
DOCS = REPO / "docs"

#: What generation of the SCAN produced the numbers in `_BASELINE`. Pinned by
#: `test_the_header_count_matches_the_table`; the comment above `_BASELINE` says what changing it
#: means and why the table cannot be read without it.
_SCAN_GENERATION: Final = "fence-aware + section-aware, 2026-09-20"

# A line is exempt when it is talking ABOUT the refusal rather than instructing the reader.
# `removed|retired` joined the list with BACKLOG #1279: a key that went away is documented in the
# past tense, and those are the two words that tense reaches for.
_DISCLAIMS = re.compile(r"refus|relocat|moved to|no longer|rejected|removed|retired", re.IGNORECASE)

#: The single home ADR 0118 gave the posture switches: every value in `_RELOCATED_TO_SECURITY` is a
#: key in THIS section, which is why naming it on a line is evidence the line is steering a reader
#: toward the replacement rather than away from it.
_REPLACEMENT_SECTION: Final = "security"
#: Naming the replacement section exempts a line -- FOR THE KEYS THAT RELOCATE THERE, AND NO OTHERS.
#:
#: It used to be a bare `\[security\]` alternative inside `_DISCLAIMS`, which exempted the whole
#: LINE, and `_REMOVED_KEYS` contains ("security", "handles_real_patient_data") -- a key whose
#: REFUSED section is `[security]`. So the exemption meant to protect the replacement spelling was
#: also hiding the one refused key that lives in the replacement section. Measured 2026-09-20 over
#: docs/**/*.md with sections tracked: exempting per line gives 36 hits, dropping the alternative
#: outright gives 42, and this per-key narrowing gives 39. The 3-hit difference is the whole of the
#: argument -- all three are `[security].handles_real_patient_data = false` presented as config to
#: write (ADRs 0115, 0148, 0186), which the blunt form hid and the narrowed form reports. The other
#: 6 that dropping it outright would add are correct `[security] <replacement>` prose, two of them
#: in docs/DEPLOYMENT.md and docs/SECURITY.md -- and SECURITY.md reading 0 is BACKLOG #1383's whole
#: agreed scope, so dropping the alternative is the option that breaks something real.
_NAMES_THE_REPLACEMENT_SECTION = re.compile(rf"\[{_REPLACEMENT_SECTION}\]", re.IGNORECASE)

# TOML values only: quoted string, LOWERCASE bool, or bare number. Capitalised True is Python.
_VALUE = r'("[^"]*"|true|false|\d+)(?![\w])'

#: Fence languages whose content is NOT a `messagefoundry.toml` fragment, so a bare `key = value`
#: inside one is not config a reader would copy. Census of every fence language in docs/**/*.md,
#: 2026-09-20: python (1019 lines), powershell (622), toml (540), unlabelled (512), sql (490),
#: mermaid (284), bash (133), yaml (88), json (77), jsonc (23), text (21), pwsh (18), markdown (7),
#: csv (4). All 6 of the hits this rule removes are `python` fences carrying keyword arguments to a
#: connector or to `outbound()` -- `MLLP(host="pacs", ...)`, `outbound(..., messages_days=7)` and at
#: least three more of that shape. Their values are lowercase Python string literals, which
#: `_VALUE`'s capitalisation rule cannot separate from TOML: it tells `True` from `true` and nothing
#: else. The fence language is the only thing that can.
#:
#: IT IS A DENY-LIST AND THAT IS THE POINT: an unrecognised language FAILS OPEN and gets scanned. An
#: allow-list would fail closed, and a gate that quietly stops scanning a new fence language is the
#: silent under-report this whole rework exists to remove. A false positive from a future language
#: reds the build and gets a name added here, loudly. Unlabelled fences are scanned for the same
#: reason -- measured the same day, including or excluding them gives an identical 39 hits, so the
#: choice is made on which way to fail rather than on the corpus.
_NOT_A_CONFIG_FENCE: Final[frozenset[str]] = frozenset(
    {
        "bash",
        "console",
        "csv",
        "json",
        "jsonc",
        "markdown",
        "mermaid",
        "powershell",
        "pwsh",
        "python",
        "sh",
        "shell",
        "sql",
        "text",
        "yaml",
        "yml",
    }
)


def _dotted_assignment(section: str, key: str) -> str:
    r"""The `[section].key = value` citation pattern for one refused key.

    THE `(?<![\w.])` GUARD IS WHAT KEEPS PYTHON ATTRIBUTE ACCESS OUT, and it is why this spelling
    was excluded by ACCIDENT for as long as it was. `settings.api.public_origin =` and
    `self.public_origin =` reach the key through an identifier and a dot, so rejecting a preceding
    dot rejects them -- and it rejected `[api].public_origin = "..."` with exactly the same
    character, because the guard sat in front of the key rather than in front of the bracket.
    Measured 2026-09-20 over docs/**/*.md: 45 citations before admitting this spelling, 52 after.

    THE PREFIX IS ANCHORED TO THE KEY'S OWN SECTION, and a generic `[\w+]\.` is measurably wrong.
    `enabled` is refused under `[auth]` and is ordinary LIVE config under at least `[cluster]`,
    `[backup]`, `[approvals]`, `[update_check]` and `[integrity]`. Measured the same day, an
    unanchored prefix added 14 hits and every one of them was a correct line of supported config --
    a gate that reports those sends a builder to break working examples, which is the failure
    `test_the_scanner_does_not_flag_a_line_documenting_the_refusal` exists to name.
    `test_the_dotted_form_is_anchored_to_the_keys_own_section` holds this line.

    THIS SPELLING COUNTS WHEREVER IT APPEARS, fence or no fence, because it carries its own section
    and cannot be mistaken for anything else: it is not valid Python, not valid shell, and not a
    key in any other TOML table. Only the BARE spelling needs the context `_citations` reads.

    The BRACKETLESS dotted path (`api.host = "..."`) is deliberately NOT matched: it is
    indistinguishable from attribute access ON A BARE LINE, and it occurs zero times in
    docs/**/*.md, so admitting the ambiguity would buy nothing.
    """
    return rf"(?<![\w.])\[{re.escape(section)}\]\.{re.escape(key)}\s*=\s*{_VALUE}"


def _bare_assignment(key: str) -> str:
    r"""The `key = value` citation pattern, which carries NO section of its own.

    It takes no `section` argument on purpose -- there is nothing on the line to anchor to. What
    section it belongs to is read from the document around it, in `_citations`.
    """
    return rf"(?<![\w.]){re.escape(key)}\s*=\s*{_VALUE}"


#: Built once, not per line. THE ONE PLACE THE SCAN COST IS MEASURED, so the prefilter in
#: `_citations` cites this rather than restating it. One whole-corpus pass over docs/**/*.md
#: (320 files, 91,215 lines), best of three on 2026-09-20, identical hit counts at every step:
#:
#:     2.31s  rebuilding the pattern string per line, as this scan did before
#:     1.84s  compiled once here
#:     0.22s  and `_citations` also skipping the 94 percent of lines with no `=`
#:
#: This generation compiles TWO patterns per key and runs one `line_contexts` pass per document.
#: Re-measured the same way, same corpus (320 files, 91,207 lines): the whole scan is 0.35s, of
#: which `line_contexts` is 0.04s. The annotation is not what costs -- splitting one alternation
#: into two searches is, and 0.35s over the whole corpus is not worth optimising back.
_PATTERNS: tuple[tuple[str, str, re.Pattern[str], re.Pattern[str]], ...] = tuple(
    (section, key, re.compile(_dotted_assignment(section, key)), re.compile(_bare_assignment(key)))
    for section, key in _REFUSED_KEYS
)


def _citations(text: str) -> list[tuple[int, str, str]]:
    """Every line presenting a refused key as config, with the fragment that made it match.

    THE BARE SPELLING IS DECIDED BY THE LINE'S CONTEXT, in three arms: inside a fence whose
    language is not config it never matches, under a `[section]` header it matches only that
    section's own key, and with no header in force it matches as it always did. The first two arms
    are what this rework added (PR #1373 review of PR #1364). Measured 2026-09-20 over
    docs/**/*.md, the 52 hits the previous generation reported fall out as:

        7  dotted, section anchored                                      right by construction
        1  bare, under its OWN section header                            a true citation
        7  bare, under a FOREIGN header ([cluster], [backup], [[inbound]], ...)
        3  bare, under a `[security]` header writing the CORRECT replacement
        6  bare, inside a ```python fence -- Python keyword arguments
       28  bare, with no header in force (prose, or an unheaded fence)

    The middle three groups, 16 lines, were false positives a line-at-a-time scan could not see:
    it read every line in isolation, so it knew neither which `[section]` governed the line nor
    whether the line was code in some other language. All 16 are gone from this generation, and the
    3 under a `[security]` header are the sharpest of them -- the gate was reporting the very
    replacement spelling it exists to steer readers toward.

    THE 28 WITH NO HEADER IN FORCE STAY, and dropping them would have been the wrong cleanup. Prose
    is where the original defect lived: a heading like ``### `require_mfa = false` -- single-factor
    admin`` genuinely tells a reader to write a refused key, and it sits under no `[section]` at
    all. A rework that only scanned inside correctly-headed TOML fences would collapse the corpus to
    about 8 and throw away the gate's main catch -- a regression dressed as a cleanup.
    """
    hits: list[tuple[int, str, str]] = []
    contexts = line_contexts(text)
    # strict=True: `line_contexts` promises one context per line, and a desync would silently read
    # every line against its neighbour's section.
    for lineno, (line, context) in enumerate(zip(text.splitlines(), contexts, strict=True), 1):
        # Every pattern embeds a literal `=`, so a line without one cannot match any of the 16,
        # and 94 percent of the corpus is such a line (see `_PATTERNS` for what that saves).
        # `test_every_pattern_needs_an_equals` is what keeps the shortcut honest if the pattern
        # ever widens to a citation shape with no `=`.
        if "=" not in line or _DISCLAIMS.search(line):
            continue
        bare_reads_as_config = context.fence is None or context.fence not in _NOT_A_CONFIG_FENCE
        names_replacement = _NAMES_THE_REPLACEMENT_SECTION.search(line) is not None
        for section, key, dotted, bare in _PATTERNS:
            if names_replacement and section != _REPLACEMENT_SECTION:
                continue
            match = dotted.search(line)
            if match is None and bare_reads_as_config and context.section in (None, section):
                match = bare.search(line)
            if match is not None:
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

    THESE ARE THREE SPELLINGS, NOT THREE BRANCHES. Only `dotted` exercises the anchored pattern;
    `bare` and `space` both match through the bare one. `space` puts the bracket INSIDE the line,
    where no section-header rule can see it -- a header governs a block and is alone on its line --
    so it is caught by the no-header arm, exactly as `bare` is.
    """
    section, key = next(iter(_RELOCATED_TO_SECURITY))
    prefix = {"bare": "", "space": f"[{section}] ", "dotted": f"[{section}]."}[spelling]
    planted = f"Set `{prefix}{key} = true` in your config.\n"
    assert _citations(planted), f"the scanner did not catch a {spelling} citation of {key}"


def test_a_foreign_section_header_is_not_a_citation() -> None:
    """THE GAP THIS FILE USED TO PIN AS A WRONG ANSWER, now closed.

    HISTORY, KEPT BECAUSE A DELETED TEST LEAVES NO TRACE THE GAP EVER EXISTED. This was
    `test_the_bare_branch_is_still_section_blind`, and it ASSERTED THE WRONG ANSWER ON PURPOSE:
    the bare pattern ignored every bracket on the page, so `[cluster] enabled = true` was reported
    as a citation of the refused `[auth].enabled`. 10 of the 52 hits baselined at the time were
    that shape. The note then read that closing it "means dropping the bare branch or tracking the
    section header, which re-baselines the whole corpus" -- and tracking the header is what
    happened, in this commit, with the whole corpus re-baselined alongside it.

    So the assertion is inverted rather than removed. The POSITIVE arm is not optional: a scan
    broken outright would satisfy the negative one on its own.
    """
    assert ("auth", "enabled") in _REFUSED_KEYS, _REFUSED_KEYS
    foreign = "```toml\n[cluster]\nenabled = true\n```\n"
    own = "```toml\n[auth]\nenabled = true\n```\n"
    assert not _citations(foreign), _citations(foreign)
    assert _citations(own) == [(3, "[auth].enabled", "enabled = true")], _citations(own)


def test_an_array_of_tables_header_governs_its_block() -> None:
    """`[[inbound]]` is a header too, and a tracker that only matched `[table]` read it as none.

    MEASURED AS AN INSTRUMENT ERROR, 2026-09-20, in the very probe that classified the corpus for
    this rework: a first split reported 6 foreign headers and 29 lines with no header in force,
    because its header pattern matched `[table]` and not `[[table]]`. The line it lost is
    docs/CONNECTIONS.md `messages_days = 7` under `[[inbound]]` inside a ```toml fence -- a real
    foreign section reading as prose, which is the arm that KEEPS a hit. The corrected split is 7
    and 28. A header tracker that silently degrades to "no header" fails in the reporting
    direction, so it would never have reddened anything; only the classification caught it.
    """
    assert ("retention", "messages_days") in _REFUSED_KEYS, _REFUSED_KEYS
    foreign = "```toml\n[[inbound]]\nmessages_days = 7\n```\n"
    own = "```toml\n[[retention]]\nmessages_days = 7\n```\n"
    assert not _citations(foreign), _citations(foreign)
    assert _citations(own), "an array-of-tables header of the key's OWN section must still count"


def test_a_list_indented_block_is_still_read() -> None:
    """A fence nested in a numbered step carries a list indent, and so does its header.

    docs/CONNECTIONS.md indents `[inbound.settings]` by two spaces. A column-0-only tracker reads
    that as no header in force and reports the keys under it, which is the same
    unguarded-because-indented defect the shared `TOML_FENCE_RE` comment records for fences.
    """
    assert ("auth", "enabled") in _REFUSED_KEYS, _REFUSED_KEYS
    foreign = "1. Wire it up:\n\n   ```toml\n   [cluster]\n   enabled = true\n   ```\n"
    own = "1. Wire it up:\n\n   ```toml\n   [auth]\n   enabled = true\n   ```\n"
    assert not _citations(foreign), _citations(foreign)
    assert _citations(own), "an indented header of the key's OWN section must still count"


def test_a_fence_resets_the_section_in_force() -> None:
    """A header inside one block must not reach the block after it, or the prose between them.

    Without the reset, a page whose first fence opens `[cluster]` would read every later bare
    `enabled = true` -- prose included -- as `[cluster]`, and the no-header arm that carries 28 of
    the corpus's hits would silently stop firing. That is an under-report, so it is pinned.
    """
    assert ("auth", "enabled") in _REFUSED_KEYS, _REFUSED_KEYS
    text = "```toml\n[cluster]\nenabled = false\n```\n\nSet `enabled = true` to require sign-in.\n"
    assert _citations(text) == [(6, "[auth].enabled", "enabled = true")], _citations(text)


def test_a_non_config_fence_is_not_scanned_for_a_bare_key() -> None:
    """PAIRED CONTROL: the same text is a citation in prose and not one inside a ```python fence.

    `_VALUE`'s capitalisation rule separates `serve_ui=True` from TOML, but it cannot separate a
    lowercase Python string from a TOML string -- `host="epic-host"` is both. The fence language is
    what tells them apart, and docs/CONNECTIONS.md carried 5 of those plus one `messages_days=7`.
    """
    assert ("api", "host") in _REFUSED_KEYS, _REFUSED_KEYS
    fenced = '```python\ninbound = MLLP(host="epic-host")\n```\n'
    prose = 'Set `host="epic-host"` in your config.\n'
    assert not _citations(fenced), _citations(fenced)
    assert _citations(prose), "the same assignment outside a fence must still be a citation"

    # AND THE DENY-LIST MUST FAIL OPEN, which is the half a negative arm alone cannot show.
    # `_NOT_A_CONFIG_FENCE` names the languages measured in docs/; a language it does not name is
    # still scanned. An allow-list would pass the two arms above and silently stop scanning here,
    # which is the shape of every gate that quietly goes vacuous.
    unlisted = '```ini\nhost="epic-host"\n```\n'
    assert "ini" not in _NOT_A_CONFIG_FENCE, _NOT_A_CONFIG_FENCE
    assert _citations(unlisted), "an unrecognised fence language must still be scanned"


def test_a_security_block_is_clean_for_a_relocated_key_and_not_for_a_removed_one() -> None:
    """THE TRAP: `[security]` is the replacement section for 14 keys AND the refused section for 1.

    `_REMOVED_KEYS` contains ("security", "handles_real_patient_data"), so a blanket "exempt
    anything under `[security]`" rule gets that key wrong while getting the other 14 right. Nothing
    about `[security]` is special here -- matching the section handles both, because the question is
    always "is this the key's OWN section?" and the answer happens to differ per key.
    """
    assert ("security", "handles_real_patient_data") in _REFUSED_KEYS, _REFUSED_KEYS
    assert ("auth", "require_mfa") in _REFUSED_KEYS, _REFUSED_KEYS
    replacement = "```toml\n[security]\nrequire_mfa = true\n```\n"
    still_refused = "```toml\n[security]\nhandles_real_patient_data = true\n```\n"
    assert not _citations(replacement), _citations(replacement)
    assert _citations(still_refused), "a REMOVED key in its own section is still a citation"


def test_naming_the_replacement_section_exempts_only_the_keys_that_relocate_there() -> None:
    """The per-key narrowing of the `[security]` exemption, in both directions.

    `_NAMES_THE_REPLACEMENT_SECTION` records what each option measured. This holds the shape: a
    line naming `[security]` beside a RELOCATED key's replacement spelling is exempt, and the same
    line naming `[security]` beside the key that is REFUSED there is not.
    """
    assert not _citations('Write `[security] require_mfa_scope = "every_local_account"` instead.\n')
    assert _citations(
        "A throwaway box must declare `[security].handles_real_patient_data = false`.\n"
    )


def test_every_pattern_needs_an_equals() -> None:
    """`_citations` skips any line with no `=`, leaving 94 percent of the corpus unscanned.

    That is sound only while every pattern requires one. A future widening that admitted a
    citation shape without `=` would silently under-report -- the same blind-spot shape the
    dotted spelling had, found the same way it was: by checking the claim instead of the code.
    """
    for section, key in _REFUSED_KEYS:
        assert "=" in _dotted_assignment(section, key), (section, key)
        assert "=" in _bare_assignment(key), (section, key)


def test_the_dotted_form_is_anchored_to_the_keys_own_section() -> None:
    """NEGATIVE CONTROL, PAIRED with a positive arm so it cannot pass by matching nothing.

    `_dotted_assignment` records why the `[section].` prefix is anchored and what an unanchored one
    measured; this is the test that holds that line. The FIRES arm proves the scanner is live on
    this key, so a regression that broke dotted matching outright could not turn MISSES green.
    """
    assert ("auth", "enabled") in _REFUSED_KEYS, _REFUSED_KEYS
    assert _citations("Set `[auth].enabled = true` in your config.\n")
    assert not _citations("Set `[cluster].enabled = true` in your config.\n")


def test_the_scanner_does_not_flag_python_attribute_access() -> None:
    """NEGATIVE CONTROL: admitting the dotted form must not admit attribute access with it.

    Every probe here carries a LOWERCASE TOML value, so the `_VALUE` capitalisation rule cannot
    rescue it, and none of them sits in a fence, so the fence rule cannot either -- the lookbehind
    in `_dotted_assignment` is the only thing rejecting these, and this test fails the moment it is
    dropped.
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
    Capitalisation is the whole discriminator on a line no fence marks as Python."""
    assert not _citations("`create_app(serve_ui=True)` yields the console plane.\n")


def test_the_line_annotator_agrees_with_the_toml_fence_extractor() -> None:
    """CORPUS-WIDE CONTROL over the two instruments in `tests/_docs_toml.py`.

    They find fences by different mechanisms and the module docstring records why their closing
    rules differ on purpose. That licence is only safe while they still agree about what is inside
    a ```toml fence: if the annotator ended a block early, the scan would read a block's tail as
    prose and its `[section]` header would stop governing -- silently widening the scan rather than
    failing. Every body line of every ```toml fence in docs/ must annotate as `toml`.

    PAIRED WITH THE COUNT, because a zero over zero fences proves nothing: the corpus carries 540
    such lines as of 2026-09-20, and the floor below fails if the extractor ever finds none.
    """
    checked = 0
    disagreements: list[str] = []
    for doc in sorted(DOCS.rglob("*.md")):
        text = doc.read_text(encoding="utf-8")
        contexts = line_contexts(text)
        for fence in TOML_FENCE_RE.finditer(text):
            first = text.count("\n", 0, fence.start()) + 2  # first line INSIDE the fence
            for lineno in range(first, first + fence.group("body").count("\n")):
                checked += 1
                if contexts[lineno - 1].fence != "toml":
                    rel = str(doc.relative_to(REPO)).replace("\\", "/")
                    disagreements.append(f"{rel}:{lineno} -> {contexts[lineno - 1]}")
    assert not disagreements, "the two fence instruments disagree:\n    " + "\n    ".join(
        disagreements
    )
    assert checked >= 400, (
        f"only {checked} fenced TOML lines were compared; the control is going vacuous, which is "
        f"how a zero stops meaning the two instruments agree"
    )


# THE MEASURED BASELINE, AND WHY THIS IS A RATCHET RATHER THAN A CLEAN GATE.
#
# 23 documents carry 53 of these citations -- the row count and the sum of the table below, pinned
# by test_the_header_count_matches_the_table, because two drafts of this line have already drifted
# from the dict they describe: one said 58 against a sum of 59, and the document count read 27
# against 26 rows. BACKLOG #1383's agreed scope is docs/SECURITY.md ONLY -- the ASVS tracker
# recommended that scope, the Liaison endorsed it unaltered, and widening it here would be a scope
# decision nobody made. SECURITY.md is now 0 and is absent from this table.
#
# A gate that only watched one file would let the others spread. A repo-wide gate would land RED and
# get disabled. So this is a RATCHET: no file may exceed its measured count, and a file absent from
# the table must be at zero. New docs and new citations fail immediately.
#
# IT SELF-PRUNES, WHICH IS WHAT KEEPS A BASELINE FROM ROTTING INTO A SUPPRESSION LIST: fixing a
# file below its number FAILS until you lower the number, and fixing it entirely FAILS until you
# delete the row. The list can only shrink, and it cannot silently stop matching reality.
#
# A ROW MOVES FOR TWO DIFFERENT REASONS AND BOTH ARE LEGITIMATE. THE FILE MAKES YOU SAY WHICH.
#
# The gate means: NO SHIPPED DOCUMENT MAY PRESENT A REFUSED CONFIG KEY IN A SHAPE A READER WOULD
# COPY. A row counts LINES THE INSTRUMENT CURRENTLY REPORTS, which is a PROXY for that rule and not
# the rule itself. So:
#
#   * A DOCUMENT FIX lowers exactly one row, and the header sentence's sum with it. `_SCAN_GENERATION`
#     is untouched. Someone rewrote a line; the instrument is unchanged and every other row still
#     holds.
#   * An INSTRUMENT CHANGE re-measures the WHOLE table in the SAME commit as the scan change, and
#     changes `_SCAN_GENERATION` to say what the scan now reads. Rows may move in EITHER direction:
#     a scan that learns to read something new goes up, a scan that learns to stop misreading goes
#     down, and neither is a document getting better or worse.
#
# test_the_header_count_matches_the_table pins the generation string alongside the counts, so the
# second case cannot be committed while looking like the first. Before this convention existed there
# was nothing in the file telling the two apart, and a reader finding a lowered row could not know
# whether a document had been fixed or the scanner had stopped seeing it.
#
# WHAT EACH GENERATION MEASURED, so a row's history reads straight:
#   * BACKLOG #1279 WIDENED THE SCAN to `_REMOVED_KEYS` and the count went UP. The rows it added are
#     all HISTORICAL: an accepted ADR recording what a since-removed key did, and closed ledger rows
#     quoting the same. Those cannot be rewritten to a live spelling, because there is none -- the
#     key relocated to nothing. A ratchet whose only remedy is to delete a decision record is the
#     wrong instrument, so they are baselined. What the widening DOES catch is the case it was added
#     for: a NEW doc telling a reader to write one, which fails immediately, at zero.
#   * ADMITTING THE DOTTED `[section].key` SPELLING (post-merge review of PR #1364) took the on-disk
#     count from 45 to 52 and added two rows, for the same reason, and all seven new citations are
#     ADR prose recording what a since-removed or since-relocated key did.
#   * THIS GENERATION made the scan FENCE-AWARE and SECTION-AWARE (PR #1373 review), which is the
#     first re-measure to move rows DOWN: on-disk 52 to 39, and 26 rows to 21. `_citations` holds
#     the per-arm breakdown of the 16 lines that went and why each was a false positive, and
#     `_NAMES_THE_REPLACEMENT_SECTION` holds the 3 that were ADDED in the same pass -- a refused key
#     that a blunter exemption had been hiding. Do not read the smaller number as documents getting
#     better; nothing in docs/ changed in this commit.
#
# FIVE ROWS WENT TO ZERO AND WERE DELETED, all for the same reason: their one hit was a bare key
# under a foreign `[section]` header inside a ```toml fence, so it was never a citation at all.
# Named here rather than as a comment on a surviving row, because a note about a DELETED row has no
# row to sit on and reads as a claim about whichever line follows it:
#
#     docs/adr/0049-turnkey-dr-backup-restore-verify.md            [backup] enabled
#     docs/adr/0056-engine-managed-vip-failover.md                 [cluster.vip] enabled
#     docs/CLUSTERING.md                                           [cluster] enabled
#     docs/EARLY-ADOPTER-GUIDE.md                                  [cluster] enabled
#     docs/MENTAL-MODEL.md                                         [cluster] enabled
#
# `enabled` is the key behind all five: it is refused under `[auth]` and is ordinary live config
# under at least `[cluster]`, `[backup]` and `[cluster.vip]` (see `_dotted_assignment`).
#
# THE TWO WITHHELD ROWS BELOW COULD NOT BE RE-MEASURED, AND THEIR EPISTEMIC STATUS CHANGED WITH THIS
# GENERATION. Their documents are in no clone (see _WITHHELD_FROM_PUBLIC_CHECKOUTS). Under the
# previous generation they were LOWER BOUNDS, and honestly so: every change to that point WIDENED
# the scan, and widening can only raise a count. This generation NARROWS it, so the two numbers are
# now bounds in an UNKNOWN direction -- 12 and 2 may each be too high, too low, or right, and
# nothing in any checkout can tell. Whoever holds those documents must re-measure them. Set
# MEFOR_DOCS_CITE_WITHHELD_ROOT at a tree that carries them and the rows are enforced exactly,
# rather than hand-edited; the sibling guards this exemption was borrowed from
# (MEFOR_THREAT_MODEL_DOC, MEFOR_COVERAGE_PLAN_DOC) ship the same affordance per document.
_BASELINE: dict[str, int] = {
    # Dotted spelling, PR #1364 review: was 1, the added one is `[ai].data_class`.
    "docs/adr/0014-alerting-rules-engine.md": 2,
    # Dotted spelling, PR #1364 review: a NEW row, both hits `[ai].data_class` in this ADR's prose.
    "docs/adr/0019-pluggable-keyprovider-hsm-kms-vault.md": 2,
    "docs/adr/0022-fhir-resource-codec-rest-client.md": 1,
    "docs/adr/0027-per-connection-retention.md": 1,
    "docs/adr/0096-cluster-leader-preference-and-non-promotable-standby.md": 1,
    # #1279: was 2. Dotted spelling, PR #1364 review: was 5, the added one is the
    # `# was [ai].data_class = "phi"` migration note. Fence + section: was 6, and the two that went
    # are the `[security]`-block case -- correct replacement config, reported as a defect.
    "docs/adr/0118-secure-by-default-security-configuration-section.md": 4,
    # Dotted spelling, PR #1364 review: a NEW row -- three `[store].allow_unencrypted_phi=true`,
    # all of them this ADR stating what the audited opt-out did, including its acceptance
    # criterion.
    "docs/adr/0109-at-rest-encryption-fail-closed-on-an-undeclared-phi-posture.md": 3,
    # #1279 rows below: each records what the removed key did, in a decision record.
    # Fence + section: 0115, 0148 and 0186 each gained one `[security].handles_real_patient_data`
    # that the old per-line `[security]` exemption hid.
    "docs/adr/0115-asvs-l3-drive-to-pass-secure-by-default-flips-and-residual-closure.md": 2,
    "docs/adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md": 3,
    "docs/adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md": 2,
    # The owner's ruling, quoted verbatim in the status line. CLAUDE.md forbids rewriting a
    # quotation, and the sentence retiring the key necessarily contains the key.
    "docs/adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md": 2,
    "docs/adr/0135-engine-brokered-ai-assistance-customer-managed-llm-egress-with-per-use-audit.md": 1,
    "docs/adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md": 2,
    "docs/adr/0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md": 1,
    "docs/CLOUD-PHI-HIPAA.md": 1,
    "docs/CONFIGURATION.md": 3,
    # Fence + section: was 9, the single largest false-positive cluster in the corpus and the one
    # that made both instruments load-bearing at once -- 6 were `python` fences (connector and
    # `outbound()` keyword arguments), 1 sat under `[outbound.settings]` and 1 under `[[inbound]]`,
    # which is the array-of-tables shape a `[table]`-only header tracker reads as no header at all.
    "docs/CONNECTIONS.md": 1,
    # Fence + section: was 3, and the one that went sat under a `[security]` header.
    "docs/CONTAINER-EXPOSURE-EVALUATION.md": 2,
    "docs/REMOTE-CONSOLE.md": 1,
    "docs/SECURITY-LOOSENING.md": 3,
    "docs/testing/master-test-plan/03-store-and-data-lifecycle.md": 12,
    "docs/testing/master-test-plan/16-security-phi-and-supply-chain.md": 2,
    "docs/TRAY.md": 1,
}

# THE ONLY ROWS A CLONE MAY LEGITIMATELY LACK, and naming them is the point: an exemption that
# said "any missing file is fine" would delete the self-pruning property this baseline exists to
# have. Both of these are UNTRACKED -- `git ls-files` does not report them, they sit on a
# maintainer's disk, and no checkout anywhere carries them. CI simply cannot see the documents, and
# failing on that made this test unpassable on every runner while the baseline was correct about
# the corpus it describes. tests/test_threat_model_doc_drift.py and tests/test_crit2_inline_doc_drift.py
# make the same call for their own withheld documents: warn that the assertion is inert, do not fail.
# A row here that IS present on disk is still enforced exactly, so the ratchet holds locally.
_WITHHELD_FROM_PUBLIC_CHECKOUTS = frozenset(
    {
        "docs/testing/master-test-plan/03-store-and-data-lifecycle.md",
        "docs/testing/master-test-plan/16-security-phi-and-supply-chain.md",
    }
)

#: Point this at a tree that carries the withheld documents (a maintainer's working copy) and their
#: rows are measured and enforced like any other. Only a row named above consults it: a row that is
#: merely MISSING stays a hard failure, so the override cannot be used to park an unmeasured path.
_WITHHELD_ROOT_ENV: Final = "MEFOR_DOCS_CITE_WITHHELD_ROOT"


class BaselineRowUnenforced(UserWarning):
    """A baseline row names a document this checkout does not carry."""


def _withheld_copy(rel: str) -> pathlib.Path | None:
    """The overridden location of a withheld document, when one is configured and present."""
    root = os.environ.get(_WITHHELD_ROOT_ENV, "").strip()
    if not root:
        return None
    candidate = pathlib.Path(root) / rel
    return candidate if candidate.is_file() else None


def _audit(baseline: Mapping[str, int]) -> tuple[list[str], int]:
    """``(complaints, rows actually read)`` for ``baseline`` against this checkout.

    Split out of the test so the withheld-root override can be exercised against a synthetic
    baseline: the real table names two documents no checkout carries, so nothing else could prove
    the override enforces rather than merely resolves.
    """
    stale: list[str] = []
    enforced = 0
    for rel, expected in baseline.items():
        path = REPO / rel
        if not path.exists():
            if rel not in _WITHHELD_FROM_PUBLIC_CHECKOUTS:
                stale.append(f"{rel}: listed but missing")
                continue
            override = _withheld_copy(rel)
            if override is None:
                warnings.warn(
                    f"{rel} is absent from this checkout, so its baseline of {expected} is "
                    f"INERT in this run. It is enforced wherever the document exists, and "
                    f"{_WITHHELD_ROOT_ENV} points this row at a tree that carries it.",
                    BaselineRowUnenforced,
                    stacklevel=2,
                )
                continue
            path = override
        enforced += 1
        actual = len(_citations(path.read_text(encoding="utf-8")))
        if actual != expected:
            verb = "now clean -- delete this row" if actual == 0 else f"now {actual} -- lower it"
            stale.append(f"{rel}: baseline says {expected}, {verb}")
    return stale, enforced


def test_the_header_count_matches_the_table() -> None:
    """The comment above `_BASELINE` states a row count, a sum, and which scan produced them.

    That sentence has drifted twice already: one draft read 58 against a sum of 59, another read
    27 documents against 26 rows. This file's whole argument is that the table is the single
    source of truth, and that is worth nothing while the sentence introducing it can quietly
    disagree. Change a row, change the header -- this is what makes you.

    THE GENERATION STRING IS PINNED HERE FOR A DIFFERENT REASON, and it is the one that needed a
    ruling: the counts alone cannot say WHY a row moved. Lowering a row without touching the
    generation asserts a document was fixed; re-measuring the table and moving the generation
    asserts the instrument changed. The comment above `_BASELINE` writes both cases out.
    """
    # The generation string is repeated as a LITERAL rather than compared to itself: asserting
    # `_SCAN_GENERATION == _SCAN_GENERATION` would pass whatever it said, which is the vacuous shape
    # this file keeps pairing controls against. Change the constant and this literal together.
    assert (len(_BASELINE), sum(_BASELINE.values()), _SCAN_GENERATION) == (
        23,
        53,
        "fence-aware + section-aware, 2026-09-20",
    )


def test_every_withheld_row_is_still_a_baseline_row() -> None:
    """The exemption must not outlive the rows it exempts.

    Delete a row from _BASELINE and leave its name here, and this file starts carrying a
    permanent licence for a path nothing measures -- a suppression list growing in the one place
    the ratchet cannot see. Tie the two together so that cannot happen quietly.
    """
    orphans = sorted(_WITHHELD_FROM_PUBLIC_CHECKOUTS - set(_BASELINE))
    assert not orphans, f"exempted paths that are no longer baseline rows: {orphans}"


def test_the_withheld_root_override_enforces_rather_than_merely_resolves(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PAIRED CONTROL on `_WITHHELD_ROOT_ENV`: the right count passes and a wrong one fails.

    An override that only located the file would look identical to one that measured it, right up
    until a maintainer trusted it. The planted document carries exactly one citation.
    """
    rel = next(iter(sorted(_WITHHELD_FROM_PUBLIC_CHECKOUTS)))
    planted = tmp_path / rel
    planted.parent.mkdir(parents=True, exist_ok=True)
    section, key = next(iter(_RELOCATED_TO_SECURITY))
    planted.write_text(f"Set `[{section}].{key} = true` in your config.\n", encoding="utf-8")
    monkeypatch.setenv(_WITHHELD_ROOT_ENV, str(tmp_path))

    stale, enforced = _audit({rel: 1})
    assert (stale, enforced) == ([], 1), (stale, enforced)
    stale, enforced = _audit({rel: 0})
    assert enforced == 1 and stale, (stale, enforced)

    # And with no override the same row is INERT rather than wrong -- the behaviour every public
    # checkout gets, which is what makes the arms above a comparison rather than a single reading.
    monkeypatch.delenv(_WITHHELD_ROOT_ENV)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        stale, enforced = _audit({rel: 999})
    assert (stale, enforced) == ([], 0), (stale, enforced)
    assert any(w.category is BaselineRowUnenforced for w in caught), [w.category for w in caught]


def test_the_baseline_is_exact_and_self_pruning() -> None:
    """A baseline row that no longer matches is a lie about the corpus, so fail on it.

    This is the half that stops a ratchet decaying into a permanent allowlist: you cannot fix a
    document and leave its old number behind, and you cannot list a file that is already clean.

    ABSENT IS NOT STALE. A row whose document this checkout does not carry is UNENFORCED, not
    wrong, and only the paths named in _WITHHELD_FROM_PUBLIC_CHECKOUTS get that reading. Any
    other missing file is still a hard failure -- deleting or renaming a document you have not
    de-listed is exactly the drift this test is for.
    """
    stale, enforced = _audit(_BASELINE)
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
