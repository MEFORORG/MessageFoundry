#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Forbidden-content scanner: keep customer/PHI-adjacent strings out of the public repo.

Two callers share this one module so their detection can never drift:
  * ``.pre-commit-config.yaml`` runs it over staged files before every commit.
  * ``.github/workflows/security.yml`` runs it over the whole tracked tree in CI.

Why a custom scanner in addition to gitleaks: gitleaks finds *secrets* (keys/tokens). This finds
*customer-identifying* strings -- a partner/vendor name, a real site-estate's site-code prefix, a
routable host IP -- which are not credentials but must never reach the open-source repo.

Token authority is EXTERNALIZED. The committed source carries only STRUCTURAL detectors -- at least a
routable-IPv4 detector, a worktree/branch slug detector, an absolute-home-path detector, a private
artifact-URL detector and the prefix-free estate-identifier *shape*; the real customer/vendor name
patterns, estate substrings, and the site-code numeric prefix are loaded at runtime from, in order
of precedence:

  1. ``MEFOR_FORBIDDEN_TOKENS`` -- either a path to a token file OR the token content inline
     (newline-separated, same format). Used in CI via the Actions secret of the same name.
  2. ``scripts/security/scan-tokens.local.txt`` -- a git-ignored local file (pre-commit). A synthetic
     template ships as ``scan-tokens.local.txt.example``.

With no source present the scanner degrades to STRUCTURAL-ONLY (the shape detectors above stay live);
the name / estate / site-code detectors are simply empty -- appropriate for a fork with no access to
the secret. STRUCTURAL-ONLY IS NOT A CLASS-LEVEL CLEAN: the shape detectors catch a *shape*, so a
green structural-only run says nothing about a partner/vendor name, or about a site code carried in
prose, in a hyphenated name, or in an HL7 field. Only a loaded token source covers those.
Set ``MEFOR_REQUIRE_TOKENS=1`` to fail closed (exit 2) instead when the source is absent, so a
misconfigured owner/CI run refuses rather than silently under-scanning.

PRESENCE IS NOT SUFFICIENCY. A source that loads only PART of its tokens is the dangerous case: it
satisfies "tokens present", prints no structural-only warning, and passes a gate that calls itself
fail-closed. So requiring tokens also requires every floor section (``names`` / ``estate`` /
``site_prefixes``) to be non-empty, and ``MEFOR_MIN_DETECTORS=N`` (or ``--require-tokens=N``) asserts
a minimum TOTAL, which is what catches loss *within* a section. It is a floor, not an equality:
adding tokens is free, losing them fails. The expected total comes from OUTSIDE the token source --
a count carried inside the file would be destroyed by the same mangling it is meant to detect.

``--require-tokens[=N]`` exists because pre-commit can pass args to a hook but cannot set env for
one, so it is the only way to make the commit-time gate fail closed on a checkout with no token file.

Token-file format (sectioned; ``#`` comments and blank lines ignored):
  [names]        REGEX | REASON | CASE  -- REASON optional (default "customer/vendor token");
                 CASE optional: "i" case-insensitive (default) or "s" case-sensitive. The field
                 delimiter is a space-pipe-space (`` | ``); a regex alternation ``a|b`` is unaffected.
  [estate]       one substring token per line (matched case-insensitively, anywhere in a body).
  [site_prefix]  one numeric prefix per line; the detector matches PREFIX + four digits.

Usage:
  scan_forbidden.py [FILE ...]      # scan the given files (how pre-commit invokes it)
  scan_forbidden.py --path DIR      # scan every text file under DIR
  scan_forbidden.py --show-context  # also print the matched line/value (NEVER used in CI -- a hit
                                    #   means the content already sits in a tracked file, so echoing
                                    #   it would copy the leak into public CI logs; default is
                                    #   reasons-only: location + category, never the matched text)
  scan_forbidden.py                 # scan all git-tracked files in the current repo
  scan_forbidden.py --self-test     # probe each LOADED class with a string derived from itself, so a
                                    #   table that parsed but cannot match is caught. Counts and class
                                    #   names only -- never a token, so it is safe in public CI.

Exit: 0 clean, 1 forbidden content found (fail closed), 2 usage error / required-tokens-missing /
self-test failure (an instrument that cannot see is not a content hit; the two need different fixes).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------------------------------
# Structural detectors (NO customer data -- safe to commit). These run regardless of the token source.
# --------------------------------------------------------------------------------------------------

# Routable-IPv4 detector. The look-arounds keep dotted OIDs (1.3.6.1..., 2.16.840...) and version
# strings embedded in longer dotted sequences from matching; only a free-standing IPv4 does.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.])")
# Non-routable / documentation / loopback prefixes never identify a real host: RFC1918 private,
# loopback, link-local, broadcast, RFC5737 TEST-NET-1/2/3 (documentation), multicast/reserved.
_ALLOWED_IP = re.compile(
    r"^(?:"
    r"0\.|127\.|10\.|192\.168\.|169\.254\.|255\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|"  # 172.16.0.0/12
    r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|"  # TEST-NET-1/2/3 (RFC 5737)
    r"22[4-9]\.|23\d\."  # 224.0.0.0+ multicast/reserved
    r")"
)

# Internal-environment disclosure. Neither of these is a customer token, so NO token list can catch
# them -- they are recognised by SHAPE, and they are therefore live even in structural-only / fork
# runs where the token tables are empty. Both reached a publish dry run undetected once.
#
# A worktree/branch slug is whatever the task happened to be CALLED, so it can name a prospect segment,
# a customer engagement, or a competitor study. That is unbounded: the leak is the project name itself,
# and there is no list to add it to. Matching the shape is the only control that scales. It is
# case-folded whole: agent slugs are lowercase by convention, but nothing on the path lowercases them --
# scripts/worktree/new.ps1 hands -Branch to `git worktree add -b` after validating it with
# `git check-ref-format` (which permits mixed case), and -Name reaches the worktree DIRECTORY verbatim.
# So an upper-cased slug is reachable -- and unlike _HOME_PATH no common URL shape collides here.
#
# The shape, assembled from ONE word atom so the two arms below cannot drift into different
# definitions of "slug". A second spelling of the shape is a second thing to keep in step, and the
# arms disagreeing about what a slug is would be invisible.
_SLUG_WORD = r"[a-z0-9]+"
_SLUG_HEAD = rf"{_SLUG_WORD}(?:-{_SLUG_WORD})*"  # one or more words -- whatever the task was called
_SLUG_HEAD_MULTI = rf"{_SLUG_WORD}(?:-{_SLUG_WORD})+"  # two or more; see the bare arm for why
_SLUG_HEX = r"[0-9a-f]{6}"  # the suffix the tooling appends

# ARM 1 -- the path-prefixed form. The prefix IS the evidence, so this arm needs no other context and
# fires anywhere in a line. Unchanged behaviour: it is the detector that has always shipped.
_WORKTREE_SLUG_PATH = re.compile(rf"(?i:(?:claude/|worktrees/){_SLUG_HEAD}-{_SLUG_HEX})")

# ARM 2 -- the BARE form (BACKLOG #1083). The prefix used to be MANDATORY, so the identical slug
# written in prose matched the shape and not the pattern and shipped; one instance sat on `origin`
# for two days while the guard passed every commit.
#
# Making the prefix merely optional is the wrong fix, and this is MEASURED, not feared: over the 1968
# tracked non-binary files at b3bc8026 an ungated bare shape matched 116 lines, nearly all of them
# ordinary prose -- hyphenated words whose tail is six letters that are also six hex digits, dotted
# namespaces ending in a six-digit year-month, and the short blob ids this repo writes constantly. A
# guard that fires on healthy content gets allowlisted into uselessness, which is worse than the leak
# it misses. So the bare arm narrows by CONTEXT rather than by shape: the slug must either BE a
# backticked token, or follow a lead-in word that says an identifier is coming. Same corpus, same
# run: 5 lines, all five genuine bare slugs, zero false positives.
#
# The lead-in set is closed and deliberately short. Adding a word widens the gate everywhere; it is
# cheaper to be missed here than to be switched off.
_SLUG_LEAD_IN = r"\b(?:session|worktree|branch|lane|slug|agent|seat)(?:es|s)?\b"

# Hand-written stand-in hex. Prose ABOUT this detector -- the backlog items that describe it, the
# fixtures in its own test suite -- spells the suffix as an obvious placeholder, and a guard that
# refuses its own documentation is exactly the pressure that gets a guard allowlisted off. The same
# judgement (and the same closed-list shape) as _HOME_PATH's `me`/`svc`/`you` exemption below.
# SCOPED TO THIS ARM ON PURPOSE: arm 1 has the prefix as its evidence and must keep firing on a
# prefixed stand-in, which is how both of its casing fixtures are written.
_SLUG_PLACEHOLDER_HEX = r"(?:a1b2c3|abc123|abcdef|123456|000000)"

# TWO words minimum, where arm 1 accepts one, and the asymmetry was measured the hard way. Over the
# tracked corpus a one-word bare head cost nothing -- a NULL produced by luck rather than by a
# mechanism, since no such token happened to be backticked anywhere in the tree. The missing positive
# control arrived from writing this comment block: an earlier draft named three of the colliding
# tokens in backticks, and the detector fired on the paragraph describing it. They were reworded to
# the prose form used above, which is why no example here is spelled out. A one-word head plus a
# six-letter tail is a hyphenated English word; the generated slugs this guard exists for are
# adjective-noun-hex. The cost is a real and accepted gap: a genuine one-word bare slug is missed
# unless it carries a path prefix.
#
# The TRAILING guard is load-bearing in a way the prefixed arm's is not: `[0-9a-f]{6}` would
# otherwise match the first six characters of a longer hex run, so a full-length blob id after a
# lead-in word (`branch foo-bar-1234567890ab`) would read as a slug. There is deliberately no LEADING
# guard: a symmetric one was written and then measured out. It suppressed a real detection
# (`session -quiet-harbour-<hex>`, where the separator is a hyphen) and, over the same 1968-file
# corpus, changed the hit set by nothing in either direction -- the mid-slug start it was meant to
# prevent still reports the same LINE, which is the granularity this scanner reports at.
_SLUG_BARE = (
    rf"{_SLUG_HEAD_MULTI}-(?!{_SLUG_PLACEHOLDER_HEX}(?![A-Za-z0-9-]))"
    rf"{_SLUG_HEX}(?![A-Za-z0-9-])"
)
_WORKTREE_SLUG_BARE = re.compile(
    rf"(?i:`{_SLUG_BARE}`|{_SLUG_LEAD_IN}[^A-Za-z0-9]{{1,12}}{_SLUG_BARE})"
)

#: Both arms, reported as ONE finding per line. `worktrees/` is itself a lead-in word, so a prefixed
#: path satisfies both; double-reporting one line adds noise rather than information.
_WORKTREE_SLUG_DETECTORS: tuple[re.Pattern[str], ...] = (
    _WORKTREE_SLUG_PATH,
    _WORKTREE_SLUG_BARE,
)
# An absolute user-home path carries the OS account name, and inside a worktree path the slug as well.
# Exempt: bracket/env placeholders (<you>, $HOME, %USERPROFILE%, {home}), the well-known shared and CI
# accounts, and the DOCUMENTATION placeholder names this repo already uses in examples (me, svc, you,
# user, username, example). Everything else looks like a real account and fires. That list is the whole
# judgement call here: "is this a real person's login" is not decidable by shape, so the pattern trusts
# a small, explicit set of conventional stand-ins and treats anything else as a disclosure.
#
# The drive-letter arm folds case INLINE. Windows paths are case-INSENSITIVE, so `C:\Users\<name>`,
# `c:\users\<name>` and `C:\USERS\<name>` are the SAME directory naming the SAME account, and a
# literal `Users` caught only one of those four spellings. (The examples use the `<name>`
# placeholder the lookahead below exempts: a real account segment written here would trip this
# very detector.) Keep the fold SCOPED to that arm -- do NOT lift it to a whole-pattern
# re.IGNORECASE. That also lower-cases the POSIX /Users arm, and `/users/` is an extremely
# common URL segment: measured, it then matches the web console's /ui/users/... routes in 47
# places on the tracked tree and reds this required context on its first run. The exemption
# list below stays case-SENSITIVE for the inverse reason -- on POSIX `Public` and `public` are
# DIFFERENT accounts, and widening an exemption is the under-detection direction.
_HOME_PATH = re.compile(
    r"(?:(?i:[A-Za-z]:[\\/]users)|/home|/Users)[\\/]"
    r"(?!<|\$|%|\{"
    r"|(?:Public|Default|All|ContainerAdministrator|runner|vsts"
    r"|me|svc|you|user|username|example)[\\/\s\"'`]"
    r")"
    r"[A-Za-z][A-Za-z0-9._-]*"
)

# Private artifact URL (BACKLOG #1454). The UUID here is not a name, it is a CAPABILITY: whoever holds
# the URL can fetch the artifact, so the string discloses the CONTENT the way a token does rather than
# the way a hostname does. Every other detector in this file recognises something that IDENTIFIES a
# party; this one recognises something that GRANTS ACCESS, which is why none of them can stand in for
# it. An artifact URL carries no home path, no host address and no estate identifier.
#
# It arrives the way this whole class arrives -- pasted out of one session into a note, a handoff or a
# backlog row that a later commit sweeps into the tree. This repo is public on GitHub and on PyPI, so
# the paste and the publication are one step apart.
#
# PREVENTIVE, NOT REMEDIAL, and measured rather than assumed. At 16efb8cde over the 2095 tracked files
# the population is zero. THE CONTROL IS THE PART THAT MAKES THAT ZERO MEAN ANYTHING, and it must be a
# control that FIRES over this same corpus -- an earlier draft of this block quoted a slug-detector
# count as its control, which is itself zero on a healthy tree, so every row was a zero and the block
# demonstrated only that something had been typed:
#
#     detector hits over 2095 tracked files                      = 0
#     CONTROL needle='<uuid-shape>' (bare UUID) over that corpus = 8 files / 35 lines   (FIRES)
#     CONTROL planted URL through scan_file                      = 1 hit                (FIRES)
#
# Filed anyway because the sibling project hit it for real: KORUS carried two of these on its own
# origin/main from the commit that brought its playbooks over, and its leak gate passed them both.
# They came out because a person read the diff, which is the review this gate exists to make cheaper.
#
# THE UUID SHAPE IS REQUIRED ON PURPOSE, and it is what keeps the detector off its own documentation.
# The placeholder this file, its tests and any future ADR have to print -- claude.ai/code/artifact/
# followed by a bracketed <uuid> -- is not a hit. The alternative is a detector whose own manual trips
# it, which earns an allowlist line, and an allowlist line here is a per-line veto over every OTHER
# detector on that line too.
#
# THREE ADDRESSES, NOT ONE, and this is read off the vendor's own grammar rather than guessed. The
# installed client (claude.exe 2.1.259, recovered with `grep -a`, negative control returning 0) parses
#
#     /code/(?:artifact|frame)/(?:([A-Za-z0-9_-]*)-)?(<uuid>)(?:[/?#]|$)
#
# and separately builds `${uuid}.frame.${env}claudeusercontent.com`. So `frame` is a sibling of
# `artifact`, an OPTIONAL human-readable vanity segment may sit between the path and the UUID, and the
# content host carries the UUID as a SUBDOMAIN with the string `claude.ai` absent entirely. A pattern
# anchored on `artifact/` immediately followed by the UUID -- which is what this detector shipped as
# first, and what KORUS still carries -- reports a file holding any of the other forms as CLEAN. The
# vanity form is the one that matters most, because it is the shape a person's address bar produces
# and pasting is the whole arrival path above.
#
# A PUBLICLY SHARED artifact still does not match: that path segment is plural (/public/artifacts/),
# so the singular literal cannot reach it. A deliberately published URL is not a disclosure.
#
# NO BARE-UUID DETECTOR, and that is a decision with a number behind it. A bare UUID names no host, no
# account and no project -- it is an opaque 128-bit integer, and it becomes a disclosure only when
# something says what it addresses, which is exactly what the URL prefix supplies. Measured over the
# same 2095 files, a bare-UUID detector would fire on 35 lines across 8 files TODAY, every one of them
# innocent: a vendored CLA action bundle, a deployment guide, an HL7 sample message, and five test
# modules that build session ids. That is a false-positive storm on the first run, each one answered
# with an allowlist line that switches this whole gate off for the lines it covers. A gate people mute
# is worth nothing. (KORUS reasoned to the same conclusion from a zero; a zero argues weakly either
# way, so the number above is the one to cite.)
#: The UUID, written once so the two arms below cannot drift into different ideas of one -- the same
#: single-atom discipline the slug detector's two arms follow.
_ARTIFACT_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

_ARTIFACT_URL = re.compile(
    # ARM 1 -- the path form on claude.ai. The vanity segment is bounded at 64 characters rather than
    # left unbounded as the vendor writes it: the grammar's `*` is safe there because it is anchored
    # at both ends, and here it is not. {0,64} still admits the vendor's own cap of 60.
    rf"claude\.ai/(?:code/)?(?:artifact|frame)/(?:[A-Za-z0-9_-]{{0,64}}-)?{_ARTIFACT_UUID}"
    # ARM 2 -- the direct content host, where the UUID is a SUBDOMAIN and `claude.ai` never appears,
    # so arm 1 cannot see it however it is widened. A literal host anchors it, so it carries no
    # false-positive risk worth trading against.
    rf"|{_ARTIFACT_UUID}\.frame\.(?:staging\.)?claudeusercontent\.com",
    re.IGNORECASE,
)

# Ported-estate identifier SHAPE. The site-code detectors below are keyed on a numeric PREFIX loaded
# from the token source, so they are _NEVER until the owner adds that estate's prefix -- and an estate
# whose prefix nobody has added yet is exactly the one that leaks. Measured on this repo's own history:
# a required merge context exited 0 on a tracked file carrying a real site code, because the file WAS
# scanned and the loaded detectors simply did not cover that prefix (BACKLOG #321). This one is keyed
# on STRUCTURE, so like the two detectors above it fires with no token source at all -- a backstop
# rather than a second thing waiting on the owner.
#
# The UNDERSCORE ANCHOR is the entire design, and it is what keeps a required gate from crying wolf.
# A bare delimited six-digit run matches 1,414 lines across 152 tracked files (HL7 samples, DMV soak
# rows, benchmark artifacts, lock files) -- counted over EVERY scanned file, which is the population
# this detector actually sees, since unlike the site-code detectors below it is not skip-gated. (The
# skip-gated population is 638/145; quoting that number for an ungated detector would be an
# instrument that answers the adjacent question.) Requiring the run to join a LETTER-BEARING
# identifier segment takes that to 5, every one of them this gate's own illustration of the shape,
# and to 0 once those five adopt the house placeholder. That is the
# form the class actually takes here -- the [TYPE]_[PARTNER]_[MESSAGE] connection convention
# (docs/CONNECTIONS.md) and the Corepoint PT_* pattern both produce it, and so did both identifiers
# the #321 audit found -- replayed against the content that got through, this fires on it and on no
# other line of that file.
#
# WIDTH IS PINNED AT SIX because that is what the format yields -- a site code is a numeric prefix
# plus four digits (see _SITE_CODE_FILE below) over the two-digit prefix space the anonymizer models
# (anon/surrogates.py builds non-site prefixes from range(10, 100)). Measured either side: five digits
# collides with the harness's zero-padded connection names (IB_CS_00000 and siblings, three files),
# seven matches nothing at all. A leading-zero carve-out would buy the width-5 band back, and is
# deliberately NOT taken: it is a silent under-detection hole in a gate whose filed defect is an
# unnoticed blind spot, and the one line it would have rescued is a docstring example that the house
# placeholder convention fixes instead.
#
# HYPHEN IS EXCLUDED, measured: the same shape joined by "-" re-admits 11 hits across 6 files, every
# one a false positive (a dated OASIS namespace quoted in security-critical code, a CFR citation, a
# sandbox depth constant, a synthetic MRN).
#
# NOT gated on the _SITE_SKIP_* sets, unlike the site-code detectors. Their skip exists because BARE
# digit runs storm in lock/SVG/password files; the anchor already removes that storm (measured: zero
# matches across those files), so the skip would only open a hole -- a flame-graph SVG's frame labels
# are function names, and a transform function name is one of the two forms this exists for.
_ESTATE_ID_SHAPE = re.compile(
    r"(?<![A-Za-z0-9.])"
    # Arm 1, code-trailing: `PT_<code>_ADT`, `IB_FEED_<code>.py`. The trailing lookahead permits `.`
    # so a module filename written in prose is not waved through, but still pins the run at exactly
    # six digits.
    r"(?:[A-Za-z][A-Za-z0-9]*_\d{6}(?![A-Za-z0-9])"
    # Arm 2, code-leading: `<code>_router.py`. It also rescues a segment arm 1 cannot reach, because
    # the segment before the code starts with a digit (`IB_2ND_<code>_MFN`). No trailing lookahead:
    # the following segment must merely CONTAIN a letter, which is what rejects `1_000000_2`.
    r"|\d{6}_[A-Za-z0-9]*[A-Za-z])"
)
#: Shared so the content hit and the file-name hit are one grep, and so the reason describes the SHAPE
#: rather than asserting the class: this cannot tell a site code from a coincidental six-digit segment,
#: and a reason reading "site code" would make a green run read as "no site codes here".
_ESTATE_ID_REASON = "six-digit run inside an underscore-joined identifier"

# A pattern that can never match -- the "detector off" sentinel used for the site-code regexes when no
# numeric prefix is loaded (structural-only / fork context). ``(?!)`` is an always-failing assertion,
# so ``.search``/``.finditer``/``.fullmatch`` never fire and ``.pattern`` stays a valid string.
_NEVER: re.Pattern[str] = re.compile(r"(?!)")

# --------------------------------------------------------------------------------------------------
# SECURITY-RECORD CONTENT (BACKLOG #1337). A requirement identifier PAIRED WITH ITS VERDICT.
#
# WHAT IS AND IS NOT RECORD CONTENT, because the distinction is the whole detector:
#   * A BARE CITATION is a forward reference -- "this code was written with that requirement in
#     mind". It asserts no coverage, no result and no gap, and it is legitimately public: the
#     backlog's own item titles read `#1107 ASVS 1.2.2 -- apiclient path encoding`. NOT a hit.
#   * AN IDENTIFIER SITTING BESIDE A VERDICT is the assessment itself, and the assessment is
#     vaulted. THAT is the pair this matches.
#
# WHY NOT MATCH THE IDENTIFIER SHAPE. Because it is the SAME SHAPE AS A SEMANTIC VERSION, and this
# repository is full of them. Measured over 2045 tracked files: the bare dotted-triple appears
# 8018 times across 649 files -- 1233 in ide/package-lock.json, 934 in uv.lock, 661 in
# docs/BACKLOG.md, every one a version or an item number. A gate firing 8018 times is switched off
# within a day, and a gate that is off is worse than one never built, because the pipeline still
# shows a passing step.
#
# PROXIMITY ALONE IS ALSO NOT ENOUGH, and this is measured rather than assumed. "Identifier within
# 120 characters of a verdict word" scores 1028 hits across 119 files; adding an ASVS context marker
# still leaves 548 across 50, dominated by the backlog's own legitimate citations. Only the TIGHT
# PAIR -- identifier and verdict adjacent on one line, separated by punctuation -- discriminates.
#
# MEASURED RESULT OF THE RULE BELOW, over the same 2045 tracked files: ZERO hits. It is silent on
# uv.lock (934 triples), ide/package-lock.json (1233), constraints.lock (90), docs/BACKLOG.md (661),
# docs/ASVS-ASSESSMENT-METHOD.md (23) and docs/research/asvs-16-2-2-*.md (3) -- the last two being
# tracked, public, and specifically flagged as the shape most likely to produce a false positive.
# A zero over a corpus is only evidence beside a control that fires; both live in
# tests/test_scan_forbidden.py and neither may be deleted without the other.
# NO PLACEHOLDER EXEMPTION, DELIBERATELY, and the alternative is worth recording because it was
# built and then withdrawn. ``_SLUG_PLACEHOLDER_HEX`` above exempts obviously-fake values so the slug
# detector's fixtures stay quiet, and the same device works here -- reserving 0.0.0/9.9.9/99.99.99
# was implemented and measured discriminating correctly on all sixteen probes.
#
# It was dropped because it buys nothing this detector needs and costs a standing bypass: four
# identifier values that can never be reported, forever, in any file. The test fixtures keep the
# identifier and the verdict as SEPARATE string literals and join them at runtime instead, so the
# source carries no pair for this rule to match and no exemption is required. A future document that
# genuinely must illustrate the pair verbatim is an allowlist entry with a written reason, which is
# the sanctioned path and leaves a record; a reserved-value list leaves none.
_RECORD_ID = r"(?<![\w.])\d{1,2}\.\d{1,2}\.\d{1,3}(?![\w.])"
_RECORD_VERDICT = r"(?:pass|fail|partial|needs-review|not[- ]applicable|n/a)"
# Separated ONLY by punctuation that binds a label to a value -- colon, equals, pipe, dash, arrow, a
# table cell edge. A space alone is deliberately not enough: `see 1.2.2 later, this will pass` is
# prose, and admitting it is what took the earlier attempts to 548 hits.
_RECORD_PAIR: tuple[re.Pattern[str], ...] = (
    re.compile(rf"(?i){_RECORD_ID}\s*[:=|\-—>\]]+\s*{_RECORD_VERDICT}\b"),
    re.compile(rf"(?i)\b{_RECORD_VERDICT}\s*[:=|\-—<\[]+\s*{_RECORD_ID}"),
)

# Skip routable-IP detection (only) where dotted numbers are package versions, not hosts.
_IP_SKIP_SUFFIXES = {".lock"}
_IP_SKIP_NAMES = {"requirements.lock", "uv.lock", "package-lock.json"}

# Lock/SVG/password-list files are dense with incidental standalone digit runs -> skip the site-code
# file scan (only) on them to avoid a false-positive storm.
_SITE_SKIP_SUFFIXES = {".lock", ".svg"}
_SITE_SKIP_NAMES = {
    "requirements.lock",
    "uv.lock",
    "package-lock.json",
    "common_passwords.txt",
}

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "build",
    "dist",
}

# The ONLY skipped path: the git-ignored real-token file itself. It is never committed (so it is
# absent from a tracked scan), but a whole-worktree ``--path .`` scan on the owner's machine would
# otherwise walk it and self-trip on every real token it exists to hold. Nothing that reaches the
# public repo is skipped -- no blanket public directory, and NOT ``.gitignore`` (which is scanned).
SKIP_PATHS = ("scripts/security/scan-tokens.local.txt",)


def _is_skipped(posix: str) -> bool:
    # ``posix`` is ALWAYS relative to the scan root (main() derives it that way in --path mode too), so
    # this is an EXACT path match, never a suffix match. A suffix test would skip a same-named file at a
    # different path, which must still be scanned.
    return posix in SKIP_PATHS


# --------------------------------------------------------------------------------------------------
# LOCATION detectors. Everything else in this file judges a file by its BYTES; these judge it by where
# it sits, and a file matching one is a hit whatever it contains.
#
# Why this class needs its own detector, measured 2026-08-05: the private security corpus is prose
# about THIS repo -- threat models, ASVS assessments, remediation plans -- so it carries no customer
# name, no site code, no IP, and no secret. A token scanner is the wrong instrument for it and reports
# clean by working correctly. Against the 89-document vault corpus the content detectors would have
# missed 55 of them.
#
# ``docs/security/`` is gitignored (.gitignore:144) and lives only in the private vault clone, so on
# the ordinary path nothing here ever fires. It is aimed at the path .gitignore cannot cover: a branch
# created from a fetched vault ref delivers those files inside a commit TREE, never through the index,
# so no ignore rule is ever consulted and the working tree ends up carrying them legitimately-tracked.
#
# Deliberately narrow. ``docs/reviews/`` and ``docs/marketing/`` are gitignored too, but they are
# gitignored for tidiness rather than because publishing them would hand an attacker a map, and a
# detector that cries wolf gets deleted. Add an entry here only with the reason it is a LEAK.
FORBIDDEN_PATHS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?:^|/)docs/security/"),
        "private security document -- docs/security/ is vault-only and must never reach the public repo",
    ),
)


def forbidden_path_reason(posix: str) -> str | None:
    """Why this PATH is forbidden, or ``None``.

    Matched unanchored on purpose: a vendored or relocated copy (``ide/docs/security/x.md``) is the
    same leak as the top-level one, and anchoring to ``^`` would wave it through.
    """
    for pattern, reason in FORBIDDEN_PATHS:
        if pattern.search(posix):
            return reason
    return None


# --------------------------------------------------------------------------------------------------
# Token authority (EXTERNALIZED -- never committed). These module globals are (re)computed by
# ``reload_tokens()`` and read by the anonymizer leak-check bridges (messagefoundry/anon/leak.py and
# tee/anon/leak.py) as the single source of truth, so their names/shapes are a stable public contract.
# --------------------------------------------------------------------------------------------------

#: Location of the git-ignored local token file (pre-commit source). Overridable in tests.
LOCAL_TOKEN_FILE = Path(__file__).parent / "scan-tokens.local.txt"

FORBIDDEN: list[tuple[re.Pattern[str], str]] = []
ESTATE_TOKENS: tuple[str, ...] = ()
SITE_CODE_RE: re.Pattern[str] = _NEVER
#: Boundary-aware site-code FILE detector: fires on a code delimited by non-alphanumerics
#: (``PT_<site>_ADT`` -> matches) but NOT on the prefix embedded in a longer alphanumeric run
#: (a SHA, a DOB, a dotted version), so the broad-substring false-positive storm does not happen on
#: source files. ``.`` is a boundary exclusion too (a real site code is never dot-adjacent). The
#: example above uses the house ``<site>`` placeholder rather than a digit run, because a concrete one
#: written here trips ``_ESTATE_ID_SHAPE``; the digit-level contrast is demonstrated instead by
#: ``tests/test_scan_forbidden.py::test_scan_file_site_code_ignores_embedded_digit_runs``.
_SITE_CODE_FILE: re.Pattern[str] = _NEVER
#: The site-code detectors above match a prefix followed by four LITERAL digits. But the SECRET IS THE
#: PREFIX, not any particular code, so a doc or comment that writes the PATTERN itself -- the prefix
#: followed by a regex quantifier expression, or by an x-run -- discloses exactly the same thing while
#: matching neither. Not hypothetical: ADR 0030's de-identification pass certified a file clean by
#: grepping one form and walked past three occurrences of the other, one on the ADJACENT line. A
#: form-blind sweep reads as evidence of absence while being incapable of finding what it looks for.
_SITE_CODE_PATTERN_LITERAL: re.Pattern[str] = _NEVER
#: Estate tokens are substring-matched, so a few are file-scanned and the rest are body-only. Listed in
#: the token source under ``[estate_body_only]``: tokens that are ordinary words or a vendor product
#: name used as an example identifier, which mass-false-positive over tracked source. Everything in
#: ``[estate]`` and NOT here is compiled into ``_ESTATE_FILE_RES`` and applied by ``scan_file``.
_ESTATE_BODY_ONLY: frozenset[str] = frozenset()
#: (token, boundary-aware pattern) for every file-scanned estate token. The boundary requires non-LETTER
#: flanks: it must fire on ``OB_<TOKEN>_ORU`` (underscore is a word char, so the ``\b`` name patterns
#: cannot see it -- the exact hole that let a customer org name sit in a tracked test and be reported
#: clean by every gate) while NOT firing on a token that is merely a run of letters inside an unrelated
#: identifier, e.g. the WebAuthn exception name ``InvalidCBORData``.
_ESTATE_FILE_RES: tuple[tuple[str, re.Pattern[str]], ...] = ()
#: True when a token source was found AND it actually yielded detectors. Both halves matter: see
#: ``reload_tokens``.
TOKENS_PRESENT: bool = False
#: The parsed site prefixes themselves, kept so ``loaded_token_counts`` can report how many loaded.
#: Deriving that number from ``SITE_CODE_RE is not _NEVER`` made it a 0-or-1 presence BIT, so N loaded
#: prefixes and 1 printed identically -- and the counts line is the ONE diagnostic that distinguishes a
#: real scan from a vacuous one, so a floor built on it would have inherited the same blindness.
_SITE_PREFIXES: tuple[str, ...] = ()


def _resolve_token_text() -> str | None:
    """The active token content, or ``None`` if no source is configured.

    ``MEFOR_FORBIDDEN_TOKENS`` wins: an existing file path is read; any other non-empty value is taken
    as inline content; an explicitly-empty value means "no source". Otherwise the git-ignored local
    file is read if present.
    """
    env = os.environ.get("MEFOR_FORBIDDEN_TOKENS")
    if env is not None:
        env = env.strip()
        if not env:
            return None
        try:
            p = Path(env)
            if p.is_file():
                return p.read_text(encoding="utf-8")
        except OSError:
            pass
        return env  # inline newline-separated token content
    try:
        if LOCAL_TOKEN_FILE.is_file():
            return LOCAL_TOKEN_FILE.read_text(encoding="utf-8")
    except OSError:
        pass
    return None


#: Zero-width, bidi-control, BOM and C0/C1 control codepoints. These are the corruption class the
#: COUNT FLOOR cannot see. A zero-width space is not ``str.isspace()`` and survives ``str.strip()``
#: (unlike NBSP, which strips to empty), so one injected INSIDE a token by a paste through a rendering
#: surface leaves an entry that parses, counts toward the floor, and silently never matches: measured
#: identical counts with detection flipped off. Rejecting them at parse time is what makes the floor
#: count detectors that can FIRE rather than entries that merely PARSE.
def _is_invisible(ch: str) -> bool:
    """True for a codepoint that carries no glyph: control, zero-width, BOM or bidi mark.

    ``str.isprintable()`` is False for exactly the categories that matter here -- Cc controls and
    Cf formats, which covers U+200B ZERO WIDTH SPACE, U+FEFF and the bidi overrides -- and True for
    ordinary letters, digits and the plain space. Expressed via isprintable() rather than a
    character-class literal on purpose: a literal needs escape sequences that are themselves easy to
    mangle, in a check whose entire job is catching mangling.
    """
    return not ch.isprintable()


#: An empty negative lookahead matches nothing anywhere -- the module's own ``_NEVER`` sentinel.
_NEVER_MATCH_RE = re.compile(r"\(\?\!\)")


def _reject_entry(kind: str, value: str) -> bool:
    """True (and warns) when an entry carries an invisible codepoint, so it must be dropped.

    This is the corruption class the COUNT FLOOR cannot see. A zero-width space is not
    ``str.isspace()`` and survives ``str.strip()`` (unlike NBSP, which strips to empty), so one
    injected INSIDE a token by a paste through a rendering surface leaves an entry that parses,
    counts toward the floor, and silently never matches -- measured: identical counts, detection
    flipped off. Rejecting these makes the floor count detectors that can FIRE, not entries that
    merely PARSE.

    The warning deliberately does NOT echo the value: this runs in a world-readable Actions log on
    a public repo and the value is a customer/vendor token. Codepoint and offset are enough to fix.
    """
    for offset, ch in enumerate(value):
        if _is_invisible(ch):
            print(
                f"scan_forbidden: ignoring a {kind} containing an invisible/control codepoint "
                f"U+{ord(ch):04X} at offset {offset} - it would count toward the detector floor "
                "but never match. Re-set the token source from the file rather than pasting it.",
                file=sys.stderr,
            )
            return True
    return False


#: UTF-8 BOM. Built with chr() rather than written literally: an escape or a raw
#: codepoint here is exactly the kind of thing that gets mangled in transit, in the one
#: place whose job is to survive mangling.
_BOM = chr(0xFEFF)


def _parse_tokens(
    text: str,
) -> tuple[list[tuple[re.Pattern[str], str]], tuple[str, ...], tuple[str, ...], list[str]]:
    """Parse sectioned token content.

    Returns (name patterns, estate substrings, body-only estate substrings, site prefixes).
    ``[estate_body_only]`` is a SUBSET marker, not a separate token set -- a token listed there should
    also appear in ``[estate]``; it simply stays out of the file scan.
    """
    section: str | None = None
    names: list[tuple[re.Pattern[str], str]] = []
    estate: list[str] = []
    body_only: list[str] = []
    prefixes: list[str] = []
    known = {"names", "estate", "estate_body_only", "site_prefix"}
    for lineno, raw in enumerate(text.splitlines(), 1):
        # Strip a BOM before anything else: a UTF-8 BOM immediately ahead of the first section header
        # defeats the ``startswith("[")`` test below, silently voiding that entire section.
        line = raw.lstrip(_BOM).strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section not in known:
                # Silently discarding an unrecognised section is how a typo'd header dropped up to 13
                # tokens with no diagnostic at all. Name it.
                print(
                    f"scan_forbidden: line {lineno}: unknown section header — its entries will be "
                    f"IGNORED (expected one of: {', '.join(sorted(known))})",
                    file=sys.stderr,
                )
            continue
        if section is None:
            print(
                f"scan_forbidden: line {lineno}: content before the first section header — IGNORED",
                file=sys.stderr,
            )
            continue
        if section == "names":
            parts = [p.strip() for p in line.split(" | ")]
            if len(parts) > 3:
                # The field delimiter is a space-pipe-space, so a regex with a SPACED alternation
                # (``a | b``) splits into extra fields and parts[0] silently truncates to its first
                # branch -- still compiling, so the re.error handler never fires and the count is
                # unchanged. Ambiguous input is refused rather than half-honoured.
                print(
                    f"scan_forbidden: line {lineno}: [names] entry has {len(parts)} fields, expected "
                    "at most 3 (PATTERN | REASON | CASE) — a spaced regex alternation would be "
                    "truncated, so this entry is IGNORED (content withheld)",
                    file=sys.stderr,
                )
                continue
            pattern = parts[0]
            reason = parts[1] if len(parts) > 1 and parts[1] else "customer/vendor token"
            case = parts[2].lower() if len(parts) > 2 and parts[2] else "i"
            if case not in {"i", "s"}:
                # Warn, but KEEP the entry. Dropping it would lose a detector, and under-detection is
                # the dangerous direction; the ``else re.I`` below already falls back to
                # case-INSENSITIVE, which is strictly broader than case-sensitive and so can only
                # over-match, never under-match. Fail toward more detection.
                print(
                    f"scan_forbidden: line {lineno}: [names] CASE field is not 'i' or 's' — defaulting "
                    "to case-INSENSITIVE (content withheld)",
                    file=sys.stderr,
                )
            # Only an explicit "s" is case-sensitive; anything else (including a malformed flag) is
            # case-insensitive. There is deliberately no separate assignment implementing that
            # fallback -- one would be dead code, indistinguishable from this line under mutation.
            flags = 0 if case == "s" else re.I
            if _reject_entry("name pattern", pattern):
                continue
            if _NEVER_MATCH_RE.search(pattern):
                # ``(?!)`` is this module's own "detector off" sentinel. Accepted from a token source
                # it would compile cleanly, count toward the floor, and never fire.
                print(
                    "scan_forbidden: ignoring a name pattern that can never match "
                    "(contains the empty-negative-lookahead sentinel)",
                    file=sys.stderr,
                )
                continue
            try:
                compiled = re.compile(pattern, flags)
                if compiled.search(reason):
                    # A REASON is printed verbatim on every hit, into a world-readable Actions log on
                    # the public repo. A reason that names its own token therefore publishes the token
                    # on the first match -- the same defect as echoing it in a parse warning, just on
                    # the success path. Neutralise the LABEL, keep the DETECTOR: dropping the entry
                    # would trade a disclosure for under-detection, which is the worse failure.
                    print(
                        f"scan_forbidden: line {lineno}: [names] REASON matches its own pattern and "
                        "would echo the token on every hit — using the generic reason instead",
                        file=sys.stderr,
                    )
                    reason = "customer/vendor token"
                names.append((compiled, reason))
            except re.error:
                # NEVER echo the pattern. This warning lands in a world-readable Actions log on the
                # PUBLIC repo and the pattern IS the customer/vendor token, so a malformed line --
                # exactly the case where the source was mishandled -- would leak the thing the gate
                # exists to protect. Position only.
                print(
                    f"scan_forbidden: ignoring an uncompilable [names] regex at entry "
                    f"{len(names) + 1} (content withheld)",
                    file=sys.stderr,
                )
        elif section == "estate":
            if not _reject_entry("estate token", line):
                estate.append(line.lower())
        elif section == "estate_body_only":
            if not _reject_entry("estate_body_only token", line):
                body_only.append(line.lower())
        elif section == "site_prefix":
            # ASCII digits only: str.isdigit() is True for non-ASCII digits (e.g. Arabic-Indic), which
            # would compile into the site-code alternation and never match an ASCII site code.
            if line.isdigit() and line.isascii():
                prefixes.append(line)
            else:
                # Position only -- see the [names] branch above. A site prefix is customer data.
                print(
                    f"scan_forbidden: ignoring a non-ASCII-numeric [site_prefix] entry at position "
                    f"{len(prefixes) + 1} (content withheld)",
                    file=sys.stderr,
                )
    # DEDUPE before the caller counts. The floor is a count, so a double-pasted section would
    # otherwise inflate it: 13 estate tokens pasted twice reads as 26 and masks the loss of 13 real
    # ones. Duplicates also add no detection. Order is preserved so behaviour is deterministic.
    estate = list(dict.fromkeys(estate))
    body_only = list(dict.fromkeys(body_only))
    prefixes = list(dict.fromkeys(prefixes))
    seen_names: dict[tuple[str, int], None] = {}
    deduped_names: list[tuple[re.Pattern[str], str]] = []
    for compiled, why in names:
        key = (compiled.pattern, compiled.flags)
        if key not in seen_names:
            seen_names[key] = None
            deduped_names.append((compiled, why))
    return deduped_names, tuple(estate), tuple(body_only), prefixes


def reload_tokens() -> None:
    """Recompute the externalized token globals from the current environment / local file.

    Called once at import and again at the top of :func:`main` (so a fresh CLI process always reflects
    its environment). Tests call it after adjusting the source. Never raises: an absent source simply
    yields empty tables (structural-only).
    """
    global FORBIDDEN, ESTATE_TOKENS, SITE_CODE_RE, _SITE_CODE_FILE, TOKENS_PRESENT
    global _SITE_CODE_PATTERN_LITERAL, _ESTATE_BODY_ONLY, _ESTATE_FILE_RES, _SITE_PREFIXES
    text = _resolve_token_text()
    names, estate, body_only, prefixes = _parse_tokens(text or "")
    # A source being PRESENT is not the same as a source being USABLE. Deriving TOKENS_PRESENT from
    # ``text is not None`` alone meant a mangled secret -- headers lost, comments only, a UTF-8 BOM ahead
    # of the first section header -- produced ZERO detectors while still reporting "tokens present", so
    # MEFOR_REQUIRE_TOKENS=1 passed and the gate ran structural-only with a green tick. The cutover
    # runbook has the owner paste a whole sectioned file into a GitHub secret box, which is exactly the
    # mangling case. Require that parsing actually yielded something.
    TOKENS_PRESENT = text is not None and bool(names or estate or prefixes)
    FORBIDDEN = names
    ESTATE_TOKENS = estate
    _ESTATE_BODY_ONLY = frozenset(body_only)
    _ESTATE_FILE_RES = tuple(
        (token, re.compile(rf"(?<![A-Za-z]){re.escape(token)}(?![A-Za-z])", re.IGNORECASE))
        for token in estate
        if token not in _ESTATE_BODY_ONLY
    )
    _SITE_PREFIXES = tuple(prefixes)
    if prefixes:
        alt = "|".join(re.escape(p) for p in prefixes)
        SITE_CODE_RE = re.compile(rf"(?:{alt})\d{{4}}")
        _SITE_CODE_FILE = re.compile(rf"(?<![A-Za-z0-9.])(?:{alt})\d{{4}}(?![A-Za-z0-9.])")
        _SITE_CODE_PATTERN_LITERAL = re.compile(
            rf"(?<![A-Za-z0-9])(?:{alt})(?:\\+d\s*\{{\s*4\s*\}}|[xX]{{4}})(?![A-Za-z0-9])"
        )
    else:
        SITE_CODE_RE = _NEVER
        _SITE_CODE_FILE = _NEVER
        _SITE_CODE_PATTERN_LITERAL = _NEVER


#: The committed synthetic template, used only to RECOGNISE itself (never as a token source).
EXAMPLE_TOKEN_FILE = Path(__file__).parent / "scan-tokens.local.txt.example"


def is_synthetic_token_set() -> bool:
    """Is the loaded token set just the shipped synthetic example?

    Copying ``scan-tokens.local.txt.example`` is the documented way an OUTSIDE CONTRIBUTOR satisfies
    the pre-commit hook: the real list is private and will never be distributable. That is a fine
    contributor posture -- but it yields a gate that exits 0 while being BLIND to every real customer
    token, which is indistinguishable from a genuinely clean run unless it is announced. A maintainer
    who reaches for the example instead of installing the real list would get exactly the false-clean
    this module exists to prevent, and the count floor cannot catch it: the synthetic set POPULATES
    every section, so it satisfies "detectors that can fire" while firing on nothing real.

    Compared against the PARSED content, not the file bytes, so reformatting or re-commenting the copy
    still reads as synthetic.
    """
    if not TOKENS_PRESENT:
        return False
    try:
        example = EXAMPLE_TOKEN_FILE.read_text(encoding="utf-8")
        ex_names, ex_estate, _body, ex_prefixes = _parse_tokens(example)
    except (OSError, ValueError):
        return False
    return (
        tuple(p.pattern for p, _ in ex_names) == tuple(p.pattern for p, _ in FORBIDDEN)
        and tuple(ex_estate) == ESTATE_TOKENS
        and tuple(ex_prefixes) == _SITE_PREFIXES
    )


def loaded_token_counts() -> dict[str, int]:
    """Detector counts for the current token tables.

    ``main`` prints these on every run. "The gate exited 0" is NOT evidence it scanned anything -- these
    counts are what distinguishes a real scan from a vacuous one, and they are what
    ``MEFOR_MIN_DETECTORS`` / ``--require-tokens N`` assert against.

    ``estate`` and ``estate_file_scanned`` legitimately differ: tokens listed under
    ``[estate_body_only]`` are ordinary words or vendor product names that mass-false-positive over
    tracked source, so they are applied to message BODIES but held out of the file scan. A gap between
    the two is expected, not a defect -- only the FLOOR counts (``names`` / ``estate`` /
    ``site_prefixes``) feed the gate.
    """
    return {
        "names": len(FORBIDDEN),
        "estate": len(ESTATE_TOKENS),
        "estate_file_scanned": len(_ESTATE_FILE_RES),
        "site_prefixes": len(_SITE_PREFIXES),
    }


#: The sections a fully-loaded token source must ALL populate. ``TOKENS_PRESENT`` is deliberately an OR
#: (any section proves a source exists at all); the gate below is the AND.
_FLOOR_SECTIONS: tuple[str, ...] = ("names", "estate", "site_prefixes")


def parse_min_spec(value: str) -> int | dict[str, int]:
    """Parse a floor spec: either a bare total (``21``) or per-section (``names=7,estate=13``).

    Per-section is STRICTLY STRONGER and is what CI should use. A bare total is a SUM, so growth in a
    cheap section masks collapse in an expensive one -- names 7->1 alongside estate 13->19 still
    totals 21 and passes, with 6 of 7 customer-name detectors silently off.
    """
    value = value.strip()
    if value.isdigit() and value.isascii():
        return int(value)
    spec: dict[str, int] = {}
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"floor spec {part!r} is neither an integer nor section=N")
        name, _, num = part.partition("=")
        name, num = name.strip(), num.strip()
        if name not in _FLOOR_SECTIONS:
            raise ValueError(
                f"unknown floor section {name!r} (expected one of {', '.join(_FLOOR_SECTIONS)})"
            )
        if not (num.isdigit() and num.isascii()):
            raise ValueError(f"floor for {name!r} must be an integer, got {num!r}")
        spec[name] = int(num)
    if not spec:
        raise ValueError("empty floor spec")
    return spec


def token_floor_failure(min_detectors: int | dict[str, int] | None = None) -> str | None:
    """Why the loaded tables are not trustworthy, or ``None`` if they are.

    Presence is not sufficiency. ``TOKENS_PRESENT`` is satisfied by ANY ONE section surviving, so a
    partially-mangled source -- a clipboard paste that lost a section, a typo'd header, a BOM ahead of
    the first header -- loaded as few as 1 of 21 detectors and still passed a "fail-closed" gate with a
    green tick. Losing only the FINAL line, the likeliest paste error, silently disabled every
    site-code detector while printing "fail-closed". This closes that in two independent ways:

    * every floor section must be non-empty (catches whole-section loss), and
    * the total must meet ``min_detectors`` when given (catches loss WITHIN a section, e.g. 7 names
      down to 3, which the section check alone cannot see).

    The expected total is deliberately supplied from OUTSIDE the token source (CI env / CLI arg). An
    ``[expect]`` count carried inside the file would be destroyed by the very mangling it is meant to
    detect -- self-referential, and vacuous in exactly the way this function exists to prevent.
    """
    if not TOKENS_PRESENT:
        return (
            "no token source is configured (set MEFOR_FORBIDDEN_TOKENS or place "
            "scripts/security/scan-tokens.local.txt) — refusing to run structural-only"
        )
    counts = loaded_token_counts()
    empty = [s for s in _FLOOR_SECTIONS if not counts[s]]
    if empty:
        return (
            f"the token source loaded but section(s) {', '.join(empty)} are EMPTY — a partial or "
            f"mangled source (loaded {', '.join(f'{s}={counts[s]}' for s in _FLOOR_SECTIONS)}). "
            "Re-set the source from the file rather than pasting it"
        )
    if isinstance(min_detectors, dict):
        short = [f"{s} {counts[s]}<{need}" for s, need in min_detectors.items() if counts[s] < need]
        if short:
            return (
                f"section detector counts below their floor ({', '.join(short)}) — the token source "
                "is incomplete. Per-section floors catch the case a total cannot: growth in one "
                "section masking collapse in another"
            )
    elif min_detectors is not None:
        total = sum(counts[s] for s in _FLOOR_SECTIONS)
        if total < min_detectors:
            return (
                f"only {total} detectors loaded, below the required floor of {min_detectors} "
                f"({', '.join(f'{s}={counts[s]}' for s in _FLOOR_SECTIONS)}) — the token source is "
                "incomplete. This is a FLOOR: adding tokens is free, losing them is not"
            )
    return None


#: Benign strings an allowlist entry must NOT match. An entry that matches any of these is broad
#: enough to veto ordinary source lines, and therefore broad enough to switch the gate off wholesale.
#: The empty string is included so a pattern that can match nothing-in-particular is caught too.
#: The last entry is the canary for ``_ESTATE_ID_SHAPE``. ``0123456789`` rejects a bare ``\d{6}``, but
#: it carries no underscore, so it ACCEPTED ``_\d{6}`` / ``\d{6}_`` -- an entry that narrow-looking
#: would veto every line joining a digit run to an identifier segment, switching the whole gate off on
#: those lines while the loaded-counts diagnostic still read healthy. This canary is a dated release
#: tag: an eight-digit run, so no six-digit window has a boundary on both sides and it can therefore
#: never be a site code under ANY prefix list -- it tests allowlist BREADTH without becoming a hit.
_ALLOWLIST_CANARIES: tuple[str, ...] = (
    "",
    "the quick brown fox jumps over the lazy dog",
    "def handler(message: Message) -> list[Send]:",
    "# a perfectly ordinary comment",
    "0123456789",
    "v_20260814_rc",
)


#: Identifier separators neutralised before the second name-pattern pass. Only ``_`` today: it is
#: the one separator that is also a WORD character, so it is the only one that defeats `\b`. Kept as
#: a pattern (not str.replace) so a future separator is a one-character edit.
_IDENT_SEP = re.compile(r"_")


def _takes_ident_pass(pat: re.Pattern[str]) -> bool:
    r"""Whether a name pattern is eligible for the identifier (underscore-neutralised) pass.

    Only SINGLE-TOKEN patterns are. The gap being closed is a lone token buried in an identifier --
    ``OB_TOKEN_ORU`` -- which a \b-anchored pattern cannot see because ``_`` is a word character.

    A MULTI-WORD pattern must be excluded, and this is not hypothetical: neutralising ``_`` for a
    two-word phrase makes it match ordinary snake_case. Measured on the real tree, a phrase pattern
    matched 9 occurrences of a perfectly generic Python identifier across two files -- every one a
    false positive, and enough to block the cutover PR on its own required gate. Whitespace in the
    pattern (literal or ``\s``) is the signal.
    """
    src = pat.pattern
    return " " not in src and r"\s" not in src


def _load_allowlist() -> list[re.Pattern[str]]:
    """Optional line-regex allowlist for vetted false positives (one regex per line, '#' comments).

    NEVER allowlist real customer data -- only genuinely-innocent lines a structural pattern
    over-matches.
    """
    f = Path(__file__).parent / "scan-allowlist.txt"
    if not f.exists():
        return []
    out: list[re.Pattern[str]] = []
    for lineno, raw in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            pat = re.compile(line)
        except re.error:
            print(
                f"scan_forbidden: scan-allowlist.txt line {lineno}: uncompilable regex — IGNORED",
                file=sys.stderr,
            )
            continue
        # An allowlist entry is a per-line VETO applied BEFORE any detector runs, so one over-broad
        # entry disables the ENTIRE gate -- every detector, every file -- while the "loaded ..."
        # diagnostic still reports full counts, making the log indistinguishable from a healthy run.
        # This file is committed and public, so the entry that does it need not be malicious: a
        # hastily-written `.` or `.*` for one false positive is enough. Reject anything that matches
        # ordinary prose or the empty string.
        if any(pat.search(probe) is not None for probe in _ALLOWLIST_CANARIES):
            print(
                f"scan_forbidden: scan-allowlist.txt line {lineno}: pattern matches ordinary text — "
                "it would veto every line and disable the whole gate. IGNORED. Anchor it or make it "
                "specific to the false positive you are excusing.",
                file=sys.stderr,
            )
            continue
        out.append(pat)
    return out


ALLOWLIST = _load_allowlist()
reload_tokens()


# --------------------------------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------------------------------


def _git_tracked() -> list[str]:
    # Fixed literal argv ["git", "ls-files"]: no shell, no user input.
    return subprocess.run(  # nosec B603 B607
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout.splitlines()


def _candidate_files(argv: list[str]) -> list[tuple[Path, str]]:
    # Returns (openable path, scan-root-RELATIVE posix). The relative posix is what all skip decisions
    # and hit reports key on, so the logic is identical whether we scan tracked files (already
    # repo-relative) or a --path snapshot in an arbitrary directory.
    if argv and argv[0] == "--path":
        if len(argv) < 2:
            print("scan_forbidden: --path requires at least one file or directory", file=sys.stderr)
            sys.exit(2)
        # EVERY path after --path is scanned, and a FILE is scanned as itself. Both used to be silent
        # no-ops: only argv[1] was read, so trailing paths were dropped without a word, and rglob() on a
        # non-directory yields nothing, so naming a file scanned exactly zero of it. The ZERO-files
        # refusal below only fires when the TOTAL is zero, so mixing one real directory with dropped
        # paths exited 0 and read as "all of these are clean". Measured 2026-08-04: a four-path audit
        # reported clean having examined one of the four.
        out: list[tuple[Path, str]] = []
        for raw in argv[1:]:
            root = Path(raw)
            if root.is_file():
                # rel is the bare name, matching the directory case's intent: components of the path the
                # caller NAMED must not themselves trigger a SKIP_DIRS short-circuit.
                out.append((root, root.name))
                continue
            out.extend((p, p.relative_to(root).as_posix()) for p in root.rglob("*") if p.is_file())
        return out
    if argv:
        return [(Path(a), Path(a).as_posix()) for a in argv]
    return [(Path(p), Path(p).as_posix()) for p in _git_tracked()]


def _read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:  # binary file -- nothing to scan
        return None
    return data.decode("utf-8", errors="replace")


def scan_file(path: Path, rel_posix: str | None = None, *, show_context: bool = False) -> list[str]:
    """Forbidden-content hits in a file, as ``path:line: reason`` strings.

    Reasons-only by default (location + category, never the matched value or line) so a hit report is
    safe to print in public CI logs. ``show_context`` additionally appends the matched value and the
    trimmed line -- for local triage only, never CI.
    """
    posix = rel_posix if rel_posix is not None else path.as_posix()
    if _is_skipped(posix):
        return []
    # LOCATION before content, and deliberately before the binary/unreadable early-return below: a
    # forbidden path is a hit whatever its bytes are, and a PDF or an image under docs/security/ is
    # exactly as much of a leak as the markdown beside it. Reported at line 0 because the finding is
    # the path itself and there is no line to point at -- the reason names the file, not a location
    # inside it. Scanning stops here; content hits on a file that must not exist add nothing.
    if reason := forbidden_path_reason(posix):
        return [f"{path}:0: {reason}"]
    hits: list[str] = []
    # The NAME is half of what #321 found: one of the two leaked identifiers was a feed module's
    # filename, and a module need not repeat its own name in its text. Placed before the binary
    # early-return for the same reason the location rule above is -- a DICOM or PDF sample named with
    # a site code is exactly as much of a leak as the .py beside it, and _read_text drops binaries
    # unread. Line 0 because the finding is the file, not a location inside it. Unlike a location-rule
    # hit this does NOT stop the scan: the content still has to be judged.
    #
    # This one hit necessarily carries the offending string, because the string is the path and every
    # hit names its path. That is not a new disclosure -- by the time CI scans it the file is already
    # in the public tree and in the PR's file list, and at pre-commit time nothing is public yet -- but
    # it is why the remedy is renaming the file, not an ALLOWLIST line: the allowlist is a per-line
    # content veto and cannot reach this, exactly as it cannot reach the location rule.
    if _ESTATE_ID_SHAPE.search(posix):
        hits.append(f"{posix}:0: {_ESTATE_ID_REASON}, in the file NAME")
    text = _read_text(path)
    if text is None:
        return hits
    ip_scan = path.suffix not in _IP_SKIP_SUFFIXES and path.name not in _IP_SKIP_NAMES
    site_scan = path.suffix not in _SITE_SKIP_SUFFIXES and path.name not in _SITE_SKIP_NAMES
    for lineno, line in enumerate(text.splitlines(), 1):
        if any(a.search(line) for a in ALLOWLIST):
            continue
        ctx = f": {line.strip()[:120]}" if show_context else ""
        before = len(hits)
        # ``_`` is a WORD character, so a \b-anchored name pattern cannot see its token inside an
        # identifier: ``\bTOKEN\b`` does not match ``OB_TOKEN_ORU``. That blindness has hidden real
        # leaks in this repo more than once, and the estate set only covers it for tokens that happen
        # to appear in BOTH lists. Scanning a shadow copy with identifier separators neutralised closes
        # it for EVERY name pattern rather than for the instances someone remembered to duplicate.
        # Substitution preserves length, so offsets and ``show_context`` stay meaningful.
        unwrapped = _IDENT_SEP.sub(" ", line)
        for pat, reason in FORBIDDEN:
            if pat.search(line) or (_takes_ident_pass(pat) and pat.search(unwrapped)):
                hits.append(f"{posix}:{lineno}: {reason}{ctx}")
        if site_scan:
            for m in _SITE_CODE_FILE.finditer(line):
                value = f" ({m.group(0)})" if show_context else ""
                hits.append(f"{posix}:{lineno}: site code{value}{ctx}")
            if _SITE_CODE_PATTERN_LITERAL.search(line):
                hits.append(f"{posix}:{lineno}: site-code pattern written out{ctx}")
        if ip_scan:
            for m in _IPV4.finditer(line):
                ip = m.group(0)
                if not _ALLOWED_IP.match(ip):
                    value = f" ({ip})" if show_context else ""
                    hits.append(f"{posix}:{lineno}: routable IP address{value}{ctx}")
        # Internal-environment disclosure. Reason-only, never the value: the slug or account name IS
        # the disclosure, so echoing it into a public CI log would publish what the hit is reporting.
        if any(p.search(line) for p in _WORKTREE_SLUG_DETECTORS):
            hits.append(f"{posix}:{lineno}: worktree/branch slug (internal project name)")
        if _HOME_PATH.search(line):
            hits.append(f"{posix}:{lineno}: absolute user-home path (OS account name)")
        # Reason-only, and NOT ctx-appended even under show_context. The other reason-only detectors
        # withhold the value because it NAMES someone; this one withholds it because the URL IS the
        # access. Echoing it into a public CI log would hand out the capability the hit reports.
        if _ARTIFACT_URL.search(line):
            hits.append(f"{posix}:{lineno}: private artifact URL (the link itself grants access)")
        # Security-record content (BACKLOG #1337). REASON-ONLY, never the value, for the same reason
        # as the slug above: the identifier-verdict pair IS the disclosure, so echoing it into a
        # public CI log would publish exactly what the hit reports.
        if any(p.search(line) for p in _RECORD_PAIR):
            hits.append(
                f"{posix}:{lineno}: security-record content (requirement id beside a verdict)"
            )
        # Reason-only for the same reason as the two above, and NOT ``ctx``-appended even under
        # show_context: the identifier IS the disclosure.
        if _ESTATE_ID_SHAPE.search(line):
            hits.append(
                f"{posix}:{lineno}: {_ESTATE_ID_REASON} (the ported-estate site-code shape)"
            )
        # Estate substrings run LAST and only on a line nothing else flagged: the sets overlap (the
        # customer name is typically in [names] AND [estate]), and double-reporting one line adds noise
        # rather than information. What this adds is the case no other detector can reach -- a token
        # butted against word characters, e.g. ``OB_<TOKEN>_ORU``.
        if len(hits) == before:
            for _token, estate_pat in _ESTATE_FILE_RES:
                if estate_pat.search(line):
                    hits.append(f"{posix}:{lineno}: estate token{ctx}")
                    break
    return hits


def scan_text(text: str, *, include_estate: bool = False) -> list[str]:
    """Forbidden-token **reasons** in an in-memory string -- the importable single source of truth for
    body scanning (the anonymizer leak-check, ADR 0030 §5).

    Always runs the FORBIDDEN name patterns + a routable-IP check. With ``include_estate`` (a message
    body, where a token can sit *inside* a field the word-boundary form would miss) it also applies the
    ESTATE_TOKENS substring set. The ``site_prefix`` code is deliberately NOT checked here: a broad
    substring search false-positives on every value that merely contains such a run (timestamps,
    fabricated dates), so the anonymizer checks it **field-anchored** instead
    (``surrogates.message_has_site_code``). Returns REASONS ONLY -- never the matched text -- so a
    caller may raise/log the result without leaking PHI.
    """
    reasons: list[str] = []
    for pat, reason in FORBIDDEN:
        if pat.search(text):
            reasons.append(reason)
    for m in _IPV4.finditer(text):
        if not _ALLOWED_IP.match(m.group(0)):
            reasons.append("routable IP address")
            break
    if include_estate:
        lowered = text.lower()
        reasons.extend(f"estate token ({token})" for token in ESTATE_TOKENS if token in lowered)
    return reasons


def _parse_require_flag(argv: list[str]) -> tuple[bool, int | dict[str, int] | None, list[str]]:
    """Pull ``--require-tokens[=N]`` out of argv, returning (require, floor, remaining args).

    pre-commit can pass ARGS to a hook but has no per-hook ``env:`` key, so this flag is the only way
    to make the COMMIT-time gate fail closed. Without it a fresh clone or a new worktree -- neither of
    which carries the git-ignored token file -- runs every commit with zero name/estate/site detectors
    and reports "Passed". CI keeps using the environment variables.
    """
    require = False
    minimum: int | dict[str, int] | None = None
    rest: list[str] = []
    for arg in argv:
        if arg == "--require-tokens":
            require = True
        elif arg.startswith("--require-tokens="):
            value = arg.split("=", 1)[1]
            require, minimum = True, parse_min_spec(value)
        elif arg.startswith("--") and arg != "--path":
            # Refuse unknown flags rather than treating them as filenames. Falling through put an
            # unrecognised token at rest[0], which defeated the ``rest[0] == "--path"`` test: the run
            # silently became a file-list scan of a nonexistent file, examined ZERO files, and exited
            # 0. A typo'd flag must fail loudly, not quietly scan nothing.
            raise ValueError(f"unknown option {arg!r}")
        else:
            rest.append(arg)
    return require, minimum, rest


#: Values accepted as "on" for MEFOR_REQUIRE_TOKENS. An exact ``== "1"`` compare meant a well-meant
#: ``true``/``yes`` silently disabled the gate while looking configured.
_TRUTHY = frozenset({"1", "true", "yes", "on"})


#: A section small enough that a RATIO cannot express drift. Growth from 1 to 2 is 50% however
#: healthy it is, so at these sizes a ratio measures the section's SIZE rather than the floor's
#: staleness. Measured 2026-08-26 against the live list: site_prefixes floor 1 / loaded 2 scores 50%
#: and would fail an 80% rule on its first run while nothing is actually wrong.
_SMALL_SECTION_MAX = 4
#: For a small section, the floor may lag the loaded count by at most this many detectors. One is
#: deliberate: it admits today's 1-against-2 and refuses 1-against-3.
_MAX_ABSOLUTE_LAG = 1
#: For every other section, the floor must be at least this share of what actually loaded.
_MIN_FLOOR_RATIO = 0.8


def floor_freshness_failure(
    min_detectors: dict[str, int] | None, counts: dict[str, int] | None = None
) -> str | None:
    """Has the FLOOR fallen behind the token list it is supposed to guard? (BACKLOG #1368, SEC-04)

    ``token_floor_failure`` answers the opposite question -- did the LIST fall below the FLOOR -- and
    catches a token source that is truncated or misconfigured. It cannot see the other direction: a
    list that grows while the floor stays put still passes, and the floor quietly stops meaning
    anything. A floor of 7 against a list of 40 is satisfied by any 7 detectors surviving.

    TWO RULES, BECAUSE ONE SHAPE DOES NOT FIT BOTH SIZES. Above ``_SMALL_SECTION_MAX`` a ratio is the
    honest measure. At or below it a ratio is dominated by the section's size -- see the constant --
    so the rule is an absolute lag instead.

    Returns None when the floor is still fresh, else a sentence naming the section and both numbers.
    NEVER returns or logs token CONTENT: every value here is a count.
    """
    if not min_detectors:
        return None
    counts = loaded_token_counts() if counts is None else counts
    stale: list[str] = []
    for section, floor in sorted(min_detectors.items()):
        loaded = counts.get(section, 0)
        if loaded <= floor:
            continue  # at or below the floor is token_floor_failure's question, not this one
        if loaded <= _SMALL_SECTION_MAX:
            if loaded - floor > _MAX_ABSOLUTE_LAG:
                stale.append(f"{section} floor {floor} lags {loaded} loaded by {loaded - floor}")
        elif floor < _MIN_FLOOR_RATIO * loaded:
            stale.append(
                f"{section} floor {floor} is {floor / loaded:.0%} of {loaded} loaded "
                f"(needs {_MIN_FLOOR_RATIO:.0%})"
            )
    if not stale:
        return None
    return (
        f"detector floor has fallen behind the token list ({'; '.join(stale)}). The floor still "
        "passes, which is the problem: it no longer constrains the list it guards. Raise "
        "MEFOR_MIN_DETECTORS in .github/workflows/security.yml and branch-leak-scan.yml to match "
        "what actually loads, in the same change that grew the list."
    )


# --------------------------------------------------------------------------------------------------
# SELF-TEST: can the detectors that LOADED actually FIRE? (BACKLOG #321, Proposed 2)
# --------------------------------------------------------------------------------------------------
# The floor counts detectors that PARSED. Parsing and matching are different questions, and this
# module already carries the proof: with no prefix loaded both site-code detectors become ``_NEVER``,
# an empty negative lookahead that matches nothing anywhere. A blind scanner and a clean tree produce
# the same exit 0. So the floor establishes that a table arrived, never that the table can see.
#
# This closes that by probing each loaded class WITH A STRING DERIVED FROM ITSELF. Nothing here
# prints, returns or stores a token value: probes are built in memory, matched in memory, and only
# class names and COUNTS leave the function. That is what lets it run in a world-readable Actions log
# on the one run that holds the real secret -- which is the only place the real table ever loads, and
# therefore the only place this question can be answered about the set the gate actually uses.


#: A ``[names]`` entry that is a plain word wrapped in word boundaries. That is the shape the class is
#: overwhelmingly made of, and the only shape a matching string can be recovered from: a regex cannot
#: be inverted in general, so anything richer is reported as UNPROBED rather than guessed at.
_PLAIN_WORD_NAME = re.compile(r"\\b([A-Za-z][A-Za-z0-9]*)\\b")


def plain_word_name_probes(text: str) -> list[str]:
    """Words the plain-word ``[names]`` entries in ``text`` must match, recovered from the SOURCE.

    Public because the self-test below and the loaded-set test suite both need it, and a second
    spelling of "which entries are probeable" would be a second definition that can drift silently --
    the same single-source rule the section-header parse follows.

    Returns the recovered WORDS, which are token content, so a caller must not print them. Recovering
    nothing is not an error here; the caller decides what an unprobeable class means.
    """
    probes: list[str] = []
    in_names = False
    for raw in text.splitlines():
        line = raw.lstrip(_BOM).strip()
        if line.startswith("[") and line.endswith("]"):
            in_names = line[1:-1].strip().lower() == "names"
            continue
        if not in_names or not line or line.startswith("#"):
            continue
        if m := _PLAIN_WORD_NAME.fullmatch(line.split("|")[0].strip()):
            probes.append(m.group(1))
    return probes


def self_test() -> tuple[list[str], list[str]]:
    """Probe every loaded class with a string built from what that class loaded.

    Returns ``(report, failures)``. Both hold counts and class names only -- never a token, never a
    probe -- so both are safe to print in public CI.

    Probing is TOTAL for ``site_prefix`` and for the file-scanned ``estate`` subset: a prefix is ASCII
    digits and an estate pattern is ``re.escape``d around its own literal, so a matching string is
    derivable from every entry that loaded. There a shortfall is a FAILURE. ``names`` is partial by
    nature (see ``plain_word_name_probes``), so an unprobeable entry is counted, not failed --
    a required gate that reds on a legitimate list shape gets switched off, and the value here is in
    running on every real load rather than in being maximally strict on one.

    The one unconditional failure is a run that probed NOTHING. That is the vacuous pass this check
    exists to remove, and it must not be reported as a clean bill.
    """
    report: list[str] = []
    failures: list[str] = []
    probed_anything = False

    # [site_prefix] -- the class that falls back to _NEVER, so the class where a silent load failure
    # and a clean tree are the same green tick. The probe wraps the code in identifier separators
    # because that is the boundary the FILE detector requires.
    fired = 0
    for prefix in _SITE_PREFIXES:
        m = _SITE_CODE_FILE.search(f"PT_{prefix}0000_ADT")
        if m is not None and m.group(0).startswith(prefix):
            fired += 1
    if _SITE_PREFIXES:
        probed_anything = True
        report.append(f"site_prefix fired {fired}/{len(_SITE_PREFIXES)}")
        if fired != len(_SITE_PREFIXES):
            failures.append(
                f"site_prefix: {len(_SITE_PREFIXES) - fired} of {len(_SITE_PREFIXES)} loaded "
                "prefix(es) did not match a site code built from that same prefix -- the detector "
                "is loaded and inert"
            )

    # [estate] -- only the FILE-SCANNED subset. An [estate_body_only] token never enters scan_file, so
    # probing one would assert nothing about the gate that guards tracked files.
    fired = 0
    for token, pattern in _ESTATE_FILE_RES:
        if pattern.search(f"OB_{token}_ORU"):
            fired += 1
    if _ESTATE_FILE_RES:
        probed_anything = True
        report.append(f"estate_file_scanned fired {fired}/{len(_ESTATE_FILE_RES)}")
        if fired != len(_ESTATE_FILE_RES):
            failures.append(
                f"estate: {len(_ESTATE_FILE_RES) - fired} of {len(_ESTATE_FILE_RES)} file-scanned "
                "token(s) did not match their own literal butted against identifier separators"
            )

    # [names] -- partial by construction. The probe line is ordinary prose so nothing but a name
    # pattern could account for a hit.
    words = plain_word_name_probes(_resolve_token_text() or "")
    fired = sum(
        1
        for word in words
        if any(pat.search(f"contact {word} about the interface") for pat, _reason in FORBIDDEN)
    )
    if words:
        probed_anything = True
    report.append(f"names fired {fired}/{len(words)} probeable of {len(FORBIDDEN)} loaded")
    if words and fired != len(words):
        failures.append(
            f"names: {len(words) - fired} of {len(words)} plain-word entries did not match their "
            "own word -- the entry parsed but the detector is inert"
        )
    if FORBIDDEN and not words:
        report.append(
            "names UNPROVEN: no entry is a plain word, so no probe could be derived for this class"
        )

    if not probed_anything:
        failures.append(
            "no class could be probed at all, so this run proved nothing about detection -- which "
            "is the vacuous pass the self-test exists to remove"
        )
    return report, failures


def _detector_count_report(counts: dict[str, int]) -> list[str]:
    """Machine-readable counts AND the load MODE, one ``key=value`` per line.

    THE MODE IS THE POINT AND THE COUNTS ARE NOT SUFFICIENT. The synthetic example set and the real
    list can report the SAME three numbers -- measured 2026-08-26, both 8/14/2 -- so a caller checking
    counts alone cannot tell which table it just measured, and would happily assert a floor against a
    set that matches nothing real. `mode` is the only field that discriminates.
    """
    if not TOKENS_PRESENT:
        mode = "none"
    elif is_synthetic_token_set():
        mode = "synthetic"
    else:
        mode = "real"
    return [f"mode={mode}"] + [f"{k}={v}" for k, v in sorted(counts.items())]


def main(argv: list[str]) -> int:
    reload_tokens()
    # SEC-04 / BACKLOG #1368. Both are read BEFORE the require/floor parsing below, because each is a
    # terminal mode that reports and exits rather than scanning.
    if "--print-detector-counts" in argv:
        for line in _detector_count_report(loaded_token_counts()):
            print(line)
        return 0
    if "--assert-floor-fresh" in argv:
        spec = os.environ.get("MEFOR_MIN_DETECTORS", "").strip()
        if not spec:
            print(
                "scan_forbidden: --assert-floor-fresh needs MEFOR_MIN_DETECTORS set; refusing rather "
                "than passing vacuously.",
                file=sys.stderr,
            )
            return 2
        try:
            parsed = parse_min_spec(spec)
        except ValueError as exc:
            print(f"scan_forbidden: MEFOR_MIN_DETECTORS: {exc}", file=sys.stderr)
            return 2
        if not isinstance(parsed, dict):
            print(
                "scan_forbidden: --assert-floor-fresh needs a PER-SECTION floor "
                "(names=N,estate=N,site_prefixes=N); a single total cannot say which section drifted.",
                file=sys.stderr,
            )
            return 2
        for line in _detector_count_report(loaded_token_counts()):
            print(line)
        why = floor_freshness_failure(parsed)
        if why is not None:
            print(f"scan_forbidden: {why}", file=sys.stderr)
            return 1
        return 0

    # BACKLOG #321. A third terminal mode, and the third distinct question about the same tables: the
    # floor asks whether the list fell BELOW it, --assert-floor-fresh asks whether it outgrew it, and
    # this asks whether what loaded can FIRE. Only the last one can see a table that is fully
    # populated, fully fresh, and inert.
    if "--self-test" in argv:
        if not TOKENS_PRESENT:
            print(
                "scan_forbidden: --self-test needs a loaded token source; refusing rather than "
                "reporting a pass against empty tables (fail closed).",
                file=sys.stderr,
            )
            return 2
        for line in _detector_count_report(loaded_token_counts()):
            print(line)
        report, failures = self_test()
        for line in report:
            print(f"self-test: {line}")
        for why in failures:
            print(f"scan_forbidden: self-test: {why}", file=sys.stderr)
        # 2, not 1: a hit is content that must be removed from the tree, this is an instrument that
        # cannot see. They call for different actions and must not share an exit code.
        return 2 if failures else 0

    show_context = "--show-context" in argv
    rest = [a for a in argv if a != "--show-context"]
    try:
        flag_require, minimum, rest = _parse_require_flag(rest)
    except ValueError as exc:
        print(f"scan_forbidden: {exc}", file=sys.stderr)
        return 2

    # Announce what loaded BEFORE any refusal, so a failure shows the counts that CAUSED it. Exit 0
    # alone cannot distinguish "scanned with the real tables and found nothing" from "loaded nothing
    # and had nothing to find" -- both are silent successes.
    counts = loaded_token_counts()
    # Three distinguishable states, because "exit 0" collapses them: real tables (silent), the shipped
    # synthetic example (populates every section and so passes the floor, but matches nothing real),
    # and no source at all. Only the first is evidence.
    if not TOKENS_PRESENT:
        mode = "  [STRUCTURAL-ONLY: no token source configured]"
    elif is_synthetic_token_set():
        mode = "  [SYNTHETIC EXAMPLE TOKENS — blind to real customer tokens; CI is authoritative]"
    else:
        mode = ""
    print(
        "scan_forbidden: loaded " + ", ".join(f"{k}={v}" for k, v in counts.items()) + mode,
        file=sys.stderr,
    )

    env_require = os.environ.get("MEFOR_REQUIRE_TOKENS", "").strip()
    if env_require and env_require.lower() not in _TRUTHY:
        print(
            f"scan_forbidden: MEFOR_REQUIRE_TOKENS={env_require!r} is not a recognised value "
            f"({'/'.join(sorted(_TRUTHY))}) — refusing rather than silently running unguarded.",
            file=sys.stderr,
        )
        return 2
    require = flag_require or env_require.lower() in _TRUTHY
    if minimum is None:
        env_min = os.environ.get("MEFOR_MIN_DETECTORS", "").strip()
        if env_min:
            try:
                minimum = parse_min_spec(env_min)
            except ValueError as exc:
                print(f"scan_forbidden: MEFOR_MIN_DETECTORS: {exc}", file=sys.stderr)
                return 2
            # Asking for a floor implies requiring tokens; otherwise a floor set without the require
            # flag would be silently inert -- another gate that cannot fail.
            require = True

    if require:
        why = token_floor_failure(minimum)
        if why is not None:
            print(f"scan_forbidden: {why} (fail closed).", file=sys.stderr)
            return 2

    path_mode = bool(rest) and rest[0] == "--path"
    hits: list[str] = []
    scanned = 0
    for abs_path, rel in _candidate_files(rest):
        # SKIP_DIRS is evaluated on the RELATIVE parts, so a scan-root path component that happens to be
        # named build/venv/dist/… can no longer short-circuit the scan of every file.
        if not abs_path.is_file() or set(Path(rel).parts) & SKIP_DIRS or _is_skipped(rel):
            continue
        scanned += 1
        hits.extend(scan_file(abs_path, rel, show_context=show_context))

    # PRINT WHAT WAS SCANNED, not just what was loaded. Exit 0 plus a token-count line cannot tell a
    # caller whether the files they named were examined -- and when --path silently dropped trailing
    # paths, nothing in the output revealed it. A coverage number makes an under-scan visible without
    # having to suspect it.
    if path_mode:
        print(
            f"scan_forbidden: examined {scanned} file(s) across {len(rest) - 1} named path(s).",
            file=sys.stderr,
        )

    # A --path scan that examined ZERO files is not a pass: it means the whole tree was skipped (a
    # SKIP_DIRS component in the path, or an empty/wrong tree). Refuse rather than report a vacuous clean.
    if path_mode and scanned == 0:
        print(
            "scan_forbidden: --path examined ZERO files (all skipped, or empty tree) — refusing "
            "(fail closed). Check the scan path for a SKIP_DIRS component (build/venv/dist/…).",
            file=sys.stderr,
        )
        return 2

    if hits:
        print("FORBIDDEN CONTENT -- commit blocked (fail closed):", file=sys.stderr)
        for h in hits:
            print(f"  {h}", file=sys.stderr)
        print(
            f"\n{len(hits)} hit(s). A real customer/host string must be removed, not allowlisted. "
            "For a genuine false positive, narrow the pattern or add a vetted line to "
            "scripts/security/scan-allowlist.txt.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
