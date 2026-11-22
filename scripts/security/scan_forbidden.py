#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Forbidden-content scanner: keep customer/PHI-adjacent strings out of the public repo.

At least these callers share this one module so their detection can never drift:
  * ``.pre-commit-config.yaml`` runs it over staged files before every commit.
  * ``.github/workflows/security.yml`` runs it over the whole tracked tree in CI.
  * ``.github/workflows/pr-body-leak-scan.yml`` runs its ``--pr-body`` mode over a pull request's
    description, the one public surface the tree scans cannot read.

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
  scan_forbidden.py [FILE ...]      # scan the given files; after a ``--`` every argument is a path,
                                    #   never an option (how pre-commit invokes it)
  scan_forbidden.py --path DIR      # scan the files under DIR, less the build and environment
                                    #   directories ``_walk`` prunes
  scan_forbidden.py --show-context ...  # FIRST argument only; also print the matched line/value (NEVER used in CI -- a hit
                                    #   means the content already sits in a tracked file, so echoing
                                    #   it would copy the leak into public CI logs; default is
                                    #   reasons-only: location + category, never the matched text)
  scan_forbidden.py                 # scan all git-tracked files in the current repo
  scan_forbidden.py --pr-body FILE  # scan one pull request body (``-`` for stdin; --pr-body-event
                                    #   EVENT.json reads it from a webhook payload) for security-record
                                    #   content: a requirement id beside its verdict, its gap, or a
                                    #   code path. Reasons-only; needs no token source. Run by
                                    #   .github/workflows/pr-body-leak-scan.yml (BACKLOG #3364).
  scan_forbidden.py --self-test     # probe each LOADED class with a string derived from itself, so a
                                    #   table that parsed but cannot match is caught. Counts and class
                                    #   names only -- never a token, so it is safe in public CI. Each
                                    #   class also states how many loaded entries no probe could be
                                    #   built for, because a ratio that silently drops those reads as
                                    #   full coverage over a hole.

Exit: 0 clean, 1 forbidden content found (fail closed), 2 for an instrument that cannot see, at least a
usage error, required tokens missing, a self-test failure, a --path run that read no file, and an
unreadable file with no content hit beside it (it is not a content hit; the two need different fixes).
The terminal modes (--print-detector-counts, --assert-floor-fresh, --self-test, --pr-body) count only
as the whole command line.
"""

from __future__ import annotations

import bisect
import codecs
import errno
import json
import os
import re
import re._constants as _sre_constants
import re._parser as _sre_parser
import stat
import subprocess
import sys
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, NamedTuple

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

# --------------------------------------------------------------------------------------------------
# PULL-REQUEST BODY RECORD CONTENT (BACKLOG #3364). The same vaulted assessment as the pair above, in
# the one public surface this scanner did not read: an engine pull request's description. Owner ruling
# 2026-10-09 scoped it to three kinds, each a requirement identifier BOUND to something that rebuilds
# the private grid -- a VERDICT, a GAP, or the CODE that implements it. A bare identifier with none of
# the three beside it is NOT flagged; whether it should be is an open owner decision, not this
# detector's call.
#
# WHY NOT REUSE _RECORD_PAIR ALONE. It binds only by punctuation, which is right for tracked files and
# wrong for prose: a description says the identifier "stays" or "is held at" its verdict, with no colon
# or pipe anywhere. Measured over the 2438 public engine PR bodies that existed on 2026-10-20, the
# punctuation-only pair caught a small minority of the verdict sentences the rule below catches.
#
# WHAT KEEPS PROSE MATCHING FROM STORMING, measured over the same corpus. Three narrowings, each of
# which removed a named class of false positive and none of which removed a true one:
#   * the identifier shape is the requirement range, not any dotted triple: chapter 1-17, a
#     single-digit section, and no zero component, which drops most semantic versions outright;
#   * an identifier that directly follows a runtime, tool or package name ("Python", "OpenSSL", a word
#     carrying a digit, "from"/"to" in a version bump) is a VERSION and is skipped -- versions next to
#     code paths and pass/fail counts were the dominant false positive before this rule;
#   * a verdict must sit next to the identifier (directly, after a state verb such as "stays" or "held
#     at", or across a table cell), while a gap word or a code path need only share the sentence
#     within _PR_WINDOW characters. Past tense ("passed", "failed") is a test count, not a verdict.
# The measured residue is stated in the pull request that added this, not here: it is a number about a
# corpus that keeps growing, and a copy of it in this file would go stale silently.
#
# REASON-ONLY, like every record detector here: the identifier beside its verdict IS the disclosure, so
# a hit names a line and a kind and never echoes the text into a public CI log.
_PR_REQ_ID = re.compile(
    # Letters and digits, not `\w`, bound the shape: `_` is markdown emphasis here, and an underscore
    # beside the identifier must not hide it.
    r"(?<![A-Za-z0-9.])(?P<lead>V|ASVS[ -]?)?(?:1[0-7]|[1-9])\.[1-9]\.[1-9]\d?(?![A-Za-z0-9]|\.\d)"
)
#: A word boundary that markdown `_` emphasis does not defeat, as _PR_REQ_ID reads one.
_PR_NB = r"(?<![A-Za-z0-9])"
_PR_NA = r"(?![A-Za-z0-9])"
#: The same edges, where an underscore joined to a letter or digit on its other side is a snake_case
#: name, not emphasis: "_gap_" is the word "gap", "retry_gap" is not. Before the word, one or two
#: emphasis underscores count only after a non-word character, so a match never starts inside a word
#: run ("x__messagefoundry"), which kept _PR_CODE linear.
_PR_EB = r"(?:(?<!\w)|(?<=(?<!\w)_)|(?<=(?<!\w)__))"
_PR_EA = _PR_NA + r"(?!_[A-Za-z0-9])"
#: _PR_EB where a path segment must not start mid-path: neither the word nor its emphasis underscores
#: may follow a "/", "." or "-", so "site/_tests/notes" names no code root ("site/tests" never did).
_PR_EB_PATH = r"(?:(?<![\w/.-])|(?<=(?<![\w/.-])_)|(?<=(?<![\w/.-])__))"
#: Words after which a dotted triple is a version. A missed entry costs a false positive the author can
#: rephrase around; a lead never hides a verdict stated with a record verb (see _PR_STRONG_VERB).
_PR_VERSION_LEAD = re.compile(
    r"(?i)(?:\b(?:c?python|pypy|openssl|libressl|versions?|releases?|v|to|pwsh|powershell|qt"
    r"|node(?:js)?|npm|pip(?:-audit)?|pytest|mypy|ruff|uv|uvicorn|uvloop|fastapi|starlette|pydantic"
    r"|httpx|anyio|lxml|cryptography|signxml|paramiko|zizmor|gh|git|sqlite|postgres(?:ql)?|ubuntu"
    r"|windows|macos|requests|hl7apy|hl7|semgrep|bandit|gitleaks|trivy|actionlint|go|rust|bumps?"
    r"|hypothesis|psutil|pyotp|sigstore|mutmut|websockets|sections?)"
    # A word carrying a digit (`ldap3`), a word cut at a hyphen (`openssl-bin-`), or a hyphenated
    # package name (`js-yaml`). Each starts at a word boundary, and `re-` is excluded so the record's
    # own verbs ("re-scores", "re-read") are not mistaken for a package.
    r"|\b[A-Za-z][\w-]*\d[\w-]*|\b[A-Za-z]\w*-|\b(?!re-)[a-z]+(?:-[a-z]+)+|\u00a7)"
    # A table cell edge is transparent, so `| lxml | <version> |` reads the package name.
    r"[\s*`_|]*$"
    # A pin operator (`==`, `~=`, `@`) or a field separator with no space before it (an HL7 version
    # field, `VER=`): neither is how prose or a markdown table cell introduces a requirement.
    r"|(?:[=@~<>^]|\S\|)[\s*`_]*$"
)
#: "<version> to <version>" is a dependency bump, whichever side the requirement shape lands on, and a
#: triple followed by an HL7 message type is the HL7 version this engine is built around.
_PR_VERSION_TAIL = re.compile(
    r"^[*`_]*\s+(?:(?:to|->|\u2192)\s+[*`_]*v?\d+\.\d+"
    r"|(?:ADT|ORU|ORM|OML|SIU|MDM|DFT|BAR|VXU|RDE|MFN|ACK|QBP|RSP)\b)"
)
#: Even a `V` lead is a version after "HL7": `HL7 V2.5.1` is the message standard, not a requirement.
_PR_HL7_LEAD = re.compile(r"(?i)\bhl7[\s*`_]*$")
#: The markup characters markdown wraps around a value.
_PR_MARKUP = r"[*`_\"']"
_PR_FMT = _PR_MARKUP + "*"
_PR_SEP = r"[\s*`_\"']+"
#: Binds a label to a value: colon, equals, pipe, the dashes and arrows, a bracket or table cell edge.
_PR_BIND = r"[:=|\-\u2013\u2014\u2192"
#: The tree scan's verdict words plus the spellings prose uses for them, so a word added to the record
#: vocabulary reaches both surfaces. "fail closed" and its kin name a control's failure MODE, which is
#: what a security pull request describes; they are not a verdict.
_PR_VERDICT_WORDS = rf"{_RECORD_VERDICT}|na|needs review|not met|unmet|met"
_PR_VERDICT_TAIL = r"(?![A-Za-z0-9/-])(?!\s+(?:closed|open|safe|fast|through|over)\b)"
_PR_VERDICT = rf"(?:{_PR_VERDICT_WORDS}|passes|fails|passing|failing){_PR_VERDICT_TAIL}"
#: The verdict words that name a STATE, without "passing"/"failing"/"passes"/"fails": a test "kept
#: failing" or "keeps passing", and that is CI prose, not a requirement held at a verdict.
_PR_VERDICT_STATE = rf"(?:{_PR_VERDICT_WORDS}){_PR_VERDICT_TAIL}"
#: The record's verbs for keeping a requirement at a verdict ("held at", "capped at", "held partial").
_PR_HOLD_VERB = r"(?:held|holds?|holding|kept|keeps?|capped|pinned)"
#: Verbs that only a record uses of a verdict. A version does not "stay partial", so these bind even an
#: identifier the version filter set aside ("Applies to <id>, which stays partial").
_PR_STRONG_VERB = (
    rf"(?:stays?|remains?|{_PR_HOLD_VERB} at|went to|goes to|moves? to|moved to|back to"
    r"|re-?scored(?: as)?|scored(?: as)?|scores"
    # "<id> went from partial to pass" names the old verdict as surely as the new one.
    r"|(?:went|goes|moves?|moved) from)"
)
_PR_PLAIN_STATE_VERB = rf"(?:{_PR_STRONG_VERB}|is(?: now| still)?|was|are|reads|now|at|from)"
#: The adverbs a record sentence hedges a verdict with, one list for each place one may stand: before
#: the verb (_PR_AUX), after a modal (_PR_MODAL), between "has" and "been", and before the verdict
#: (_PR_QUALIFIER). Lists kept apart drifted, so a word one place took unbound another (BACKLOG #8175
#: item 6): "<id> has likely been met", "<id> is only partial", "<id> never stays partial".
_PR_HEDGE = r"(?:likely|probably|still|now|also|only|then|already|so|never|yet|honestly|since)"
#: "has been" with any negations and hedges between, in any order and any markup ("has since been",
#: "hasn't yet been", "has still not been", "has _never_ been").
_PR_HAS_BEEN = rf"(?:has|have|had)(?:n['\u2019]t)?(?:{_PR_SEP}(?:not|{_PR_HEDGE}))*{_PR_SEP}been"
#: The passive and negated forms ("were", "has been", "isn't", "has not been", "is no longer") bind an
#: unmarked identifier only with a state verdict ending its clause (_pr_verdict_bound).
_PR_STATE_VERB = (
    rf"(?:{_PR_PLAIN_STATE_VERB}|were|(?:{_PR_HAS_BEEN}|been)"
    r"|(?:is|was|are|were)(?:n['\u2019]t| not| no longer))"
)
_PR_PLAIN_QUALIFIER_WORDS = r"a|an|the|its|permanent|genuine|accepted|honest"
_PR_PLAIN_QUALIFIER = rf"(?:(?:{_PR_PLAIN_QUALIFIER_WORDS}){_PR_SEP})*"
_PR_QUALIFIER = (
    rf"(?:(?:{_PR_PLAIN_QUALIFIER_WORDS}|recorded|known|interim|provisional|{_PR_HEDGE}){_PR_SEP})*"
)
#: Words that may stand between the identifier and its verb without unbinding it: a passive auxiliary
#: ("<id> was held at partial"), a negated one ("<id> isn't met") and the hedges ("<id> likely stays").
_PR_AUX = (
    rf"(?:(?:is|was|are|were|be|been|{_PR_HAS_BEEN}"
    rf"|(?:is|was|are|were)n['\u2019]t|not|no longer|{_PR_HEDGE})" + _PR_SEP + r")*"
)
#: A modal or a negation bound to a bare verdict verb: "<id> cannot pass", "<id> would not be met",
#: "<id> needs to pass", "<id> will remain partial". On an identifier the text does not mark as a
#: requirement it binds only where the verdict ends the clause (_PR_VERDICT_END), because
#: "<version> will fail the handshake" is the same words with an object.
_PR_MODAL = (
    r"(?:can(?:not)?|can['\u2019]t|could|would|will|should|may|might|must|does|do|did"
    r"|(?:does|did|wo|would|could|should)n['\u2019]t|needs? to|has to|is (?:un)?able to)"
    rf"(?:{_PR_SEP}(?:not|{_PR_HEDGE}|reach|have|be|been|stay|remain))*"
)
#: Read from the end of the identifier: "<id> stays partial", "<id> cell to pass", "<id> | fail".
_PR_VERDICT_AFTER = re.compile(
    rf"(?i)^{_PR_FMT}(?:\s+(?:cell|row))?"
    # A comma binds only before "which"/"that", emphasised or not: "<id>, which stays partial".
    rf"(?:\s*{_PR_BIND}>\](]+\s*|{_PR_SEP}|,\s*(?={_PR_FMT}(?:which|that){_PR_NA}))"
    rf"(?:{_PR_FMT}(?:(?:which|that){_PR_SEP})?{_PR_AUX}"
    rf"(?:(?P<strong>{_PR_STRONG_VERB})|(?P<modal>{_PR_MODAL})|{_PR_STATE_VERB}|(?P<as>as)"
    rf"|(?P<to>to)){_PR_SEP}(?:at{_PR_SEP})?)?"
    rf"{_PR_QUALIFIER}{_PR_FMT}(?P<verdict>{_PR_VERDICT})"
)
#: The same binding as engine PR 2448 read it, with no hedge, passive or negation: what it binds needs
#: no mark. What only _PR_VERDICT_AFTER binds ("<version> still fail", "were failing") is CI prose as
#: often as a record, so it binds an unmarked identifier only with a state verdict ending its clause.
_PR_PLAIN_VERDICT_AFTER = re.compile(
    rf"(?i)^{_PR_FMT}(?:\s+(?:cell|row))?"
    rf"(?:\s*{_PR_BIND}>\](]+\s*|{_PR_SEP})"
    rf"(?:{_PR_FMT}(?:(?:which|that){_PR_SEP})?{_PR_PLAIN_STATE_VERB}{_PR_SEP}(?:at{_PR_SEP})?)?"
    rf"{_PR_PLAIN_QUALIFIER}{_PR_FMT}{_PR_VERDICT}"
)
_PR_VERDICT_STATE_RE = re.compile(rf"(?i){_PR_VERDICT_STATE}")
#: A modal chained into a record verb ("<id> will remain partial") is as strong as the verb alone.
_PR_MODAL_STRONG = re.compile(r"(?i)(?:stay|remain)$")
#: What may follow a verdict a modal binds: the end of the clause, or a word that starts no object. A
#: preposition is not one: "<version> will fail on the strict validator" is a verb and its phrase.
_PR_VERDICT_END = re.compile(
    rf"(?i){_PR_FMT}(?:\s*(?:$|[.,;:!?)\]|])"
    # Emphasis on the word ("_yet_", "*yet*", "`yet`") does not hide it, as "\b" hid "_yet_".
    rf"|\s+{_PR_FMT}(?:yet|today|now|either|again|until|unless|because){_PR_EA})"
)
#: A verb that states the verdict BEFORE the identifier: "does not meet <id>", "satisfies ASVS <id>",
#: and the record's idiom for a requirement that does not pass yet, "an honest pass for <id>". "pass"
#: and "fail" are not among the verbs: "callers can pass <version> explicitly" is ordinary English.
_PR_VERB_BEFORE = re.compile(
    rf"(?i){_PR_NB}(?:meets?|meeting|satisf(?:y|ies|ied|ying)"
    rf"|honest{_PR_SEP}pass{_PR_SEP}(?:at|for|on))"
    rf"(?:{_PR_SEP}(?:the|cells?|requirements?|its|all|any|of|ASVS|vault))*{_PR_SEP}{_PR_FMT}$"
)
#: "to <verdict>" with no move verb is ordinary English ("requires <version> to pass"), so a bare "to"
#: binds only when the text before the identifier says the identifier is what moves.
_PR_MOVE_OBJECT = rf"{_PR_SEP}(?:(?:the|vault|cells?|ASVS){_PR_SEP})*$"
_PR_MOVE_LEAD = re.compile(
    rf"(?i){_PR_NB}(?:move[sd]?|moving|takes?|took|brings?|brought|re-?grade[sd]?|re-?score[sd]?|of"
    r"|upgrade[sd]?|downgrade[sd]?|sets?|flip(?:s|ped)?|raise[sd]?|lower(?:s|ed)?|drops?|dropped)"
    + _PR_MOVE_OBJECT
)
#: Move verbs that are also ordinary English ("updates <version> to pass Z-segments through"), so they
#: bind only an identifier the text marks as a requirement ("update the <id> row to na").
_PR_MARKED_MOVE_LEAD = re.compile(
    rf"(?i){_PR_NB}(?:update[sd]?|updating|mark(?:s|ed)?)" + _PR_MOVE_OBJECT
)
#: Read up to the start of the identifier: "partial: <id>", "| fail | <id>".
_PR_VERDICT_BEFORE = re.compile(
    rf"(?i){_PR_EB}{_PR_VERDICT}{_PR_FMT}\s*{_PR_BIND}<\[(]+\s*{_PR_FMT}$"
)
#: A table cell that is nothing but a verdict, optionally after a state verb ("Stay partial").
_PR_CELL_VERDICT = re.compile(rf"(?i)(?:{_PR_STATE_VERB}{_PR_SEP})?{_PR_QUALIFIER}{_PR_VERDICT}")
#: A cell that OPENS with a verdict and goes on: "unchanged, partial. No build reaches it."
#: The dashes a cell sets a verdict off with: "unchanged - partial", "partial -- no build".
_PR_CELL_DASH = r"\s+(?:--?|\u2013|\u2014)"
#: The words a verdict cell goes on with ("stays partial until #1"), each the record's own connective.
_PR_CELL_GOES_ON = (
    r"until|pending|because|since|while|unless|once|after|awaiting|but|due|for|per|as|at"
)
#: A bare verdict that opens a cell ("Pass (12 messages)") is also how an HL7 conformance table reads,
#: so with no "unchanged" or state verb before it, it binds only a row whose identifier is marked.
_PR_CELL_VERDICT_LEAD = re.compile(
    rf"(?i)(?:(?P<prefix>unchanged(?:[,;:]|{_PR_CELL_DASH})?|{_PR_STATE_VERB}){_PR_SEP})?"
    rf"{_PR_QUALIFIER}{_PR_VERDICT}{_PR_FMT}(?:[.;,:](?:\s|$)|\s*\(|{_PR_CELL_DASH}(?:\s|$)"
    rf"|(?P<goes_on>\s+(?:{_PR_CELL_GOES_ON})\b)|$)"
)
#: The markup a table cell wraps around a value, and the separators of a cell that lists identifiers.
_PR_CELL_MARKUP = re.compile(_PR_MARKUP)
#: The characters _PR_MARKUP matches plus every space character (a tab and a no-break space included),
#: as str.strip takes them, to trim only a cell's ends.
_PR_CELL_EDGE = "".join(c for c in map(chr, range(0x3001)) if c.isspace()) + "*`_\"'"
#: Unicode's Default_Ignorable_Code_Point ranges: the zero-width space and joiners, direction marks
#: and controls, the byte-order mark, variation selectors, the Hangul fillers and the tag characters.
#: They render as nothing, so where a body holds one, scan_pr_body reads it a second time with every
#: one deleted, inside a word or a cell as well as around one, and keeps the hits of both readings.
#: The deletion reaches the text the verdict, gap and map patterns read, not the line's kind:
#: _pr_units decides a row, heading, list item or empty line from the line as written, so an
#: invisible character before a row's first pipe makes it a paragraph in both passes. A further
#: pass of each reading deletes them before the kinds are read (_pr_scan_reading). A fixed table,
#: so an import pays nothing for it.
_PR_DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
_PR_INVISIBLE = re.compile(
    "[" + "".join(f"{chr(low)}-{chr(high)}" for low, high in _PR_DEFAULT_IGNORABLE) + "]"
)
#: No "\s*" around a separator: on a long run of spaces it backtracks quadratically, so whitespace is a
#: separator of its own and the empty parts are dropped.
_PR_CELL_LIST = re.compile(r"[,;/&+]|(?i:\band\b)|\s+")
#: A requirement lead ("ASVS", "ASVS V", "V") before a cell's identifier, dropped from both sides of
#: the comparison, since an identifier's match carries its lead only when the lead touches the digits.
_PR_CELL_ID_LEAD = re.compile(r"(?i)(?<![A-Za-z0-9])(?:asvs[\s:-]*v?|v)(?=\d)")
#: The record's own nouns carrying the verdict when the identifier is a clause away: "held the cell at
#: partial", "the cell stays partial", "its re-score to pass". Read inside _PR_WINDOW like a gap word,
#: because "cell" or "re-score" beside a verdict is record vocabulary, not ordinary English.
_PR_PROSE_VERDICT = re.compile(
    rf"(?i){_PR_EB}(?:cells?|row){_PR_SEP}(?:is{_PR_SEP}|was{_PR_SEP}|confirmed{_PR_SEP})?"
    rf"(?:{_PR_STATE_VERB}|held|reading){_PR_SEP}{_PR_QUALIFIER}{_PR_FMT}{_PR_VERDICT}"
    rf"|{_PR_EB}held{_PR_SEP}(?:(?:the|both|its|each|that){_PR_SEP})?cells?{_PR_SEP}at{_PR_SEP}{_PR_FMT}{_PR_VERDICT}"
    rf"|{_PR_EB}re-?(?:score|grade|read)\w*{_PR_SEP}(?:{_PR_MODAL}{_PR_SEP})?"
    rf"(?:to|reach(?:es|ed)?){_PR_SEP}{_PR_QUALIFIER}{_PR_FMT}{_PR_VERDICT}"
)
#: The verdict held with a pronoun or no object: "held it at partial", "holds partial". The same words
#: are ordinary engine prose ("the framer holds partial frames", "capped at na fields"), so this binds
#: only a marked identifier or a verdict that ends its clause (_PR_VERDICT_END).
_PR_BARE_HOLD = re.compile(
    rf"(?i){_PR_NB}{_PR_HOLD_VERB}(?:{_PR_SEP}(?:it|them|both|each))?{_PR_SEP}(?:at{_PR_SEP})?"
    rf"{_PR_QUALIFIER}{_PR_FMT}{_PR_VERDICT_STATE}"
)
_PR_GAP = re.compile(
    rf"(?i){_PR_EB}(?:gaps?|residuals?|shortfalls?|unimplemented|unmet"
    rf"|not (?:yet )?(?:implemented|built|covered|met|reachable)){_PR_EA}"
)
#: Gap words the record uses that are also ordinary English ("on the grounds that", "incomplete
#: reads", "the router omits it"), so they bind only an identifier the text marks as a requirement.
_PR_GAP_MARKED = re.compile(
    rf"(?i){_PR_NB}(?:incomplete|lack(?:s|ed|ing)?|omit(?:s|ted)?|omissions?|grounds?"
    rf"|(?:still|falls?|fell|falling){_PR_SEP}short){_PR_NA}"
)
#: A source path, a path under one of this repository's code roots, a dotted engine module, or a link to
#: a file on GitHub. Docs are deliberately not code here: the ruled kind is a map to the code that
#: implements a requirement.
_PR_CODE = re.compile(
    r"(?<![\w/.-])(?:[\w.-]+/)*[\w-]+\.(?:py|pyi|pyx|ts|tsx|js|mjs|cjs|ps1|psm1|sh|ya?ml)"
    rf"{_PR_EA}|{_PR_EB_PATH}"
    r"(?:messagefoundry\w*|harness|ide|tee|packaging|scripts|tests)/[\w./-]+"
    # A dotted engine module, also as a regular expression escapes it (`messagefoundry\.anon`).
    rf"|{_PR_EB}messagefoundry\w*(?:\\?\.\w+)+"
    rf"|{_PR_EB}github\.com/[\w.-]+/[\w.-]+/(?:blob|tree)/\S+"
)
#: A code symbol in backticks rather than a path: a call, a private name, a snake_case name, or a dotted
#: attribute carrying an underscore or a class name. A plain word, a version, a hyphenated label and a
#: file or domain name do not have that shape. A symbol is weaker evidence than a path, because a
#: setting or an HL7 helper beside an HL7 version has it too, so it binds only a marked identifier.
#: A call runs to the closing backtick (`f(g(x))`, `load(p).routers`) and takes no "->" tail, so one
#: run of characters reaches the backtick and nothing overlaps it to backtrack on.
_PR_SYMBOL = re.compile(
    r"`(?:def\s+|class\s+)?(?:_?[A-Za-z]\w*(?:\.\w+)*\([^`\n]*"
    r"|(?:_\w+(?:\.\w+)*"
    r"|[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+"
    r"|(?=[A-Z]|[\w.]*(?:_|\.[A-Z]))[A-Za-z]\w*"
    r"(?:\.(?!(?i:md|rst|txt|toml|json|lock|html?|ini|cfg|hl7|xml|csv|log|org|com|io|net)`)"
    r"[A-Za-z_]\w*)+)"
    r"(?:\s*->[^`\n]*)?)`"
)
#: "ASVS 5", "ASVS v5", "ASVS 5.0", "ASVS v5.0.0": the standard's own version, before an identifier.
_PR_ASVS_VERSION = r"asvs[\s*`_:]+v?\d+(?:\.\d+){0,2}[\s*`_:]*"
#: The same, ending where an identifier starts. "v5" there is the standard's version, not a word
#: carrying a digit, so it does not make the identifier after it a version (_pr_requirement_ids).
_PR_ASVS_VERSION_BEFORE = re.compile(rf"(?i){_PR_NB}{_PR_ASVS_VERSION}$")
#: An identifier the text itself marks as a requirement: "ASVS <id>", "cell <id>", "<id> row". Weaker
#: evidence may bind it. A bare `V` lead does not mark one: "V2.1.3" is also how a version is written,
#: and so is a possessive ("2.5.1's segment grammar"). "ASVS" does, however it is set off from the
#: identifier ("ASVS V<id>", "ASVS `<id>`", "ASVS: <id>", "asvs <id>").
_PR_MARK_BEFORE = re.compile(
    # "ASVS 5 <id>", "ASVS 5.0 <id>", "ASVS v5.0.0 V<id>", and the version-prefixed form "v5.0.0-<id>".
    rf"(?i){_PR_NB}(?:(?:cells?|requirements?|asvs)[\s*`_:]*|{_PR_ASVS_VERSION}"
    r"|v\d\.\d\.\d-)$"
)
#: One separator class only: a markup class before _PR_SEP overlaps it and backtracks quadratically.
_PR_MARK_AFTER = re.compile(
    # A bind character may set the noun off, and after one "the" may lead it ("<id>: the row ...").
    # Not after a plain space: "Since <version> the row is not failing" is CI prose.
    rf"(?i)(?:{_PR_SEP}|(?:\s*[:=\u2013\u2014]\s*|\s+--?\s+)(?:the{_PR_SEP})?)"
    r"(?:cell|row|requirement|anchor|limb|ground|clause|re-?score|re-?read)s?" + _PR_NA
)
#: Only a list separator, as the words between "ASVS <id>" and the next identifier of the same list.
_PR_ID_LIST_GAP = re.compile(r"(?:[\s,;/&+*`_\"']|(?i:and|or)(?![A-Za-z0-9]))+")
#: A table header cell that names its column ASVS, however it spells the rest ("ASVS", "ASVS ID",
#: "ASVS v5.0", "ASVS:", "Requirement (ASVS)", "OWASP ASVS", "ASVS_ID"), so a row under it has every
#: identifier in that column marked as a requirement, though the row never says so itself. Searched
#: with the cell's markup read as a space, so "ASVS_ID" and "**ASVS**" both name it. A cell with a
#: negation anywhere before "ASVS" disclaims it ("Version (not ASVS)", "Non-ASVS ref", "(**not** an
#: ASVS id)", "Not in ASVS") and names no column, as main's whole-cell match named none.
_PR_TABLE_ASVS_HEAD = re.compile(rf"(?i){_PR_NB}asvs{_PR_NA}")
#: "No." is the abbreviation for "number" ("Ref No. (ASVS)"), not a negation.
_PR_TABLE_ASVS_DISCLAIMER = re.compile(
    rf"(?i){_PR_NB}(?:not|non|no(?!\s*\.)|never|without){_PR_NA}"
)
#: The characters of a markdown table's second line, which makes the line above it a header row. A set
#: and not a pattern: a class holding "-" twice backtracks quadratically on a long run of dashes.
_PR_TABLE_DELIMITER_CHARS = frozenset("|:- \t")
#: A cell edge: a pipe markdown has not escaped. "a \| b" is one cell, so it must not shift the column
#: a header names or the column an identifier sits in.
_PR_CELL_PIPE = re.compile(r"(?<!\\)\|")
#: One cell of a GFM delimiter row: dashes, with an optional alignment colon at either end.
_PR_DELIMITER_CELL = re.compile(r":?-+:?")
#: How far a gap word or a code path may sit from the identifier, inside one sentence.
_PR_WINDOW = 80
#: A sentence ends at a full stop before a capital, or at an HTML tag: bot bodies carry release notes as
#: HTML, and a tag is a block edge there however the text runs on.
#: An HTML tag is a tag name and at most 20 attributes, each a name with an optional quoted (500 at
#: most) or unquoted (200 at most, as HTML allows one) value, closed by `>` straight after them or by
#: `/>`. Every quantifier is bounded or anchored on a different class, so the tag cannot run past a
#: newline, a `;` or a full stop the way `[^<>]*` did: `n<limit max=3 ... stays partial -> later` is no
#: tag, so its verdict stays, and nor is prose like `x<y or z > w`. A boolean attribute
#: (`<details open>`) is one.
_PR_TAG_NAME = r"[A-Za-z]\w*(?:-\w+)*"
_PR_TAG_ATTRS = (
    rf"(?:\s+{_PR_TAG_NAME}"
    r"""(?:\s*=\s*(?:"[^"<>\n]{0,500}"|'[^'<>\n]{0,500}'|[^\s"'<>=`]{1,200}))?)"""
    r"{0,20}"
)
_PR_TAG_END = r"(?:\s*/>|>)"
#: The whitespace lead starts only at the head of a run, so a long run is read once; it is optional so
#: a tag the previous split's trailing whitespace already reached still splits.
_PR_SENTENCE_SPLIT = re.compile(
    rf"(?<=[.!?])\s+(?=[A-Z*`\[(\"'#>-])"
    rf"|(?:(?<!\s)\s+)?</?{_PR_TAG_NAME}{_PR_TAG_ATTRS}{_PR_TAG_END}\s*"
)
_PR_LIST_ITEM = re.compile(r"(?:[-*+]|\d+[.)])\s")
_PR_HEADING = re.compile(r"#{1,6}\s")
#: Anchored: unanchored, it deleted the first `>` anywhere in a line, the close of the line's first tag.
_PR_QUOTE = re.compile(r"^(?:>\s?)+")
#: Quote markers as GFM reads them for a blank line: only a space or tab after each ">", so a ">" then
#: a no-break space is a line with content, not a blank one.
_PR_QUOTE_BLANK = re.compile(r"^(?:[ \t]*>[ \t]?)+")
#: A line GFM opens with a quote marker: at most three spaces before the first ">". Four spaces or a
#: tab make an indented code line at the top level, not a quote.
_PR_QUOTE_OPEN = re.compile(r" {0,3}>")
#: The line endings str.splitlines reads, as main numbered the body's lines: GFM's three ("\n", "\r\n",
#: "\r") and the separators only str.splitlines ends a line at (a form feed, U+2028 and their kin).
_PR_LINE_END = re.compile(r"\r\n|[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")
_PR_GFM_LINE_ENDS = frozenset(("\r\n", "\n", "\r"))
#: A markdown link reads as its text: `[<id>](url) stays partial` is the identifier beside its verdict.
#: The body is read a second time with each target kept after its text, so a link whose TARGET is the
#: code path maps the identifier to code too (BACKLOG #5582).
#: No `[` in the text and no bracket in the target, so each scan stops at the next one and a run of
#: `[` or of `[x](` stays linear.
_PR_MD_LINK = re.compile(r"\[([^\[\]\n]*)\]\(([^()\[\]\s]*)\)")
#: An inline HTML tag, which sits inside a sentence rather than ending one: `<b>`, `<code>`, `<a href>`.
#: It is taken out of the line before the sentence split, so only a block tag still ends a sentence.
#: A `<code>` tag reads as a backtick, as markdown writes one; the second reading keeps a tag's
#: attributes, so an `<a href>` target is read as the markdown one is. The attributes are the split's
#: bounded grammar, so the tag stops where a real one would and stays linear on a long run.
_PR_INLINE_TAG = re.compile(
    r"</?(?i:(code|kbd|samp|tt)|a|abbr|b|cite|del|dfn|em|i|ins|mark|q|s|small|span|strong|sub|sup|u|var)"
    rf"({_PR_TAG_ATTRS}){_PR_TAG_END}"
)
#: A dotted number inside a link target, which a target reading must not take as a requirement id: a
#: GitHub ``blob/8.1.8/CHANGES.rst`` link is a version and a path, never a map.
#: Starts only at the first digit of a run, so a long run of digits is read once, not once per digit.
_PR_TARGET_NUMBER = re.compile(r"(?<!\d)\d+(?:\.\d+)+")
#: The floor. The baseline reading is one pass of :func:`scan_pr_body` and reads every line as
#: origin/main did before BACKLOG #5582 changed the reading: the rewrites above found more, and missed
#: some main caught, three review rounds running. It takes the quote marker out with the pattern below,
#: as main did, and reads links and splits sentences with :func:`_pr_base_link_sub` and
#: :func:`_pr_base_split_spans`, which give the output of main's link and split patterns in linear
#: time; those patterns backtrack on a long run, and tests/test_scan_forbidden.py keeps them as its
#: oracles and pins the two functions equal to them. Do not
#: tighten any of the three: a change to one is a change to the floor. The pass runs this module's
#: table model, whose loose reading keeps a table's ASVS columns wherever main kept them but past a
#: blank line under a header that has had a data row (_pr_loose_columns).
_PR_BASE_QUOTE = re.compile(r"(?:>\s?)+")
#: The lookahead class of main's full-stop split.
_PR_BASE_SPLIT_LOOKAHEAD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ*`[(\"'#>-")
PR_BODY_REASONS = {
    "verdict": "requirement verdict (a requirement id beside its verdict)",
    "gap": "requirement gap (a requirement id beside a gap or residual)",
    "map": "requirement-to-code map (a requirement id beside a code path)",
}


#: A unit's (offset, line) marks, its text, and whether it is a table row.
_PrUnits = list[tuple[list[tuple[int, int]], str, bool]]


def _pr_lines(body: str) -> tuple[list[str], list[int], list[int], set[int]]:
    """The body's one line model: its lines as str.splitlines reads them, so a hit reports the line
    number main reported; the numbers of its blank lines as GFM counts them, in two lists; and the
    numbers of the lines that open a GFM line with a quote marker GFM reads as one.

    A blank line is a whole GFM line (between "\\n", "\\r\\n" or "\\r") holding only spaces and tabs.
    A quote blank is a whole GFM line that opens with a quote marker (_PR_QUOTE_OPEN) and holds only
    quote markers besides, a blank line inside a quote; it ends only a quoted table
    (_pr_table_starts). A ">" then a no-break space is a quoted line with content, neither. A
    separator only str.splitlines reads (a form feed, U+2028) ends a line here but never makes a
    blank or quoted one: the line it ends, or the line it opens, lies inside a GFM line, so it ends
    no GFM table, and a ">" after it is content, not a quote marker."""
    lines: list[str] = []
    blanks: list[int] = []
    quote_blanks: list[int] = []
    quoted: set[int] = set()

    def classify(line: str, gfm_end: bool) -> None:
        opens_quote = _PR_QUOTE_OPEN.match(line) is not None
        if opens_quote:
            quoted.add(len(lines))
        if not gfm_end:
            return
        if not line.strip(" \t"):
            blanks.append(len(lines))
        elif opens_quote and not _PR_QUOTE_BLANK.sub("", line).strip(" \t"):
            quote_blanks.append(len(lines))

    start = 0
    # Whether the current line starts a GFM line: the body's start, or a GFM line ending before it.
    whole = True
    for end in _PR_LINE_END.finditer(body):
        lines.append(body[start : end.start()])
        gfm_end = end.group() in _PR_GFM_LINE_ENDS
        if whole:
            classify(lines[-1], gfm_end)
        whole = gfm_end
        start = end.end()
    # A final line ending opens no line, as str.splitlines reads it.
    if start < len(body):
        lines.append(body[start:])
        if whole:
            classify(lines[-1], gfm_end=True)
    return lines, blanks, quote_blanks, quoted


def _pr_inline(line: str, targets: bool) -> str:
    """A line with its links read as their text and its inline tags taken out. With ``targets``, each
    link's target follows its text and each inline tag leaves its attributes, so a target is read too."""

    def tag(m: re.Match[str]) -> str:
        if m.group(1):
            return "`"
        attrs = m.group(2)
        return f" {_PR_TARGET_NUMBER.sub('n', attrs)} " if targets and attrs else ""

    def link(m: re.Match[str]) -> str:
        return f"{m.group(1)} {_PR_TARGET_NUMBER.sub('n', m.group(2))}" if targets else m.group(1)

    return _PR_MD_LINK.sub(link, _PR_INLINE_TAG.sub(tag, line))


#: The three readings of a body (scan_pr_body). The baseline reads it as origin/main did before
#: BACKLOG #5582; the text reading takes inline tags out and reads links as their text; the target
#: reading also keeps each link target and inline tag attribute beside its text.
_PrReading = Literal["base", "text", "targets"]
_PR_BASE: _PrReading = "base"
_PR_TEXT: _PrReading = "text"
_PR_TARGETS: _PrReading = "targets"


def _pr_units(lines: list[str], delete_invisible: bool, reading: _PrReading) -> _PrUnits:
    """Split a PR body's lines into the units a sentence can live in, as markdown renders them.

    A blank line, a list item or a table row starts a new unit, and a heading is a unit of its own; any
    other line continues the paragraph above it, so a hard-wrapped sentence is read whole. A quote is
    read without its `>` markers, so a wrapped quote is one paragraph too. Each unit carries
    (offset, line) marks so a hit can be reported at the line its identifier sits on. ``reading`` is
    one of the three readings: the baseline takes the first `>` run of a line out wherever it sits
    and reads a link as its text (see ``_PR_BASE_QUOTE``); the other two take only a leading quote marker out and read the line through
    :func:`_pr_inline`, where a line that held only inline tags is transparent. The units, their
    lines and their kinds are the same with delete_invisible or without it; only the text differs,
    with its default-ignorable characters deleted.
    """
    units: _PrUnits = []
    marks: list[tuple[int, int]] = []
    parts: list[str] = []

    def flush() -> None:
        if parts:
            units.append((list(marks), " ".join(parts), False))
            marks.clear()
            parts.clear()

    for lineno, raw in enumerate(lines, 1):
        # The line's type (empty, row, heading, list item) is read before invisible characters are
        # deleted, as GFM reads it: an invisible character is content there, so a line holding only
        # one is not empty.
        if reading == _PR_BASE:
            unquoted = _PR_BASE_QUOTE.sub("", raw.strip(), count=1).strip()
            structure = _pr_base_link_sub(unquoted)
        else:
            unquoted = _PR_QUOTE.sub("", raw.strip(), count=1).strip()
            structure = _pr_inline(unquoted, reading == _PR_TARGETS).strip()
            # A line that held only inline tags is transparent, not a paragraph break.
            if unquoted and not structure:
                continue
        line = _PR_INVISIBLE.sub("", structure).strip() if delete_invisible else structure
        if not structure:
            flush()
            continue
        if structure.startswith("|") or _PR_HEADING.match(structure):
            flush()
            units.append(([(0, lineno)], line, structure.startswith("|")))
            continue
        if _PR_LIST_ITEM.match(structure):
            flush()
        offset = marks[-1][0] + len(parts[-1]) + 1 if parts else 0
        marks.append((offset, lineno))
        parts.append(line)
    flush()
    return units


def _pr_next(stops: list[int], at: int, end: int) -> int:
    """The first stop at or after ``at``, or ``end``."""
    i = bisect.bisect_left(stops, at)
    return stops[i] if i < len(stops) else end


def _pr_base_link_sub(line: str) -> str:
    r"""The output of main's link pattern substituted by ``\1`` (``_MAIN_MD_LINK`` in
    tests/test_scan_forbidden.py), in linear time. Each part of the pattern stops at the first character it cannot take, and backtracking
    cannot make a shorter run end on the character the next part needs, so a match is found by lookups:
    the next `]` or newline, then `(`, then the next `)` or whitespace, which must be `)`."""
    if "[" not in line:
        return line
    n = len(line)
    text_ends = [i for i, c in enumerate(line) if c in "]\n"]
    target_ends = [i for i, c in enumerate(line) if c == ")" or c.isspace()]
    out: list[str] = []
    pos = i = 0
    while (i := line.find("[", i)) != -1:
        j = _pr_next(text_ends, i + 1, n)
        if j + 1 < n and line[j] == "]" and line[j + 1] == "(":
            k = _pr_next(target_ends, j + 2, n)
            if k < n and line[k] == ")":
                out += [line[pos:i], line[i + 1 : j]]
                pos = i = k + 1
                continue
        i += 1
    out.append(line[pos:])
    return "".join(out)


def _pr_base_split_spans(unit: str) -> list[tuple[int, int]]:
    """The (start, end) of every match in ``unit`` of main's split pattern (``_MAIN_SENTENCE_SPLIT`` in
    tests/test_scan_forbidden.py), in linear time. Each
    alternative's whitespace run ends where the run does, since a shorter run leaves whitespace where
    the lookahead or the `<` must be; the tag runs to the next `>`."""
    n = len(unit)
    run_end = list(range(n + 1))
    for p in range(n - 1, -1, -1):
        if unit[p].isspace():
            run_end[p] = run_end[p + 1]
    closes = [i for i, c in enumerate(unit) if c == ">"]

    def letter(at: int) -> bool:
        return at < n and unit[at].isascii() and unit[at].isalpha()

    spans: list[tuple[int, int]] = []
    p = 0
    while p < n:
        e = run_end[p]
        if (
            e > p
            and e < n
            and p > 0
            and unit[p - 1] in ".!?"
            and unit[e] in _PR_BASE_SPLIT_LOOKAHEAD
        ):
            spans.append((p, e))
            p = e
            continue
        if e < n and unit[e] == "<":
            name = e + 2 if e + 1 < n and unit[e + 1] == "/" else e + 1
            if letter(name):
                g = _pr_next(closes, name + 1, n)
                if g < n:
                    spans.append((p, run_end[g + 1]))
                    p = run_end[g + 1]
                    continue
        p += 1
    return spans


def _pr_base_sentences(unit: str, is_row: bool) -> list[tuple[int, str]]:
    """:func:`_pr_sentences` with origin/main's split, read by :func:`_pr_base_split_spans`."""
    if is_row:
        return [(0, unit)]
    spans = _pr_base_split_spans(unit)
    sentences, start = [], 0
    for begin, end in spans:
        sentences.append((start, unit[start:begin]))
        start = end
    sentences.append((start, unit[start:]))
    return sentences


def _pr_line_at(marks: list[tuple[int, int]], offset: int) -> int:
    """The line of the last mark at or before the offset. Marks rise in offset and line together, so
    a bisection finds it: a scan over every mark, once per binding identifier, is quadratic in a
    hard-wrapped paragraph."""
    return marks[bisect.bisect_right(marks, offset, key=lambda mark: mark[0]) - 1][1]


def _pr_requirement_ids(text: str) -> list[tuple[re.Match[str], bool]]:
    """Every requirement-shaped triple, each paired with whether its context says it is a version."""
    found = []
    for m in _PR_REQ_ID.finditer(text):
        before = text[max(0, m.start() - 40) : m.start()]
        tail = _PR_VERSION_TAIL.match(text[m.end() : m.end() + 40]) is not None
        if m.group("lead"):
            version = m.group("lead") == "V" and (tail or _PR_HL7_LEAD.search(before) is not None)
        else:
            version = tail or (
                _PR_VERSION_LEAD.search(before) is not None
                and _PR_ASVS_VERSION_BEFORE.search(before) is None
            )
        found.append((m, version))
    return found


#: The gap and map evidence in one window: (gap word, marked-only gap word, code path, code symbol).
_PrEvidence = tuple[bool, bool, bool, bool]


def _pr_evidence(window: str) -> _PrEvidence:
    return (
        _PR_GAP.search(window) is not None,
        _PR_GAP_MARKED.search(window) is not None,
        _PR_CODE.search(window) is not None,
        _PR_SYMBOL.search(window) is not None,
    )


def _pr_marked(text: str, m: re.Match[str]) -> bool:
    """Whether the text names the identifier as a requirement, not just a number of that shape."""
    return bool(
        (m.group("lead") or "").startswith("ASVS")
        or _PR_MARK_BEFORE.search(text, max(0, m.start() - 20), m.start())
        or _PR_MARK_AFTER.match(text, m.end())
    )


def _pr_verdict_bound(text: str, m: re.Match[str], version: bool, marked: bool) -> bool:
    before = text[max(0, m.start() - 60) : m.start()]
    after = text[m.end() : m.end() + 80]
    if not version and (
        _PR_VERDICT_BEFORE.search(before) or (marked and _PR_VERB_BEFORE.search(before))
    ):
        return True
    hit = _PR_VERDICT_AFTER.match(after)
    if hit is None:
        return False
    modal = hit.group("modal")
    if hit.group("strong") is not None or (modal and _PR_MODAL_STRONG.search(modal)):
        return True
    if version:
        return False
    ends = _PR_VERDICT_END.match(after, hit.end()) is not None
    if modal is not None:
        return marked or ends
    if hit.group("as") is not None:
        return marked
    # A bare "to" is only a verdict binding after a move verb; every other state verb stands alone.
    if hit.group("to") is not None:
        return _PR_MOVE_LEAD.search(before) is not None or (
            marked and _PR_MARKED_MOVE_LEAD.search(before) is not None
        )
    return (
        marked
        or _PR_PLAIN_VERDICT_AFTER.match(after) is not None
        or (ends and _PR_VERDICT_STATE_RE.fullmatch(hit.group("verdict")) is not None)
    )


def _pr_prose_verdict(window: str, marked: bool) -> bool:
    """The record's nouns and hold verbs carrying a verdict a clause away from the identifier."""
    if _PR_PROSE_VERDICT.search(window):
        return True
    return any(
        marked or _PR_VERDICT_END.match(window, hold.end())
        for hold in _PR_BARE_HOLD.finditer(window)
    )


def _pr_table_verdict(row: str, ids: set[str], marked: bool) -> bool:
    """A table row with an identifier cell and a cell that is nothing but a verdict, wherever it sits.
    The identifier cell may list several, split by a comma, semicolon, slash, "&", "+", "and" or
    whitespace, each with or without its ASVS or V lead. A cell that opens with a bare verdict and
    goes on binds only a row whose identifier is marked (_PR_CELL_VERDICT_LEAD).

    Every cell, identifier or verdict, is read twice, and either reading may match. Trimmed at its
    ends only (markup and spaces), as engine PR 2448 read it, the markup inside it stays where the cell patterns expect
    it ("stays`partial`" through _PR_SEP, "isn't met" as a contraction). With all its markup deleted,
    a lead or a verdict reads beside its neighbour ("ASVS `<id>`", "unchanged, `partial`.")."""
    if not ids:
        return False
    # Split at every pipe, escaped or not, as engine PR 2893 read cells and as the loose column reading
    # counts them (the GFM column reading counts only unescaped pipes, _PR_CELL_PIPE). Splitting an
    # escaped pipe here only adds cells to read; the backslash it leaves behind is not unescaped, so
    # an id and a verdict joined by "\|" are not read as a pair.
    raw = row.strip().strip("|").split("|")
    cells = [c.strip(_PR_CELL_EDGE) for c in raw] + [
        _PR_CELL_MARKUP.sub("", c).strip() for c in raw
    ]
    keys = {_PR_CELL_ID_LEAD.sub("", i) for i in ids}

    def lists_ids(cell: str) -> bool:
        parts = [p for p in _PR_CELL_LIST.split(_PR_CELL_ID_LEAD.sub("", cell)) if p]
        return bool(parts) and all(p in keys for p in parts)

    def is_verdict(cell: str) -> bool:
        return _PR_CELL_VERDICT.fullmatch(cell) is not None

    def opens_with_verdict(cell: str) -> bool:
        lead = _PR_CELL_VERDICT_LEAD.match(cell)
        if lead is None:
            return False
        # A cell that goes on in words ("is passing for the nightly") is CI prose as often as a record,
        # so it binds only a row whose identifier is marked.
        if lead.group("goes_on") is not None:
            return marked
        return marked or lead.group("prefix") is not None

    return any(lists_ids(c) for c in cells) and any(
        is_verdict(c) or opens_with_verdict(c) for c in cells
    )


def _pr_is_delimiter(row: str) -> bool:
    return "-" in row and set(row) <= _PR_TABLE_DELIMITER_CHARS


def _pr_between(found: list[int], above: int, below: int) -> bool:
    """Whether a line number in ``found``, which is sorted, lies strictly between two lines."""
    return bisect.bisect_right(found, above) < bisect.bisect_left(found, below)


def _pr_table_starts(
    units: _PrUnits, blanks: list[int], quote_blanks: list[int], quoted: set[int]
) -> list[bool]:
    """For each unit, whether it starts a run of rows: it is a row, and the unit above is not a row or
    a blank line (only spaces and tabs, as GFM reads one) lies between them. A line holding only a
    no-break space emits no unit either, but GFM does not count it blank, so it ends no table.

    A quote blank (only quote markers) between two rows ends the run only inside a quoted table:
    every row since the last unit that is not a row, through the row below the quote blank, opens a
    GFM line with a quote marker GFM reads as one (at most three spaces before it, _PR_QUOTE_OPEN;
    the line numbers in ``quoted``). A ">" after a form feed or U+2028 is content, not one. Blank
    lines emit no unit, so that span reaches across them to a header above a blank line. Anywhere
    else, a lone ">" between rows does not end the run, as main read no blank line at all.

    These runs bound only the GFM reading (_pr_table_columns), whose columns can only add marks; the
    loose reading (_pr_loose_columns) does not read them."""

    starts = []
    # Whether every row since the last unit that is not a row opens with a quote marker.
    block_quoted = True
    for index, (marks, _, is_row) in enumerate(units):
        above = units[index - 1] if index else None
        line = marks[0][1]
        block_quoted = not is_row or (block_quoted and line in quoted)
        starts.append(
            is_row
            and (
                above is None
                or not above[2]
                or _pr_between(blanks, above[0][0][1], line)
                or (block_quoted and _pr_between(quote_blanks, above[0][0][1], line))
            )
        )
    return starts


def _pr_is_header(units: _PrUnits, starts: list[bool], index: int, strict: bool) -> bool:
    """Whether a row is a header: a delimiter row comes next, in the same run of rows. A "---" rule
    after a table is a unit of its own, not a row, so it makes no header. Strict, the pair must also
    be one GFM renders as a table: one delimiter cell per header cell, each "-" with an optional ":"
    at its ends."""
    if index + 1 >= len(units) or not units[index + 1][2] or starts[index + 1]:
        return False
    header, delimiter = units[index][1], units[index + 1][1]
    if _pr_is_delimiter(header) or not _pr_is_delimiter(delimiter):
        return False
    if not strict:
        return True
    header_cells, delimiter_cells = _pr_cells(header), _pr_cells(delimiter)
    return len(header_cells) == len(delimiter_cells) and all(
        _PR_DELIMITER_CELL.fullmatch(c.strip()) for c in delimiter_cells
    )


def _pr_table_columns(units: _PrUnits, starts: list[bool]) -> list[set[int]]:
    """For each unit, the ASVS columns its table's header names, as GFM reads the table, or none.

    A run of rows holds at most one table, and it starts at the run's first header GFM would render:
    pipe lines above it render as a paragraph, and a dash-only row below it is data, not a second
    delimiter. A run with no GFM-valid pair still takes its first header-shaped pair (a mistyped
    delimiter still reads as a table to a person). A non-row unit or a blank line ends the run.
    Columns here count unescaped pipes (_PR_CELL_PIPE)."""
    columns: list[set[int]] = [set() for _ in units]
    start = 0
    while start < len(units):
        end = start + 1
        if units[start][2]:
            while end < len(units) and units[end][2] and not starts[end]:
                end += 1
            run = range(start, end)
            header = next((i for i in run if _pr_is_header(units, starts, i, strict=True)), None)
            if header is None:
                header = next(
                    (i for i in run if _pr_is_header(units, starts, i, strict=False)), None
                )
            if header is not None:
                names = _pr_asvs_columns(units[header][1])
                for i in range(header, end):
                    columns[i] = names
        start = end
    return columns


def _pr_loose_columns(units: _PrUnits, blanks: list[int]) -> list[set[int]]:
    """For each unit, the ASVS columns as main read them, united with the GFM reading above: every
    row above a dash-shaped unit is re-read as a header, and its cells are split at every pipe.

    A unit that is not a row ends this reading, as on main. So does a blank line (``blanks``, as
    _pr_lines counts one) between two rows once the header has had a data row: the pipe lines below
    it are another block, which the header above does not name (BACKLOG #3364 step 9). This is the
    one place the reading drops a mark main kept. A blank line above the first data row, or a
    quote-marker-only line anywhere, ends nothing, as on main: a header with no rows yet is read as
    heading the rows below it."""
    columns: list[set[int]] = []
    current: set[int] = set()
    # Whether a data row has been read under the current header.
    has_rows = False
    for index, (marks, text, is_row) in enumerate(units):
        # A data row above implies the unit above is a row, as any other unit clears it.
        if not is_row or (has_rows and _pr_between(blanks, units[index - 1][0][0][1], marks[0][1])):
            current, has_rows = set(), False
        if is_row and not _pr_is_delimiter(text):
            if index + 1 < len(units) and _pr_is_delimiter(units[index + 1][1]):
                current, has_rows = _pr_asvs_columns(text, loose=True), False
            elif current:
                has_rows = True
        columns.append(current)
    return columns


def _pr_in_list(text: str, end: int, m: re.Match[str]) -> bool:
    """Whether only a list separator lies between the end of the identifier before and this one, so a
    second identifier in "ASVS <id> and <id>" is marked by the lead the first carries."""
    return _PR_ID_LIST_GAP.fullmatch(text, end, m.start()) is not None


def _pr_cells(row: str) -> list[str]:
    """A header or delimiter row's cells, split at unescaped pipes. One edge pipe comes off each end,
    not every one: "|| ASVS |" has an empty first cell."""
    row = row.strip().removeprefix("|")
    if row.endswith("|") and not row.endswith("\\|"):
        row = row[:-1]
    return _PR_CELL_PIPE.split(row)


def _pr_asvs_columns(header: str, loose: bool = False) -> set[int]:
    """The columns of a table header row whose cell names the column ASVS, with the cell's markup
    read as a space and again deleted ("**ASVS**", "AS*VS*"). Loose, the cells split at every pipe and
    lose every edge pipe, as engine PR 2893 split them."""
    cells = header.strip().strip("|").split("|") if loose else _pr_cells(header)
    return {i for i, c in enumerate(cells) if _pr_names_asvs(c)}


def _pr_names_asvs(cell: str) -> bool:
    """Whether a header cell names its column ASVS: a reading of its markup (as a space, or deleted)
    finds "ASVS", and no reading that finds it has a negation word before it. Emphasis on the
    negation, or extra space after it, does not hide it."""
    found = [
        (reading, head)
        for reading in (_PR_CELL_MARKUP.sub(" ", cell), _PR_CELL_MARKUP.sub("", cell))
        if (head := _PR_TABLE_ASVS_HEAD.search(reading)) is not None
    ]
    return bool(found) and not any(
        _PR_TABLE_ASVS_DISCLAIMER.search(reading, 0, head.start()) for reading, head in found
    )


def _pr_sentences(unit: str, is_row: bool) -> list[tuple[int, str]]:
    if is_row:
        return [(0, unit)]
    sentences, start = [], 0
    for split in _PR_SENTENCE_SPLIT.finditer(unit):
        sentences.append((start, unit[start : split.start()]))
        start = split.end()
    sentences.append((start, unit[start:]))
    return sentences


def scan_pr_body(body: str) -> list[str]:
    """Record-content hits in a pull request body, as ``pr-body:<line>: <reason>`` strings.

    Reasons only, never the matched text. One hit per kind per LINE: sentences of one paragraph that
    restate a verdict on the same line report it once, rather than storming.

    Read three times, and the hits are the union (BACKLOG #5582). The baseline reads the lines as
    origin/main did before BACKLOG #5582 (see ``_PR_BASE_QUOTE``). The second reads each link as its text and each inline tag as no
    edge, and the third keeps each link's target beside it, so a code path only a target names is
    seen; from the third only a map counts. Each reading builds its own units from one line model
    (:func:`_pr_lines`), so every reading keeps each line where it was and the hits merge by (line,
    kind), sorted by line and then in ``PR_BODY_REASONS`` order.
    """
    found: set[tuple[int, int]] = set()
    lines, blanks, quote_blanks, quoted = _pr_lines(body)
    invisible = _PR_INVISIBLE.search(body) is not None
    gfm = (blanks, quote_blanks, quoted)
    every_kind = frozenset(PR_BODY_REASONS)
    base = _pr_units(lines, False, _PR_BASE)
    _pr_scan_reading(lines, gfm, _PR_BASE, base, invisible, every_kind, found)
    as_text = _pr_units(lines, False, _PR_TEXT)
    # With no `<` the two splits are the same full-stop rule, so equal units would only repeat the
    # baseline's hits.
    if "<" in body or as_text != base:
        _pr_scan_reading(lines, gfm, _PR_TEXT, as_text, invisible, every_kind, found)
    # No link and no tag means no target, so the third reading would only repeat the second.
    if "](" in body or "<" in body:
        with_targets = _pr_units(lines, False, _PR_TARGETS)
        if with_targets != as_text:
            # Only a map: the third reading exists so a target's code path counts, and a target's
            # words are a URL's, not the body's own verdict or gap.
            only_map = frozenset({"map"})
            _pr_scan_reading(lines, gfm, _PR_TARGETS, with_targets, invisible, only_map, found)
    # One hit per kind per line, in line order, however many readings found it.
    kinds = list(PR_BODY_REASONS)
    return [f"pr-body:{line}: {PR_BODY_REASONS[kinds[kind]]}" for line, kind in sorted(found)]


def _pr_scan_units(
    units: _PrUnits,
    gfm: tuple[list[int], list[int], set[int]],
    sentences: Callable[[str, bool], list[tuple[int, str]]],
    kinds: frozenset[str],
    found: set[tuple[int, int]],
) -> tuple[list[bool], list[set[int]], list[set[int]]]:
    """Scan every unit with its own runs of rows and columns; return the runs and both columns."""
    starts = _pr_table_starts(units, *gfm)
    asvs = _pr_table_columns(units, starts)
    loose = _pr_loose_columns(units, gfm[0])
    for unit, unit_asvs, unit_loose in zip(units, asvs, loose, strict=True):
        _pr_scan_unit(unit, unit_asvs, unit_loose, found, sentences, kinds)
    return starts, asvs, loose


def _pr_scan_reading(
    lines: list[str],
    gfm: tuple[list[int], list[int], set[int]],
    reading: _PrReading,
    units: _PrUnits,
    invisible: bool,
    kinds: frozenset[str],
    found: set[tuple[int, int]],
) -> None:
    """Scan one reading of a body's lines, whose units are ``units``, adding each hit of ``kinds``."""
    sentences = _pr_base_sentences if reading == _PR_BASE else _pr_sentences
    # Both passes of a reading share the units' kinds and lines, so they share where each run of rows
    # starts.
    starts, asvs, loose = _pr_scan_units(units, gfm, sentences, kinds, found)
    # Where the body holds an invisible character, it is read again with each one deleted. A unit
    # whose text and columns that leaves unchanged reads the same, so only the others are scanned.
    if invisible:
        deleted = _pr_units(lines, True, reading)
        for unit, unit_asvs, unit_loose, plain, plain_asvs, plain_loose in zip(
            deleted,
            _pr_table_columns(deleted, starts),
            _pr_loose_columns(deleted, gfm[0]),
            units,
            asvs,
            loose,
            strict=True,
        ):
            if unit[1] != plain[1] or unit_asvs != plain_asvs or unit_loose != plain_loose:
                _pr_scan_unit(unit, unit_asvs, unit_loose, found, sentences, kinds)
        # The passes above read each line's kind as written, so an invisible character before a
        # row's first pipe makes it a paragraph there. A further pass deletes every one before the
        # kinds are read, so such a line is read as a row, with its own runs of rows. It only adds
        # hits; where it builds the units the second pass built, it would add none.
        regrouped = _pr_units([_PR_INVISIBLE.sub("", line) for line in lines], False, reading)
        if regrouped != deleted:
            _pr_scan_units(regrouped, gfm, sentences, kinds, found)


def _pr_scan_unit(
    unit: tuple[list[tuple[int, int]], str, bool],
    asvs_columns: set[int],
    loose_columns: set[int],
    hits: set[tuple[int, int]],
    sentences: Callable[[str, bool], list[tuple[int, str]]],
    kinds: frozenset[str],
) -> None:
    """Scan one unit of one reading of scan_pr_body, adding each hit of ``kinds`` to ``hits`` as
    (line, kind)."""
    marks, unit_text, is_row = unit
    for start, sentence in sentences(unit_text, is_row):
        found = _pr_sentence_found(sentence, is_row, asvs_columns, loose_columns)
        for kind_index, kind in enumerate(PR_BODY_REASONS):
            if kind in kinds:
                hits.update((_pr_line_at(marks, start + at), kind_index) for at in found[kind])


def _pr_sentence_found(
    sentence: str, is_row: bool, asvs_columns: set[int], loose_columns: set[int]
) -> dict[str, list[int]]:
    """Every binding in one sentence of a unit, by kind, as offsets into it."""
    # Every identifier that binds a kind is recorded, not only the first: a repair that makes an
    # earlier identifier bind must not move a hit off the line main reported it at.
    found: dict[str, list[int]] = {kind: [] for kind in PR_BODY_REASONS}
    # The tree scan's tight pair, before the version filter can set its identifier aside: what
    # that scan flags in a file, this one flags in a body -- when the pair's identifier has the
    # requirement shape, since the tree scan's own shape admits every dotted triple.
    for p in _RECORD_PAIR:
        pair = p.search(sentence)
        if pair is not None and _PR_REQ_ID.search(sentence, pair.start(), pair.end()):
            found["verdict"].append(pair.start())
            break
    ids = _pr_requirement_ids(sentence)
    # A table pairs an identifier cell with any other cell, so a row is one whole window, and
    # its searches run once rather than once per identifier: a row is unbounded in length.
    evidence: _PrEvidence | None = None
    row_marked = False
    previous: tuple[int, bool] | None = None
    # Where the cell edges sit, found once for the row; an identifier's column is then a lookup.
    # The GFM reading counts unescaped pipes; the loose reading, every pipe. Either may mark.
    pipes = [p.start() for p in _PR_CELL_PIPE.finditer(sentence)] if asvs_columns else []
    all_pipes = [i for i, ch in enumerate(sentence) if ch == "|"] if loose_columns else []
    for m, version in ids:
        window = (
            sentence if is_row else sentence[max(0, m.start() - _PR_WINDOW) : m.end() + _PR_WINDOW]
        )
        marked = not version and (
            _pr_marked(sentence, m)
            or (previous is not None and previous[1] and _pr_in_list(sentence, previous[0], m))
            or (bool(asvs_columns) and bisect.bisect_left(pipes, m.start()) - 1 in asvs_columns)
            or (
                bool(loose_columns)
                and bisect.bisect_left(all_pipes, m.start()) - 1 in loose_columns
            )
        )
        previous = (m.end(), marked)
        row_marked = row_marked or marked
        if _pr_verdict_bound(sentence, m, version, marked) or (
            not version and not is_row and _pr_prose_verdict(window, marked)
        ):
            found["verdict"].append(m.start())
        if version:
            continue
        if evidence is None or not is_row:
            evidence = _pr_evidence(window)
        gap, marked_gap, code, symbol = evidence
        if gap or (marked_gap and marked):
            found["gap"].append(m.start())
        if code or (symbol and marked):
            found["map"].append(m.start())
    requirement_ids = {m.group(0) for m, version in ids if not version}
    # A row's own verdict is read whether or not an identifier bound one, so the row's line keeps
    # it however the identifiers read.
    if is_row and _pr_table_verdict(sentence, requirement_ids, row_marked):
        found["verdict"].append(0)
    return found


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

#: Directories a ``--path`` WALK skips: tool caches, virtual environments and build output that sit
#: untracked in a working tree, where a whole-tree scan would otherwise read third-party code. Applied
#: in ``--path`` mode only, as ``_walk`` describes; there a tracked file is pruned too where git
#: cannot list the tracked files. The tracked and staged scans prune no directory (BACKLOG #5585).
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


#: A vendored JavaScript action's compiled bundle, which .gitignore re-includes under the same glob. It
#: is third-party code bundled from node_modules, so the name detectors false-positive on it; its own
#: source beside it is scanned. This is the narrowed form of what the blanket ``dist`` directory skip
#: did for it before BACKLOG #5585: only a .js file directly in such a dist directory, and no path with a
#: ``.`` or ``..`` component, not every ``dist`` segment in the tree.
_VENDORED_ACTION_BUNDLE = re.compile(r"\.github/actions/(?:[\w-][\w.-]*/)+dist/[\w-][\w.-]*\.js")


def _is_skipped(posix: str) -> bool:
    # ``posix`` is ALWAYS relative to the scan root (main() derives it that way in --path mode too), so
    # this is an EXACT path match, never a suffix match. A suffix test would skip a same-named file at a
    # different path, which must still be scanned. The bundle pattern is a ``fullmatch`` for the
    # same reason.
    return posix in SKIP_PATHS or _VENDORED_ACTION_BUNDLE.fullmatch(posix) is not None


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
# ``reload_tokens()`` and read by the anonymizer leak-check bridges (messagefoundry_toolkit/anon/leak.py and
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

#: The width of a site prefix the anonymizer loads (``messagefoundry_toolkit/anon/surrogates.py``
#: ``_load_site_prefixes``: a two-digit prefix plus four digits). A loaded prefix of another width
#: still arms this scan, but the anonymizer drops it, so its site-code scrub and leak check match
#: nothing for it while this gate counts it live. :func:`token_floor_failure` refuses such a source
#: (BACKLOG #5366). ``tests/test_scan_forbidden_site_prefix_width.py`` holds the two widths together.
_SITE_PREFIX_WIDTH = 2


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
                if len(line) != _SITE_PREFIX_WIDTH:
                    # Kept, so this scan loses no detector, and named: the anonymizer drops it
                    # (BACKLOG #5366). Position only, as below -- a site prefix is customer data.
                    print(
                        f"scan_forbidden: line {lineno}: [site_prefix] entry is not exactly "
                        f"{_SITE_PREFIX_WIDTH} ASCII digits -- this scan matches it but the anonymizer "
                        "cannot load it, so a required-token run refuses this source (content withheld)",
                        file=sys.stderr,
                    )
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

    A source that passes both is still refused when a ``[site_prefix]`` entry is not two digits
    (BACKLOG #5366). That check runs after the two above, so its reason names a source that loaded.

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
    wide = sum(len(p) != _SITE_PREFIX_WIDTH for p in _SITE_PREFIXES)
    if wide:
        # A count only, never the entry: a site prefix is customer data. This scan matches the entry,
        # so the counts read it as live, but the anonymizer loads two-digit prefixes only and its
        # site-code scrub and leak check would match nothing for it (BACKLOG #5366). Checked after
        # the floors, so the anonymizer's refusal_advice, which finds this reason by
        # surrogates.SITE_PREFIX_WIDTH_MARK, can read it as a source that loaded.
        return (
            f"{wide} [site_prefix] entr{'y is' if wide == 1 else 'ies are'} not exactly "
            f"{_SITE_PREFIX_WIDTH} ASCII digits, and the anonymizer loads two-digit prefixes only "
            "(surrogates.py), so its site-code scrub and leak check would not match what this gate "
            "reports as loaded"
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


def _name_matches(pat: re.Pattern[str], text: str, unwrapped: str) -> bool:
    """One name pattern against ``text``, and against ``unwrapped`` (``text`` with ``_IDENT_SEP``
    neutralised) when it takes the identifier pass. The ONE rule both ``scan_file`` and ``scan_text``
    apply, so the two cannot drift again (BACKLOG #5584)."""
    return bool(pat.search(text) or (_takes_ident_pass(pat) and pat.search(unwrapped)))


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
                "it would veto every line and disable the whole gate. IGNORED. Write it as the whole "
                "line it excuses, specific to that false positive.",
                file=sys.stderr,
            )
            continue
        # A whole-line match (``_allowlisted``) holds an entry to the line it was written for only
        # if no part of it can absorb arbitrary text: ``.*OIDC.*``, or ``^# keep .* here$``, excuses
        # a leak written inside the padding exactly as an unanchored entry did (BACKLOG #5445).
        # The parse-tree walk (``_absorbs_any_text``) refuses a wildcard, a negated class, an
        # absorbing category, a back reference or a wide body in a repeat reaching past
        # _MAX_BOUND; a narrow positive class such as ``[0-9.]+`` or a short ``.{1,32}`` still
        # passes it, and review is what stops those. A verbose entry, ``(?x)`` or a scoped
        # ``(?x:...)``, is refused outright.
        if _absorbs_any_text(line) or pat.flags & re.VERBOSE or _VERBOSE_FLAG.search(line):
            print(
                f"scan_forbidden: scan-allowlist.txt line {lineno}: pattern has a wildcard (at "
                "least ., \\S, \\W, \\D, \\w, a negated class, a class holding one of those, a back "
                "reference, or a body covering half the letters and a space or half the digits) in "
                "a repeat reaching past 32 characters, could not be read as a regex tree, or is "
                "verbose ((?x)), so a leak written inside the line it excuses would pass "
                "every detector. IGNORED. Spell that part out.",
                file=sys.stderr,
            )
            continue
        out.append(pat)
    return out


#: The class categories refused inside an unbounded repeat. ``\S`` absorbs any run without a space
#: (a name, an IP, a site code), ``\D`` any run without a digit (a name), ``\w`` any word token.
#: ``\W`` absorbs only spaces and punctuation, not a name; it is here so that ``[\w\W]``, which with
#: ``\w`` matches anything, is caught, and as the conservative choice for a bare ``\W+``. ``\s`` and
#: ``\d`` are not refused alone; a repeat holding them can still be wide (``_Cover``).
_ABSORBING_CATEGORIES = frozenset(
    {
        _sre_constants.CATEGORY_NOT_SPACE,
        _sre_constants.CATEGORY_NOT_DIGIT,
        _sre_constants.CATEGORY_WORD,
        _sre_constants.CATEGORY_NOT_WORD,
    }
)
#: An inline verbose flag, global (``(?x)``) or scoped (``(?ix:...)``); ``(?-x:...)`` turns it off.
_VERBOSE_FLAG = re.compile(r"\(\?[aiLmsux]*x")
_REPEATS = frozenset(
    {_sre_constants.MAX_REPEAT, _sre_constants.MIN_REPEAT, _sre_constants.POSSESSIVE_REPEAT}
)
#: The most characters a repeat may reach before its body is judged: the product of its own upper
#: bound and those of the repeats nested inside it, so ``\S{1,4294967294}`` and
#: ``(?:.{0,32}){0,32}`` are judged as ``\S+`` and ``.*`` are. A short reach, ``.{1,32}``, still
#: passes, and review is what stops it.
_MAX_BOUND = 32
#: Atoms the walk knows hold no sub-pattern. Any other opcode it does not open is refused, so a
#: construct this walk was not written for cannot hide a wildcard inside it.
_LEAVES = frozenset(
    {
        _sre_constants.LITERAL,
        _sre_constants.NOT_LITERAL,
        _sre_constants.ANY,
        _sre_constants.IN,
        _sre_constants.AT,
        _sre_constants.GROUPREF,
    }
)
_ASCII_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class _Cover:
    r"""What one outermost repeat's body can match: the union of every literal and positive class
    anywhere inside it, so ``(?:[A-Za-z]+|[0-9.]+| )+`` is judged as one class, not three narrow
    ones, and whether it holds an atom that absorbs a leak on its own (``.``, a negated class, an
    absorbing category, a back reference). The rule for WIDE: the union covers at least half the
    ASCII letters (13), each in either case, AND covers a space or at least half the ASCII digits
    (5). So ``[ -~]+``, ``[ A-Ya-y]+``, ``[ -Y]+``, ``[A-Za-z0-9]+`` and ``(?:[a-z]+| )+`` are wide,
    while ``[A-Z_]+`` (a letter run, the DMV wait-type column) and ``[ a-f]+`` are not."""

    def __init__(self) -> None:
        self.literals: set[int] = set()
        self.ranges: list[tuple[int, int]] = []
        self.categories: set[Any] = set()
        self.absorbing = False

    def add_class(self, items: Any) -> None:
        """Add a parsed class to the union. A negated class, an absorbing category
        (``_ABSORBING_CATEGORIES``) or a member this does not know marks the body absorbing."""
        for op, arg in items:
            if op == _sre_constants.LITERAL:
                self.literals.add(arg)
            elif op == _sre_constants.RANGE:
                self.ranges.append(arg)
            elif op == _sre_constants.CATEGORY and arg not in _ABSORBING_CATEGORIES:
                self.categories.add(arg)
            else:
                self.absorbing = True

    def covers(self, ch: str) -> bool:
        code = ord(ch)
        return (
            code in self.literals
            or any(low <= code <= high for low, high in self.ranges)
            or (ch == " " and _sre_constants.CATEGORY_SPACE in self.categories)
            or (ch.isdigit() and _sre_constants.CATEGORY_DIGIT in self.categories)
        )

    def wide(self) -> bool:
        letters = sum(self.covers(ch) or self.covers(ch.lower()) for ch in _ASCII_LETTERS)
        digits = sum(self.covers(d) for d in "0123456789")
        return letters >= 13 and (self.covers(" ") or digits >= 5)


def _absorbs_any_text(pattern: str, flags: int = 0) -> bool:
    r"""Whether ``pattern`` holds a repeat (``*``, ``+``, ``{n,m}``, lazy or possessive) that reaches
    more than ``_MAX_BOUND`` characters, counting the repeats nested inside it, and whose body,
    anywhere inside it at any depth of groups, branches and repeats, holds an atom that absorbs a
    leak or is wide (``_Cover``). An allowlist entry holding one is not tied to the one line it was
    written for.

    Read from the PARSED pattern, ``re._parser.parse``, as ``re`` compiles it, never from its
    source text: a comment group parts nothing (``.(?#c)*`` compiles as ``.*``, and ``(?#[).*``
    opens no class), while a literal class such as ``[.*]`` and an escaped ``\.`` are still no
    wildcard. An opcode the walk does not know is refused, and so is a parse tree whose shape it
    does not expect. A short reach such as ``.{1,32}``, and a narrow positive class such as
    ``[0-9.]+`` or ``[a-z]+``, still pass; review is what stops those."""
    try:
        return _seq_absorbs(_sre_parser.parse(pattern, flags))
    except (re.error, IndexError, TypeError, ValueError):
        # The loader compiled it already, so a parse that disagrees, or a ``re._parser`` whose
        # private tuples changed shape, is refused rather than raised out of the module import.
        return True


def _children(op: Any, arg: Any) -> list[Any] | None:
    """The sub-sequences a container opcode holds, or ``None`` for a leaf. An opcode that is
    neither raises ``ValueError``, which ``_absorbs_any_text`` turns into a refusal."""
    if op in _REPEATS:
        return [arg[2]]
    if op == _sre_constants.SUBPATTERN:
        return [arg[3]]
    if op == _sre_constants.ATOMIC_GROUP:
        return [arg]
    if op == _sre_constants.BRANCH:
        return list(arg[1])
    if op in (_sre_constants.ASSERT, _sre_constants.ASSERT_NOT):
        return [arg[1]]
    if op == _sre_constants.GROUPREF_EXISTS:
        return [option for option in arg[1:] if option is not None]
    if op in _LEAVES:
        return None
    raise ValueError(f"unknown regex opcode {op}")


def _seq_absorbs(seq: Any) -> bool:
    """``_absorbs_any_text`` over a sequence outside every repeat: each outermost repeat is judged
    whole, by its reach and the ``_Cover`` of its body."""
    for op, arg in seq:
        children = _children(op, arg)
        if op in _REPEATS:
            cover = _Cover()
            reach = min(arg[1], _MAX_BOUND + 1) * _body_reach(arg[2], cover)
            if reach > _MAX_BOUND and (cover.absorbing or cover.wide()):
                return True
        elif children is not None and any(_seq_absorbs(child) for child in children):
            return True
    return False


def _body_reach(seq: Any, cover: _Cover) -> int:
    """Fill ``cover`` from ``seq``, inside a repeat, and return the largest product of the upper
    bounds of the repeats nested in it, capped past ``_MAX_BOUND``; 1 with none."""
    reach = 1
    for op, arg in seq:
        children = _children(op, arg)
        if children is None:
            if op in (_sre_constants.ANY, _sre_constants.NOT_LITERAL, _sre_constants.GROUPREF):
                cover.absorbing = True
            elif op == _sre_constants.IN:
                cover.add_class(arg)
            elif op == _sre_constants.LITERAL:
                cover.literals.add(arg)
            continue
        inner = max(_body_reach(child, cover) for child in children) if children else 1
        if op in _REPEATS:
            inner *= min(arg[1], _MAX_BOUND + 1)
        reach = min(max(reach, inner), _MAX_BOUND + 1)
    return reach


ALLOWLIST = _load_allowlist()
reload_tokens()


def _allowlisted(line: str) -> bool:
    """Whether an allowlist entry excuses ``line``. An entry must match the WHOLE line: applied with
    ``search``, an entry missing its ``^``/``$`` excused any line that merely CARRIED its shape, so a
    leak beside that shape went past every detector (BACKLOG #5445). ``fullmatch`` removes the
    dependence on anchors. It does not stop an entry whose own pieces can absorb a leak: the
    loader's wildcard refusal (``_absorbs_any_text``) catches the common spellings of that, and
    review of each entry is what catches the rest."""
    return any(a.fullmatch(line) for a in ALLOWLIST)


# --------------------------------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------------------------------


def _ls_files(root: Path, *, keep_location: bool = False) -> list[str]:
    """``git ls-files`` in ``root``, NUL-separated so a name git would C-quote (non-ASCII, a quote, a
    control byte) comes back as itself rather than as a path that does not exist. Raises on failure.

    Fixed argv, no shell, ``root`` a separate argument. Every call passes two ``-c`` settings, which
    outrank any config file. ``safe.bareRepository=explicit`` makes git refuse a bare repository it
    finds by searching rather than one ``GIT_DIR`` names, so a directory of committed files shaped
    like a bare repository is not taken as one and the config a commit wrote there is not read.
    ``core.fsmonitor=false`` stops git running a file-system monitor command that a repository's
    config names: ``ls-files`` runs that command when it reads the index. Any other setting in that
    config is still read.

    ``keep_location`` passes on ``GIT_DIR``, ``GIT_INDEX_FILE`` and the other location variables, so
    the tracked scan lists the index a hook names (a temporary one included), as a bare ``git
    ls-files`` does. The ``--path`` walk drops them, because with them git keys the list from another
    directory and the paths would not be relative to ``root``."""
    env = (
        None
        if keep_location
        else {k: v for k, v in os.environ.items() if k not in _GIT_LOCATION_ENV}
    )
    out = subprocess.run(  # nosec B603 B607
        ["git", *_GIT_SAFETY, "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=True,
        env=env,
    ).stdout
    return [p for p in out.decode("utf-8", errors="surrogateescape").split("\0") if p]


#: The ``-c`` settings every git call this module makes passes; ``_ls_files`` says what each does.
_GIT_SAFETY = ("-c", "safe.bareRepository=explicit", "-c", "core.fsmonitor=false")


_GIT_LOCATION_ENV = frozenset(
    {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_PREFIX", "GIT_NAMESPACE"}
)

#: The errnos that mean a path is not there. POSIX gives ENOTDIR, not ENOENT, for ``a/b.md`` when
#: ``a`` is a regular file, as it is when a tracked directory was replaced by a file.
_GONE = frozenset({errno.ENOENT, errno.ENOTDIR})


def _path_key(rel: str) -> str:
    """A root-relative path as the walk compares it with git's list: NFC and case-folded, because a
    case-insensitive or normalizing filesystem can spell a tracked path differently from the index.
    Folding only ever counts more paths as tracked, so more is read, never less."""
    return unicodedata.normalize("NFC", rel).casefold()


def _git_tracked() -> list[str]:
    return _ls_files(Path("."), keep_location=True)


def _tracked_under(root: Path) -> set[str] | None:
    """The files git tracks under ``root``, relative to it, possibly none, or ``None``.

    ``None`` when no directory from ``root`` up holds a ``.git`` entry, and git is then not run: a
    pushed commit's snapshot written outside any work tree is such a root, and ``None`` prunes
    nothing (BACKLOG #5595). A snapshot inside a work tree is not told apart from the work tree. An
    empty set when git tracks no file under ``root``, and when git is not on PATH or fails, such as
    when it refuses the directory: the walk then prunes SKIP_DIRS by name, as it did before git was
    asked, and in the failure case tracked files are pruned with them."""
    resolved = root.resolve()
    if not root.is_dir() or not any((d / ".git").exists() for d in (resolved, *resolved.parents)):
        return None
    try:
        tracked = {_path_key(p) for p in _ls_files(root)}
    except (OSError, subprocess.CalledProcessError) as exc:
        print(
            f"scan_forbidden: git could not list the tracked files under {root} ({type(exc).__name__}),"
            " so the walk skips the build and environment directories there by name, tracked or not.",
            file=sys.stderr,
        )
        return set()
    return tracked


#: A file to judge: its openable path, its scan-root-relative posix path, and in ``--path`` mode
#: where it is (``_locations``), which the location rule judges too; empty elsewhere. The staged and
#: tracked scans judge only the path they were given, which is relative to the working directory, so
#: run from a subdirectory they do not see a ``docs/security`` above it (a known open gap).
_Candidate = tuple[Path, str, tuple[str, ...]]


def _locations(path: Path) -> tuple[str, ...]:
    """Where ``path`` is, as the location rule judges it in ``--path`` mode (BACKLOG #5446): both its
    path as named, made absolute, and its real path, whole, NFC and case-folded as ``_path_key``
    folds. A file is a hit if EITHER falls under a docs/security directory. The real path, so a
    named root or file that is, or sits behind, a link, junction or subst drive into docs/security,
    a root named from inside ``docs``, or one reached by ``..``, is judged where it lands; ``_walk``
    asks this of a file link it lists, and of a file under a junction it descends. The named path,
    so a link that sits under docs/security and points out of it is judged where it sits as well.

    A directory symbolic link BELOW a named root is not followed: ``os.walk`` lists it and does not
    descend it, so the files behind it are not judged at all, by this rule or any other. That
    route is left open.

    Whole, not relative to a work tree: no ``.git`` entry, planted in a commit snapshot at ``docs``,
    at ``docs/security`` or below it, can strip the prefix the rule keys on. The cost is that a
    tree which itself sits under some ``docs/security`` directory is a hit on every file it holds:
    fail closed."""
    named = _path_key(Path(os.path.abspath(path)).as_posix())
    real = _path_key(Path(os.path.realpath(path)).as_posix())
    return (named,) if named == real else (named, real)


#: How a --path hit for a named root that does not exist ends. ``main`` leaves such a hit out of the
#: summary's unread count, since nothing was there to be set aside.
_NO_ROOT = "does not exist, so its files were not scanned (fail closed)"


def _walk(raw: str, out: list[_Candidate], errors: list[str]) -> None:
    """Every file under the directory ``raw``, keyed by its root-relative posix path (BACKLOG #5585).
    SKIP_DIRS is pruned as ``_tracked_under`` answers: where git lists the tracked files, only for
    files it does not list, so by name under a root git tracks nothing under; where git cannot list
    them, by name, tracked files included; outside a work tree, not at all. ``.git`` is always
    pruned. A directory the walk cannot list is reported in ``errors``, where ``rglob`` used to drop
    it without a word, except one below the root whose listing raises ENOENT or ENOTDIR, which is
    passed over as removed since it was listed, whatever the cause of that errno."""
    root = Path(raw)
    at_root = _locations(root)
    tracked = _tracked_under(root)
    tracked_dirs = {
        "/".join(p.split("/")[:i]) for p in tracked or () for i in range(1, p.count("/") + 1)
    }

    def refused(exc: OSError) -> None:
        # Root-relative, as a content hit is: the absolute form can carry a user-home path. The root
        # itself is named as the caller wrote it.
        try:
            name = Path(os.fsdecode(exc.filename)).relative_to(root).as_posix()
        except (TypeError, ValueError):
            name = "."
        if name != "." and exc.errno in _GONE:
            return  # Removed after it was listed (a cache cleared mid-walk): nothing left to read.
        name = raw if name == "." else name
        if exc.errno == errno.ENOENT:
            errors.append(f"{name}/:0: {_NO_ROOT}")
            return
        why = errno.errorcode.get(exc.errno or 0, type(exc).__name__)
        errors.append(f"{name}:0: unreadable ({why}), so its content was not scanned (fail closed)")

    for top, dirs, files in os.walk(root, onerror=refused):
        rel_top = Path(top).relative_to(root).as_posix()
        prefix = "" if rel_top == "." else rel_top + "/"
        in_skip_dir = bool(set(Path(prefix).parts) & SKIP_DIRS)
        # Under a skipped directory only the paths leading to tracked files are walked at all.
        dirs[:] = [
            d
            for d in dirs
            if d != ".git"
            and (
                tracked is None
                or _path_key(prefix + d) in tracked_dirs
                or (d not in SKIP_DIRS and not in_skip_dir)
            )
        ]
        for name in files:
            rel = prefix + name
            if name == ".git" or (
                in_skip_dir and tracked is not None and _path_key(rel) not in tracked
            ):
                continue
            path = Path(top) / name
            # Every file by the root's locations joined to its path, which is where it sits; a link
            # inside the root (a file link, or a junction the walk descended) where it lands too.
            key = _path_key(rel)
            where = tuple(f"{at}/{key}" for at in at_root)
            if os.path.realpath(path) != os.path.abspath(path):
                where += _locations(path)
            out.append((path, rel, where))


def _candidate_files(paths: list[str], *, path_mode: bool) -> tuple[list[_Candidate], list[str]]:
    # Returns (openable path, scan-root-RELATIVE posix, location) triples, the location for --path only
    # (_Candidate), and an unreadable-directory hit for each
    # directory a --path walk could not list. The relative posix is what all skip decisions and hit
    # reports key on, so the logic is identical whether we scan tracked files (already repo-relative) or
    # a --path snapshot in an arbitrary directory.
    if path_mode:
        if not paths:
            print("scan_forbidden: --path requires at least one file or directory", file=sys.stderr)
            sys.exit(2)
        # EVERY path after --path is scanned, and a FILE is scanned as itself. Both used to be silent
        # no-ops: only argv[1] was read, so trailing paths were dropped without a word, and rglob() on a
        # non-directory yields nothing, so naming a file scanned exactly zero of it. The ZERO-files
        # refusal below only fires when the TOTAL is zero, so mixing one real directory with dropped
        # paths exited 0 and read as "all of these are clean". Measured 2026-08-04: a four-path audit
        # reported clean having examined one of the four.
        out: list[_Candidate] = []
        errors: list[str] = []
        for raw in paths:
            root = Path(raw)
            if root.is_file():
                # rel is the bare name, matching the directory case, where the rel path starts below
                # the root the caller NAMED. Its locations (_locations) are judged too, so a file
                # named under docs/security/ is still a hit (BACKLOG #5446).
                if root.name != ".git":
                    out.append((root, root.name, _locations(root)))
                continue
            _walk(raw, out, errors)
        return out, errors
    if paths:
        return [(Path(a), Path(a).as_posix(), ()) for a in paths], []
    return [(Path(p), Path(p).as_posix(), ()) for p in _git_tracked()], []


#: Byte-order marks, longest first: a UTF-32-LE mark begins with the UTF-16-LE one. The wide entries of
#: the table in messagefoundry/security/audit_all_platforms.py, copied because this file loads
#: standalone by path; UTF-8 needs no entry here, since a NUL-free file decodes as UTF-8 anyway.
_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)
_HEAD_BYTES = 4096


def _bomless_utf16(head: bytes) -> str | None:
    """The UTF-16 codec a head with no byte-order mark is written in, or ``None``. Text in the ASCII
    range, which every token is, has a NUL in every other byte and none between; binary has neither."""
    for codec, nul_at in (("utf-16-le", 1), ("utf-16-be", 0)):
        nuls, others = head[nul_at::2], head[1 - nul_at :: 2]
        if (
            len(nuls) >= 2
            and nuls.count(0) * 10 >= len(nuls) * 9
            and others.count(0) * 10 <= len(others)
        ):
            return codec
    return None


def _wide_shape(body: bytes, codec: str, bom: bytes) -> bool:
    """Whether the bytes after a byte-order mark have the NUL pattern its encoding gives ASCII text:
    one NUL in each 2-byte unit for UTF-16, three in each 4-byte unit for UTF-32."""
    if not body:
        return True
    if codec == "utf-16":
        return _bomless_utf16(body) == ("utf-16-le" if bom == codecs.BOM_UTF16_LE else "utf-16-be")
    nul_at = (1, 2, 3) if bom == codecs.BOM_UTF32_LE else (0, 1, 2)
    nuls = b"".join(body[i::4] for i in nul_at)
    return len(nuls) >= 3 and nuls.count(0) * 10 >= len(nuls) * 9


def _read_text(path: Path) -> list[str] | None:
    """The file's readings as text, one unless the bytes disagree with a byte-order mark, or ``None``
    for binary. Raises ``OSError`` when the file cannot be read, which
    ``scan_file`` reports as a hit: an unread file is not a clean one (BACKLOG #5583).

    A NUL near the start used to mean binary outright, so UTF-16 and UTF-32 text, which a Windows tool
    writes routinely, went unscanned. A byte-order mark or the UTF-16 shape now decodes it first."""
    # The head alone decides binary, so a large binary is not read whole only to be set aside.
    with path.open("rb") as f:
        head = f.read(_HEAD_BYTES)
        bom_codec = next(((bom, codec) for bom, codec in _BOMS if head.startswith(bom)), None)
        wide = None
        if bom_codec is None and b"\x00" in head:
            wide = _bomless_utf16(head)
            if wide is None:
                return None
        data = head + f.read()
    if bom_codec is not None:
        bom, codec = bom_codec
        wide_text = data.decode(codec, errors="replace")
        if _wide_shape(head[len(bom) :], codec, bom):
            return [wide_text]
        # The bytes disagree with the mark: a UTF-8 body behind a stray mark, or wide text mostly above
        # U+00FF (box drawing, CJK). Neither reading can be ruled out, so both are scanned: picking one
        # hid every token of the other (fail closed). A UTF-32 mark is also UTF-16 text whose first
        # character is U+0000 (FF FE 00 00 in little-endian), so that reading is scanned too.
        readings = [wide_text, data.decode("utf-8", errors="replace")]
        if codec == "utf-32":
            utf16 = "utf-16-le" if bom == codecs.BOM_UTF32_LE else "utf-16-be"
            readings.append(data.decode(utf16, errors="replace"))
        return readings
    return [data.decode(wide or "utf-8", errors="replace")]


def scan_file(path: Path, rel_posix: str | None = None, *, show_context: bool = False) -> list[str]:
    """Forbidden-content hits in a file, as ``path:line: reason`` strings.

    Reasons-only by default (location + category, never the matched value or line) so a hit report is
    safe to print in public CI logs. ``show_context`` additionally appends the matched value and the
    trimmed line -- for local triage only, never CI.
    """
    return _scan_file(path, rel_posix, show_context=show_context)[0]


def _location_reason(posix: str, where: tuple[str, ...] = ()) -> str | None:
    """Why the location rule forbids a file, judged by ``posix`` and each of ``where``
    (``_name_hits`` says what those are), or ``None``. Case-folded in every mode, so the staged and
    tracked scans agree with --path on Docs/Security.

    Asked BEFORE the file skip rules (``_is_skipped``): a skip keys on the root-relative path,
    which in ``--path`` mode starts below the root the caller named, so a file under a named
    docs/security whose relative path happened to match SKIP_PATHS or the vendored-bundle pattern
    was dropped unjudged and the run exited 0 (BACKLOG #5446). NOT before the SKIP_DIRS pruning in
    ``_walk``, which still runs first: where git lists no tracked file there, or cannot list at all
    (a planted ``.git`` can make it fail), a file under ``docs/security/build/`` or another skipped
    directory is never listed, so never judged. That route is left open."""
    judged = (_path_key(posix), *where)
    return next(filter(None, map(forbidden_path_reason, judged)), None)


def _name_hits(path: Path, posix: str, where: tuple[str, ...] = ()) -> tuple[list[str], bool]:
    """The hits a file earns by its path and name alone, and whether its content is not to be read.
    Judged whatever its bytes are. ``_scan_file`` keeps them when the content cannot be read, and the
    non-file branch of ``main`` keeps them beside any does-not-exist or unreadable hit.

    A location hit names ``path``, the root the caller wrote joined to ``posix``, so in a scan of
    several roots it names the root (the branch leak scan's commit directory). Under an absolute root
    that path can carry a user-home path.

    ``where`` is where the file is, from ``_locations``, and the location rule judges each beside
    ``posix`` (BACKLOG #5446). In ``--path`` mode ``posix`` starts below the root the caller named, so
    naming ``docs/security`` itself, a file in it, or its parent ``docs`` dropped the prefix the rule
    keys on, and a private document read clean."""
    if reason := _location_reason(posix, where):
        return [f"{path.as_posix()}:0: {reason}"], True
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
    return hits, False


def _line_hits(text: str, posix: str, path: Path, show_context: bool) -> list[tuple[int, str, str]]:
    """Content hits in one reading of a file, as (line, key, hit). The key is the hit, what it matched
    (the value, or the name pattern) and its count on that line, so the same finding on the same line
    in another reading is one hit, and two different findings of one kind stay two."""
    ip_scan = path.suffix not in _IP_SKIP_SUFFIXES and path.name not in _IP_SKIP_NAMES
    site_scan = path.suffix not in _SITE_SKIP_SUFFIXES and path.name not in _SITE_SKIP_NAMES
    out: list[tuple[int, str, str]] = []
    # How many times each (hit, matched) pair has been seen, so counting the nth costs one lookup.
    counts: dict[str, int] = {}
    for lineno, line in enumerate(text.splitlines(), 1):

        def add(reason: str, matched: str, extra: str = "", lineno: int = lineno) -> None:
            hit = f"{posix}:{lineno}: {reason}"
            # The nth such finding on this line: two on one line stay two, as they always were.
            key = f"{hit}\0{matched}"
            nth = counts.get(key, 0)
            counts[key] = nth + 1
            out.append((lineno, f"{key}\0{nth}", hit + extra))

        if _allowlisted(line):
            continue
        ctx = f": {line.strip()[:120]}" if show_context else ""
        before = len(out)
        # ``_`` is a WORD character, so a \b-anchored name pattern cannot see its token inside an
        # identifier: ``\bTOKEN\b`` does not match ``OB_TOKEN_ORU``. That blindness has hidden real
        # leaks in this repo more than once, and the estate set only covers it for tokens that happen
        # to appear in BOTH lists. Scanning a shadow copy with identifier separators neutralised closes
        # it for EVERY name pattern rather than for the instances someone remembered to duplicate.
        # Substitution preserves length, so offsets and ``show_context`` stay meaningful.
        unwrapped = _IDENT_SEP.sub(" ", line)
        for pat, reason in FORBIDDEN:
            if _name_matches(pat, line, unwrapped):
                add(reason, pat.pattern, ctx)
        if site_scan:
            for m in _SITE_CODE_FILE.finditer(line):
                value = f" ({m.group(0)})" if show_context else ""
                add("site code", m.group(0), f"{value}{ctx}")
            if lit := _SITE_CODE_PATTERN_LITERAL.search(line):
                add("site-code pattern written out", lit.group(0), ctx)
        if ip_scan:
            for m in _IPV4.finditer(line):
                ip = m.group(0)
                if not _ALLOWED_IP.match(ip):
                    value = f" ({ip})" if show_context else ""
                    add("routable IP address", ip, f"{value}{ctx}")
        # Internal-environment disclosure. Reason-only, never the value: the slug or account name IS
        # the disclosure, so echoing it into a public CI log would publish what the hit is reporting.
        if (slug := _first_match(_WORKTREE_SLUG_DETECTORS, line)) is not None:
            add("worktree/branch slug (internal project name)", slug)
        if home := _HOME_PATH.search(line):
            add("absolute user-home path (OS account name)", home.group(0))
        # Reason-only, and NOT ctx-appended even under show_context. The other reason-only detectors
        # withhold the value because it NAMES someone; this one withholds it because the URL IS the
        # access. Echoing it into a public CI log would hand out the capability the hit reports.
        if url := _ARTIFACT_URL.search(line):
            add("private artifact URL (the link itself grants access)", url.group(0))
        # Security-record content (BACKLOG #1337). REASON-ONLY, never the value, for the same reason
        # as the slug above: the identifier-verdict pair IS the disclosure, so echoing it into a
        # public CI log would publish exactly what the hit reports.
        if (pair := _first_match(_RECORD_PAIR, line)) is not None:
            add("security-record content (requirement id beside a verdict)", pair)
        # Reason-only for the same reason as the two above, and NOT ``ctx``-appended even under
        # show_context: the identifier IS the disclosure.
        if shape := _ESTATE_ID_SHAPE.search(line):
            add(f"{_ESTATE_ID_REASON} (the ported-estate site-code shape)", shape.group(0))
        # Estate substrings run LAST and only on a line nothing else flagged: the sets overlap (the
        # customer name is typically in [names] AND [estate]), and double-reporting one line adds noise
        # rather than information. What this adds is the case no other detector can reach -- a token
        # butted against word characters, e.g. ``OB_<TOKEN>_ORU``.
        if len(out) == before:
            for token, estate_pat in _ESTATE_FILE_RES:
                if estate_pat.search(line):
                    add("estate token", token, ctx)
                    break
    return out


def _first_match(patterns: tuple[re.Pattern[str], ...], line: str) -> str | None:
    """The text the first of ``patterns`` to match ``line`` matched, or ``None``."""
    for p in patterns:
        if m := p.search(line):
            return m.group(0)
    return None


#: What ``_scan_file`` did with a file's content: read it as text, set it aside unread (binary, or
#: under a forbidden path), or fail to read it at all.
_FileState = Literal["read", "unread", "unreadable"]


def _scan_file(
    path: Path,
    rel_posix: str | None = None,
    *,
    show_context: bool = False,
    where: tuple[str, ...] = (),
) -> tuple[list[str], _FileState]:
    """``scan_file``'s hits, and what became of the file's content. A binary file is judged by its name
    and location only, so the run must not count it as scanned, and an unreadable one is an instrument
    failure, not a clean file (BACKLOG #5583)."""
    posix = rel_posix if rel_posix is not None else path.as_posix()
    # The location rule first: a skipped name under docs/security is still a hit (_location_reason).
    if _is_skipped(posix) and _location_reason(posix, where) is None:
        return [], "unread"
    # LOCATION before content, and deliberately before the binary/unreadable early-return below: a
    # forbidden path is a hit whatever its bytes are, and a PDF or an image under docs/security/ is
    # exactly as much of a leak as the markdown beside it. Reported at line 0 because the finding is
    # the path itself and there is no line to point at -- the reason names the file, not a location
    # inside it. Scanning stops here; content hits on a file that must not exist add nothing.
    hits, stop = _name_hits(path, posix, where)
    if stop:
        return hits, "unread"
    try:
        texts = _read_text(path)
    except OSError as exc:
        # The errno name only: the message can carry the path's absolute form, a user-home path.
        why = errno.errorcode.get(exc.errno or 0, type(exc).__name__)
        hits.append(f"{posix}:0: unreadable ({why}), so its content was not scanned (fail closed)")
        return hits, "unreadable"
    if texts is None:
        return hits, "unread"
    # Each reading is numbered on its own, so a hit names a line of that reading, never one past
    # its end, and a finding two readings share on one line is reported once (BACKLOG #8244).
    seen: set[str] = set()
    found: list[tuple[int, str]] = []
    for text in texts:
        for lineno, key, hit in _line_hits(text, posix, path, show_context):
            if key not in seen:
                seen.add(key)
                found.append((lineno, hit))
    hits.extend(hit for _, hit in sorted(found, key=lambda f: f[0]))
    return hits, "read"


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

    The name patterns get the same identifier pass ``scan_file`` gives them, so a token inside an
    underscore-joined identifier is found here too (BACKLOG #5584). The estate reason names no token:
    the token IS the private estate string, and the leak-check raises and logs these reasons.
    """
    reasons: list[str] = []
    unwrapped = _IDENT_SEP.sub(" ", text)
    for pat, reason in FORBIDDEN:
        if _name_matches(pat, text, unwrapped):
            reasons.append(reason)
    for m in _IPV4.finditer(text):
        if not _ALLOWED_IP.match(m.group(0)):
            reasons.append("routable IP address")
            break
    if include_estate:
        lowered = text.lower()
        if any(token in lowered for token in ESTATE_TOKENS):
            reasons.append("estate token")
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

    DEDUPED, because ``_parse_tokens`` dedupes the entries these mirror. Two identical source lines
    compile to ONE detector, so returning the word twice would count two probes against one loaded
    entry -- and a caller measuring coverage would understate what went untested. Deduping at a call
    site instead would put the rule in one caller and not the other, which is the drift this helper
    was made public to prevent.
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
    return list(dict.fromkeys(probes))


class _ClassCoverage(NamedTuple):
    """One token class's self-test coverage, and why any of it went unprobed.

    ``label`` IS the key ``loaded_token_counts`` prints for this class and ``loaded`` IS that key's
    value, so the report and the counts block above it share one vocabulary. Deriving the denominator
    separately reintroduces exactly the cross-block arithmetic this change removes: an earlier draft
    printed ``estate_file_scanned ... of 14 loaded`` under a counts line reading
    ``estate_file_scanned=13``, each internally consistent and disagreeing with the other.

    ``unprobed_reason`` travels WITH the class rather than sitting in a table keyed by label. A table
    needs a default, and a default silently degrades the one channel this whole check exists to make
    legible the day a class is renamed.

    Counts and class names only -- never a token, never a probe. These fields print in a
    world-readable Actions log on the one run that holds the real secret.
    """

    label: str
    fired: int
    probeable: int
    loaded: int
    unprobed_reason: str

    @property
    def unprobed(self) -> int:
        """Loaded entries no probe could be built for, clamped at zero in ONE place.

        A ``[names]`` entry can be recoverable as a plain word and still be DROPPED at parse time
        (too many fields, an invisible codepoint), which would otherwise give a negative residual.
        Nothing is lost by clamping: that entry has no detector, so it cannot fire, and the
        ``fired != probeable`` check reports it as an inert detector -- the accurate reading.
        """
        return max(self.loaded - self.probeable, 0)

    def line(self) -> str:
        """This class's report line, with the UNPROBED residual NAMED rather than left to subtraction.

        ``fired 6/6`` reads as full coverage. Measured against the REAL table on 2026-09-05, unchanged
        from the 2026-09-03 run this check shipped with: the three class lines read ``2/2``, ``13/13``
        and ``6/6 probeable of 8 loaded`` while THREE of the 24 loaded entries had never been probed
        at all -- two ``[names]`` regexes the prober cannot invert, plus one ``[estate_body_only]``
        hold-out visible only by subtracting a number in the report from a number in the counts block
        printed above it. A ratio whose denominator silently drops what it could not test is the same
        green-line-over-a-hole this check exists to remove, so the residual is stated in words, on the
        same line, in the same units as the numerator.
        """
        line = f"{self.label} fired {self.fired}/{self.probeable} probeable of {self.loaded} loaded"
        if self.unprobed:
            line += f"; {self.unprobed} UNPROBED ({self.unprobed_reason})"
        return line


def self_test() -> tuple[list[str], list[str]]:
    """Probe every loaded class with a string built from what that class loaded.

    Returns ``(report, failures)``. Both hold counts and class names only -- never a token, never a
    probe -- so both are safe to print in public CI.

    Probing is TOTAL for ``site_prefix`` and for the file-scanned ``estate`` subset: a prefix is ASCII
    digits and an estate pattern is ``re.escape``d around its own literal, so a matching string is
    derivable from every entry that loaded. There a shortfall between what was probed and what FIRED
    is a FAILURE -- a detector that loaded and cannot match its own value is inert.

    WHICH WAY A SHORTFALL IN *PROBEABILITY* FAILS, AND WHY IT IS SPLIT IN TWO:

    * A PARTIAL shortfall is REPORTED, not failed -- fail-open, deliberately. A rich ``[names]``
      regex and an ``[estate_body_only]`` hold-out are both legitimate, intended list shapes, and a
      required merge context that reds on a correct list is a required merge context somebody
      switches off. The price of fail-open is that nothing downstream alarms, so the residual is
      instead made impossible to miss: every class states its own UNPROBED count, and a final
      aggregate line states the total across classes.
    * A TOTAL shortfall -- a class that loaded entries and could probe NONE of them -- is a FAILURE.
      It is not a false failure but an accurate report that the class was never exercised, and it is
      the rule this function already enforced globally, now applied per class. Without it a run can
      print ``names fired 0/0 probeable of 8 loaded``, exit 0 because a sibling class happened to
      probe, and leave the class this gate was built for entirely unverified.

    EVERY CLASS THAT LOADED ANYTHING REPORTS A LINE. These guards were once ``if <probes>``, so a
    class whose entries were all unprobeable vanished from the report and its silence read as
    "nothing to say" rather than "nothing was checked".
    """
    report: list[str] = []
    failures: list[str] = []
    # ONE source for every "loaded" number, here and in the counts block main prints directly above
    # this report. Re-deriving them from len(_SITE_PREFIXES) / len(ESTATE_TOKENS) / len(FORBIDDEN)
    # would be a second definition of the same numbers, and the drift would be invisible: each block
    # stays internally consistent while disagreeing with the other.
    counts = loaded_token_counts()
    coverage: list[_ClassCoverage] = []

    # [site_prefix] -- the class that falls back to _NEVER, so the class where a silent load failure
    # and a clean tree are the same green tick. The probe wraps the code in identifier separators
    # because that is the boundary the FILE detector requires.
    fired = 0
    for prefix in _SITE_PREFIXES:
        m = _SITE_CODE_FILE.search(f"PT_{prefix}0000_ADT")
        if m is not None and m.group(0).startswith(prefix):
            fired += 1
    if _SITE_PREFIXES:
        coverage.append(
            _ClassCoverage(
                "site_prefixes",
                fired,
                len(_SITE_PREFIXES),
                counts["site_prefixes"],
                # Unreachable by construction: a prefix is ASCII digits, so a probe is derivable from
                # every entry that loads and probeable always equals loaded. Kept as a tripwire rather
                # than a generic default -- if this text ever prints, that invariant has broken.
                "probing is total for this class, so a residual here is a bug",
            )
        )
        if fired != len(_SITE_PREFIXES):
            failures.append(
                f"site_prefix: {len(_SITE_PREFIXES) - fired} of {len(_SITE_PREFIXES)} loaded "
                "prefix(es) did not match a site code built from that same prefix -- the detector "
                "is loaded and inert"
            )

    # [estate] -- only the FILE-SCANNED subset can be probed. An [estate_body_only] token never enters
    # scan_file, so probing one would assert nothing about the gate that guards tracked files. The
    # denominator is the WHOLE class, which is what turns that hold-out from a gap between two numbers
    # in two different blocks into a stated count on this class's own line.
    fired = 0
    for token, pattern in _ESTATE_FILE_RES:
        if pattern.search(f"OB_{token}_ORU"):
            fired += 1
    if ESTATE_TOKENS:
        coverage.append(
            _ClassCoverage(
                "estate",
                fired,
                len(_ESTATE_FILE_RES),
                counts["estate"],
                "held out of the file scan by [estate_body_only]",
            )
        )
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
    if FORBIDDEN:
        coverage.append(
            _ClassCoverage(
                "names",
                fired,
                len(words),
                counts["names"],
                "not a plain word in word boundaries, so no probe string is derivable",
            )
        )
        # No `words and` guard: fired is derived from words, so an empty words gives 0 != 0, which is
        # already false. The empty case is the total shortfall below, and it is a different finding.
        if fired != len(words):
            failures.append(
                f"names: {len(words) - fired} of {len(words)} plain-word entries did not match their "
                "own word -- the entry parsed but the detector is inert"
            )

    for cov in coverage:
        report.append(cov.line())
        if cov.probeable == 0:
            failures.append(
                f"{cov.label}: none of the {cov.loaded} loaded entries could be probed, so this run "
                f"proved nothing about the {cov.label} class -- the per-class form of the vacuous "
                "pass this check exists to remove. Extend the prober to the shape this class now "
                "uses; silencing it leaves the class unverified either way"
            )

    # THE AGGREGATE, and it is here because three class lines each reading "fired N/N" add up to a
    # report a skimmer reads as full coverage. One line, one pair of numbers, in the units the counts
    # block already uses, so the size of the untested remainder cannot be missed by reading down.
    total_loaded = sum(cov.loaded for cov in coverage)
    unprobed = sum(cov.unprobed for cov in coverage)
    summary = f"coverage {total_loaded - unprobed} of {total_loaded} loaded entries probed"
    if unprobed:
        blind = sum(1 for cov in coverage if cov.unprobed)
        summary += f"; {unprobed} UNPROBED across {blind} class(es)"
    report.append(summary)

    # The per-class rule above covers every class that LOADED something, so what is left for this one
    # is a call that reached here with empty tables. ``main`` refuses that before it gets this far, but
    # a direct caller can reach it, and an empty run must not come back as a clean bill.
    if not coverage:
        failures.append(
            "no class loaded anything, so this run proved nothing about detection -- which is the "
            "vacuous pass the self-test exists to remove"
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


def _report_hits(header: str, hits: list[str], advice: str) -> int:
    """Print a hit report to stderr in the one shape every mode uses, and return the hit exit code."""
    print(header, file=sys.stderr)
    for h in hits:
        print(f"  {h}", file=sys.stderr)
    print(f"\n{len(hits)} hit(s). {advice}", file=sys.stderr)
    return 1


def _pr_body_mode(argv: list[str]) -> int:
    """``--pr-body PATH`` or ``--pr-body-event PATH``: scan one pull request body and exit.

    ``--pr-body`` reads a text file, or stdin for ``-``: the form for an author checking a draft.
    ``--pr-body-event`` reads ``pull_request.body`` from a webhook payload, which is how CI feeds it --
    ``$GITHUB_EVENT_PATH``, so the body never passes through an Actions expression, a shell variable or
    an environment block, and is neither shell input nor bound by the size limit on one. Needs no token
    source -- the three record kinds are structural -- so it runs the same on a fork.

    The mode must be the WHOLE command line. A staged file that happened to be named like the flag
    reaches pre-commit's argv after ``--require-tokens``, and must not switch the commit gate into
    scanning one file as a body.
    """
    if len(argv) != 2 or argv[0] not in ("--pr-body", "--pr-body-event"):
        print(
            "scan_forbidden: usage: --pr-body FILE (- for stdin) | --pr-body-event EVENT.json, alone.",
            file=sys.stderr,
        )
        return 2
    mode, source = argv
    try:
        if mode == "--pr-body":
            body = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
        else:
            event = json.loads(Path(source).read_text(encoding="utf-8"))
            # A payload with no pull request is a misrouted run, not an empty body: refuse it.
            if not isinstance(event, dict) or not isinstance(event.get("pull_request"), dict):
                print(
                    f"scan_forbidden: {mode}: {source} is not a pull request event.",
                    file=sys.stderr,
                )
                return 2
            body = event["pull_request"].get("body") or ""
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"scan_forbidden: {mode}: cannot read {source}: {exc}", file=sys.stderr)
        return 2
    # Say what was read, as the tree scan does: a body that silently arrived empty would otherwise pass
    # exactly as a clean one does.
    print(
        f"scan_forbidden: examined a pull request body of {len(body.splitlines())} line(s).",
        file=sys.stderr,
    )
    hits = scan_pr_body(body)
    if hits:
        return _report_hits(
            "FORBIDDEN CONTENT in the pull request body (fail closed):",
            hits,
            "A public pull request body must not state a requirement's verdict, its gap, or the code "
            "that implements it; the per-requirement grid is private. Edit the body to describe the "
            "change without them. A bare requirement number with none of the three beside it is not "
            "flagged.",
        )
    return 0


def main(argv: list[str]) -> int:
    # BACKLOG #3364. A terminal mode taken before any token-floor handling: it scans text that is not a
    # file in the tree, and none of its detectors come from the token source.
    if argv and argv[0].startswith("--pr-body"):
        return _pr_body_mode(argv)
    reload_tokens()
    # SEC-04 / BACKLOG #1368. Both are read BEFORE the require/floor parsing below, because each is a
    # terminal mode that reports and exits rather than scanning.
    #
    # Each terminal mode must be the WHOLE command line, as the body modes above are (BACKLOG #5585).
    # pre-commit passes ``--require-tokens`` and then the staged names, so a staged file spelled like
    # one of these flags used to switch the commit gate into reporting and exiting 0 without scanning
    # anything. Anywhere else the flag falls through to ``_parse_require_flag``, which refuses it.
    terminal = argv[0] if len(argv) == 1 else None
    if terminal == "--print-detector-counts":
        for line in _detector_count_report(loaded_token_counts()):
            print(line)
        return 0
    if terminal == "--assert-floor-fresh":
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
    if terminal == "--self-test":
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

    # First only, for the reason the terminal modes above are whole-line only: taken from anywhere, a
    # staged file named ``--show-context`` was dropped unscanned and switched on value echoing.
    # Anywhere else ``_parse_require_flag`` refuses it.
    show_context = bool(argv) and argv[0] == "--show-context"
    rest = argv[1:] if show_context else list(argv)
    # Everything after the first ``--`` is a path operand, never an option, so a staged
    # file named ``--path`` or ``--require-tokens`` is scanned rather than read as the flag. pre-commit
    # passes ``--`` ahead of the staged names for that reason (BACKLOG #5585).
    operands: list[str] = []
    if "--" in rest:
        cut = rest.index("--")
        rest, operands = rest[:cut], rest[cut + 1 :]
    try:
        flag_require, minimum, rest = _parse_require_flag(rest)
    except ValueError as exc:
        print(f"scan_forbidden: {exc}", file=sys.stderr)
        return 2
    path_mode = bool(rest) and rest[0] == "--path"
    paths = (rest[1:] if path_mode else rest) + operands

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

    # Only a file whose content was read as text counts as scanned. A binary file is judged by its name
    # and location only, and an unreadable one fails the run with exit 2; counting either as scanned let
    # a run whose files were all unread report coverage it did not have (BACKLOG #5583). A directory the
    # --path walk could not list is unreadable in the same way.
    try:
        candidates, hits = _candidate_files(paths, path_mode=path_mode)
    except (OSError, subprocess.CalledProcessError) as exc:
        # 2, not a traceback's 1: git could not list the tracked files, so nothing was scanned.
        print(
            f"scan_forbidden: cannot list the tracked files ({type(exc).__name__})", file=sys.stderr
        )
        return 2
    scanned = 0
    # A walk hit for a directory the walk could not list is counted as unread; one for a named root
    # that does not exist is not, since nothing was there. Both still fail the run as unreadable.
    unread = sum(not h.endswith(_NO_ROOT) for h in hits)
    unreadable = len(hits)
    for abs_path, rel, where in candidates:
        # SKIP_DIRS is applied by the --path walk alone (_walk); the tracked and staged scans prune no
        # directory. The location rule is asked before the skip (_location_reason), so a skipped
        # name under docs/security goes on to be judged by it below.
        if _is_skipped(rel) and _location_reason(rel, where) is None:
            continue
        if not abs_path.is_file():
            # Not a regular file, or one is_file() could not stat (it hides that error). In every mode,
            # an lstat of the entry itself that fails other than ENOENT or ENOTDIR (_GONE) fails the
            # run. In staged mode (any path named on the command line, with or without ``--``, outside
            # --path) a directory, a link to a directory, a link whose target cannot be stat'ed, or a
            # missing name also fails the run. _GONE is passed over in the --path walk (removed since
            # it was listed) and in the tracked scan (deleted in the work tree, or under a directory
            # replaced by a file). Anything else whose lstat
            # succeeds, such as a FIFO, or outside staged mode a dangling link, is judged by its path
            # and name only; the walk never lists a link to a directory, so that is not judged. Every
            # entry that reaches the hits is also judged by its path and name.
            try:
                st_mode = abs_path.lstat().st_mode
                reason = None
                if paths and not path_mode:
                    if stat.S_ISDIR(st_mode):
                        reason = "a directory, not a file"
                    elif stat.S_ISLNK(st_mode):
                        try:
                            if stat.S_ISDIR(abs_path.stat().st_mode):
                                reason = "a link to a directory, not a file"
                        except OSError as link_exc:
                            why = errno.errorcode.get(link_exc.errno or 0, type(link_exc).__name__)
                            reason = f"a link whose target cannot be stat'ed ({why})"
            except OSError as exc:
                # Gone since it was listed, or a tracked file deleted in the work tree.
                if exc.errno in _GONE and (path_mode or not paths):
                    continue
                reason = (
                    "does not exist"
                    if exc.errno in _GONE
                    else f"unreadable ({errno.errorcode.get(exc.errno or 0, type(exc).__name__)})"
                )
            unread += 1
            # The path alone decides a location or name hit, so it is kept for every entry that gets
            # here: an unstatable name under docs/security/, or in staged mode a missing one, still
            # exits 1, not 2. A gone entry passed over above earns no hit.
            hits.extend(_name_hits(abs_path, rel, where)[0])
            if reason is None:
                continue
            hits.append(f"{rel}:0: {reason}, so its content was not scanned (fail closed)")
            unreadable += 1
            continue
        file_hits, state = _scan_file(abs_path, rel, show_context=show_context, where=where)
        hits.extend(file_hits)
        if state == "read":
            scanned += 1
        else:
            unread += 1
            unreadable += state == "unreadable"

    # PRINT WHAT WAS SCANNED, not just what was loaded. Exit 0 plus a token-count line cannot tell a
    # caller whether the files they named were examined -- and when --path silently dropped trailing
    # paths, nothing in the output revealed it. A coverage number makes an under-scan visible without
    # having to suspect it.
    if path_mode:
        print(
            f"scan_forbidden: examined {scanned} file(s) across {len(paths)} named path(s); "
            f"{unread} more were binary, not regular files, unreadable or under a forbidden path, "
            "so their content was not scanned.",
            file=sys.stderr,
        )

    # A --path scan that examined ZERO files is not a pass: an empty or wrong tree, all-binary content,
    # or every file under a directory the walk skipped. Refuse rather than report a vacuous clean.
    # A hit outranks the refusal: a run whose only file sits under a forbidden path still reports it.
    if path_mode and scanned == 0 and not hits:
        print(
            "scan_forbidden: --path examined ZERO files (all skipped or unread, or empty tree) — refusing "
            "(fail closed). Check that the path names the tree meant: an empty or all-binary tree, or one "
            "whose every file sits under a skipped build/venv/dist/… directory, scans nothing.",
            file=sys.stderr,
        )
        return 2

    # 2, not 1: an unread file is an instrument that could not see, which wants its permissions or lock
    # fixed, not content removed. The same split as --self-test's.
    # A content hit outranks it: a confirmed leak keeps exit 1 and its own advice, beside the unread list.
    if unreadable and len(hits) == unreadable:
        _report_hits(
            "UNREADABLE FILES -- their content was not scanned (fail closed):",
            hits,
            "Fix the permissions or lock, or name a file that exists, then scan again. Any content "
            "hit above still applies.",
        )
        return 2

    if hits:
        return _report_hits(
            "FORBIDDEN CONTENT -- commit blocked (fail closed):",
            hits,
            "A real customer/host string must be removed, not allowlisted. For a genuine false "
            "positive, narrow the pattern or add a vetted line to scripts/security/scan-allowlist.txt.",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
