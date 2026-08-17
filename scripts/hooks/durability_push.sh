#!/bin/sh
# MessageFoundry durability hook -- INSTALLED COPY. Source: scripts/hooks/durability_push.sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
#
# DURABILITY HOOK (post-commit). Pushes this commit somewhere it is not the only copy.
# This file is installed VERBATIM as .git/hooks/post-commit -- it needs no shim, because unlike the
# claim and push gates it has no Python payload to locate. Re-install after editing:
#     pwsh -NoProfile -File scripts/coord/install-git-hooks.ps1
#
# WHY THIS EXISTS. Committing is a session's own judgment; pushing is not, because `origin` IS the
# published artifact and a push there is publication. So a session can create work it is not
# permitted to make durable, and a session that stops at a usage cap takes the only copy with it.
# Measured 2026-08-16 across this checkout: 802 commits on 239 branches existed on no remote at all,
# and the oldest was 17 days old. Nothing reported it, because git raises no signal for
# "correct but unpublished" -- it conflicts on concurrent edits, never on an unpublished divergence.
#
# WHAT MAKES IT SAFE TO RUN WITHOUT APPROVAL. A tag under `rescue/auto/` on a PRIVATE remote buys
# DURABILITY without REVIEW and without DISCLOSURE: it opens no pull request, cannot auto-merge, and
# is not visible outside the nominated remote. The approval gate exists to control publication, and
# this publishes nothing. That is the whole design -- the sessions that most need durability are the
# ones that cannot stop and ask for it.
#
# OPT-IN, AND FAIL-SAFE BY ABSENCE. Does nothing unless a remote is nominated:
#     git config mefor.durabilityRemote <remote-name>
# An unset key is a no-op, so a fresh clone, a CI checkout, or a contributor's fork never pushes
# anywhere. The operator names the remote; this script never guesses one.
#
# THE REMOTE MUST BE PRIVATE. This script cannot verify visibility offline -- GitHub does not expose
# it over the git protocol -- so it hard-refuses the one target known to be public and otherwise
# trusts the nomination. Verify before nominating:
#     gh repo view <owner>/<repo> --json visibility
# Nominating a public remote turns a durability control into an unreviewed publication channel.
#
# AND THE SAFE REMOTE IS NOT THE DEFAULT ONE. This checkout carries two remotes that differ in KIND:
#     origin   MEFORORG/MessageFoundry       PUBLIC
#     private  wshallwshall/MessageFoundry   PRIVATE
# `git push` with no remote named resolves to `origin`, so the dangerous target is the one a hand
# reaches by default and the safe one must be typed. That is a sharper trap than assuming a remote is
# private and being wrong: here the wrong answer is what happens when nobody decides anything. It is
# also why this hook takes an explicitly nominated remote rather than defaulting to one -- there is no
# default that is safe to guess, and guessing `origin` would publish.
#
# NEVER FAILS A COMMIT. Always exits 0 and pushes in the background. A durability mechanism that can
# block or slow a commit gets disabled by the first person it inconveniences, and then protects
# nobody. Failure here is silent by design: the reporting job belongs to
# scripts/coord/unbacked_check.ps1, which measures the true state rather than trusting this ran.
#
# WHAT IT DOES NOT COVER, stated because a control trusted past its reach is worse than none:
#   * Uncommitted work. Nothing here helps; a lost working tree is lost.
#   * Rebases. The tag force-moves to follow the branch, so commits only reachable from a discarded
#     tip are orphaned remotely. The local reflog still holds them. This narrows the window; it does
#     not close it.
#   * Concentration. Every tag lands on ONE nominated remote. That is one account away from total
#     loss, and tags are mutable and unprotected.
#
# Re-install after changing this file:  pwsh -NoProfile -File scripts/coord/install-git-hooks.ps1

REMOTE=$(git config --get mefor.durabilityRemote 2>/dev/null)
[ -n "$REMOTE" ] || exit 0

URL=$(git remote get-url "$REMOTE" 2>/dev/null)
[ -n "$URL" ] || exit 0

# Hard refusal for the canonical PUBLIC remote. This is a named-target check, not a general
# visibility test -- there is no offline visibility test. It exists because the most likely
# misconfiguration by far is nominating the remote that is already there.
case "$URL" in
  *MEFORORG/MessageFoundry*)
    echo "durability_push: REFUSING -- mefor.durabilityRemote names the canonical PUBLIC repo." >&2
    echo "  A push there is publication, which is the gate this hook exists to avoid tripping." >&2
    echo "  Nominate a private remote instead, then re-commit." >&2
    exit 0
    ;;
esac

BRANCH=$(git symbolic-ref --quiet --short HEAD 2>/dev/null)
if [ -n "$BRANCH" ]; then
  TAG="refs/tags/rescue/auto/$BRANCH"
else
  # Detached HEAD is the state most likely to lose work -- no branch ref keeps the commit alive, so
  # the reflog is the only thing holding it. Tag by sha rather than skipping.
  TAG="refs/tags/rescue/auto/detached/$(git rev-parse --short HEAD 2>/dev/null)"
fi

# Backgrounded and detached so the commit returns immediately. --force because the tag tracks a
# moving tip. Output is discarded: see "NEVER FAILS A COMMIT" above.
( git push --quiet --force "$REMOTE" "HEAD:$TAG" >/dev/null 2>&1 & ) >/dev/null 2>&1

exit 0
