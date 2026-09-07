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
# nobody. PUSH failure here is silent by design: the reporting job belongs to
# scripts/coord/unbacked_check.ps1, which measures the true state rather than trusting this ran.
#
# THE REF IT WRITES RECORDS WHAT IT CAPTURED (BACKLOG #1349), and the reason is the whole item. A
# rescue ref is consulted ONCE, in the moment the original is already gone -- so a ref that records
# nothing can only be graded against a branch that still exists, which is exactly the population it
# was never needed for. Measured 2026-09-03 in this checkout: `rescue.ps1 -Check` examined 1671 refs
# and returned UNVERIFIABLE for all 1671, because every one of them was written by a bare push.
#
# So this pushes an ANNOTATED TAG OBJECT carrying the same `mefor-rescue-v1` message
# scripts/coord/rescue.ps1 -Anchor writes, and `-Check` reads it back without needing the branch.
# The object is built with `git hash-object -t tag -w` and pushed BY ID -- no local ref is created.
# That is deliberate: a local annotated tag reachable from a branch tip would be swept up by
# `git push --follow-tags` or `git push --tags` to whatever remote a hand reaches for, and the
# default one is PUBLIC. Provenance must not open the publication path this hook exists to avoid.
#
# IT COSTS THREE MORE GIT SPAWNS IN THE FOREGROUND, MEASURED RATHER THAN GUESSED. Five runs of each
# form on 2026-09-03: 2.615s of user+sys for this version against 1.688s for the bare-push one, so
# about 0.19s of CPU per commit. Wall clock is NOT quoted, because the box was running six
# concurrent test processes at the time and the figure would be about the load, not the hook. It
# stays in the foreground rather than joining the background push so that a failure is reported to
# the terminal that caused it instead of arriving after the prompt returns.
#
# AND EVERY NEW FAILURE MODE HERE DEGRADES TO A WARNING. `git hash-object` fsck-validates the object
# and exits non-zero on a malformed tagger line, and `git var GIT_COMMITTER_IDENT` can be empty in a
# repository with no identity configured. Either way $TAGOBJ comes back empty, the push falls back to
# the bare `HEAD:` form it used before, one warning goes to stderr, and THE COMMIT STANDS. Durability
# is the property that must never regress; provenance is the property that improves it.
#
# WHAT IT DOES NOT COVER, stated because a control trusted past its reach is worse than none:
#   * Uncommitted work. Nothing here helps; a lost working tree is lost.
#   * Rebases. The tag force-moves to follow the branch, so commits only reachable from a discarded
#     tip are orphaned remotely. The local reflog still holds them. This narrows the window; it does
#     not close it.
#   * Concentration. Every tag lands on ONE nominated remote. That is one account away from total
#     loss, and tags are mutable and unprotected.
#   * The refs already pushed. Provenance cannot be retrofitted -- the information was never
#     captured. Unlike the dated tag namespace, though, THIS one heals: the ref force-moves on the
#     next commit to the same branch, so it carries provenance from then on.
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

# NAMESPACE BY REPOSITORY. Two repositories push rescue tags to ONE remote -- the engine's `private`
# and the vault's `origin` are the same GitHub repo -- so a tag keyed by branch name ALONE collides on
# any name both use. `main` is the obvious one, and the push is --force, so the second repo to commit
# silently overwrites the first's coverage. Measured 2026-08-19: refs/tags/rescue/auto/main held a sha
# belonging to NEITHER repo's main.
#
# Discriminate by the git COMMON DIR, never by the remote URL -- the URL is the thing that makes these
# two indistinguishable in the first place. The common dir is shared by every worktree of a repo and
# differs between repos, which is exactly the grouping wanted here.
REPO=$(basename "$(dirname "$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)")" 2>/dev/null)
# A tag path component must not carry spaces or shell-special characters.
REPO=$(printf '%s' "$REPO" | tr -c 'A-Za-z0-9._-' '-')
[ -n "$REPO" ] || REPO=unknown

BRANCH=$(git symbolic-ref --quiet --short HEAD 2>/dev/null)
if [ -n "$BRANCH" ]; then
  TAG="refs/tags/rescue/auto/$REPO/$BRANCH"
else
  # Detached HEAD is the state most likely to lose work -- no branch ref keeps the commit alive, so
  # the reflog is the only thing holding it. Tag by sha rather than skipping.
  TAG="refs/tags/rescue/auto/$REPO/detached/$(git rev-parse --short HEAD 2>/dev/null)"
fi

# --- provenance (BACKLOG #1349) ---------------------------------------------------------------
# SRC is what gets pushed. It stays HEAD unless a provenance tag object can be built, so the
# durability guarantee is unconditional and the provenance rides on top of it.
SRC=HEAD
TAGOBJ=

COMMIT=$(git rev-parse --verify --quiet "HEAD^{commit}" 2>/dev/null)
IDENT=$(git var GIT_COMMITTER_IDENT 2>/dev/null)

if [ -n "$COMMIT" ] && [ -n "$IDENT" ]; then
  if [ -n "$BRANCH" ]; then
    # WAS IT THE TIP? Verified rather than assumed. A post-commit hook runs with HEAD on the commit
    # it just made, so the answer is True by construction -- and "true by construction" is the exact
    # shape of claim this item exists to distrust, so it costs one rev-parse to actually check.
    TIP=$(git rev-parse --verify --quiet "refs/heads/$BRANCH^{commit}" 2>/dev/null)
    if [ "$TIP" = "$COMMIT" ]; then
      WASTIP="was-tip: True"
    else
      WASTIP="was-tip: False"
    fi
    LABEL="$BRANCH"
  else
    # NO BRANCH, SO THE LINE IS OMITTED RATHER THAN GUESSED. `was-tip: True` and `was-tip: False`
    # are both claims about a branch that does not exist. Leaving the line out is what makes
    # `rescue.ps1 -Check` report SELF-DESCRIBING -- "intact, and whether it held a tip cannot be
    # told" -- which is the true statement about a detached capture.
    WASTIP=
    LABEL="(detached)"
  fi

  CAPTURED=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)

  MSG="mefor-rescue-v1
commit: $COMMIT
branch: $LABEL"
  if [ -n "$WASTIP" ]; then
    MSG="$MSG
$WASTIP"
  fi
  if [ -n "$CAPTURED" ]; then
    MSG="$MSG
captured: $CAPTURED"
  fi
  MSG="$MSG
writer: durability_push.sh"

  # `-w` writes the object and prints its id; nothing references it until the push lands, and an
  # unreferenced loose object is collected on the usual schedule if the push never does.
  TAGOBJ=$(printf 'object %s\ntype commit\ntag %s\ntagger %s\n\n%s\n' \
    "$COMMIT" "${TAG#refs/tags/}" "$IDENT" "$MSG" \
    | git hash-object -t tag -w --stdin 2>/dev/null)
fi

if [ -n "$TAGOBJ" ]; then
  SRC="$TAGOBJ"
else
  echo "durability_push: WARNING -- could not build a provenance tag object for $TAG." >&2
  echo "  Pushing the bare commit instead, so DURABILITY IS UNAFFECTED and this commit stands." >&2
  echo "  The ref will read UNVERIFIABLE under scripts/coord/rescue.ps1 -Check, which is the" >&2
  echo "  honest verdict for a ref that records nothing about what it captured." >&2
fi

# Backgrounded and detached so the commit returns immediately. --force because the tag tracks a
# moving tip. Output is discarded: see "NEVER FAILS A COMMIT" above.
( git push --quiet --force "$REMOTE" "$SRC:$TAG" >/dev/null 2>&1 & ) >/dev/null 2>&1

exit 0
