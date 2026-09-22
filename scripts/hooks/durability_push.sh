#!/bin/sh
# MessageFoundry durability hook -- INSTALLED COPY. Source: scripts/hooks/durability_push.sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
#     origin   MEFORORG/MessageFoundry             PUBLIC
#     private  MEFORORG/MessageFoundry-vault   PRIVATE
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
#   * A rewrite that is never followed by a commit. The preserve-before-move block below fires on
#     the next commit to the rewritten branch, because that is when the moving tag would discard the
#     old tip. Until then nothing is at risk -- the remote tag still holds the old tip -- but nothing
#     is captured either, so a clone lost in that window loses the discarded commits.
#   * A branch whose name is a prefix of another branch's. `refs/tags/rescue/auto/<repo>/a` and
#     `.../a/b` cannot both exist: git refuses the second, one ref being a directory the other needs
#     to be a file. That predates this hook's bookkeeping ref, which inherits the same shape.
#   * Concentration. Every tag lands on ONE nominated remote. That is one account away from total
#     loss, and tags are mutable and unprotected.
#   * The refs already pushed. Provenance cannot be retrofitted -- the information was never
#     captured. Unlike the dated tag namespace, though, THIS one heals: the ref force-moves on the
#     next commit to the same branch, so it carries provenance from then on.
#
# Re-install after changing this file:  pwsh -NoProfile -File scripts/coord/install-git-hooks.ps1

REMOTE=$(git config --get mefor.durabilityRemote 2>/dev/null)
[ -n "$REMOTE" ] || exit 0

# EVERY URL THE PUSH COULD USE, NOT THE ONE A READER ASSUMES. `git remote get-url` returns
# remote.<name>.url -- the FETCH url -- while the `git push` at the foot of this script resolves
# remote.<name>.pushurl when one is set. Reading only the fetch url left the entire refusal
# bypassable by one config line: `git remote set-url --push <name> <public>` on an otherwise private
# remote force-pushed a rescue tag to the public repository on every commit, and this guard printed
# nothing. Measured 2026-09-19 with two local bare repos: with the public spelling as the fetch url
# the hook refused; moved to the pushurl, the same spelling reached the push with no refusal.
#
# So collect both sets and refuse if ANY of them names the public repository. `--push --all` falls
# back to the fetch url when no pushurl is configured, so the two overlap in the ordinary case and
# a duplicate costs one extra comparison.
URLS=$(
  git remote get-url --all "$REMOTE" 2>/dev/null
  git remote get-url --push --all "$REMOTE" 2>/dev/null
)
[ -n "$URLS" ] || exit 0

# Hard refusal for the canonical PUBLIC remote. This is a named-target check, not a general
# visibility test -- there is no offline visibility test. It exists because the most likely
# misconfiguration by far is nominating the remote that is already there.
#
# THE TRAILING MATCH IS LOAD-BEARING, AND A PREFIX GLOB HERE FAILED IN EXACTLY THE WRONG DIRECTION.
# This read `*MEFORORG/MessageFoundry*` until 2026-09-19, when the private vault was transferred
# into the same organization and became `MEFORORG/MessageFoundry-vault`. That path matches the
# prefix glob, so the hook began refusing the PRIVATE remote as though it were the public one --
# and because the refusal is `exit 0`, every commit still succeeded with durability silently OFF.
# The two repositories are now one suffix apart under one owner, so nothing before the end of the
# path distinguishes them.
#
# ANCHORING ALONE LEFT THE OTHER DIRECTION OPEN, AND THAT ONE IS WORSE. The first fix matched three
# literal spellings, so `https://github.com/mefororg/messagefoundry.git` -- the same public
# repository, differing only in case -- was ACCEPTED and pushed. Measured 2026-09-19 against the
# then-current script. Over-refusing turns durability off quietly; under-refusing opens the
# unreviewed publication path this guard is the only thing standing in front of, and GitHub resolves
# owner and name case-insensitively, so that URL reaches the same repository.
#
# So normalise, then compare whole. One repository has several legitimate spellings -- https, ssh,
# `git://`, scp-style `host:owner/name`, with or without `.git`, with or without a trailing slash --
# and `.wiki` is stripped because a public repository's wiki is public too.
#
# NOT COVERED, DELIBERATELY: the host is not examined, so any host serving this owner and name is
# refused exactly as before; and a GitHub rename redirect is invisible offline, per the header.
# Everything this does not name is still trusted to the nomination.
#
# This matcher is the vault clone's, ported rather than reinvented (vault PR 1604). The two clones
# carry separate copies of this script and nothing re-syncs them, which is why the anchor fix and
# the case fix were each live on one side only.
#
# THE SUFFIXES ARE STRIPPED IN A LOOP, NOT ONCE EACH IN A FIXED ORDER. A single pass over
# `/`, `.git`, `.wiki` leaves any other composition intact, and each survivor is an ACCEPT -- the
# publishing direction. Measured 2026-09-19 against the one-pass version: `MessageFoundry//`,
# `MessageFoundry.git//` and `MessageFoundry///` all escaped the refusal. The loop terminates
# because every iteration removes at least one character.
#
# `[:upper:]`/`[:lower:]` rather than `A-Z`/`a-z`: POSIX defines tr's range endpoints in COLLATION
# order, so under a locale whose collation interleaves cases the ranges do not map what they appear
# to and an uppercase URL survives unchanged -- again an accept. A git hook inherits whatever
# LC_ALL/LC_CTYPE the committing shell carries, and nothing here controls that.
is_public_repo() {
  _n=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  while :; do
    case "$_n" in
      */) _n=${_n%/}; continue ;;
      *.git) _n=${_n%.git}; continue ;;
      *.wiki) _n=${_n%.wiki}; continue ;;
    esac
    break
  done
  case "$_n" in
    */mefororg/messagefoundry | *:mefororg/messagefoundry | mefororg/messagefoundry) return 0 ;;
  esac
  return 1
}

# A `while read` rather than `for`, so a URL containing whitespace is one candidate and not two.
printf '%s
' "$URLS" | while IFS= read -r _u; do
  [ -n "$_u" ] || continue
  is_public_repo "$_u" && exit 1
  :
done || {
  echo "durability_push: REFUSING -- mefor.durabilityRemote names the canonical PUBLIC repo." >&2
  echo "  A push there is publication, which is the gate this hook exists to avoid tripping." >&2
  echo "  Nominate a private remote instead, then re-commit." >&2
  exit 0
}

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

# --- preserve before the tag moves off a discarded tip ----------------------------------------
# THE TAG NAMES A BRANCH, NOT A COMMIT, SO EVERY COMMIT FORCE-MOVES IT. On an ordinary commit the
# old value is an ancestor of the new one and the move costs nothing. After a rebase, an amend or a
# reset it is NOT an ancestor, and the move used to make the discarded commits reachable from no ref
# on the remote at all -- silently, which is the whole reason this is worth code. The tag still
# existed, the push still succeeded, and the only thing that changed was what the tag covered.
#
# MEASURED 2026-09-20, in a throwaway repository with this hook installed rather than argued from
# this source. Two commits on a branch, a rebase onto a moved main, then one more commit. Before the
# rebase the tag peeled to the pre-rebase tip; after it, both pre-rebase commits were reachable from
# NO ref in the bare remote. The same query asked of the new tip named the tag, so the scan that
# returned "no coverage" was not simply a broken scan.
#
# SO THE VALUE ABOUT TO BE DISCARDED IS PUSHED SOMEWHERE IMMUTABLE FIRST.
# `refs/tags/rescue/orphan/<repo>/<branch>/<sha>` is keyed by the sha it holds, so it never needs to
# move -- and it is pushed WITHOUT --force, so a second attempt at the same name is refused by git
# rather than by hope and the first capture stands. It sits under `refs/tags/rescue/`, which is
# already what the fetch refspec collects and what `scripts/coord/rescue.ps1 -Check` audits, so
# nothing downstream needs teaching about it.
#
# WHAT THE OLD VALUE IS, AND WHY IT IS A LOCAL REF INSTEAD OF A REMOTE READ. `$LAST` holds the
# commit this hook last pushed for `$TAG`. Asking the remote instead would cost a network round trip
# on every commit and would still hand back only a sha -- and a sha is not enough, because the
# discarded commit has to still BE here to be pushed. A ref does both jobs at once: it answers
# offline, and it keeps the object reachable so the reflog's expiry cannot take the rescue with it.
#
# IT IS DELIBERATELY NOT UNDER refs/tags/. `git push --follow-tags` and `git push --tags` sweep
# refs/tags to whatever remote a hand reaches for, and the default one here is PUBLIC. That is the
# same hazard the provenance object above avoids by being pushed by id and never given a local tag,
# and a bookkeeping ref that reopened it would be a worse defect than the one this block closes.
#
# ONE SPAWN ON AN ORDINARY COMMIT, AND THE EXIT CODE IS READ RATHER THAN THE OUTPUT. `git merge-base
# --is-ancestor` exits 0 for an ancestor, 1 for a rewrite, and 128 when a name does not resolve.
# Measured on git 2.55.0.windows.5 across all three, including the two states that reach it here
# with nothing to compare: the first commit on a branch, where `$LAST` does not exist yet, and the
# degraded path above, where `$COMMIT` is empty. Both give 128, and only the 1 arm does further
# work -- so a rewrite pays three more spawns and every other commit pays one.
LAST="refs/mefor/durability/${TAG#refs/tags/rescue/auto/}"
KEEP=

git merge-base --is-ancestor "$LAST" "$COMMIT" >/dev/null 2>&1
ANCESTRY=$?

if [ "$ANCESTRY" -eq 1 ]; then
  PREV=$(git rev-parse --verify --quiet "$LAST^{commit}" 2>/dev/null)
  if [ -n "$PREV" ]; then
    # TWELVE CHARACTERS RATHER THAN `git rev-parse --short`. printf is a shell builtin, so it costs
    # no git spawn -- but the deciding reason is that git's abbreviation LENGTH grows with the
    # object count, so the same commit spells a different ref name on two different days. A name
    # relied on for immutability must not do that.
    ORPHAN="refs/tags/rescue/orphan/${TAG#refs/tags/rescue/auto/}/$(printf '%.12s' "$PREV")"
    ORPHANSRC="$PREV"

    if [ -n "$IDENT" ] && [ -n "$LABEL" ] && [ -n "$CAPTURED" ]; then
      # NO was-tip LINE, FOR THE REASON THE DETACHED CASE OMITS ONE. `was-tip` answers "was this the
      # branch tip at the moment it was captured", and this ref is captured precisely because it is
      # no longer the tip -- so False is literally true and reads as SHORT-AT-CAPTURE, "a partial
      # snapshot", which is the opposite of what a reader should conclude about the only remaining
      # copy of discarded work. True would be a straight falsehood. Omitting it gives
      # SELF-DESCRIBING, and `orphaned-by` then says the thing that actually drives a recovery
      # decision: which commit displaced this one.
      OMSG="mefor-rescue-v1
commit: $PREV
branch: $LABEL
captured: $CAPTURED
orphaned-by: $COMMIT
writer: durability_push.sh"
      OTAGOBJ=$(printf 'object %s\ntype commit\ntag %s\ntagger %s\n\n%s\n' \
        "$PREV" "${ORPHAN#refs/tags/}" "$IDENT" "$OMSG" \
        | git hash-object -t tag -w --stdin 2>/dev/null)
      # Same degradation rule as above: provenance is allowed to fail, durability is not. A bare
      # commit still reaches the remote and still holds the work.
      [ -n "$OTAGOBJ" ] && ORPHANSRC="$OTAGOBJ"
    fi

    KEEP="$ORPHANSRC:$ORPHAN"
  fi
fi

# Backgrounded and detached so the commit returns immediately. --force on the moving tag because it
# tracks a moving tip. Output is discarded: see "NEVER FAILS A COMMIT" above.
#
# PRESERVE, THEN DISCARD, AND THAT IS THE ONLY ORDER SAFE TO BE INTERRUPTED IN. Killed between the
# two pushes, the orphan is already on the remote and the moving tag is merely stale -- which the
# next commit repairs. The reverse order loses exactly the commits this block exists for. The orphan
# push's own result is deliberately not checked: a refusal there means the name is already taken by
# the capture this one would duplicate, and stopping on it would take the moving tag down too.
#
# $LAST IS UPDATED ONLY AFTER THE MOVING PUSH SUCCEEDS, so it keeps meaning "what the remote has"
# rather than "what was attempted". A commit made offline leaves it alone, and the first push that
# does land still preserves the right tip.
# EVERY OPERATION THAT CAN BLOCK INDEFINITELY IS BOUNDED. Today those are the two pushes, and the
# invariant is the rule -- the list is only today's reading of it. `git update-ref` below is left
# unbounded deliberately: it is a local ref write governed by core.filesRefLockTimeout and cannot
# wait on a network or on a person. Anything added here that talks to a remote -- a fetch, an
# ls-remote, a push --delete -- belongs inside the bound.
#
# WHY, MEASURED 2026-09-22 ON A DEVELOPER MACHINE. Eighteen `sh .git/hooks/post-commit` processes
# were alive across nine commits, the oldest 40 hours, three of them spinning -- 57 CPU-hours
# between them. Six `git commit` processes were still alive above them, so those commits had not
# returned in 40 hours either. Both hook names leak the same way; `post-merge` is this same file
# under another name, so a `git pull` loop reaches it too.
#
# THE BOUND DOES NOT EXPLAIN THAT LEAK AND MUST NOT BE READ AS ITS FIX. In every one of those repos
# the push had already SUCCEEDED -- the moving tag matched HEAD and `$LAST` had been written, which
# is this function's last statement. The work finished and the shells stayed anyway. That failure is
# unexplained and unfixed. Do not close it on the strength of this block.
#
# WHAT THE BOUND DOES FIX IS A SEPARATE AND REPRODUCIBLE MODE: a push that never finishes leaves
# these same shells alive forever. Reproduced on demand by pointing `core.sshCommand` at a sleep,
# which wedges the push offline, and pinned by tests/test_durability_hook_push_bound.py.
#
# A BOUND IS NOT A RETRY, AND IT MUST NOT BECOME ONE. A timed-out push simply did not land, so it
# falls through to the `$LAST` rule above and the next commit tries again -- the same path a commit
# made offline already takes.
#
# THE BOUND IS PER PUSH, SO THE WORST CASE IS NOT ITS VALUE. With an orphan capture to preserve, the
# fork can live 2 x (timeout + 10), about 620s at the default, before it goes.
#
# AND IT DOES NOT REACH GRANDCHILDREN. Measured on this platform: when the bound fired, `git push`
# and the transport helper it spawned both died, and the helper's OWN child survived and reparented.
# MSYS process-group emulation does not carry a group kill that far. Bounding the shells is the large
# majority of the harm measured above; the residue is real, and is named here rather than assumed
# away.
#
# INTERACTIVE PROMPTING IS OFF, BECAUSE A BACKGROUND PUSH HAS NOBODY TO ANSWER IT. A push that
# reaches a terminal credential prompt waits for input that cannot arrive, with no error recorded
# anywhere -- one concrete way a push "never finishes". This disables only the TERMINAL prompt;
# configured credential helpers still answer, so a properly provisioned remote is unaffected. It
# sits below every foreground git call in this file, so it scopes to the pushes.
GIT_TERMINAL_PROMPT=0
export GIT_TERMINAL_PROMPT

_durability_push() {
  # READ ON THIS SIDE OF THE FORK. Nothing above the background job needs either value, and this
  # hook's synchronous path is paid on every commit in every armed checkout -- a `git config` spawn
  # plus a PATH walk is about 65ms there and nothing here.
  #
  # `timeout` ships with Git for Windows and with coreutils. Where it is absent the push runs
  # unbounded rather than not at all: durability is the point of this hook, and it must not come to
  # depend on a helper being installed.
  _timeout=$(git config --get mefor.durabilityPushTimeout 2>/dev/null)
  case "$_timeout" in
    '' | *[!0-9]* | 0) _timeout=300 ;;
  esac
  if command -v timeout >/dev/null 2>&1; then
    # -k follows a declined TERM with a KILL, so a push wedged below the signal still goes.
    _bounded() { timeout -k 10 "$_timeout" "$@"; }
  else
    _bounded() { "$@"; }
  fi

  if [ -n "$KEEP" ]; then
    # A REFUSAL HERE IS FINE; A TIMEOUT IS NOT, AND THE ORDERING RULE ABOVE IS WHY. A refusal means
    # the name is already taken by the capture this one would duplicate, so the tip IS held and the
    # moving push may proceed -- that is the existing "deliberately not checked" reasoning, and it
    # stands. A TIMEOUT is a new kind of non-success with the opposite meaning: the capture did not
    # land, so moving the tag now discards exactly the commits it exists to preserve, and `$LAST`
    # would then advance past them. Stop instead and let the next commit repair it.
    # 124 is timeout's own exit code; 137 is the -k KILL landing.
    _bounded git push --quiet "$REMOTE" "$KEEP"
    case "$?" in
      124 | 137) return 1 ;;
    esac
  fi
  _bounded git push --quiet --force "$REMOTE" "$SRC:$TAG" || return 1
  [ -n "$COMMIT" ] || return 0
  git update-ref "$LAST" "$COMMIT"
}

( _durability_push >/dev/null 2>&1 & ) >/dev/null 2>&1

exit 0
