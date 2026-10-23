#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#
# SessionStart setup for a Claude Code CLOUD session. A no-op everywhere else.
#
# WHY THIS IS IN THE REPOSITORY AND NOT IN A CLOUD ENVIRONMENT'S SETUP SCRIPT. A setup script lives
# in one claude.ai account's environment settings, entered by hand in the UI, and this project's
# sessions run under several separate accounts. The repository's .claude/settings.json is the one
# thing every cloud session clones, so a hook wired there covers every account with no per-account
# step. The cost is that it runs on every session start, not once per cached image. Measured on a
# probe session on 2026-10-19 (MEFORORG/MessageFoundry PR 2432): the pwsh install took 17 s and the
# Python 3.14 install 3 s, and both are skipped once present.
#
# WHAT A CLOUD SESSION LACKS, AND WHAT THAT COSTS. The image ships no pwsh, so every other hook in
# .claude/settings.json fails to start. A hook that cannot start is a non-blocking error, so the
# blanket-stage, API-burn and filesystem-scan guards are OFF while the tool calls run. The image's
# default Python is 3.13 and the project requires 3.14. Its commits are made as an identity the
# required `cla` check refuses (wiki note 20261002T125230275Z-0glfkb, PR 1926). And it is a fresh
# clone, so none of the repository's git hooks are installed: every commit skipped the claim gate,
# the ledger gate and the leak gate, and a Builder could only run them by hand.
#
# LOUD, NEVER BLOCKING. Each failure prints a line naming what is now off, and the hook still exits
# 0: a SessionStart hook cannot stop a session, and a non-zero exit would only hide this output.
#
# ONE OTHER MODE, RUN BY HAND: `bash scripts/hooks/cloud-setup.sh --arm-pre-commit` arms the
# pre-commit hooks and does nothing else. It is not a hook, so it exits 1 whenever nothing was armed.
#
# THE GATE IS ALSO INLINE IN settings.json, so a local session never reads this file. The check
# here is the second copy, for anyone who runs the file by hand.

arm=0
case "${1:-}" in
    "") ;;
    --arm-pre-commit) arm=1 ;;
    *)
        echo "usage: cloud-setup.sh [--arm-pre-commit]" >&2
        exit 2
        ;;
esac

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    [ "$arm" = 0 ] || echo "cloud-setup.sh --arm-pre-commit: for cloud sessions only (CLAUDE_CODE_REMOTE=true); nothing was armed." >&2
    exit "$arm"
fi

say() { printf '[cloud-setup] %s\n' "$*"; }

root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null)}"
if [ -z "$root" ] || [ ! -f "$root/pyproject.toml" ]; then
    say "NOT RUN: no checkout found (CLAUDE_PROJECT_DIR='${CLAUDE_PROJECT_DIR:-}'). Every repo guard is OFF in this session."
    exit "$arm"
fi
cd "$root" || exit "$arm"

# Run a step with its output kept out of the context unless it fails.
quiet() {
    local log
    log="$(mktemp)"
    if "$@" >"$log" 2>&1; then rm -f "$log"; return 0; fi
    tail -n 5 "$log" | sed 's/^/[cloud-setup]   /'
    rm -f "$log"
    return 1
}

# THE PRE-COMMIT HOOKS: the ledger gate, the leak gate and the linters in .pre-commit-config.yaml. A
# session start only checks and reports on them. They are armed by hand, before the first commit,
# with `bash scripts/hooks/cloud-setup.sh --arm-pre-commit`, for two reasons. Arming builds every
# hook environment, and gitleaks and actionlint compile Go, which can take minutes; the venv note
# below says what a hook that reaches its timeout loses. And the shim goes in only once they have all
# built, because it refuses every commit while one of its hooks cannot start.

python_ok() { python -c 'import sys; sys.exit(sys.version_info < (3, 14))' >/dev/null 2>&1; }

# $1 says why; $2, when given, says how to turn the hooks on.
pre_commit_off() {
    say "PRE-COMMIT HOOKS NOT INSTALLED: $1. Every hook in .pre-commit-config.yaml is OFF, the ledger gate and the leak gate among them.${2:+ $2}"
}

# Can the hooks start here? Every local hook runs `python`. The leak gate runs with --require-tokens,
# which without a full token source refuses any commit that stages a text file. The scanner answers
# that itself, asked as the hook asks it but over an empty file, so a hit cannot pass for a refusal.
pre_commit_can_run() {
    if ! python_ok; then
        pre_commit_off "python does not run Python 3.14, and the local hooks run python"
        return 1
    fi
    local empty ok=0
    empty="$(mktemp)"
    quiet python scripts/security/scan_forbidden.py --require-tokens "$empty" || ok=1
    rm -f "$empty"
    if [ "$ok" != 0 ]; then
        pre_commit_off "the leak gate's scanner refuses to run here, as its output above says, so the leak gate would refuse any commit that stages a text file" \
            "Without a token source, set MEFOR_FORBIDDEN_TOKENS on the cloud environment."
        return 1
    fi
    # The shipped example passes that check and matches nothing real, so a pass on it is no scan.
    if python scripts/security/scan_forbidden.py --print-detector-counts 2>/dev/null | grep -qx 'mode=synthetic'; then
        say "WARNING: the leak gate's tokens are the shipped synthetic example, so it is blind to every real customer token. Only CI's leak gate sees them."
    fi
}

pre_commit_armed() { grep -qs 'File generated by pre-commit' "$(git rev-parse --git-path hooks/pre-commit)"; }

# The framework is a uv tool, as on the local primary checkout, so the shim pins the tool's own
# interpreter rather than a venv that can be deleted. The version is the one measured there.
arm_pre_commit() {
    pre_commit_can_run || return 1
    if ! quiet uv tool install pre-commit==4.7.0; then
        pre_commit_off "uv tool install pre-commit==4.7.0 failed"
        return 1
    fi
    local pc
    pc="$(uv tool dir --bin 2>/dev/null)/pre-commit"
    if [ ! -x "$pc" ]; then
        pre_commit_off "uv installed pre-commit, but there is no executable at '$pc'"
        return 1
    fi
    # Not quiet: this is the step that takes minutes, so its progress is worth seeing.
    if ! "$pc" install-hooks; then
        pre_commit_off "a hook environment did not build, as the pre-commit output above says"
        return 1
    fi
    if ! quiet "$pc" install; then
        pre_commit_off "pre-commit install failed"
        return 1
    fi
    say "pre-commit hooks installed: the hooks in .pre-commit-config.yaml now run on each commit."
}

if [ "$arm" = 1 ]; then
    arm_pre_commit || exit 1
    exit 0
fi

# At VM boot another process can hold an apt or dpkg lock: on 2026-10-21 a bare `dpkg -i` lost to
# pid 280 and pwsh never installed. So the install waits out a held lock instead of failing, from
# ONE budget shared by its apt-get calls, because per-call waits could add up past the hook's
# timeout in .claude/settings.json (see the venv note below for what a timeout costs).
lock_wait=120

# Seconds left before the deadline $1, a value of $SECONDS; never negative.
lock_left() {
    local left=$(($1 - SECONDS))
    echo $((left > 0 ? left : 0))
}

# apt-get, waiting out a held lock for whatever the budget has left. DPkg::Lock::Timeout covers
# dpkg's locks; apt is not relied on to wait for the package-lists lock (`update`) or the archives
# lock (`install`), so a run whose output names a held lock is retried until the deadline. Any
# other failure returns at once. LC_ALL=C keeps that message in the English the grep matches, and
# stdin is closed because the hook's stdin carries the SessionStart JSON, not answers for dpkg.
apt_wait() {
    local deadline=$1 out rc
    shift
    while :; do
        out="$(DEBIAN_FRONTEND=noninteractive LC_ALL=C apt-get -o DPkg::Lock::Timeout="$(lock_left "$deadline")" "$@" </dev/null 2>&1)"
        rc=$?
        if [ "$rc" = 0 ] || ! grep -q 'Could not get lock' <<<"$out" || [ "$(lock_left "$deadline")" = 0 ]; then
            break
        fi
        sleep 2
    done
    printf '%s\n' "$out"
    return "$rc"
}

install_pwsh() {
    local deb deadline=$((SECONDS + lock_wait))
    deb="$(mktemp --suffix=.deb)"
    # packages.microsoft.com is on the cloud environment's default Trusted allowlist. The .deb goes
    # through apt-get, not dpkg -i, because dpkg cannot wait for its lock; apt-get reads an argument
    # as a file only when it contains a slash, and mktemp's path is absolute. --reinstall keeps
    # dpkg -i's re-laying of an already-installed copy. curl is time-bounded like the lock waits.
    curl -fsSL --connect-timeout 20 --max-time 60 -o "$deb" \
        https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb &&
        apt_wait "$deadline" install -y -qq --reinstall "$deb" &&
        apt_wait "$deadline" update -qq &&
        apt_wait "$deadline" install -y -qq powershell
    local rc=$?
    rm -f "$deb"
    return $rc
}

pwsh_new=0
if command -v pwsh >/dev/null 2>&1; then
    :
elif quiet install_pwsh && command -v pwsh >/dev/null 2>&1; then
    pwsh_new=1
    say "installed pwsh $(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>/dev/null)"
else
    say "PWSH INSTALL FAILED. Every hook in .claude/settings.json fails to start in this session, so the git-stage, API-burn and fs-scan guards are OFF. Do not run git add -A or a gh polling loop."
fi

py=""
if quiet uv python install 3.14; then
    # --system, so the answer is never a venv, active or in this checkout: the link made below has to
    # outlive any venv.
    py="$(uv python find --system 3.14 2>/dev/null)"
fi
if [ -z "$py" ]; then
    say "PYTHON 3.14 INSTALL FAILED. The project requires 3.14; pytest and mypy will not run."
fi

# The git hooks run `python`: every local hook in .pre-commit-config.yaml names it, and the claim
# gate and push guard try it before python3. A stock Ubuntu image has no `python`, so give it this
# 3.14 wherever `python` does not already run 3.14 or later.
python_dir=/usr/local/bin

# Link $python_dir/python to the interpreter $1; that directory comes before /usr/bin on the image's
# PATH. ln without -f never replaces a file, and a link that does not help is removed again. A link
# whose interpreter has since gone is replaced, or it would block every later start.
ensure_python() {
    python_ok && return 0
    # No interpreter to link: PYTHON 3.14 INSTALL FAILED above already says so.
    [ -n "$1" ] || return 1
    if [ -L "$python_dir/python" ] && [ ! -e "$python_dir/python" ]; then
        rm -f "$python_dir/python"
    fi
    if ln -s "$1" "$python_dir/python" 2>/dev/null; then
        hash -r
        if python_ok; then
            say "linked $python_dir/python to $1, because the git hooks run python"
            return 0
        fi
        rm -f "$python_dir/python"
    fi
    say "PYTHON NOT LINKED: python does not run 3.14 here, and a link at $python_dir/python to $1 could not be made or is shadowed on PATH. The git hooks run an older python, or none."
    return 1
}

ensure_python "$py"

# The default cloud identity is not a GitHub account, so the required `cla` check refuses it. Commit
# as the GitHub account this session pushes as, through its noreply address: never a fixed name, so
# whoever runs the session is who the commits and the cla check name. Set for this clone only.
gh_user="$(gh api user --jq '"\(.id)\t\(.login)\t\(.name // .login)"' 2>/dev/null)"
if [ -n "$gh_user" ]; then
    IFS=$'\t' read -r gh_id gh_login gh_name <<<"$gh_user"
    git config user.name "$gh_name"
    git config user.email "${gh_id}+${gh_login}@users.noreply.github.com"
else
    say "git identity left as the session set it: gh api user failed. The cla check will refuse these commits."
fi

# THE GIT HOOKS A LOCAL CLONE HAS. scripts/coord/install-git-hooks.ps1 writes the claim gate
# (commit-msg), the push guard (pre-push) and the durability hook, and needs no venv. The durability
# hook stays inert here: it pushes only to a remote named by mefor.durabilityRemote, and nothing
# sets one.
#
# ONCE PER CLONE. The installer copies the gates from the checkout it runs in, so it must not run
# again on a resume or compact: by then the branch may carry a Builder's own edit to a gate, and the
# commits that edit makes would be checked by the edited copy. So an installed claim gate skips it.
git_hooks_off() {
    say "GIT HOOKS NOT INSTALLED: $1, so the claim gate (commit-msg) and the push guard (pre-push) are OFF.${2:+ $2}"
}

if grep -qs 'MessageFoundry claim gate' "$(git rev-parse --git-path hooks/commit-msg)"; then
    :
elif ! command -v pwsh >/dev/null 2>&1; then
    git_hooks_off "no pwsh to run scripts/coord/install-git-hooks.ps1"
elif ! quiet pwsh -NoProfile -NonInteractive -File scripts/coord/install-git-hooks.ps1 </dev/null; then
    git_hooks_off "scripts/coord/install-git-hooks.ps1 failed" \
        "Fix what its output above names, then run: pwsh -NoProfile -File scripts/coord/install-git-hooks.ps1"
fi

# The pre-commit hooks are only reported on here; arm_pre_commit above says why.
if ! pre_commit_armed && pre_commit_can_run; then
    pre_commit_off "a session start does not build their environments, which can take minutes" \
        "Before your first commit, run: bash scripts/hooks/cloud-setup.sh --arm-pre-commit (with a 10-minute timeout, or in the background: the Bash tool stops a command at 2 minutes by default)"
fi

# The venv is NOT built here. A full install runs for minutes, and a hook that reaches its timeout
# loses all of its output, including the warnings above. Build it as the first step of the work.
if [ -n "$py" ] && [ ! -x .venv/bin/python ]; then
    if command -v pwsh >/dev/null 2>&1; then
        say "no venv yet. Before running checks: pwsh -NoProfile -File scripts/worktree/ensure-venv.ps1 -Python '$py'"
    else
        say "no venv yet, and no pwsh to run scripts/worktree/ensure-venv.ps1. Before running checks: '$py' -m venv .venv, then .venv/bin/python -m pip install with that script's install line."
    fi
fi

# Hooks for one event start together, so on a fresh VM the role-card hook ran before pwsh existed
# and injected nothing. Run it again only then; on a resumed VM it already ran and would repeat.
# It resolves the seat itself (KORUS_SEAT, set on the cloud environment); nothing here supplies one.
if [ "$pwsh_new" = 1 ]; then
    pwsh -NoProfile -NonInteractive -File scripts/hooks/role-card-inject.ps1 -WorktreeRoot "$root" </dev/null
fi

say "cloud session. No seat registry, mail or ADR allocation reaches the local fleet from here; open the PR with gh api -X POST repos/MEFORORG/MessageFoundry/pulls, because gh pr is refused (GraphQL)."
exit 0
