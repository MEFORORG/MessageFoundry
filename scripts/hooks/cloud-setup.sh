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
# required `cla` check refuses (wiki note 20261002T125230275Z-0glfkb, PR 1926).
#
# LOUD, NEVER BLOCKING. Each failure prints a line naming what is now off, and the hook still exits
# 0: a SessionStart hook cannot stop a session, and a non-zero exit would only hide this output.
#
# THE GATE IS ALSO INLINE IN settings.json, so a local session never reads this file. The check
# here is the second copy, for anyone who runs the file by hand.

[ "${CLAUDE_CODE_REMOTE:-}" = "true" ] || exit 0

say() { printf '[cloud-setup] %s\n' "$*"; }

root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null)}"
if [ -z "$root" ] || [ ! -f "$root/pyproject.toml" ]; then
    say "NOT RUN: no checkout found (CLAUDE_PROJECT_DIR='${CLAUDE_PROJECT_DIR:-}'). Every repo guard is OFF in this session."
    exit 0
fi
cd "$root" || exit 0

# Run a step with its output kept out of the context unless it fails.
quiet() {
    local log
    log="$(mktemp)"
    if "$@" >"$log" 2>&1; then rm -f "$log"; return 0; fi
    tail -n 5 "$log" | sed 's/^/[cloud-setup]   /'
    rm -f "$log"
    return 1
}

install_pwsh() {
    local deb
    deb="$(mktemp --suffix=.deb)"
    # packages.microsoft.com is on the cloud environment's default Trusted allowlist.
    curl -fsSL https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -o "$deb" &&
        dpkg -i "$deb" &&
        apt-get update -qq &&
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq powershell
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
    py="$(uv python find 3.14 2>/dev/null)"
fi
if [ -z "$py" ]; then
    say "PYTHON 3.14 INSTALL FAILED. The project requires 3.14; pytest and mypy will not run."
fi

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
