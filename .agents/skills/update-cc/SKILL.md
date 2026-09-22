---
name: update-cc
description: Update the Claude Desktop app on this machine while the disableAutoUpdates policy blocks the in-app update path. Use when the user types "/update-cc", asks to update Claude Desktop or "the desktop app", or reports the banner "Claude <model> needs the latest desktop app to run on this computer" with a dead Update link, or a missing Help > Check for Updates. Do NOT use for updating the Claude Code CLI, npm packages, or project dependencies.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill update-cc` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
