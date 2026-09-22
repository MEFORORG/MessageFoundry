---
name: respawn-fleet
description: Detect which fleet seats died together after an account switch or a desktop-app restart, then spawn one replacement session per seat from its own measured briefing. ONLY use this skill when the user explicitly invokes it - they type "/respawn-fleet", or they literally ask to respawn, re-spawn, restart or replace the fleet, the team, or the dead seats. Do NOT trigger it on paraphrased asks such as "what was everyone doing", "who died", "check the fleet", "read the handoffs", or "what is the status" - those ask about state, and this skill spawns sessions. The user has deliberately scoped it to explicit invocation only.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill respawn-fleet` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
