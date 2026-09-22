---
name: "fleet-push-or-open-a-pr"
description: "Push a branch, open a pull request, or touch CI or the merge queue. Use before the push and before anything that reads a check result."
user-invocable: true
disable-model-invocation: false
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill fleet-push-or-open-a-pr` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
