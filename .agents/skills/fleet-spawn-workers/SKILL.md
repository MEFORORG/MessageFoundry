---
name: "fleet-spawn-workers"
description: "Spawn workers or create a Workflow. Use before any fan-out, including sizing it."
user-invocable: true
disable-model-invocation: false
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill fleet-spawn-workers` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
