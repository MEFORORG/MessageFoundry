---
name: "fleet-read-a-ref-or-pipeline"
description: "Write a shell pipeline, or read a git ref, dot-path or history. Use before trusting an exit code, a grep count, or a read that may have failed silently."
user-invocable: true
disable-model-invocation: false
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill fleet-read-a-ref-or-pipeline` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
