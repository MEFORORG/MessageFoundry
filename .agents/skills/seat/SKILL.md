---
name: seat
description: Use when the user types "/seat" or "/seat <name>", or literally writes "run the seat skill" / "use the seat skill". Do NOT trigger on paraphrased asks such as "what seat am I", "take the builder role", "who are you here", or "read your role card" - the user has deliberately scoped this to explicit invocation only. Answer those normally without loading this skill unless they name it.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill seat` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
