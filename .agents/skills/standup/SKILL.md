---
name: standup
description: Report where the current conversation session stands, as two tables - work sorted into completed, in flight, and to do, plus anything blocking progress. ONLY use this skill when the user explicitly invokes it by name - they type "/standup" or literally write "run the standup skill" / "give me a standup". Do NOT trigger it on paraphrased asks such as "what's the status", "where are we", "what's left", "recap what you did", or "any blockers?" - the user has deliberately scoped this skill to explicit invocation only. Answer those normally without loading this skill unless they name it.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill standup` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
