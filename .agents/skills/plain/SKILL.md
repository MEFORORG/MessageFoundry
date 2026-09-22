---
name: plain
description: Write in the Plain style - short, direct answers in plain English - for the rest of this conversation. Changes nothing on disk. ONLY use this skill when the user explicitly invokes it by name - they type "/plain", or literally write "run the plain skill" / "use the plain style". Do NOT trigger it on paraphrased asks such as "keep it short", "be brief", "simplify this", "plain English please", or "write this more clearly" - answer those normally. For rewriting an existing document down to a lower reading level, use the plain-writing skill instead; this skill changes how Claude replies, not how a document reads.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill plain` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
