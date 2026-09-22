---
name: concise
description: Write in the Concise style - terse replies that lead with the result and skip preamble and narration - for the rest of this conversation. Changes nothing on disk. ONLY use this skill when the user explicitly invokes it by name - they type "/concise", or literally write "run the concise skill" / "use the concise style". Do NOT trigger it on paraphrased asks such as "be brief", "shorter please", "cut the preamble", "less narration", or "keep it tight" - answer those normally without loading this skill unless they name it.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill concise` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
