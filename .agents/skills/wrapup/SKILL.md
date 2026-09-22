---
name: wrapup
description: Close out the current session - find anything still outstanding, finish it proactively, then verify nothing would be lost and report "safe to archive". If anything remains for the user to do or consider, put that in a table at the end. ONLY use this skill when the user explicitly invokes it by name - they type "/wrapup", or literally write "run wrapup" / "use the wrapup skill", or send the standing closeout prompt "Anything left to do here? If yes, be proactive and get it done. If not, clean up and report safe to archive". Do NOT trigger it on paraphrased asks such as "are we done?", "anything else?", "can I close this?", "wrap it up", or "is that everything?" - the user has deliberately scoped this skill to explicit invocation only. Answer those normally without loading this skill unless they name it.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill wrapup` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
