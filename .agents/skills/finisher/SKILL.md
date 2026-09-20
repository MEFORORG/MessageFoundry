---
name: finisher
description: Close out the current session - finish anything still outstanding, print a table of what is left, then hand off to the wrapup skill and report "safe to archive" in bold. ONLY use this skill when the user explicitly invokes it by name - they type "/finisher", or literally write "run finisher" / "use the finisher skill", or send the standing closeout prompt "Anything left to do here? If yes, be proactive and get it done, and also print a table showing what is left to do. If there is nothing left to do, run /wrapup and report safe to archive in bold as the last thing you print". Do NOT trigger it on paraphrased asks such as "are we done?", "anything else?", "can I close this?", "wrap it up", or "is that everything?" - the user has deliberately scoped this skill to explicit invocation only. Answer those normally without loading this skill unless they name it.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill finisher` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
