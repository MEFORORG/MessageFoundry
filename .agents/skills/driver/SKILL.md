---
name: driver
description: Adopt the Driver rules for the rest of this conversation - press forward proactively, and resolve anything that looks like an Owner decision through your own recommendation, then adversarial review, then AskUserQuestion (the Lander and Watchdog seats are exempt from that last step and nag in a table instead). Changes nothing on disk. ONLY use this skill when the user explicitly invokes it by name - they type "/driver", or literally write "run the driver skill" / "use driver". Do NOT trigger it on paraphrased asks such as "be proactive", "keep going", "stop asking me", "use your judgment", or "just decide" - answer those normally without loading this skill unless they name it.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill driver` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
