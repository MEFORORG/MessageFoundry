---
name: carry-on
description: Take over the fleet seat this session is named for, and resume that seat's work from its role playbook and handoff. ONLY use this skill when the user explicitly invokes it by name - they type "/carry-on" or literally write "run carry-on" / "use the carry-on skill". Do NOT trigger it on paraphrased asks such as "pick up where we left off", "resume the work", "what was I doing", or "read the handoff" - the user has deliberately scoped this skill to explicit invocation only.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill carry-on` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
