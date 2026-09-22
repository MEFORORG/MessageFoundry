---
name: batch
effort: ultracode
description: Read one numbered batch out of the MEFOR backlog runbook, verify its rows against the code and the merged pull requests, then dispatch builders for it. ONLY use this skill when the user explicitly invokes it - they type "/batch ##", or they literally ask to run a batch or dispatch builders for a batch number. Do NOT trigger it on paraphrased asks such as "what is next", "pick up some backlog work", "dispatch a builder", "what is in batch 60", or "how is the backlog going" - a read about state is not a dispatch, and this skill spawns builders. The user has deliberately scoped it to explicit invocation only.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill batch` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
