---
name: e2e-smoke
description: Run the engine end to end - start a real `serve` on the sample config, send one synthetic ADT over MLLP, assert an AA or CA ACK and the PROCESSED disposition through the API. Use before committing a change to messagefoundry/pipeline/, transports/, parsing/, store/ or config/, or whenever unit tests pass but you need proof the running engine still moves a message.
---

<!-- codex-claude-skill-pointer -->

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill e2e-smoke` from the repo root, then read the returned file before doing this task. That file is authoritative; do not copy its procedure here.

Resolve its linked resources relative to its source directory. Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. Use this Codex task's identity, never Claude's session files.
