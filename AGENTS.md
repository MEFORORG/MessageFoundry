# Codex uses the current Claude Code sources

Read [CLAUDE.md](CLAUDE.md) before starting work. It is the authoritative,
current repo guide for both Claude Code and Codex. Do not keep a second copy here.
Read any applicable package-level CLAUDE.md as well as package-level AGENTS.md.

Read [docs/CODEX.md](docs/CODEX.md) for Codex transport and session identity.
That page describes host differences; it does not replace the repo's rules.

Use the current scripts, checks, and gates referenced by CLAUDE.md. Claude's
`.claude/settings.json` supplies repo hook policy through the Codex bridge.
Never edit Claude settings, credentials, or session markers to configure Codex.

When a repo skill applies, read its current source `SKILL.md`, which
`scripts/codex/invoke.ps1 source-skill <name>` prints. The entries under
`.agents/skills/` are discovery pointers only; run `source-skill` before
reporting a skill missing. It reads this checkout's `.claude/skills/`, then the
primary checkout's, which git does not carry into a linked worktree (all but
`e2e-smoke`), then
Claude's user-level skills; the first that holds the name wins.
Resolve linked resources from the source skill's directory.
Treat an explicit `$<name>` Codex invocation as the source's `/<name>` invocation.

Use native Codex task and usage tools for Codex identity, liveness, and usage.
Claude account and process readings do not describe Codex. Run seat declarations
through `scripts/codex/invoke.ps1 run scripts/coord/seat.ps1` so they cannot
replace a Claude marker. Do not infer your seat from a Claude session here.
