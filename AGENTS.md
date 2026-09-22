# Codex uses the current Claude Code sources

Read [CLAUDE.md](CLAUDE.md) before starting work. It is the authoritative,
current repo guide for both Claude Code and Codex. Do not keep a second copy here.
Read any applicable package-level CLAUDE.md as well as package-level AGENTS.md.

Read [docs/CODEX.md](docs/CODEX.md) for Codex transport and session identity.
That page describes host differences; it does not replace the repo's rules.

Use the current scripts, checks, and gates referenced by CLAUDE.md. Claude's
`.claude/settings.json` supplies repo hook policy through the Codex bridge.
Never edit Claude settings, credentials, or session markers to configure Codex.

When a repo skill applies, read its current `.claude/skills/<name>/SKILL.md`.
The entries under `.agents/skills/` are discovery pointers only. If a requested
skill is not listed there, check `.claude/skills/` before reporting it missing.
Resolve linked resources from the source skill's directory.
Also check Claude's user-level skills through
`scripts/codex/invoke.ps1 source-skill <name>`. Repo names take precedence.
Treat an explicit `$<name>` Codex invocation as the source's `/<name>` invocation.

Use native Codex task and usage tools for Codex identity, liveness, and usage.
Claude account and process readings do not describe Codex. Run seat declarations
through `scripts/codex/invoke.ps1 run scripts/coord/seat.ps1` so they cannot
replace a Claude marker. Do not infer your seat from a Claude session here.
