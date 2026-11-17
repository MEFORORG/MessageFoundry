# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Codex transport for the current Claude Code repo hooks and scripts.

No hook policy is copied here. Read .claude/settings.json for every event.
Account-level Claude settings, credentials and permissions are not imported.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVENTS = (
    "SessionStart",
    "SessionEnd",
    "PreToolUse",
    "PostToolUse",
    "PermissionRequest",
    "UserPromptSubmit",
    "PreCompact",
    "PostCompact",
    "Stop",
    "SubagentStart",
    "SubagentStop",
)
POINTER_MARKER = "<!-- codex-claude-skill-pointer -->"


def user_skill_directory() -> Path:
    config_root = os.environ.get("CLAUDE_CONFIG_DIR")
    return (Path(config_root) if config_root else Path.home() / ".claude") / "skills"


def source_skill(root: Path, name: str, *, user_skills: Path | None = None) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError("Skill name must be a single directory name")
    for directory in (root / ".claude/skills", user_skills or user_skill_directory()):
        source = directory / name / "SKILL.md"
        if source.is_file():
            return source
    raise FileNotFoundError(f"Claude skill source not found: {name}")


def sync_skills(
    root: Path, *, migrate_copies: bool = False, user_skills: Path | None = None
) -> list[str]:
    """Refresh discovery metadata; keep procedure text solely in the Claude source."""
    sources_by_name = {}
    if user_skills is not None:
        sources_by_name.update((path.parent.name, path) for path in user_skills.glob("*/SKILL.md"))
    sources_by_name.update(
        (path.parent.name, path) for path in (root / ".claude/skills").glob("*/SKILL.md")
    )
    sources = [sources_by_name[name] for name in sorted(sources_by_name)]
    if not sources:
        raise FileNotFoundError("No skill sources found under .claude/skills")
    messages = []
    for source in sources:
        body = source.read_text(encoding="utf-8-sig")
        match = re.match(r"\A---\s*\n.*?\n---(?:\s*\n|$)", body, re.DOTALL)
        if not match:
            raise ValueError(f"Missing skill frontmatter: {source}")
        target = root / ".agents/skills" / source.parent.name / "SKILL.md"
        if target.exists():
            old = target.read_text(encoding="utf-8-sig")
            if POINTER_MARKER not in old:
                if not migrate_copies:
                    messages.append(
                        f"Unrelated or old skill left alone: {target.relative_to(root)}"
                    )
                    continue
                backup = root / ".codex/migration-backup" / target.relative_to(root)
                backup.parent.mkdir(parents=True, exist_ok=True)
                if not backup.exists():
                    backup.write_bytes(target.read_bytes())
        # Never a markdown link into .claude/skills/: .gitignore keeps everything under .claude/
        # except settings.json out of git, so such a link dangles in every other clone and fails
        # tests/test_link_resolution.py. source_skill() applies the repo-first precedence at run time.
        pointer = (
            match[0].rstrip()
            + "\n\n"
            + POINTER_MARKER
            + "\n\n"
            + f"Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 source-skill {source.parent.name}` "
            "from the repo root, then read the returned file "
            "before doing this task. That file is authoritative; do not copy its procedure here.\n\n"
            "Resolve its linked resources relative to its source directory. "
            "Read [the Codex transport notes](../../../docs/CODEX.md) for host-specific differences. "
            "Use this Codex task's identity, never Claude's session files.\n"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_text(encoding="utf-8-sig") != pointer:
            target.write_text(pointer, encoding="utf-8")
        source_label = source.relative_to(root) if source.is_relative_to(root) else source
        messages.append(f"Pointer: {target.relative_to(root)} -> {source_label}")
    for target in (root / ".agents/skills").glob("*/SKILL.md"):
        if POINTER_MARKER not in target.read_text(encoding="utf-8-sig"):
            continue
        # The invocation-time resolver decides. A repo-only refresh did not enumerate user-level
        # sources, so it falls back to the default user directory exactly as an invocation would.
        try:
            source_skill(root, target.parent.name, user_skills=user_skills)
        except (FileNotFoundError, ValueError):
            messages.append(
                f"MISSING SOURCE: {target.relative_to(root)}; remove or rename this pointer"
            )
    return messages


def child_environment(root: Path, session_id: str) -> dict[str, str]:
    if not session_id:
        raise ValueError("Codex session id missing; pass --session-id or set CODEX_THREAD_ID")
    env = os.environ.copy()
    # These describe a Claude process/account. Never borrow a parent's identity.
    for name in tuple(env):
        if name.startswith("CLAUDE_") or name == "KORUS_SEAT":
            env.pop(name)
    env.update(
        KORUS_AGENT="codex",
        KORUS_SESSION_ID=session_id,
        KORUS_STATE_REL=".codex/sessions/"
        + base64.urlsafe_b64encode(session_id.encode()).decode().rstrip("="),
        CLAUDE_PROJECT_DIR=str(root),  # Path compatibility only, in this child process.
        PYTHONIOENCODING="utf-8",
    )
    return env


def merge_output(result: dict, update: dict) -> None:
    """Keep the strongest decision and all context across matching handlers."""
    for key in ("systemMessage", "stopReason", "reason"):
        if update.get(key):
            result[key] = "\n".join(filter(None, (result.get(key), update[key])))
    if update.get("continue") is False:
        result["continue"] = False
    if update.get("decision") == "block":
        result["decision"] = "block"
    if update.get("hookSpecificOutput"):
        target = result.setdefault("hookSpecificOutput", {})
        source = update["hookSpecificOutput"]
        for key, value in source.items():
            if key == "additionalContext":
                target[key] = "\n".join(filter(None, (target.get(key), value)))
            elif key not in ("permissionDecision", "permissionDecisionReason"):
                target[key] = value
        ranks = {None: 0, "allow": 1, "ask": 2, "deny": 3}
        if ranks.get(source.get("permissionDecision"), 0) > ranks.get(
            target.get("permissionDecision"), 0
        ):
            target["permissionDecision"] = source["permissionDecision"]
            if "permissionDecisionReason" in source:
                target["permissionDecisionReason"] = source["permissionDecisionReason"]


def dispatch(root: Path, payload: dict) -> dict:
    event = payload["hook_event_name"]
    env = child_environment(root, payload.get("session_id", ""))
    config = json.loads((root / ".claude/settings.json").read_text(encoding="utf-8-sig"))
    if config.get("disableAllHooks"):
        return {}
    result: dict = {}
    if event == "SessionStart":
        unknown = set(config.get("hooks", {})) - set(EVENTS)
        context = (
            "Read CLAUDE.md now; it is the current repo authority. "
            "Read docs/CODEX.md for the Codex transport. "
            "Run identity-sensitive scripts through scripts/codex/invoke.ps1 run. "
            f"This Codex session id is {payload['session_id']}. "
            "Claude account usage and process-liveness tools do not measure Codex; "
            "use native Codex usage and task tools for those readings."
        )
        if unknown:
            context += " Unmapped Claude hook events need an adapter: " + ", ".join(sorted(unknown))
        merge_output(
            result, {"hookSpecificOutput": {"hookEventName": event, "additionalContext": context}}
        )
    aliases = {str(payload.get("tool_name", ""))}
    if "Bash" in aliases:
        aliases.add("PowerShell")
    if "apply_patch" in aliases:
        aliases.update(("Edit", "Write"))
    discriminator = (
        aliases
        if event in ("PreToolUse", "PostToolUse", "PermissionRequest")
        else {
            str(
                payload.get(
                    "source",
                    payload.get("trigger", payload.get("agent_type", payload.get("reason", ""))),
                )
            )
        }
    )
    for group in config.get("hooks", {}).get(event, []):
        matcher = group.get("matcher", "")
        if matcher not in ("", "*") and not any(
            re.search(matcher, value) for value in discriminator
        ):
            continue
        for hook in group.get("hooks", []):
            if hook.get("type") != "command" or hook.get("async"):
                raise ValueError(
                    f"Unsupported Claude hook transport: {hook.get('type')}, async={hook.get('async', False)}"
                )
            command = hook["command"]
            if "args" in hook:
                argv = [
                    command,
                    *[str(arg).replace("${CLAUDE_PROJECT_DIR}", str(root)) for arg in hook["args"]],
                ]
            else:
                # Command-only sources use the current platform's shell. Environment expansion
                # belongs to that shell; structured args above need no shell parsing.
                command = command.replace(
                    "${CLAUDE_PROJECT_DIR}",
                    "$env:CLAUDE_PROJECT_DIR" if os.name == "nt" else "${CLAUDE_PROJECT_DIR}",
                )
                argv = (
                    ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command]
                    if os.name == "nt"
                    else ["sh", "-c", command]
                )
            completed = subprocess.run(  # nosec B603 - trusted repo hook; event data is stdin only
                argv,
                input=json.dumps(payload),
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=hook.get("timeout", 30),
                check=False,
            )
            if completed.stderr:
                print(completed.stderr, file=sys.stderr, end="")
            if completed.returncode == 2:
                raise PermissionError(completed.stderr or "Claude hook blocked this event")
            completed.check_returncode()
            output = completed.stdout.strip()
            if not output:
                continue
            try:
                update = json.loads(output)
            except json.JSONDecodeError:
                if event != "SessionStart":
                    print(output, file=sys.stderr)
                    continue
                output = output.replace(
                    "scripts\\coord\\seat.ps1",
                    "scripts\\codex\\invoke.ps1 run scripts/coord/seat.ps1",
                )
                update = {
                    "hookSpecificOutput": {"hookEventName": event, "additionalContext": output}
                }
            if not isinstance(update, dict):
                raise ValueError("Hook JSON output must be an object")
            merge_output(result, update)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("hook", "run", "doctor", "sync-skills", "source-skill", "state-dir")
    )
    parser.add_argument("--session-id", default=os.environ.get("CODEX_THREAD_ID", ""))
    parser.add_argument("--migrate-copies", action="store_true")
    parser.add_argument("--include-user-skills", action="store_true")
    args, rest = parser.parse_known_args()
    if args.mode == "sync-skills":
        user_skills = user_skill_directory() if args.include_user_skills else None
        print(
            "\n".join(
                sync_skills(ROOT, migrate_copies=args.migrate_copies, user_skills=user_skills)
            )
        )
        return 0
    if args.mode == "source-skill":
        if len(rest) != 1:
            parser.error("source-skill requires exactly one skill name")
        print(source_skill(ROOT, rest[0]))
        return 0
    if args.mode == "state-dir":
        print(ROOT / child_environment(ROOT, args.session_id)["KORUS_STATE_REL"])
        return 0
    if args.mode == "hook":
        payload = json.load(sys.stdin)
        result = dispatch(ROOT, payload)
        if result:
            print(json.dumps(result))
        return 0
    if args.mode == "doctor":
        config = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8-sig"))
        for event in config.get("hooks", {}):
            print(f"{event}: {'bridged' if event in EVENTS else 'UNMAPPED'}")
        for path in ("CLAUDE.md", ".pre-commit-config.yaml", "scripts/worktree/new.ps1"):
            if not (ROOT / path).is_file():
                raise FileNotFoundError(path)
            print(f"source: {path}")
        print("Skills: .agents pointers read the current repo and user-level Claude sources.")
        print("Hook activation still requires Codex project and hook trust.")
        return 0
    if not rest:
        parser.error("run requires a repo script and its arguments")
    script = (ROOT / rest[0]).resolve()
    if not script.is_relative_to(ROOT / "scripts") or not script.is_file():
        parser.error("run target must be an existing script under this repo's scripts/")
    if script.suffix not in (".ps1", ".py"):
        parser.error("run supports PowerShell and Python scripts")
    if script.name == "seat.ps1" and any(arg.lower() == "-bumpepoch" for arg in rest[1:]):
        parser.error("Claude's pool epoch does not apply to a Codex account")
    argv = (
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)]
        if script.suffix == ".ps1"
        else [sys.executable, str(script)]
    )
    return subprocess.call(  # nosec B603 - explicit user command, confined repo script, no shell
        [*argv, *rest[1:]], cwd=ROOT, env=child_environment(ROOT, args.session_id)
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        re.error,
        subprocess.SubprocessError,
    ) as exc:
        print(f"Codex bridge: {exc}", file=sys.stderr)
        sys.exit(2)
