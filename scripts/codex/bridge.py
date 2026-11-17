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
import shutil
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


TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PermissionRequest")
# The payload field a matcher is compared with. Claude Code ignores a matcher on every other event,
# UserPromptSubmit and Stop among them, so the bridge runs those groups unconditionally.
MATCHER_FIELDS = {
    "SessionStart": "source",
    "SessionEnd": "reason",
    "PreCompact": "trigger",
    "PostCompact": "trigger",
    "SubagentStart": "agent_type",
    "SubagentStop": "agent_type",
}
# Claude Code adds a hook's plain exit-0 stdout as context for these events only.
PLAIN_CONTEXT_EVENTS = ("SessionStart", "UserPromptSubmit")
# Hook mode's exit code for run_hook's block. invoke.ps1 turns it into 2 and every other non-zero,
# the interpreter's and argparse's 2 included, into a non-blocking 1. See docs/CODEX.md, "Who
# decides a block".
BLOCK_EXIT = 10


class HookBlocked(Exception):
    """A deliberate block: a hook exited 2, or failed with onFailure set to block."""


def git_bash() -> str | None:
    """The Git Bash that Claude Code runs a bash hook with on Windows, or None if there is none."""
    configured = os.environ.get("CLAUDE_CODE_GIT_BASH_PATH")
    if configured:
        return configured  # As set: a wrong path then fails to start and is reported.
    git = shutil.which("git")
    if git:
        # git.exe sits in Git/cmd, Git/bin or Git/mingw64/bin. Git/bin/bash.exe is the wrapper that
        # puts Git's usr/bin and mingw64/bin on PATH, so a hook's own cat or grep resolves.
        for parent in Path(git).resolve().parents[:3]:
            if (parent / "bin/bash.exe").is_file():
                return str(parent / "bin/bash.exe")
    return None


# A command-only PowerShell hook runs under pwsh -Command. The head line keeps a native non-zero
# exit from throwing where a PowerShell build defaults that preference on. The tail lifts a 2 that
# -Command reports as 1, for example a guard script's exit 2, back to 2. See docs/CODEX.md, "Who
# decides a block", and the tests for which shapes block.
POWERSHELL_HEAD = "$PSNativeCommandUseErrorActionPreference = $false\n"
POWERSHELL_TAIL = (
    "\n;\nif (-not $?) { if ((Microsoft.PowerShell.Utility\\Get-Variable -Name LASTEXITCODE"
    " -Scope Global -ValueOnly -ErrorAction Ignore) -eq 2) { exit 2 }; exit 1 }"
)


def hook_argv(root: Path, hook: dict) -> list[str]:
    command = hook["command"]
    if "args" in hook:
        return [
            str(part).replace("${CLAUDE_PROJECT_DIR}", str(root))
            for part in (command, *hook["args"])
        ]
    # A command-only source runs in the shell it names. Claude Code's default is bash, and on
    # Windows PowerShell when Git Bash is not installed. Environment expansion belongs to that
    # shell; structured args above need no shell parsing.
    shell = hook.get("shell")
    if shell in ("bash", None):
        bash = git_bash() if os.name == "nt" else "bash"
        if bash:
            return [bash, "-c", command]
        if shell == "bash":
            raise FileNotFoundError("Git Bash not found; a shell: bash hook cannot run")
        shell = "powershell"
    if shell == "powershell":
        command = command.replace("${CLAUDE_PROJECT_DIR}", "${env:CLAUDE_PROJECT_DIR}")
        script = POWERSHELL_HEAD + command + POWERSHELL_TAIL
        return ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script]
    raise ValueError(f"Unsupported Claude hook shell: {shell}")


def hook_failed(result: dict, hook: dict, why: str) -> None:
    """Report a failure Claude Code treats as non-blocking, unless the hook opts into blocking."""
    label = hook.get("statusMessage") or " ".join(
        [hook["command"], *(str(arg) for arg in hook.get("args", []))]
    )
    message = f"Codex bridge: hook {why}: {label}"
    if hook.get("onFailure") == "block":
        raise HookBlocked(f"{message} (onFailure is block)")
    # On stderr and as a systemMessage, since a host may not show the stderr of an exit 0.
    print(f"{message} (not blocking)", file=sys.stderr)
    merge_output(result, {"systemMessage": f"{message} (not blocking)"})


def print_hook_stderr(text: str) -> None:
    if text:
        print(text, file=sys.stderr, end="" if text.endswith("\n") else "\n")


def read_settings(root: Path) -> dict:
    config = json.loads((root / ".claude/settings.json").read_text(encoding="utf-8-sig"))
    if not isinstance(config, dict):
        raise ValueError(".claude/settings.json must hold a JSON object")
    return config


def discriminator_for(event: str, payload: dict) -> set[str] | None:
    """The values a matcher is compared with, or None where Claude Code ignores the matcher."""
    if event in TOOL_EVENTS:
        names = {str(payload.get("tool_name", ""))}
        if "Bash" in names:
            names.add("PowerShell")
        if "apply_patch" in names:
            names.update(("Edit", "Write"))
        return names
    if event in MATCHER_FIELDS:
        return {str(payload.get(MATCHER_FIELDS[event]) or "")}
    return None


def group_selected(group: dict, discriminator: set[str] | None) -> bool:
    matcher = group.get("matcher", "")
    return (
        discriminator is None
        or matcher in ("", "*")
        or any(re.search(matcher, value) for value in discriminator)
    )


def run_hook(root: Path, stdin: bytes | str | None = None, event: str = "") -> int:
    """Decide one Codex hook event: 0 to proceed or 2 to block, never anything else.

    With no stdin given, the payload is read from this process's stdin as UTF-8 bytes; the text
    stream would decode it with the console code page. `event` is the event Codex registered.
    """
    result: dict = {}
    try:
        if stdin is None:
            stdin = sys.stdin.buffer.read()
        payload = json.loads(stdin.decode("utf-8-sig") if isinstance(stdin, bytes) else stdin)
        if not isinstance(payload, dict):
            raise ValueError("the hook payload must be a JSON object")
        named = str(payload.get("hook_event_name") or "")
        if event:
            canonical = next((known for known in EVENTS if known.lower() == event.lower()), None)
            if canonical is None or named.lower() != event.lower():
                raise ValueError(f"the payload names event {named!r}, registered as {event!r}")
            payload["hook_event_name"] = canonical  # The canonical spelling selects the settings.
        dispatch(root, payload, result)
    except HookBlocked as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - a bridge fault is reported here, never a block
        # A fault never blocks, on any event, but a decision already gathered, such as an
        # earlier hook's deny, still stands.
        message = f"Codex bridge fault: {type(exc).__name__}: {exc} (not blocking)"
        print(message, file=sys.stderr)
        merge_output(result, {"systemMessage": message})
    if result:
        print(json.dumps(result))
    return 0


def run_one_hook(root: Path, payload: dict, env: dict[str, str], hook: dict, result: dict) -> None:
    event = payload["hook_event_name"]
    if hook.get("type") != "command" or hook.get("async"):
        raise ValueError(
            f"Unsupported Claude hook transport: {hook.get('type')}, async={hook.get('async', False)}"
        )
    # Claude Code's hook contract: exit 2 blocks. Any other failure, a timeout or a command
    # that cannot start included, is a non-blocking error unless the hook sets onFailure to
    # block, and the remaining hooks still run. Only a successful hook's stdout is read.
    try:
        completed = subprocess.run(  # nosec B603 - trusted repo hook; stdin carries event data
            hook_argv(root, hook),
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
    except subprocess.TimeoutExpired as exc:
        captured = exc.stderr or ""
        if isinstance(captured, bytes):
            captured = captured.decode("utf-8", "replace")
        print_hook_stderr(captured)
        hook_failed(result, hook, f"timed out after {exc.timeout} seconds")
        return
    except OSError as exc:
        hook_failed(result, hook, f"could not start ({exc})")
        return
    if completed.returncode == 2:
        raise HookBlocked(completed.stderr.strip() or "Claude hook blocked this event")
    print_hook_stderr(completed.stderr)
    if completed.returncode:
        hook_failed(result, hook, f"exited {completed.returncode}")
        return
    output = completed.stdout.strip()
    if not output:
        return
    try:
        update = json.loads(output)
    except json.JSONDecodeError:
        update = None
    if not isinstance(update, dict):
        if event not in PLAIN_CONTEXT_EVENTS:
            print(output, file=sys.stderr)
            return
        output = output.replace(
            "scripts\\coord\\seat.ps1",
            "scripts\\codex\\invoke.ps1 run scripts/coord/seat.ps1",
        )
        update = {"hookSpecificOutput": {"hookEventName": event, "additionalContext": output}}
    merge_output(result, update)


def run_group(root: Path, payload: dict, env: dict[str, str], group: dict, result: dict) -> None:
    for hook in group.get("hooks", []):
        try:
            run_one_hook(root, payload, env, hook, result)
        except HookBlocked:
            raise
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            # A defect belongs to its own hook: it blocks only when that hook set onFailure to
            # block. Any other hook's defect is reported and that hook skipped.
            message = f"Codex bridge: skipped a hook with a defect: {type(exc).__name__}: {exc}"
            if isinstance(hook, dict) and hook.get("onFailure") == "block":
                raise HookBlocked(f"{message} (onFailure is block)") from exc
            print(f"{message} (not blocking)", file=sys.stderr)
            merge_output(result, {"systemMessage": f"{message} (not blocking)"})


def blocks_on_failure(group: dict) -> bool:
    hooks = group.get("hooks", []) if isinstance(group, dict) else []
    return any(isinstance(hook, dict) and hook.get("onFailure") == "block" for hook in hooks)


def dispatch(root: Path, payload: dict, result: dict | None = None) -> dict:
    """Run the event's hooks, gathering their output into `result`, which a fault leaves intact."""
    result = {} if result is None else result
    event = payload["hook_event_name"]
    config = read_settings(root)
    if config.get("disableAllHooks"):
        return result
    env = child_environment(root, payload.get("session_id", ""))
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
    discriminator = discriminator_for(event, payload)
    for group in config.get("hooks", {}).get(event, []):
        try:
            if group_selected(group, discriminator):
                run_group(root, payload, env, group, result)
        except HookBlocked:
            raise
        except (AttributeError, KeyError, TypeError, ValueError, re.error) as exc:
            # A defect in the group itself, such as its matcher, keeps all of its hooks from
            # running: it is reported and the group skipped, so the groups after it still run,
            # unless a hook in it set onFailure to block, which has then failed.
            message = (
                f"Codex bridge: skipped a hook group with a defect: {type(exc).__name__}: {exc}"
            )
            if blocks_on_failure(group):
                raise HookBlocked(f"{message} (onFailure is block)") from exc
            print(f"{message} (not blocking)", file=sys.stderr)
            merge_output(result, {"systemMessage": f"{message} (not blocking)"})
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
        hook_parser = argparse.ArgumentParser(prog="bridge.py hook", allow_abbrev=False)
        hook_parser.add_argument("--event", default="", help="the event Codex registered")
        event = hook_parser.parse_args(rest).event
        return BLOCK_EXIT if run_hook(ROOT, None, event) == 2 else 0
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
