# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Codex transport for the current Claude Code repo hooks and scripts.

No hook policy is copied here. Read .claude/settings.json for every event.
Account-level Claude settings, credentials and permissions are not imported.
"""

from __future__ import annotations

import argparse
import base64
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
# Must equal $blockExit in invoke.ps1; a mismatch leaves a block at 2, which its caller's
# pwsh -Command reports as 1.
BLOCK_EXIT = 10
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
# Codex kills the whole bridge at its own per-event timeout (.codex/config.toml), and the bridge runs
# an event's hooks one after another, so they all share that one budget. The margin leaves time for
# the launcher, the interpreter and the reply.
DEFAULT_OUTER_TIMEOUT = 90.0
GIT_REPOSITORY_VARIABLES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE")
OUTER_TIMEOUT_MARGIN = 10.0
KILL_DRAIN_TIMEOUT = 3.0


def user_skill_directory() -> Path:
    config_root = os.environ.get("CLAUDE_CONFIG_DIR")
    return (Path(config_root) if config_root else Path.home() / ".claude") / "skills"


@functools.cache
def repo_skill_directories(root: Path) -> tuple[Path, ...]:
    """This checkout's skills, then the primary checkout's for a linked worktree.

    .gitignore keeps .claude/skills out of git, so a linked worktree holds none of its own. Cached,
    because sync_skills resolves every pointer through source_skill and each would ask git again.
    """
    own = (root / ".claude/skills",)
    top = root.resolve()
    query = ["rev-parse", "--path-format=absolute", "--show-toplevel", "--git-common-dir"]
    try:
        lines = subprocess.run(  # nosec B603 B607 - fixed git query, no shell
            ["git", "-C", str(root), *query],
            env={k: v for k, v in os.environ.items() if k not in GIT_REPOSITORY_VARIABLES},
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=True,
        ).stdout.splitlines()
    except (OSError, subprocess.SubprocessError) as exc:
        # On stderr, so source-skill's stdout stays one path line. Silence would hide the primary
        # checkout's skills with no trace. Outside any repository this is expected.
        detail = str(exc)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            detail += f": {exc.stderr.strip()}"
        message = f"git query failed, primary checkout's skills not searched: {detail}"
        print(f"Codex bridge: warning: {message}", file=sys.stderr)
        return own
    # Only for a checkout's own top level, never a directory nested in some other repository. A bare
    # repository has no primary checkout; its common dir is not named .git.
    if len(lines) != 2 or Path(lines[0]).resolve() != top:
        return own
    common = Path(lines[1])
    if common.name == ".git" and common.parent.resolve() != top:
        return (*own, common.parent / ".claude/skills")
    return own


def source_skill(root: Path, name: str, *, user_skills: Path | None = None) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError("Skill name must be a single directory name")
    for directory in (*repo_skill_directories(root), user_skills or user_skill_directory()):
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
    # Later updates win, so the order runs from lowest precedence to highest.
    for directory in reversed(repo_skill_directories(root)):
        sources_by_name.update((path.parent.name, path) for path in directory.glob("*/SKILL.md"))
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


class HookBlocked(Exception):
    """A hook exited 2."""


# The key each non-tool event's matcher reads, as Claude Code's events carry them. An event not
# named here reads the first of DISCRIMINATOR_KEYS that is set.
EVENT_DISCRIMINATOR_KEYS = {
    "SessionStart": "source",
    "PreCompact": "trigger",
    "PostCompact": "trigger",
    "SubagentStart": "agent_type",
    "SubagentStop": "agent_type",
    "SessionEnd": "reason",
}
DISCRIMINATOR_KEYS = ("source", "trigger", "agent_type", "reason")
# What a fault outside a hook's own run raises: a bad matcher, an unsupported transport, malformed
# settings or output. The same set `__main__` turns into exit 2.
OUTER_FAULTS = (
    OSError,
    ValueError,
    KeyError,
    TypeError,
    AttributeError,
    re.error,
    subprocess.SubprocessError,
)
# Events whose exit-0 plain-text stdout Claude Code adds to the model's context.
PLAIN_TEXT_CONTEXT_EVENTS = ("SessionStart", "UserPromptSubmit")


def blocks(result: dict[str, Any]) -> bool:
    """Whether a merged result stops or holds the event: a deny, ask, block or `continue: false`."""
    specific = result.get("hookSpecificOutput") or {}
    decision = specific.get("decision")
    return (
        result.get("continue") is False
        or result.get("decision") == "block"
        or specific.get("permissionDecision") in ("deny", "ask")
        or (isinstance(decision, dict) and decision.get("behavior") == "deny")
    )


def hook_label(hook: dict[str, Any]) -> str:
    return " ".join(str(part) for part in (hook["command"], *hook.get("args", [])))


def outer_timeout(root: Path, event: str) -> float:
    """The timeout .codex/config.toml gives the bridge's own entry for this event, or the default."""
    try:
        config = tomllib.loads((root / ".codex/config.toml").read_text(encoding="utf-8-sig"))
        timeouts = [
            float(hook["timeout"])
            for group in config.get("hooks", {}).get(event, [])
            for hook in group.get("hooks", [])
            if "scripts/codex/invoke.ps1" in str(hook.get("command", ""))
            and isinstance(hook.get("timeout"), int | float)
            and not isinstance(hook.get("timeout"), bool)
        ]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, AttributeError) as exc:
        # The bridge never needed this file before; an unreadable one must not fail every event.
        print(
            f"Codex bridge: .codex/config.toml unreadable, using the default: {exc}",
            file=sys.stderr,
        )
        return DEFAULT_OUTER_TIMEOUT
    return min(timeouts, default=DEFAULT_OUTER_TIMEOUT)


def find_bash() -> str:
    """Claude Code runs a `shell: bash` hook under Git Bash on Windows; find that one, never WSL's."""
    found = shutil.which("bash")
    if os.name != "nt":
        if found:
            return found
        raise FileNotFoundError("bash not found for a shell: bash hook")
    candidates = []
    if configured := os.environ.get("CLAUDE_CODE_GIT_BASH_PATH"):
        candidates.append(Path(configured))
    if git := shutil.which("git"):
        # git.exe sits at several depths. bin/bash.exe first: it is the wrapper Git for Windows
        # launches, which puts /usr/bin on PATH. usr/bin/bash.exe started directly does not, so a
        # hook's own `bash` or coreutils could then resolve elsewhere, WSL's bash.exe included.
        # Up to the install root only; a walk to the drive root would try C:\bin, which any user
        # may create.
        for parent in Path(git).resolve().parents[:3]:
            candidates += [parent / "bin/bash.exe", parent / "usr/bin/bash.exe"]
    # System32's and WindowsApps' bash.exe launch WSL, which does not see this environment.
    if found and not re.search(r"[\\/](system32|windowsapps)[\\/]", found, re.IGNORECASE):
        candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError("Git Bash not found for a shell: bash hook")


def hook_argv(root: Path, hook: dict) -> list[str]:
    command = hook["command"]
    if "args" in hook:
        return [
            command,
            *[str(arg).replace("${CLAUDE_PROJECT_DIR}", str(root)) for arg in hook["args"]],
        ]
    # A command-only source runs in the shell it names, as in Claude Code; with none, in the current
    # platform's shell. Environment expansion belongs to that shell.
    shell = hook.get("shell")
    if shell == "bash":
        return [find_bash(), "-c", command]
    if shell == "powershell" or (shell is None and os.name == "nt"):
        command = command.replace("${CLAUDE_PROJECT_DIR}", "$env:CLAUDE_PROJECT_DIR")
        return ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command]
    if shell is None:
        return ["sh", "-c", command]
    raise ValueError(f"Unsupported Claude hook shell: {shell}")


def run_hook(
    argv: list[str], payload: dict, root: Path, env: dict[str, str], timeout: float | None
) -> subprocess.CompletedProcess[str]:
    """subprocess.run, except a timeout never waits unbounded on the hook's descendants.

    On Windows subprocess.run kills only the direct child, then waits with no limit for any
    grandchild still holding the pipes, so a timeout kills the tree with taskkill /T. Whatever still
    holds the pipes after that gets a short drain, and is then abandoned to the bridge's own exit.
    """
    process = subprocess.Popen(  # nosec B603 - trusted repo hook; event data is stdin only
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=root,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        stdout, stderr = process.communicate(json.dumps(payload), timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(  # nosec B603 B607 - fixed command, our own child's pid
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                timeout=10,
                check=False,
            )
        process.kill()
        try:
            process.communicate(timeout=KILL_DRAIN_TIMEOUT)
        except subprocess.TimeoutExpired:
            print(
                "Codex bridge: a timed-out hook's descendant still holds its pipes", file=sys.stderr
            )
        raise
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


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
    deadline: float | None = None
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
    # A null or empty key reads as "", never as the text "None", and an event with no key of its
    # own falls through to the next key that is set.
    key = EVENT_DISCRIMINATOR_KEYS.get(event)
    if event in ("PreToolUse", "PostToolUse", "PermissionRequest"):
        discriminator = aliases
    elif key is not None:
        discriminator = {"" if payload.get(key) in (None, "") else str(payload[key])}
    else:
        discriminator = {
            next(
                (str(payload[k]) for k in DISCRIMINATOR_KEYS if payload.get(k) not in (None, "")),
                "",
            )
        }
    # Outside SessionStart a hook that fails other than by exit 2 no longer stops the event's later
    # hooks: they still run while the event's shared budget lasts, and once it is spent each later
    # hook is recorded as timed out without running. A hook's exit 2 still ends the event at once,
    # as on origin/main. The first fault is raised once the event's hooks end, unless a decision
    # blocks() reads as standing, `continue: false` among them, was merged from another hook; that
    # keeps the exit code a lone failing hook gave on main. A fault outside a hook's own run, such
    # as an unsupported hook or a field of the wrong type, ends them at once and takes the first
    # fault's place. Such a decision merged before that fault still stands, from another hook or
    # from earlier in the same object: merge_output merges systemMessage, stopReason and reason
    # first, then continue and decision, then hookSpecificOutput, so a bad field loses what the
    # same object would have merged after it.
    fault: Exception | None = None

    def record(exc: Exception, label: str) -> None:
        nonlocal fault
        if fault is None:
            fault = exc
        else:
            print(f"Codex bridge: hook {label!r} also failed: {exc}", file=sys.stderr)

    try:
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
                if deadline is None:
                    # Read only once a hook will run, so an event with none skips the file. The
                    # margin never takes more than half the budget, or a short cap would run nothing.
                    cap = outer_timeout(root, event)
                    deadline = time.monotonic() + cap - min(OUTER_TIMEOUT_MARGIN, cap / 2)
                try:
                    argv = hook_argv(root, hook)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, 0)
                    limit = hook.get("timeout", 30)
                    completed = run_hook(
                        argv,
                        payload,
                        root,
                        env,
                        remaining if limit is None else min(limit, remaining),
                    )
                    if completed.stderr:
                        print(completed.stderr, file=sys.stderr, end="")
                    if completed.returncode == 2:
                        raise HookBlocked(completed.stderr or "Claude hook blocked this event")
                    completed.check_returncode()
                except (OSError, ValueError, subprocess.SubprocessError, HookBlocked) as exc:
                    # A failed SessionStart hook, exit 2 included, is a non-blocking error in
                    # Claude Code: the session starts with every other hook's context. Run as
                    # `python bridge.py hook` or `pwsh -File invoke.ps1 hook`, a hook's exit 2 and
                    # a fault `__main__` catches both exit 2, with no deny or block output.
                    # docs/CODEX.md states what the registered line returns.
                    label = hook_label(hook)
                    if event == "SessionStart":
                        message = f"Codex bridge: SessionStart hook {label!r} failed: {exc}"
                        print(message, file=sys.stderr)
                        merge_output(result, {"systemMessage": message})
                        continue
                    if isinstance(exc, HookBlocked):
                        if fault is not None:
                            print(f"Codex bridge: a hook also failed: {fault}", file=sys.stderr)
                        raise
                    record(exc, label)
                    continue
                output = completed.stdout.strip()
                if not output:
                    continue
                try:
                    update = json.loads(output)
                except json.JSONDecodeError:
                    if event not in PLAIN_TEXT_CONTEXT_EVENTS:
                        print(output, file=sys.stderr)
                        continue
                    update = plain_text_context(event, output)
                # JSON that is not an object is a failed hook on every event but SessionStart, as
                # on origin/main; SessionStart reports one as a note, as
                # tests/test_b616_5879_codex_hook_shell_and_budget.py pins. Claude Code would take
                # it as plain text on UserPromptSubmit; docs/CODEX.md names that difference.
                if not isinstance(update, dict):
                    if event != "SessionStart":
                        record(ValueError("Hook JSON output must be an object"), hook_label(hook))
                        continue
                    message = "Codex bridge: a SessionStart hook printed JSON that is not an object"
                    print(message, file=sys.stderr)
                    merge_output(result, {"systemMessage": message})
                    continue
                merge_output(result, update)
    except OUTER_FAULTS as exc:
        # A fault outside a hook's own run ends the event's hooks. A decision blocks() reads as
        # standing that was already merged still stands, below, rather than being lost to the
        # fault's exit.
        if fault is not None:
            print(f"Codex bridge: a hook also failed: {fault}", file=sys.stderr)
        fault = exc
    if fault is not None:
        if not blocks(result):
            raise fault
        message = f"Codex bridge: a hook failed; the decision merged from the hooks' output stands: {fault}"
        print(message, file=sys.stderr)
        merge_output(result, {"systemMessage": message})
    return result


def plain_text_context(event: str, output: str) -> dict[str, Any]:
    """A hook's exit-0 plain text as the event's added context, as Claude Code adds it."""
    output = output.replace(
        "scripts\\coord\\seat.ps1", "scripts\\codex\\invoke.ps1 run scripts/coord/seat.ps1"
    )
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": output}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("hook", "run", "doctor", "sync-skills", "source-skill", "state-dir")
    )
    parser.add_argument("--session-id", default=os.environ.get("CODEX_THREAD_ID", ""))
    parser.add_argument("--migrate-copies", action="store_true")
    parser.add_argument("--include-user-skills", action="store_true")
    # A hook's exit 2 exits 2, or BLOCK_EXIT where argv is exactly `hook ... --block-exit 10`, the
    # form invoke.ps1 builds; it ends its process with 2 for it. It is taken out before argparse, so
    # no prefix of it is captured from a run script's own flags. Nothing inherits argv.
    argv = sys.argv[1:]
    block_exit = 2
    if argv[:1] == ["hook"] and argv[-2:] == ["--block-exit", str(BLOCK_EXIT)]:
        argv, block_exit = argv[:-2], BLOCK_EXIT
    args, rest = parser.parse_known_args(argv)
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
        try:
            result = dispatch(ROOT, payload)
        except HookBlocked as exc:
            print(f"Codex bridge: {exc}", file=sys.stderr)
            return block_exit
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
        print(
            "Skills: .agents pointers read the current repo, the primary checkout of a linked "
            "worktree, and user-level Claude sources."
        )
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
