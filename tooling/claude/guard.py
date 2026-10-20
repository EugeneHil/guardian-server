"""Claude Code PreToolUse guard: blocks access to secrets and unsafe git operations.

Exit code 2 blocks the tool call (reason on stderr); 0 allows it. Any internal
error fails closed.
"""

import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys

PROTECTED_BRANCHES = {"main", "develop"}
SECRET_GLOBS = [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.cer", "config.local.json"]
ALLOWED_NAMES = {".env.example"}
FILE_TOOLS = {"Read", "Edit", "Write", "NotebookEdit"}
SEGMENT_SEPARATORS = re.compile(r"&&|\|\||;|\||\n")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def is_secret_path(path: str) -> bool:
    name = os.path.basename(path.rstrip("/"))
    if name in ALLOWED_NAMES:
        return False
    return any(fnmatch.fnmatch(name, pattern) for pattern in SECRET_GLOBS)


def tokenize(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def git_args(tokens: list[str]) -> list[str] | None:
    """Return the arguments after `git`, or None if the segment is not a git command."""
    rest = tokens
    while rest and (rest[0] == "env" or ASSIGNMENT.match(rest[0])):
        rest = rest[1:]
    if not rest or rest[0] != "git":
        return None
    return rest[1:]


def check_git(args: list[str], current_branch: str | None) -> str | None:
    if "--no-verify" in args:
        return "git --no-verify is forbidden: hooks must run"
    positional = [a for a in args if not a.startswith("-")]
    if not positional:
        return None
    subcommand, refs = positional[0], positional[1:]
    on_protected = current_branch in PROTECTED_BRANCHES
    if subcommand == "commit" and on_protected:
        return f"committing on protected branch '{current_branch}' is forbidden; use a feature branch"
    if subcommand == "push":
        if any(a in ("--force", "-f") or a.startswith("--force-with-lease") for a in args):
            return "force push is forbidden"
        for ref in refs[1:]:
            target = ref.split(":")[-1]
            if target in PROTECTED_BRANCHES:
                return f"pushing to protected branch '{target}' is forbidden; open a PR"
        if len(refs) <= 1 and on_protected:
            return f"pushing from protected branch '{current_branch}' is forbidden; open a PR"
    return None


def check_bash(command: str, current_branch: str | None) -> str | None:
    for segment in SEGMENT_SEPARATORS.split(command):
        tokens = tokenize(segment)
        for token in tokens:
            if is_secret_path(token):
                return f"access to secret file '{token}' is forbidden"
        args = git_args(tokens)
        if args is not None:
            reason = check_git(args, current_branch)
            if reason:
                return reason
    return None


def decide(event: dict, current_branch: str | None) -> str | None:
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    if tool in FILE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if path and is_secret_path(path):
            return f"access to secret file '{path}' is forbidden"
        return None
    if tool == "Bash":
        return check_bash(tool_input.get("command", ""), current_branch)
    return None


def current_branch_in(cwd: str | None) -> str | None:
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=cwd or None,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def main() -> int:
    try:
        event = json.load(sys.stdin)
        reason = decide(event, current_branch_in(event.get("cwd")))
    except Exception as exc:  # fail closed
        reason = f"guard error: {exc}"
    if reason:
        print(f"Blocked by warden guard: {reason}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
