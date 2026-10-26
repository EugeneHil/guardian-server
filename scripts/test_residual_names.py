"""Guards against leftovers of the former product name (Warden -> Guardian).

Each group pairs the pattern with the set of files it covers and a flag that says
whether it is enforced yet. Groups are switched on as the rename lands.
The groups are disjoint by path, except `all`, which covers every tracked file.
Run: python3 -I -B -m unittest discover -s scripts
"""
import fnmatch
import os
import re
import subprocess
import unittest
from collections import namedtuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

Group = namedtuple("Group", "pattern paths enforced")

PATTERN = re.compile(r"warden|wdn(?!_)", re.IGNORECASE)

# Files that carry the configuration surface (env vars, headers, CLI text); they are
# renamed together in a later step, so they are excluded from the `cpp` group.
CONFIG_GLOBS = (
    "src/config.*",
    "src/cli.*",
    "src/admin_routes.*",
    "src/version.*",
    "tests/config_test.cpp",
    "tests/cli_test.cpp",
    "tests/api_admin_test.cpp",
    "config.example.json",
    "web/*",
    "docs/api.md",
)
CMAKE_FILES = ("CMakeLists.txt", "CMakePresets.json", "vcpkg.json")
CPP_DIRS = ("cmake/", "src/", "tests/")
SCRIPT_DIRS = ("scripts/", ".github/", "tooling/")
DOC_ROOT_FILES = (".gitignore", ".gitleaks.toml")


def matches_any(path, globs):
    return any(fnmatch.fnmatchcase(path, glob) for glob in globs)


def is_submodule_path(path):
    return path == ".gitmodules" or path.startswith("external/")


def is_config_path(path):
    return matches_any(path, CONFIG_GLOBS)


def is_cpp_path(path):
    if is_config_path(path):
        return False
    return path in CMAKE_FILES or path.startswith(CPP_DIRS)


def is_scripts_path(path):
    return path.startswith(SCRIPT_DIRS)


def is_docs_path(path):
    if is_config_path(path):
        return False
    return path in DOC_ROOT_FILES or (path.endswith(".md") and not path.startswith(SCRIPT_DIRS))


GROUPS = {
    "submodule": Group(PATTERN, is_submodule_path, True),
    "cpp": Group(PATTERN, is_cpp_path, True),
    "config": Group(PATTERN, is_config_path, True),
    "scripts": Group(PATTERN, is_scripts_path, False),
    "docs": Group(PATTERN, is_docs_path, False),
    "all": Group(PATTERN, lambda path: True, False),
}

# Files exempt from a group because they must spell the old name.
SELF = "scripts/test_residual_names.py"
ALLOW = {name: {SELF} for name in GROUPS}

# The former WARDEN_* variables and the former header must stay spelled where the server
# detects them (hard cut: they are refused, never read) and in the tests asserting that.
_LEGACY_NAMES = {
    "src/config.cpp": "lists the former WARDEN_* variables so legacyEnvVarProblem can refuse them",
    "tests/config_test.cpp": "asserts legacyEnvVarProblem names each former variable",
    "tests/cli_test.cpp": "asserts serve and token refuse to start with a former variable set",
    "tests/api_admin_test.cpp": "asserts the former X-Warden-Request header is rejected",
}
for _group in ("config", "all"):
    ALLOW[_group] |= set(_LEGACY_NAMES)


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def read_text(path):
    try:
        with open(os.path.join(ROOT, path), "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def offenders(group_name):
    group = GROUPS[group_name]
    allowed = ALLOW[group_name]
    found = []
    for path in tracked_files():
        if path in allowed or not group.paths(path):
            continue
        if group.pattern.search(path):
            found.append(f"{path}: path name")
        text = read_text(path)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if group.pattern.search(line):
                found.append(f"{path}:{number}: {line.strip()}")
    return found


CORE_DIR = os.path.join(ROOT, "external", "guardian-core")


def core_problems(core_dir):
    """Reasons why the checked-out core is not a post-rename guardian-core."""
    if not os.path.isfile(os.path.join(core_dir, "CMakeLists.txt")):
        return [f"{core_dir} is not checked out; run `git submodule update --init`"]
    problems = []
    if not os.path.isdir(os.path.join(core_dir, "include", "guardian")):
        problems.append("include/guardian/ is missing")
    if os.path.isdir(os.path.join(core_dir, "include", "warden")):
        problems.append("include/warden/ still exists")
    grep = subprocess.run(
        ["git", "-C", core_dir, "grep", "-I", "-i", "-l", "-E", "namespace warden"],
        capture_output=True,
    )
    if grep.returncode == 0:
        problems.append("namespace warden found in: " + grep.stdout.decode("utf-8").strip())
    elif grep.returncode != 1:
        problems.append("git grep failed: " + grep.stderr.decode("utf-8").strip())
    return problems


class ResidualNames(unittest.TestCase):
    def test_core_submodule_is_renamed(self):
        # Fails (never skips) when the pin is a pre-rename core or the submodule is absent.
        problems = core_problems(CORE_DIR)
        self.assertEqual(problems, [], "external/guardian-core is not a renamed core:\n" + "\n".join(problems))

    def _check(self, name):
        if not GROUPS[name].enforced:
            self.skipTest(f"group {name!r} is not enforced yet")
        found = offenders(name)
        self.assertEqual(found, [], f"residual names in group {name!r}:\n" + "\n".join(found))

    def test_group_submodule(self):
        self._check("submodule")

    def test_group_cpp(self):
        self._check("cpp")

    def test_group_config(self):
        self._check("config")

    def test_group_scripts(self):
        self._check("scripts")

    def test_group_docs(self):
        self._check("docs")

    def test_group_all(self):
        self._check("all")


if __name__ == "__main__":
    unittest.main()
