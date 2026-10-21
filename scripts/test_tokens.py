import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOKENS_PY = os.path.join(HERE, "tokens.py")
GENERATOR_REL = os.path.join("external", "warden-core", "design-tokens")


def make_layout(tmp):
    """Copy the files tokens.py needs into a throwaway repo layout and init git in the generator dir."""
    root = os.path.join(tmp, "repo")
    os.makedirs(os.path.join(root, "scripts"))
    os.makedirs(os.path.join(root, "web"))
    shutil.copy(TOKENS_PY, os.path.join(root, "scripts", "tokens.py"))
    shutil.copytree(
        os.path.join(ROOT, GENERATOR_REL),
        os.path.join(root, GENERATOR_REL),
        ignore=shutil.ignore_patterns("__pycache__", "generated"),
    )
    return root


def run_tokens(root, *args):
    return subprocess.run(
        [sys.executable, "-I", "-B", os.path.join(root, "scripts", "tokens.py"), *args],
        capture_output=True,
        text=True,
    )


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


class TokensTest(unittest.TestCase):
    def test_generates_css_without_touching_submodule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_layout(tmp)
            gen_dir = os.path.join(root, GENERATOR_REL)
            git(gen_dir, "init", "-q")
            git(gen_dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "add", "-A")
            git(gen_dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "x")
            result = run_tokens(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            css = os.path.join(root, "web", "tokens.css")
            self.assertTrue(os.path.isfile(css))
            with open(css, encoding="utf-8") as fh:
                self.assertIn("--color-background", fh.read())
            self.assertEqual(git(gen_dir, "status", "--porcelain", "--untracked-files=all"), "")

    def test_check_passes_when_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_layout(tmp)
            self.assertEqual(run_tokens(root).returncode, 0)
            result = run_tokens(root, "--check")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_check_fails_when_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_layout(tmp)
            self.assertEqual(run_tokens(root).returncode, 0)
            css = os.path.join(root, "web", "tokens.css")
            with open(css, "a", encoding="utf-8") as fh:
                fh.write("/* stale */\n")
            result = run_tokens(root, "--check")
            self.assertEqual(result.returncode, 1)

    def test_check_fails_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_layout(tmp)
            self.assertEqual(run_tokens(root, "--check").returncode, 1)

    def test_failed_generation_keeps_existing_css(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_layout(tmp)
            self.assertEqual(run_tokens(root).returncode, 0)
            css = os.path.join(root, "web", "tokens.css")
            with open(css, "rb") as fh:
                before = fh.read()
            generator = os.path.join(root, GENERATOR_REL, "generate.py")
            with open(generator, "w", encoding="utf-8") as fh:
                fh.write("import sys\nopen(sys.argv[sys.argv.index('--css') + 1], 'w').write('partial')\nsys.exit(3)\n")
            self.assertEqual(run_tokens(root).returncode, 1)
            with open(css, "rb") as fh:
                self.assertEqual(fh.read(), before)
            self.assertEqual(os.listdir(os.path.join(root, "web")), ["tokens.css"])

    def test_committed_tokens_css_is_current(self):
        result = run_tokens(ROOT, "--check")
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
