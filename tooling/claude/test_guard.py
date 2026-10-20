import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from guard import decide, main  # noqa: E402


def E(tool, **inp):
    return {"tool_name": tool, "tool_input": inp, "cwd": "/tmp"}


class GuardTests(unittest.TestCase):
    def test_blocks_reading_env(self):
        self.assertIsNotNone(decide(E("Read", file_path="/r/api/.env"), "feature/x"))

    def test_blocks_editing_env_local(self):
        self.assertIsNotNone(decide(E("Edit", file_path="/r/.env.local"), "feature/x"))

    def test_blocks_writing_pem(self):
        self.assertIsNotNone(decide(E("Write", file_path="/r/certs/server.pem"), "feature/x"))

    def test_blocks_config_local(self):
        self.assertIsNotNone(decide(E("Read", file_path="/r/config.local.json"), "feature/x"))

    def test_allows_env_example(self):
        self.assertIsNone(decide(E("Read", file_path="/r/.env.example"), "feature/x"))

    def test_allows_config_example(self):
        self.assertIsNone(decide(E("Read", file_path="/r/config.example.json"), "feature/x"))

    def test_allows_normal_source(self):
        self.assertIsNone(decide(E("Edit", file_path="/r/src/Engine.cpp"), "feature/x"))

    def test_blocks_cat_secret_in_bash(self):
        self.assertIsNotNone(decide(E("Bash", command="cat ~/.ssh/id.key"), "feature/x"))

    def test_blocks_commit_on_develop(self):
        self.assertIsNotNone(decide(E("Bash", command="git commit -m 'x'"), "develop"))

    def test_allows_commit_on_feature(self):
        self.assertIsNone(decide(E("Bash", command="git commit -m 'feat: x'"), "feature/WRD-1-x"))

    def test_blocks_plain_push_from_main(self):
        self.assertIsNotNone(decide(E("Bash", command="git push"), "main"))

    def test_blocks_push_refspec_to_protected(self):
        for c in ["git push origin HEAD:main", "git push -u origin develop", "git push origin main"]:
            self.assertIsNotNone(decide(E("Bash", command=c), "feature/x"), c)

    def test_allows_push_feature(self):
        self.assertIsNone(
            decide(E("Bash", command="git push -u origin feature/WRD-1-x"), "feature/WRD-1-x")
        )

    def test_blocks_force_push(self):
        self.assertIsNotNone(decide(E("Bash", command="git push --force-with-lease"), "feature/x"))

    def test_blocks_no_verify(self):
        self.assertIsNotNone(decide(E("Bash", command="git commit --no-verify -m x"), "feature/x"))

    def test_blocks_push_in_compound_command(self):
        self.assertIsNotNone(decide(E("Bash", command="cd repo && git push origin main"), "feature/x"))

    def test_unrelated_tool_allowed(self):
        self.assertIsNone(decide(E("Grep", pattern="TODO"), "develop"))

    def test_malformed_input_fails_closed(self):
        with mock.patch("sys.stdin", io.StringIO("not json")), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(main(), 2)


if __name__ == "__main__":
    unittest.main()
