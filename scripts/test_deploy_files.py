"""Deploy gate: the deploy workflow, PowerShell scripts and VPS runbook must keep their
security properties (pinned host key, no inline secrets, cleanup, zip-slip protection)."""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def run_blocks(text):
    """Return (line number, body) for every `run:` value, inline or block scalar."""
    lines = text.splitlines()
    blocks = []
    i = 0
    while i < len(lines):
        match = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", lines[i])
        if not match:
            i += 1
            continue
        key_indent = len(match.group(1)) + (2 if lines[i].lstrip().startswith("- ") else 0)
        rest = match.group(2)
        start = i + 1
        body = []
        if rest[:1] in ("|", ">"):
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or indent_of(lines[j]) > key_indent):
                body.append(lines[j])
                j += 1
            i = j
        else:
            body.append(rest)
            i += 1
        blocks.append((start, "\n".join(body)))
    return blocks


class DeployWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read(".github", "workflows", "deploy.yml")

    def test_production_environment(self):
        self.assertIn("environment: production", self.text)

    def test_host_key_is_pinned(self):
        self.assertIn("StrictHostKeyChecking=yes", self.text)
        self.assertIn("UserKnownHostsFile", self.text)
        self.assertIn("known_hosts", self.text)
        self.assertIn("BatchMode=yes", self.text)
        self.assertNotIn("StrictHostKeyChecking=no", self.text)
        self.assertNotIn("StrictHostKeyChecking no", self.text)

    def test_no_secrets_inside_run_blocks(self):
        blocks = run_blocks(self.text)
        self.assertGreaterEqual(len(blocks), 3, "run block parser found too few blocks")
        for line, body in blocks:
            self.assertNotRegex(body, r"\bsecrets\b", f"secrets reference in run block at line {line}")
            self.assertNotRegex(body, r"\$\{\{\s*(github|inputs)\.",
                                f"github/inputs expression in run block at line {line}")
        # Secrets may only be assigned to env mappings: `NAME: ${{ secrets.NAME }}`.
        for number, line in enumerate(self.text.splitlines(), 1):
            if "secrets." in line:
                self.assertRegex(line, r"^\s+[A-Z_]+:\s+\$\{\{\s*secrets\.[A-Z_]+\s*\}\}\s*$",
                                 f"line {number} uses a secret outside an env assignment")

    def test_run_block_parser_catches_inline_secret(self):
        bad = "steps:\n  - run: |\n      echo ${{ secrets.X }}\n  - run: echo ${{ secrets.Y }}\n"
        found = [body for _, body in run_blocks(bad) if re.search(r"\bsecrets\b", body)]
        self.assertEqual(len(found), 2)
        tricky = "steps:\n  - run: |\n      echo '${{ toJSON(secrets) }}' ${{ github.ref }}\n"
        self.assertTrue([b for _, b in run_blocks(tricky) if re.search(r"\bsecrets\b", b)])
        good = "steps:\n  - run: |\n      echo \"$X\"\n    env:\n      X: ${{ secrets.X }}\n"
        self.assertFalse([b for _, b in run_blocks(good) if "secrets." in b])

    def test_key_cleanup_always_runs(self):
        self.assertRegex(self.text, r"if:\s*always\(\)")
        self.assertRegex(self.text, r"(?s)if:\s*always\(\).*(shred|Remove|rm )")

    def test_no_shell_tracing(self):
        self.assertNotRegex(self.text, r"set\s+-[a-z]*x")

    def test_permissions_and_triggers(self):
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read$")
        self.assertRegex(self.text, r"tags:\s*\n\s*-\s*['\"]?v\*\.\*\.\*['\"]?")
        self.assertIn("workflow_dispatch", self.text)
        self.assertIn("concurrency:", self.text)
        self.assertIn("needs: build", self.text)

    def test_only_main_tags_are_deployed(self):
        self.assertRegex(self.text, r"if:\s*startsWith\(github\.ref,\s*'refs/tags/v'\)")
        self.assertIn("git merge-base --is-ancestor", self.text)
        self.assertIn("origin/main", self.text)
        build = self.text.split("  deploy:")[0]
        self.assertIn("merge-base", build)
        self.assertIn("fetch-depth: 0", build)
        deploy = self.text.split("  deploy:")[1]
        self.assertNotIn("actions/checkout", deploy)

    def test_timeouts_and_ssh_hardening(self):
        self.assertEqual(self.text.count("timeout-minutes:"), 2)
        for opt in ("ConnectTimeout=20", "ServerAliveInterval=15", "ServerAliveCountMax=4"):
            self.assertIn(opt, self.text)
        self.assertIn("-ExecutionPolicy Bypass", self.text)

    def test_key_files_have_mode_600(self):
        self.assertIn("umask 077", self.text)
        self.assertIn("chmod 600", self.text)


class ApplyUpdateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read("scripts", "apply-update.ps1")

    def test_required_mentions(self):
        for needle in ("bin.prev", "healthz", "StrictMode", "ErrorActionPreference"):
            self.assertIn(needle, self.text)

    def test_zip_slip_protection(self):
        self.assertRegex(self.text, r"(?i)zip-slip")
        self.assertIn("'..'", self.text)
        self.assertIn("incoming", self.text)

    def test_loopback_only_certificate_skip(self):
        self.assertIn("127.0.0.1", self.text)
        self.assertNotIn("ServicePointManager", self.text)
        self.assertNotRegex(self.text, r"(?i)TrustAllCerts")


class InstallServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read("scripts", "install-service.ps1")

    def test_required_mentions(self):
        for needle in ("AppStopMethodConsole", "WardenServer", "icacls", "StrictMode",
                       "ErrorActionPreference", "AppRotateFiles", "AppExit"):
            self.assertIn(needle, self.text)

    def test_deploy_user_can_stop_and_start(self):
        # Stop-Service needs enumerate-dependents (SW), Start-Service needs query-config (CC).
        self.assertIn("CCLCSWRPWPLORC", self.text)
        self.assertNotIn("Contains($deploySid)", self.text)

    def test_nssm_must_be_admin_only_location(self):
        self.assertRegex(self.text, r"(?i)C:\\Users")
        self.assertIn("AppStopMethodSkip' @('6')", self.text)

    def test_no_embedded_secrets(self):
        self.assertNotRegex(self.text, r"(?i)password\s*=\s*['\"][^'\"]+['\"]")


class RunbookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read("docs", "vps-setup.md")

    def test_nine_numbered_steps(self):
        for number in range(1, 10):
            self.assertRegex(self.text, rf"(?m)^## Step {number}\. \S", f"missing Step {number}")
        self.assertNotRegex(self.text, r"(?m)^## Step 10\.")

    def test_secret_names_and_environment(self):
        for needle in ("VPS_HOST", "VPS_USER", "VPS_SSH_KEY", "VPS_KNOWN_HOSTS", "production",
                       "token add mac-eugene", "PasswordAuthentication no", "8443",
                       "winget", "NSSM", "--out-dir C:\\warden\\data\\tls", "Rollback"):
            self.assertIn(needle, self.text)

    def test_hardening_details(self):
        for needle in ("sshd -t", "administrators_authorized_keys", "Selected tags", "v*.*.*",
                       "ruleset", "-ExecutionPolicy Bypass", "--scope machine", "Program Files\\nssm",
                       "-NoStart", "ABOVE", "SECOND"):
            self.assertIn(needle, self.text)
        self.assertNotIn("restart the service (`Restart-Service WardenServer`)", self.text)

    def test_no_real_hosts_or_keys(self):
        self.assertIn("<vps-ip>", self.text)
        self.assertNotRegex(self.text, r"(?<![~\d.])\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b(?<!127\.0\.0\.1)(?<!0\.0\.0\.0)")
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", self.text)
        self.assertNotIn("BEGIN PRIVATE KEY", self.text)


if __name__ == "__main__":
    unittest.main()
