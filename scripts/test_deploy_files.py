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


class ReleasePresetTest(unittest.TestCase):
    def test_ci_builds_release_in_the_same_job_and_deploy_uses_same_preset(self):
        ci = read(".github", "workflows", "ci.yml")
        deploy = read(".github", "workflows", "deploy.yml")
        windows_job = ci.split("  server-windows:")[1].split("  server-quality:")[0]
        for name in ("Configure (Release)", "Build (Release)", "Test (Release)"):
            self.assertIn(name, windows_job)
        for text in (windows_job, deploy):
            self.assertIn("cmake --preset windows-release", text)
            self.assertIn("cmake --build --preset windows-release", text)
            self.assertIn("ctest --preset windows-release", text)
        self.assertNotIn("-DCMAKE_BUILD_TYPE=Release", deploy)
        self.assertIn("build/windows-release/guardian-server.exe", deploy)
        self.assertNotIn("matrix", ci)
        for job in ("server-windows", "server-quality", "tokens"):
            self.assertIn("  %s:" % job, ci)

    def test_release_presets_exist(self):
        import json
        presets = json.loads(read("CMakePresets.json"))
        configure = {p["name"]: p for p in presets["configurePresets"]}
        self.assertEqual(configure["windows-release"]["inherits"], "windows")
        self.assertEqual(configure["windows-release"]["cacheVariables"]["CMAKE_BUILD_TYPE"], "Release")
        for kind in ("buildPresets", "testPresets"):
            self.assertIn("windows-release", [p["name"] for p in presets[kind]])


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
        self.assertNotRegex(self.text, r"(?i)ServicePointManager\]::ServerCertificateValidationCallback")
        self.assertNotRegex(self.text, r"(?i)TrustAllCerts")

    def test_probe_negotiates_tls12_on_windows_powershell(self):
        # The server requires TLS 1.2; Windows PowerShell 5.1 may default to older protocols.
        self.assertRegex(
            self.text,
            r"\[Net\.ServicePointManager\]::SecurityProtocol\s*=\s*\[Net\.ServicePointManager\]::SecurityProtocol"
            r"\s*-bor\s*\[Net\.SecurityProtocolType\]::Tls12")

    def test_health_window_is_sixty_seconds(self):
        # A service start takes about 15 s on the VPS; keep a generous window after it.
        self.assertRegex(self.text, r"\[int\]\$HealthTimeoutSeconds = 60\b")
        self.assertIn("for 60 seconds", self.text)

    def test_consumed_archive_is_removed_after_success(self):
        self.assertRegex(self.text, r"Remove-Item -LiteralPath \$zipFull")


class InstallServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read("scripts", "install-service.ps1")

    def test_required_mentions(self):
        for needle in ("AppStopMethodConsole", "GuardianServer", "icacls", "StrictMode",
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
                       "NSSM", "--out-dir C:\\guardian\\data\\tls", "Rollback"):
            self.assertIn(needle, self.text)

    def test_hardening_details(self):
        for needle in ("sshd -t", "administrators_authorized_keys", "Selected tags", "v*.*.*",
                       "ruleset", "-ExecutionPolicy Bypass", "Program Files\\nssm",
                       "-NoStart", "ABOVE", "SECOND"):
            self.assertIn(needle, self.text)
        self.assertNotIn("restart the service (`Restart-Service GuardianServer`)", self.text)

    def test_firewall_rules_are_matched_on_name(self):
        # Display names are localized on Windows; the rules are created with a fixed Name.
        self.assertIn("-Name 'GuardianSSH'", self.text)
        self.assertIn("-Name 'GuardianHTTPS'", self.text)
        self.assertIn("$n -like 'Guardian*'", self.text)
        self.assertNotIn("$d -like", self.text)
        self.assertIn("Set-NetFirewallRule -Name 'GuardianHTTPS' -RemoteAddress", self.text)

    def test_operator_guidance(self):
        self.assertIn("Tls12", self.text)
        self.assertNotIn("is not even valid", self.text)
        self.assertIn("silently apply only to administrators", self.text)
        self.assertNotIn("(or running the workflow by hand)", self.text)
        self.assertIn("re-running it on an existing tag", self.text)
        self.assertIn("lowercase", self.text)
        self.assertIn("scp config.example.json", self.text)
        self.assertIn("incoming", self.text.split("## Deploying")[1])
        bootstrap = [l for l in self.text.splitlines() if l.rstrip().endswith("-Bootstrap")]
        self.assertTrue(bootstrap)
        for line in bootstrap:
            self.assertIn("-ExecutionPolicy Bypass", line)

    def test_windows_server_without_winget(self):
        self.assertNotIn("winget install", self.text)
        self.assertNotIn("winget list", self.text)
        for needle in ("Get-AuthenticodeSignature", "vc_redist.x64.exe", "Get-FileHash",
                       "99F5045FFFBFFB745D67FE3A065A953C4A3D9C253B868892D9B685B0EE7D07B8",
                       "2.24-101-g897c7ad", "curl.exe", "CoreNet-", "guardian-fw-disabled",
                       "Start-Service sshd", "AuthenticationMethods publickey", "sshd.exe\" -T"):
            self.assertIn(needle, self.text)
        self.assertNotIn("KbdInteractiveAuthentication no", self.text)

    def test_no_real_hosts_or_keys(self):
        self.assertIn("<vps-ip>", self.text)
        self.assertNotRegex(self.text, r"(?<![~\d.])\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b(?<!127\.0\.0\.1)(?<!0\.0\.0\.0)")
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", self.text)
        self.assertNotIn("BEGIN PRIVATE KEY", self.text)


class CutoverRunbookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read("docs", "vps-cutover.md")

    def test_ten_numbered_steps(self):
        for number in range(1, 11):
            self.assertRegex(self.text, rf"(?m)^## Step {number}\. \S", f"missing Step {number}")
        self.assertNotRegex(self.text, r"(?m)^## Step 11\.")

    def test_key_commands(self):
        old = "War" + "den"  # built so that this file does not spell the former product name
        for needle in (f"Stop-Service {old}Server", f"Move-Item C:\\{old.lower()} C:\\guardian",
                       f"nssm remove {old}Server confirm", "GuardianServer",
                       "C:\\guardian\\bin\\guardian-server.exe", "GUARDIAN_<NAME>=<value>",
                       "AppEnvironmentExtra", "guardian-deploy", "VPS_USER", "VPS_SSH_KEY",
                       "/healthz", "/api/v1/policy", "Step 9. Manual rollback", "read -rs TOKEN",
                       "New-NetFirewallRule -Name 'GuardianSSH'", "Remove-NetFirewallRule -Name", "v0.1.1"):
            self.assertIn(needle, self.text)

    def test_hard_cut_check_reads_the_registry_and_machine_scope(self):
        self.assertIn("Services\\$Svc\\Parameters", self.text)
        self.assertIn("-Type MultiString", self.text)
        self.assertIn("GetEnvironmentVariables('Machine')", self.text)
        self.assertIn("AppEnvironmentExtra", self.text)
        self.assertRegex(self.text, r"(?m)^\s*foreach \(\$v in 'AppEnvironmentExtra', 'AppEnvironment'\)")
        self.assertRegex(self.text, r"(?i)no `?" + "WAR" + "DEN_")

    def test_no_raw_environment_output(self):
        # NSSM output is not parseable in PowerShell 5.1 and would print secret values.
        self.assertNotRegex(self.text, r"(?m)^\s*nssm get \w+ AppEnvironment")

    def test_backup_is_verified(self):
        self.assertIn("-Exclude logs,staging,incoming,bin.prev,web.prev).FullName", self.text)
        self.assertRegex(self.text, r"throw \"No backup")
        zip_name = "war" + "den-pre-cutover.zip"
        self.assertIn(f"Expand-Archive C:\\cutover-backup\\{zip_name} -DestinationPath $tmp -Force", self.text)

    def test_order_and_etag(self):
        self.assertIn("Order of events", self.text)
        self.assertIn("grep -iE '^(HTTP|etag)'", self.text)
        self.assertIn("Failure in step 2 or 3", self.text)
        self.assertRegex(self.text, r"(?s)Step 8\..*push the tag `v0\.2\.0`.*Step 9\.")

    def test_no_secret_values(self):
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", self.text)
        self.assertNotRegex(self.text, r"GUARDIAN_ADMIN_PASSWORD=\S")
        self.assertNotRegex(self.text, r"(?<![~\d.])\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b(?<!127\.0\.0\.1)")


if __name__ == "__main__":
    unittest.main()
