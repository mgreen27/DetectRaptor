import csv
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import validate_mft


class MFTDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.csv_path = REPO_ROOT / "csv" / "MFT.csv"
        with cls.csv_path.open(
                newline="", encoding="utf-8-sig") as handle:
            cls.rows = list(csv.DictReader(handle))
        cls.rules = {row["Detection"]: row for row in cls.rows}

    def test_mft_csv_is_valid(self):
        self.assertEqual([], validate_mft.validate_mft_csv(self.csv_path))

    def test_komari_rule_has_valid_columns_and_does_not_self_suppress(self):
        rule = self.rules["RMM - Komari"]

        self.assertEqual(rule["PathRegex"], ".")
        self.assertEqual(rule["IgnoreRegex"], "")
        self.assertEqual(rule["Criticality"], "Medium")
        self.assertEqual(
            rule["Reference"],
            "Komari server or agent filename indicator")

    def test_validator_rejects_malformed_high_risk_fields(self):
        invalid_csv = io.StringIO()
        writer = csv.writer(invalid_csv)
        writer.writerow(validate_mft.EXPECTED_FIELDS)
        writer.writerow((
            "Invalid",
            "^tool\\.exe$| ^TOOL\\.exe$",
            ".",
            ".*",
            "test",
            "NotASeverity",
            "NotAScope",
            "NotAnEntryType",
        ))
        writer.writerow((
            "Invalid Directory Scope",
            "^tool$",
            ".",
            "",
            "test",
            "Medium",
            "Both",
            "Directory",
        ))

        with tempfile.NamedTemporaryFile(
                mode="w", newline="", encoding="utf-8",
                suffix=".csv") as handle:
            handle.write(invalid_csv.getvalue())
            handle.flush()
            issues = validate_mft.validate_mft_csv(handle.name)

        issue_text = "\n".join(issues)
        self.assertIn("whitespace around alternative", issue_text)
        self.assertIn("duplicate case-insensitive alternatives", issue_text)
        self.assertIn("IgnoreRegex suppresses all detections", issue_text)
        self.assertIn("invalid Criticality", issue_text)
        self.assertIn("invalid Scope", issue_text)
        self.assertIn("invalid EntryType", issue_text)
        self.assertIn("Directory rules must use Scope MFT", issue_text)

    def test_mft_notebook_queries_use_current_names_and_valid_commas(self):
        template = (
            REPO_ROOT / "templates" / "MFT.template"
        ).read_text(encoding="utf-8")

        self.assertEqual(
            template.count(
                "WHERE Detection.Name =~ 'Defence Evasion|RMM'"),
            2)
        self.assertNotIn("Defense Evasion Binaries", template)
        self.assertIn(
            "count() as Total,\n"
            "                OSPath as ExampleOSPath\n"
            "            FROM source()",
            template)

    def test_filezilla_rule_matches_executables_not_supporting_files(self):
        rule = re.compile(
            self.rules["Data Transfer - FileZilla"]["KeywordRegex"],
            re.IGNORECASE)

        for filename in (
                "filezilla.exe",
                "FileZillaPortable.exe",
                "filezilla-server.exe",
                "filezilla-server-gui.exe",
                "filezilla-server-impersonator.exe"):
            with self.subTest(filename=filename):
                self.assertRegex(filename, rule)

        for filename in (
                "filezilla.mo",
                "libfilezilla.mo",
                "brand-filezilla.svg",
                "filezilla.xml",
                "FileZillaPortable"):
            with self.subTest(filename=filename):
                self.assertNotRegex(filename, rule)

    def test_vpn_rule_matches_high_confidence_filenames(self):
        rule = re.compile(
            self.rules["VPN"]["KeywordRegex"], re.IGNORECASE)

        for filename in (
                "NordVPN.exe",
                "ProtonVPN.exe",
                "OpenVPNConnect.exe",
                "openvpnserv.exe",
                "wireguard.exe",
                "mullvad-daemon.exe",
                "tapexpressvpn.sys",
                "expressvpn-wintun.sys"):
            with self.subTest(filename=filename):
                self.assertRegex(filename, rule)

        for filename in (
                "brand-openvpn.svg",
                "openvpn.ico",
                "wireguard.dll",
                "OpenVPN Connect",
                "https+++protonvpn.com"):
            with self.subTest(filename=filename):
                self.assertNotRegex(filename, rule)

    def test_rmm_product_directory_rule_is_exact(self):
        self.assertNotIn("RMM - General", self.rules)
        rule_text = self.rules[
            "RMM - Product Directory"]["KeywordRegex"]
        rule = re.compile(rule_text, re.IGNORECASE)

        for basename in (
                "Meraki Systems Manager Agent",
                "TrendMicro BaseCamp",
                "AB Tutor",
                "Datto",
                "SolarWinds RMM",
                "Naverisk"):
            with self.subTest(basename=basename):
                self.assertRegex(basename, rule)

        for basename in (
                "RemoteAgent",
                "TestWindowRemoteAgent.exe",
                "DattoDocumentation",
                "NaveriskAgent"):
            with self.subTest(basename=basename):
                self.assertNotRegex(basename, rule)

    def test_procdump_rule_excludes_only_azure_monitor_bundle(self):
        self.assertNotIn(
            "procdump",
            self.rules["Credential Theft"]["KeywordRegex"].casefold())

        rule = self.rules["Credential Access Tool - ProcDump"]
        keyword = re.compile(rule["KeywordRegex"], re.IGNORECASE)
        ignore = re.compile(rule["IgnoreRegex"], re.IGNORECASE)

        self.assertRegex("procdump.exe", keyword)
        self.assertRegex("procdump64.exe", keyword)
        self.assertRegex("procdumpdll.dll", keyword)
        self.assertNotRegex("procdump", keyword)

        azure_path = (
            r"C:\Packages\Plugins"
            r"\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent"
            r"\1.43.0.0\Monitoring\Agent"
            r"\procdump\arm64\procdump64.exe")
        self.assertRegex(azure_path, ignore)
        self.assertNotRegex(r"C:\Tools\procdump64.exe", ignore)

    def test_mft_detection_output_includes_reference(self):
        template = (
            REPO_ROOT / "templates" / "MFT.template"
        ).read_text(encoding="utf-8")

        self.assertIn("Reference=Reference,", template)

    def test_scope_and_entry_type_classification(self):
        for name in (
                "Execution Path",
                "Hack Tool - Impacket"):
            with self.subTest(name=name):
                self.assertEqual(self.rules[name]["Scope"], "MFT")
                self.assertEqual(self.rules[name]["EntryType"], "File")

        for name in (
                "RMM - Product Directory",
                "RMM - RealVNC Product Directory",
                "RMM - VNC Product Directory",
                "RMM - Barracuda"):
            with self.subTest(name=name):
                self.assertEqual(self.rules[name]["Scope"], "MFT")
                self.assertEqual(
                    self.rules[name]["EntryType"], "Directory")

        self.assertEqual(
            self.rules["Data Transfer - FileZilla"]["Scope"], "Both")
        self.assertEqual(
            self.rules["Data Transfer - FileZilla"]["EntryType"], "File")

    def test_vnc_file_and_directory_indicators_are_split(self):
        self.assertNotIn("RMM - RealVNC", self.rules)
        self.assertNotIn("RMM - VNC", self.rules)

        realvnc_file = re.compile(
            self.rules["RMM - RealVNC Installer"]["KeywordRegex"],
            re.IGNORECASE)
        realvnc_directory = re.compile(
            self.rules[
                "RMM - RealVNC Product Directory"]["KeywordRegex"],
            re.IGNORECASE)

        self.assertRegex(
            "VNC-Connect-Installer-7.15.0.exe", realvnc_file)
        self.assertNotRegex("RealVNC", realvnc_file)
        self.assertRegex("RealVNC", realvnc_directory)
        self.assertNotRegex("RealVNC.exe", realvnc_directory)

    def test_mft_template_enforces_scope_and_entry_type(self):
        template = (
            REPO_ROOT / "templates" / "MFT.template"
        ).read_text(encoding="utf-8")

        self.assertIn("Scope =~ '^(MFT|Both)$'", template)
        self.assertIn("EntryType = 'File' AND NOT IsDir", template)
        self.assertIn("EntryType = 'Directory' AND IsDir", template)
        self.assertIn("Scope=Scope,", template)
        self.assertIn("EntryType=EntryType,", template)

    def test_amcache_template_excludes_directory_rules(self):
        template = (
            REPO_ROOT / "templates" / "Amcache.template"
        ).read_text(encoding="utf-8")

        self.assertIn("Scope =~ '^(Amcache|Both)$'", template)
        self.assertIn("AND NOT EntryType = 'Directory'", template)
        self.assertIn("Scope=Scope,", template)
        self.assertIn("EntryType=EntryType,", template)

    def test_quick_assist_is_split_by_artifact_context(self):
        self.assertNotIn("RMM - Microsoft Quick Assist", self.rules)

        amcache = self.rules[
            "RMM - Microsoft Quick Assist Execution"]
        unusual = self.rules[
            "RMM - Microsoft Quick Assist Unusual Path"]

        self.assertEqual(amcache["Scope"], "Amcache")
        self.assertEqual(amcache["IgnoreRegex"], "")
        self.assertEqual(unusual["Scope"], "MFT")

        ignore = re.compile(unusual["IgnoreRegex"], re.IGNORECASE)
        self.assertRegex(
            r"C:\Program Files\WindowsApps"
            r"\MicrosoftCorporationII.QuickAssist_2.0.35.0_x64__8wekyb3d8bbwe"
            r"\Microsoft.RemoteAssistance.QuickAssist\QuickAssist.exe",
            ignore)
        self.assertRegex(
            r"C:\Windows\WinSxS"
            r"\amd64_microsoft-windows-quickassist\quickassist.exe",
            ignore)
        self.assertNotRegex(r"C:\Tools\QuickAssist.exe", ignore)

    def test_archive_utilities_are_split_by_path_context(self):
        self.assertNotIn("Archive Utilities", self.rules)

        amcache = self.rules["Archive Utilities - Amcache"]
        user = self.rules[
            "Archive Utilities - User or Public Staging"]
        temporary = self.rules[
            "Archive Utilities - Windows Temporary Staging"]

        self.assertEqual(amcache["Scope"], "Amcache")
        self.assertEqual(user["Scope"], "MFT")
        self.assertEqual(temporary["Scope"], "MFT")

        user_path = re.compile(user["PathRegex"], re.IGNORECASE)
        user_ignore = re.compile(user["IgnoreRegex"], re.IGNORECASE)
        self.assertRegex(r"C:\Users\analyst\Downloads\7z.exe", user_path)
        self.assertRegex(
            r"C:\Users\analyst\AppData\Local"
            r"\SourceTree\app-3.4.22\tools\7z.exe",
            user_ignore)
        self.assertNotRegex(r"C:\Users\analyst\Downloads\7z.exe", user_ignore)

        temp_path = re.compile(temporary["PathRegex"], re.IGNORECASE)
        temp_ignore = re.compile(
            temporary["IgnoreRegex"], re.IGNORECASE)
        self.assertRegex(r"C:\Windows\Temp\staging\7za.exe", temp_path)
        self.assertRegex(
            r"C:\Windows\SystemTemp\NuGetScratch\abc\7z.exe",
            temp_ignore)
        self.assertNotRegex(
            r"C:\Windows\Temp\staging\7za.exe", temp_ignore)

    def test_enumeration_rules_use_exact_filenames(self):
        scanner = re.compile(
            self.rules[
                "Enumeration Tool - Network and AD Scanner"][
                    "KeywordRegex"],
            re.IGNORECASE)
        nmap = re.compile(
            self.rules[
                "Enumeration Tool - Nmap and Everything"][
                    "KeywordRegex"],
            re.IGNORECASE)

        self.assertRegex("advanced_ip_scanner.exe", scanner)
        self.assertRegex("netscan.exe", scanner)
        self.assertNotRegex("advanced_ip_scanner_de_de.qm", scanner)
        self.assertRegex("nmap.exe", nmap)
        self.assertNotRegex("brand-nmap.svg", nmap)
        self.assertNotRegex("zenmap.exe.png", nmap)

    def test_templates_add_rmm_path_context_and_approval_overlay(self):
        for template_name in ("MFT.template", "Amcache.template"):
            with self.subTest(template=template_name):
                template = (
                    REPO_ROOT / "templates" / template_name
                ).read_text(encoding="utf-8")
                self.assertIn("ApprovedRMMNameRegex", template)
                self.assertIn("ApprovedRMMPathRegex", template)
                self.assertIn("as LocationContext", template)
                self.assertIn("as RMMDisposition", template)
                self.assertIn("RMM location summary", template)

    def test_suspicious_location_rules_are_split_and_scoped(self):
        self.assertNotIn("Suspicious Location", self.rules)
        names = (
            "Suspicious Location - Public Executable or Script",
            "Suspicious Location - Public Archive or Installer",
            "Suspicious Location - User Temporary Staging",
            "Suspicious Location - Roaming Script or Archive",
            "Suspicious Location - ProgramData Root File",
            "Suspicious Location - PerfLogs Staging",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(self.rules[name]["Scope"], "MFT")
                self.assertEqual(self.rules[name]["EntryType"], "File")
                keyword = re.compile(
                    self.rules[name]["KeywordRegex"], re.IGNORECASE)
                self.assertNotRegex("payload.exe.config", keyword)

        public_rule = self.rules[
            "Suspicious Location - Public Executable or Script"]
        path = re.compile(public_rule["PathRegex"], re.IGNORECASE)
        ignore = re.compile(public_rule["IgnoreRegex"], re.IGNORECASE)

        self.assertRegex(
            r"C:\Users\Public\Documents\unknown\payload.exe", path)
        self.assertRegex(
            r"C:\Users\Public\Documents"
            r"\KUKA Public\OptionPackages\plugin.dll",
            ignore)
        self.assertRegex(
            r"C:\Users\Public\Documents"
            r"\Aurora Vision Studio 5.6\Filters\filter.dll",
            ignore)
        self.assertNotRegex(
            r"C:\Users\Public\Documents\unknown\payload.exe", ignore)

    def test_mft_template_has_timestamp_difference_notebook(self):
        template = (
            REPO_ROOT / "templates" / "MFT.template"
        ).read_text(encoding="utf-8")

        self.assertIn("SI and FN timestamp differences", template)
        self.assertIn(
            "SITimestamps.Created0x10 != FNTimestamps.Created0x30",
            template)


if __name__ == "__main__":
    unittest.main()
