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
import validate_mft_whitelist
import assign_mft_metadata
import sync_mft_lolrmm
import normalize_mft_metadata


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

    def test_mft_whitelist_is_valid(self):
        self.assertEqual(
            [],
            validate_mft_whitelist.validate_whitelist(
                REPO_ROOT / "csv" / "MFT_Whitelist.csv",
                self.csv_path,
            ),
        )

    def test_whitelist_validator_rejects_broad_paths(self):
        issues = validate_mft_whitelist.validate_path_pattern(
            r"\\.*$")
        self.assertTrue(
            any("specific directory and basename" in issue
                for issue in issues))

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
            "BAD-ID",
            "Invalid",
            "Other",
            "BAD-TECHNIQUE",
            "NotAConfidence",
            "^tool\\.exe$| ^TOOL\\.exe$",
            ".",
            ".*",
            "test",
            "NotASeverity",
            "NotAScope",
            "NotAnEntryType",
            "test",
            "",
        ))
        writer.writerow((
            "DR-MFT-GEN-001",
            "Invalid Directory Scope",
            "Other",
            "",
            "Unreviewed",
            "^tool$",
            ".",
            "",
            "test",
            "Medium",
            "Both",
            "Directory",
            "test",
            "",
        ))
        writer.writerow((
            "DR-MFT-GEN-001",
            "Duplicate Rule ID",
            "Other",
            "",
            "Medium",
            "^duplicate\\.exe$",
            ".",
            "",
            "test",
            "Medium",
            "MFT",
            "File",
            "test",
            "",
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
        self.assertIn("invalid RuleID", issue_text)
        self.assertIn("duplicate RuleID", issue_text)
        self.assertIn("invalid Confidence", issue_text)
        self.assertIn("invalid Technique", issue_text)
        self.assertIn("invalid Scope", issue_text)
        self.assertIn("invalid EntryType", issue_text)
        self.assertIn("Directory rules must use Scope MFT", issue_text)

    def test_rule_metadata_is_complete_unique_and_idempotent(self):
        rule_ids = [row["RuleID"] for row in self.rows]

        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        for row in self.rows:
            with self.subTest(rule_id=row["RuleID"]):
                self.assertRegex(
                    row["RuleID"],
                    r"^DR-MFT-[A-Z][A-Z0-9]{2,5}-\d{3}$")
                self.assertTrue(row["Category"])
                self.assertIn(
                    row["Confidence"],
                    validate_mft.ALLOWED_CONFIDENCE)
                self.assertTrue(row["Source"])

        migrated = assign_mft_metadata.assign_metadata(self.rows)
        self.assertEqual(rule_ids, [row["RuleID"] for row in migrated])
        self.assertEqual(self.rows, migrated)

        self.assertEqual(
            self.rules[
                "Masquerading - Windows Binary Name in AppData"]["RuleID"],
            "DR-MFT-MASQ-001")
        self.assertEqual(
            self.rules[
                "Persistence - User Startup Executable or Script"]["RuleID"],
            "DR-MFT-PERS-001")

    def test_lolrmm_sync_is_deterministic_and_coverage_is_accounted(self):
        managed_paths = (
            REPO_ROOT / "csv" / "MFT.csv",
            REPO_ROOT / "csv" / "MFT_RMM_IDs.csv",
            REPO_ROOT / "csv" / "MFT_RMM_Coverage.csv",
            REPO_ROOT / "csv" / "MFT_Metadata_Summary.csv",
        )
        before = {
            path: path.read_bytes() for path in managed_paths}

        sync_mft_lolrmm.sync(
            REPO_ROOT / "csv" / "MFT.csv",
            REPO_ROOT / "csv" / "lolrmm.csv",
            REPO_ROOT / "csv" / "MFT_RMM_Overrides.csv",
            REPO_ROOT / "csv" / "MFT_RMM_IDs.csv",
            REPO_ROOT / "csv" / "MFT_RMM_Coverage.csv",
        )
        normalize_mft_metadata.normalize_files(
            REPO_ROOT / "csv" / "MFT.csv",
            REPO_ROOT / "csv" / "MFT_Metadata_Summary.csv",
        )

        self.assertEqual(
            before,
            {path: path.read_bytes() for path in managed_paths})

        with (
                REPO_ROOT / "csv" / "MFT_RMM_Coverage.csv"
        ).open(newline="", encoding="utf-8") as handle:
            coverage = list(csv.DictReader(handle))

        statuses = {row["Status"] for row in coverage}
        self.assertEqual(
            statuses, {"Generated", "Excluded", "Override"})
        with (
                REPO_ROOT / "csv" / "lolrmm.csv"
        ).open(newline="", encoding="utf-8-sig") as handle:
            upstream = list(csv.DictReader(handle))
        self.assertEqual(
            {sync_mft_lolrmm.source_id(row) for row in upstream},
            {row["SourceID"] for row in coverage if row["SourceID"]},
        )
        self.assertGreaterEqual(
            sum(row["Status"] == "Generated" for row in coverage), 200)
        for row in coverage:
            with self.subTest(source_id=row["SourceID"]):
                if row["Status"] == "Excluded":
                    self.assertIn(
                        row["Reason"],
                        {
                            "No safe Windows filename indicator",
                            "Only non-specific DLL filename indicators",
                        })

    def test_lolrmm_dlls_require_product_specific_names(self):
        accepted, filtered = sync_mft_lolrmm.filename_patterns(
            r"^control\.dll$|^controlio\.dll$",
            "Controlio",
            "controlio",
        )
        self.assertEqual([r"^controlio\.dll$"], accepted)
        self.assertEqual([r"^control\.dll$"], filtered)

        generated = {
            row["SourceID"]: row
            for row in self.rows
            if row["Source"] == "LOLRMM"
        }

        removed = {
            "controlio": ("libeay32.dll", "ssleay32.dll"),
            "fleetdeck.io": ("fd_agent.dll",),
            "idrive": ("IDComponent.dll",),
            "invgate": ("Software Matt.dll", "sas.dll"),
        }
        for source_id, filenames in removed.items():
            regex = re.compile(
                generated[source_id]["KeywordRegex"], re.IGNORECASE)
            for filename in filenames:
                with self.subTest(
                        source_id=source_id, filename=filename):
                    self.assertNotRegex(filename, regex)

        retained = {
            "echoware": ("echoware.dll",),
            "lunixar": (
                "LunixarRemote.dll",
                "LunixarUpdater.dll",
                "Lunixar.Agent.Core.dll",
                "Lunixar.dll",
            ),
        }
        for source_id, filenames in retained.items():
            regex = re.compile(
                generated[source_id]["KeywordRegex"], re.IGNORECASE)
            for filename in filenames:
                with self.subTest(
                        source_id=source_id, filename=filename):
                    self.assertRegex(filename, regex)

        with (
                REPO_ROOT / "csv" / "MFT_RMM_Coverage.csv"
        ).open(newline="", encoding="utf-8") as handle:
            coverage = {
                row["SourceID"]: row for row in csv.DictReader(handle)
            }
        self.assertIn(
            r"^libeay32\.dll$",
            coverage["controlio"]["FilteredFilenameRegex"])
        self.assertIn(
            r"^sas\.dll$",
            coverage["invgate"]["FilteredFilenameRegex"])

    def test_lolrmm_generated_rules_are_safe_and_attributable(self):
        generated = [
            row for row in self.rows
            if (row["Category"] == "Remote Access Software"
                and row["Source"] == "LOLRMM")]

        self.assertGreaterEqual(len(generated), 200)
        self.assertEqual(
            len(generated),
            len({row["SourceID"] for row in generated}))
        for row in generated:
            with self.subTest(rule_id=row["RuleID"]):
                self.assertEqual(
                    row["Category"], "Remote Access Software")
                self.assertTrue(row["SourceID"])
                self.assertRegex(
                    row["Reference"], r"^https://lolrmm\.io/tools/")
                self.assertNotRegex(
                    row["KeywordRegex"],
                    r"(^|\|)\^\.\*\\?\.(exe|dll|msi|sys)")

    def test_metadata_policy_is_normalized(self):
        self.assertNotIn(
            "Unreviewed", {row["Confidence"] for row in self.rows})

        for row in self.rows:
            with self.subTest(rule_id=row["RuleID"]):
                if row["EntryType"] == "Directory":
                    self.assertEqual(row["Scope"], "MFT")
                if row["Category"] == "Remote Access Software":
                    self.assertEqual(row["Criticality"], "Medium")
                    self.assertRegex(
                        row["Technique"], r"^T1219(?:\.002)?$")

        expected_techniques = {
            "Credential Access Tool - ProcDump": "T1003.001",
            "Credential Access - NTDS Database in User Profile": "T1003.003",
            "Persistence - User Startup Executable or Script": "T1547.001",
            "Masquerading - Double Extension Payload": "T1036.007",
            "Defence Evasion - Security Control Utilities": "T1562.001",
        }
        for detection, technique in expected_techniques.items():
            with self.subTest(detection=detection):
                self.assertEqual(
                    self.rules[detection]["Technique"], technique)

        normalized = normalize_mft_metadata.normalize(self.rows)
        self.assertEqual(self.rows, normalized)

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
        self.assertEqual(
            self.rules["RMM - VNC"]["EntryType"], "File")
        self.assertEqual(
            self.rules["RMM - VNC Product Directory"]["EntryType"],
            "Directory")

    def test_mft_template_enforces_scope_and_entry_type(self):
        template = (
            REPO_ROOT / "templates" / "MFT.template"
        ).read_text(encoding="utf-8")

        self.assertIn("Scope =~ '^(MFT|Both)$'", template)
        self.assertIn("EntryType = 'File' AND NOT IsDir", template)
        self.assertIn("EntryType = 'Directory' AND IsDir", template)
        self.assertIn("Scope=Scope,", template)
        self.assertIn("EntryType=EntryType,", template)
        self.assertIn("RuleID=RuleID,", template)
        self.assertIn("Category=Category,", template)
        self.assertIn("Technique=Technique,", template)
        self.assertIn("Confidence=Confidence,", template)
        self.assertIn("Source=Source,", template)
        self.assertIn("SourceID=SourceID,", template)

    def test_mft_template_emits_all_matches_and_groups_by_path(self):
        template = (
            REPO_ROOT / "templates" / "MFT.template"
        ).read_text(encoding="utf-8")

        self.assertNotIn("LIMIT 1", template)
        self.assertIn("LET keyword_patterns <= SELECT KeywordRegex", template)
        self.assertIn(
            "FileRegex=join(array=keyword_patterns.KeywordRegex", template)
        self.assertIn("name: File match summary", template)
        self.assertIn(
            "enumerate(items=Detection.RuleID) as RuleIDs", template)
        self.assertIn(
            "enumerate(items=Detection.Name) as Detections", template)
        self.assertIn("GROUP BY Fqdn,OSPath", template)
        self.assertIn("name: Operational metrics", template)
        self.assertIn("name: Rule path prevalence", template)
        self.assertIn(
            "name: MFT and Amcache exact path correlation", template)
        self.assertIn(
            "name: Cross-artifact correlation pivots", template)
        self.assertEqual(
            1, template.count("field=RuleID + '|MFT'"))

    def test_amcache_template_excludes_directory_rules(self):
        template = (
            REPO_ROOT / "templates" / "Amcache.template"
        ).read_text(encoding="utf-8")

        self.assertIn("Scope =~ '^(Amcache|Both)$'", template)
        self.assertIn("AND NOT EntryType = 'Directory'", template)
        self.assertIn("Scope=Scope,", template)
        self.assertIn("EntryType=EntryType,", template)
        self.assertIn("RuleID=RuleID,", template)
        self.assertIn("Category=Category,", template)
        self.assertIn("Technique=Technique,", template)
        self.assertIn("Confidence=Confidence,", template)
        self.assertIn("Source=Source,", template)
        self.assertIn("SourceID=SourceID,", template)
        self.assertNotIn("LIMIT 1", template)
        self.assertIn("name: Operational metrics", template)
        self.assertIn("name: File match summary", template)
        self.assertEqual(
            1, template.count("field=RuleID + '|Amcache'"))

    def test_templates_emit_flattened_analyst_fields(self):
        for template_name in ("MFT.template", "Amcache.template"):
            with self.subTest(template=template_name):
                template = (
                    REPO_ROOT / "templates" / template_name
                ).read_text(encoding="utf-8")
                for field in (
                        "RuleID,",
                        "Detection as DetectionName,",
                        "Category,",
                        "Technique,",
                        "Confidence,",
                        "Criticality,",
                        "Source,",
                        "SourceID,"):
                    self.assertIn(field, template)

    def test_quick_assist_is_split_by_artifact_context(self):
        self.assertNotIn("RMM - Microsoft Quick Assist", self.rules)

        amcache = self.rules[
            "RMM - Microsoft Quick Assist Execution"]
        unusual = self.rules[
            "RMM - Microsoft Quick Assist Unusual Path"]

        self.assertEqual(amcache["Scope"], "Amcache")
        self.assertEqual(amcache["IgnoreRegex"], "")
        self.assertEqual(unusual["Scope"], "MFT")
        self.assertEqual(unusual["IgnoreRegex"], "")

        whitelists = validate_mft_whitelist.read_csv(
            REPO_ROOT / "csv" / "MFT_Whitelist.csv")
        policy = next(
            row for row in whitelists
            if row["RuleID"] == unusual["RuleID"]
            and row["Artifact"] == "MFT")
        path = re.compile(policy["PathRegex"], re.IGNORECASE)
        self.assertRegex(
            r"C:\Program Files\WindowsApps"
            r"\MicrosoftCorporationII.QuickAssist_2.0.35.0_x64__8wekyb3d8bbwe"
            r"\Microsoft.RemoteAssistance.QuickAssist\QuickAssist.exe",
            path)
        self.assertRegex(
            r"C:\Windows\WinSxS"
            r"\amd64_microsoft-windows-quickassist\quickassist.exe",
            path)
        self.assertNotRegex(r"C:\Tools\QuickAssist.exe", path)

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

    def test_generic_tool_rules_use_filename_boundaries(self):
        expected = {
            "Attacker Tool - CrackMapExec": (
                ("crackmapexec.exe", "cme.py"),
                ("crackmapexec-notes.txt", "libcrackmapexec.dll"),
            ),
            "Attacker Tool - SafetyKatz": (
                ("SafetyKatz.exe",),
                ("SafetyKatz.exe.config", "MySafetyKatz.exe"),
            ),
            "Data Transfer - Restic": (
                ("restic.exe",),
                ("restic.exe.log", "restic-documentation.txt"),
            ),
            "Defence Evasion - Service and Process Utilities": (
                ("processhacker.exe", "nssm.exe"),
                ("processhacker.sys", "processhacker.exe.config"),
            ),
            "Web Browsing History Tool": (
                ("BrowsingHistoryView.exe",),
                ("BrowsingHistoryView.chm", "BrowsingHistoryView.exe.config"),
            ),
        }

        for detection, (positive, negative) in expected.items():
            regex = re.compile(
                self.rules[detection]["KeywordRegex"], re.IGNORECASE)
            for filename in positive:
                with self.subTest(detection=detection, filename=filename):
                    self.assertRegex(filename, regex)
            for filename in negative:
                with self.subTest(detection=detection, filename=filename):
                    self.assertNotRegex(filename, regex)

        self.assertNotIn("Data Transfer", self.rules)
        self.assertNotIn("Defence Evasion", self.rules)

    def test_generic_path_tool_families_are_anchored(self):
        categories = {
            "Attacker Tool",
            "Data Transfer",
            "Defence Evasion",
            "Execution",
            "Privilege Escalation",
            "Policy Violation",
            "Web History",
        }
        for row in self.rows:
            if row["Category"] not in categories:
                continue
            if row["PathRegex"] != ".":
                continue
            with self.subTest(rule_id=row["RuleID"]):
                self.assertTrue(row["KeywordRegex"].startswith("^"))
                self.assertTrue(row["KeywordRegex"].endswith("$"))

    def test_templates_add_rmm_path_context_and_approval_overlay(self):
        for template_name in ("MFT.template", "Amcache.template"):
            with self.subTest(template=template_name):
                template = (
                    REPO_ROOT / "templates" / template_name
                ).read_text(encoding="utf-8")
                self.assertIn("ApprovedRMMNameRegex", template)
                self.assertIn("ApprovedRMMPathRegex", template)
                self.assertIn("SuppressWhitelisted", template)
                self.assertIn("Whitelists", template)
                self.assertIn("memoize(", template)
                self.assertIn("AS WhitelistCandidate", template)
                self.assertIn("AS Disposition", template)
                self.assertIn("as LocationContext", template)
                self.assertIn("as RMMDisposition", template)
                self.assertIn("RMM location summary", template)

    def test_suspicious_location_rules_are_split_and_scoped(self):
        self.assertNotIn("Suspicious Location", self.rules)
        names = (
            "Suspicious Location - Public Executable or Script",
            "Suspicious Location - Public Archive Installer or Dump",
            "Suspicious Location - Local Temp Executable or Script",
            "Suspicious Location - Local Temp Archive Installer or Dump",
            "Suspicious Location - AppData Root Executable or Script",
            "Suspicious Location - AppData Root Archive or Installer",
            "Suspicious Location - Uncommon AppData Folder",
            "Suspicious Location - Recycle Bin Executable or Script",
            "Suspicious Location - ProgramData Root Executable or Script",
            "Suspicious Location - ProgramData Root Archive Installer or Dump",
            "Suspicious Location - PerfLogs Executable or Script",
            "Suspicious Location - PerfLogs Archive Installer or Dump",
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

    def test_appdata_uncommon_sibling_excludes_standard_folders(self):
        rule = self.rules[
            "Suspicious Location - Uncommon AppData Folder"]
        keyword = re.compile(rule["KeywordRegex"], re.IGNORECASE)
        path = re.compile(rule["PathRegex"], re.IGNORECASE)
        ignore = re.compile(rule["IgnoreRegex"], re.IGNORECASE)

        suspicious_path = r"C:\Users\analyst\AppData\Update\payload.exe"
        self.assertRegex("payload.exe", keyword)
        self.assertRegex(suspicious_path, path)
        self.assertNotRegex(suspicious_path, ignore)

        for standard_path in (
                r"C:\Users\analyst\AppData\Local\Vendor\payload.exe",
                r"C:\Users\analyst\AppData\LocalLow\Vendor\payload.exe",
                r"C:\Users\analyst\AppData\Roaming\Vendor\payload.exe"):
            with self.subTest(path=standard_path):
                self.assertRegex(standard_path, path)
                self.assertRegex(standard_path, ignore)

    def test_local_temp_rules_separate_payloads_from_dumps(self):
        executable_rule = self.rules[
            "Suspicious Location - Local Temp Executable or Script"]
        dump_rule = self.rules[
            "Suspicious Location - Local Temp Archive Installer or Dump"]
        executable_keyword = re.compile(
            executable_rule["KeywordRegex"], re.IGNORECASE)
        dump_keyword = re.compile(
            dump_rule["KeywordRegex"], re.IGNORECASE)
        temp_path = r"C:\Users\analyst\AppData\Local\Temp\crash.dmp"

        self.assertEqual(executable_rule["Criticality"], "High")
        self.assertEqual(dump_rule["Criticality"], "Medium")
        self.assertRegex(
            temp_path,
            re.compile(dump_rule["PathRegex"], re.IGNORECASE))
        self.assertRegex("payload.exe", executable_keyword)
        self.assertNotRegex("crash.dmp", executable_keyword)
        self.assertRegex("crash.dmp", dump_keyword)
        self.assertRegex("archive.iso", dump_keyword)

        executable_path = re.compile(
            executable_rule["PathRegex"], re.IGNORECASE)
        self.assertRegex(
            r"C:\Users\analyst\AppData\Local\Temp\payload.exe",
            executable_path)
        self.assertNotRegex(
            r"C:\Users\analyst\AppData\Local\Temp\Vendor\payload.exe",
            executable_path)

    def test_appdata_root_rules_are_shallow_and_cover_local_and_roaming(self):
        executable_rule = self.rules[
            "Suspicious Location - AppData Root Executable or Script"]
        archive_rule = self.rules[
            "Suspicious Location - AppData Root Archive or Installer"]

        executable_keyword = re.compile(
            executable_rule["KeywordRegex"], re.IGNORECASE)
        executable_path = re.compile(
            executable_rule["PathRegex"], re.IGNORECASE)
        archive_keyword = re.compile(
            archive_rule["KeywordRegex"], re.IGNORECASE)
        archive_path = re.compile(
            archive_rule["PathRegex"], re.IGNORECASE)

        self.assertEqual(executable_rule["Criticality"], "High")
        self.assertEqual(archive_rule["Criticality"], "Medium")

        for path in (
                r"C:\Users\analyst\AppData\Local\payload.exe",
                r"C:\Users\analyst\AppData\Roaming\update.ps1"):
            with self.subTest(path=path):
                self.assertRegex(path, executable_path)

        for path in (
                r"C:\Users\analyst\AppData\Local\Programs\Vendor\app.exe",
                r"C:\Users\analyst\AppData\Roaming\npm\tool.ps1"):
            with self.subTest(path=path):
                self.assertNotRegex(path, executable_path)

        self.assertRegex("payload.exe", executable_keyword)
        self.assertRegex("update.ps1", executable_keyword)
        self.assertNotRegex("archive.zip", executable_keyword)

        for path in (
                r"C:\Users\analyst\AppData\Local\stage.zip",
                r"C:\Users\analyst\AppData\Roaming\package.msi"):
            with self.subTest(path=path):
                self.assertRegex(path, archive_path)

        self.assertNotRegex(
            r"C:\Users\analyst\AppData\Roaming\Vendor\package.zip",
            archive_path)
        self.assertRegex("stage.zip", archive_keyword)
        self.assertRegex("image.iso", archive_keyword)
        self.assertNotRegex("payload.exe", archive_keyword)

        self.assertNotIn(
            "Suspicious Location - Roaming Script or Archive",
            self.rules)

    def test_appdata_system_binary_masquerading_rule(self):
        rule = self.rules[
            "Masquerading - Windows Binary Name in AppData"]
        keyword = re.compile(rule["KeywordRegex"], re.IGNORECASE)
        path = re.compile(rule["PathRegex"], re.IGNORECASE)

        self.assertEqual(rule["Criticality"], "High")
        self.assertRegex("svchost.exe", keyword)
        self.assertRegex("conhost.dll", keyword)
        self.assertNotRegex("vendor.exe", keyword)
        self.assertRegex(
            r"C:\Users\analyst\AppData\Local\Temp\svchost.exe", path)
        self.assertNotRegex(r"C:\Windows\System32\svchost.exe", path)

    def test_user_startup_rules_separate_payloads_and_shortcuts(self):
        executable_rule = self.rules[
            "Persistence - User Startup Executable or Script"]
        shortcut_rule = self.rules[
            "Persistence - User Startup Shortcut"]
        startup_path = (
            r"C:\Users\analyst\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\payload.exe")

        self.assertEqual(executable_rule["Criticality"], "High")
        self.assertEqual(shortcut_rule["Criticality"], "Medium")
        self.assertRegex(
            startup_path,
            re.compile(executable_rule["PathRegex"], re.IGNORECASE))
        self.assertRegex(
            "payload.exe",
            re.compile(executable_rule["KeywordRegex"], re.IGNORECASE))
        self.assertNotRegex(
            "launch.lnk",
            re.compile(executable_rule["KeywordRegex"], re.IGNORECASE))
        self.assertRegex(
            "launch.lnk",
            re.compile(shortcut_rule["KeywordRegex"], re.IGNORECASE))

    def test_recycle_bin_payload_rule(self):
        rule = self.rules[
            "Suspicious Location - Recycle Bin Executable or Script"]
        self.assertEqual(rule["Criticality"], "High")
        self.assertRegex(
            "payload.ps1",
            re.compile(rule["KeywordRegex"], re.IGNORECASE))
        self.assertRegex(
            r"C:\$Recycle.Bin\S-1-5-21-1\$R123\payload.ps1",
            re.compile(rule["PathRegex"], re.IGNORECASE))

    def test_double_extension_payload_rule(self):
        rule = self.rules["Masquerading - Double Extension Payload"]
        keyword = re.compile(rule["KeywordRegex"], re.IGNORECASE)
        path = re.compile(rule["PathRegex"], re.IGNORECASE)

        self.assertEqual(rule["Criticality"], "High")
        self.assertRegex("invoice.pdf.exe", keyword)
        self.assertRegex("photo.jpg.scr", keyword)
        self.assertNotRegex("report.pdf", keyword)
        self.assertNotRegex("archive.tar.gz", keyword)
        self.assertRegex(
            r"C:\Users\analyst\Downloads\invoice.pdf.exe", path)
        self.assertNotRegex(r"C:\Program Files\invoice.pdf.exe", path)

    def test_hexadecimal_and_guid_appdata_payload_rules(self):
        hex_rule = self.rules["Suspicious AppData Hexadecimal Payload"]
        guid_rule = self.rules["Suspicious AppData GUID Directory Payload"]
        hex_name = "0123456789abcdef0123456789abcdef.exe"
        hex_path = (
            r"C:\Users\analyst\AppData\Local"
            r"\0123456789abcdef0123456789abcdef"
            r"\0123456789abcdef0123456789abcdef.exe")
        guid_path = (
            r"C:\Users\analyst\AppData\Roaming"
            r"\{12345678-1234-1234-1234-123456789abc}\payload.dll")

        self.assertEqual(hex_rule["Criticality"], "Medium")
        self.assertRegex(
            hex_name,
            re.compile(hex_rule["KeywordRegex"], re.IGNORECASE))
        self.assertRegex(
            hex_path,
            re.compile(hex_rule["PathRegex"], re.IGNORECASE))
        self.assertNotRegex(
            "vendor.exe",
            re.compile(hex_rule["KeywordRegex"], re.IGNORECASE))

        self.assertEqual(guid_rule["Criticality"], "Medium")
        self.assertRegex(
            "payload.dll",
            re.compile(guid_rule["KeywordRegex"], re.IGNORECASE))
        self.assertRegex(
            guid_path,
            re.compile(guid_rule["PathRegex"], re.IGNORECASE))
        self.assertNotRegex(
            r"C:\Users\analyst\AppData\Roaming\Vendor\payload.dll",
            re.compile(guid_rule["PathRegex"], re.IGNORECASE))

    def test_ntds_database_rule_is_exact_and_user_scoped(self):
        rule = self.rules[
            "Credential Access - NTDS Database in User Profile"]
        keyword = re.compile(rule["KeywordRegex"], re.IGNORECASE)
        path = re.compile(rule["PathRegex"], re.IGNORECASE)

        self.assertEqual(rule["Criticality"], "High")
        self.assertRegex("ntds.dit", keyword)
        self.assertNotRegex("copy-ntds.dit", keyword)
        self.assertNotRegex("other.dit", keyword)
        self.assertRegex(
            r"C:\Users\analyst\Desktop\ntds.dit", path)
        self.assertNotRegex(
            r"C:\Windows\NTDS\ntds.dit", path)

    def test_generic_location_dump_rules_are_medium(self):
        high_rules = (
            "Suspicious Location - Public Executable or Script",
            "Suspicious Location - Local Temp Executable or Script",
            "Suspicious Location - ProgramData Root Executable or Script",
            "Suspicious Location - PerfLogs Executable or Script",
        )
        medium_rules = (
            "Suspicious Location - Public Archive Installer or Dump",
            "Suspicious Location - Local Temp Archive Installer or Dump",
            "Suspicious Location - ProgramData Root Archive Installer or Dump",
            "Suspicious Location - PerfLogs Archive Installer or Dump",
        )

        for name in high_rules:
            with self.subTest(name=name):
                rule = self.rules[name]
                self.assertEqual(rule["Criticality"], "High")
                self.assertNotRegex(
                    "crash.dmp",
                    re.compile(rule["KeywordRegex"], re.IGNORECASE))

        for name in medium_rules:
            with self.subTest(name=name):
                rule = self.rules[name]
                self.assertEqual(rule["Criticality"], "Medium")
                self.assertRegex(
                    "crash.dmp",
                    re.compile(rule["KeywordRegex"], re.IGNORECASE))

    def test_appdata_recommendation_samples_include_expected_match(self):
        samples = (
            (
                r"C:\Users\analyst\AppData\Local\Temp\svchost.exe",
                "svchost.exe",
                "Masquerading - Windows Binary Name in AppData",
            ),
            (
                r"C:\Users\analyst\Downloads\invoice.pdf.exe",
                "invoice.pdf.exe",
                "Masquerading - Double Extension Payload",
            ),
            (
                r"C:\Users\analyst\Desktop\ntds.dit",
                "ntds.dit",
                "Credential Access - NTDS Database in User Profile",
            ),
            (
                r"C:\Users\analyst\AppData\Local"
                r"\0123456789abcdef0123456789abcdef"
                r"\0123456789abcdef0123456789abcdef.exe",
                "0123456789abcdef0123456789abcdef.exe",
                "Suspicious AppData Hexadecimal Payload",
            ),
            (
                r"C:\Users\analyst\AppData\Roaming"
                r"\{12345678-1234-1234-1234-123456789abc}\payload.dll",
                "payload.dll",
                "Suspicious AppData GUID Directory Payload",
            ),
            (
                r"C:\Users\analyst\AppData\Update\payload.exe",
                "payload.exe",
                "Suspicious Location - Uncommon AppData Folder",
            ),
            (
                r"C:\Users\analyst\AppData\Roaming\Microsoft\Windows"
                r"\Start Menu\Programs\Startup\payload.exe",
                "payload.exe",
                "Persistence - User Startup Executable or Script",
            ),
            (
                r"C:\Users\analyst\AppData\Roaming\Microsoft\Windows"
                r"\Start Menu\Programs\Startup\launch.lnk",
                "launch.lnk",
                "Persistence - User Startup Shortcut",
            ),
            (
                r"C:\$Recycle.Bin\S-1-5-21-1\$R123\payload.ps1",
                "payload.ps1",
                "Suspicious Location - Recycle Bin Executable or Script",
            ),
            (
                r"C:\Users\analyst\AppData\Local\Temp\crash.dmp",
                "crash.dmp",
                "Suspicious Location - Local Temp Archive Installer or Dump",
            ),
        )

        for path, filename, expected in samples:
            matches = []
            for rule in self.rows:
                if rule["Scope"] not in ("MFT", "Both"):
                    continue
                if rule["EntryType"] not in ("File", "Any"):
                    continue
                if not re.search(
                        rule["KeywordRegex"], filename, re.IGNORECASE):
                    continue
                if not re.search(rule["PathRegex"], path, re.IGNORECASE):
                    continue
                if rule["IgnoreRegex"] and re.search(
                        rule["IgnoreRegex"], path, re.IGNORECASE):
                    continue
                matches.append(rule["Detection"])

            with self.subTest(path=path):
                self.assertTrue(matches)
                self.assertIn(expected, matches)

        local_temp_system_binary = (
            r"C:\Users\analyst\AppData\Local\Temp\svchost.exe")
        local_temp_matches = []
        for rule in self.rows:
            if rule["Scope"] not in ("MFT", "Both"):
                continue
            if not re.search(
                    rule["KeywordRegex"], "svchost.exe", re.IGNORECASE):
                continue
            if not re.search(
                    rule["PathRegex"], local_temp_system_binary,
                    re.IGNORECASE):
                continue
            if rule["IgnoreRegex"] and re.search(
                    rule["IgnoreRegex"], local_temp_system_binary,
                    re.IGNORECASE):
                continue
            local_temp_matches.append(rule["RuleID"])

        self.assertIn("DR-MFT-MASQ-001", local_temp_matches)
        self.assertIn(
            self.rules[
                "Suspicious Location - Local Temp Executable or Script"][
                    "RuleID"],
            local_temp_matches)

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
