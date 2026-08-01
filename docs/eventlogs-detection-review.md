# DetectRaptor Eventlogs detection review

> Scope: `/Users/matt/git/DetectRaptor/csv/Eventlogs.csv`, `DetectRaptor.Windows.Detection.Evtx`, and `DetectRaptor.Windows.Detection.Powershell.PSReadline`.

## Snapshot

- Source CSV: `/Users/matt/git/DetectRaptor/csv/Eventlogs.csv`
- CSV rows: **25**
- PowerShell-source rows: **16**
- Updated generator output for PSReadLine: **16** rows; selection is parsed from the `eventlog` column.
- Updated generator output for ISEAutoSave: **16** rows; it uses the same parsed-field selector.
- Checked-in `vql/*.yaml` files are intentionally left unchanged; the commit workflow regenerates them.
- CSV SHA-256: `adf5dbf0aa05ecc4837147550ac65a255cd7b31f9a22e7054e390e5e7e339f8e`

## How matching currently works

- EVTX passes each row to `Windows.EventLogs.EvtxHunter` as `EvtxGlob`, `IdRegex`, `IocRegex`, and `WhitelistRegex`.
- PSReadLine ignores `eventid`; it searches command-history lines with the same PowerShell rule and applies `ignore` against the complete command line.
- The `ignore` field is a suppression regex, not a contextual exception object. A broad match can hide malicious content anywhere in the event or command line.
- EVTX and PSReadLine currently share rules even though event XML/script-block content and interactive command history have different noise characteristics.

## Implementation status

1. **Completed:** Event ID 1102 searches `Security.evtx` and Event ID 104 searches `System.evtx` through one combined rule.
2. **Completed:** TcpClient rule ID corrected to `win_powershell_tcpsocket`.
3. **Completed:** PSReadLine and ISEAutoSave parse the CSV and select the `eventlog` field; `win_sus_service` is excluded.
4. **Completed:** Encoded-command matching requires a plausible Base64 payload.
5. **Completed:** Removed the redundant `win_powershell_large_b64` rule; `win_powershell_base64` covers `FromBase64String` usage.
6. **Completed:** Retired the broad SysWOW64 execution rule.
7. **Completed:** Retired the broad VHDMP rule that labelled user-profile virtual-disk activity as T1553.005.
8. **Completed:** Corrected `win_proxy_hunter` from ICS technique T0884 to Enterprise technique T1090.
9. **Completed:** Removed five broad alternatives from `win_powershell_suspicious_cmdlet` without merging the offensive-cmdlet rules.
10. **Completed:** Rebuilt `win_powershell_memoryloader` to require a primitive plus an execution/loading sink.

## Remaining structural findings

1. **High:** PSReadLine receives rules that depend on event-log context and ignores event IDs entirely.
2. **High:** Ordinary Hyper-V administration is still overstated as hidden virtual-instance activity.
3. **High:** PowerShell coverage is duplicated across base64, encoded command, generic keywords, memory loading and two offensive-cmdlet rules.
4. **Medium:** Whitelists are mostly product-name substrings. These can suppress malicious activity copied into, launched by or mentioning the trusted product.

## Rule summary

| # | ID | Source | Event IDs | Priority | Disposition | Whitelist |
|---:|---|---|---|---|---|---|
| 1 | `win_domain_trust_discovery_execution` | `security` | `^(4688\|4648)$` | Medium | Refine | None |
| 2 | `win_enumeration_execution` | `security` | `^(4688\|4648)$` | Medium | Refine | None |
| 3 | `win_exfiltration_programs` | `security` | `^(4688)$` | Medium | Refine | None |
| 4 | `win_syswow64_binaries` | `security` | `^(4688)$` | Completed | Retired | None |
| 5 | `win_eventlog_clear` | `{Security.evtx,System.evtx}` | `^(104\|1102)$` | Completed | Implemented | None |
| 6 | `win_sus_service` | `system.evtx` | `^(7045)$` | High | Refine | None |
| 7 | `win_disable_defender` | `defender` | `^(5001\|5010\|5012)$` | Low | Retain/rename | None |
| 8 | `win_sus_bitsjobs` | `bits` | `^(59\|60\|61)$` | Medium | Refine | Present |
| 9 | `win_vssadmin_execution` | `security` | `^(4688)$` | High | Refine | None |
| 10 | `win_ntdsutil_execution` | `security` | `^(4688)$` | Medium | Refine | None |
| 11 | `virtual_disk_mounted` | `VHDMP` | `^(1\|2\|12\|22\|23)$` | Completed | Retired | None |
| 12 | `win_powershell_web` | `powershell` | `^(4104)$` | Medium | Split by confidence | Present |
| 13 | `win_powershell_suspicious_keywords` | `powershell` | `^(200\|400\|800\|4100\|4103\|4104)$` | High | Split/deduplicate | Present |
| 14 | `win_powershell_base64` | `powershell` | `^(200\|400\|800\|4100\|4103\|4104)$` | Completed | Implemented | Present |
| 15 | `win_powershell_mimikatz` | `powershell` | `^(200\|400\|800\|4100\|4103\|4104)$` | High | Split by confidence | Present |
| 16 | `win_powershell_memoryloader` | `powershell` | `^(200\|400\|800\|4100\|4103\|4104)$` | Completed | Implemented | Present |
| 17 | `win_powershell_cobaltstrike_loader` | `powershell` | `^(200\|400\|800\|4100\|4103\|4104)$` | Medium | Strengthen | None |
| 18 | `win_powershell_malicious_cmdlets` | `powershell` | `^(200\|400\|800\|4100\|4103\|4104)$` | Medium | Retain/refine | Present |
| 19 | `win_powershell_tamper_with_windows_defender` | `powershell` | `^(200\|400\|800\|4100\|4103\|4104)$` | High | Correct syntax/expand | None |
| 20 | `win_proxy_hunter` | `{Powershell,Security,Sysmon}` | `.` | Critical | Rebuild | None |
| 21 | `win_powershell_tcpsocket` | `powershell` | `^(4103\|4104)$` | Completed | Implemented | Present |
| 22 | `win_powershell_dns` | `powershell` | `^(4103\|4104)$` | High | Split behaviours | Present |
| 23 | `win_powershell_downgrade` | `powershell` | `^(4103\|4104)$` | High | Tighten | Present |
| 24 | `win_powershell_suspicious_cmdlet` | `powershell` | `^(4103\|4104)$` | High | Broad terms removed | Present |
| 25 | `win_powershell_suspicious_keywords2` | `powershell` | `^(4103\|4104)$` | Critical | Split/reduce | Present |
| 26 | `win_powershell_encoded_command` | `powershell` | `^(4103\|4104)$` | Completed | Implemented | None |
| 27 | `win_powershell_hyperv` | `powershell` | `^(200\|400\|800\|4100\|4103\|4104)$` | High | Rename/contextualize | None |

## Complete rule-by-rule review

### 1. `win_domain_trust_discovery_execution`

- **Name:** T1482-Execution of Domain Trust Discovery Tools
- **Source selector:** `security`
- **Event IDs:** `^(4688|4648)$`
- **Review priority:** Medium
- **Disposition:** Refine

**Current detection regex**

```regex
adfind|adget|dsquery|nltest
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** Useful hunt, but bare `nltest` and substring matching are noisy and do not prove trust discovery.

**Proposed detection candidate**

```regex
\b(?:adfind|admod|adget|dsquery)(?:\.exe)?\b|\bnltest(?:\.exe)?\s+/(?:domain_trusts|dclist|dsgetdc|trusted_domains)\b
```

**Whitelist and implementation recommendation:** Do not add a global whitelist. If required, allowlist an exact signed administration script or management-system path.

### 2. `win_enumeration_execution`

- **Name:** T1046-Network and discovery tools
- **Source selector:** `security`
- **Event IDs:** `^(4688|4648)$`
- **Review priority:** Medium
- **Disposition:** Refine

**Current detection regex**

```regex
fscan.exe|netscan|nmap.exe|massscan.exe|SharpShares|PingCastle
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** `massscan.exe` appears to be a typo for `masscan.exe`; `netscan` may be authorized inventory software. Substrings lack process boundaries.

**Proposed detection candidate**

```regex
\b(?:fscan|nmap|masscan|SharpShares|PingCastle)(?:\.exe)?\b|\b(?:SoftPerfect\s+)?NetScan(?:\.exe)?\b
```

**Whitelist and implementation recommendation:** Allowlist approved scanner hashes, signer, deployment path, management host and change window; avoid excluding the product name globally.

### 3. `win_exfiltration_programs`

- **Name:** T1567.002-Execution of Exfiltration Programs
- **Source selector:** `security`
- **Event IDs:** `^(4688)$`
- **Review priority:** Medium
- **Disposition:** Refine

**Current detection regex**

```regex
meg\.exe|rclone|rsync|megacmd|megasync|megaclient
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** Tool presence is useful but `rsync` and cloud clients are not inherently exfiltration. Current rule omits common filename variants and command context.

**Proposed detection candidate**

```regex
\b(?:meg|MEGAcmd|MEGAsync|megaclient|rclone|rsync)(?:\.exe)?\b
```

**Whitelist and implementation recommendation:** Classify as tool execution first. Raise severity when command arguments contain remote destinations, copy/sync operations, config files, user-profile staging or unusual parents.

### 4. `win_syswow64_binaries`

- **Name:** T1567.002-Use of 32-bit LOLBINs
- **Source selector:** `security`
- **Event IDs:** `^(4688)$`
- **Review priority:** Completed
- **Disposition:** Retired

**Previous detection regex**

```regex
syswow64
```

**Previous whitelist / ignore regex**

```regex
<none>
```

**Assessment:** Any 32-bit process normally executes from `SysWOW64`. The ATT&CK mapping to T1567.002 is incorrect and expected noise will be extreme.

**Proposed detection candidate:** No direct one-line replacement.

**Implemented:** The broad row was removed from `csv/Eventlogs.csv`. Replace it only with specific suspicious SysWOW64 LOLBIN, parent-child, path masquerading or command-line behaviours.

### 5. `win_eventlog_clear`

- **Name:** T1070.001-Windows Event Log Cleared
- **Source selector:** `{Security.evtx,System.evtx}`
- **Event IDs:** `^(104|1102)$`
- **Review priority:** Completed
- **Disposition:** Implemented

**Current detection regex**

```regex
.
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** Event ID 1102 detects Security audit-log clearing. Event ID 104 detects event-log clearing recorded by `Microsoft-Windows-Eventlog` in the System channel. The collected `Channel` and `EventID` fields distinguish the two cases.

**Proposed detection candidate**

```regex
.
```

**Whitelist and implementation recommendation:** No global whitelist. Triage Event ID 104 using its cleared-log name and subject/process context because legitimate administrators and maintenance software may clear non-Security logs.

### 6. `win_sus_service`

- **Name:** T1543.003-Suspicious Windows Service Creation
- **Source selector:** `system.evtx`
- **Event IDs:** `^(7045)$`
- **Review priority:** High
- **Disposition:** Refine

**Current detection regex**

```regex
echo|COMSPEC|powershell|ADMIN\\$|C\\$|cmd\.exe|MiniDump|lsass\.exe|BTOBTO|Sliver
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** Event ID 7045 is useful, but `echo` is extremely broad and the rule does not constrain matches to the service image path.

**Proposed detection candidate**

```regex
(?:ImagePath|ServiceFileName).*(?:cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?|pwsh(?:\.exe)?|%COMSPEC%|\\\\ADMIN\$|\\\\C\$|MiniDump|lsass\.exe|BTOBTO|Sliver)
```

**Whitelist and implementation recommendation:** Use exact service name/image-path/signer allowlists for approved software. Do not globally suppress `cmd.exe`, PowerShell or administrative shares.

### 7. `win_disable_defender`

- **Name:** T1562.001-Win Defender Disabled
- **Source selector:** `defender`
- **Event IDs:** `^(5001|5010|5012)$`
- **Review priority:** Low
- **Disposition:** Retain/rename

**Current detection regex**

```regex
.
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** Event IDs 5001, 5010 and 5012 are valuable state-change telemetry, but the title should describe the exact Defender events rather than all Defender disablement.

**Proposed detection candidate**

```regex
.
```

**Whitelist and implementation recommendation:** No global whitelist. Track expected policy-management sources separately and retain visibility when protection state changes.

### 8. `win_sus_bitsjobs`

- **Name:** T1197-Suspicious BitsTransfer Activity
- **Source selector:** `bits`
- **Event IDs:** `^(59|60|61)$`
- **Review priority:** Medium
- **Disposition:** Refine

**Current detection regex**

```regex
\.(ps1|exe|rar|dll|7z|zip|bat|xyz|tk)
```

**Current whitelist / ignore regex**

```regex
edgedl.me.gvt1.com|oneclient\.sfx\.ms|\.dell\.com|download\.autodesk\.com|\.windowsupdate\.com|\.microsoft\.com/|\.adobe.com/
```

**Assessment:** Extension matching is useful but weak. Current domain ignores are broad and may hide abused trusted hosting or redirected content.

**Proposed detection candidate**

```regex
\.(?:ps1|exe|rar|dll|7z|zip|bat|xyz|tk)(?:[?&#\s]|$)
```

**Whitelist and implementation recommendation:** Anchor approved domains and paths precisely. Add destination path, creator process and transfer-command context; avoid blanket `microsoft.com` suppression.

### 9. `win_vssadmin_execution`

- **Name:** T1490-Delete Volume Shadow Copies
- **Source selector:** `security`
- **Event IDs:** `^(4688)$`
- **Review priority:** High
- **Disposition:** Refine

**Current detection regex**

```regex
vssadmin|bcdedit
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** Any `vssadmin` or `bcdedit` execution is not equivalent to deleting shadow copies. Require destructive arguments and include alternate tooling.

**Proposed detection candidate**

```regex
\b(?:vssadmin(?:\.exe)?\s+(?:delete\s+shadows|resize\s+shadowstorage)|wmic(?:\.exe)?.*shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+catalog|bcdedit(?:\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no)\b
```

**Whitelist and implementation recommendation:** Allowlist exact backup/restore workflows only after command-line review; do not suppress the executable globally.

### 10. `win_ntdsutil_execution`

- **Name:** T1003.003-Dumping of NTDS Database
- **Source selector:** `security`
- **Event IDs:** `^(4688)$`
- **Review priority:** Medium
- **Disposition:** Refine

**Current detection regex**

```regex
ntdsutil|NtdsAudit
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** `ntdsutil` is dual-use. Require IFM, snapshot or NTDS activation context; keep NtdsAudit visible as credential-access/review tooling.

**Proposed detection candidate**

```regex
\bntdsutil(?:\.exe)?\b.*(?:ifm|activate\s+instance\s+ntds|snapshot)|\bNtdsAudit(?:\.exe)?\b
```

**Whitelist and implementation recommendation:** Allowlist approved domain-controller maintenance commands and operators, not all `ntdsutil` execution.

### 11. `virtual_disk_mounted`

- **Name:** T1553.005-Subvert Trust Controls: Mark-of-the-Web Bypass
- **Source selector:** `VHDMP`
- **Event IDs:** `^(1|2|12|22|23)$`
- **Review priority:** Completed
- **Disposition:** Retired

**Previous detection regex**

```regex
C:\\Users\\.+
```

**Previous whitelist / ignore regex**

```regex
<none>
```

**Assessment:** Every VHD/VHDX mounted from a user path is labelled as MOTW bypass, but the event alone does not establish T1553.005.

**Proposed detection candidate**

```regex
C:\\Users\\[^\\]+\\.*\.(?:iso|vhd|vhdx)\b
```

**Implemented:** Removed the broad VHDMP row from `csv/Eventlogs.csv`. Normal user-profile virtual-disk activity does not establish Mark-of-the-Web bypass, so a Claude-specific whitelist is no longer required.

**Replacement recommendation:** Implement T1553.005 only as a correlated workflow using Internet-origin evidence, `Zone.Identifier` state, virtual-disk mounting and subsequent payload execution.

### 12. `win_powershell_web`

- **Name:** T1059.001-PowerShell Web Request
- **Source selector:** `powershell`
- **Event IDs:** `^(4104)$`
- **Review priority:** Medium
- **Disposition:** Split by confidence

**Current detection regex**

```regex
Invoke-WebRequest|iwr |wget |curl |Net.WebClient|Start-BitsTransfer
```

**Current whitelist / ignore regex**

```regex
Get-SystemDriveInfo|Function Get-Software|Windows Defender Advanced Threat Protection
```

**Assessment:** Aliases and web clients are common administration activity. Literal spaces miss punctuation and alternate syntax.

**Proposed detection candidate**

```regex
\b(?:Invoke-WebRequest|iwr|wget|curl|Start-BitsTransfer)\b|(?:New-Object\s+)?(?:System\.)?Net\.WebClient\b
```

**Whitelist and implementation recommendation:** Keep the existing product exclusions only if evidence-backed. High-confidence tier should require download-to-disk, execution, hidden window, user-writable destination or remote IP/domain context.

### 13. `win_powershell_suspicious_keywords`

- **Name:** T1059.001-Suspicious Powershell Commandlets
- **Source selector:** `powershell`
- **Event IDs:** `^(200|400|800|4100|4103|4104)$`
- **Review priority:** High
- **Disposition:** Split/deduplicate

**Current detection regex**

```regex
Invoke-Expression|-noP -sta -w 1 -enc |IEX |-W Hidden|-WindowStyle Hidden|-nop |127\.0\.0\.1|System\.Reflection\.AssemblyName|System\.Reflection\.Emit\.AssemblyBuilderAccess|System\.Runtime\.InteropServices\.MarshalAsAttribute|memorystream|SuspendThread|GzipStream
```

**Current whitelist / ignore regex**

```regex
\\\\windows\\\\sentinel\\\\|DisableUnusedSmb1.ps1|chocolatey|Windows Defender Advanced Threat Protection|Microsoft Intune Management Extension|AppData\\Local\\Temp\\SDIAG_|Posh-SSH\.(ps1|psm1)
```

**Assessment:** Mixes execution flags, loopback, reflection, compression and memory-loading primitives. Several terms duplicate dedicated rules and standalone `IEX` matching is weak.

**Proposed detection candidate**

```regex
(?:^|[\s;|])(?:IEX|Invoke-Expression)(?:\s|\()|-(?:nop|noP)\b|-W(?:indowStyle)?\s+Hidden\b|127\.0\.0\.1
```

**Whitelist and implementation recommendation:** Move reflection/memory terms to the memory-loader rule. Replace broad vendor exclusions with exact trusted paths or signed script identities.

### 14. `win_powershell_base64`

- **Name:** T1059.001-Use of Base64 Decode APIs
- **Source selector:** `powershell`
- **Event IDs:** `^(200|400|800|4100|4103|4104)$`
- **Review priority:** Completed
- **Disposition:** Implemented

**Current detection regex**

```regex
\bFromBase64String\s*\(
```

**Current whitelist / ignore regex**

```regex
struct LSA_ENUMERATION_INFORMATION|Windows Defender Advanced Threat Protection|AppData\\Local\\Temp\\SDIAG_
```

**Assessment:** The rule now detects the Base64 decode API only. Encoded-command switches are handled by the dedicated validated rule.

**Proposed detection candidate**

```regex
\bFromBase64String\s*\(
```

**Whitelist and implementation recommendation:** Existing path/product exclusions remain pending replay review; the obsolete `-Encoding UTF8` ignore was removed.

### 15. `win_powershell_mimikatz`

- **Name:** T1059.001-Mimikatz Execution via PowerShell
- **Source selector:** `powershell`
- **Event IDs:** `^(200|400|800|4100|4103|4104)$`
- **Review priority:** High
- **Disposition:** Split by confidence

**Current detection regex**

```regex
TOKEN_PRIVILE|SE_PRIVILEGE_ENABLED|mimikatz|lsass\.dmp|-dumpcr|SEKURLSA::Pth|kerberos::ptt|kerberos::golden
```

**Current whitelist / ignore regex**

```regex
\\\\windows\\\\sentinel\\\\|CIS_1.10.1_L1_Monitor.ps1|namespace PS_LSA|Windows Defender Advanced Threat Protection|AppData\\Local\\Temp\\SDIAG_
```

**Assessment:** `mimikatz`, `sekurlsa` and Kerberos module strings are strong. Generic token privilege structures are frequently present in legitimate source and security tooling.

**Proposed detection candidate**

```regex
\b(?:mimikatz|lsass\.dmp|sekurlsa::(?:logonpasswords|pth)|kerberos::(?:ptt|golden))\b
```

**Whitelist and implementation recommendation:** Move `TOKEN_PRIVILE` and `SE_PRIVILEGE_ENABLED` to a lower-confidence source-code rule. Scope Sentinel/CIS/Defender exclusions to exact trusted paths and versions.

### 16. `win_powershell_memoryloader`

- **Name:** T1059.001-Loading Powershell in Memory
- **Source selector:** `powershell`
- **Event IDs:** `^(200|400|800|4100|4103|4104)$`
- **Review priority:** Completed
- **Disposition:** Implemented

**Previous detection regex**

```regex
System\.Reflection\.AssemblyName|System\.Reflection\.Emit\.AssemblyBuilderAccess|System\.Runtime\.InteropServices\.MarshalAsAttribute|memorystream
```

**Current whitelist / ignore regex**

```regex
AppData\\Local\\Temp\\SDIAG_|Defender Advanced Threat Protection
```

**Assessment:** The previous single .NET type names matched generated modules and legitimate development activity. `MarshalAsAttribute` alone was especially noisy.

**Implemented detection regex**

```regex
(?:AssemblyBuilderAccess|Reflection\.Emit|MemoryStream)[\s\S]*(?:Assembly(?:\.Load|\]::Load)|CreateType|GetDelegateForFunctionPointer|VirtualAlloc)|(?:Assembly(?:\.Load|\]::Load)|CreateType|GetDelegateForFunctionPointer|VirtualAlloc)[\s\S]*(?:AssemblyBuilderAccess|Reflection\.Emit|MemoryStream)
```

**Implemented:** The rule now requires both a memory/reflection primitive and an execution or loading sink in either order. Standalone `MarshalAsAttribute` was removed.

**Remaining whitelist recommendation:** Keep only exact diagnostic/security product path exclusions after replay validation.

### 17. `win_powershell_cobaltstrike_loader`

- **Name:** T1059.001-Cobalt Strike Powershell Loader
- **Source selector:** `powershell`
- **Event IDs:** `^(200|400|800|4100|4103|4104)$`
- **Review priority:** Medium
- **Disposition:** Strengthen

**Current detection regex**

```regex
\$Doit|-bxor 35
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** `$Doit` and `-bxor 35` are fragile historical indicators and either string can occur independently.

**Proposed detection candidate**

```regex
(?s)(?:\$Doit.*-bxor\s+35|-bxor\s+35.*\$Doit)
```

**Whitelist and implementation recommendation:** No default whitelist. Supplement with current loader behaviours, decoded content, named pipes, network and process telemetry instead of relying on this signature alone.

### 18. `win_powershell_malicious_cmdlets`

- **Name:** T1059.001-Malicious Powershell Commandlets
- **Source selector:** `powershell`
- **Event IDs:** `^(200|400|800|4100|4103|4104)$`
- **Review priority:** Medium
- **Disposition:** Retain/refine

**Current detection regex**

```regex
Invoke-DllInjection|Invoke-Shellcode|Invoke-WmiCommand|Get-GPPPassword|Get-Keystrokes|Get-TimedScreenshot|Get-VaultCredential|Invoke-CredentialInjection|Invoke-Mimikatz|Invoke-NinjaCopy|Invoke-TokenManipulation|Out-Minidump|VolumeShadowCopyTools|Invoke-ReflectivePEInjection|Invoke-UserHunter|Invoke-ACLScanner|Invoke-DowngradeAccount|Get-ServiceUnquoted|Get-ServiceFilePermission|Get-ServicePermission|Invoke-ServiceAbuse|Install-ServiceBinary|Get-RegAutoLogon|Get-VulnAutoRun|Get-VulnSchTask|Get-UnattendedInstallFile|Get-ApplicationHost|Get-RegAlwaysInstallElevated|Get-Unconstrained|Add-RegBackdoor|Add-ScrnSaveBackdoor|Gupt-Backdoor|Invoke-ADSBackdoor|Enabled-DuplicateToken|Invoke-PsUaCme|Remove-Update|Check-VM|Get-LSASecret|Get-PassHashes|Show-TargetScreen|Port-Scan|Invoke-PoshRatHttp|Invoke-PowerShellTCP|Invoke-PowerShellWMI|Add-Exfiltration|Add-Persistence|Do-Exfiltration|Start-CaptureServer|Get-ChromeDump|Get-ClipboardContents|Get-FoxDump|Get-IndexedItem|Get-Screenshot|Invoke-Inveigh|Invoke-NetRipper|Invoke-EgressCheck|Invoke-PostExfil|Invoke-PSInject|Invoke-RunAs|MailRaider|New-HoneyHash|Set-MacAttribute|Invoke-DCSync|Invoke-PowerDump|Exploit-Jboss|Invoke-ThunderStruck|Invoke-VoiceTroll|Set-Wallpaper|Invoke-InveighRelay|Invoke-PsExec|Invoke-SSHCommand|Get-SecurityPackages|Install-SSP|Invoke-BackdoorLNK|PowerBreach|Get-SiteListPassword|Get-System|Invoke-BypassUAC|Invoke-Tater|Invoke-WScriptBypassUAC|PowerUp|PowerView|Get-RickAstley|Find-Fruit|HTTP-Login|Find-TrustedDocuments|Invoke-Paranoia|Invoke-WinEnum|Invoke-ARPScan|Invoke-PortScan|Invoke-ReverseDNSLookup|Invoke-SMBScanner|Invoke-Mimikittenz|Invoke-SessionGopher|Invoke-AllChecks|Start-Dnscat|Invoke-KrbRelayUp|Invoke-Rubeus|Invoke-Pandemonium|Invoke-Mongoose|Invoke-NETMongoose|Invoke-SecretsDump|Invoke-NTDS|Invoke-SharpRDP|Invoke-Kirby|Invoke-SessionHunter|Invoke-PrintNightmare|Invoke-Monkey365|Invoke-AzureHound|Kerberoast|Bloodhound|Sharphound
```

**Current whitelist / ignore regex**

```regex
\\\\windows\\\\sentinel\\\\|Get-SystemDriveInfo|Posh-SSH\.(ps1|psm1)|Microsoft System Center
```

**Assessment:** The explicit offensive-function list is valuable, but 4104 also records module/function definitions, not only execution. This list overlaps `win_powershell_suspicious_cmdlet`, but the rules remain separate.

**Proposed detection candidate:** No direct one-line replacement.

**Whitelist and implementation recommendation:** Keep as “offensive PowerShell content present,” add token boundaries and distinguish function definitions from invocation where possible. Narrow all product ignores to exact paths.

### 19. `win_powershell_tamper_with_windows_defender`

- **Name:** T1562.001-Win Defender Disable using Powershell
- **Source selector:** `powershell`
- **Event IDs:** `^(200|400|800|4100|4103|4104)$`
- **Review priority:** High
- **Disposition:** Correct syntax/expand

**Current detection regex**

```regex
Set-MpPreference -DisableRealtimeMonitoring|Set-MpPreference DisableBehaviorMonitoring|Set-MpPreference -DisableScriptScanning|Set-MpPreference -DisableBlockAtFirstSeen|MpPreference -ExclusionPath
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** One pattern omits the parameter hyphen and the rule does not consistently require a disabling value. Exclusion changes should remain visible.

**Proposed detection candidate**

```regex
\bSet-MpPreference\b.*(?:-DisableRealtimeMonitoring\s+(?:\$true|1)|-DisableBehaviorMonitoring\s+(?:\$true|1)|-DisableScriptScanning\s+(?:\$true|1)|-DisableBlockAtFirstSeen\s+(?:\$true|1)|-ExclusionPath\b)
```

**Whitelist and implementation recommendation:** No broad whitelist. Correlate approved management parent, signed script, account and policy source while retaining the event.

### 20. `win_proxy_hunter`

- **Name:** T1090-Proxy
- **Source selector:** `{Powershell,Security,Sysmon}`
- **Event IDs:** `.`
- **Review priority:** Critical
- **Disposition:** Rebuild

**Current detection regex**

```regex
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5} :\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}:socks
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** The ATT&CK mapping is now T1090. The current regex still only detects unusual chained `IP:port:IP` strings, and the mixed eventlog selector complicates collection.

**Proposed detection candidate**

```regex
\b(?:socks[45]?|https?)://[^\s]+|\b(?:-Proxy|-ProxyServer)\s+\S+|\b(?:chisel|ligolo|gost|frpc|ssh)\b.*\b(?:socks|proxy|-[DR])\b
```

**Implemented mapping:** Changed the detection name and EVTX notebook filter to `T1090-Proxy`.

**Remaining implementation recommendation:** Split PowerShell, Security and Sysmon source rows so event IDs and context can be tuned independently, then expand detection to explicit proxy syntax and known tunnelling tools.

### 21. `win_powershell_tcpsocket`

- **Name:** C2-Powershell Socket Connection
- **Source selector:** `powershell`
- **Event IDs:** `^(4103|4104)$`
- **Review priority:** Completed
- **Disposition:** Implemented

**Current detection regex**

```regex
Net\.Sockets\.TCPClient
```

**Current whitelist / ignore regex**

```regex
\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\Downloads\\PSScript_.+\.ps1
```

**Assessment:** The malformed ID was corrected. The current TcpClient content expression remains intentionally unchanged in this batch.

**Proposed detection candidate**

```regex
(?:System\.)?Net\.Sockets\.TcpClient\s*\(|New-Object\s+(?:System\.)?Net\.Sockets\.TcpClient\b
```

**Whitelist and implementation recommendation:** Narrow the Defender exclusion to an exact trusted path plus expected signer/version; enrich with remote endpoint and subsequent stream activity in a later change.

### 22. `win_powershell_dns`

- **Name:** Powershell potential DNS disruption
- **Source selector:** `powershell`
- **Event IDs:** `^(4103|4104)$`
- **Review priority:** High
- **Disposition:** Split behaviours

**Current detection regex**

```regex
Add-DnsClientNrptRule|New-NetRoute|drivers\\etc\\hosts
```

**Current whitelist / ignore regex**

```regex
Microsoft\.PowerShell\.Cmdletization\.MethodParameter
```

**Assessment:** `Add-DnsClientNrptRule`, `New-NetRoute` and hosts-file modification are different behaviours. `New-NetRoute` is not DNS disruption.

**Proposed detection candidate:** No direct one-line replacement.

**Whitelist and implementation recommendation:** Create separate NRPT, route-change and hosts-file-write rules. For hosts, require a write primitive plus `drivers\etc\hosts`. Keep generated Cmdletization definitions in a narrowly scoped low-confidence exclusion.

### 23. `win_powershell_downgrade`

- **Name:** Powershell potential downgrade attack
- **Source selector:** `powershell`
- **Event IDs:** `^(4103|4104)$`
- **Review priority:** High
- **Disposition:** Tighten

**Current detection regex**

```regex
-ve*r*s*i*o*n*\s+2|powershell -version
```

**Current whitelist / ignore regex**

```regex
Microsoft Azure AD Sync
```

**Assessment:** The obfuscation regex is malformed for the intended purpose and `powershell -version` matches versions other than 2.

**Proposed detection candidate**

```regex
(?:powershell(?:\.exe)?\s+)?-(?:version|v)\s+2(?:\.0)?\b
```

**Whitelist and implementation recommendation:** Remove blanket Azure AD Sync suppression. If needed, whitelist an exact signed script/path and retain EngineVersion 2 telemetry as high confidence.

### 24. `win_powershell_suspicious_cmdlet`

- **Name:** Powershell Suspicious CommandLet - IN DEVELOPMENT
- **Source selector:** `powershell`
- **Event IDs:** `^(4103|4104)$`
- **Review priority:** High
- **Disposition:** Broad terms removed

**Current detection regex**

```regex
Add-Exfiltration|Add-Persistence|Add-RegBackdoor|Add-ScrnSaveBackdoor|Check-VM|Do-Exfiltration|Enabled-DuplicateToken|Exploit-Jboss|Find-Fruit|Find-GPOLocation|Find-TrustedDocuments|Get-ApplicationHost|Get-ChromeDump|Get-ClipboardContents|Get-FoxDump|Get-GPPPassword|Get-IndexedItem|Get-Keystrokes|LSASecret|Get-PassHash|Get-RegAlwaysInstallElevated|Get-RegAutoLogon|Get-RickAstley|Get-Screenshot|Get-SecurityPackages|Get-ServiceFilePermission|Get-ServicePermission|Get-ServiceUnquoted|Get-SiteListPassword|Get-System|Get-TimedScreenshot|Get-UnattendedInstallFile|Get-Unconstrained|Get-VaultCredential|Get-VulnAutoRun|Get-VulnSchTask|Gupt-Backdoor|HTTP-Login|Install-SSP|Install-ServiceBinary|Invoke-ACLScanner|Invoke-ADSBackdoor|Invoke-ARPScan|Invoke-AllChecks|Invoke-BackdoorLNK|Invoke-BypassUAC|Invoke-CredentialInjection|Invoke-DCSync|Invoke-DllInjection|Invoke-DowngradeAccount|Invoke-EgressCheck|Invoke-Inveigh|Invoke-InveighRelay|Invoke-Mimikittenz|Invoke-NetRipper|Invoke-NinjaCopy|Invoke-PSInject|Invoke-Paranoia|Invoke-PortScan|Invoke-PoshRat|Invoke-PostExfil|Invoke-PowerDump|Invoke-PowerShellTCP|Invoke-PsExec|Invoke-PsUaCme|Invoke-ReflectivePEInjection|Invoke-ReverseDNSLookup|Invoke-RunAs|Invoke-SMBScanner|Invoke-SSHCommand|Invoke-Service|Invoke-Shellcode|Invoke-Tater|Invoke-ThunderStruck|Invoke-Token|Invoke-UserHunter|Invoke-VoiceTroll|Invoke-WScriptBypassUAC|Invoke-WinEnum|MailRaider|New-HoneyHash|Out-Minidump|Port-Scan|PowerBreach|PowerUp|PowerView|Remove-Update|Set-MacAttribute|Set-Wallpaper|Show-TargetScreen|Start-CaptureServer|VolumeShadowCopyTools|CachedRDPConnection|invoke-\S+hunter|get-\S+(credent|password)|Kerberos.*(policy|ticket)|netfirewall|Uninstall-Windows|Verb\s+Runas|AmsiBypass|nishang|Invoke-Interceptor|EXEonRemote|NetworkRelay|PowerShelludp|PowerShellIcmp|CreateShortcut|copy-vss|invoke-dll|invoke-mass|out-shortcut
```

**Current whitelist / ignore regex**

```regex
\\\\windows\\\\sentinel\\\\|Microsoft Azure AD Sync|Lenovo.ThinkPad
```

**Assessment:** The explicit offensive functions remain. The broad alternatives `get-net\S+`, `(Computer|User)Property`, `Install-Service`, `remoteps` and `NEEEEWWW` have been removed.

**Implemented:** Removed only the five requested broad alternatives. The rule was not merged with `win_powershell_malicious_cmdlets`; specific entries such as `Install-ServiceBinary` remain.

**Remaining recommendation:** Add token boundaries and distinguish function definitions from invocation where practical. Retain the two offensive-cmdlet rules separately.

### 25. `win_powershell_suspicious_keywords2`

- **Name:** Suspicious Powershell Keywords2 - IN DEVELOPMENT
- **Source selector:** `powershell`
- **Event IDs:** `^(4103|4104)$`
- **Review priority:** Critical
- **Disposition:** Split/reduce

**Current detection regex**

```regex
bitstransfer|mimik|metasp|AssemblyBuilderAccess|Reflection\.Assembly|shellcode|injection|cnvert|shell\.application|Rc4ByteStream|lsass\.exe|localadmin|LastLoggedOn|hijack|BackupPrivilege|ngrok|comsvcs|backdoor|brute.?force|Port.?Scan|Exfiltration|exploit|DisableRealtimeMonitoring|beacon
```

**Current whitelist / ignore regex**

```regex
\\\\windows\\\\sentinel\\\\|Microsoft Azure AD Sync|# Remote Desktop Management Localization File|Microsoft System Center 2025|New-remoteConnectorCertificate.ps1
```

**Assessment:** Generic words such as `injection`, `localadmin`, `hijack`, `exploit`, `beacon` and `backdoor` frequently occur in documentation, modules and security products.

**Proposed detection candidate:** No direct one-line replacement.

**Whitelist and implementation recommendation:** Split strong operational indicators (`comsvcs`, `lsass.exe`, `ngrok`, `DisableRealtimeMonitoring`) from weak vocabulary. Narrow Defender generated-module suppression to the `MSFT_MpPreference` class definition; never globally suppress operational `Set-MpPreference` commands.

### 26. `win_powershell_encoded_command`

- **Name:** T1059.001-Powershell encoded command
- **Source selector:** `powershell`
- **Event IDs:** `^(4103|4104)$`
- **Review priority:** Completed
- **Disposition:** Implemented

**Current detection regex**

```regex
(?:^|\s)-(?:e|en|enc|enco|encod|encode|encodedcommand)\s+['"]?[A-Za-z0-9+\/]{16,}={0,2}['"]?(?:\s|$)
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** The rule now requires a supported encoded-command abbreviation followed by a plausible Base64 payload, preventing `-End` and `-Encoding` false matches.

**Proposed detection candidate**

```regex
(?:^|\s)-(?:e|en|enc|enco|encod|encode|encodedcommand)\s+['"]?[A-Za-z0-9+/]{16,}={0,2}['"]?(?:\s|$)
```

**Whitelist and implementation recommendation:** Keep exact approved payload hashes as local classifications, not global exclusions.

### 27. `win_powershell_hyperv`

- **Name:** T1564.006 Hide Artifacts: Run Virtual Instance
- **Source selector:** `powershell`
- **Event IDs:** `^(200|400|800|4100|4103|4104)$`
- **Review priority:** High
- **Disposition:** Rename/contextualize

**Current detection regex**

```regex
FeatureName:(microsoft-hyper-v|microsoft-hyper-v-Management-clients)|Start-VM|import-vm
```

**Current whitelist / ignore regex**

```regex
<none>
```

**Assessment:** `Start-VM` and `Import-VM` are normal Hyper-V administration and do not establish hidden execution. Current mapping overstates confidence.

**Proposed detection candidate:** No direct one-line replacement.

**Whitelist and implementation recommendation:** Rename to Hyper-V administration activity and assign low confidence, or require suspicious VM/image paths, unexpected user, remote origin, newly imported VM, and follow-on network/process activity.

## Current PSReadLine rule set

The generated artifact currently embeds the following 16 rows:

- `win_powershell_web`
- `win_powershell_suspicious_keywords`
- `win_powershell_base64`
- `win_powershell_mimikatz`
- `win_powershell_memoryloader`
- `win_powershell_cobaltstrike_loader`
- `win_powershell_malicious_cmdlets`
- `win_powershell_tamper_with_windows_defender`
- `win_proxy_hunter`
- `win_powershell_tcpsocket`
- `win_powershell_dns`
- `win_powershell_downgrade`
- `win_powershell_suspicious_cmdlet`
- `win_powershell_suspicious_keywords2`
- `win_powershell_encoded_command`
- `win_powershell_hyperv`

## Proposed whitelist model

1. Keep the repository CSV focused on globally safe exclusions only.
2. Put customer/site-specific exceptions in a separate overlay CSV keyed by rule ID.
3. Prefer exact path + signer/hash + parent process + account constraints over product-name substrings.
4. Record owner, justification, evidence, scope and expiry for every local whitelist.
5. Replay both malicious positive fixtures and known-benign negative fixtures before accepting an ignore.
6. Report suppressed-hit counts so a whitelist cannot silently eliminate a rule.

## Remaining recommended implementation order

1. Add token boundaries and invocation context to the two retained offensive-cmdlet rules.
2. Split generic PowerShell keyword rules into strong operational indicators and low-confidence vocabulary.
3. Reclassify the Hyper-V rule; the broad SysWOW64 and VHDMP/MOTW rules are retired.
4. Replace product-name whitelists with scoped local overlays and add suppression metrics.

## Validation requirements

- Parse all CSV rows and compile `eventid`, `rule` and `ignore` expressions with RE2-compatible syntax.
- Generate EVTX and PSReadLine artifacts from source and verify them with the bundled Velociraptor binary.
- Assert PSReadLine contains only explicitly designated PSReadLine-compatible rows.
- Add positive and negative fixtures for every changed regex.
- Replay against IR1502 and compare hit count, host count, suppression count and retained confirmed-interesting samples.
- Manually inspect a bounded sample of every new whitelist before promotion.
