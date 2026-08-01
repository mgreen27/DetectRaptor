# DetectRaptor MFT detection uplift

> Scope: `csv/MFT.csv`,
> `DetectRaptor.Windows.Detection.MFT`, and the shared Amcache lookup data.

## Objective

Reduce broad filename noise while retaining attributable executable, service,
driver, and product-directory indicators. This document records completed
changes and remaining structural work.

Generated `vql/*.yaml` files are intentionally unchanged locally. The GitHub
Actions build regenerates them from the CSV and template sources.

## Evidence used

A sanitized enterprise MFT hunt sample contained **3,668 findings across 59
hosts**. The four Phase 1 detections contributed **1,038** findings:

| Detection | Previous | Retained | Main noise source |
|---|---:|---:|---|
| Data Transfer - FileZilla | 477 | 15 | Translation files, icons and configuration |
| VPN | 317 | 24 | Icons, source packages, logs and documentation |
| RMM - General / Product Directory | 95 | 0 | Visual Studio TestWindow RemoteAgent components |
| Credential Theft and ProcDump | 149 | 28 | Azure Monitor Agent bundled ProcDump |

Server-side replay of the completed rules against the same stored results
retained **67 findings** across these detections. This is a point-in-time
tuning result, not a production suppression guarantee.

## Completed changes

### CSV integrity and validation

- Repaired the malformed Komari row.
- Added `scripts/validate_mft.py`.
- MFT and Amcache generation now fail when the shared CSV is invalid.
- Validation covers CSV shape, required fields, criticality, regex syntax,
  global ignore expressions, whitespace, and duplicate case-insensitive
  alternatives.

### FileZilla

Replaced the broad `FileZilla` substring with exact client, portable, server,
helper, and administration executable filenames. Translation files, icons,
configuration files and directories no longer match.

### VPN

Replaced product-name substrings with high-confidence Windows executable,
service and driver filenames for the existing VPN product set. Icons,
JavaScript packages, documentation, logs and browser-storage directories no
longer match.

### RMM product directories

Replaced `RMM - General` with `RMM - Product Directory`.

- Removed the generic `RemoteAgent` term.
- Anchored Meraki, Trend Micro BaseCamp, AB Tutor, Datto, SolarWinds RMM and
  Naverisk basenames.
- Existing dedicated Datto and Naverisk executable rules remain in place.
- Phase 2 subsequently added strict `IsDir` directory semantics.

### ProcDump

- Split ProcDump from the mixed `Credential Theft` rule.
- Added exact ProcDump executable and DLL basenames.
- Added an exact path exclusion for copies bundled with Microsoft Azure Monitor
  Agent, including x86, x64 and ARM64 packages.
- ProcDump outside the trusted bundle path remains visible.

### Analyst output

Added the rule `Reference` field to the MFT detection result dictionary.

### Notebook corrections

- Corrected the Defence Evasion filter spelling and target field.
- Corrected the folder-grouping query comma syntax.

## Phase 2: scope and entry-type semantics

Phase 2 added two required CSV fields:

| Field | Values | Purpose |
|---|---|---|
| `Scope` | `MFT`, `Amcache`, `Both` | Selects which artifact consumes the rule |
| `EntryType` | `File`, `Directory`, `Any` | Controls MFT file-versus-directory matching |

Current classification:

| Scope | Entry type | Rules |
|---|---|---:|
| Both | File | 278 |
| MFT | File | 11 |
| MFT | Directory | 12 |
| Amcache | File | 2 |

Completed implementation:

- MFT loads only `MFT` and `Both` rules.
- MFT requires `NOT IsDir` for `File` rules and `IsDir` for `Directory`
  rules.
- Amcache loads only `Amcache` and `Both` rules and excludes directory rules.
- Scope and entry type are included in analyst output.
- Execution Path, Impacket path and Suspicious Location rules are MFT-only.
- Explicit product-name directory indicators are MFT-only directory rules.
- Mixed RealVNC and VNC rows were split into file and directory detections.
- CSV validation rejects unsupported values and directory rules outside MFT
  scope.

Legacy rules that represent executable or original-file basenames remain
`Both,File`, even when the regex omits an extension. They can be reclassified
later when reliable product-specific evidence shows that they represent
directories.

## Phase 3: path-aware tuning

Phase 3 separates file presence from execution evidence and adds location
context without globally suppressing all installed tools.

### Quick Assist

- Amcache retains the exact Quick Assist filename as execution evidence.
- MFT reports Quick Assist only outside WindowsApps, component servicing,
  WinSxS, System32, SysWOW64 and Windows upgrade component paths.
- Entries with unresolved MFT parent paths remain visible.

Stored-result replay reduced Quick Assist MFT findings from **378 to 123**. The
retained results had unresolved parent paths and require analyst review.

### Archive utilities

The previous global archive-utility rule was split into:

- Amcache execution evidence outside Program Files.
- MFT user, public, PerfLogs and Recycle Bin staging.
- MFT Windows temporary staging with exact exclusions for NuGetScratch and
  observed Autodesk package extraction paths.

SourceTree and Autodesk web-deployment embedded archive utilities are excluded
only from the user-staging rule. Stored-result replay reduced MFT archive
findings from **418 to 13**.

### Enumeration tools

- Replaced broad product substrings with exact scanner filenames.
- Split network/AD scanners, BloodHound tooling, and Nmap/Everything.
- Translation files, icons, spreadsheets, logs and product directories no
  longer match.

Stored-result replay reduced enumeration findings from **207 to 24**.

Across Quick Assist, archive utilities and enumeration tools, Phase 3 reduced
the comparable MFT findings from **1,003 to 160**.

### RMM context and approval overlay

MFT and Amcache now emit:

- `LocationContext`: `Installed`, `User or temporary`, `ProgramData`, `System`,
  `Unresolved`, or `Other`.
- `RMMDisposition`: `Approved`, `Review`, or `Not applicable`.

Operators can supply both `ApprovedRMMNameRegex` and `ApprovedRMMPathRegex`.
Matching results are marked approved but are not suppressed. This preserves a
complete RMM inventory while supporting environment-specific disposition.

New notebook queries summarize RMM by location and prioritize unapproved
portable, user, temporary, unresolved and other paths.

Across the stored sample, the previous RMM findings were distributed as:

| Location context | Findings |
|---|---:|
| Installed | 649 |
| System | 212 |
| Unresolved | 176 |
| User or temporary | 50 |
| Other | 12 |
| ProgramData | 5 |

## Phase 4: Suspicious Location redesign

The previous single Suspicious Location rule had a malformed AppData depth
expression and combined unrelated path and file classes. It was replaced with
separate path and file-class detections:

1. Public executable and script files at High.
2. Public archives, installers and dumps at Medium.
3. User Local AppData Temp executable and script files at High.
4. User Local AppData Temp archives, installers and dumps at Medium.
5. Executables and scripts directly under the Local or Roaming AppData root.
6. Archives and installers directly under the Local or Roaming AppData root.
7. Executables and scripts directly under the ProgramData root at High.
8. ProgramData root archives, installers and dumps at Medium.
9. PerfLogs executable and script files at High.
10. PerfLogs archives, installers and dumps at Medium.

Known industrial and engineering vendor content under Users Public is excluded
with explicit path expressions for Autodesk, KUKA, Matrox Imaging, Aurora,
FabImage, MATRIX VISION, EPLAN and the observed project-content root. These
are path-specific suppressions rather than global vendor-name exclusions.

Stored-result replay reduced the previous **635** Suspicious Location findings
to **3**:

- One executable directly under ProgramData.
- One installer under Users Public downloaded installations.
- One executable under an unrecognized Users Public vendor directory.

The new Local Temp, AppData root and PerfLogs rules require validation in a
fresh post-deployment hunt because the previous malformed AppData rule did not
collect a representative comparison set.

An additional notebook query surfaces SI/FN creation or modification timestamp
differences for the new Suspicious Location detections.

### AppData root follow-up

A subsequent sanitized multi-client review showed that recursively treating
scripts, dumps and archives anywhere under Roaming AppData as High generated
293 findings:

- 132 known application crash dumps;
- 94 developer or editor scripts;
- 40 application resource archives;
- 27 residual scripts or archives.

No reviewed match was a file directly under the Local or Roaming AppData root.
The broad Roaming rule was therefore retired. Local and Roaming now use the
same shallow root-file logic:

- executable or script directly under either root: High;
- archive or installer directly under either root: Medium;
- nested application content: no generic suspicious-location classification.

Local AppData Temp remains separate because it represents a different,
higher-risk staging context. Generic dump files are Medium because MFT does
not provide the process context needed to distinguish malicious process dumps
from application crash reporting.

### AppData and user-profile follow-up

The remaining AppData recommendations were implemented as focused rules rather
than another recursive catch-all:

- **Uncommon AppData sibling:** High for payloads under an immediate AppData
  subtree other than `Local`, `LocalLow`, or `Roaming`.
- **Windows binary-name masquerading:** High when selected Windows system
  executable or DLL basenames occur anywhere beneath a user AppData path.
- **Per-user Startup persistence:** High for executable or script payloads;
  Medium for shortcuts because the shortcut target still requires resolution.
- **Hexadecimal AppData payload:** Medium when both the AppData directory and
  executable or DLL basename use long hexadecimal components.
- **GUID-like AppData directory payload:** Medium for executable or script
  content beneath a GUID-shaped Local or Roaming directory.
- **Double-extension payload:** High for executable or script files under a
  user profile that masquerade behind a document, image, or archive extension.
- **Recycle Bin payload:** High for executable or script files staged beneath
  `$Recycle.Bin`.
- **User-profile NTDS database:** High for the exact `ntds.dit` basename under
  a user profile. Generic `.dit` files are no longer treated as equivalent.

The higher-specificity rules are ordered before the generic one-letter
filename rule. This is required while the current artifact returns only the
first matching lookup row.

The rule concepts were cross-checked against the Neo23x0 `signature-base`
filename indicators and Sigma file-event detection methodology. Patterns were
adapted to MFT capabilities: no process-creation or creator-process condition
was assumed, and broad dump-file severity was reduced accordingly. Exact
upstream rule text was not copied.

## Combined stored-result replay

Applying the completed MFT rules to the **3,668** stored hunt rows retained
**1,198** and suppressed **2,470**, a **67% reduction** in the comparable result
set.

The replay identified **27 rows matching more than one rule**. The current
artifact still returns only the first matching rule, which confirms the Phase 5
requirement to preserve or aggregate all matching RuleIDs.

## Phase 5: rule metadata and multi-match output

Phase 5 introduced stable identity and complete rule-match reporting.

### Rule metadata

Every MFT CSV row now includes:

| Field | Purpose |
|---|---|
| `RuleID` | Immutable `DR-MFT-<CATEGORY>-NNN` identifier |
| `Category` | Consistent analyst grouping |
| `Technique` | Optional ATT&CK mapping where the rule is unambiguous |
| `Confidence` | Rule precision: High, Medium, Low, or Unreviewed |
| `Source` | DetectRaptor, internal, or upstream rule origin |
| `SourceID` | Optional upstream identifier, including LOLRMM tool slugs |

All current rows have unique RuleIDs. Initial legacy rules without sufficient
precision review were marked `Unreviewed`; Phase 8 subsequently normalized
the remaining confidence values.

`scripts/assign_mft_metadata.py` assigns metadata to new rows while preserving
all existing RuleIDs. `scripts/validate_mft.py` rejects missing, malformed, or
duplicate IDs and invalid confidence or ATT&CK values.

### Multi-match results

The MFT artifact no longer uses `LIMIT 1` when enriching a file against the
rule table. Each file-to-rule match is emitted as a separate flat result row,
preserving complete metadata for CSV export, VQL analysis, and SIEM ingestion.

Filename regexes are deduplicated only for the initial MFT collection filter.
The complete rule table is retained for enrichment so rules sharing the same
`KeywordRegex` are not discarded.

The **File match summary** notebook groups results by `Fqdn` and `OSPath` and
aggregates:

- RuleIDs;
- detection names;
- categories;
- techniques;
- confidence values;
- criticalities.

Including `Fqdn` prevents identical paths on different endpoints from being
merged in hunt notebooks. Within each endpoint, `OSPath` is the file grouping
key.

Amcache consumes the same metadata fields. Its existing single-match behavior
has not yet been changed.

## Phase 6: LOLRMM alignment

`csv/lolrmm.csv` is now the authoritative source for generated RMM filename
coverage.

- `scripts/sync_mft_lolrmm.py` extracts safe Windows filename indicators.
- Full paths contribute their basename when the basename is sufficiently
  specific.
- DLL indicators require a product-specific basename token. Generic library
  names remain visible in `FilteredFilenameRegex` for review but do not
  generate detections.
- Linux/macOS-only, directory-only, empty, invalid, or generic wildcard
  indicators are excluded.
- Duplicate upstream records are merged by SourceID.
- Known source aliases for Quick Assist, Remote Utilities, LiteManager, and
  UltraVNC are canonicalized.
- `csv/MFT_RMM_IDs.csv` preserves RuleIDs across upstream refreshes.
- `csv/MFT_RMM_Overrides.csv` retains directory rules, artifact-specific
  Quick Assist behavior, local additions, and filename coverage absent from
  current upstream data.
- `csv/MFT_RMM_Coverage.csv` records every generated, excluded, or overridden
  source.

Current output contains 243 generated LOLRMM rules, 27 curated overrides, and
54 explicitly excluded upstream records without a safe Windows filename
indicator.

### Post-hunt DLL and Local Temp tuning

A sanitized running-hunt review found that generic LOLRMM DLL basenames were
dominated by operating-system and unrelated vendor packages. The generator now
filters `libeay32.dll`, `ssleay32.dll`, `fd_agent.dll`, `IDComponent.dll`,
`Software Matt.dll`, and `sas.dll`. Product-specific DLL names such as
`echoware.dll` and the Lunixar DLL family remain covered. Existing executable,
installer, script, service, and driver indicators are unaffected.

The generic Local Temp executable/script rule now matches only files directly
under `AppData\Local\Temp`. Nested package extraction trees are excluded from
that generic rule. Nested malware must be detected by a specific filename,
masquerading, RMM, persistence, or other behavior rule. This is an intentional
noise-versus-coverage tradeoff and is enforced with a negative replay fixture.

## Phase 7: generic filename-rule review

The path-independent tool families were reviewed and tightened:

- 63 curated rules were anchored or otherwise constrained.
- Attacker-tool filenames now require explicit basename and extension
  boundaries.
- Data Transfer and Defence Evasion duplicate names were split into
  attributable detections.
- Broad supporting-file matches such as `.config`, documentation, icons, and
  log suffixes no longer match the reviewed rules.
- PowerScan and PsMapExec script alternatives are individually anchored.
- Archive utility names were reduced to known executable basenames.

Positive and negative regression tests enforce these filename boundaries.

## Phase 8: confidence, severity, and scope normalization

`scripts/normalize_mft_metadata.py` applies the metadata policy after every
LOLRMM refresh:

- no rules remain `Unreviewed`;
- exact reviewed filename indicators are High confidence;
- wildcard or broader indicators are Medium confidence;
- RMM presence remains Medium criticality;
- directory rules are MFT-only;
- RMM rules map to T1219, with Quick Assist using T1219.002;
- selected credential access, defence evasion, discovery, execution,
  persistence, masquerading, tunnelling, and impact rules have explicit
  ATT&CK mappings.

`csv/MFT_Metadata_Summary.csv` reports confidence, criticality, scope, and
ATT&CK coverage by category.

## Phase 9: replay and regression framework

Phase 9 adds two complementary regression layers:

- `tests/fixtures/mft_replay.csv` contains 23 sanitized positive and negative
  MFT and Amcache cases.
- `tests/fixtures/mft_expected.csv` defines exact, required, and forbidden
  RuleID expectations.
- `scripts/replay_mft.py` reproduces scope, entry-type, filename, path, and
  ignore-regex matching and retains every matching rule.
- Candidate rules can be compared with `--baseline-rules`; the comparison
  reports Added, Removed, and Unchanged matches by CaseID and RuleID.
- `scripts/build_mft_replay_coverage.py` generates one deterministic synthetic
  positive per rule in `csv/MFT_Replay_Coverage.csv`.
- All 368 current rules have a verified synthetic positive. Forty generated
  cases also match another rule; `AdditionalRuleIDs` preserves those overlaps
  for collision review.

Synthetic positives prove that rules remain reachable under the implemented
matching semantics. They do not prove that a detection is malicious, precise,
or operationally low-noise. Manual fixtures and stored hunt-result replay are
still required for those decisions.

Replay output is written only when an explicit output path is supplied. This
avoids implicit use of `/tmp` and supports CSV-based offline analysis.

## Phase 10: path-aware whitelisting

Phase 10 adds auditable suppression after rule matching:

- `csv/MFT_Whitelist.csv` stores WhitelistID, RuleID, artifact, filename,
  path, reason, source, and review date.
- `scripts/validate_mft_whitelist.py` rejects unknown rules, duplicate
  RuleID/artifact policies, broad regexes, invalid scope combinations, and
  unanchored or insufficiently specific paths. Expired review dates fail
  validation.
- MFT and Amcache build an in-memory whitelist index using RuleID and artifact.
- Filename and path must both match before a result is suppressed.
- Suppression is applied to each RuleID match independently. Another rule
  matching the same OSPath remains visible.
- `SuppressWhitelisted` defaults to true. Disabling it emits retained and
  suppressed rows with the matching policy metadata for audit.
- Replay reports raw, retained, and suppressed match counts and can write
  suppressed rows to a separate CSV.

The existing Quick Assist trusted-component exclusion was migrated from the
rule's opaque `IgnoreRegex` into `DR-MFT-WL-001`. Quick Assist outside those
paths remains visible, and Amcache execution evidence is not suppressed.
Customer-specific RMM approvals remain runtime overlays.

Phase 10 validation covers one trusted-path suppression, unusual-path
retention, Amcache retention, and preservation of unrelated RuleID matches on
the same file.

## Phase 11: performance and analyst workflow

Phase 11 adds measurable match expansion and analyst-facing pivots:

- `scripts/benchmark_mft_replay.py` benchmarks the sanitized fixtures plus one
  generated positive per rule.
- Replay now reports unique file records separately from unique path strings
  and total rule matches.
- The whitelist table is indexed once and retrieved once per rule match.
- Amcache no longer stops at the first matching rule. It now preserves the
  same multi-match behavior as MFT.
- MFT and Amcache emit flattened RuleID, detection, category, technique,
  confidence, criticality, source, filename, and path fields while retaining
  the nested Detection dictionary.
- Operational metric notebooks separate rule matches, unique endpoint paths,
  multi-match endpoint paths, and endpoints.
- Rule/path prevalence and whitelist suppression audit views were added.
- RMM summaries now include RuleID, SourceID, endpoint context, disposition,
  location context, and an example path.
- An exact-path MFT/Amcache correlation view was added.
- A normalized cross-artifact pivot stacks MFT, Amcache, BinaryRename, EVTX,
  and PSReadLine evidence by endpoint, path, and event time.

The benchmark covers 391 cases and 368 rules, or 143,888 estimated rule
evaluations per iteration. Exact match and timing metrics are regenerated
during validation because they vary with rule tuning and development-host
performance.

## Current acceptance state

- Every supported LOLRMM Windows indicator is represented or explicitly
  excluded with a documented reason.
- Curated overrides survive upstream refreshes.
- Replay reports unique files separately from total rule matches.
- Whitelist changes have positive and negative regression evidence.
- MFT and Amcache rendered artifacts pass local Velociraptor verification.
- Production hunt runtime and result-size comparison remains an operational
  deployment check after GitHub Actions rebuilds the generated artifacts.

## Validation

Run:

```bash
python scripts/sync_mft_lolrmm.py
python scripts/normalize_mft_metadata.py
python scripts/assign_mft_metadata.py --check
python scripts/validate_mft.py
python scripts/validate_mft_whitelist.py
python scripts/build_mft_replay_coverage.py
python scripts/replay_mft.py --check
python scripts/benchmark_mft_replay.py --iterations 3
python -m unittest discover -s tests -v
```

Generate and verify MFT and Amcache artifacts before release. Review result
counts and retained examples against the same endpoint population after each
tuning phase.
