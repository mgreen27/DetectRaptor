# DetectRaptor
A repository to share publicly available bulk Velociraptor detection content in an easy to consume way.

Simply take the release [VQL zip](https://github.com/mgreen27/DetectRaptor/releases/download/DetectRaptor/DetectRaptorVQL.zip)
and import it into Velociraptor.  

This is made easy via the Velociraptor artifact exchange: [Server.Import.DetectRaptor](https://docs.velociraptor.app/exchange/artifacts/pages/detectraptor/)
1. Import Velociraptor Artifact Exchange
   Server Artifacts > + Server.Import.ArtifactExchange
![image](https://github.com/user-attachments/assets/b826c858-5e55-4896-a382-d58f2c7d8b96)

This should import the "Import DetectRaptor" artifact.

2. Import DetectRaptor
   Server Artifacts > + Exchange.Server.Import.DetectRaptor
![image](https://github.com/user-attachments/assets/d75ade94-455d-40a1-94be-ea45b8e0fa30)


Current artifacts include:
- DetectRaptor.Windows.Detection.Amcache
- DetectRaptor.Windows.Detection.Applications
- DetectRaptor.Windows.Detection.BinaryRename
- DetectRaptor.Windows.Detection.Bootloaders
- DetectRaptor.Windows.Detection.Evtx
- DetectRaptor.Windows.Detection.HijackLibsEnv
- DetectRaptor.Windows.Detection.HijackLibsMFT
- DetectRaptor.Windows.Detection.Powershell.ISEAutoSave
- DetectRaptor.Windows.Detection.LolDriversMalicious
- DetectRaptor.Windows.Detection.LolDriversVulnerable
- DetectRaptor.Windows.Detection.Yara.LolDrivers
- DetectRaptor.Windows.Detection.LolRMM
- DetectRaptor.Windows.Detection.MFT
- DetectRaptor.Windows.Detection.NamedPipes
- DetectRaptor.Windows.Registry.NetworkProvider
- DetectRaptor.Windows.Detection.Powershell.PSReadline
- DetectRaptor.Windows.Detection.Webhistory
- DetectRaptor.Generic.Detection.YaraFile
- DetectRaptor.Linux.Detection.YaraProcessLinux
- DetectRaptor.Macos.Detection.YaraProcessMacos
- DetectRaptor.Windows.Detection.YaraProcessWin
- DetectRaptor.Generic.Detection.YaraWebshell
- DetectRaptor.Windows.Detection.ZoneIdentifier

Server artifacts:
- DetectRaptor.Server.StartHunts
- DetectRaptor.Server.ManageContent

Some contributing repositories:
- https://github.com/svch0stz/velociraptor-detections
- https://www.bootloaders.io/
- https://hijacklibs.net/
- https://www.loldrivers.io/
- https://www.lolrmm.io/
- https://github.com/SigmaHQ/sigma
- https://yarahq.github.io/

## Validation

Run the Eventlogs, PSReadLine, and MFT regression tests from the repository
root:

```bash
python -m unittest discover -s tests -v
```

Validate the MFT detection CSV directly:

```bash
python scripts/sync_mft_lolrmm.py
python scripts/normalize_mft_metadata.py
python scripts/assign_mft_metadata.py --check
python scripts/validate_mft.py
python scripts/validate_mft_whitelist.py
python scripts/build_mft_replay_coverage.py
python scripts/replay_mft.py --check
python scripts/benchmark_mft_replay.py --iterations 3
```

When adding an MFT rule, leave the generated metadata fields empty and run:

```bash
python scripts/assign_mft_metadata.py
```

This assigns an immutable `DR-MFT-<CATEGORY>-NNN` RuleID and baseline
category, confidence, source, and ATT&CK metadata. Existing RuleIDs are
preserved.

`sync_mft_lolrmm.py` regenerates LOLRMM-backed MFT rules from
`csv/lolrmm.csv`, preserving IDs through `csv/MFT_RMM_IDs.csv` and applying
`csv/MFT_RMM_Overrides.csv`. `normalize_mft_metadata.py` then applies the
reviewed confidence, severity, scope, and ATT&CK policy.

`build_mft_replay_coverage.py` creates a deterministic synthetic positive for
every MFT rule and records overlapping rule matches in
`csv/MFT_Replay_Coverage.csv`. `replay_mft.py --check` evaluates the sanitized
positive and negative fixtures under `tests/fixtures/`. It can also compare a
candidate rules file with a baseline using `--baseline-rules`, and write
detailed match, comparison, and summary output to explicitly selected paths.

`csv/MFT_Whitelist.csv` contains built-in path-aware suppression policies.
Policies require an exact RuleID and artifact plus matching filename and path
regexes. `SuppressWhitelisted` is enabled by default in MFT and Amcache;
disable it to audit suppressed rows and their WhitelistID metadata. Local or
customer-specific RMM approvals remain runtime parameters and are not
committed to the repository.

`benchmark_mft_replay.py` combines the sanitized fixtures with one generated
positive per rule. It reports raw, retained, and suppressed matches; unique
files and path strings; multi-match expansion; estimated rule evaluations; and
runtime. Additional replay-format CSV inputs may be supplied with `--input`.
Benchmark JSON is written only when `--output` is explicitly provided.

Regenerate the affected artifacts from `scripts/`:

```bash
cd scripts
python evtx.py
python psreadline.py
python iseautosave.py
python mft.py
python amcache.py
```

Verify the generated artifacts with Velociraptor:

```bash
./velociraptor artifacts verify \
  vql/Evtx.yaml \
  vql/PSReadline.yaml \
  vql/ISEAutoSave.yaml \
  vql/MFT.yaml
```

## Detection uplift notes

- `docs/eventlogs-detection-review.md`
- `docs/mft-detection-uplift.md`
