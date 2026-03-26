# AGENTS.md

## Repo Purpose
- `DetectRaptor` publishes Velociraptor detection artifacts and supporting IOC/YARA data.
- The main deliverables are generated YAML artifacts in `vql/` and a release zip containing those artifacts.
- Most of the repo is generator input (`templates/`, `csv/`, external feeds) plus Python scripts that rebuild the generated outputs.

## Repository Layout
- `scripts/`: Python generators. Most scripts read a template plus CSV/YARA input and write one or more files into `vql/`, `csv/`, or `yara/`.
- `templates/`: VQL templates with insertion markers. Treat these as source files.
- `csv/`: Mixed source and generated IOC data. Static lists like `MFT.csv` are maintained here; other files such as `bootloaders.csv`, `drivers_*.csv`, `hijacklibs.csv`, and `lolrmm.csv` are regenerated from external feeds.
- `yara/`: Generated or imported YARA bundles used by YARA artifacts.
- `vql/`: Generated Velociraptor artifacts. Do not hand-edit unless you are deliberately breaking the generator flow.
- `.github/workflows/`: Scheduled and push-triggered regeneration jobs.

## Source Of Truth
- Prefer editing `templates/`, `scripts/`, and intentionally curated CSV inputs.
- Treat `vql/*.yaml` as generated output.
- Treat these as generated unless there is a clear reason not to:
  - `csv/bootloaders.csv`
  - `csv/drivers_malicious.csv`
  - `csv/drivers_vulnerable.csv`
  - `csv/hijacklibs.csv`
  - `csv/lolrmm.csv`
  - `yara/webshells.yar`
  - `yara/full_*`
  - `vql/*.yaml`

## Local Workflow
- Run generator scripts from `scripts/`, not from the repo root. Most scripts use relative paths like `../templates/...` and `../vql/...`.
- Typical pattern:
  - `cd scripts`
  - `python amcache.py`
  - `python applications.py`
- If you need to rebuild multiple artifacts, follow the same grouping used by the GitHub Actions workflows instead of inventing a new sequence.
- `scripts/starthunts.py` depends on the current contents of `vql/`; run it after the other artifact generators so it can enumerate the latest artifact names.

## Python Dependencies
- Core dependencies used across workflows: `PyYAML`, `requests`, `pandas`, `regex`, `plyara`, and for file-YARA generation `yara-python`.
- `YaraFile.yaml` workflow also installs Ubuntu build packages before `yara-python`.
- There is no pinned local project environment in the repo. If you need repeatable local execution, mirror the versions used in `.github/workflows/`.

## GitHub Actions
- `.github/workflows/ZipVQL.yaml`
  - Trigger: push to `master`
  - Purpose: rebuilds the template/CSV-driven artifacts that do not require remote IOC feeds beyond the checked-in inputs.
  - Runs: `amcache.py`, `applications.py`, `binaryrename.py`, `evtx.py`, `iseautosave.py`, `mft.py`, `namedpipes.py`, `psreadline.py`, `webhistory.py`, `zoneidentifier.py`, `starthunts.py`
  - Then auto-commits updated `vql/*.yaml`, zips them, and refreshes the `DetectRaptor` release.
- `.github/workflows/OtherProjects.yaml`
  - Trigger: weekly Sunday schedule plus manual dispatch
  - Purpose: refreshes external IOC projects and rebuilds the affected artifacts.
  - Runs: `bootloaders.py`, `hijacklibs.py`, `loldrivers.py`, `loldrivers_yara.py`, `lolrmm.py`
  - Auto-commits regenerated `vql/*.yaml` and `csv/*.csv`, then refreshes the release zip.
- `.github/workflows/YaraProcess.yaml`
  - Trigger: weekly Sunday schedule plus manual dispatch
  - Purpose: downloads YARA Forge process-oriented rules, filters them per OS, writes `yara/full_*_process.yar`, then rebuilds the YARA process VQL artifacts with `yaraprocess.py`.
  - Auto-commits regenerated `vql/*.yaml` and `yara/*.yar`, then refreshes the release zip.
- `.github/workflows/Webshell.yaml`
  - Trigger: weekly Sunday schedule plus manual dispatch
  - Purpose: downloads YARA Forge rules, extracts webshell-related rules with `get_webshell_yara.py`, then embeds them into `YaraWebshell.yaml` via `yarawebshell.py`.
  - Auto-commits regenerated `vql/*.yaml` and `yara/*.yar`, then refreshes the release zip.
- `.github/workflows/YaraFile.yaml`
  - Trigger: weekly Sunday schedule plus manual dispatch
  - Purpose: downloads YARA Forge file-oriented rules, filters them per OS, writes `yara/full_*_file.yar.gz`, and updates `yara/yara-rules-full.yar`.
  - Auto-commits only the YARA outputs. This workflow does not rebuild the release zip because the checked-in `vql/YaraFile.yaml` is static and downloads the gzipped rule files from the repository at runtime.

## External Data Feeds
- `bootloaders.py`: `bootloaders.io` API
- `hijacklibs.py`: `hijacklibs.net` CSV API
- `loldrivers.py`: `loldrivers.io` API
- `loldrivers_yara.py`: LOLDrivers YARA files from GitHub
- `lolrmm.py`: `lolrmm.io` API
- `get_memory_yara.py`, `get_file_yara.py`, `get_webshell_yara.py`: YARA Forge release zip from GitHub

## Editing Rules
- Avoid hand-editing generated `vql/` files unless the task is explicitly about a generated artifact snapshot.
- If an artifact looks wrong, fix the template or generator script and regenerate.
- Keep output naming aligned with the current generator behavior. Several scripts derive output filenames from the YAML `name` field.
- Be careful with broad file patterns in the workflows. Scheduled jobs commit whatever matches their `file_pattern`.

## Validation
- There is no formal test suite in this repo.
- Minimum safe checks after changes:
  - Run the affected generator script(s) from `scripts/`
  - Confirm expected output files changed
  - Sanity-check generated YAML headers in `vql/`
  - If you touched Python, run `python -m py_compile scripts/*.py`
- After each execution, update the results, review what changed, and iterate on improvements when the output is incomplete or low quality.
- If generation requires network access and you cannot run it, state that explicitly in your summary.

## Repo-Specific Warnings
- The workflows assume the default branch is `master`.
- Some scripts fetch large external archives and may leave extracted directories like `scripts/yara-forge-rules/` or zip files behind.
- `scripts/get_*_yara.py` rewrite downloaded `.yar` files in place before producing final outputs.
- The current YARA cleanup step also normalizes some rule syntax for compatibility, including rewriting hex-form XOR ranges like `xor(0x01-0xff)` to decimal form. Treat that as a temporary fix rather than a permanent normalization rule.
