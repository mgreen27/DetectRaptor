#!/usr/bin/python3
"""
This script adds a YARA rule set to Velociraptor YaraProcess artifacts.

Simply set variables and run the script.

"""

from pathlib import Path

from base_functions_yara import *

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
YARA_DIR = REPO_ROOT / "yara"
# set variables
windows_yar = 'windows_process.yar'
linux_yar = 'linux_process.yar'
macos_yar = 'macos_process.yar'
urls = [ # when testing Memory focused rules in all sets identical - reducing download for now
        #"https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
        #"https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
    ]


extract_dir = str(SCRIPT_DIR / "yara-forge-rules")
unsupported_modules = [ "hash", "dotnet", "console" ]

download_rules(urls,extract_dir)

target_files = []
for root, _, files in os.walk(extract_dir):
    for filename in fnmatch.filter(files, "*.yar"):
        target_files.append(os.path.join(root, filename))

for file in target_files:
    with open(file, 'r') as yara_file:
        lines = yara_file.readlines()

    cleaned_lines = [
        normalize_xor_ranges(normalize_string_escapes(line))
        for line in lines
        if not is_corrupted(line)
    ]
    with open(file, 'w') as yara_file:
        yara_file.writelines(cleaned_lines)

parser = plyara.Plyara()

for file in target_files:
    package = os.path.basename(file).split('.')[0].split('-')[-1]
    windows_path = str(YARA_DIR / f'{package}_{windows_yar}')
    linux_path = str(YARA_DIR / f'{package}_{linux_yar}')
    macos_path = str(YARA_DIR / f'{package}_{macos_yar}')

    with open(file, 'r') as data:
        parsed_rules = parser.parse_string(data.read())
        print(f"\n{len(parsed_rules)} total rules in {file}")

        parsed_rules = search_in_rules(parsed_rules, 'memory','file')
        parsed_rules = module_fix(parsed_rules, unsupported_modules)
        
        print(f"{len(parsed_rules)} inscope rules")

        windows_rules = find_windows(parsed_rules)
        linux_rules = find_linux(parsed_rules)
        macos_rules = find_macos(parsed_rules)


        # Write filtered rules to respective files
        for os_rules, output_path in [(windows_rules, windows_path), (linux_rules, linux_path), (macos_rules, macos_path)]:
            filtered_rules = ''
            print(f'{len(os_rules)} rules to be written to {output_path}')

            for i in find_modules_used(os_rules):
                filtered_rules = f'import "{i}"\n' + filtered_rules

            for rule in os_rules:
                filtered_rules += render_rule(rule)


            with open(output_path, 'w') as final_yara:
                final_yara.write(filtered_rules)
                print(f'\tWriting to: {output_path}')
                print(f'\tSHA1: {shasum(output_path)}')
parser.clear()
