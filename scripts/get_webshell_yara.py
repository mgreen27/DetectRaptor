#!/usr/bin/python3
"""
This script adds a YARA rule set to a Velociraptor YaraWebshell artifact.

Simply set variables and run the script.

"""

from pathlib import Path

from base_functions_yara import *

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
YARA_DIR = REPO_ROOT / "yara"

# set variables
output_path = str(YARA_DIR / 'webshells.yar')
urls = ["https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"]
extract_dir = str(SCRIPT_DIR / "yara-forge-rules")
unsupported_modules = [ "hash", "dotnet", "console" ]

download_rules(urls,extract_dir)

parser = plyara.Plyara()
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

for file in target_files:
    with open(file, 'r') as data:
        parsed_rules = parser.parse_string(data.read())

        print(f"\n{len(parsed_rules)} total rules in {file}")
        parsed_rules = search_in_rules(parsed_rules, 'webshell','')
        parsed_rules = module_fix(parsed_rules, unsupported_modules)

        print(f"{len(parsed_rules)} inscope rules")

        filtered_rules = ''
        for i in find_modules_used(parsed_rules):
            filtered_rules = f'import "{i}"\n' + filtered_rules

        for rule in parsed_rules:
            filtered_rules += render_rule(rule)

        with open(output_path, 'w') as final_yara:
            final_yara.write(filtered_rules)
            print(f'\tWriting to: {output_path}')
            print(f'\tSHA1: {shasum(output_path)}')

parser.clear()
