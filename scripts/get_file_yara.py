#!/usr/bin/python3
"""
This script adds a YARA rule set to a Velociraptor YaraFile artifact.

Simply set variables and run the script.
"""
import gzip
import io
import shutil

from base_functions_yara import *

# Set variables
windows_yar = 'windows_file.yar'
linux_yar = 'linux_file.yar'
macos_yar = 'macos_file.yar'
urls = [
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
]
extract_dir = "./yara-forge-rules"
unsupported_modules = [ "hash", "dotnet", "console" ]

download_rules(urls,extract_dir)

target_files = []
for root, _, files in os.walk(extract_dir):
    for filename in fnmatch.filter(files, "*.yar"):
        target_files.append(os.path.join(root, filename))

for file in target_files:
    with open(file, 'r') as yara_file:
        lines = yara_file.readlines()

    cleaned_lines = [line for line in lines if not is_corrupted(line)]
    with open(file, 'w') as yara_file:
        yara_file.writelines(cleaned_lines)

parser = plyara.Plyara()

for file in target_files:
    package = os.path.basename(file).split('.')[0].split('-')[-1]
    windows_path = f'../yara/{package}_{windows_yar}'
    linux_path = f'../yara/{package}_{linux_yar}'
    macos_path = f'../yara/{package}_{macos_yar}'

    with open(file, 'r') as data:
        parsed_rules = parser.parse_string(data.read())
        print(f"\n{len(parsed_rules)} total rules in {file}")

        # find rules in scope
        parsed_rules = module_fix(parsed_rules, unsupported_modules)
        parsed_rules = drop_memory_only(parsed_rules)

        print(f"{len(parsed_rules)} inscope rules")

        #parsed_rules,private_rules = find_private(parsed_rules) # drops private rules for now... these are sometimes multi OS.

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
                # hacky fix for private rule with conflict
                if 'windows' in output_path:
                    if '(AVASTTI_EXE_PRIVATE or AVASTTI_ELF_PRIVATE)' in rule['raw_condition']:
                        rule['raw_condition'] = rule['raw_condition'].replace('(AVASTTI_EXE_PRIVATE or AVASTTI_ELF_PRIVATE)','AVASTTI_EXE_PRIVATE')
                    if 'pe.number_of_signatures' in rule['raw_condition']:
                        print(f"Dropping {rule['rule_name']}: pe.number_of_signatures issue (currently working on a fix)" )
                        continue
                    if 'ESET_Not_Ms_PRIVATE' in rule['raw_condition']:
                        print(f"Dropping {rule['rule_name']}: pe.number_of_signatures issue (currently working on a fix)" )
                        continue

                if rule.get('tags'):
                    filtered_rules += f"rule {rule['rule_name']} : {' '.join(rule['tags'])} {{\n    {rule.get('raw_meta','')}{rule.get('raw_strings','')}{rule['raw_condition']}}}\n"
                else:
                    filtered_rules += f"rule {rule['rule_name']} {{\n    {rule.get('raw_meta','')}{rule.get('raw_strings','')}{rule['raw_condition']}}}\n"

            with open(output_path, 'w') as final_yara:
                final_yara.write(filtered_rules)
            print(f'\tWriting to: {output_path}\t\tSHA1: {shasum(output_path)}')

            try:
                gz_path = output_path + '.gz'

                # Open the input file for reading in binary mode
                with open(output_path, 'rb') as output_yara:
                    with gzip.open(gz_path, 'wb') as gz_file:
                        gz_file.writelines(output_yara)
                print(f'\tWriting to: {gz_path}\tSHA1: {shasum(gz_path)}')                

            except:
                continue

    # finally copy yara forge to yara folder for licence reference
    shutil.copy(file, '../yara/' + os.path.basename(file))


parser.clear()

