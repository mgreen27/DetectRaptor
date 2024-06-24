#!/usr/bin/python3
"""
This script Adds a yara rule set to a velociraptor ProcessYara artifacts.

Simply set variables and run the script.

"""

from base_functions import *
import requests
import zipfile
import fnmatch
import plyara

# set variables
windows_yar = 'windows_process.yar'
linux_yar = 'linux_process.yar'
macos_yar = 'macos_process.yar'
urls = [ # when testing Memory focused rules in all sets identical - reducing download for now
        #"https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
        #"https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
    ]


extract_dir = "yara-forge-rules"

# remove lines plyara has issues
def is_corrupted(line):
    # Define the corrupted items
    corrupted_items = ['quality = -', 'score = -']
    # Check if the line contains any of the corrupted items
    return any(item in line for item in corrupted_items)

# function to search for the string in the rule names and metadata
def search_in_rules(rules, search_string, tag_ignore):
    matching_rules = []
    seen_rule_names = set()
    search_string = search_string.lower()
    tag_ignore = tag_ignore.lower()

    for rule in rules:
        rule_name = rule.get('rule_name', '').lower()
        metadata = rule.get('metadata', [])
        tags = [tag.lower() for tag in rule.get('tags', [])]
        target_tag = False

        # Check for the search string in tags
        for tag in tags:
            if search_string in tag:
                target_tag = True
                if rule_name not in seen_rule_names:
                    seen_rule_names.add(rule_name)
                    matching_rules.append(rule)
                break
        
        if target_tag:
            continue
        
        # Skip rules with the tag to be ignored
        if tag_ignore in tags:
            continue
        
        # Check for the search string in the rule name
        if search_string in rule_name:
            if rule_name not in seen_rule_names:
                seen_rule_names.add(rule_name)
                matching_rules.append(rule)
            continue
        
        # Check for the search string in the metadata
        for item in metadata:
            for key, value in item.items():
                if search_string in str(value).lower():
                    if rule_name not in seen_rule_names:
                        seen_rule_names.add(rule_name)
                        matching_rules.append(rule)
                    break
            else:
                continue
            break

    return matching_rules

# function to filter out non matching rules
def filter_non_matching_rules(all_rules, *matching_rules_sets):
    matching_rules_ids = set()
    for rules_set in matching_rules_sets:
        matching_rules_ids.update(id(rule) for rule in rules_set)
    
    non_matching_rules = [rule for rule in all_rules if id(rule) not in matching_rules_ids]
    return non_matching_rules

for url in urls:
    filename = os.path.basename(url)

    response = requests.get(url)
    if response.status_code == 200:
        with open(filename, 'wb') as file:
            file.write(response.content)
        print(f"Downloaded {filename}")
    else:
        print(f"Failed to download file: Status code {response.status_code}")

    # Extract files scope target files
    os.makedirs(extract_dir, exist_ok=True)
    with zipfile.ZipFile(filename, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

target_files = []
for root, dirs, files in os.walk(extract_dir):
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
    windows_path = '../yara/' + package + '_' + windows_yar
    linux_path = '../yara/' + package + '_' + linux_yar
    macos_path = '../yara/' + package + '_' + macos_yar
    parsed_rules = matching_rules =  crossplatform_rules = []
    windows_rules = linux_rules = macos_rules = crossplatform_rules = []
    filtered_rules = ''

    with open(file, 'r') as data:
        parsed_rules = parser.parse_string(data.read())
        print(f"\n{len(parsed_rules)} total rules in {file}")

        matching_rules = search_in_rules(parsed_rules, 'memory','file')
        print(f"{len(matching_rules)} inscope rules")

        linux_rules= search_in_rules(matching_rules, 'linux','')
        macos_rules= search_in_rules(matching_rules, 'macos','')
        
        # We need a special case to find cross platform... not pretty but working
        for rule in matching_rules:
            metadata = rule.get('metadata', [])
            for item in metadata:
                for key, value in item.items():
                    if key == 'os' and 'all' in str(value).lower():
                        crossplatform_rules.append(rule)
                        break
                else:
                    continue

        windows_rules = filter_non_matching_rules(matching_rules,(linux_rules + macos_rules))
        linux_rules = linux_rules + crossplatform_rules
        macos_rules = macos_rules + crossplatform_rules

        for os_rules in [ (windows_rules,windows_path),(linux_rules,linux_path),(macos_rules,macos_path)]:
            output_path = os_rules[1]
            filtered_rules = ''
            print(f'{len(os_rules[0])} rules to be written to {output_path}')
            
            for rule in os_rules[0]:
                if rule.get('tags'):
                    filtered_rules = filtered_rules + "rule %s : %s {\n    %s%s%s}\n" % (rule['rule_name'],' '.join(rule['tags']),rule['raw_meta'],rule['raw_strings'],rule['raw_condition'])
                else:
                    filtered_rules = filtered_rules + "rule %s {\n    %s%s%s}\n" % (rule['rule_name'],rule['raw_meta'],rule['raw_strings'],rule['raw_condition'])

            filtered_rules = ['        ' + line.rstrip() for line in filtered_rules.splitlines()]
            filtered_rules = ''.join([x + "\n" for x in filtered_rules])
            #print(filtered_rules)

            with open(output_path, 'w') as final_yara:
                final_yara.write(filtered_rules)
                print('\tWriting to: ' + output_path)
                print('\tSHA1: ' + shasum(output_path))
parser.clear()
