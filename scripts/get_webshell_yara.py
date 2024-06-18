#!/usr/bin/python3
"""
This script Adds a yara rule set to a velociraptor WebshellYara artifact.

Simply set variables and run the script.

"""

from base_functions import *
import requests
import zipfile
import fnmatch
import plyara

# set variables
output_path = '../yara/webshells.yar'
url = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
filename = os.path.basename(url)
extract_dir = "yara-forge-rules"

filtered_rules = ''

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
    print(f"Extracted files to {extract_dir}")
target_files = []
for root, dirs, files in os.walk(extract_dir):
    for filename in fnmatch.filter(files, "*.yar"):
        # Print the full path of the .yar file
        target_files.append(os.path.join(root, filename))


# remove lines plyara has issues
def is_corrupted(line):
    # Define the corrupted items
    corrupted_items = ['quality = -', 'score = -']
    # Check if the line contains any of the corrupted items
    return any(item in line for item in corrupted_items)

for file in target_files:
    # Read the YARA file
    with open(file, 'r') as yara_file:
        lines = yara_file.readlines()

    cleaned_lines = [line for line in lines if not is_corrupted(line)]
    with open(file, 'w') as yara_file:
        yara_file.writelines(cleaned_lines)


#Function to search for the string in the rule names and metadata
def search_in_rules(rules, search_string):
    matching_rules = []
    for rule in rules:
        rule_name = rule.get('rule_name', '').lower()
        metadata = rule.get('metadata', [])

        if search_string in rule_name:
            matching_rules.append(rule)
            continue
        
        for item in metadata:
            for key, value in item.items():
                if search_string in str(value).lower():
                    matching_rules.append(rule)
                    break
            else:
                continue
            break

    return matching_rules


parser = plyara.Plyara()

for file in target_files:
    with open(file, 'r') as data:
        parsed_rules = parser.parse_string(data.read())
        matching_rules = search_in_rules(parsed_rules, 'webshell')

        for rule in matching_rules:
            try:
                # set import bool to add to rule later
                if 'pe' in rule['imports']:
                    pe = True
                if 'math' in rule['imports']:
                    math = True
            except:
                pass
            if rule.get('tags'):
                filtered_rules = filtered_rules + "rule %s : %s {\n    %s%s%s}\n" % (rule['rule_name'],' '.join(rule['tags']),rule['raw_meta'],rule['raw_strings'],rule['raw_condition'])
            else:
                filtered_rules = filtered_rules + "rule %s {\n    %s%s%s}\n" % (rule['rule_name'],rule['raw_meta'],rule['raw_strings'],rule['raw_condition'])

parser.clear()

if os.path.exists(filename):
    os.remove(filename)

if math:
    filtered_rules = 'import "math"\n' + filtered_rules
if pe:
    filtered_rules = 'import "pe"\n' + filtered_rules

filtered_rules = ['        ' + line.rstrip() for line in filtered_rules.splitlines()]
filtered_rules = ''.join([x + "\n" for x in filtered_rules])
print(filtered_rules)

with open(output_path, 'w') as final_yara:
    final_yara.write(filtered_rules)
    print('\tWriting to: ' + output_path)
    print('\tSHA1: ' + shasum(output_path))
