#!/usr/bin/python3
"""
This script adds a YARA rule set to Velociraptor YARA glob artifacts.

Simply set variables and run the script.
"""

import os
import requests
import zipfile
import fnmatch
import plyara
import re

from base_functions import shasum  # Assuming this is defined in base_functions

def download_rules(urls,extract_dir):
    for root, _, files in os.walk(extract_dir):
        if any(filename.endswith(".yar") for filename in files):
            print(f"Using existing extracted rules in {extract_dir}")
            return

    for url in urls:
        filename = os.path.basename(url)

        if os.path.exists(filename):
            print(f"Using existing archive {filename}")
        else:
            response = requests.get(url)
            if response.status_code == 200:
                with open(filename, 'wb') as file:
                    file.write(response.content)
                print(f"Downloaded {filename}")
            else:
                print(f"Failed to download file: Status code {response.status_code}")
                continue

        # Extract files scope target files
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(filename, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)        

# remove lines plyara has issues
def is_corrupted(line):
    # Define the corrupted items
    corrupted_items = ['quality = -', 'score = -']
    # Check if the line contains any of the corrupted items
    return any(item in line for item in corrupted_items)


def normalize_string_escapes(line):
    # plyara rejects some valid YARA string escapes such as \r. Rewrite only
    # the unsupported single-escaped sequences inside double-quoted strings.
    unsupported = {
        'r': '\\x0d',
        'v': '\\x0b',
        'a': '\\x07',
    }

    def replace_string(match):
        content = match.group(1)
        normalized = []
        i = 0

        while i < len(content):
            ch = content[i]
            if ch != '\\':
                normalized.append(ch)
                i += 1
                continue

            slash_count = 1
            while i + slash_count < len(content) and content[i + slash_count] == '\\':
                slash_count += 1

            next_index = i + slash_count
            if next_index < len(content) and slash_count % 2 == 1:
                next_char = content[next_index]
                if next_char in unsupported:
                    normalized.append('\\' * (slash_count - 1))
                    normalized.append(unsupported[next_char])
                    i = next_index + 1
                    continue

            normalized.append('\\' * slash_count)
            i += slash_count

        return f'"{"".join(normalized)}"'

    return re.sub(r'"((?:[^"\\]|\\.)*)"', replace_string, line)


def normalize_xor_ranges(line):
    # Plyara accepts decimal xor ranges more reliably than hex literals.
    def replace_xor(match):
        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        return f"xor({start}-{end})"

    return re.sub(
        r'xor\(\s*0x([0-9a-fA-F]+)\s*-\s*0x([0-9a-fA-F]+)\s*\)',
        replace_xor,
        line,
    )

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


def module_fix(rules, unsupported_modules):
    matching_rules = []
    seen_rule_names = set()

    for rule in rules:
        rule_name = rule.get('rule_name', '').lower()
        local_imports = []
        unsupported = False

        for import_name in rule.get('imports', []):
            for condition in rule.get('condition_terms', []):
                if condition.startswith(import_name + '.'):
                    if import_name in unsupported_modules:
                        unsupported = True
                        break
                    if import_name not in local_imports:
                        local_imports.append(import_name)
            if unsupported:
                break 

        if unsupported:
            continue 

        rule['imports'] = local_imports
        if rule_name not in seen_rule_names:
            seen_rule_names.add(rule_name)
            matching_rules.append(rule)

    return matching_rules


def find_modules_used(rules):
    seen_modules = set()
    for rule in rules:
        for import_name in rule.get('imports', []):
            if import_name not in seen_modules:
                seen_modules.add(import_name)
    return seen_modules


def render_rule(rule):
    scopes = ' '.join(rule.get('scopes', []))
    scope_prefix = f"{scopes} " if scopes else ""
    tags = f" : {' '.join(rule['tags'])}" if rule.get('tags') else ""
    return (
        f"{scope_prefix}rule {rule['rule_name']}{tags} {{\n"
        f"    {rule.get('raw_meta', '')}{rule.get('raw_strings', '')}{rule['raw_condition']}"
        f"}}\n"
    )


def drop_memory_only(rules):
    matching_rules = []
    seen_rule_names = set()

    for rule in rules:
        rule_name = rule.get('rule_name', '').lower()
        tags = [tag.lower() for tag in rule.get('tags', [])]

        if any(tag != "memory" for tag in tags):
            if rule_name not in seen_rule_names:
                seen_rule_names.add(rule_name)
                matching_rules.append(rule)
            continue

        if 'memory' not in tags and rule_name not in seen_rule_names:
            seen_rule_names.add(rule_name)
            matching_rules.append(rule)

    return matching_rules


def find_windows(rules):
    matching_rules = []
    seen_rule_names = set()

    for rule in rules:
        rule_name = rule.get('rule_name', '').lower()
        metadata = rule.get('metadata', [])
        tags = [tag.lower() for tag in rule.get('tags', [])]
        imports = [i.lower() for i in rule.get('imports', [])]
        is_windows = False

        # Keep Linux/ELF-specific rules out of the Windows bundle even if the
        # rule was otherwise picked up by the broad fallback logic below.
        if any('elf' in import_name for import_name in imports):
            continue

        if any('linux' in tag or 'elf' in tag or 'macos' in tag or 'macho' in tag for tag in tags):
            continue

        if any(
            'linux' in str(value).lower() or ' elf ' in str(value).lower() or 'macos' in str(value).lower() or 'macho' in str(value).lower()
            for item in metadata
            for value in item.values()
        ):
            continue

        # Check for the search string in tags
        for tag in tags:
            if 'windows' in tag or 'pe' in tag:
                is_windows = True
                if rule_name not in seen_rule_names:
                    seen_rule_names.add(rule_name)
                    matching_rules.append(rule)
                break

        for i in imports:
            if 'pe' in i:
                is_windows = True
                if rule_name not in seen_rule_names:
                    seen_rule_names.add(rule_name)
                    matching_rules.append(rule)
                break
        
        if is_windows:
            continue

        if 'linux' in rule_name or '_elf' in rule_name or 'macos' in rule_name or 'macho' in rule_name:
            continue

        if 'eset_moose' in rule_name:
            continue

        if rule_name not in seen_rule_names:
            seen_rule_names.add(rule_name)
            matching_rules.append(rule)

    return matching_rules

def find_linux(rules):
    matching_rules = []
    seen_rule_names = set()

    for rule in rules:
        rule_name = rule.get('rule_name', '').lower()
        metadata = rule.get('metadata', [])
        tags = [tag.lower() for tag in rule.get('tags', [])]
        imports = [i.lower() for i in rule.get('imports', [])]
        is_linux = False

        # Check for the search string in tags
        for tag in tags:
            if 'linux' in tag or 'elf' in tag:
                is_linux = True
                if rule_name not in seen_rule_names:
                    seen_rule_names.add(rule_name)
                    matching_rules.append(rule)
                break

        for i in imports:
            if 'elf' in i:
                is_linux = True
                if rule_name not in seen_rule_names:
                    seen_rule_names.add(rule_name)
                    matching_rules.append(rule)
                break
        
        if is_linux:
            continue
        
        if 'linux' in rule_name or '_elf' in rule_name:
            if rule_name not in seen_rule_names:
                seen_rule_names.add(rule_name)
                matching_rules.append(rule)
            continue
        
        # Check for the search string in the metadata
        for item in metadata:
            for key, value in item.items():
                if 'linux' in str(value).lower() or ' elf ' in str(value).lower():
                    if rule_name not in seen_rule_names:
                        seen_rule_names.add(rule_name)
                        matching_rules.append(rule)
                    break
                elif key == 'os' and 'all' in str(value).lower():
                    if rule_name not in seen_rule_names:
                        seen_rule_names.add(rule_name)
                        matching_rules.append(rule)
                    break
                else:
                    continue

    return matching_rules


def find_macos(rules):
    matching_rules = []
    seen_rule_names = set()

    for rule in rules:
        rule_name = rule.get('rule_name', '').lower()
        metadata = rule.get('metadata', [])
        tags = [tag.lower() for tag in rule.get('tags', [])]
        imports = [i.lower() for i in rule.get('imports', [])]
        is_macos = False

        # Check for the search string in tags
        for tag in tags:
            if 'macos' in tag or 'macho' in tag:
                is_linux = True
                if rule_name not in seen_rule_names:
                    seen_rule_names.add(rule_name)
                    matching_rules.append(rule)
                break
        
        if is_macos:
            continue
        
        if 'macos' in rule_name or 'macho' in rule_name:
            if rule_name not in seen_rule_names:
                seen_rule_names.add(rule_name)
                matching_rules.append(rule)
            continue
        
        # Check for the search string in the metadata
        for item in metadata:
            for key, value in item.items():
                if 'macos' in str(value).lower() or ' macho ' in str(value).lower():
                    if rule_name not in seen_rule_names:
                        seen_rule_names.add(rule_name)
                        matching_rules.append(rule)
                    break

                elif key == 'os' and 'all' in str(value).lower():
                    if rule_name not in seen_rule_names:
                        seen_rule_names.add(rule_name)
                        matching_rules.append(rule)
                    break
                else:
                    continue
                break

    return matching_rules


def find_private(rules):
    private_rules = []
    not_private = []
    seen_rule_names = set()

    for rule in rules:
        rule_name = rule.get('rule_name', '').lower()
        scopes = [scope.lower() for scope in rule.get('scopes', [])]
        if 'private' in scopes:
            #print (rule_name,scopes)
            if rule_name not in seen_rule_names:
                seen_rule_names.add(rule_name)
                private_rules.append(rule)

        for condition in rule.get('condition_terms', []):
                if condition.lower() in seen_rule_names:
                    #print(rule_name,condition)
                    if rule_name not in seen_rule_names:
                        seen_rule_names.add(rule_name)
                        private_rules.append(rule)

        if rule_name not in seen_rule_names:
            seen_rule_names.add(rule_name)
            not_private.append(rule)

    return not_private, private_rules
