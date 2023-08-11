#!/usr/bin/python3
"""
This script downloads yara for velociraptor artifacts and normalises 
ready for use.

"""
import requests
import sys
import re
import os
import yaml


# set variables
target_url = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar'
output_path = '../yara/webshells.yar'


if __name__ == "__main__":
    print('Preparing yara download')
    response = requests.get(target_url)

    if response.status_code == 200:
        content = response.content.decode('ascii', errors='ignore')
        
        # remove multiline patterns
        pattern_multiline = r'/\*.*?\*/'
        content = re.sub(pattern_multiline, '', content, flags=re.DOTALL)

        # remove all but basic metadata
        lines_to_remove = [
            r'^\s*hash[\d]* = "[a-fA-F0-9]+"\s*$\n',
            r'^\s*date = "[\d/]+"\s*$\n',
            r'^\s*score = [0-9]+\s*$\n',
            r'^\s*super_rule = [0-9]+\s*$\n'
        ]

        content = re.sub('|'.join(lines_to_remove), '', content, flags=re.MULTILINE)

        # write yara rule
        print('\tWriting to: ' + output_path)
        with open(output_path, 'w') as outfile:
            outfile.write(content)
    else:
        print(f"Failed to download the file. Status code: {response.status_code}")
        print(data.str)
        exit()
