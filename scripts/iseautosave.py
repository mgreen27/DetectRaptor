#!/usr/bin/python3
"""
This script converts PowerShell Eventlogs.csv rules to a Velociraptor
ISEAutoSave artifact.
"""

from base_functions import build_vql
from psreadline import build_powershell_lookup_table

# set variables
template_vql = '../templates/ISEAutoSave.template'
ioc_csv = '../csv/Eventlogs.csv'
output_path = '../vql/'


if __name__ == "__main__":
    print('Building ISEAutoSave IOC artifact')

    lookup_table = build_powershell_lookup_table(ioc_csv)
    lookup_table = ''.join(
        ["        " + line for line in lookup_table.splitlines(keepends=True)])

    # Grab VQL template.
    with open(template_vql, 'r') as file:
        template = file.read()

    build_vql(lookup_table, template, output_path)
