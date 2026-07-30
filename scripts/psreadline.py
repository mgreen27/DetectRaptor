#!/usr/bin/python3
"""
This script converts PowerShell Eventlogs.csv rules to a PSReadLine
Velociraptor artifact.
"""

import csv
import io

from base_functions import build_vql

# set variables
template_vql = '../templates/PSReadline.template'
ioc_csv = '../csv/Eventlogs.csv'
output_path = '../vql/'


def build_powershell_lookup_table(filename):
    """Return CSV text containing only PowerShell-compatible source rows."""
    with open(filename, 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or 'eventlog' not in reader.fieldnames:
            raise ValueError('Eventlogs CSV must contain an eventlog column')

        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=reader.fieldnames,
            lineterminator='\n')
        writer.writeheader()

        for row in reader:
            if 'powershell' in row['eventlog'].casefold():
                writer.writerow(row)

    return output.getvalue()


if __name__ == "__main__":
    print('Building PSReadline IOC artifact')

    lookup_table = build_powershell_lookup_table(ioc_csv)
    lookup_table = ''.join(
        ["        " + line for line in lookup_table.splitlines(keepends=True)])

    # Grab VQL template.
    with open(template_vql, 'r') as file:
        template = file.read()

    build_vql(lookup_table, template, output_path)
