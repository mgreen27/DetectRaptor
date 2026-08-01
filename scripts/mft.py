#!/usr/bin/python3
"""
This script converts a MFT IOC list to a Velociraptor artifact.

Simply set variables and run the script.

"""

from base_functions import *
from validate_mft import validate_mft_csv
from validate_mft_whitelist import validate_whitelist

# set variables
template_vql = '../templates/MFT.template'
ioc_csv = '../csv/MFT.csv'
whitelist_csv = '../csv/MFT_Whitelist.csv'
output_path = '../vql/'
    
if __name__ == "__main__":
    print('Building MFT IOC artifact')

    validation_issues = validate_mft_csv(ioc_csv)
    if validation_issues:
      raise SystemExit(
          "MFT CSV validation failed:\n" + "\n".join(validation_issues))

    whitelist_issues = validate_whitelist(whitelist_csv, ioc_csv)
    if whitelist_issues:
      raise SystemExit(
          "MFT whitelist validation failed:\n"
          + "\n".join(whitelist_issues))

    # grab csv contents and split to list of lines
    with open(ioc_csv, 'r') as file:
      lookup_table = file.readlines()

    # format lookup table txt for VQL insertion
    lookup_table = ''.join(["        " + x for x in lookup_table])

    #grab VQL template
    with open(template_vql, 'r') as file:
      template = file.read()

    with open(whitelist_csv, 'r') as file:
      whitelist_table = ''.join(
          ["        " + line for line in file.readlines()])
    template = template.replace('%whitelist%', whitelist_table)

    # build vql artifacts
    build_vql(lookup_table,template,output_path)
