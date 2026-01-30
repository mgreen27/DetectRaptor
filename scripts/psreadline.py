#!/usr/bin/python3
"""
This script converts a PowerShell evtx IOC list to a PSReadline 
Velociraptor artifact.

Simply set variables and run the script.

"""

from base_functions import *

# set variables
template_vql = '../templates/PSReadline.template'
ioc_csv = '../csv/Eventlogs.csv'
output_path = '../vql/'
  
if __name__ == "__main__":
    print('Building PSReadline IOC artifact')

    # grab csv contents and split to list of lines
    lookup_table = []
    count = 0
    with open(ioc_csv, 'r') as file:
      for line in file.readlines():
        if count == 0 or 'powershell' in line.lower():
          lookup_table.append(line)
        count += 1

    # format lookup table txt for VQL insertion
    lookup_table = ''.join(["        " + x for x in lookup_table])

    #grab VQL template
    with open(template_vql, 'r') as file:
      template = file.read()

    # build vql artifacts
    build_vql(lookup_table,template,output_path)