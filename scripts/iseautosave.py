#!/usr/bin/python3
"""
This script converts a ISEAutoSave IOC list to a velociraptor artifact.

Simply set variables and run the script.

"""

import sys
import re
import os
import yaml

# set variables
template_vql = '../templates/ISEAutoSave.template'
ioc_csv = '../csv/Eventlogs.csv'
output_path = '../vql/'


def build_vql(lookup_table,template,output_path):

    vql = (template % dict(
        ioc=''.join(["        " + x for x in lookup_table])
      ))

    name = yaml.load(vql, Loader=yaml.BaseLoader)['name']
    output_path = output_path +  name.split('.')[-1] + '.yaml'
    
    print('\tWriting to:' + output_path)

    with open(output_path, 'w') as outfile:
      outfile.write(vql)

    
if __name__ == "__main__":
    print('Building ISEAutoSave IOC artifact')

    # grab csv contents and split to list of lines
    lookup_table = []
    count = 0
    with open(ioc_csv, 'r') as file:
      for line in file.readlines():
        if count == 0 or 'powershell' in line.lower():
          lookup_table.append(line)
        count += 1

    #grab VQL template
    with open(template_vql, 'r') as file:
      template = file.read()

    # build vql artifacts
    build_vql(lookup_table,template,output_path)