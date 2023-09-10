#!/usr/bin/python3
"""
This script converts a Installed software list to a velociraptor 
Suspicious Application detection artifact.

Simply set variables and run the script.

"""

from base_functions import *

# set variables
template_vql = '../templates/Applications.template'
ioc_csv = '../csv/InstalledSoftware.csv'
output_path = '../vql/'
    
if __name__ == "__main__":
    print('Building InstalledSoftware IOC artifact')

    # grab csv contents and split to list of lines
    with open(ioc_csv, 'r') as file:
      lookup_table = file.readlines()

    # format lookup table txt for VQL insertion
    lookup_table = ''.join(["        " + x for x in lookup_table])

    #grab VQL template
    with open(template_vql, 'r') as file:
      template = file.read()

    # build vql artifacts
    build_vql(lookup_table,template,output_path)