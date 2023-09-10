#!/usr/bin/python3
"""
This script converts a Installed software list to a velociraptor 
Suspicious Application detection artifact.

Simply set variables and run the script.

"""

import sys
import re
import os
import yaml
import hashlib

# set variables
template_vql = '../templates/Applications.template'
ioc_csv = '../csv/InstalledSoftware.csv'
output_path = '../vql/'


def build_vql(lookup_table,template,output_path):

    vql = (template % dict(
        ioc=''.join(["        " + x for x in lookup_table])
      ))

    name = yaml.load(vql, Loader=yaml.BaseLoader)['name']
    output_path = output_path +  name.split('.')[-1] + '.yaml'
    
    print('\tWriting to: ' + output_path)

    with open(output_path, 'w') as outfile:
      outfile.write(vql)
    
    print('\tSHA1: ' + shasum(output_path))

def shasum(filename):
    h  = hashlib.sha1()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()
    
    
if __name__ == "__main__":
    print('Building InstalledSoftware IOC artifact')

    # grab csv contents and split to list of lines
    with open(ioc_csv, 'r') as file:
      lookup_table = file.readlines()

    #grab VQL template
    with open(template_vql, 'r') as file:
      template = file.read()

    # build vql artifacts
    build_vql(lookup_table,template,output_path)