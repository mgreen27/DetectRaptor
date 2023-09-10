#!/usr/bin/python3
"""
This script Adds a yara rule set to a velociraptor WebshellYara artifact.

Simply set variables and run the script.

"""

from base_functions import *

# set variables
template_vql = '../templates/WebshellYara.template'
yara_file = '../yara/webshells.yar'
output_path = '../vql/'
    
if __name__ == "__main__":
    print('Building WebshellYara artifact')

    # grab yara contents and split to list of lines
    with open(yara_file, 'r') as file:
      yara_rule = ['        ' + line.rstrip() for line in file.readlines()]
      yara_rule = ''.join([x + "\n" for x in yara_rule])

    #grab VQL template
    with open(template_vql, 'r') as file:
      template = file.read()

    # build vql artifacts
    build_vql(yara_rule,template,output_path)