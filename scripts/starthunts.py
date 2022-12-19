#!/usr/bin/python3
"""
This script builds Server.StartHunt

Simply set variables and run the script.

"""

import sys
import re
import os
import yaml

# set variables
template_vql = '../templates/StartHunts.template'
output_path = '../vql/'
prefix = 'DetectRaptor.'


def build_vql(lookup_table,template,output_path):

    vql = (template % dict(
        hunts=''.join(["        " + x for x in lookup_table])
      ))

    name = yaml.load(vql, Loader=yaml.BaseLoader)['name']
    output_path = output_path +  name.split('.')[-1] + '.yaml'
    
    print('\tWriting to:' + output_path)

    with open(output_path, 'w') as outfile:
      outfile.write(vql)

    
if __name__ == "__main__":
    print('Building Webhistory IOC artifact')

    lookup_table = ['Artifact\n']

    # grab each yaml file's name
    for artifact in os.listdir(output_path):
      if artifact != 'StartHunts.yaml':
        with open(output_path + artifact, 'r') as stream:
          try:
              lookup_table.append(prefix + yaml.safe_load(stream)['name'] + '\n')
          except yaml.YAMLError as exc:
              print(exc)

    #grab VQL template
    with open(template_vql, 'r') as file:
      template = file.read()

    # build vql artifacts
    build_vql(lookup_table,template,output_path)