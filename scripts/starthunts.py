#!/usr/bin/python3
"""
This script builds Server.StartHunt

Simply set variables and run the script.

"""

from base_functions import *

# set variables
template_vql = '../templates/StartHunts.template'
output_path = '../vql/'
prefix = 'DetectRaptor.'
    
if __name__ == "__main__":
    print('Building Server.StartHunts')

    lookup_table = ['Artifact,Timeout,CpuLimit,IopsLimit\n']

    # grab each yaml file's name
    for artifact in os.listdir(output_path):
      if artifact != 'StartHunts.yaml':
        with open(output_path + artifact, 'r') as stream:
          try:
              lookup_table.append(prefix + yaml.safe_load(stream)['name'] + ',,,' + '\n')
          except yaml.YAMLError as exc:
              print(exc)

    # format lookup table txt for VQL insertion
    lookup_table = ''.join(["        " + x for x in lookup_table])
    
    #grab VQL template
    with open(template_vql, 'r') as file:
      template = file.read()

    # build vql artifacts
    build_vql(lookup_table,template,output_path)