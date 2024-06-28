#!/usr/bin/python3
"""
This script Adds a yara rule set to a velociraptor FileYara artifacts.

Simply set variables and run the script.

"""

import base64
from base_functions import *

# set variables: os = [template, compiledrules.gz]
windows = [ '../templates/FileYaraWin.template', '../yara/full_windows_file.yarc.gz' ]
linux   = [ '../templates/FileYaraLinux.template', '../yara/full_linux_file.yarc.gz' ]
macos   = [ '../templates/FileYaraMacos.template', '../yara/full_macos_file.yarc.gz' ]

output_path = '../vql/'
    
def encode_base64(data):
  if isinstance(data, str):
    data = data.encode('utf-8')
  # Encode the data to base64
  encoded_data = base64.b64encode(data)
  # Convert the encoded bytes back to a string
    
  return encoded_data.decode('utf-8')

if __name__ == "__main__":
    print('Building FileYara artifacts')

    for os in [ windows, linux, macos ]:
      # open gzipped rules and base64 encode
      with open(os[1], 'rb') as gz_file:
        gz_rules = gz_file.read()
        gz_rules=encode_base64(gz_rules)

      #grab VQL template 
      with open(os[0], 'r') as templatefile:
        template = templatefile.read()

      # build vql artifacts
      build_vql(gz_rules,template,output_path)