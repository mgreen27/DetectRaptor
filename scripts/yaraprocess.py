#!/usr/bin/python3
"""
This script Adds a yara rule set to a velociraptor YaraProcess artifacts.

Simply set variables and run the script.

"""

from base_functions import *

# set variables
windows = [ '../templates/YaraProcessWin.template', '../yara/full_windows_process.yar' ]
linux   = [ '../templates/YaraProcessLinux.template', '../yara/full_linux_process.yar' ]
macos   = [ '../templates/YaraProcessMacos.template', '../yara/full_macos_process.yar' ]

output_path = '../vql/'
    
if __name__ == "__main__":
    print('Building YaraProcess artifacts')

    for os in [ windows, linux, macos]:
      template_vql = os[0]
      yara_file = os[1]

      # grab yara contents and split to list of lines
      with open(yara_file, 'r') as file:
        yara_rule = ['        ' + line.rstrip() for line in file.readlines()]
        yara_rule = ''.join([x + "\n" for x in yara_rule])

      #grab VQL template
      with open(template_vql, 'r') as file:
        template = file.read()

      # build vql artifacts
      build_vql(yara_rule,template,output_path)