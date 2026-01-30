#!/usr/bin/python3
"""
This script builds Living Off The Land Drivers based Velociraptor artifacts

https://www.loldrivers.io/

"""

from base_functions import *
import requests
import csv
import json
import gzip
import base64

#Malicious Vulnerable driver    
# set variables
mal_drivers = 'https://raw.githubusercontent.com/magicsword-io/LOLDrivers/refs/heads/main/detections/yara/yara-rules_mal_drivers.yar'
vlun_drivers = 'https://raw.githubusercontent.com/magicsword-io/LOLDrivers/refs/heads/main/detections/yara/yara-rules_vuln_drivers_strict.yar'

template_vql = '../templates/YaraLolDrivers.template'
output_path = '../vql/'


if __name__ == "__main__":
    print('Building LolDrivers YARA artifact')

    # first download loldrivers yar and build regex csv
    mal_yara = requests.get(mal_drivers).text
    vuln_yara = requests.get(vlun_drivers).text

    mal_yara_compressed = base64.b64encode(gzip.compress(mal_yara.encode('utf-8'))).decode('utf-8')
    vuln_yara_compressed = base64.b64encode(gzip.compress(vuln_yara.encode('utf-8'))).decode('utf-8')
    
    #grab VQL template
    with open(template_vql, 'r') as file:
        template = file.read()

    malware_start = template.split('%malwareyara%')[0]
    malware_end = template.split('%malwareyara%')[1]
    vql = "{}{}{}".format(malware_start,mal_yara_compressed,malware_end)

    vuln_start = vql.split('%vulnyara%')[0]
    vuln_end = vql.split('%vulnyara%')[1]
    vql = "{}{}{}".format(vuln_start,vuln_yara_compressed,vuln_end)

    name = yaml.load(vql, Loader=yaml.BaseLoader)['name']
    output_path = output_path +  'LolDriversYara.yaml'
    
    print('\tWriting to: ' + output_path)

    with open(output_path, 'w') as outfile:
      outfile.write(vql)

    print('\tSHA1: ' + shasum(output_path))
