#!/usr/bin/python3
"""
This script builds EFI Bootloaders based Velociraptor artifacts

https://https://bootloaders.io/

"""

from base_functions import *
import requests
import csv
import json

#Malicious Vulnerable driver    
# set variables
loldrivers_url = 'https://www.bootloaders.io/api/bootloaders.json'
ioc_csv = '../csv/bootloaders.csv'

template_vql = '../templates/Bootloaders.template'
output_path = '../vql/'

if __name__ == "__main__":
    print('Building Bootloaders artifact')

    # first download loldrivers csv and build regex csv
    data = requests.get(loldrivers_url).json()

    flattened = []

    for item in data:
        for sample in item["KnownVulnerableSamples"]:
            if len(item['CVE']) ==1:
                Name = item['CVE'][0]
            else:
                Name = "|".join(item['CVE'])
            
            try:
                row = {
                    'Name': Name,
                    'Category': item['Category'],
                    'Filename': sample['Filename'],
                    'MachineType': sample['MachineType'],
                    'SHA256': sample['SHA256'].lower(),
                    'AuthentiSHA256': sample['Authentihash']['SHA256'].lower(),
                    'BootloadersUrl':'https://www.bootloaders.io/bootloaders/' + item['Id'].lower() + '/'
                }             
                if row['SHA256'] or row['AuthentiSHA256']:
                    flattened.append(row)
            except:
                break

    # next write to csv and build VQL
    with open(ioc_csv, 'w') as csvfile:
        fieldnames = ['Name','Category','Filename','MachineType','SHA256','AuthentiSHA256','BootloadersUrl']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in flattened:
            writer.writerow(row)

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