#!/usr/bin/python3
"""
This script builds Living Off The Land Drivers based Velociraptor artifacts

https://https://www.lolrmm.io/

"""

from base_functions import *
import requests
import csv
import json

#Malicious Vulnerable driver    
# set variables
loldrivers_url = 'https://www.loldrivers.io/api/drivers.json'
ioc_csv_malicious = '../csv/drivers_malicious.csv'
ioc_csv_vulnerable = '../csv/drivers_vulnerable.csv'

template_vql = '../templates/LolDrivers.template'
output_path = '../vql/'


if __name__ == "__main__":
    print('Building LolDrivers artifact')

    # first download loldrivers csv and build regex csv
    data = requests.get(loldrivers_url).json()

    flattened_malicious = []
    flattened_vulnerable = []

    for item in data:
        for sample in item["KnownVulnerableSamples"]:
            try:
                row = {
                    'Name': item['Tags'][0],
                    'SHA1': sample['SHA1'],
                    'Product': sample['Product'],
                    'Description': sample['Description'],
                    'ProductVersion': sample['ProductVersion'],
                    'FileVersion': sample['FileVersion'],
                    'MachineType': sample['MachineType'],
                    'Category': item['Category'],
                    'Usecase':item['Commands']['Usecase'],
                    'LolDriversUrl':'https://www.loldrivers.io/drivers/' + item['Id'].lower() + '/'
                }
                #print(row)               
                if row['SHA1'] and not row['SHA1'] == '-':
                    if item["Category"].lower() == "malicious":
                        flattened_malicious.append(row)
                    else:
                        flattened_vulnerable.append(row)
            except:
                break

    # next write to csv and build VQL
    for ioc_csv in (ioc_csv_malicious, ioc_csv_vulnerable):
        with open(ioc_csv, 'w') as csvfile:
            fieldnames = ['Name','SHA1','Product','Description','ProductVersion','FileVersion','MachineType','Category','Usecase','LolDriversUrl']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            if 'malicious' in ioc_csv:
                for row in flattened_malicious:
                    writer.writerow(row)
            else:
                for row in flattened_vulnerable:
                    writer.writerow(row)

        # grab csv contents and split to list of lines
        with open(ioc_csv, 'r') as file:
          lookup_table = file.readlines()

        # format lookup table txt for VQL insertion
        lookup_table = ''.join(["        " + x for x in lookup_table])
    
        #grab VQL template
        with open(template_vql, 'r') as file:
            template = file.read()

        if 'malicious' in ioc_csv:
            template = template.replace("name: Windows.Detection.LolDrivers", 
                    "name: Windows.Detection.LolDriversMalicious" )
        else:
            template = template.replace("name: Windows.Detection.LolDrivers", 
                    "name: Windows.Detection.LolDriversVulnerable" )

        # build vql artifacts
        build_vql(lookup_table,template,output_path)
