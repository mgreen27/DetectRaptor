#!/usr/bin/python3
"""
This script builds Living Off The Land Drivers based Velociraptor artifacts

https://https://www.loldrivers.io/

"""

from base_functions import *
import requests
import csv
import json


# set variables
loldrivers_url = 'https://www.loldrivers.io/api/drivers.json'
ioc_csv = '../csv/drivers.csv'

template_vql = '../templates/LolDrivers.template'
output_path = '../vql/'


# Define a function to flatten the KnownVulnerableSamples dictionary
def flatten_field(record):
    flat_record = {}
    for key, value in record.items():
        if isinstance(value, dict):
            for subkey, subvalue in value.items():
                flat_record[key + "_" + subkey] = subvalue
        elif isinstance(value, list):
            for i, subdict in enumerate(value):
                for subkey, subvalue in subdict.items():
                    flat_record[key + "_" + str(i) + "_" + subkey] = subvalue
    return flat_record

if __name__ == "__main__":
    print('Building LolDrivers artifact')

    # first download loldrivers csv and build regex csv
    data = requests.get(loldrivers_url).json()

    flattened_data = []

    for item in data:
        for sample in item["KnownVulnerableSamples"]:
            try:
                row = {
                    'Name': sample['Filename'],
                    'SHA1': sample['SHA1'],
                    'Product': sample['Product'],
                    'Description': sample['Description'],
                    'ProductVersion': sample['ProductVersion'],
                    'FileVersion': sample['FileVersion'],
                    'MachineType': sample['MachineType'],
                    'Category': item['Category'],
                    'Usecase':item['Commands']['Usecase'],
                    'LolDriversUrl':'https://www.loldrivers.io/drivers/' + os.path.splitext(sample['Filename'])[0].lower() + '/'
                }
                #print(row)               
                if row['SHA1'] and not row['SHA1'] == '-':
                    flattened_data.append(row)
            except:
                break

    # next write to csv and build VQL
    with open(ioc_csv, 'w') as csvfile:
        fieldnames = ['Name','SHA1','Product','Description','ProductVersion','FileVersion','MachineType','Category','Usecase','LolDriversUrl']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in flattened_data:
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
