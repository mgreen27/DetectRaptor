#!/usr/bin/python3
"""
This script builds Hijacklibs based Velociraptor artifacts

https://hijacklibs.net/

Current csv structure:
    row[0]  = Name
    row[1]  = Author
    row[2]  = Created
    row[3]  = Vendor
    row[4]  = CVE
    row[5]  = ExpectedLocations
    row[6]  = VulnerableExecutablePath
    row[7]  = VulnerableExecutableType
    row[8]  = VulnerableExecutableAutoElevated
    row[9]  = VulnerableExecutablePrivilegeEscalation
    row[10] = VulnerableExecutableCondition
    row[11] = VulnerableExecutableSHA256
    row[11] = VulnerableExecutableEnvironmentVariable
    row[12] = Resources
    row[13] = Acknowledgements
    row[14] = URL
"""

from base_functions import *
import requests
import csv
import pandas as pd

# set variables
hijacklibs_url = 'https://hijacklibs.net/api/hijacklibs.csv'
ioc_csv = '../csv/hijacklibs.csv'
env_ioc_csv = '../csv/hijacklibs_env.csv'

template_vql = '../templates/Hijacklibs.template'
env_template_vql = '../templates/HijacklibsEnv.template'
output_path = '../vql/'


def convert_env(variable):
    variable = re.sub(r'\\', r'\\\\', variable)
    variable = re.sub(r'\.', '\\.', variable)
    variable = re.sub(r'\(', '\\(', variable)
    variable = re.sub(r'\)', '\\)', variable)
    variable = re.sub(r'\+', '\\+', variable)
    variable = re.sub('%WINDIR%', r'\\\\Windows', variable)
    variable = re.sub('%SYSTEM32%', r'\\\\Windows\\\\System32', variable)
    variable = re.sub('%SYSWOW64%', r'\\\\Windows\\\\SysWOW64', variable)
    variable = re.sub('%VERSION%', r'[^\\\\]+', variable)
    variable = re.sub('%PROGRAMFILES%', r'\\\\Program Files( \\(x86\\))?', variable)
    variable = re.sub('%PROGRAMDATA%', r'\\\\Programdata', variable)
    variable = re.sub('%APPDATA%', r'\\\\(Users\\\\[^\\\\]+|windows\\\\(System32|SysWOW64)\\\\config\\\\systemprofile)\\\\AppData\\\\[^\\\\]+', variable)
    variable = re.sub('%LOCALAPPDATA%', r'\\\\(Users\\\\[^\\\\]+|windows\\\\(System32|SysWOW64)\\\\config\\\\systemprofile)\\\\AppData\\\\[^\\\\]+', variable)

    return variable


# function that appends to our final list data 
def append_csv_data(target, x, grouped_name):
    target.append(
        [
            grouped_name,
            '|'.join(x['Vendor'].unique().tolist()),
            '|'.join(x['ExpectedLocation'].unique().tolist()),
            '|'.join(x['ExecutablePath'].unique().tolist()),
            '|'.join(x['Type'].unique().tolist()),
            '|'.join(x['ExecutableSHA256'].unique().tolist()),
            '|'.join(x['Url'].unique().tolist())
        ])


if __name__ == "__main__":
    print('Building HijackLibs artifact')

    # first download hijacklibs iocs and build regex csv
    csv_data = requests.get(hijacklibs_url).content.decode("utf-8")
    
    flattened_data = []
    usable_data = []

    env_flattened_data = []
    env_usable_data = []

    #for row in csv_data.split('\n'):
    for row in csv.reader(csv_data.split('\n')):
        if not row:
            continue
        if row[0] == 'Name':
            # firstly check headers are expected and set headers
            if not row == ['Name', 'Author', 'Created', 'Vendor', 'CVE', 'ExpectedLocations', 'VulnerableExecutablePath', 'VulnerableExecutableType', 'VulnerableExecutableAutoElevated', 'VulnerableExecutablePrivilegeEscalation', 'VulnerableExecutableCondition', 'VulnerableExecutableSHA256', 'VulnerableExecutableEnvironmentVariable', 'Resources', 'Acknowledgements', 'URL']:
                print('API may have changed')
                print(row)
            
            #[row[0],row[3],row[5],row[6],row[7],row[11],row[15]]
            flattened_data.append(['DllName','Vendor','ExpectedLocation','ExecutablePath','Type','ExecutableSHA256','Url'])
            usable_data.append(['DllName','Vendor','ExpectedLocation','ExecutablePath','Type','ExecutableSHA256','Url'])

            env_flattened_data.append(['DllName','Vendor','ExpectedLocation','ExecutablePath','Type','ExecutableSHA256','Url'])
            env_usable_data.append(['DllName','Vendor','ExpectedLocation','ExecutablePath','Type','ExecutableSHA256','Url'])
        else:
            # normalise paths to regex
            row[5] = convert_env(row[5])
            row[6] = convert_env(row[6])

            # flatten ExpectedLocations and VulnerableExecutablePath
            if ',' in row[5] and ',' in row[6]:
                for value5 in row[5].split(','):
                    for value6 in row[6].split(','):
                        if row[7] == 'Environment Variable':
                            env_flattened_data.append([row[0],row[3],value5.lstrip(),value6.lstrip(),row[7],row[11],row[15]])
                        else:
                            flattened_data.append([row[0],row[3],value5.lstrip(),value6.lstrip(),row[7],row[11],row[15]])
            # flatten ExpectedLocations
            elif ',' in row[5]:
                for value5 in row[5].split(','):
                    if row[7] == 'Environment Variable':
                        env_flattened_data.append([row[0],row[3],value5.lstrip(),row[6],row[7],row[11],row[15]])
                    else:
                        flattened_data.append([row[0],row[3],value5.lstrip(),row[6],row[7],row[11],row[15]])

            # flatten VulnerableExecutablePath
            elif ',' in row[6]:
                for value6 in row[6].split(','):
                    if row[7] == 'Environment Variable':
                        env_flattened_data.append([row[0],row[3],row[5],value6.lstrip(),row[7],row[11],row[15]])
                    else:
                        flattened_data.append([row[0],row[3],row[5],value6.lstrip(),row[7],row[11],row[15]])
            else:
                if row[7] == 'Environment Variable':
                    env_flattened_data.append([row[0],row[3],row[5],row[6],row[7],row[11],row[15]])
                else:
                    flattened_data.append([row[0],row[3],row[5],row[6],row[7],row[11],row[15]])
 
    ## use pandas to group by DllName and join hijacklibs data
    # sideload version
    df = pd.DataFrame(flattened_data[1:], columns=flattened_data[0])
    grouped = df.groupby('DllName')
    grouped.apply(lambda x: append_csv_data(usable_data, x, x.name), include_groups=False)


    # finally we write to csv and build VQL
    with open(ioc_csv, 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(usable_data)

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
    
    ## use pandas to group by DllName and join hijacklibs data
    # env variables version
    df = pd.DataFrame(env_flattened_data[1:], columns=env_flattened_data[0])
    grouped = df.groupby('DllName')
    grouped.apply(lambda x: append_csv_data(env_usable_data, x, x.name))

    ## finally we write to csv and build VQL
    ## env_variable hijack
    with open(env_ioc_csv, 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(env_usable_data)

    # grab csv contents and split to list of lines
    with open(env_ioc_csv, 'r') as file:
      lookup_table = file.readlines()
    
    # format lookup table txt for VQL insertion
    lookup_table = ''.join(["        " + x for x in lookup_table])

    #grab VQL template
    with open(env_template_vql, 'r') as file:
      template = file.read()

    # build vql artifacts
    build_vql(lookup_table,template,output_path)  
