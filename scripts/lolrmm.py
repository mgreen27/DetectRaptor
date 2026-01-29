#!/usr/bin/python3
"""
This script builds LOLRMM csv for Velociraptor DetectRaptor

https://www.lolrmm.io/

"""

from base_functions import *
import requests
import csv
import json
import regex

# set variables
lolrmm_url = 'https://lolrmm.io/api/rmm_tools.json'
ioc_csv = '../csv/lolrmm.csv'



if __name__ == "__main__":
    print('Building LolRMM csv')

    # first download lolrmm 
    data = requests.get(lolrmm_url).json()

    with open(ioc_csv, mode="w", newline="", encoding="utf-8") as csvfile:
        csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(["Name", "Description", "LolRMMLink", "PathRegex", "DomainRegex"])  
    
        for item in data:
            name = item.get('Name', '')
            description = item.get('Description', '')
            lolrmm= 'https://lolrmm.io/tools/' + re.sub(r"[ ()]", "_", item.get("Name", "").lower())

            install_paths = set()
            if item.get('Details', {}).get('InstallationPaths'):
                for path in item['Details']['InstallationPaths']:
                    path = path.replace('\\','\\\\') # escape folder slashes
                    path = path.replace('.','\\.')  # escape "."
                    path = path.replace('*','.*')  # Replace asterisks (*) with .* to match any sequence of characters
                    path = path.replace('(','\\(')  # escape "("
                    path = path.replace(')','\\)')  # escape ")"
                    path = path.replace('<string ID>','.*')  # Replace <string ID> with .+
                    path = path.replace('(Random','(.*')  # Replace (Random) with .+
                    if '.exe' in path and '\\\\' not in path: # any path that has no slash indicaiting its a process name
                        path = f'^{path}'
                    if path.endswith('.exe'):
                        path = path + '$'
                    if path not in install_paths:
                        install_paths.add(path)
            path_regex = '|'.join(sorted(install_paths))

            domains = set()
            for network in item.get("Artifacts", {}).get("Network", []):
                for domain in network.get("Domains", []):
                    if domain == "user_managed":
                        continue
                    domain = domain.replace('.','\\.')  
                    domain = domain.replace('*','.*')
                    if not domain.endswith('$'):
                        domain = domain + '$'
                    if re.match(r"(\d{1,3}(\\\.\d{1,3}){3})\$", domain):
                        domain = '^' + domain
                    if domain not in domains:
                        domains.add(domain)
            domain_regex = '|'.join(sorted(domains))

            csv_writer.writerow([name, description, lolrmm, path_regex, domain_regex])

    print(f"../csv/lolrmm.csv SHA256: {sha256sum(ioc_csv)}")
