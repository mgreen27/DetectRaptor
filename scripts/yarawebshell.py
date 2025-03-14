#!/usr/bin/python3
"""
This script Adds a yara rule set to a velociraptor YaraWebshell artifact.

Simply set variables and run the script.

"""
import gzip
import io
import base64
from base_functions import *

# set variables
template_vql = '../templates/YaraWebshell.template'
yara_file = '../yara/webshells.yar'
output_path = '../vql/'
    
if __name__ == "__main__":
    print('Building YaraWebshell artifact')


    with open(yara_file, "rb") as f_in:
        file_data = f_in.read()
    
    compressed_data = io.BytesIO()
    
    with gzip.GzipFile(fileobj=compressed_data, mode="wb") as f_out:
        f_out.write(file_data)

    compressed_data.seek(0)
    compressed_bytes = compressed_data.getvalue()
    base64_yara_rules = base64.b64encode(compressed_bytes).decode("utf-8")

    #grab VQL template
    with open(template_vql, 'r') as file:
      template = file.read()

    # build vql artifacts
    build_vql(base64_yara_rules,template,output_path)