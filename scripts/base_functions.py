#!/usr/bin/python3
"""
DetectRaptor functions

"""

import sys
import re
import os
import yaml
import hashlib

def build_vql2(lookup_table,template,output_path):

    vql = (template % dict(
        ioc=''.join(["        " + x for x in lookup_table])
      ))

    name = yaml.load(vql, Loader=yaml.BaseLoader)['name']
    output_path = output_path +  name.split('.')[-1] + '.yaml'
    
    print('\tWriting to: ' + output_path)

    with open(output_path, 'w') as outfile:
      outfile.write(vql)

    print('\tSHA1: ' + shasum(output_path))
    print(dict(
        ioc=''.join(["        " + x for x in lookup_table])
      ))


def build_vql(inserted,template,output_path):
    template_start = template.split('%splitme%')[0]
    template_end = template.split('%splitme%')[1]

    vql = "{}{}{}".format(template_start,inserted,template_end)

    name = yaml.load(vql, Loader=yaml.BaseLoader)['name']
    output_path = output_path +  name.split('.')[-1] + '.yaml'
    
    print('\tWriting to: ' + output_path)

    with open(output_path, 'w') as outfile:
      outfile.write(vql)

    print('\tSHA1: ' + shasum(output_path))


def shasum(filename):
    h  = hashlib.sha1()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()

def sha256sum(filename):
    h = hashlib.sha256()
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()