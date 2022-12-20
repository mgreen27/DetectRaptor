#!/usr/bin/python3
"""
This script diffs two files

"""

files = [
    '../../velociraptor-detections/Eventlogs.csv,../csv/EventLogs.csv',
    '../../velociraptor-detections/ExeOriginalName.csv,../csv/ExeOriginalName.csv',
    '../../velociraptor-detections/NamedPipes.csv,../csv/NamedPipes.csv',
    '../../velociraptor-detections/SuspiciousSoftware.csv,../csv/InstalledSoftware.csv',
    '../../velociraptor-detections/ToolsAndMalware.csv,../csv/MFT.csv',
    '../../velociraptor-detections/WebBrowsers.csv,../csv/WebBrowsers.csv'
]

print('\nComparing: detection csv files')
for pair in files:
    pair = pair.split(',')
    
    print('\n####### COMPARING ##############################################################################')
    print('\tFile1: ' + pair[0])
    print('\tDetectRaptor: ' + pair[1])

    file1 = open(pair[0])
    file2 = open(pair[1])

    file1_lines = file1.readlines()
    file2_lines = file2.readlines()

    for i in range(len(file1_lines)):
        if file1_lines[i].rstrip() != file2_lines[i].rstrip():
            print("\n\tLine " + str(i+1) + " doesn't match.")
            print("\t------------------------")
            print("File1:\t" + file1_lines[i].rstrip())
            print("Raptor:\t" + file2_lines[i].rstrip())
    file1.close()
    file2.close()