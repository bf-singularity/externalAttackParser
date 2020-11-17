import json
import sys
import subprocess
import os
from datetime import datetime
import re

"""
goals: 
    (1) provide output that can be fed into nmap or other tools (eyewitness)
    (2) provide output that we can use for reporting

for nmap, we need to group together all systems that share ports so that we can fire off a portscan for all systems
that have those ports open. 

Question: "But why are you scanning multiple IPs for a single port, instead of multiple ports for an IP like a normal person??"
Answer: AWS accounts usually have a relatively small number of security groups applied to a large number of IP addresses, so it's likely that many systems have the same port(s) open. I would expect that grouping by port would lead to less individual port scans than grouping by IP. Ideally I can come up with a way to scan all IPs that have identical ports open at the same time, but that probably won't be in v1 of this tool. 

"""

#read in target file from command line
with open(sys.argv[1], 'r') as inFile:
    content = inFile.readlines()
    awsJson = json.loads(content[1]) #scout results.js file contains dict starting on second line

    # dicts to hold ports and IP addresses for systems
    tcpPortSystems = {}
    udpPortSystems = {}
    allPortSystems = {}
    tcpPortSystemsIpv6 = {}
    udpPortSystemsIpv6 = {}
    allPortSystemsIpv6 = {}

    # Loop through IPs of externally accessible systems
    for ip,info in awsJson['services']['ec2']['external_attack_surface'].items():

        # Loop through protocols
        for prot,protDetails in info['protocols'].items():
        
            #case tcp
            if prot == "TCP":
                for port,v in protDetails["ports"].items():
                    for cidr in v["cidrs"]:
                        if "0.0.0.0/0" in cidr["CIDR"]:
                            if ":" in ip:
                                if port in tcpPortSystemsIpv6:
                                    tcpPortSystemsIpv6[port].append(ip)
                                else:
                                    tcpPortSystemsIpv6[port] = [ip]
                            else:
                                if port in tcpPortSystems:
                                    tcpPortSystems[port].append(ip)
                                else:
                                    tcpPortSystems[port] = [ip]
            #case udp
            if prot == "UDP":
                for port,v in protDetails["ports"].items():
                    for cidr in v["cidrs"]:
                        if "0.0.0.0/0" in cidr["CIDR"]:
                            if ":" in ip:
                                if port in udpPortSystemsIpv6:
                                    udpPortSystemsIpv6[port].append(ip)
                                else:
                                    udpPortSystemsIpv6[port] = [ip]
                            else:
                                if port in udpPortSystems:
                                    udpPortSystems[port].append(ip)
                                else:
                                    udpPortSystems[port] = [ip]
            #case all
            if prot == "ALL":
                for port,v in protDetails["ports"].items():
                    for cidr in v["cidrs"]:
                        if "0.0.0.0/0" in cidr["CIDR"]:
                            if ":" in ip:
                                if port in allPortSystemsIpv6:
                                    allPortSystemsIpv6[port].append(ip)
                                else:
                                    allPortSystemsIpv6[port] = [ip]
                            else:
                                if port in allPortSystems:
                                    allPortSystems[port].append(ip)
                                else:
                                    allPortSystems[port] = [ip]

"""
nmap
"""
now = datetime.now()
date_time = now.strftime("%m-%d-%Y-%H-%M-%S")
path = "/tmp/xmlFiles-" + date_time

try:
    os.mkdir(path)
except OSError:
    print ("Creation of the directory %s failed" % path)
else:
    print ("Created the directory %s for storing nmap XML results" % path)

# TODO tomorrow - make this into a function that gets called 6 times for each of the dicts
for port, ips in tcpPortSystems.items():
    print("Scanning port " + port + " on " + str(len(ips)) + " systems")
    args = "nmap -v -sV -Pn -oX " + path + "/ipv4-tcp-" + port + ".xml -p " + port
    args = args + " " + " ".join(ips)
    result = subprocess.run(args, shell=True, capture_output=True).stdout.decode('utf-8')

"""
combining all nmap output and parsing
"""
#path = "/tmp/xmlFiles-11-16-2020-17-20-52" #for testing
fileCounter = 1
with open(path + "/combined.xml", "w+") as comboFile:
    for filename in os.listdir(path):
        # What follows below is some hacky code to write certain parts of files and not others in order to create a combined XML file that can be read by nmap-parse-output
        writeLine = False
        skipToEnd = False
        if not filename == "combined.xml":
            with open(path + "/" + filename, "r") as inFile:
                for line in inFile.readlines():
                    if fileCounter == 1: #for first file, remove end of xml
                        if skipToEnd == False:
                            writeLine = True
                        if line.startswith("<runstats>") == True:
                            writeLine = False
                            skipToEnd = True
                        if writeLine == True:
                            comboFile.write(line)
                    elif fileCounter < len(os.listdir(path)): #for all other files except the last, remove start and end of xml
                        if line.startswith("<host starttime") == True:
                            writeLine = True
                        if line.startswith("<runstats>") == True:
                            writeLine = False
                        if writeLine == True:
                            comboFile.write(line)
                    elif fileCounter == len(os.listdir(path)): #for the last file, only remove start of xml, but leave the end
                        if line.startswith("<host starttime") == True:
                            writeLine = True
                        if writeLine == True:
                            comboFile.write(line)
        fileCounter += 1

print("All done!")
print("run \"nmap-parse-output " + path + "/combined.xml group-by-ports\" for an overview of publicly accessible services")
print("Note that the combined.xml file is a spliced together XML file that can be read by nmap-parse-output. You can trust the IP and port info from this file, but not the metadata.")