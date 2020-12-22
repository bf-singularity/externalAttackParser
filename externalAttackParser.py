import json
import sys
import subprocess
import os
from datetime import datetime
import re
import argparse

"""
goals: 
    (1) provide output that can be fed into nmap or other tools (eyewitness)
    (2) provide output that we can use for reporting

for nmap, we need to group together all systems that share ports so that we can fire off a portscan for all systems
that have those ports open. 

Question: "But why are you scanning multiple IPs for a single port, instead of multiple ports for an IP like a normal person??"
Answer: AWS accounts usually have a relatively small number of security groups applied to a large number of IP addresses, so it's likely that many systems have the same port(s) open. I would expect that grouping by port would lead to less individual port scans than grouping by IP. Ideally I can come up with a way to scan all IPs that have identical ports open at the same time, but that probably won't be in v1 of this tool. 

Question: "Doesn't hirudinea already do this?"
Answer: No. Hirudinea has some similar functionality in that it tries to find publicly exposed assets. But this tool goes a bit deeper when it comes to EC2 instances. Hirudinea will report on any EC2 instance that has a public IP assigned to it. But what if the instance has a security group applied to it that restricts access to ports based on IP address? Even though the instance has a public IP, it is not actually publicly exposed. My tool parses through IPs and finds systems that explicitly allow access on ports to 0.0.0.0/0, then performs nmap scans to see if something is live on those ports. 
"""

# TODO:
# DONE - support for ALL ports open to ALL
# ability to exit out of portscan without cancelling the whole program
# multithreading to provide status on long port scans
# HTML report


def prompt(conn, portRange, ips):
    willContinue = False
    while willContinue == False:
        choice = input("You are about to " + conn + " scan portrange " + str(portRange[0]) + "-" + str(portRange[-1]) + " (" + str(len(portRange)) + " ports) on " + str(len(ips)) + " systems. Do you wish to continue? [Y/N] ")
        if choice.upper() == "Y" or choice.upper() == "YES":
            return True
        elif choice.upper() == "N" or choice.upper() == "NO":
            print("Skipping this port scan")
            return False    


def nmapScan(portDict):
    for port, ips in portDict["ports"].items():
        message = "Scanning " + portDict["connProt"] + " port " + port + " on " + str(len(ips)) + " " + portDict["ipProt"] + " systems."
        if portDict["connProt"] == "TCP":
            args = "nmap -v -Pn -oX " + path + "/" + portDict["ipProt"] + "-tcp-" + port + ".xml -p " + port
            if portDict["ipProt"] == "ipv6": #nmap needs the -6 flag to scan IPv6 addresses
                args = args + " -6"
            args = args + " " + " ".join(ips)
        else: 
            args = "sudo nmap -sU -v -Pn -oX " + path + "/" + portDict["ipProt"] + "-udp-" + port + ".xml -p " + port
            if portDict["ipProt"] == "ipv6": #nmap needs the -6 flag to scan IPv6 addresses
                args = args + " -6"
            args = args + " " + " ".join(ips)
        
        if "-" in port: # for large scans, check with user
            ports = port.split("-")
            portRange = range(int(ports[0]),int(ports[1])+1)

            checkForPromt = False
            if len(portRange) > 100 and portDict["connProt"] == "UDP": #UDP scans can take very long
                checkForPromt = True
            elif len(portRange) > 100 and len(ips) > 10 and portDict["connProt"] == "TCP":
                checkForPromt = True
            elif len(portRange) > 1000:
                checkForPromt = True
                
            if checkForPromt == True:
                willContinue = prompt(portDict["connProt"], portRange, ips)
                if willContinue == False:
                    continue
                else:
                    message += " This can take a long time."

        print(message)
        result = subprocess.run(args, shell=True, capture_output=True).stdout.decode('utf-8')


def print_resultsfile(awsJson):
    for k,v in awsJson['services']['ec2']['external_attack_surface'].items():
        print(k)
        print(v)


#Parse command line arguments    
parser = argparse.ArgumentParser()
parser.add_argument('-u', action="store_true", dest='udp', default=False, help="UDP mode")
parser.add_argument('path', help="Path to the scoutsuite_results_aws.js file on which to run this script.")
arguments = parser.parse_args()

#read in target file from command line
with open(arguments.path, 'r') as inFile:
    content = inFile.readlines()
    awsJson = json.loads(content[1]) #scout results.js file contains dict starting on second line


# dicts to hold ports and IP addresses for systems
tcpPortSystems = {}
udpPortSystems = {}
allPortSystems = {}
tcpPortSystemsIpv6 = {}
udpPortSystemsIpv6 = {}
allPortSystemsIpv6 = {}

#TODO UDP/TCP
csvFile = "Region,DnsName,IP Address,Ports\n"
# Loop through IPs of externally accessible systems
for ip,info in awsJson['services']['ec2']['external_attack_surface'].items():
    tmpPorts = [] #used for csv report

    # Loop through protocols
    # TODO refactor to avoid repeat code
    try:
        for prot,protDetails in info['protocols'].items():

            # use dns name unless there isn't one, then use ipv4/ipv6 IP
            if "PublicDnsName" not in info: 
                system = ip
                name = "N/A" #to be used for csv report
            else:
                system = info["PublicDnsName"]
                name = info["PublicDnsName"]

            if prot == "TCP": #case tcp
                for port,v in protDetails["ports"].items():
                    for cidr in v["cidrs"]:
                        if "0.0.0.0/0" in cidr["CIDR"]:
                            if ":" in system:
                                if port in tcpPortSystemsIpv6:
                                    if system in tcpPortSystemsIpv6[port]:
                                        pass
                                    else:
                                        tcpPortSystemsIpv6[port].append(system)
                                else:
                                    tcpPortSystemsIpv6[port] = [system]
                            else:
                                if port in tcpPortSystems:
                                    if system in tcpPortSystems[port]:
                                        pass
                                    else:
                                        tcpPortSystems[port].append(system)
                                else:
                                    tcpPortSystems[port] = [system]
                            #CSV reporting
                            tmpPorts.append(port)
                            
            #case udp
            if prot == "UDP":
                for port,v in protDetails["ports"].items():
                    for cidr in v["cidrs"]:
                        if "0.0.0.0/0" in cidr["CIDR"]:
                            if ":" in system:
                                if port in udpPortSystemsIpv6:
                                    if system in udpPortSystemsIpv6[port]:
                                        pass
                                    else:
                                        udpPortSystemsIpv6[port].append(system)
                                else:
                                    udpPortSystemsIpv6[port] = [system]
                            else:
                                if port in udpPortSystems:
                                    if system in udpPortSystems[port]:
                                        pass
                                    else:
                                        udpPortSystems[port].append(system)
                                else:
                                    udpPortSystems[port] = [system]
                            #CSV reporting
                            tmpPorts.append(port)
            #case all
            # TODO this will probably error out because "ALL" protocol doesn't use port notation
            if prot == "ALL":
                for port,v in protDetails["ports"].items():
                    for cidr in v["cidrs"]:
                        if "0.0.0.0/0" in cidr["CIDR"]:
                        #if "4.34.125.215/32" in cidr["CIDR"]: #testing
                            if ":" in system:
                                if port in allPortSystemsIpv6:
                                    if system in allPortSystemsIpv6[port]:
                                        pass
                                    else:
                                        allPortSystemsIpv6[port].append(system)
                                else:
                                    allPortSystemsIpv6[port] = [system]
                            else:
                                if port in allPortSystems:
                                    if system in allPortSystems[port]:
                                        pass
                                    else:
                                        allPortSystems[port].append(system)
                                else:
                                    allPortSystems[port] = [system]
                            #CSV reporting
                            tmpPorts.append(port)
        #add to csv report
        if tmpPorts:
            csvFile = csvFile + "tbd," + name + "," + ip + ",\"" + "\n".join(tmpPorts) + "\"\n" 
    
    except KeyError as e:
        print("KeyError: " + str(e))
        print(ip)
        print(info)
        exit(0)

with open("report.csv", "w+") as outFile:
    outFile.write(csvFile)

# Add info to dicts to indicate what info they contain, then add dicts to single list
# Copying original dicts into new dict because I suck at coming up with good data structures from the start
dictList = []

#TODO ALL protocol
if arguments.udp == False: #running in TCP mode, so only append TCP dicts
    tcpPortSystemsNew = {}
    tcpPortSystemsNew["connProt"] = "TCP"
    tcpPortSystemsNew["ipProt"] = "ipv4"
    tcpPortSystemsNew["ports"] = tcpPortSystems
    dictList.append(tcpPortSystemsNew)

    tcpPortSystemsIpv6New = {}
    tcpPortSystemsIpv6New["connProt"] = "TCP"
    tcpPortSystemsIpv6New["ipProt"] = "ipv6"
    tcpPortSystemsIpv6New["ports"] = tcpPortSystemsIpv6
    dictList.append(tcpPortSystemsIpv6New)

else: #running in UDP mode, so only append UDP dicts
    udpPortSystemsNew = {}
    udpPortSystemsNew["connProt"] = "UDP"
    udpPortSystemsNew["ipProt"] = "ipv4"
    udpPortSystemsNew["ports"] = udpPortSystems
    dictList.append(udpPortSystemsNew)

    udpPortSystemsIpv6New = {}
    udpPortSystemsIpv6New["connProt"] = "UDP"
    udpPortSystemsIpv6New["ipProt"] = "ipv6"
    udpPortSystemsIpv6New["ports"] = udpPortSystemsIpv6
    dictList.append(udpPortSystemsIpv6New)

#DONE - print CSV file with publicly accessible IPs and Ports as reported by the security groups. Will be useful for reporting. 

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

# perform nmap scanning on open ports and IPs
# results are stored in /tmp
for portDict in dictList:
    nmapScan(portDict)

"""
combining all nmap output and parsing
"""
#path = "/tmp/xmlFiles-11-25-2020-10-57-53" #for testing
fileCounter = 1
with open(path + "/combined.xml", "w+") as comboFile:
    # What follows below is some hacky code to write certain parts of files and not others in order to create a combined XML file that can be read by nmap-parse-output
    endline = "" #variable to hold end of the first file, to be removed and added back in later
    for filename in os.listdir(path):
        writeLine = False
        skipToEnd = False
        if filename == "combined.xml":
            continue
        else:
            with open(path + "/" + filename, "r") as inFile:
                for line in inFile.readlines():
                    if fileCounter == 1: #for first file, remove end of xml
                        if skipToEnd == False:
                            writeLine = True
                        if line.startswith("<runstats>") == True:
                            writeLine = False
                            skipToEnd = True
                            endline += line
                        if writeLine == True:
                            comboFile.write(line)
                    else: #for all other files remove start and end of xml
                        if line.startswith("<host starttime") == True:
                            writeLine = True
                        if line.startswith("<runstats>") == True:
                            writeLine = False
                        if writeLine == True:
                            comboFile.write(line)
        fileCounter += 1
    comboFile.write(endline) #write the end of the XML 
    comboFile.write("</runstats>")
    comboFile.write("</nmaprun>")

print("\nAll done!\n")
print("run \"nmap-parse-output " + path + "/combined.xml group-by-ports\" for an overview of publicly accessible services")
print("Note that the combined.xml file is a spliced together XML file that can be read by nmap-parse-output. You can trust the IP and port info from this file, but not the metadata.")
if allPortSystems or allPortSystemsIpv6:
    print("\nThe following IPs exposed all TCP ports (1-65535) and we not automatically scanned:")
    for port, systems in allPortSystems.items():
        for system in systems:
            print("* " + system)
    for port, systems in allPortSystemsIpv6.items():
        for system in systems:
            print(system)