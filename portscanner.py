#!/usr/bin/env python
# Original source code framework from http://www.pythonforbeginners.com/code-snippets-source-code/port-scanner-in-python
# Additional source: http://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/
# Github page: https://github.com/fridrichperez/it567/blob/master/portscanner.py
import socket
import subprocess
import sys 
from time import strftime
from datetime import datetime
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import * # Make sure scapy is installed for python
from netaddr import * # Make sure netaddr is installed for python: sudo apt-get install python-pip; sudo pip install netaddr

# Clear the screen
subprocess.call("clear", shell = True)

try:
	# Ask for host IP address input
	remoteServerIP = raw_input("Enter a remote host or subnet mask to scan, preferably a '/24' subnet: ")
	
	# Provide option to select a min and max port range 
	minPort = raw_input("Enter Minimum Port Number: ")
	maxPort = raw_input("Enter Maximum Port Number: ")

	# Print waiting section
	print "-" * 60
	print "Please wait, scanning remote host", remoteServerIP
	print "-" * 60

	# Check if port inputs are valid
	try:
		if int(minPort) >= 0 and int(maxPort) >= 0 and int(maxPort) >= int(minPort): 
			pass 
		else:
			print "\n Invalid range of Ports"
			print "Exiting..."
			sys.exit(1)
	except Exception:
		print "\n Invalid range of Ports"
		print "Exiting..."
		sys.exit(1)
except KeyboardInterrupt:
	print "\n Exiting..."
	sys.exit(1)

# Build range with inputted port numbers	
ports = range(int(minPort), int(maxPort) + 1)   

# Check what time the scan started
t1 = datetime.now()

# Set flag values for later reference
SYNACK = 0x12 
RSTACK = 0x14

# Function used to check if there is an existing host
def checkHost(ip): 
	conf.verb = 0 
	try:
		# Ping the target
		ping = sr1(IP(dst = ip)/ICMP()) 
		print "\n[*] Target is Up, Beginning Scan..."
	except Exception:
		print "\n Couldn't Resolve Target. Exiting..."
		sys.exit(1)

# Function to scan a given port on scapy
def scanPort(port):
	try:
		srcport = RandShort()
		conf.verb = 0
		
		# Construct SYN packet to receive SYNACK or RSTACK
		SYNACKpkt = sr1(IP(dst = remoteServerIP) / TCP(sport = srcport, dport = port, flags = "S"))
		
		# Get the flags of received packet
		pktflags = SYNACKpkt.getlayer(TCP).flags
		
		# Cross-reference flags
		if pktflags == SYNACK:
			return True
		else:
			return False
		
		# Construct RST packet
		RSTpkt = IP(dst = remoteServerIP) / TCP(sport = srcport, dport = port, flags = "R")
		send(RSTpkt)
	except KeyboardInterrupt:
		RSTpkt = IP(dst = remoteServerIP) / TCP(sport = srcport, dport = port, flags = "R")
		send(RSTpkt)
		print "\n User requested shut down. Exiting..."
		sys.exit(1)
		
# Function for multiple hosts
def checkMoreHost(ip):
	conf.verb = 0 
	iptest = ip.size
	# Ping the target
	ping = sr1(IP(dst = ip)/ICMP()) 
	if ping == True:
		print str(ip)
		# For loop to iterate through port range
		for port in ports:
			# Call scanPort function 
			status = scanPort(port)
			if status == True:
				print "Port " + str(port) + ": Open"
				
# Function used to check if a subnet range is used
def checkSubnet(ip):
	conf.verb = 0 
	subnet = IPNetwork(ip)
	
	# This is only going to test for /24 subnet for now at least
	if subnet.size == 256:
		minIP = subnet.network
		maxIP = subnet.broadcast
		
		addresses = range(str(minIP), str(maxIP))
		print "\n Started scan at " + strftime("%H:%M:%S") + "...\n"
		
		# Execute checkHost in For loop
		for ipaddress in addresses:
			checkMoreHost(ipaddress)
						
	else:
		checkHost(ip)
		print "\n Started scan at " + strftime("%H:%M:%S") + "...\n"
		
		# For loop to iterate through port range
		for port in ports:
		
		# Call scanPort function 
		status = scanPort(port)
		if status == True:
			print "Port " + str(port) + ": Open"

# Execute checkSubnet function
checkSubnet(remoteServerIP)		

# Check the time again
t2 = datetime.now()

# Calculate the difference of time to see how long it took to run port scanner
total =  t2 - t1

# Printing the information to screen
print "\n Scanning completed in: " + str(total)
