import os
import sys
from scapy.all import * 
conf.verb = 0



def do_TCP(ip_address, destination_port, source_port):
	print "Running TCP Scan on IP Address: ", ip_address, " on Port: ", destination_port
	answered, unanswered = sr(IP(dst = ip_address)/TCP(dport = destination_port, flags ="S"), timeout = 1)
	answered.summary()
	print "Answered Ports: ", answered
	print "Unanswered Ports: ", unanswered


def do_UDP(ip_address, destination_port, source_port):
	print "Running UDP scan on IP Address: ", ip_address, " on Port: ", destination_port
	answered, unanswered = sr(IP(dst = ip_address)/UDP(dport = destination_port, sport = source_port), timeout = 2, verbose = 0)
	answered.summary()
	print "Answered Ports: ", answered
	print "Unanswered Ports: ", unanswered


def do_ICMP(ip_address):
	print"Running ICMP on IP Address: ", ip_address
	answered, unanswered = sr(IP(dst = ip_address)/ICMP(), timeout = 10)
	answered.summary() 
	answered.summary(lambda (s,r): r.sprintf("%IP.src% is alive")) #ICMP Ping - scapy.readthedocs.io
	unanswered.summary()

def do_TRACEROUTE(hostname): #https://jvns.ca/blog/2013/10/31/day-20-scapy-and-traceroute/
	print "Running Traceroute to Host: ", hostname
	for i in range(1, 28): #Allow up to 28 hops to reach destination
		packet = IP(dst = hostname, ttl = i) / UDP(dport = 33434)
		#Send packet and parse response
		reply = sr1(packet, verbose = 0, timeout = 5)
		if reply is None:
			#Got no reply
			print("%d. * * *" % i)
			continue
		elif reply.type == 3:
			#Finished - to the desintation
			print "Complete!", reply.src
			break
		else:
			#In the middle
			print "%d. hop(s) away from source: " % i, reply.src


print("Welcome to Justin's Port Scanner\n")

#Allow user to seelct type of Scanning to do
print("Options:\n") 
print("1. TCP Scan (Single IP Address and Single Host)\n")
print("2. TCP Scan (Single IP Address and Multiple Ports - up to 10)\n")
print("3. TCP Scan (Multiple IP Addresses and Single Port)\n")
print("4. UDP Scan (Single IP Address and Single Port)\n")
print("5. UDP Scan (Single IP Address and Multiple Ports - up to 10)\n")
print("6. UDP Scan (Multiple IP Addresses - up to 10 - and Single Port)\n")
print("7. ICMP\n")
print("8. Traceroute\n")

#Get user's selection
user_selection = input("What option do you want to run? (Enter 1, 2, 3, 4, 5, 6, 7, or 8) ")




if user_selection == 1: #TCP - Single IP Address - Single Port
	ip_address = raw_input("Enter IP Address: ")
	destination_port = input("Enter Destination Port: ")
	source_port = input("Enter Source Port: ")
	do_TCP(ip_address, destination_port, source_port)


elif user_selection == 2: #TCP - Single IP Address - Multiple Ports (up to 10)
	ip_address = raw_input("Enter IP Address: ")
	ports = []
	numPorts = 0
	maxPorts = 10
	while len(ports) < maxPorts:
		port = input("Enter Destination Port: (One at a time, up to 10. when finished enter 0) ")
		if port == 0:
			if numPorts == 0:
				print "You need at least one port.. Exiting...."
			break
		ports.append(port)
		numPorts += 1
	
	source_port = input("Enter Source Port: ")
	portPosition = 0

	while portPosition < numPorts:
		do_TCP(ip_address, ports[portPosition], source_port)
		print "\n"
		portPosition += 1



elif user_selection == 3: #TCP - Multiple IP Addresses (up to 10) - Single Port
	ip_addresses = []
	numIP = 0
	maxIP = 10

	while len(ip_addresses) < maxIP:
		ip_address = raw_input("Enter IP Addresses: (One at a time, up to 10. when finished enter 'done') ")
		if ip_address == 'done':
			if numIP == 0:
				print "You need at least one IP Address.. Exiting...."
			break
		ip_addresses.append(ip_address)
		numIP += 1
	
	destination_port = input("Enter Desintation Port: ")
	source_port = input("Enter Source Port: ")


	ipPosition = 0
	while ipPosition < numIP:
		do_TCP(ip_addresses[ipPosition], destination_port, source_port)
		print "\n"
		ipPosition += 1


elif user_selection == 4: #UDP - Single IP Address - Single Port
	ip_address = raw_input("Enter IP Address: ")
	destination_port = input("Enter Destination Port: ")
	source_port = input("Enter Source Port: ")
	do_UDP(ip_address, destination_port, source_port)


elif user_selection == 5: #UDP - Single IP Address - Multiple Port (up to 10)
	ip_address = raw_input("Enter IP Address: ")
	ports = []
	numPorts = 0
	maxPorts = 10
	while len(ports) < maxPorts:
		port = input("Enter Destination Port: (One at a time, up to 10. when finished enter 0) ")
		if port == 0:
			if numPorts == 0:
				print "You need at least one port.. Exiting...."
			break
		ports.append(port)
		numPorts += 1

	source_port = input("Enter Source Port: ")
	portPosition = 0

	while portPosition < numPorts:
		do_UDP(ip_address, ports[portPosition], source_port)
		print "\n"
		portPosition += 1


elif user_selection == 6: #UDP - Multiple IP Addresses (up to 10) - Single Port 
	ip_addresses = []
	numIP = 0
	maxIP = 10

	while len(ip_addresses) < maxIP:
		ip_address = raw_input("Enter IP Addresses: (One at a time, up to 10. when finished enter 'done') ")
		if ip_address == 'done':
			if numIP == 0:
				print "You need at least one IP Address.. Exiting...."
			break
		ip_addresses.append(ip_address)
		numIP += 1
	
	destination_port = input("Enter Desintation Port: ")
	source_port = input("Enter Source Port: ")


	ipPosition = 0
	while ipPosition < numIP:
		do_UDP(ip_addresses[ipPosition], destination_port, source_port)
		print "\n"
		ipPosition += 1

elif user_selection == 7: #ICMP
	ip_address = raw_input("Enter IP Address: ")
	do_ICMP(ip_address)

elif user_selection == 8: #Traceroute
    hostname = raw_input("Enter hostname: (Such as google.com) ")
    do_TRACEROUTE(hostname)
else:
    #Invalid Entry
    print("Invalid selection! Exiting...")
    exit()






