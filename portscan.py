from scapy.all import *
import socket
import sys


def portit(host, port):
	hosts = [host]
	ports = [port]

	for host in hosts:
		for port in ports:
			try:
				print "[+] Connecting to " + host + ":" + str(port)
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(5)
				result = s.connect_ex((host, int(port)))
				if result == 0:
					print "  [*] Port " + str(port) + " open\n"
				s.close()

			except:
				pass

def portit2(host, port):
	hosts = [host]
	ports = [port]

	for host in hosts:
		for port in ports:
			try:
				print "[+] Connecting to " + host + ":" + str(port)
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.settimeout(5)
				result = s.connect_ex((host, int(port)))
				if result == 0:
					print "html file has been created in the current directory"
					save = str(host)+ "\n  [*] Port " + str(port) + " open"
					#print save
					f = open('portscan.html','w')
					message = """<html>
					<head></head>
					<body><p>"""+save+"""</p></body>
					</html>"""
					f.write(message)
					f.close()
				s.close()

			except:
				pass 

def traceit(host):
	hostname = host
	for i in range(1, 28):
    		pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
    		# Send the packet and get a reply
    		reply = sr1(pkt, verbose=0)
    		if reply is None:
        		# No reply =(
        		break
    		elif reply.type == 3:
        		# We've reached our destination
        		print "Done!", reply.src
        		break
    		else:
        		# We're in the middle somewhere
        		print "%d hops away: " % i , reply.src
Response = " "
Response2 = " "
host = " "
port = " "
while Response != "end":
	Response = raw_input("Enter '1' for traceroute\nEnter '2' for Port Scanner\nEnter '3' for html copy of Port Scanner Results\nEnter 'end' if you want to exit\n")
	if Response == "1":
		Response2 = raw_input("Enter host to traceroute:\n")
		traceit(str(Response2))
	if Response == "2":
		host = raw_input("Enter the host address:\n")
		port = raw_input("Enter the port number:\n")
		portit(host,port)
	if Response == "3":
		host = raw_input("Enter the host address:\n")
		port = raw_input("Enter the port number:\n")
		portit2(host,port)
