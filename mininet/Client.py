# Python TCP Client A
import socket 
import sys

import socket 
from threading import Thread 
from SocketServer import ThreadingMixIn 
import commands

from uuid import getnode 
import netifaces

print 'Number of arguments:', len(sys.argv), 'arguments.'
print 'Argument List:', str(sys.argv)

ip = commands.getoutput("hostname -I") 
print("IP address:",ip)

intf = netifaces.interfaces()[1]
mac1 = netifaces.ifaddresses(intf)[netifaces.AF_LINK]
mac = mac1[0]['addr']
print("MAC address:",mac)

'''mac1 = getnode()
h = iter(hex(mac1)[2:].zfill(12))
mac = ":".join(i + next(h) for i in h)
print("MAC address:",mac)'''

#host = socket.gethostname()
host = sys.argv[2]
port = 2004
BUFFER_SIZE = 2000 
#MESSAGE = raw_input("tcpClientA: Enter message/ Enter exit:") 
 
tcpClientA = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
tcpClientA.connect((host, port))

messg = ip+"#"+mac+"#"+sys.argv[1]

tcpClientA.send(messg)
app_details1 = tcpClientA.recv(1024)
app_details = app_details1.split(",")
host1 = app_details[0]
port1 = int(app_details[1])
tcpClientA.close()
tcpClientA = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
tcpClientA.connect((host1, port1))
messg = "data"
tcpClientA.close()




#print "data received from registration server:", tm


'''while MESSAGE != 'exit':
    tcpClientA.send(MESSAGE)     
    data = tcpClientA.recv(BUFFER_SIZE)
    print " Client2 received data:", data
    MESSAGE = raw_input("tcpClientA: Enter message to continue/ Enter exit:")'''
 
 