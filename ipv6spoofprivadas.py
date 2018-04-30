import sys
from scapy.all import *

send((IPv6(src="2a01:1000:1000:1000:1000:1000:1000:1000", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth1", count=9)
