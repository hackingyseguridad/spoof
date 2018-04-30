#!/usr/bin/python
#Author : Antonio Taboada
#Date: 10/10/2017
#Filename: ipv6spoofudp.py
#Purpose : Simple IPv6 UDP spoof origen IP ;
import sys
from scapy.all import *

destino ="2a02:9140:3c01:1200:319a:c5b7:fff1:8005"

iporigen ="2a02:9140:3c01:1200:f24d:a2ff:fef7:5586"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "2a02:9140:3c01:1100:20b:dbff:fe53:37a1"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "2001::1"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "::224.0.0.1"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "::192.168.1.1"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "::255.0.0.0"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
print iporigen
iporigen = "0200::1"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "::1"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "::1.1.1.1"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "0100::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "0200::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "2001:db8::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "2002::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "2002:0a00::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "2a02::1"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "fc00::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "fe80::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "fec0::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
iporigen = "ff00::"
print iporigen
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="eth0", count=9999)
