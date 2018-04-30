import sys
from scapy.all import *

ipdestino = "2002:9140:3c01:1000:7e20:fd5d:dc94:b192"

send((IPv6(src="2001::1", dst=)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="::224.0.0.1", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="::127.0.0.1", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="::255.0.0.0", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="0200::1", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="::1", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="::1.1.1.1", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="0100::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="0200::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="2001:db8::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="2002::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="2002:0a00::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="2a02::1", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="2a02:9000::aaaa", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="fc00::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="fe80::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="fec0::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
send((IPv6(src="ff00::", dst=ipdestino)/UDP(dport=53)),iface="eth0", count=999)
