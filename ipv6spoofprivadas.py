import sys
from scapy.all import *

send(IPv6(src="2001::1", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="::224.0.0.1", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="::127.0.0.1", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="::255.0.0.0", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="0200::1", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="::/128", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="::1/128", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="::ffff:0:0", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="0100::", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="0200::", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="2001:db8::", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="2002::", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="2002:0a00::", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="2a02::1", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="2a02:9000::aaaa", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=9)
send(IPv6(src="fc00::", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="fe80::", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="fec0::", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)
send(IPv6(src="ff00::", dst="2a02:9140:3c00:9200:20a7:3f07:d4a4:4096")/UDP(dport=53),iface="eth0", count=999)