import sys
from scapy.all import *
ipdestino = "2a02:9140:3c00:7b00:6f99:c2bf:7d3d:dc22"
ipv6 = IPv6(dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9)
iporigen = "2002:9140:3c01:1100:20b:dbff:fe53:37a1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=99999)
iporigen = "2a02:9130:8420:39::33"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=99999)

iporigen = "2002:9140:3c01:1100:20b:dbff:fe53:37a1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)

iporigen = "2002:9140:3c01:1100:20b:dbff:fe53:37a1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "2002:9140:3c01:e00:20b:dbff:fe53:37a3"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "2001::1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "::224.0.0.1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "::192.168.1.1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "::255.0.0.0"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "0200::1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "::1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "::1.1.1.1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "0100::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "0200::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "2001:db8::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "2002::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "2002:0a00::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "2a02::1"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "fc00::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "fe80::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "fec0::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
iporigen = "ff00::"
ipv6 = IPv6(src=iporigen, dst=ipdestino)/ICMPv6EchoRequest()
send(ipv6,iface="wlo1", count=9999)
