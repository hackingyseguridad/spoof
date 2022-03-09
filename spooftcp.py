#!/usr/bin/python
#Author : Antonio Taboada
#Date: 10/03/2022
#Filename: spooftcp.py
#Purpose : Simple envio de paquete TCP suplantando IP  origen ;
import sys
from scapy.all import *

A = '192.168.1.201' # spoofed source IP address
B = '192.168.0.200' # destination IP address
C = 80 # source port
D = 80 # destination port
payload = "hackingyseguridad.com" # packet payload

spoofed_packet = IP(src=A, dst=B) / TCP(sport=C, dport=D, flags='SA') / payload
send(spoofed_packet)
