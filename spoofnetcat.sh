#!/bin/bash
echo 
echo "Uso.: ./spoofnetcat.sh ip_spoof ip_destino puerto_udp"
echo
while : ; do
echo -n "hola" | nc -u -s $1 $2 $3
done
