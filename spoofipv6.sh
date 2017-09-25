#!/bin/sh
echo
echo "Test envio de paquetes UDP con IPv6 suplantada"
echo "Uso: ./spoofipv6.sh IP_objetivo Puerto_UDP IP_spoof"
nping -6 $1 --udp -p $2 -c 9999 --privileged --send-ip $3
