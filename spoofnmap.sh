#!/bin/bash
# (c) hackingyseguridad.com 2025

cat << "INFO"

▬▬▬.◙.▬▬▬
═▂▄▄▓▄▄▂
◢◤ █▀▀████▄▄▄▄◢◤
█▄ █ █▄ ███▀▀▀▀▀▀▀╬
◥█████◤
══╩══╩═
╬═╬
╬═╬
╬═╬
╬═╬
╬═╬    spoof V.1.0
╬═╬    hackingyseguridad.com
╬═╬⛑/
╬═╬/▌
╬═╬/  \

INFO
echo
echo "..."
echo
nmap -Pn -S $1 -p 23 -sV $1
nmap -Pn -S 127.0.0.1 -p 23 -sV $1
nmap -Pn -S localhost -p 23 -sV $1
nmap -Pn --open -S 127.0.0.1  -sACV  -T4 -f -O --max-retries 1 --defeat-rst-ratelimit --script firewall-bypass,http-waf-fingerprint,http-waf-detect $1 -p 23


