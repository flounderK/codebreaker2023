#!/bin/bash

function scan_port_for_ssh () {
	if [ $# -lt 2 ]; then
	   echo "Usage: $0 <ip-addr> <port>"
	   exit
	fi
	PORT="$2"

	LOCALPORT=8080

	IP_ADDR="$1"

	ssh -S ~/.sshscan -M -fN -o "IdentitiesOnly=yes" -i ~/.ssh/jumpbox.key -L $LOCALPORT:$IP_ADDR:$PORT user@external-support.bluehorizonmobile.com
	OUTP=$(nmap -vv -Pn -sT -sV --script ssh-hostkey --script-args="ssh_hostkey=all" -d -p $LOCALPORT localhost)

	echo "$OUTP" | sed "s/$LOCALPORT/$PORT/g" >> nmapoutput

	ssh -O exit -S ~/.sshscan -o "IdentitiesOnly=yes" -i ~/.ssh/jumpbox.key user@external-support.bluehorizonmobile.com
}

# 100.90.12.106

for i in $(seq 1638 65535); do
	echo "port $i"
	scan_port_for_ssh $1 $i
done
