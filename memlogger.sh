#!/bin/bash
while :
do
	echo "==========================="
	date
	top -c -b -n 1 | grep "mascot\|bls"
	sleep 1
done
