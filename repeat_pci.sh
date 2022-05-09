#!/bin/bash

protocol=${1:-ecdsa}
party=${2:-0}
inputs=${3:-10}
repeat=${4:-3}
target=${5:-pci_results}

set -x

mkdir -p $target

for ((i=0; i<=repeat; i++));
do
   echo "$i"
   ./mascot-${protocol}-party.x -p ${party} -I ${inputs} -ip pci_ip.txt > $target/result_${protocol}_p${party}_${inputs}_inputs_run_${i}.txt 2>&1
   sleep 5
   cat $target/result_${protocol}_p${party}_${inputs}_inputs_run_${i}.txt
done


set +x
