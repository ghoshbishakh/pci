#!/bin/bash
# ./repeat_pci ecdsa 0 3
protocol=${1:-ecdsa}
party=${2:-0}
repeat=${4:-3}
target=${5:-pci_results}

set -x

mkdir -p $target

for ((i=0; i<=repeat; i++));
do
   for ((ipsize=10; ipsize<=100; ipsize=ipsize+10));
   do
      echo "$i"
      ./mascot-${protocol}-party.x -p ${party} -I ${ipsize} -ip pci_ip.txt > $target/result_${protocol}_p${party}_${ipsize}_inputs_run_${i}.txt 2>&1
      sleep 5
      cat $target/result_${protocol}_p${party}_${ipsize}_inputs_run_${i}.txt
   done
done

set +x
