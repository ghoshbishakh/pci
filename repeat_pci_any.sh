#!/bin/bash
# ./repeat_pci ecdsa 0 3
protocol=${1:-ecdsa}
party=${2:-0}
repeat=${3:-3}
target=${4:-pci_results}

set -x

mkdir -p $target

declare -a arr=(10 20 50 100 200 500 1000)

for ((i=0; i<=repeat; i++));
do
   for ipsize in "${arr[@]}"
   do
      sleep 5
      echo "$ipsize"
      ./mascot-${protocol}-party.x -p ${party} -I ${ipsize} -ip pci_ip.txt > $target/result_${protocol}_p${party}_${ipsize}_inputs_run_${i}.txt 2>&1
      cat $target/result_${protocol}_p${party}_${ipsize}_inputs_run_${i}.txt
   done
done

set +x
