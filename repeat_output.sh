#!/bin/bash
# ./repeat_pci ecdsa 0 3
#protocol=${1:-ecdsa}
party=${1:-0}
repeat=${2:-3}
target=${3:-pci_results}

set -x

mkdir -p $target

declare -a arr=(1 100)

for ((i=0; i<=repeat; i++));
do
   for ipsize in "${arr[@]}"
   do
      sleep 5
      echo "$ipsize"
      ./mascot-ecdsa-party.x -p ${party} -I 100 -O ${ipsize} -ip pci_ip.txt > $target/result_ecdsa_p${party}_${ipsize}_common_run_${i}.txt 2>&1
      cat $target/result_ecdsa_p${party}_${ipsize}_common_run_${i}.txt
      sleep 5
      ./mascot-bls-party.x -p ${party} -I 100 -O ${ipsize} -ip pci_ip.txt > $target/result_bls_p${party}_${ipsize}_common_run_${i}.txt 2>&1
      cat $target/result_bls_p${party}_${ipsize}_common_run_${i}.txt
   done
done

set +x
