#!/bin/bash
party=${1:-0}
repeat=${2:-3}
target=${3:-pci_all_results}

set -x

mkdir -p $target

declare -a arr=(1 10 20 50 100)

for ((i=0; i<=repeat; i++));
do
   for claims in "${arr[@]}"
   do
      sleep 5
      echo "ECDSA - $claims"
      ./mascot-ecdsa-pciall.x -p ${party} -I 100 -K ${claims} -ip pci_ip.txt > $target/result_ecdsa_p${party}_${claims}_claims_run_${i}.txt 2>&1
      cat $target/result_ecdsa_p${party}_${claims}_claims_run_${i}.txt
      sleep 5

      echo "BLS - $claims"
      ./mascot-bls-party.x -p ${party} -I 100 -K ${claims} -ip pci_ip.txt > $target/result_bls_p${party}_${claims}_claims_run_${i}.txt 2>&1
      cat $target/result_bls_p${party}_${claims}_claims_run_${i}.txt
   done
done

set +x

