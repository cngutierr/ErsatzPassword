#!/bin/bash

#authentication latency experiment

#use ersatz pam_unix module
cp ../../pam_unix.so* /usr/lib/

#run the experiment 1000 time using ersatz mods and log output
./exp1 test1 password > ../output/exp1_ersatz.data
for i in `seq 1 999`;
do
	./exp1 test1 password >> ../output/exp1_ersatz.data
done


#run the experiment 1000 times using original mods and log output
cp ../original_pam_unix/pam_unix.so* /usr/lib/
./exp1 test1 password > ../output/exp1_normal.data
for i in `seq 1 999`;
do
	./exp1 test1 password >> ../output/exp1_normal.data
done
