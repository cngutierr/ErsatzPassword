#!/bin/bash

./exp3 password1 1 > ../output/exp3_new.data
sleep 1
for i in `seq 2 1000`;
do
	./exp3 password$i $i >> ../output/exp3_new.data
	sleep 1
done
