#!/bin/bash

#time the ersatz code
cp ../pam_unix.so* /usr/lib/
./exp2 root password > ../output/root_password_ersatz
for i in `seq 1 999`;
do
	./exp2 root password >> ../output/root_password_ersatz
done

./exp2 root ersatz > ../output/root_ersatz_ersatz
for i in `seq 1 999`;
do
	./exp2 root ersatz >> ../output/root_ersatz_ersatz
done

#time the
cp ../back/pam_unix.so* /usr/lib/
./exp2 test1 password > ../output/test_password_normal
for i in `seq 1 999`;
do
	./exp2 test1 password >> ../output/test_password_normal
done



