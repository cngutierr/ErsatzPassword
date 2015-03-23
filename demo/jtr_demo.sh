#!/bin/bash

#get the root password hash
cat /etc/master.passwd | grep "^root" > pw_hash_dump

#run john against the pw_hashes
john --config=demo.conf --wordlist=demo.lst pw_hash_dump
