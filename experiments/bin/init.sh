#!/bin/bash

#back up old version of pam_unix and install
mkdir -p ../original_pam_unix
cp /usr/lib/pam_unix.so*  ../original_pam_unix
