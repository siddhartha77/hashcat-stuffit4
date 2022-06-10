#!/bin/bash

# To be used with the unstuff CLI from StuffIt Deluxe 15.

archiveName=archive.sit
passwordFile=pass.txt

IFS=$'\n'

set -f

for i in $(cat < ${passwordFile}); do
	unstuff -p $i ${archiveName}
	[ $? -eq 0 ] && echo ${i} && exit 0
done
