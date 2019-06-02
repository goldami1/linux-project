# The shell path that will execute this script
#!/bin/bash

# ----------------------------------
# Description : This script check the directory's quota.
# Input	      : None
# Exit code   : 0 - DIR is in QUOTA    
#		        1 - DIR is out of QUOTA 
# ----------------------------------

# Varible definition
#DIR="/tmp/testdir"		        # Directory to check quota
#QUOTA_MB=50		             	# The max size of the directory directory
DATE=`date +%H:%M:%S_%d.%m.%Y`	# Get the time HH:MM:SS_dd:mm:YY

if [ $# -lt 2 -o $# -gt 2 ]; then
	echo "[$DATE Warnning] : The number of arguments must be 2"
	exit 1
fi

echo $1 | egrep '^[0-9]+$' > /dev/null 2>&1 
if [ ! "$?" -eq "0" ]; then
	echo "[$DATE Warnning] : $1 is not a number"
	exit 1
fi	

# If the file in $DIR path is not a directory, then prints to the stdout that in the current date time the file path is not a directory (using DATE and DIR) and returns an exit code - unsuccessful
if [ ! -d "$2" ]; then
	echo "[$DATE Warnning] : $2 is not a directory or does not exist"		
	exit 1	
fi

while [ 1 = 1 ]; do

# Get the directory size
dir_size_MB=`du -ks $2 | awk '{size=int($1/1024); print size}'`

# If the directory size in megabytes is greater than the threshold, then prints to the stdout a sentence using the local vars DATE, DIR, dir_size_MB and QUOTA_MB, and returns an exit code - unsuccessful. otherwise, prints a sentence to the stdout using the local vars DATE, DIR, dir_size_MB and QUOTA_MB
if [ $dir_size_MB -gt $1 ]; then
	echo "[$DATE Warnning] : $2 size(${dir_size_MB}MB) OUT of quota(${1}MB)"
	#exit 1
else
	echo "[$DATE INFO] : $2 size(${dir_size_MB}MB) in quota(${1}MB)"
fi

sleep 10

# Returns an exit code - successful
#exit 0
done
