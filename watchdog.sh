#!/bin/bash

usage () {
	echo "The script $0 monitors a list of processes from a config file"
	echo "Usage: $0 -f CONF_FILE [-d SEC] [-h]"
	echo "	-f CONF_FILE - path of the config file"
	echo "	-d SEC - seconds for the delay between iterations"
	echo "	-h - displays usage"
}

abort () {
	local date_time=`date +%H:%M:%S_%d.%m.%Y`
	
	echo $date_time $1
	exit 1
}

check_flags () {
	while getopts ":f:d:h" opt; do
		case $opt in
			f)
				config_file_path=$OPTARG;;
			d)
				sleep_sec=$OPTARG;;
			h)
				usage
				exit 0;;
			*)
				abort "ERROR: you do not use $0 correctly. use $0 -h for usage";;
		esac
	done
	shift $((OPTIND-1))
}

check_validation () {
	if [ $1 -eq 0 ]; then
		abort "ERROR: you do not use $0 correctly. use $0 -h for usage" 
	fi

	if [ ! -f $config_file_path ]; then
		abort "ERROR: the path or file does not exist"
	fi

	if ! [[ $sleep_sec =~ ^[0-9]+$ ]]; then
		abort "ERROR: the seconds must be a number"
	fi 
}

print_line () {
	if [ -z $4 ]; then 
		echo "$1) Command $2  Log $3"
	else
		echo "$1) Command $2  Log $3 StdErr $4"
	fi
}

get_pid () {
	local curr_pid=`ps -ef | grep $1 | grep -v grep | awk '{print $2}' | awk 'NR == 1 {print}'`

	# if there is more than one process with the command name (couse by fork)
	# get the root parent pid
	while [ true ]; do
		local curr_ppid=`ps -ef | awk -v var=$pid '{if($2 == var) print $3}'`
		
		ps -ef | awk -v var=$curr_ppid '{if($2 == var) print}' | grep $1
		if [ "$?" -eq "1" ]; then
			break
		fi
	done

	pid=$curr_pid
}

get_ppid () {
	local curr_ppid=`ps -ef | grep $1 | grep -v grep | awk '{print $3}' | awk 'NR == 1 {print}'`

	# if there is more than one process with the command name (couse by fork)
	# get the root parent ppid
	while [ true ]; do
		ps -ef | awk -v var=$curr_ppid '{if($2 == var) print}' | grep $1
		if [ "$?" -eq "1" ]; then
			break
		fi
	done

	ppid=$curr_ppid
}

is_running () {
	ps -ef | grep $1 | grep -v grep > /dev/null 2>&1

	if [ "$?" -eq "0" ]; then
		return 0
	fi

	return 1
}

running () {
	get_pid $1
	get_ppid $1
	
	echo "  -> IS already running [PID=$pid, PPID=$ppid]"
}

not_running () {
	echo "  -> NOT running. restarting..."

	if [ -z $3 ]; then 
		bash $1 > $2 2>&1 &
	else
		bash $1 > $2 2> $3 &
	fi
}

is_line_comment_or_empty () {
	echo "$1" | grep -q '^#'
	
	if [ "$?" -eq "0" ]; then
		return 0
	else
		echo "$1" | grep -q '^$'

		if [ "$?" -eq "0" ]; then
			return 0
		fi
	fi

	return 1
}	

run () {
	local comm_name
	local full_comm
	local log
	local error
	local line_num=1

	while read line; do
		is_line_comment_or_empty "$line"

		if [ "$?" -ne 1 ]; then
			continue
		fi

		comm_name=`echo $line | awk -F':' '{print $1}' | awk '{print $1}'`
		full_comm=`echo $line | awk -F':' '{print $1}'`
		log=`echo $line | awk -F':' '{print $2}'`
		error=`echo $line | awk -F':' '{print $3}'`

		print_line $line_num $comm_name $log $error
		is_running $comm_name
		
		if [ "$?" -eq "0" ]; then
			running $comm_name
		else
			not_running "$full_comm" $log $error
		fi

		line_num=`expr $line_num + 1`
	done < $1
}

#################### Main of the script ####################

sleep_sec=2

check_flags "$@"
check_validation $#

while [ true ]; do
	run $config_file_path
	echo 
	sleep $sleep_sec
done



  
