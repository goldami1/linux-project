#!/bin/bash

usage () {
	echo "Usage: systemStatus.sh -c [config_file]"
	echo "  This script checks the system status according the config file thresholds"
}

abort () {
	echo $1
	exit 1
}

check_args_num () {
	if [ $1 -ne 1 ]; then
		usage
		exit 1
	fi
}

get_args_num () {
	local args_num=0
	local regex='^-.$'

	for arg in "$@"; do
		if [[ $arg =~ $regex ]]; then
			continue
		fi
		
		args_num=`expr $args_num + 1`
	done	

	echo $args_num
}

check_args_num () {
	if [ $1 -ne $2 ]; then
		usage
		exit 1
	fi
}


set_config_file_var () {
	if [ ! -f $1 ]; then
		abort "config_file must be a valid path and a file"
	else
		config_file=$1
	fi
}

check_flags () {
	while getopts "c:" opt; do
		case $opt in
			c)
				set_config_file_var $OPTARG
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
	shift $((OPTIND-1))
}

read_config_file () {
	while read line; do
		is_line_comment_or_empty "$line"

		if [ $? -ne 1 ]; then
			continue
		fi

		handle_line_with_severity "$line"
	done < $1
}

is_line_comment_or_empty () {
	echo "$1" | egrep -q '^\s*#'
	
	if [ $? -eq 0 ]; then
		return 0
	else
		echo "$1" | egrep -q '^\s*$'

		if [ $? -eq 0 ]; then
			return 0
		fi
	fi

	return 1
}

parse_param_in_line () {
	echo $1 | awk -v var=$2 '{ print $var }'
}

handle_line_with_severity () {
	local severity=`parse_param_in_line "$1" 1`

	case $severity in
		L)
			handle_line_with_sign "$1" $severity
			;;
		M)	
			handle_line_with_sign "$1" $severity
			;;
		H)	
			handle_line_with_sign "$1" $severity
			;;
		*)
			echo "warning: $severity unknown severity"
			;;
	esac
}

handle_line_with_sign () {
	local sign=`parse_param_in_line "$1" 3`

	case $sign in
		">")
			handle_line_with_verification "$1" $2 "maximal" "-gt"
			;;
		"<")
			handle_line_with_verification "$1" $2 "minimal" "-lt"
			;;
		*)
			echo "warning: $sign unknown sign"
			;;
	esac
}

handle_line_with_verification () {
	local verification=`parse_param_in_line "$1" 2`
	local threshold=`parse_param_in_line "$1" 4`

	case $verification in 
		cpu_idle)
			cpu_idle $2 $3 $4 $threshold 
			;;
		free_mem_mb)
			free_mem_mb $2 $3 $4 $threshold
			;;
		free_swap_mb)
			free_swap_mb $2 $3 $4 $threshold
			;;
		logged_in_users)
			logged_in_users $2 $3 $4 $threshold
			;;
		threads_per_processes)
			threads_per_processes $2 $3 $4 $threshold
			;;
		open_ports)
			open_ports $2 $3 $4 $threshold
			;;
		rpm_size_gb)
			rpm_size_gb $2 $3 $4 $threshold
			;;
		docker_images)
			docker_images $2 $3 $4 $threshold 
			;;
		file_system_usage)
			file_system_usage $2 $3 $4 $threshold
			;;
		*)
			echo "warning: $verification unknown verification name"
			;;
	esac	
}

cpu_idle () {
	local severity=$1
	local sign_verbal=$2
	local sign=$3
	local threshold=$4

	local isPassed=1
	local cpu_idle=`mpstat 3 1| grep Average| awk '{idle=int($12); print idle}'`
	
	echo "[`date`] cpu_idle	: current $cpu_idle%, $sign_verbal $threshold"	
	threshold=`echo $threshold | sed 's/.$//'`
	
	if [ $cpu_idle $sign $threshold ]; then
		echo "-Not OK"
		isPassed=0
	fi
	
	increase_severity_counter $1 $isPassed
}

free_mem_mb () {
	local severity=$1
	local sign_verbal=$2
	local sign=$3
	local threshold=$4

	local isPassed=1
	local free_mem_mb=`free -m | grep Mem | awk '{ print $4 }'`
	
	echo "[`date`] free_mem_MB : current ${free_mem_mb}MB, $sign_verbal $threshold"	
	threshold=`echo $threshold | sed 's/..$//'`	

	if [ $free_mem_mb $sign $threshold ]; then
		echo "-Not OK"
		isPassed=0
	fi
	
	increase_severity_counter $1 $isPassed
}

free_swap_mb () {
	local severity=$1
	local sign_verbal=$2
	local sign=$3
	local threshold=$4

	local isPassed=1
	local free_swap_mb=`free -m | grep Swap | awk '{print $4}'`
	
	echo "[`date`] free_swap_MB : current ${free_swap_mb}MB, $sign_verbal $threshold"	
	threshold=`echo $threshold | sed 's/..$//'`	

	if [ $free_swap_mb $sign $threshold ]; then
		echo "-Not OK"
		isPassed=0
	fi
	
	increase_severity_counter $1 $isPassed
}

logged_in_users () {
	local severity=$1
	local sign_verbal=$2
	local sign=$3
	local threshold=$4

	local isPassed=1
	local logged_in_users=`who | wc -l`
	
	echo "[`date`] logged_in_users : current ${logged_in_users}, $sign_verbal $threshold"	
	
	if [ $logged_in_users $sign $threshold ]; then
		echo "-Not OK"
		isPassed=0
	fi
	
	increase_severity_counter $1 $isPassed
}

threads_per_processes () {
	local severity=$1
	local sign_verbal=$2
	local sign=$3
	local threshold=$4

	local isPassed=1
	local processes_num=0
	local processes_pids=`ps -ef | awk 'NR>1 { print $2 }'`

	for pid in $processes_pids; do
		local threads_num=`ps -T -p $pid | wc -l`
		
		if [ $threads_num $sign $threshold ]; then
			processes_num=`expr $processes_num + 1`
		fi
	done
	
	echo "[`date`] threads_per_processes : current $processes_num processes, $sign_verbal $threshold threads"	
	
	if [ $processes_num -gt 0 ]; then
		echo "-Not OK"
		isPassed=0
	fi
	
	increase_severity_counter $1 $isPassed
}

open_ports () {
	local severity=$1
	local sign_verbal=$2
	local sign=$3
	local threshold=$4

	local isPassed=1
	local open_ports_num=`netstat -l | wc -l`
	
	echo "[`date`] open_ports : current $open_ports_num, $sign_verbal $threshold"	
	
	if [ $open_ports_num $sign $threshold ]; then
		echo "-Not OK"
		isPassed=0
	fi
	
	increase_severity_counter $1 $isPassed
}

rpm_size_gb () {
	local severity=$1
	local sign_verbal=$2
	local sign=$3
	local threshold=$4

	local isPassed=1
	local rpms_sizes=`rpm -qai | egrep '^Size' | awk '{ print $3 }'`
	local does_rpm_exist=0

	threshold=`echo $threshold | sed 's/..$//'`

	for rpm_size in $rpms_sizes; do
		rpm_size=`expr $rpm_size / 1024 / 1024 / 1024`		

		if [ $rpm_size $sign $threshold ]; then
			does_rpm_exist=1
			break
		fi
	done

	if [ $does_rpm_exist -eq 1 ]; then
		echo "[`date`] rpm_size : current there is rpm with size ${rpm_size}GB, $sign_verbal ${threshold}GB"
	else
		echo "[`date`] rpm_size : current there is no rpm with size, $sign_verbal ${threshold}GB"	
	fi
	
	if [ $does_rpm_exist -eq 1 ]; then
		echo "-Not OK"
		isPassed=0
	fi
	
	increase_severity_counter $1 $isPassed
}

docker_images () {
	local severity=$1
	local sign_verbal=$2
	local sign=$3
	local threshold=$4

	local isPassed=1
	local docker_images_num=`docker images -a | tail -n +2 | wc -l`

	echo "[`date`] docker_images : current $docker_images_num, $sign_verbal $threshold"
	
	if [ $docker_images_num $sign $threshold ]; then
		echo "-Not OK"
		isPassed=0
	fi
	
	increase_severity_counter $1 $isPassed
}

file_system_usage () {
	local severity=$1
	local sign_verbal=$2
	local sign=$3
	local threshold=$4

	local isPassed=1
	local files_system_usage=`df -a | awk '{ print $5 }' | tail -n +2`
	local regex='^-$'
	local does_fs_exist=0

	threshold=`echo $threshold | sed 's/.$//'`

	for file_system_usage in $files_system_usage; do
		if [[ $file_system_usage =~ $regex ]]; then
			continue
		else
			file_system_usage=`echo $file_system_usage | sed 's/.$//'`
		fi

		if [ $file_system_usage $sign $threshold ]; then
			does_fs_exist=1
			break
		fi
	done
	
	if [ $does_fs_exist -eq 1 ]; then
		echo "[`date`] file_system_usage : current there is fs with ${file_system_usage}% in size, $sign_verbal ${threshold}%"
	else
		echo "[`date`] file_system_usage : current there is no fs with usage in size, $sign_verbal ${threshold}%"
	fi	

	if [ $does_fs_exist -eq 1 ]; then
		echo "-Not OK"
		isPassed=0
	fi
	
	increase_severity_counter $1 $isPassed
}

increase_severity_counter () {
	case $1 in
		L)
			if [ $2 -eq 1 ]; then
				low_severity_passed_counter=`expr $low_severity_passed_counter + 1`
			else
				low_severity_failed_counter=`expr $low_severity_failed_counter + 1`
			fi
			;;
		M)
			if [ $2 -eq 1 ]; then
				medium_severity_passed_counter=`expr $medium_severity_passed_counter + 1`
			else
				medium_severity_failed_counter=`expr $medium_severity_failed_counter + 1`
			fi
			;;
		H)
			if [ $2 -eq 1 ]; then
				high_severity_passed_counter=`expr $high_severity_passed_counter + 1`
			else
				high_severity_failed_counter=`expr $high_severity_failed_counter + 1`
			fi
			;;
	esac
}

print_statistics () {
	echo -e "\n" 
	echo Low Severity: passed $1, failed $2
	echo Medium Severity: passed $3, failed $4
	echo High Severity: passed $5, failed $6
}

###################### Main of the script ######################

check_args_num `get_args_num "$@"` 1
check_flags "$@"

low_severity_passed_counter=0
low_severity_failed_counter=0
medium_severity_passed_counter=0
medium_severity_failed_counter=0
high_severity_passed_counter=0
high_severity_failed_counter=0

cpu_idle=0
free_mem_mb=0
free_swap_mb=0
logged_in_users=0

while [ true ]; do
	echo -e "\nChecking status..."
	read_config_file $config_file
	print_statistics $low_severity_passed_counter $low_severity_failed_counter $medium_severity_passed_counter $medium_severity_failed_counter $high_severity_passed_counter $high_severity_failed_counter
done














