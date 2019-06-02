#!/bin/bash

usage () {
	echo Usage: mytasks.sh [task name] [task params]
	echo "  task=du_dirs -s <source dir>"
	echo "    list all the directories that exist inside <source_dir> order by size."
	echo "    Line for example: <dir name> <size in MB>"
	echo 
	echo "  task=find_shell_scripts -s <source dir> [-x]"
	echo "    list all shell scripts from source dir(including sub folders)."
	echo "    Flag -x set execution user permission to the scripts if needed."
	echo
	echo "  task=send_signals -p <config file>"
	echo -e "    Read the config file and send the relevant signal to each process name in\n    the config file."
	echo "    Every line in the config file should look like this → <signalname>:<process_name>"
	echo -e "    The task ignore empty lines or comments. Send the signal only if <process_name> is\n    running."
	echo
	echo "  task=delete_old_files -s <source_dir> -m <days>"
	echo -e "    Delete all the files(regular files) in <source_dir> that was not modified in the\n    last <days>."
	echo "    Note – delete files only inside <source_dir> (no need to sub directories)."
	echo
	echo "  task=sync_dir -s <source dir> -d <destination dir>"
	echo "    Sync all files from source dir to destination dir."
	echo "    Means copy all files\dir that does not exist on destination dir."        
        echo
	echo "  task=list_net_cards"
	echo "    Show all network interface names and for each name show its IP."
	echo "    Line for example: <network name> <IP>"
	echo
	echo "  task=list_rpms"
	echo "    Show all rpm names and for each name show its version, vendor and install date."
        echo "    Line for example: <rpm name> <version> <vendor> <install date>"
	echo
	echo "  task=ps_threads"
	echo -e "    List of all process names in the system and show their PID and how many threads\n    running inside."
	echo "    Line for example: <PID> <proc name> <number of threads>"
	echo "  task=shellshock"
	echo "    Print “shellshock” if the system exposes to the shellshock (first SVE)."
}

abort () {
	echo $1
	exit 1
}

trap_signals () {
	echo "I'll be back ;)"
}

get_task_args_num () {
	local args_num=0
	local regex='^-.$'

	for arg in "$@"; do
		if [[ $arg =~ $regex ]] || [ $arg = $1 ]; then
			continue
		fi
		
		args_num=`expr $args_num + 1`
	done	

	echo $args_num
}

check_task_args_num () {
	if [ $1 -ne $2 ]; then
		usage
		exit 1
	fi
}

set_source_dir_var () {
	if [ ! -d $1 ]; then
		abort "source_dir must be a valid path and a directory"
	else
		source_dir=$1
	fi
}

set_config_file_var () {
	if [ ! -f $1 ]; then
		abort "config_file must be a valid path and a file"
	else
		config_file=$1
	fi
}

set_days_var () {
	local regex='^[0-9]+$'

	if ! [[ $1 =~ $regex ]]; then
		abort "days must be a number"
	else
		days=$1
	fi
}

set_destination_dir_var () {
	if [ ! -d $1 ]; then
		abort "destination_dir must be a valid path and a directory"
	else
		destination_dir=$1
	fi
}

du_dirs_flags () {
	OPTIND=2
	while getopts "s:" opt; do
		case $opt in
			s)
				set_source_dir_var $OPTARG
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
	shift $((OPTIND-1))
}

find_shell_scripts_flags () {
	execution_user_permmision=0
	OPTIND=2
	while getopts "s:x" opt; do
		case $opt in
			s)
				set_source_dir_var $OPTARG
				;;
			x)
				execution_user_permmision=1
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
	shift $((OPTIND-1))
}

send_signals_flags () {
	OPTIND=2
	while getopts "p:" opt; do
		case $opt in
			p)
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

delete_old_files_flags () {
	OPTIND=2
	while getopts "s:m:" opt; do
		case $opt in
			s)
				set_source_dir_var $OPTARG
				;;
			m)
				set_days_var $OPTARG
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
	shift $((OPTIND-1))
}

sync_dir_flags () {
	OPTIND=2
	while getopts "s:d:" opt; do
		case $opt in
			s)
				set_source_dir_var $OPTARG
				;;
			d)
				set_destination_dir_var $OPTARG
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
	shift $((OPTIND-1))
}

no_flags () {
	OPTIND=2
	while getopts ":*:" opt; do
		case $opt in
			*)
				usage
				exit 1
				;;
		esac
	done
	shift $((OPTIND-1))
}

execute_du_dirs () {
	du -hBM --max-depth=1 $1 | sort -h | sed 's/\.\///g' | awk '{ for(i=2;i<=NF;i++){printf "%s ", $i}; printf "%s\n", $1 }' | egrep -wv '^\.'
}

execute_find_shell_scripts () {
	if [ $2 -eq 1 ]; then
		find $1 -type f -name "*.sh" -print -exec chmod u+x 2>/dev/null {} \;
	else
		find $1 -type f -name "*.sh" -print
	fi
}

execute_send_signals () {
	while read line; do
		is_line_comment_or_empty "$line"
		
		if [ $? -ne 1 ]; then
			continue
		fi
		
		local signal_name=`echo $line | cut -d':' -f1`
		local process_name=`echo $line | cut -d':' -f2`

		is_process_running $process_name
		
		if [ $? -eq 0 ]; then
			local pid=`get_pid $process_name`
			kill -$signal_name $pid
		fi
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

is_process_running () {
	ps -ef | awk '{ printf " %s\n", $8 }' | grep " $1" | grep -v grep > /dev/null 2>&1

	if [ $? -eq 0 ]; then
		return 0
	fi

	return 1
}

get_pid () {
	local curr_pid=`ps -ef | awk '{ print $2,$8 }' | grep " $1" | grep -v grep | awk '{ print $1 }' | awk 'NR == 1 { print }'`

	# if there is more than one process with the command name (couse by fork)
	# get the root parent pid
	while [ true ]; do
		local curr_ppid=`ps -ef | awk -v var=$pid '{if($2 == var) print $3}'`
		
		ps -ef | awk -v var=$curr_ppid '{if($2 == var) print}' | awk '{ printf " %s\n", $8 }' | grep " $1"
		if [ $? -eq 1 ]; then
			break
		fi
	done

	echo $curr_pid
}	

execute_delete_old_files () {
	find $1 -mtime +$2 -type f -exec rm > /dev/null 2>&1 {} \;
}

execute_sync_dir () {
	find $1 -type f | while read file_path; do 
		find $2 -type f -name file_path | grep -q "." > /dev/null 2>&1
		if [ $? -ne 0 ]; then
			local file_name=${file_path##*/}
			cp $file_path $2/$file_name
		fi
	done
}

execute_list_net_cards () {
	ifconfig -a | sed 's/[: \t].*//;/^$/d' | while read network_name; do
		local ip=`ifconfig $network_name | grep inet | egrep -o 'inet ([0-9]{1,3}[\.]){3}[0-9]{1,3}' | cut -d' ' -f2`
		if [ $? -eq 0 ]; then
			echo $network_name $ip
		fi
	done
}

execute_list_rpms () {
	rpm -qai | egrep '^Name  |^Version|^Vendor|^Install Date'| awk -F': ' '{ print $2 }' | awk '{line=line " " $0} NR%4==0{print substr(line,2); line=""}'
}

execute_ps_threads () {
	ps -ef | awk 'NR>1 { print $2,$8 }' | while read line; do
		local pid=`echo $line | cut -d' ' -f1 2> /dev/null`
		echo -n "${line} "  
		ps -T -p $pid | grep -v PID | wc -l
	done
}

execute_shellshock () {
	env x='() { :;}; echo shellshock' bash -c 'echo -n'
}

###################### Main of the script ######################

trap trap_signals SIGINT SIGTERM

case $1 in 
	du_dirs)
		check_task_args_num `get_task_args_num "$@"` 1
		du_dirs_flags "$@"
		execute_du_dirs	$source_dir
		;;
	find_shell_scripts)
		check_task_args_num `get_task_args_num "$@"` 1
		find_shell_scripts_flags "$@"
		execute_find_shell_scripts $source_dir $execution_user_permmision 
		;;
	send_signals)
		check_task_args_num `get_task_args_num "$@"` 1
		send_signals_flags "$@"
		execute_send_signals $config_file
		;;
	delete_old_files)
		check_task_args_num `get_task_args_num "$@"` 2
		delete_old_files_flags "$@"
		execute_delete_old_files $source_dir $days
		;;
	sync_dir)
		check_task_args_num `get_task_args_num "$@"` 2
		sync_dir_flags "$@"
		execute_sync_dir $source_dir $destination_dir
		;;
	list_net_cards)
		check_task_args_num `get_task_args_num "$@"` 0
		no_flags "$@"
		execute_list_net_cards
		;;
	list_rpms)
		check_task_args_num `get_task_args_num "$@"` 0
		no_flags "$@"
		execute_list_rpms
		;;
	ps_threads)
		check_task_args_num `get_task_args_num "$@"` 0
		no_flags "$@"
		execute_ps_threads
		;;
	shellshock)
		check_task_args_num `get_task_args_num "$@"` 0
		no_flags "$@"
		execute_shellshock
		;;
	*)
		usage
		exit 1
		;;
esac








