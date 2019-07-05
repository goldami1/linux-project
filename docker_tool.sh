#!/bin/bash

usage () {
	echo "Usage: docker_tool.sh	[-c clean_ps -s <status> |"
	echo "			-c build_push -r <url_to_registry> -u <user>"
	echo "			-p <password> -v <tag>]"
	echo
	echo "  -c clean_ps: Removes all the docker containers with a given <status>,"
	echo "		status can be \"running\" or \"exited\"."
	echo
	echo "  -c build_push: Build the image (using ./Dockerfile),"
	echo "    then tag it with <tag> and push it to registry (given -r\\-u\\-p)."
	echo "    After successful push the local image will be removed."
}

abort () {
	echo $1
	exit 1
}

get_command_args_num () {
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

is_command_arg_exist () {
	if [ -z $1 ]; then
		usage
		exit 1
	fi
}

compare_args_num () {
	if [ $1 -ne $2 ]; then
		usage
		exit 1
	fi
}

command_flag () {
	while getopts "c:" opt; do
		case $opt in
			c)
				command_name=$OPTARG
				break
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
	shift $((OPTIND-1))
}

set_status_var () {
	if [ $1 = "running" ] || [ $1 = "exited" ]; then
		status=$1
	else
		abort "status must be running or exited"
	fi
}

clean_ps_flags () {
	while getopts "s:" opt; do
		case $opt in
			s)
				set_status_var $OPTARG
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
}

build_push_flags () {
	while getopts "r:u:p:v:" opt; do
		case $opt in
			r)
				url_to_registry=$OPTARG
				;;
			u)
				user=$OPTARG
				;;
			p)
				password=$OPTARG
				;;
			v)
				tag=$OPTARG
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
}

execute_clean_ps () {
	docker rm --force $(docker ps -a --filter status=$1 | awk 'NR>1 { print $1 }') > /dev/null 2>&1
}

execute_build_push () {
	local dockerId=`docker build -t "$1:$4" . | grep "Successfully built" | cut -d" " -f3`
	if [ $? -ne 0 ]; then
		abort "Failed building docker container"
	fi
	docker login --username=$2 --password=$3 2>/dev/null && docker push $1 && docker rmi --force $dockerId  || abort "Wrong Credentials"
}

###################### Main of the script ######################

is_command_arg_exist $2
command_flag "$@"
case $command_name in
	clean_ps)
		compare_args_num `get_command_args_num "$@"` 2
		clean_ps_flags "$@"
		execute_clean_ps $status
		;;
	build_push)
		compare_args_num `get_command_args_num "$@"` 5
		build_push_flags "$@"
		execute_build_push $url_to_registry $user $password $tag
		;;
	*)
		abort "Command does not exist"
		;;
esac


