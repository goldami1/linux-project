#!/bin/bash

usage () {
	echo "Usage: docker_tool.sh	[-c clean ps -s <status> |"
	echo "			-c build_push -r <url_to_registry> -u <user>"
	echo "			-p <password> -v <tag>] [-t]"
	echo
	echo "  -c clean_ps: Removes all the docker containers with a given <status>,"
	echo "		status can be \"running\" or \"exited\"."
	echo
	echo "  -c build_push: Build the image (using ./Dockerfile),"
	echo "    then tag it with <tag> and push it to registry (given -r\\-u\\-p)."
	echo "    After successful push the local image will be removed."
}

command_flag () {
	while getopts "c:" opt; do
		case $opt in
			c)
				command_name=$OPTARG
				;;
			*)
				usage
				exit 1
				;;
		esac
	done
#	shift $((OPTIND-1))
}

clean_ps_flags () {
	while getopts "s:" opt; do
		case $opt in
			s)
				status=$OPTARG
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

###################### Main of the script ######################

command_flag "$@"
case $command_name in
	clean_ps)
		clean_ps_flags "$@"
		;;
	build_push)
		build_push_flags "$@"
		;;
esac

echo "url_to_registry is $url_to_registry"
echo "user is $user"
echo "password is $password"
echo "tag is $tag"
echo "status is $status"
echo "command_name is $command_name"