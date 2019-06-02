# The shell path that will execute this script
#!/bin/bash
# -----------------------------------------------
# Description : Check the system status in terms of cpu_idle and free_mem.
# Input		  : None
# Exit code   : Number of failed checks.
# -----------------------------------------------

# Thresholds for the checks
CPU_IDLE_MIN=90	
FREE_MEM_MB_MIN=60
FREE_SWAP_MB_MIN=50
LOGGED_IN_USERS_MAX=4

while [ 1 = 1 ]; do
# Local var that has the count of the failed tests
count_failed_test=0

# Prints a sentence to the stdout
echo "Checking status..."
# Local var that has the average idle percentage of one report of global statistics among all processors at 3 second interval
cpu_idle=`mpstat 3 1| grep Average| awk '{idle=int($12); print idle}'`
# Local var that has the free memory space in megabytes
free_mem_MB=`free -m| grep Mem| awk '{print $4}'`
free_swap_MB=`free -m | grep Swap | awk '{print $4}'`
logged_in_users=`who | wc -l`

# Prints a sentence to the stdout using the local vars "cpu_idle" and "CPU_IDLE_MIN" 
echo "cpu_idle    : current $cpu_idle%, minimal $CPU_IDLE_MIN%"	
# If cpu idle percentage is lower than the threshold (CPU_IDLE_MIN), then prints "Not OK" to the stdout and increases the counter of failed tests by one (count_failed_test)	
if [ $cpu_idle -lt $CPU_IDLE_MIN ]; then
	echo "-Not OK"
	count_failed_test=`expr $count_failed_test + 1`
fi

# Prints a sentence to the stdout using the local vars "free_mem_MB" and "FREE_MEM_MB_MIN"
echo "free_mem_MB : current ${free_mem_MB}MB, minimal ${FREE_MEM_MB_MIN}MB"
# If free memory space in megabytes is lower than the threshold, then prints "Not OK" to the stdout and increases the counter of failed tests by one (count_failed_test)
if [ $free_mem_MB -lt $FREE_MEM_MB_MIN ]; then
	echo "-Not OK"
	count_failed_test=`expr $count_failed_test + 1`
fi

echo "free_swap_MB : current ${free_swap_MB}MB, minimal ${FREE_SWAP_MB_MIN}MB"
if [ $free_swap_MB -lt $FREE_SWAP_MB_MIN ]; then
	echo "-Not OK"
	count_failed_test=`expr $count_failed_test + 1`
fi

echo "logged_in_users : current ${logged_in_users}, maximum ${LOGGED_IN_USERS_MAX}"
if [ $logged_in_users -gt $LOGGED_IN_USERS_MAX ]; then
	echo "-Not OK"
	count_failed_test=`expr $count_failed_test + 1`
fi

# Local var that has the local date time
current_date=`date`
# If the number of failed tests is greater then 0, then prints a sentence to the stdout using the local var "current_date" and returns an exit code - unsuccessful. otherwise, prints a sentence to the stdout using the local var "current_date" and returns an exit code - successful
if [ $count_failed_test -gt 0 ]; then
	echo "====> SUM: Status NOT OK [$current_date]"	
	#exit 1
else
	echo "====> SUM: Status OK [$current_date]"
	#exit 0
fi

done
