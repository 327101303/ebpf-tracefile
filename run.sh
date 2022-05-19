
# sudo ./dist/ctrace trace -e write
# sudo ./dist/ctrace trace -e sys_enter,sys_exit
# sudo ./dist/ctrace trace -e sched_process_exit

sudo ./dist/ctrace trace -t set=fs -t comm!=node,sshd,cpuUsage.sh