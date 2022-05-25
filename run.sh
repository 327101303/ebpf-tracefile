
# sudo ./dist/ctrace trace -e write
# sudo ./dist/ctrace trace -e sys_enter,sys_exit
# sudo ./dist/ctrace trace -e sched_process_exit

# sudo ./dist/ctrace trace -t set=clone -t comm!=node,sshd,cpuUsage.sh
# sudo ./dist/ctrace trace -t set=fs  -t comm!=node,sshd,cpuUsage,cpptools,cat
# sudo ./dist/ctrace trace -t event=listen  -t comm!=node,sshd,cpuUsage,cpptools,cat
sudo ./dist/ctrace trace -t event=vfs_write  -t comm!=node,sshd,cpuUsage,cpptools,cat