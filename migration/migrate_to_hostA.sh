#!/bin/bash

PREFIX=`dirname $0`
PREFIX=`readlink -f $PREFIX`
source $PREFIX/common.sh

#echo preparing the target host
ssh $HOST_A_IP $COMMON_PREFIX/listen_for_incoming_guest.sh
sleep 1

#echo requesting migration
$PREFIX/qemu_monitor_cmd.py $HOST_B_IP 4444 "migrate -d tcp:$HOST_A_IP:6666"

#echo migration result
while true; do
	RESULT=`$PREFIX/qemu_monitor_cmd.py $HOST_B_IP 4444 "info migrate"`
	echo "$RESULT"
	echo
	if [ `echo "$RESULT" | grep active | wc -l` == "0" ]; then break; fi
	sleep 0.1
done

#echo send an update to guest
#ssh $HOST_A_IP "$COMMON_PREFIX/ssh_to_local_guest.sh \"ifconfig eth1 down; ifconfig eth1 up\""
ssh $HOST_A_IP "sudo $CLICK_PATH/userlevel/click $CLICK_PATH/conf/xia/xia_vm_ping_update_hostA.click"

#echo done

