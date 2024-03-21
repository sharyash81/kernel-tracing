#!/bin/bash
sudo lttng create $1
sudo lttng enable-event -k --syscall --all
sudo lttng enable-event -k sched_switch,sched_wak'*',irq_'*',net_'*',skb_'*'
sudo lttng enable-event -k lttng_statedump_'*'
sudo lttng add-context -k -t vtid -t vpid -t procname -t prio
