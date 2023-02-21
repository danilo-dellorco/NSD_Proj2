#! /bin/bash
echo 1 > /proc/sys/net/ipv4/ip_forward

ip addr add 100.0.32.2/30 dev eth0
ip addr add 10.123.0.1/16 dev eth1

ip route add default via 100.0.32.1
