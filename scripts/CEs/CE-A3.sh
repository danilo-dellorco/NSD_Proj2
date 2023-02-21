#! /bin/bash
echo 1 > /proc/sys/net/ipv4/ip_forward

ip addr add 100.0.13.2/30 dev eth0
ip addr add 10.23.1.1/24 dev eth1

ip route add default via 100.0.13.1
