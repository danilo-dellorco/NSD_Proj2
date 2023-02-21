#! /bin/bash
echo 1 > /proc/sys/net/ipv4/ip_forward

ip addr add 100.0.13.2/30 dev enp0s3
ip addr add 10.23.1.1/24 dev enp0s8

ip route add default via 100.0.13.1