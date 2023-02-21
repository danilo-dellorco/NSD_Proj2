#! /bin/bash

ip addr add 10.23.1.2/30 dev eth0
ip route add default via 10.23.1.1