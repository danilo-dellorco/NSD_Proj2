#!/bin/bash
# Configurazione Interfacce di Rete
ip addr add 10.123.0.2/16 dev eth0
ip route add default via 10.123.0.1

python3 av/start_av.py &
/bin/bash