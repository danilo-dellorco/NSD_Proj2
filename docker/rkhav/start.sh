#!/bin/bash

# Configurazione Interfacce di Rete
ip addr add 10.123.0.4/16 dev eth0
ip route add default via 10.123.0.1

echo "Creating Baseline Report.."
rm /var/log/rkhunter*
rkhunter --check --sk --nocolors > /var/log/rkhunter_baseline.log
echo "Initialization Completed"

python3 av/start_av.py &
/bin/bash

