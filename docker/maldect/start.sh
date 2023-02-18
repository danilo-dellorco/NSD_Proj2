#!/bin/bash
# comandi configurazione di rete
# ip addr add ..
# ...
ip addr add 33.33.33.33/24 dev eth0
python3 av/start_av.py
/bin/bash