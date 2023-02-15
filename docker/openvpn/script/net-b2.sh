# Assegnazione Interfacce IP
ip addr add 192.168.16.2/24 dev eth0 2>/dev/null
ip route add default via 192.168.16.1 2>/dev/null