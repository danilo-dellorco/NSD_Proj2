# Configura gli indirizzi dell'interfacce, abilitando il nat
ip route del 0/0 2>/dev/null
ip addr add 2.0.0.1/24 dev eth1 2>/dev/null
ip addr add 192.168.17.2/24 dev eth0 2>/dev/null
ip route add default via 2.0.0.2 2>/dev/null

iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward