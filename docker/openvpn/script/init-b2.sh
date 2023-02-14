# Assegnazione Interfacce IP
ip addr add 192.168.16.2/24 dev eth0 2>/dev/null
ip route add 2.0.0.0 via 192.168.16.1 2>/dev/null

# Creazione Directory OpenVPN
mkdir /gns3volumes/openvpn/keys