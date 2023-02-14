# Assegnazione Interfacce IP
ip addr add 192.168.17.1/24 dev eth0 2>/dev/null
#ip route add default via 192.168.17.2 2>/dev/null
# Valutare se è necessario o è giusto avere la default route

# Creazione Directory OpenVPN
mkdir /gns3volumes/openvpn/keys