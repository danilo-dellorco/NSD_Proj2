# Assegnazione Interfacce IP
ip addr add 192.168.16.2/24 dev eth0 2>/dev/null
ip route add default via 192.168.16.1 2>/dev/null

# Creazione Directory OpenVPN
mkdir /gns3volumes/openvpn/keys
cp /.ovpn_tmp/hostB2.ovpn /gns3volumes/openvpn/hostB2.ovpn
rm -drf /.ovpn_tmp /script/init-b2.sh