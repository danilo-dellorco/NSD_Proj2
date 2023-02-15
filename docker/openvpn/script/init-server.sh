# Configura gli indirizzi dell'interfacce, abilitando il nat
ip route del 0/0 2>/dev/null
ip addr add 2.0.0.1/24 dev eth1 2>/dev/null
ip addr add 192.168.17.2/24 dev eth0 2>/dev/null
ip route add default via 2.0.0.2 2>/dev/null

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configura chiavi e certificati openvpn sul Server
openssl rand -writerand /.rnd
cd /usr/share/easy-rsa 1>/dev/null
source ./vars 1>/dev/null
./clean-all 1>/dev/null
./build-ca < /.ovpn_tmp/ca_cred
./build-key-server server < /.ovpn_tmp/server_cred
./build-dh
./build-key hostB2 < /.ovpn_tmp/b2_cred

# Configura le cartelle utilizzate per OpenVPN
mkdir /gns3volumes/openvpn/ccd 2>/dev/null
cp -r /usr/share/easy-rsa/keys/ /gns3volumes/openvpn/
cp /.ovpn_tmp/server.ovpn /gns3volumes/openvpn/server.ovpn
cp /.ovpn_tmp/hostB2 /gns3volumes/openvpn/ccd/hostB2

rm -drf /.ovpn_tmp /script/init-server.sh