# Configura gli indirizzi dell'interfacce, abilitando il nat
ip route del 0/0 2>/dev/null
ip addr add 2.0.0.1/24 dev eth1 2>/dev/null
ip addr add 192.168.17.2/24 dev eth0 2>/dev/null
ip route add default via 2.0.0.2 2>/dev/null

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configura chiavi e certificati openvpn sul Server
openssl rand -writerand /.rnd
cd /usr/share/easy-rsa 1>/dev/null
. ./vars 1>/dev/null
./clean-all 1>/dev/null
./build-ca < /.ca_cred
./build-key-server server < /.server_cred
./build-dh
./build-key hostB1 < /.b1_cred
./build-key hostB2 < /.b2_cred

# Configura le cartelle utilizzate per OpenVPN
cp -r /usr/share/easy-rsa/keys/ /gns3volumes/openvpn/
mkdir /gns3volumes/openvpn/ccd