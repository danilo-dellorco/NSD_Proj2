# interfaces
export EXT=eth0
export LAN=eth1
export CENTRAL_NODE=10.23.1.2
export AV1=10.123.0.2
export AV3=10.123.0.4

iptables -F

iptables -P FORWARD DROP
iptables -P INPUT DROP
iptables -P OUTPUT DROP

# 1) permit bidirectional traffic between central node and the AVs

iptables -A FORWARD -i $EXT -o $LAN -s $CENTRAL_NODE -m iprange --dst-range $AV1-$AV3 -j ACCEPT
iptables -A FORWARD -i $LAN -o $EXT -m iprange --src-range $AV1-$AV3 -d $CENTRAL_NODE -j ACCEPT

# we need to achieve also the communication between spokes otherwise it wouldn't make sense the hub-and-spoke topology
iptables -A FORWARD -i $EXT -s 10.23.0.0/24 -d 10.23.1.0/24 -j ACCEPT
iptables -A FORWARD -i $EXT -s 10.23.1.0/24 -d 10.23.0.0/24 -j ACCEPT
