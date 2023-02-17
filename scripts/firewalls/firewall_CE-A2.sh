# interfaces
export EXT=enp0s3
export LAN=enp0s8
export CENTRAL_NODE=10.23.1.2
export AV1=10.123.0.2
export AV3=10.123.0.4
#AV2 with address 10.123.0.3

# iptables without -t is implicit referred to filter table
# flush every rule from every chain
iptables -F

# default behavior drop everything
iptables -P FORWARD DROP
iptables -P INPUT DROP
iptables -P OUTPUT DROP

# 1) permit bidirectional traffic between central node and the AVs
# dobbiamo consentire il forwarding dei pacchetti dagli AVs verso il central node e viceversa
# penso è meglio specificare il range preciso di indirizzi che la rete complessiva, è più sicuro
# se si aggiungono altre macchine che non sono AV queste non potranno comunicare con il central node
iptables -A FORWARD -i $EXT -o $LAN -s $CENTRAL_NODE --dst-range $AV1-$AV3 -j ACCEPT
iptables -A FORWARD -i $LAN -o $EXT --src-range $AV1-$AV3 --d $CENTRAL_NODE -j ACCEPT

# dobbiamo permette comunque la comunicazione tra gli spokes altrimenti non ha senso avere questa topologia
iptables -A FORWARD -i $EXT -o $LAN -s 10.23.0.0/24 -d 10.23.1.0/24 -j ACCEPT
iptables -A FORWARD -i $LAN -o $EXT -s 10.23.1.0/24 -d 10.23.0.0/24 -j ACCEPT