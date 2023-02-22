# interfaces
export EXT=enp0s3
export LAN=macsec0


iptables -F

# default behaviour
iptables -P FORWARD DROP				
iptables -P INPUT DROP					
iptables -P OUTPUT ACCEPT				

# 1) permit traffic between LAN and outside with SNAT only if initiated by LAN
iptables -A FORWARD -i $LAN -o $EXT -j ACCEPT
# permit response to communication initiated by LAN
iptables -A FORWARD -m state --state ESTABLISHED -j ACCEPT
iptables -A POSTROUTING -t nat -o $EXT -j SNAT --to 10.23.0.2-10.23.0.254

# 2) deny all traffic to GW except SSH and ICMP only if initated by LAN
iptables -A INPUT -i $LAN -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i $LAN -p icmp -j ACCEPT

# 3) permit all traffic from GW to everywhere (and related response packets)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 4) permit port forwarding with DNAT to hostA2 from outside only for HTTP service
iptables -A FORWARD -i $EXT -o $LAN -p tcp --dport 80 -j ACCEPT
iptables -A PREROUTING -t nat -i $EXT -p tcp --dport 80 -j DNAT --to 10.23.0.3
