# interfaces
export EXT=enp0s3
export LAN=enp0s8

# iptables without -t is implicit referred to filter table
# flush every rule from every chain
iptables -F

# default behaviour
iptables -P FORWARD DROP				# deny all traffic in forward hook
iptables -P INPUT DROP					# deny all traffic in input hook
iptables -P OUTPUT ACCEPT				# permit all traffic in output hook (already present by default)

# 1) permit traffic between LAN and outside with SNAT only if initiated by LAN
iptables -A FORWARD -i $LAN -o $EXT -j ACCEPT
# necesssarie per le eventuali risposte ad una comunicazione iniziata dalla LAN
iptables -A FORWARD -m state --state ESTABLISHED -j ACCEPT
# nel postrouting possiamo utilizzare solo flag -o
# con masquerade mette ip del link, con SNAT --to IP mette un preciso IP o uno nel range specificato
iptables -A POSTROUTING -t nat -o $EXT -j SNAT --to 10.23.0.2-10.23.0.254

# 2) deny all traffic to GW except SSH and ICMP only if initated by LAN
# passiamo per pre-routing, input hooks
# nel input possiamo utilizzare solo flag -i
iptables -A INPUT -i $LAN -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i $LAN -p icmp -j ACCEPT
# necessarie per garantire che solo l'host possa iniziare le connessioni verso il GW e non il contrario
# se initiated by LAN è riferito alla rete esterna allora queste due regole non servono
iptables -A OUTPUT -o $LAN -p icmp -m state --state NEW -j DROP
iptables -A OUTPUT -o $LAN -p tcp --dport 22 -m state --state NEW -j DROP

# 3) permit all traffic from GW to everywhere (and related response packets)
# tutto il traffico in output è permesso dalla policy di default accept
# passiamo per pre-routing, input hooks per i pacchetti di risposta
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 4) permit port forwarding with DNAT to hostA1 and hostA2 from outside only for HTTP service
# passiamo per pre-routing, forward, post-routing hooks
# nel prerouting possiamo utilizzare solo flag -i
# con netcat apriamo porta 80 su server nella LAN-A1 
# riusciamo ad instaurare una connessione http dagli altri due siti qualsiasi host in 10.23.0.0/24 contattiamo
# il gateway re-direziona il traffico verso uno dei due host
iptables -A FORWARD -i $EXT -o $LAN -p tcp --dport 80 -j ACCEPT
iptables -A PREROUTING -t nat -i $EXT -p tcp --dport 80 -j DNAT --to 10.23.0.2-10.23.0.3
