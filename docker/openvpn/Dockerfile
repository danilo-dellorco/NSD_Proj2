FROM weibeld/ubuntu-networking:latest
RUN mkdir /openvpn
RUN mkdir /.ovpn_tmp    
RUN apt update
RUN apt install -y openvpn easy-rsa telnet nano traceroute
VOLUME /openvpn
ADD script/init-server.sh /script/init-server.sh
ADD script/init-b2.sh /script/init-b2.sh
ADD script/net-b1.sh /script/net-b1.sh
ADD script/net-b2.sh /script/net-b2.sh
ADD script/net-server.sh /script/net-server.sh

ADD config/openssl.cnf /usr/share/easy-rsa/openssl.cnf
ADD config/cred/server_cred /.ovpn_tmp/server_cred
ADD config/cred/b2_cred /.ovpn_tmp/b2_cred
ADD config/cred/ca_cred /.ovpn_tmp/ca_cred

ADD config/ovpn/hostB2.ovpn /.ovpn_tmp/hostB2.ovpn
ADD config/ovpn/server.ovpn /.ovpn_tmp/server.ovpn

ADD config/ccd/hostB2 /.ovpn_tmp/hostB2