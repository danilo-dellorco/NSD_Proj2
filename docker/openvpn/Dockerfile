FROM weibeld/ubuntu-networking:latest
RUN mkdir /openvpn
RUN apt update
RUN apt install -y tmux openvpn easy-rsa telnet python3 nano wget
VOLUME /openvpn
ADD script/init-server.sh /script/init-server.sh
ADD script/init-b1.sh /script/init-b1.sh
ADD script/init-b2.sh /script/init-b2.sh

ADD config/openssl.cnf /usr/share/easy-rsa/openssl.cnf
ADD config/.ca_cred /.server_cred
ADD config/.b1_cred /.b1_cred
ADD config/.b2_cred /.b2_cred
ADD config/.ca_cred /.ca_cred