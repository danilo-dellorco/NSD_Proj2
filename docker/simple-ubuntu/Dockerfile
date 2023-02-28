FROM weibeld/ubuntu-networking:latest
RUN apt update
RUN apt install -y telnet nano python3 unzip wget
RUN mkdir /scripts
ADD scripts/CE-A1.sh /scripts/CE-A1.sh 
ADD scripts/CE-A2.sh /scripts/CE-A2.sh
ADD scripts/CE-A3.sh /scripts/CE-A3.sh
ADD scripts/firewall_CE-A2.sh /scripts/firewall_CE-A2.sh
