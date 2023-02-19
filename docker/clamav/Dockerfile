FROM weibeld/ubuntu-networking:latest
RUN mkdir -p /av/quarantine
RUN mkdir -p /av/reports
RUN apt update
RUN apt install -y telnet nano python3 clamav inotify-tools unzip
RUN freshclam

ADD data.zip /data.zip
RUN unzip data.zip
RUN rm data.zip
