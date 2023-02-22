FROM weibeld/ubuntu-networking:latest
RUN apt update
RUN apt install -y telnet nano python3 unzip wget python3-pip
RUN pip3 install --upgrade pip
#RUN apt install rkhunter // This is Done in the container because requires user input for configurations

ADD data.zip /data.zip
RUN unzip data.zip
RUN rm data.zip
