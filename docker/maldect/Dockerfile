FROM weibeld/ubuntu-networking:latest

RUN apt update
RUN apt install -y telnet nano python3 inotify-tools unzip
ADD maldect.zip /maldect.zip
RUN unzip maldect.zip
WORKDIR /maldect
RUN ./install.sh
WORKDIR /
RUN mv /conf.maldet /usr/local/maldetect/conf.maldet
RUN rm -drf maldect.zip maldect