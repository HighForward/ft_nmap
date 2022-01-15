FROM debian:latest

RUN mkdir nmap
COPY . nmap/.

RUN chmod +x /nmap/srcs/setup_ssh.sh

RUN apt-get update
RUN apt-get -y install openssh-server
RUN apt-get -y install traceroute
RUN apt-get -y install iputils-ping
RUN apt-get -y install nmap
RUN apt-get -y install gcc make
RUN apt-get -y install libpcap-dev

EXPOSE 22

# CMD sleep 100000000
ENTRYPOINT ["/nmap/srcs/setup_ssh.sh"]