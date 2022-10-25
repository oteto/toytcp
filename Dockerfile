FROM rust:latest

RUN apt update -y && apt install -y \
	sudo \
	iproute2 \
	iputils-ping \
	iptables \
	netcat \
	tcpdump \
	ethtool

WORKDIR /opt

COPY ./ ./
RUN chmod +x ./setup.sh
