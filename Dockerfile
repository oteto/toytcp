FROM rust:latest

RUN apt update -y && apt install -y \
	sudo \
	iproute2 \
	iputils-ping \
	iptables \
	netcat \
	tcpdump \
	ethtool

RUN DEBIAN_FRONTEND=noninteractive apt install -y tshark
RUN rustup component add rustfmt

WORKDIR /opt

COPY ./ ./
RUN chmod +x ./setup.sh
