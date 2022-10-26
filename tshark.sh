#!/bin/bash

ip netns exec host1 tshark -i host1-veth1 -f "port 40000"