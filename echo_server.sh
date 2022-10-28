#!/bin/bash

ip netns exec host1 ./target/debug/examples/echo_server 10.0.0.1 40000