#!/bin/bash

ip netns exec host2 ./target/debug/examples/echo_client 10.0.0.1 40000
