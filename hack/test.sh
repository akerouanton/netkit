#!/bin/sh

ip netns exec test-nk curl -v http://192.168.65.254:8000/
ip netns exec test-veth curl -v http://192.168.65.254:8000/
