#!/bin/sh

set -o xtrace

ip link del nk0
ip netns del test
rm /sys/fs/bpf/egress_redirect
rm /sys/fs/bpf/host_ingress
