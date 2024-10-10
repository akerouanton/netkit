#!/bin/bash

set -o xtrace

ip netns del test
# rm /sys/fs/bpf/ingress_filter
rm /sys/fs/bpf/egress_redirect
rm /sys/fs/bpf/host_ingress
