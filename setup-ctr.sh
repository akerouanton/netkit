#!/bin/bash

set -o xtrace

ip link add name nk0 type netkit mode l3 forward peer forward nk1
ip addr add 172.30.0.1/24 dev nk0
ip addr add 172.30.0.2/24 dev nk1

# ./loader -iface nk0 -attach-type netkit_primary -bpf bpf.o -prog ingress_filter
./loader -iface nk0 -attach-type netkit_peer -bpf bpf.o -prog egress_redirect
./loader -iface wlan0 -attach-type tcx_ingress -bpf bpf.o -prog host_ingress

ip link set nk0 up

# Create netns and move nk1 into it
ip netns add test
ip link set nk1 netns test
ip netns exec test ip link set lo up
ip netns exec test ip link set nk1 up
ip netns exec test ip addr add 172.30.0.2 dev nk1
ip netns exec test ip route add 172.30.0.1/32 src 172.30.0.2 dev nk1
ip netns exec test ip route add default via 172.30.0.1
