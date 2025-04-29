#!/bin/sh

set -o xtrace

ip link add name nk0 mtu 65535 type netkit mode l3 forward peer forward nk1 mtu 65535
ip addr add 172.30.0.1/24 dev nk0
ip addr add 172.30.0.2/24 dev nk1

nk1_ifi=$(ip link show nk0 | head -n1 | awk '{print $1}' | sed 's/://')

# ./loader -iface nk0 -attach-type netkit_primary -bpf netkit.bpf.o -prog ingress_filter
./loader -iface nk0 -attach-type netkit_peer -bpf netkit.bpf.o -prog egress_redirect
./loader -iface eth0 -ctr-nk-ifi $nk1_ifi -attach-type tcx_ingress -bpf netkit.bpf.o -prog host_ingress

ip link set nk0 up

# Create netns and move nk1 into it
ip netns add test-nk
ip link set nk1 netns test-nk
ip netns exec test-nk ip link set lo up
ip netns exec test-nk ip link set nk1 up
ip netns exec test-nk ip addr add 172.30.0.2 dev nk1
ip netns exec test-nk ip route add 172.30.0.1/32 src 172.30.0.2 dev nk1
ip netns exec test-nk ip route add default via 172.30.0.1

iptables -t filter -I FORWARD -s 172.30.0.0/24 -j ACCEPT
