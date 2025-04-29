#!/bin/sh

set -o xtrace

ip link add name veth0 mtu 65535 type netkit mode l3 forward peer forward veth1 mtu 65535
ip addr add 172.31.0.1/24 dev veth0
ip addr add 172.31.0.2/24 dev veth1

ip link set veth0 up

ip netns add test-veth
ip link set veth1 netns test-veth
ip netns exec test-veth ip link set lo up
ip netns exec test-veth ip link set veth1 up
ip netns exec test-veth ip addr add 172.31.0.2 dev veth1
ip netns exec test-veth ip route add 172.31.0.1/32 src 172.31.0.2 dev veth1
ip netns exec test-veth ip route add default via 172.31.0.1

iptables -t nat -A POSTROUTING -s 172.31.0.0/24 -j MASQUERADE
