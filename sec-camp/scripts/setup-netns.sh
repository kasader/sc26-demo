#!/usr/bin/env bash
# Creates two network namespaces ("atk" and "vic") joined by a veth pair, so
# the whole attacker/victim/guard demo is self-contained inside one
# container -- no dependency on the host's real NICs.
set -euo pipefail

ATK_NS=atk
VIC_NS=vic
ATK_IP=10.10.0.1/24
VIC_IP=10.10.0.2/24

ip netns del "$ATK_NS" 2>/dev/null || true
ip netns del "$VIC_NS" 2>/dev/null || true

ip netns add "$ATK_NS"
ip netns add "$VIC_NS"

ip link add veth-atk type veth peer name veth-vic
ip link set veth-atk netns "$ATK_NS"
ip link set veth-vic netns "$VIC_NS"

ip netns exec "$ATK_NS" ip addr add "$ATK_IP" dev veth-atk
ip netns exec "$VIC_NS" ip addr add "$VIC_IP" dev veth-vic

ip netns exec "$ATK_NS" ip link set veth-atk up
ip netns exec "$VIC_NS" ip link set veth-vic up
ip netns exec "$ATK_NS" ip link set lo up
ip netns exec "$VIC_NS" ip link set lo up

echo "netns ready: $ATK_NS (${ATK_IP%/*}) <-veth-> $VIC_NS (${VIC_IP%/*})"
