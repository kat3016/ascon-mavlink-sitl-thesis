#!/bin/sh
# usage: sudo sh netbench.sh up | down | N0 | N1 | N2 | N3
set -e
case "$1" in
up)
  ip netns add uav
  ip link add veth-gcs type veth peer name veth-uav
  ip link set veth-uav netns uav
  ip addr add 10.10.0.1/24 dev veth-gcs && ip link set veth-gcs up
  ip netns exec uav ip addr add 10.10.0.2/24 dev veth-uav
  ip netns exec uav ip link set veth-uav up
  ip netns exec uav ip link set lo up ;;
down)
  ip netns del uav ;;
N0) P="" ;;
N1) P="delay 1ms 0.5ms distribution normal loss 0.1%" ;;
N2) P="delay 5ms 2.5ms distribution normal loss 1%" ;;
N3) P="delay 15ms 5ms distribution normal loss 5%" ;;
esac
case "$1" in N0|N1|N2|N3)
  tc qdisc del dev veth-gcs root 2>/dev/null || true
  ip netns exec uav tc qdisc del dev veth-uav root 2>/dev/null || true
  if [ -n "$P" ]; then
    tc qdisc add dev veth-gcs root netem $P
    ip netns exec uav tc qdisc add dev veth-uav root netem $P
  fi ;;
esac
