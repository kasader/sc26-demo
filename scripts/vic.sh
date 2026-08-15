#!/usr/bin/env bash
# Convenience wrapper: run a command inside the victim namespace, e.g.
#   ./vic.sh ip -br addr
exec ip netns exec vic "$@"
