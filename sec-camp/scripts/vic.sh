#!/usr/bin/env bash
# Convenience wrapper: run a command inside the victim namespace, e.g.
#   ./vic.sh curl -s -X POST http://10.10.0.2:5555/unblock-all
exec ip netns exec vic "$@"
