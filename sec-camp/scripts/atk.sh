#!/usr/bin/env bash
# Convenience wrapper: run a command inside the attacker namespace, e.g.
#   ./atk.sh /usr/local/bin/attacker -target 10.10.0.2:9999 -mode flood
exec ip netns exec atk "$@"
