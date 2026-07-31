#!/usr/bin/env bash
# Booth entrypoint: sets up the attacker/victim network namespaces, attaches
# the eBPF guard to the victim's veth, and opens a tmux session with the
# guard dashboard, victim log, and an attacker shell as three panes.
set -euo pipefail
cd "$(dirname "$0")"

RATE_THRESHOLD="${RATE_THRESHOLD:-30}"
BLOCK_TTL="${BLOCK_TTL:-15s}"
VIC_IP=10.10.0.2
VIC_PORT=9999

./setup-netns.sh
sleep 1

tmux kill-session -t sec-camp 2>/dev/null || true
tmux new-session -d -s sec-camp -n demo -x 220 -y 50

tmux send-keys -t sec-camp:demo.0 \
  "ip netns exec vic /usr/local/bin/guard -rate ${RATE_THRESHOLD} -block-ttl ${BLOCK_TTL} -nic veth-vic -target ${VIC_IP}:${VIC_PORT}" Enter
tmux split-window -t sec-camp:demo -h -p 45
tmux send-keys -t sec-camp:demo.1 \
  "ip netns exec vic /usr/local/bin/victim -listen ${VIC_IP}:${VIC_PORT}" Enter
tmux split-window -t sec-camp:demo.1 -v -p 60
tmux send-keys -t sec-camp:demo.2 "ip netns exec atk bash" Enter

cat <<EOF

============================================================
 ready. attach to the demo with:

     tmux attach -t sec-camp

 the bottom-right pane is a shell inside the attacker
 namespace. Run the flood tool from there, e.g.:

     /usr/local/bin/attacker -target ${VIC_IP}:${VIC_PORT} -mode legit
     /usr/local/bin/attacker -target ${VIC_IP}:${VIC_PORT} -mode flood
     /usr/local/bin/attacker -target ${VIC_IP}:${VIC_PORT} -mode garbage
     /usr/local/bin/attacker -target ${VIC_IP}:${VIC_PORT} -mode evasive
============================================================
EOF

exec tmux attach -t sec-camp
