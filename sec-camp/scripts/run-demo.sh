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
CTRL_PORT=5555

./setup-netns.sh
sleep 1

tmux kill-session -t sec-camp 2>/dev/null || true
tmux new-session -d -s sec-camp -n demo -x 220 -y 50

tmux send-keys -t sec-camp:demo.0 \
  "ip netns exec vic /usr/local/bin/guard -rate ${RATE_THRESHOLD} -block-ttl ${BLOCK_TTL} -listen 0.0.0.0:${CTRL_PORT}" Enter
tmux split-window -t sec-camp:demo -h -p 35
tmux send-keys -t sec-camp:demo.1 \
  "ip netns exec vic /usr/local/bin/victim -listen ${VIC_IP}:${VIC_PORT}" Enter
tmux split-window -t sec-camp:demo.1 -v -p 60
tmux send-keys -t sec-camp:demo.2 "ip netns exec atk bash" Enter

echo "waiting for the guard's HTTP API to come up..."
for _ in $(seq 1 20); do
  if ip netns exec atk bash -c "exec 3<>/dev/tcp/${VIC_IP}/${CTRL_PORT}" 2>/dev/null; then
    break
  fi
  sleep 0.5
done

echo "attaching guard to veth-vic, protecting ${VIC_IP}:${VIC_PORT}..."
ip netns exec atk curl -sf -X POST "http://${VIC_IP}:${CTRL_PORT}/setup" \
  -d "{\"address\":\"${VIC_IP}:${VIC_PORT}\",\"nic_name\":\"veth-vic\"}"
echo

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

 manual controls from any shell in this container:
     ./vic.sh curl -s -X POST http://${VIC_IP}:${CTRL_PORT}/block \\
         -d '[{"address":"1.2.3.4:5555","duration":"1m"}]'
     ./vic.sh curl -s -X POST http://${VIC_IP}:${CTRL_PORT}/unblock-all
============================================================
EOF

exec tmux attach -t sec-camp
