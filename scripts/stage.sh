#!/usr/bin/env bash
# Drive the demo's stage branches from inside the container.
#
#   ./stage.sh show 2    show what stage 2 adds to guard.c (a diff, no checkout)
#   ./stage.sh show 1-2  same, but everything stages 1 through 2 add, as one diff
#   ./stage.sh run 2     check out stage 2, rebuild, restart the guard
#
# `show` never touches the working tree, so it can't fail mid-talk; only `run`
# checks out. The repo is bind-mounted at /src by the root Makefile, so both
# see the same working tree your editor does on the host.
#
# Before the talk, start from stage 0 (`git checkout demo/step-0-parse`, then
# `make run` from the repo root): parsing and the target filter are written, the
# three defense layers are not. `./stage.sh run 0` returns there at any point.
set -euo pipefail

# tmux starts each pane as a login shell, which re-reads /etc/profile and resets
# PATH -- dropping the golang image's /usr/local/go/bin. Don't depend on it.
export PATH="$PATH:/usr/local/go/bin"

REPO=/src
RATE_THRESHOLD="${RATE_THRESHOLD:-30}"
BLOCK_TTL="${BLOCK_TTL:-15s}"
VIC_ADDR=10.10.0.2:9999
NIC=veth-vic

usage() { sed -n '3,7p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

# Bind mounts often present the repo as owned by another uid, which git refuses
# to operate on until the path is marked safe.
git config --global --add safe.directory "$REPO" 2>/dev/null || true

branch_for() {
  case "$1" in
    0) echo demo/step-0-parse ;;
    1) echo demo/step-1-blocklist ;;
    2) echo demo/step-2-ratelimit ;;
    3) echo demo/step-3-protocol ;;
    *) echo "stage must be 0, 1, 2 or 3 (got '$1')" >&2; exit 1 ;;
  esac
}

cmd="${1:-}"
stage="${2:-}"
[ -n "$cmd" ] && [ -n "$stage" ] || usage

case "$cmd" in
show)
  # A range (1-2) collapses several stages into one diff, for sections of the
  # talk that introduce more than one stage at a time.
  case "$stage" in
    [0-9]-[0-9])
      first="${stage%-*}"; last="${stage#*-}"
      [ "$first" -le "$last" ] || { echo "range must run low to high (got '$stage')" >&2; exit 1; }
      [ "$first" != 0 ] || { echo "stage 0 is the starting point -- nothing added yet" >&2; exit 1; }
      from=$(branch_for $((first - 1)))
      to=$(branch_for "$last")
      label="stages $first through $last add"
      ;;
    *)
      [ "$stage" != 0 ] || { echo "stage 0 is the starting point -- nothing added yet" >&2; exit 1; }
      from=$(branch_for $((stage - 1)))
      to=$(branch_for "$stage")
      label="stage $stage adds"
      ;;
  esac
  echo "==> what $label to guard.c ($from -> $to)"
  git -C "$REPO" --no-pager diff --stat "$from..$to" -- sec-camp/guard/guard.c
  echo
  git -C "$REPO" --no-pager diff "$from..$to" -- sec-camp/guard/guard.c
  ;;
run)
  to=$(branch_for "$stage")
  echo "==> checking out $to"
  git -C "$REPO" checkout "$to"
  echo "==> compiling C to BPF bytecode"
  cd "$REPO/sec-camp/guard"
  go generate ./...
  go build -o /usr/local/bin/guard .
  echo "==> loading into the kernel -- the verifier runs here"
  exec ip netns exec vic /usr/local/bin/guard \
    -rate "$RATE_THRESHOLD" -block-ttl "$BLOCK_TTL" -nic "$NIC" -target "$VIC_ADDR"
  ;;
*)
  usage
  ;;
esac
