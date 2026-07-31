# sec-camp: eBPF DDoS Guard Demo

*[日本語版はこちら / Japanese version here](README.md)*

A live demo built for a Security Camp 2026 (セキュリティ・キャンプ2026) booth
session. It shows, in real time, how Linux kernel eBPF (XDP) can detect,
defend against, and adapt to a DoS/DDoS-style flood at the lowest possible
layer — before the traffic ever reaches userspace.

This directory is independent of `sample01`-`sample04` (new programs:
`guard`/`attacker`/`victim`), but lives as a subpackage of the same Go module
(`go-ebpf-sample`). `guard` combines sample02's per-source blocklist approach
with sample04's protocol-flag payload validation into one new XDP program
built specifically for this demo.

## The story

Inside a single container, two network namespaces (`atk` = attacker, `vic` =
victim) are connected by a veth pair. The XDP program `guard` is attached to
the victim side of that veth.

| Stage | Attacker (`attacker -mode ...`) | eBPF guard's reaction |
| --- | --- | --- |
| Detect 1: baseline | `legit` — a handful of sources sending correctly-flagged packets | almost everything is `passed` |
| Defend 1: naive flood | `flood` — 1-2 sources sending malformed packets as fast as possible | per-source packet rate is detected and auto-blocked in-kernel (`dropped-rate`) |
| Defend 2: slow-and-bad | `garbage` — malformed packets sent below the rate limit | caught by payload flag validation (`dropped-protocol`) |
| Countering evasion | `evasive` — traffic spread across 50 sources (ports), each individually under the rate limit | per-source rate limiting is evaded, but the protocol-validation layer still catches everything (`dropped-protocol`) |

The core point of the demo is the last row: rate limiting alone can be evaded
by a distributed attacker, but combining it with payload validation keeps the
defense effective while staying entirely at the low layer (XDP).

## Architecture

```text
                 container (--privileged)
  ┌─────────────────────────────────────────────────────────┐
  │  netns: atk (10.10.0.1/24)      netns: vic (10.10.0.2/24) │
  │  ┌───────────────────┐ veth  ┌───────────────────────┐  │
  │  │ attacker           │◄────►│ veth-vic               │  │
  │  │ (Go, UDP flood)     │      │  ▲ XDP: guard.c        │  │
  │  └───────────────────┘      │  │ (rate limit + proto)  │  │
  │                              │  ▼                       │  │
  │                              │ victim (Go, UDP server)  │  │
  │                              │ guard (Go, XDP loader +  │  │
  │                              │        live dashboard)   │  │
  │                              └───────────────────────┘  │
  └─────────────────────────────────────────────────────────┘
```

`guard` reports every in-kernel "detected and dropped" decision to userspace
over a ring buffer, and userspace adds that source to a blocklist map with a
TTL (auto-lifted once it expires). The packet drop itself always happens
inside the kernel (XDP), without waiting on userspace.

## Prerequisites

* eBPF/XDP only runs on a **Linux kernel**. On macOS/Windows, run it through
  Docker Desktop's Linux VM.
* The container runs `--privileged` (loading eBPF and creating network
  namespaces needs `CAP_SYS_ADMIN`/`CAP_BPF`/`CAP_NET_ADMIN` and similar —
  for a one-off demo this is the most reliable option).
* The host kernel needs to support XDP generic mode (true for essentially
  any 5.x+ kernel).

## Build

From the repository root (where `go-ebpf-sample`'s `go.mod` lives):

```bash
docker build -f sec-camp/Dockerfile -t sec-camp-demo .
```

## Run

```bash
docker run --rm -it --privileged --name sec-camp sec-camp-demo
```

On startup it automatically:

1. Creates the `atk`/`vic` network namespaces and the veth pair.
2. Starts `victim` (the UDP server) inside `vic`.
3. Starts `guard` (the XDP program) inside `vic`; on startup it attaches itself
   to `veth-vic` and configures `10.10.0.2:9999` as the protected target.
4. Opens (and attaches to) a tmux session `sec-camp` split into three panes:
   left = guard's live dashboard, top-right = victim's log, bottom-right = a shell in the attacker namespace.

From the bottom-right pane, run the attack commands and watch the left-hand
dashboard update live with `total` / `passed` / `dropped-rate` /
`dropped-protocol` pps and the current blocklist.

```bash
# baseline: almost everything gets passed
/usr/local/bin/attacker -target 10.10.0.2:9999 -mode legit

# fast flood: dropped-rate spikes, the source gets auto-blocked
/usr/local/bin/attacker -target 10.10.0.2:9999 -mode flood

# slow malformed traffic: stays under the rate limit but is still caught by dropped-protocol
/usr/local/bin/attacker -target 10.10.0.2:9999 -mode garbage

# an attacker trying to evade rate limiting by spreading across 50 sources --
# still fully caught by the protocol-validation layer
/usr/local/bin/attacker -target 10.10.0.2:9999 -mode evasive
```

Running a `legit` traffic generator in one pane alongside an attack in
another is a good way to show that real users survive the attack unaffected.

## Cleanup

```bash
docker rm -f sec-camp
```

Removing the container removes the namespaces/veth with it — they were
created inside the container's own namespace, so nothing is left behind on
the host.

## Parameters

`guard`'s startup flags (overridable via environment variables in
`scripts/run-demo.sh`):

| Flag / env var | Default | Meaning |
| --- | --- | --- |
| `-rate` / `RATE_THRESHOLD` | 30 | Per-source pps (packets/sec) above which a source is auto-blocked |
| `-block-ttl` / `BLOCK_TTL` | 15s | How long an auto-blocked source stays blocked |

Example: `docker run --rm -it --privileged -e RATE_THRESHOLD=10 sec-camp-demo`

## Troubleshooting

* **`AttachXDP` fails**: veth interfaces can't take an XDP native-mode
  attachment. `guard/main.go` always requests `link.XDPGenericMode` (SKB
  mode), so this normally isn't an issue — but on a very old kernel even
  generic XDP may be unavailable.
* **Avoiding `--privileged`**: at minimum you need
  `--cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON`.
  The exact missing capability varies by environment, so `--privileged` is
  recommended for booth day.
* **Checking the eBPF trace with `-debug`**:
  `docker exec -it sec-camp cat /sys/kernel/debug/tracing/trace_pipe`
  (requires `/sys/kernel/debug` to be mounted from the host. If that's not
  easy to arrange, the dashboard's numbers alone tell the story just fine.)

## File layout

```text
sec-camp/
├── Dockerfile           # build recipe (clang/libbpf-dev/go)
├── guard/                # the XDP program + Go loader + dashboard
│   ├── guard.c
│   ├── gen.go
│   ├── main.go
│   └── dashboard.go
├── attacker/main.go      # UDP flood tool (legit/garbage/flood/evasive)
├── victim/main.go        # the protected UDP server
└── scripts/
    ├── setup-netns.sh    # creates the atk/vic netns + veth pair
    ├── teardown-netns.sh
    ├── run-demo.sh        # the container ENTRYPOINT; orchestrates everything
    ├── atk.sh / vic.sh    # helpers to run a command inside each namespace
```
