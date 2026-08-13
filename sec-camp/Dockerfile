# Build and run the DDoS-guard demo (attacker + victim + eBPF defender) in a
# single Linux container. Must run with enough privilege to load eBPF
# programs and create network namespaces -- see README.md for the run
# command (--privileged is the simplest option for a booth demo).
FROM golang:1.26-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libbpf-dev linux-libc-dev \
      iproute2 iptables tmux curl jq iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# linux/*.h headers (bpf.h, ip.h, udp.h, ...) expect <asm/...> at
# /usr/include/asm. gcc's builtin search path finds Debian's multiarch
# per-triple asm dir (e.g. /usr/include/aarch64-linux-gnu/asm) automatically;
# clang (used by bpf2go) does not, so point /usr/include/asm at it directly.
# asm-generic is NOT a substitute here: some headers (byteorder.h) only
# exist in the real per-arch dir. dpkg-architecture isn't installed in this
# image, so use gcc -dumpmachine (gcc ships by default for cgo) instead.
RUN ln -sf "/usr/include/$(gcc -dumpmachine)/asm" /usr/include/asm

# The demo's tmux panes run login shells, which re-read /etc/profile and reset
# PATH, losing the go toolchain this image puts on it. Put it back for any shell
# the presenter ends up typing into.
RUN printf 'export PATH="$PATH:/usr/local/go/bin"\n' > /etc/profile.d/go.sh

WORKDIR /src
COPY go.mod go.sum ./
COPY sec-camp ./sec-camp

RUN cd sec-camp/guard && go generate ./... && go build -o /usr/local/bin/guard .
RUN cd sec-camp/attacker && go build -o /usr/local/bin/attacker .
RUN cd sec-camp/victim && go build -o /usr/local/bin/victim .

RUN chmod +x /src/sec-camp/scripts/*.sh
WORKDIR /src/sec-camp/scripts

ENTRYPOINT ["/src/sec-camp/scripts/run-demo.sh"]
