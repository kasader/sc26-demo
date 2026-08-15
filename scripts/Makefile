# Convenience wrappers for driving attacker modes from inside the demo
# container (e.g. the attacker shell pane, which starts in this directory).
# See ../README.en.md for the full story. For the host-side build/run/stop
# targets, use the Makefile at the repo root instead -- this one has no
# access to the Docker daemon.

VIC_ADDR := 10.10.0.2:9999
ARGS     ?=

MODES := legit garbage flood evasive

.DEFAULT_GOAL := help
.PHONY: help $(MODES)

help:
	@echo "make legit|garbage|flood|evasive"
	@echo "                     drive that attacker mode against the victim (extra flags via ARGS=...)"

$(MODES):
	/src/sec-camp/scripts/atk.sh /usr/local/bin/attacker -target $(VIC_ADDR) -mode $@ $(ARGS)
