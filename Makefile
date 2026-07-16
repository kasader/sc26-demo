# Convenience wrappers around the sec-camp eBPF DDoS-guard demo. See
# sec-camp/README.en.md (or README.md) for the full story and manual
# controls -- this just shortcuts the commands documented there.

IMAGE      := sec-camp-demo
CONTAINER  := sec-camp
DOCKERFILE := sec-camp/Dockerfile
VIC_ADDR   := 10.10.0.2:9999

RATE_THRESHOLD ?=
BLOCK_TTL      ?=
ARGS           ?=

RUN_ENV :=
ifneq ($(RATE_THRESHOLD),)
RUN_ENV += -e RATE_THRESHOLD=$(RATE_THRESHOLD)
endif
ifneq ($(BLOCK_TTL),)
RUN_ENV += -e BLOCK_TTL=$(BLOCK_TTL)
endif

MODES := legit garbage flood evasive

.DEFAULT_GOAL := help
.PHONY: help build run stop $(MODES)

help:
	@echo "make build                     build the $(IMAGE) image"
	@echo "make run                       run the demo container (override with RATE_THRESHOLD=n, BLOCK_TTL=Ns)"
	@echo "make stop                      remove the running demo container"
	@echo "make legit|garbage|flood|evasive"
	@echo "                               drive that attacker mode against the victim (extra flags via ARGS=...)"

build:
	docker build -f $(DOCKERFILE) -t $(IMAGE) .

run:
	@docker rm -f $(CONTAINER) >/dev/null 2>&1 || true
	docker run --rm -it --privileged --name $(CONTAINER) $(RUN_ENV) $(IMAGE)

stop:
	docker rm -f $(CONTAINER)

$(MODES):
	docker exec -it $(CONTAINER) /src/sec-camp/scripts/atk.sh /usr/local/bin/attacker -target $(VIC_ADDR) -mode $@ $(ARGS)
