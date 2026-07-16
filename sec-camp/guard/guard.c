// go:build ignore

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

char __license[] SEC("license") = "Dual MIT/GPL";

volatile const __u32 is_debug;
volatile const __u32 rate_threshold =
    30; // packets/sec from one source before auto-block kicks in

#define RATE_WINDOW_NS 1000000000ULL

#define Flag_FIN 0x01  // graceful close, like TCP FIN
#define Flag_SYN 0x02  // open connection, like TCP SYN
#define Flag_RST 0x04  // abort connection, like TCP RST
#define Flag_DAT 0x08  // payload present, like TCP PSH
#define Flag_ACK 0x10  // acknowledgment, like TCP ACK
#define Flag_EACK 0x20 // extended/selective ack (RUDP-style, no TCP analog)

#define FLAG_VALID_MASK                                                        \
  (Flag_FIN | Flag_SYN | Flag_RST | Flag_DAT | Flag_ACK | Flag_EACK)

struct address_key {
  __u32 address; // host order
  __u16 port;    // host order
};

struct rate_state {
  __u64 window_start_ns;
  __u32 count;
};

struct block_event {
  __u32 address; // host order
  __u16 port;    // host order
  __u32 count;   // packets/sec observed when the block triggered
};

// index 0: total packets matching the protected target
// index 1: passed
// index 2: dropped by the rate limiter or an active blocklist entry
// index 3: dropped for an invalid protocol flag byte
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 4);
} pkt_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct address_key);
  __uint(max_entries, 1);
} target SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct address_key);
  __type(value, __u8);
  __uint(max_entries, 1024);
} blocklist SEC(".maps");

// Per-source sliding rate window. An attacker spread across enough distinct
// source ports can exhaust this table (max_entries); when bpf_map_update_elem
// below fails we simply skip the rate check for that packet instead of
// rejecting it outright, and fall through to the protocol check. That's
// deliberate: it is the reason this demo needs the protocol-flag layer too,
// not just per-source rate limiting.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct address_key);
  __type(value, struct rate_state);
  __uint(max_entries, 4096);
} rate_track SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 16);
} block_events SEC(".maps");

static __always_inline void inc_stat(__u32 idx) {
  __u64 *count = bpf_map_lookup_elem(&pkt_stats, &idx);
  if (count)
    __sync_fetch_and_add(count, 1);
}

SEC("xdp")
int guard(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return XDP_PASS;
  if (iph->protocol != IPPROTO_UDP)
    return XDP_PASS;

  __u32 ip_hlen = iph->ihl * 4;
  struct udphdr *udph = (void *)iph + ip_hlen;
  if ((void *)(udph + 1) > data_end)
    return XDP_PASS;

  __u32 tkey = 0;
  struct address_key *dst = bpf_map_lookup_elem(&target, &tkey);
  if (!dst || dst->address == 0)
    return XDP_PASS;

  if (udph->dest != bpf_htons(dst->port) ||
      iph->daddr != bpf_htonl(dst->address))
    return XDP_PASS;

  inc_stat(0);

  struct address_key src = {
      .address = bpf_ntohl(iph->saddr),
      .port = bpf_ntohs(udph->source),
  };

  if (bpf_map_lookup_elem(&blocklist, &src)) {
    inc_stat(2);
    return XDP_DROP;
  }

  __u64 now = bpf_ktime_get_ns();
  struct rate_state *rs = bpf_map_lookup_elem(&rate_track, &src);
  if (!rs) {
    struct rate_state init = {.window_start_ns = now, .count = 1};
    bpf_map_update_elem(&rate_track, &src, &init, BPF_ANY);
  } else if (now - rs->window_start_ns > RATE_WINDOW_NS) {
    rs->window_start_ns = now;
    rs->count = 1;
  } else {
    rs->count++;
    if (rs->count > rate_threshold) {
      struct block_event evt = {
          .address = src.address,
          .port = src.port,
          .count = rs->count,
      };
      bpf_ringbuf_output(&block_events, &evt, sizeof(evt), 0);
      if (is_debug)
        bpf_printk("guard: rate-block %x:%d (%d pps)", src.address, src.port,
                   rs->count);
      inc_stat(2);
      return XDP_DROP;
    }
  }

  // Protocol validation: only packets that survive the rate check reach here.
  __u8 *payload = (void *)(udph + 1);
  if ((void *)(payload + 4) > data_end) {
    inc_stat(3);
    return XDP_DROP;
  }

  // Valid iff at least one recognized bit is set and no unrecognized bits are:
  // real flag bytes are combined (e.g. DAT|ACK), not a single fixed enum value.
  __u8 flag = payload[3];
  if (flag != 0 && (flag & ~FLAG_VALID_MASK) == 0) {
    inc_stat(1);
    return XDP_PASS;
  }

  if (is_debug)
    bpf_printk("guard: protocol-drop %x:%d flag=0x%02x", src.address, src.port,
               flag);
  inc_stat(3);
  return XDP_DROP;
}
