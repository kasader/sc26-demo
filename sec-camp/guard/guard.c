//go:build ignore

// bpf_helper_defs.h (pulled in by bpf_helpers.h) uses __u32/__u64 and expects
// linux/types.h (or vmlinux.h) to already be included -- must come first.
#include <linux/types.h>
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

#define Flag_FIN 0x01 // graceful close, like TCP FIN
#define Flag_SYN 0x02 // open connection, like TCP SYN
#define Flag_RST 0x04 // abort connection, like TCP RST
#define Flag_DAT 0x08 // payload present, like TCP PSH
#define Flag_ACK 0x10 // acknowledgment, like TCP ACK

#define FLAG_VALID_MASK (Flag_FIN | Flag_SYN | Flag_RST | Flag_DAT | Flag_ACK)

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

// The single address:port this guard protects, written once by userspace at
// startup from -target. A single-entry array is just a mutable global.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct address_key);
  __uint(max_entries, 1);
} target SEC(".maps");

// Sources to drop unconditionally, added by userspace in response to the
// block_events below. Userspace owns eviction (TTL-based), so entries stay
// here until it deletes them.
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

// Kernel-to-userspace notification channel: one block_event per source that
// just tripped the rate limiter, so userspace can add it to `blocklist` with
// a TTL. The drop itself already happened in-kernel by the time this is read.
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
  // xdp_md is the "XDP metadata" context the kernel hands us for each packet at
  // the XDP hook -- the earliest point in the network path, right off the
  // driver, before the kernel allocates an sk_buff. It doesn't contain the
  // packet bytes; instead ctx->data and ctx->data_end are (32-bit) offsets to
  // the start and one-past-the-end of the raw frame in memory. We cast them to
  // real pointers and from here on treat the packet as a byte buffer laid out
  // as [ Ethernet header | IP header | UDP header | payload ].
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Walk that layout one header at a time down to UDP, bailing out to XDP_PASS
  // (hand the packet to the kernel's normal networking stack) for anything that
  // isn't IPv4/UDP or that is too short. Two rules drive every step:
  //   1. The eBPF verifier rejects the program at load time unless it can PROVE
  //      each read stays inside [data, data_end). That is what every
  //      `(void *)(hdr + 1) > data_end` check is: "is there room for a whole
  //      header of this type here?" -- `hdr + 1` is pointer arithmetic that
  //      advances by exactly sizeof(*hdr) bytes, i.e. the byte just past this
  //      header. Without the check the verifier assumes the read could be out
  //      of bounds and refuses to load us.
  //   2. Multi-byte header fields are big-endian ("network byte order"), so we
  //      compare against bpf_htons(...) (host-to-network short) rather than the
  //      raw constant, which keeps this correct on little-endian machines.

  // Ethernet header (struct ethhdr, from <linux/if_ether.h>): dst MAC, src MAC,
  // and h_proto -- the EtherType naming the next protocol. ETH_P_IP means IPv4;
  // anything else (IPv6, ARP, ...) is not ours, so pass it on.
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  // IPv4 header (struct iphdr, from <linux/ip.h>) sits immediately after the
  // Ethernet header. iph->protocol is the L4 protocol number; IPPROTO_UDP (17)
  // means a UDP datagram follows. TCP/ICMP/etc. are out of scope -> pass.
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return XDP_PASS;
  if (iph->protocol != IPPROTO_UDP)
    return XDP_PASS;

  // The IPv4 header is variable-length: iph->ihl ("Internet Header Length") is
  // measured in 32-bit words, so the real header size in bytes is ihl * 4
  // (20 for a header with no options, more if options are present). We can't
  // assume sizeof(struct iphdr) here -- we have to skip the actual header
  // length to land on the UDP header (struct udphdr, from <linux/udp.h>), then
  // bounds-check that too before touching udph->source / udph->dest below.
  __u32 ip_hlen = iph->ihl * 4;
  struct udphdr *udph = (void *)iph + ip_hlen;
  if ((void *)(udph + 1) > data_end)
    return XDP_PASS;

  // Only packets addressed to the protected target are in scope for this
  // guard; everything else (other services on the same host, etc.) passes
  // through untouched and isn't counted in pkt_stats at all.
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

  // Blocklist: sources that tripped the rate limiter before and haven't had
  // their TTL expire yet are dropped immediately, before doing any further
  // work on them.
  if (bpf_map_lookup_elem(&blocklist, &src)) {
    inc_stat(2);
    return XDP_DROP;
  }

  // Rate limiting: track packets/sec per source over a 1-second sliding
  // window. Exceeding rate_threshold reports a block_event over the ring
  // buffer (so userspace adds this source to `blocklist` with a TTL) and
  // drops the packet that tripped it. This alone stops a naive flood from a
  // small number of sources, but a source spread wide enough (see
  // `rate_track`'s comment above) evades it -- that's what the protocol
  // validation layer below is for.
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
