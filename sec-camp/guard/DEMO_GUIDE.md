# guard demo — spoken script

*[日本語版はこちら / Japanese version here](DEMO_GUIDE.jp.md)*

Use: https://excalidraw.com/

Read top to bottom. `>` lines are what you say. `[...]` lines are what you do.
Target runtime ~18 min. Guard is already running with `-rate 30`, target
`10.10.0.2:9999`. Attacker commands go in the bottom-right tmux pane.

**You only type three things live:** the blocklist lookup (§6), the rate
limiter (§7), and the protocol check (§9). Everything else is already on
screen and you explain it by pointing at it. Each of those sections gives you
the exact code and says where it goes.

The code blocks below omit the comments and the two `if (is_debug)
bpf_printk(...)` calls that are in the committed `guard.c` — don't type those
on stage. What you type still compiles and behaves identically; it's just the
committed file minus the narration.

**Before anyone arrives:** check out `demo/step-0-parse`, container up, tmux
attached, all three panes visible, dashboard idle at zeros. Editor open on
`guard.c` with everything down to `inc_stat(0);` already written — includes,
maps, structs, the whole header parse, the target filter. The three defense
layers are **not** there; the function ends in a placeholder — a `// DEMO STEP`
comment and `inc_stat(1); return XDP_PASS;` — which is what makes §3's baseline
pass everything. Screen should look calm and mean nothing yet — you explain it
in §0.

**One rule for all the typing:** §6 and §7 go *above* those two placeholder
lines. §9 *replaces* them. That way the file compiles and the counters stay
honest at every point in the talk.

**If the live typing goes wrong:** every stage has a branch holding that stage
finished, compiled and load-tested — `demo/step-1-blocklist` (§6),
`demo/step-2-ratelimit` (§7), `demo/step-3-protocol` (§9, same `guard.c` as
`main`). Check one out, rebuild with the §7 command, carry on talking.

**Running long?** The two asides you can drop without breaking anything later
are the `ihl` bug (§4) and the endianness bug (§5) — about a minute together.
Never cut §8 or §9; those two are the talk.

---

## 0. Opening (2 min)

[Stand in front of the screen. Don't point at anything yet.]

> Hi. I'm [name], I work on [one line — keep it to one].
>
> Quick question so I know who I'm talking to: hands up if you've heard of eBPF.

[However many hands: keep going. Don't adjust the talk, just know the room.]

> Either way you're fine — if you know what a network packet is, you can follow
> this.
>
> Here's what we're going to do in the next twenty minutes.
>
> I'm going to attack a server. Then I'm going to defend it — by writing code,
> live, that runs *inside the Linux kernel*. Then the attacker is going to
> adapt, and beat my defense. And then we fix it.
>
> That middle part is the bit I want you to take away. Not "here's a firewall
> that works" — a firewall that works is boring. What's interesting is watching
> a reasonable defense, the one basically everybody builds first, get walked
> straight through by an attacker who changed *how* they attack rather than how
> hard.

[Now turn to the screen.]

> So, what you're looking at. All of this is one container on this laptop.
> Nothing here touches the real network, which is also why it's fine for me to
> run an attack in a room full of people.

[Point at the left pane.]

> Left: my defense. Not doing anything yet, all zeros.

[Top-right.]

> Top right: the victim. A UDP server that logs whatever arrives, and nothing
> else. That's the thing I'm protecting.

[Bottom-right.]

> Bottom right: a shell on the attacker — as far as the network cares, a
> different computer.
>
> Two computers and a cable between them — except all three of those are
> software.

[Point at the editor.]

> And this is the code. The boring half is already written — I'll point at that
> rather than make you watch me type it. What's missing is the actual defense:
> about twenty lines, which I'll write in front of you, and which will then be
> running in the kernel of this machine.
>
> Stop me and ask things as I go — it's a booth, not a lecture. Let's start
> with why any of this is hard.

---

## 1. The problem (1.5 min)

[Point at the victim pane.]

> First question: when I flood that server with garbage, what actually breaks?
> Most people say bandwidth. It's usually not. It's this:

[Draw or point at the packet path.]

```
NIC → driver → [allocate sk_buff] → iptables → IP → UDP → socket → your program
```

> For every packet that arrives, the kernel allocates a little struct to track
> it — an sk_buff — then walks it up through the firewall, IP, UDP, and hands it
> to your program, which looks at it and says "this is garbage."
>
> You did all that work — allocate, parse, route, copy, wake up a process — for
> a packet you were always going to discard. A hundred thousand times a second
> and the machine falls over. Not because the pipe is full. Because you spent
> your entire CPU on paperwork for junk mail.
>
> So the fix is obvious: throw it away earlier. The question is how early can
> you get.

---

## 2. XDP and eBPF (2 min)

> The answer is XDP. It's a hook that runs here —

[Point at the very start of the chain, before sk_buff.]

> — before the kernel allocates anything. The packet has just come off the
> wire and it is nothing but raw bytes in memory. My code gets to look at those
> bytes and say one of two words: PASS, meaning carry on into the normal stack,
> or DROP, meaning free it right now.
>
> A DROP here costs essentially nothing — no allocation, no parsing, no wake-up
> — and the sender gets nothing back, not even an error, so they learn nothing
> about what happened.
>
> Now, the obvious problem: that's inside the kernel. Historically you got code
> in there by writing a kernel module, and if you got it wrong the whole machine
> panicked.
>
> Instead we use eBPF. I write C, compile it to a special bytecode — not a
> normal program — and hand that bytecode to the running kernel. No reboot, no
> module, no crash.
>
> And the reason it can't crash is the interesting part. Before the kernel runs
> a single instruction of mine, it runs the verifier. The verifier is a proof
> engine, and it has to prove two things: that my code always finishes — no
> infinite loops — and that it never reads memory outside what it's allowed to
> touch. If it can't prove that, the program doesn't load. Not a crash later; it
> just refuses.
>
> So in a minute, when I show you checks that look unnecessary, understand what
> they are. That's not someone being careful. That's a proof, and the kernel is
> the examiner.

[Point at the two namespaces — my filter sits on the victim's end of the cable.]

---

## 3. Baseline (0.5 min)

```bash
attacker -target 10.10.0.2:9999 -mode legit
```

> Three clients, two packets a second each. Normal traffic — everything passes,
> the victim logs it, nothing gets dropped. Remember what the passed counter
> looks like.

[Ctrl+C.]

---

## 4. Parsing — already written, just read it (1.5 min)

[Scroll to the top of `guard()`. Type nothing in this section.]

> This part I already wrote — mechanical, and near-identical in every XDP
> program on earth. Thirty seconds each.
>
> This function runs on every single packet that arrives on this interface.

[Point at the two casts.]

> The context the kernel hands me doesn't contain the packet — just two numbers:
> where it starts and where it ends. Everything below treats that range as a
> byte buffer: Ethernet header, IP header, UDP header, payload.

[Point at the ethhdr bounds check.]

> And here's the verifier. I want to read the Ethernet header, and I can't just
> read it — I have to prove a whole header is actually there. That's this line:
> `eth + 1` is "the byte just past this header," so it's asking, is there room?
> Delete it and the program will not load. That's not a style rule.
>
> And if it's not IPv4? PASS. Not my problem, let the normal stack handle it.

[Point at the iphdr check, then the ihl line.]

> Same again for IP: prove there's room, then check the protocol. Not UDP? PASS.
>
> One thing here is worth your attention, because it's a real bug people ship.
> The IP header isn't a fixed size — `ihl` holds its length, in units of four
> bytes. Usually twenty. Assume twenty, and the moment someone sends a longer
> header you're parsing completely the wrong bytes — and an attacker can send
> exactly that on purpose. So: multiply by four.

[Point at the udphdr check.]

> Prove there's room for the UDP header, and now I can see the ports.
>
> The thing to notice: everything that isn't ours has already passed straight
> through, untouched. This filter is invisible to the rest of the machine.

---

## 5. Target filter — also already written (0.5 min)

[Point at the target lookup and comparison.]

> Then: I only care about packets aimed at the one address and port I'm
> protecting. Everything else, out.

[Point at the htons/htonl.]

> These conversions matter more than they look. Numbers on the wire are
> big-endian, this machine is little-endian. Forget them and it compiles, loads,
> and silently matches nothing at all — the classic bug in this world.
> Everything looks healthy; your filter does nothing.

[Point at `inc_stat(0)`.]

> And that's the first counter — total, meaning "a packet I'm responsible for."
>
> That's the boring half. From here it's empty, and this is the part I want to
> write in front of you. Three layers, cheapest first.

---

## 6. Layer 1: blocklist (1.5 min) ← start typing here

**Where:** inside `guard()`, directly below `inc_stat(0);` and above the
placeholder that currently ends the function. Everything from here to §9 gets
typed between `inc_stat(0);` and those placeholder lines.

> Okay. Now I write.

**Type — part 1 (the identity):**

```c
  struct address_key src = {
      .address = bpf_ntohl(iph->saddr),
      .port = bpf_ntohs(udph->source),
  };
```

> First I build an identity for the sender: IP address, and port.
>
> IP, and port. Hold that thought.

**Type — part 2 (the lookup), directly below it:**

```c
  if (bpf_map_lookup_elem(&blocklist, &src)) {
    inc_stat(2);
    return XDP_DROP;
  }
```

> One hash lookup. If this sender is already on the blocklist, it's gone
> immediately — before I spend a single further cycle on it.
>
> That's a design principle, not an optimization: known-bad is the cheapest
> check you have, so it goes first.

---

## 7. Layer 2: rate limiter (2 min)

**Where:** directly below the blocklist `if` block you just typed.

**Type — part 1 (the window):**

```c
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
```

*(Leave that last `else` open — part 2 finishes it.)*

> Now: how fast is this sender going? One-second window, per sender. First
> packet starts a window. If a full second has passed, reset. Otherwise,
> count it.

**Type — part 2, continuing straight on:**

```c
    if (rs->count > rate_threshold) {
      struct block_event evt = {
          .address = src.address,
          .port = src.port,
          .count = rs->count,
      };
      bpf_ringbuf_output(&block_events, &evt, sizeof(evt), 0);
      inc_stat(2);
      return XDP_DROP;
    }
  }
```

> And if that count goes over the threshold — thirty packets a second — this
> sender is flooding. Two things happen. I push a message up to my Go program
> so it can put this sender on the blocklist for fifteen seconds. And I drop
> the packet, right now, in the kernel.
>
> I don't wait for the Go program. By the time it reads that message, the drop
> already happened. The kernel enforces; userspace just keeps the notes.

### Reload, then run flood

[In the guard pane: Ctrl+C, then rebuild and restart. Takes a few seconds —
talk over it, don't stand in silence.]

```bash
cd /src/sec-camp/guard && go generate ./... && go build -o /usr/local/bin/guard . \
  && ip netns exec vic /usr/local/bin/guard -rate 30 -block-ttl 15s \
       -nic veth-vic -target 10.10.0.2:9999
```

> While that builds — this is the compile-to-bytecode step, then the kernel
> loads it and the verifier checks it. If I got a bounds check wrong, it fails
> right here and tells me why.

[Then, in the attacker pane:]

```bash
attacker -target 10.10.0.2:9999 -mode flood
```

> Two attackers, a hundred and fifty packets a second each. Five times over the
> limit.

[Point at dropped-rate climbing, then at the blocklist panel.]

> There they are on the blocklist, with a countdown. Fifteen seconds.
>
> And watch what happens when it expires —

[Wait for the sawtooth.]

> — block drops off, attacker resumes, and within a fifth of a second it's over
> the limit again and it's straight back on. That sawtooth is the TTL working.
>
> So. Rate limiting works. Job done, right?

[Ctrl+C.]

---

## 8. The trap (2.5 min) ← this is the talk

[Point back at the `src` struct.]

> Except — look at how I decided who a sender is. IP, and port.
>
> What if the attacker sends from fifty different ports? Five packets a second
> each. My limit is thirty.
>
> Every packet looks like it's from a brand new sender. No window ever fills
> up. Not one of them is doing anything wrong.
>
> But fifty times five is two hundred and fifty packets a second hitting my
> server. That is the same order of traffic as the flood I just blocked — and
> not one single sender is breaking my rule.

```bash
attacker -target 10.10.0.2:9999 -mode evasive
```

[Let it run. Say nothing for a few seconds.]

> Total: two hundred and fifty. Dropped by rate: zero. Passed: two hundred and
> fifty.

[Point at the victim pane eating every packet.]

> My rate limiter has nothing to say about any of this. The attacker didn't
> break it. They just... spread out.
>
> This is why the second D in DDoS matters. Distributed. Rate limiting is the
> first thing everyone reaches for, and a distributed attacker walks straight
> through it.

[Leave it running.]

---

## 9. Layer 3 (3 min)

> So let's stop asking how fast they're sending, and start asking what they're
> sending.
>
> Our protocol has a flag byte in the payload — copied from how TCP works.
> Five bits that mean something: SYN, ACK, FIN, and so on. A real client sets a
> sensible combination. SYN. Or DATA plus ACK.

**Where:** directly below the rate limiter's closing `}` — and this is the one
place you **delete** something first. The placeholder that's been sitting at the
end of the function (the `// DEMO STEP` comment and its `inc_stat(1); return
XDP_PASS;`) goes away, and this block takes its place and ends the function.
Leave it in and every packet passes before it ever reaches the flag check.

**Type — part 1 (the bounds check):**

```c
  __u8 *payload = (void *)(udph + 1);
  if ((void *)(payload + 4) > data_end) {
    inc_stat(3);
    return XDP_DROP;
  }
```

> Bounds check first — verifier's still watching. No flag byte in there at all?
> That's malformed, drop it.

**Type — part 2 (the actual check):**

```c
  __u8 flag = payload[3];
  if (flag != 0 && (flag & ~FLAG_VALID_MASK) == 0) {
    inc_stat(1);
    return XDP_PASS;
  }

  inc_stat(3);
  return XDP_DROP;
```

> And now the whole thing. Grab the flag byte, and ask one question: is at
> least one known bit set, and are there no unknown bits?
>
> That's it. That's the entire check. One AND, one compare.
>
> Our attacker sends 0xff. All ones. Which means it has bits set that don't
> mean anything in our protocol. Invalid.
>
> No state. No memory. No history. It doesn't care who sent it or how fast.

[Reload the guard — same command as §7. Leave the attacker running while you
do it, so the numbers change under everyone's eyes the moment it comes back.]

```bash
cd /src/sec-camp/guard && go generate ./... && go build -o /usr/local/bin/guard . \
  && ip netns exec vic /usr/local/bin/guard -rate 30 -block-ttl 15s \
       -nic veth-vic -target 10.10.0.2:9999
```

[If you stopped the attacker, restart it:]

```bash
attacker -target 10.10.0.2:9999 -mode evasive
```

> Total: still two hundred and fifty. Dropped by rate: still zero — the rate
> limiter is *still* evaded, I didn't fix that at all. Dropped by protocol: two
> hundred and fifty. Passed: zero.

[Point at the silent victim pane.]

> The server doesn't know it's being attacked. It never saw one of those
> packets.
>
> That's the point. The distributed attacker beat the layer everyone reaches
> for first — and one bitwise AND stopped all of it. Not because it's clever,
> but because it asks a completely different question. Rate limiting asks "how
> much." This asks "what." An attacker who evades one of those is still
> standing in front of the other.
>
> That's defense in depth. And all of it happened in the kernel, before the
> packet existed as anything but bytes.

---

## 10. Closer (1 min)

[Run legit in one pane, evasive in another.]

> Last thing. Real users, and the attack, at the same time.
>
> Six packets a second passing. Two hundred and fifty being dropped. The real
> users don't notice anything.
>
> That's what a working defense actually looks like. Not "we survived." Nobody
> noticed.
>
> And to be honest with you: if the attacker started sending valid flag bytes,
> this layer would let them through, and I'd be back to needing the rate
> limiter and something above it. No single check wins. Every layer you add
> just makes the attack more expensive. That's the whole job.

---

## Answers to likely questions

**Why not iptables?** iptables runs after the kernel allocates the sk_buff. XDP
runs before. Under a flood that difference is the whole game.

**What's the verifier again?** Static analyzer in the kernel. Proves your
program terminates and stays in bounds before it will load it. Rejection at
load time, not a crash at runtime.

**Couldn't they send valid flags?** Yes. Then this layer passes them and you
need the rate limiter plus application-layer defenses. Layering, not a silver
bullet.

**Why are the stats per-CPU?** So incrementing needs no lock on the hot path.
Userspace adds up the per-CPU copies when it reads them.

**Is the rate counter race-free?** No — that hash map is shared across CPUs and
the increment isn't atomic, so under real parallelism it can undercount
slightly. For rate limiting that's fine, you block a hair late. Exactness would
need a per-CPU map or a lock.

**What if the Go program dies?** Kernel keeps filtering. Existing blocks stay
(nothing expires them anymore), new rate trips still drop. Enforcement never
depended on userspace.

**Is this real or a toy?** The mechanism is real — Cloudflare and Meta run XDP
DDoS mitigation exactly like this. The made-up flag protocol is the toy part.

**Why UDP?** Connectionless, so I can trivially send from fifty different
source ports with no handshake. The flag byte stands in for TCP's real flags.

---

## Numbers cheat sheet

| mode | sources × pps | total | what you should see |
|---|---|---|---|
| legit | 3 × 2 | 6 | passed ≈ 6 |
| flood | 2 × 150 | 300 | dropped-rate high, 2 blocked, sawtooth |
| garbage | 2 × 10 | 20 | dropped-protocol ≈ 20, nothing blocked |
| evasive | 50 × 5 | 250 | dropped-protocol ≈ 250, dropped-rate 0, nothing blocked |

Threshold 30 pps/source. Block TTL 15s.

Backup demo if you need one: `-mode legit -workers 1 -pps 60` — perfectly valid
packets, blocked anyway, because Layer 2 doesn't care about content. The mirror
image of `garbage`. Shows the two layers are asking different questions.
