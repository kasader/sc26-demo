# guard demo — spoken script

*[日本語版はこちら / Japanese version here](DEMO_GUIDE.jp.md)*

Use: https://excalidraw.com/

---

## 1. Opening (0:40)

[Stand in front of the screen. Don't point at anything yet.]

> Hi. I'm [name], I work on [one line — keep it to one].
>
> Quick question so I know who I'm talking to: hands up if you've heard of eBPF.

[However many hands: keep going. Don't adjust the talk, just know the room.]

> Either way you're fine — if you know what a network packet is, you can follow
> this.
>
> Here's the next ten minutes. I'm going to attack a server. Then I'm going to
> defend it, with code that runs *inside the Linux kernel*. Then the attacker is
> going to adapt and beat my defense. And then we fix it.
>
> That middle part is the bit I want you to watch. Not "here's a firewall that
> works" — a firewall that works is boring. What's interesting is a reasonable
> defense, the one basically everybody builds first, getting walked straight
> through by an attacker who changed *how* they attack rather than how hard.

[Turn to the screen. Point at each pane as you name it — left, top right,
bottom right — and keep moving.]

> All of this is one container on this laptop. Nothing here touches the real
> network, which is also why it's fine for me to run an attack in a room full of
> people. Left: my defense, not doing anything yet, all zeros. Top right: the
> victim, a UDP server that logs whatever arrives and nothing else. Bottom
> right: a shell on the attacker — as far as the network cares, a different
> computer.
>
> Stop me and ask things as I go — it's a booth, not a lecture.

---

## 2. Why this has to happen in the kernel (1:10)

[Point at the victim pane, then draw or point at the packet path.]

> When I flood that server with garbage, the thing that gives way is usually not
> bandwidth. Most people say bandwidth. It's this:

```
NIC → driver → [allocate sk_buff] → iptables → IP → UDP → socket → your program
```

[Point at the allocation. This is the key idea of the whole talk — don't rush
this one.]

> For every packet that arrives, the kernel allocates a little struct to track
> it — an sk_buff — then walks it up through the firewall, IP, UDP, and hands it
> to your program, which looks at it and says "this is garbage."
>
> **That allocation is the problem.** You allocated, parsed, routed, copied and
> woke up a process, for a packet you were always going to discard. A hundred
> thousand times a second and the machine falls over. Not because the pipe is
> full. Because you spent your entire CPU on paperwork for junk mail.
>
> So the fix is obvious: throw it away earlier. The question is how early can
> you get.

[Point at the very start of the chain, before the allocation.]

> The answer is XDP — a hook that runs here, before the kernel allocates
> anything. The packet has just come off the wire and it's nothing but raw bytes
> in memory. My code looks at those bytes and says one of two words: PASS, carry
> on into the normal stack, or DROP, free it right now. A DROP here costs
> essentially nothing, and the sender gets nothing back, not even an error.
>
> Now, that's code inside the kernel. Historically that meant writing a kernel
> module, and if you got it wrong the whole machine panicked. Instead we use
> eBPF: I write C, compile it to a special bytecode — not a normal program — and
> hand that bytecode to the running kernel. No reboot, no module.
>
> And the reason it can't crash is the interesting part. Before the kernel runs
> a single instruction of mine, it runs the verifier — a proof engine that has to
> prove two things: that my code always finishes, and that it never reads memory
> outside what it's allowed to touch. If it can't prove that, the program doesn't
> load. Not a crash later; it just refuses.
>
> So in a minute, when you see bounds checks that look unnecessary, understand
> what they are. That's not someone being careful. That's a proof, and the kernel
> is the examiner.

---

## 3. Layer 1: rate limiting (1:50)

[Guard pane — Ctrl+C the dashboard first. This only reads git, so it can't fail
and nothing changes yet.]

```bash
./stage.sh show 1-2
```

> Here's the first layer. About thirty lines of code and the rest is comments,
> and it's two ideas.

**Part 1 — who is this, and have I already banned them:**

```c
  struct address_key src = {
      .address = bpf_ntohl(iph->saddr),
      .port = bpf_ntohs(udph->source),
  };

  if (bpf_map_lookup_elem(&blocklist, &src)) {
    inc_stat(2);
    return XDP_DROP;
  }
```

> First I build an identity for the sender: IP address, and port.
>
> **IP, and port. Hold that thought.**
>
> Then one hash lookup. If this sender is already on the blocklist, it's gone
> immediately, before I spend a single further cycle on it. That's a design
> principle, not an optimization: known-bad is the cheapest check you have, so it
> goes first.

**Part 2 — how fast are they going:**

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

> One-second window, per sender. First packet opens a window. If a full second
> has passed, reset. Otherwise, count it.

**Part 3 — and if they're over the line:**

```c
    if (rs->count > rate_threshold) {
      struct block_event evt = {.address = src.address, .port = src.port,
                                .count = rs->count};
      bpf_ringbuf_output(&block_events, &evt, sizeof(evt), 0);
      inc_stat(2);
      return XDP_DROP;
    }
```

> Over the threshold — thirty packets a second — and this sender is flooding.
> Two things happen. I push a message up to my Go program so it can put this
> sender on that blocklist for fifteen seconds. And I drop the packet, right now,
> in the kernel.
>
> I don't wait for the Go program. By the time it reads that message, the drop
> already happened. **The kernel enforces; userspace just keeps the notes.**

### Now run it, then run flood

[This checks out stage 2, rebuilds, and restarts the guard. Takes a few seconds
and prints each step — talk over it, don't stand in silence.]

```bash
./stage.sh run 2
```

> Watch the three lines it prints, because that's the whole pipeline. It takes
> the C, compiles it to bytecode, and hands it to the running kernel, where the
> verifier checks it before it's allowed anywhere near a packet.

[Attacker pane.]

```bash
attacker -target 10.10.0.2:9999 -mode flood
```

> Two attackers, a hundred and fifty packets a second each. Five times over the
> limit.

[Point at dropped-rate climbing, then at the blocklist panel.]

> There they are on the blocklist, with a fifteen-second countdown. And watch
> what happens when it expires —

[Wait for the sawtooth.]

> — block drops off, attacker resumes, and within a fifth of a second it's over
> the limit again and straight back on. That sawtooth is the TTL working.
>
> So. Rate limiting works. Job done, right?

[Ctrl+C.]

---

## 4. The trap (1:10) ← this is the talk

[Point back at the `src` struct — stage 2 is checked out, so it's in the editor
now.]

> Except — look again at how I decided who a sender *is*. IP, and port.
>
> What if the attacker sends from fifty different ports? Five packets a second
> each. My limit is thirty.
>
> Every packet looks like it's from a brand new sender. No window ever fills up.
> **Not one of them is breaking my rule.** But fifty times five is two hundred
> and fifty packets a second hitting my server — the same order of traffic as the
> flood I just blocked.

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

## 5. Layer 2: ask what, not how fast (1:20)

> So let's stop asking how fast they're sending, and start asking *what* they're
> sending.
>
> Our protocol has a flag byte in the payload — copied from how TCP works. Five
> bits that mean something: SYN, ACK, FIN, and so on. A real client sets a
> sensible combination.

[Leave the attack running and show the last diff.]

```bash
./stage.sh show 3
```

> Fifteen lines. And notice the red lines at the bottom — this is the one step
> that *removes* something. That `return XDP_PASS` at the end of the function,
> the one that's been letting everything through, is what this replaces.

```c
  __u8 *payload = (void *)(udph + 1);
  if ((void *)(payload + 4) > data_end) {
    inc_stat(3);
    return XDP_DROP;
  }

  __u8 flag = payload[3];
  if (flag != 0 && (flag & ~FLAG_VALID_MASK) == 0) {
    inc_stat(1);
    return XDP_PASS;
  }

  inc_stat(3);
  return XDP_DROP;
```

> Bounds check first — the verifier is still watching. No flag byte in there at
> all? Malformed, drop it.
>
> Then the whole check: grab the flag byte, and ask one question. Is at least one
> known bit set, and are there no unknown bits? That's it. One AND, one compare.
>
> Our attacker sends 0xff. All ones — which means it has bits set that don't mean
> anything in our protocol. Invalid.
>
> No state. No memory. No history. It doesn't care who sent it or how fast.

[Switch while the attacker is still running, so the numbers change under
everyone's eyes the moment the guard comes back.]

```bash
./stage.sh run 3
```

[If you stopped the attacker, restart it: `attacker -target 10.10.0.2:9999 -mode
evasive`]

> Total: still two hundred and fifty. Dropped by rate: still zero — the rate
> limiter is *still* evaded, I didn't fix that at all. Dropped by protocol: two
> hundred and fifty. Passed: zero.

[Point at the silent victim pane.]

> The server doesn't know it's being attacked. It never saw one of those packets.
>
> And this is the part that matters: **we never allocated anything for them.**
> No sk_buff, no trip up the stack, no process woken up. The decision happened in
> the kernel while the packet was still just bytes on the wire — so all that work
> back in userspace was never done, because there was nothing left to do it to.

---

## 6. Closer (0:40)

[Start legit alongside the evasive attack, which is still running.]

```bash
attacker -target 10.10.0.2:9999 -mode legit
```

> Last thing: real users and the attack, at the same time. Six packets a second
> passing, two hundred and fifty being dropped, and the real users don't notice
> anything.
>
> That's what a working defense actually looks like. Not "we survived." Nobody
> noticed.
>
> Two layers, asking two different questions — how much, and what. An attacker
> who evades one of them is still standing in front of the other. That's defense
> in depth.
>
> And to be honest with you: **this is not a cure-all.** An attacker who sends
> perfectly valid flag bytes, slowly, from fifty ports — under my rate limit and
> past my protocol check — still gets through, and I'd be back to needing another
> layer above these two. No single check wins. Every layer you add just makes the
> attack more expensive. That's the whole job.

---

## Answers to likely questions

**Why branches instead of typing it live?** Because a typo in a twenty-five-line
eBPF function costs half a ten-minute slot. The diffs are the same code you'd
have watched me type, and the compile and the verifier still run in front of you.

**Why not iptables?** iptables runs after the kernel allocates the sk_buff. XDP
runs before. Under a flood that difference is the whole game.

**What's the verifier again?** Static analyzer in the kernel. Proves your
program terminates and stays in bounds before it will load it. Rejection at
load time, not a crash at runtime.

**Couldn't they send valid flags?** Yes. Then this layer passes them and you
need the rate limiter plus application-layer defenses. Layering, not a silver
bullet.

**What are the `inc_stat` calls?** One counter each for total, passed,
dropped-rate, dropped-protocol — that's what the dashboard is reading. They're
per-CPU, so incrementing needs no lock on the hot path; userspace adds up the
per-CPU copies when it reads them.

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

**How does the IP header parsing work?** (Cut for time, ask me after.) `ihl`
holds the header length in units of four bytes — assume twenty and an attacker
who sends a longer header has you parsing the wrong bytes entirely.

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
packets, blocked anyway, because layer 1 doesn't care about content. The mirror
image of `garbage`. Shows the two layers are asking different questions.

Runs about seven minutes as written, which lands under ten only if questions
wait until the end. Section 4 is the one that must not be cut.
