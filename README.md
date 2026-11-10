# XDP Inline Policy & Forwarding Plane

**Author:** Prabhat Hegde · **Copyright:** (c) 2026 Prabhat Hegde. All rights reserved. · **Status:** Draft v0.1

An inline software packet-processing plane at the **XDP** (eXpress Data Path)
hook — the driver receive path, **before `sk_buff` allocation and before the
kernel network stack** — that replays verdicts decided once by the higher-layer
authority (netfilter/firewall): drop, accept, or forward (service insertion),
plus lightweight DDoS shedding and sampled audit.

## Repository layout

| File | What it is |
|---|---|
| [xdp_plane.bpf.c](xdp_plane.bpf.c) | kernel-side XDP program (CO-RE): the 5-stage pipeline |
| [xdpctl.c](xdpctl.c) | user-space loader / control-plane agent (`load`, `deny`, `block`, `stats`) |
| [Makefile](Makefile) | vmlinux.h → BPF object → skeleton → `xdpctl` |
| [TESTING.txt](TESTING.txt) | prerequisites, build, full test plan (T1–T5), limitations |

**Quick start**

```
make
sudo ./xdpctl load <ifname>        # attach, pin maps, print miss events
sudo ./xdpctl block 10.0.0.2 32    # static drop for a source
sudo ./xdpctl stats                # per-verdict counters
```

Full test procedure (veth pair + namespace): see [TESTING.txt](TESTING.txt).

---

## 1. Problem statement

On a Linux software router / border device, every packet that enters the
kernel network stack pays a fixed cost before any policy verdict is reached:
socket-buffer (skb) allocation, netfilter rule traversal, connection-tracking
(conntrack) lookup, and routing. This cost is paid even for traffic whose fate
is already known:

1. A flow the firewall has **already denied** keeps re-entering the stack and
   being dropped high up — paying skb + netfilter cost per packet, and in a
   hairpin/service-insertion topology, re-consuming the firewall link.
2. A flow the firewall has **already permitted** (or decided to steer to an
   inserted service such as a firewall hop) re-pays the full decision cost on
   every packet, although the decision will not change.
3. **Volumetric attacks** (DDoS) weaponize exactly this cost: floods of new
   flows exhaust the conntrack state table and burn CPU in the stack before
   any rule can reject them.
4. **Netfilter is declarative and bounded**: policy can only be expressed in
   its fixed vocabulary of matches and targets. Custom logic (per-source token
   buckets, custom signals, sampling) does not fit that vocabulary.

Hardware offload (NIC filters, switch ASIC ACLs) avoids these costs but
introduces a hardware dependency: vendor lock-in, fixed table sizes, rigid
match fields, slow change cycles.

**The problem:** enforce already-decided verdicts, shed attack traffic, and
steer flows — in **software**, with custom programmability, at the earliest
possible point, wasting the least resources and relieving the kernel stack.

## 2. Proposed solution

Place an eBPF program at the XDP hook — operating on the DMA'd RX buffer
**before** skb allocation and **before** the kernel network stack is invoked —
and run it as a **replay engine** for decisions made once by the higher-layer
authority.

**Honest positioning (normative).** This plane does **not** beat or equal
hardware. Hardware is the performance ceiling, bought with a dependency cost.
This is a **software betterment**: do the job early, waste fewer resources,
give the kernel stack relief — trading some absolute performance and CPU for
flexibility, live programmability, and zero hardware dependence.

**Core model — decide once, replay many:**

- The **first** packet of an unknown flow is deferred up to the stack. The
  firewall/netfilter decides **once**, then installs an explicit signal.
- From the **second** packet onward, XDP replays that signal inline: drop,
  pass, or forward (service insertion), at line rate.

**Explicit signal model (normative):**

- **ALLOW** — the kernel's own conntrack entry (confirmed): free,
  kernel-owned, created as a side effect of the stack permitting a flow. The
  connection mark (connmark) carries a steering verdict.
- **DENY** — a **dedicated deny table** written explicitly by the authority.
  Conntrack cannot express "drop" (a dropped flow is never confirmed), and
  absence of state is ambiguous — it may be a genuine new flow. Therefore XDP
  drops **only** on a positive, explicitly installed deny signal. Never on
  inference.
- **MISS** — no signal → defer up (`XDP_PASS`). **Never drop on a miss.**

Independent of the signals, XDP keeps its **own** lightweight state for
rate-limiting and DDoS shedding (blocklists, per-source token buckets),
programmed by a detection agent. These drop **before** conntrack and thereby
**shield conntrack from state-table exhaustion**.

## 3. Scope

**In scope**

- Ingress fast path: drop / accept / forward / steer per installed signal.
- Service insertion: per-flow next-hop change toward a firewall hop.
- Lightweight DDoS defense: static blocklist, per-source token bucket.
- Sampled audit: truncated packet/flow events to a user-space consumer.
- Control-plane contract: which component writes which table.

**Out of scope**

- The firewall's own policy logic (remains in netfilter/firewall).
- Deep packet inspection, L7, decryption (stack/user space only).
- Hardware offload paths (NIC filters, switch ASIC ACLs, DPUs) — the same
  architecture maps onto them, but they are a different substrate.
- Full line-rate traffic mirroring (belongs to tc `clone_redirect` or
  hardware SPAN, not XDP).
- Egress (source-side) enforcement: XDP is ingress-only; the same design
  applies at the tc clsact egress hook and is a future profile.

## 4. Design

### 4.1 Principles (normative)

- **P1 — Explicit signals only.** XDP acts on positive verdicts installed by
  an authority; it never infers. Absence of state ⇒ defer up, never drop.
- **P2 — Decide once, replay many.** Slow path decides; fast path replays.
- **P3 — Tracking and policy stay separate.** Conntrack = allow signal only.
  Drop lives in its own table. They are never merged.
- **P4 — Least work at the lowest level.** XDP does cheap, bounded
  operations. Anything stateful, L7, or post-decrypt stays at
  netfilter/user space.
- **P5 — Outer headers only.** XDP sees the packet pre-decryption /
  decapsulation. Decisions must be expressible on the outer flow or be
  deferred up.
- **P6 — The eBPF verifier guarantees *safety*** (no crash, no unbounded
  loop), **not *correctness***. The programmer owns logic, performance, and
  non-interference with kernel operation.

### 4.2 Architecture

```
  +--------------------- CONTROL PLANE (user space) ----------------------+
  |  policy agent (firewall bridge) |  DDoS detector   |  audit consumer  |
  |     | writes deny / blocklist   |  writes rate     |    ^ reads       |
  |     | / fwd entries             |  parameters      |    | events      |
  +-----|-----------------------------|-----------------|---|------------+
        v                             v                     |
  +-------------------------- BPF MAPS (pinned) --------------------------+
  |  deny(LRU)  blocklist(LPM)  rate(LRU)  fwd(DEVMAP)  events(RINGBUF)   |
  +----------------------------------+-------------------------------------+
                                     ^ lookups / event emits
                                     |
   NIC --DMA--> [ XDP PROGRAM ] -----+----- ct lookup ----> kernel conntrack
   (RX ring,         |                                      (ALLOW + connmark)
    no skb yet)      | verdict
                     v
        +------------+-------------+
        |            |             |
     XDP_DROP   XDP_REDIRECT    XDP_PASS
     (blocklist  (forward /      (local accept, or MISS)
      / rate /    steer to            |
      deny)       firewall)           v   first packet only
                              kernel stack -> netfilter / firewall
                              decides ONCE -> installs the signal
                              (conntrack+mark | deny entry via agent)
```

Map glossary: LRU = least-recently-used bounded hash; LPM = longest-prefix-
match trie (CIDR matching); DEVMAP = interface redirect table; RINGBUF =
kernel-to-user event ring.

### 4.3 Signal tables

| Signal | Where it lives | Written by | XDP action |
|---|---|---|---|
| **ALLOW** | kernel conntrack (`IPS_CONFIRMED`) | kernel (side effect of accept) | `XDP_PASS` |
| **STEER/FWD** | connmark on the conntrack (verdict + next-hop id) | netfilter CONNMARK rule at decision | rewrite next hop, `XDP_REDIRECT` |
| **DENY** | deny map (flow → expiry) | policy agent on the drop decision | `XDP_DROP` |
| **STATIC-DENY** | blocklist map (LPM/CIDR) | operator / DDoS detector | `XDP_DROP` |
| **RATE** | rate map (token buckets) | XDP itself; params from detector | `XDP_DROP` when bucket empty |
| **AUDIT** | connmark audit bit + events ring | netfilter rule / agent | copy sample, then continue |
| *(miss)* | — | — | `XDP_PASS` (defer up) |

**Evaluation order (normative):** blocklist → rate → deny → conntrack → miss.
Deny is evaluated **before** conntrack so that a mid-flow revocation takes
effect on the very next packet, even for an established flow.

### 4.4 Packet-processing pipeline (fast path)

```
                 packet (outer headers only, pre-skb)
                                |
                                v
                   +------------------------+   hit
                   | 1. blocklist (LPM)     |---------->  XDP_DROP
                   +-----------+------------+
                               | miss
                               v
                   +------------------------+   bucket empty
                   | 2. rate (token bucket) |---------->  XDP_DROP
                   +-----------+------------+
                               | ok
                               v
                   +------------------------+   hit (not expired)
                   | 3. deny map            |---------->  XDP_DROP
                   +-----------+------------+
                               | miss
                               v
                   +------------------------+   confirmed
                   | 4. conntrack lookup    |------------------+
                   +-----------+------------+                  |
                               | none                          v
                               v                    +--------------------+
                   +------------------------+       | read connmark      |
                   | 5. MISS: defer upward  |       +----+----------+----+
                   |    (XDP_PASS to stack) |            |          |
                   +------------------------+       ALLOW_LOCAL  STEER/FWD
                     netfilter decides ONCE             |          |
                     and installs the signal        XDP_PASS   L2 rewrite +
                     (ct + mark | deny entry)                 XDP_REDIRECT
```

### 4.5 First-packet slow path (decide once)

```
     XDP (fast path)         netfilter / firewall       signal stores
          |                          |                        |
   1. no signal found                |                        |
          |------- XDP_PASS -------->|                        |
          |                   2. decide ONCE                  |
          |                          |-- allow: ct confirmed ->| (+connmark:
          |                          |                        |  local or
          |                          |                        |  steer id)
          |                          |-- deny: agent writes -->| deny[flow]
          |                          |                        |
   3. packet #2 onward               |                        |
          |<----------- lookup signal ------------------------|
          |   replay inline: DROP / PASS / REDIRECT           |
```

The in-flight race (a few packets slip upward between the decision and the map
write) is accepted; it converges in microseconds.

### 4.6 Use cases

**UC1 — LAN → Internet, denied flow.** First packet deferred up; firewall
decides DROP; agent writes the deny entry. Packet #2 onward is dropped at
XDP — the flow never again consumes skb, netfilter, or uplink resources.

**UC2 — Inter-VLAN with firewall hairpin (service insertion).** VLAN-A →
VLAN-B must transit the gateway; policy requires a firewall. First packet:
netfilter steers it to the firewall and sets connmark = STEER(fw). Packet #2
onward: XDP rewrites the next hop to the firewall port directly.

```
  VLAN10 host --> [ gateway ] ==(pkt2+: XDP steer)==> firewall
                     |  ^                                |
        1st pkt:     |  +------ permitted traffic -------+
        netfilter    |
        decides      +--> routed to VLAN20 destination
```

- *Stateful firewall:* keep STEER for every packet (firewall stays inline;
  it must see the whole flow).
- *Stateless firewall:* after permit, connmark = FWD(dest); XDP then bypasses
  the hairpin entirely.

This choice is deliberate and belongs to the operator.

**UC3 — DDoS / rate limiting.** Blocklist and token buckets drop at XDP
**before** any conntrack state can be created. This both saves the per-packet
stack cost and protects conntrack itself from state-table exhaustion —
conntrack is a prime DDoS target and must never be on the flood path.

**UC4 — Audit.** Flows flagged for audit get a truncated, sampled copy pushed
to the events ring for a user-space consumer; the original packet still
receives its normal verdict. Full mirroring is out of scope (P4): use tc
`clone_redirect` or hardware SPAN for that.

### 4.7 Constraints and boundaries

- **C1** — Outer-header visibility only. Encrypted/encapsulated traffic is
  steerable per **outer** tuple (whole tunnel), never per inner flow.
  Decryption at XDP is explicitly forbidden (wrong layer).
- **C2** — Native XDP (driver support) is required for the pre-skb benefit;
  generic/SKB mode forfeits it.
- **C3** — Conntrack lookups from XDP use kernel kfuncs (kernel ≥ 5.19,
  `CONFIG_NF_CONNTRACK`; connmark needs `CONFIG_NF_CONNTRACK_MARK`).
- **C4** — CPU cost is the accepted price: logic runs per packet per core. A
  large enough flood still consumes host CPU (hardware offload would not —
  that is the dependency trade).
- **C5** — Verifier limits: bounded loops only, 512-byte stack, program
  complexity caps → split logic via tail calls if it grows.
- **C6** — All agent-written maps are bounded (LRU + TTL) so that spoofed-
  source floods cannot grow them without limit.

### 4.8 Failure posture

- Miss ⇒ `XDP_PASS` (fail-open toward the authority). A default-deny posture
  is possible but then **requires** pre-authorized allow entries; it is a
  conscious operator choice, not the default.
- Agent down: maps retain the last programmed state; misses continue to defer
  upward. Monitored, not fatal.
- Expired deny entries are deleted on hit and the flow re-defers up for
  re-evaluation.

## 5. Implementation snapshots (high level)

These snippets convey shape, not the full implementation — see
[xdp_plane.bpf.c](xdp_plane.bpf.c) / [xdpctl.c](xdpctl.c).

**The tables (BPF maps)**

```
deny      : LRU_HASH   key = {saddr,daddr,sport,dport,proto}
                       val = expiry_ns (0 = no expiry)
blocklist : LPM_TRIE   key = {prefixlen, addr}        val = u8
rate      : LRU_HASH   key = source ip                val = {tokens,last}
fwd       : DEVMAP     key = next-hop id              val = ifindex
events    : RINGBUF    miss / audit records to user space
```

**The pipeline (shape of the XDP program)**

```c
if (blocklist_hit(src))          return XDP_DROP;
if (!tokens_available(src))      return XDP_DROP;
if (deny_active(flow))           return XDP_DROP;     /* explicit only */
ct = conntrack_lookup(flow);
if (ct && confirmed(ct)) {
    if (steer(ct->mark))         return redirect(nexthop(ct->mark));
    return XDP_PASS;                                   /* allowed */
}
emit_miss_event(flow);
return XDP_PASS;                 /* unknown: defer to the authority */
```

**Programming the drop signal (control plane)**

```c
/* called by the agent when the firewall decides DROP */
expiry = now_monotonic_ns() + ttl_ns;        /* 0 for permanent */
bpf_map_update_elem(deny_fd, &flow, &expiry, BPF_ANY);
```

**Token bucket (XDP's own light state)**

```c
tokens += (now - last) * RATE_PPS / 1e9;     /* refill */
if (tokens > BURST) tokens = BURST;
if (tokens == 0)    drop;  else  tokens--;   /* spend */
```

## 6. Observability

- Per-verdict counters (per-CPU): pass, drop_blocklist, drop_rate, drop_deny,
  redirect, miss.
- Miss/audit events on the ring buffer for the control plane.
- Map occupancy and eviction rates (deny, rate) as exhaustion alarms.

## 7. Future work

- tc clsact egress profile (source-side enforcement, same signal model).
- NAT-correct tuple derivation for conntrack lookups.
- IPv6 support; finalized connmark bit-field scheme.
- A second hook on the post-decryption path (inner-flow fast path).

---

*(c) 2026 Prabhat Hegde. All rights reserved.*
