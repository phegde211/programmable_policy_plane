// SPDX-License-Identifier: GPL-2.0
/* xdp_plane.bpf.c - inline policy & forwarding plane (skeleton)
 * Pipeline: blocklist -> rate -> deny -> conntrack(allow/steer) -> miss.
 * Author: Prabhat Hegde
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";   /* conntrack kfuncs require GPL */

#define ETH_P_IP     0x0800
#define NSEC_PER_SEC 1000000000ULL

/* connmark scheme: byte3 = verdict (0 local, 1 steer), low 16 = nexthop */
#define MARK_VERDICT(m)  ((m) >> 24)
#define MARK_NEXTHOP(m)  ((m) & 0xffff)

enum { CNT_PASS, CNT_DROP_BLOCK, CNT_DROP_RATE, CNT_DROP_DENY,
       CNT_REDIRECT, CNT_MISS, CNT_MAX };

struct flow_key {
    __u32 saddr, daddr;
    __u16 sport, dport;
    __u8  proto, pad[3];
};
struct rl_state  { __u64 tokens, last_ns; };
struct lpm_key   { __u32 prefixlen, addr; };
struct miss_event{ struct flow_key fk; __u64 ts_ns; };

/* DENY: the explicit positive drop signal, agent-written, bounded */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, __u64);                 /* expiry ns; 0 = permanent */
    __uint(max_entries, 1 << 17);
} deny SEC(".maps");

/* STATIC-DENY: known-bad sources (CIDR) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(max_entries, 1 << 14);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist SEC(".maps");

/* RATE: per-source token bucket (XDP's own light state) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);                   /* source address */
    __type(value, struct rl_state);
    __uint(max_entries, 1 << 17);
} rate SEC(".maps");

/* FWD: next-hop id -> egress ifindex */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 16);
} fwd SEC(".maps");

/* events to the control plane (miss notifications) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, CNT_MAX);
} counters SEC(".maps");

/* tunables patched by the loader before load (read-only data) */
const volatile __u64 rate_pps   = 10000;
const volatile __u64 rate_burst = 2000;
const volatile __u8  ct_enable  = 1;

/* ---- conntrack kfuncs (kernel >= 5.19, CONFIG_NF_CONNTRACK) --------- */
struct bpf_ct_opts___local {
    __s32 netns_id;
    __s32 error;
    __u8  l4proto;
    __u8  dir;
    __u8  reserved[2];
};
extern struct nf_conn *
bpf_xdp_ct_lookup(struct xdp_md *xdp_ctx, struct bpf_sock_tuple *tuple,
                  __u32 tuple__sz, struct bpf_ct_opts___local *opts,
                  __u32 opts__sz) __ksym;
extern void bpf_ct_release(struct nf_conn *ct) __ksym;

static __always_inline void count(__u32 id)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &id);
    if (v) (*v)++;
}

static __always_inline int rate_ok(__u32 src)
{
    __u64 now = bpf_ktime_get_ns();
    struct rl_state *st = bpf_map_lookup_elem(&rate, &src);

    if (!st) {
        struct rl_state init = { .tokens = rate_burst, .last_ns = now };
        bpf_map_update_elem(&rate, &src, &init, BPF_ANY);
        return 1;
    }
    /* note: cross-CPU update race accepted for the skeleton (approximate
     * policing); production uses per-CPU buckets or atomics. */
    __u64 tok = st->tokens + (now - st->last_ns) * rate_pps / NSEC_PER_SEC;
    if (tok > rate_burst) tok = rate_burst;
    st->last_ns = now;
    if (!tok) { st->tokens = 0; return 0; }
    st->tokens = tok - 1;
    return 1;
}

SEC("xdp")
int xdp_plane(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)          return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))   return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)           return XDP_PASS;

    /* 1. STATIC-DENY (IP level - applies to every protocol) */
    struct lpm_key lk = { .prefixlen = 32, .addr = ip->saddr };
    if (bpf_map_lookup_elem(&blocklist, &lk)) {
        count(CNT_DROP_BLOCK);
        return XDP_DROP;
    }

    /* 2. RATE (IP level) */
    if (!rate_ok(ip->saddr)) {
        count(CNT_DROP_RATE);
        return XDP_DROP;
    }

    /* flow-level signals are TCP/UDP only in this skeleton */
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    void *l4 = (void *)ip + ip->ihl * 4;
    if (l4 + 4 > data_end)                     return XDP_PASS;
    __be16 sport = *(__be16 *)l4;
    __be16 dport = *(__be16 *)(l4 + 2);

    struct flow_key fk = {
        .saddr = ip->saddr, .daddr = ip->daddr,
        .sport = sport,     .dport = dport,
        .proto = ip->protocol,
    };

    /* 3. DENY - the explicit drop signal; evaluated BEFORE conntrack so
     *    a revocation beats an established flow on the next packet.    */
    __u64 *exp = bpf_map_lookup_elem(&deny, &fk);
    if (exp) {
        if (*exp == 0 || *exp > bpf_ktime_get_ns()) {
            count(CNT_DROP_DENY);
            return XDP_DROP;
        }
        bpf_map_delete_elem(&deny, &fk);   /* expired: re-evaluate */
    }

    /* 4. ALLOW / STEER via kernel conntrack + connmark */
    if (ct_enable) {
        struct bpf_sock_tuple tup = {};
        tup.ipv4.saddr = ip->saddr; tup.ipv4.daddr = ip->daddr;
        tup.ipv4.sport = sport;     tup.ipv4.dport = dport;

        struct bpf_ct_opts___local o = {
            .netns_id = -1, .l4proto = ip->protocol,
        };
        struct nf_conn *ct = bpf_xdp_ct_lookup(ctx, &tup,
                                               sizeof(tup.ipv4),
                                               &o, sizeof(o));
        if (ct) {
            unsigned long status = ct->status;
            __u32 mark = ct->mark;           /* CONFIG_NF_CONNTRACK_MARK */
            bpf_ct_release(ct);              /* mandatory before return  */

            if (status & IPS_CONFIRMED) {
                if (MARK_VERDICT(mark) == 1) {
                    /* production: bpf_fib_lookup() + MAC rewrite here */
                    count(CNT_REDIRECT);
                    return bpf_redirect_map(&fwd, MARK_NEXTHOP(mark), 0);
                }
                count(CNT_PASS);
                return XDP_PASS;             /* ALLOW_LOCAL */
            }
        }
    }

    /* 5. MISS: no signal -> defer upward. NEVER drop on ambiguity. */
    struct miss_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->fk = fk;
        ev->ts_ns = bpf_ktime_get_ns();
        bpf_ringbuf_submit(ev, 0);
    }
    count(CNT_MISS);
    return XDP_PASS;
}
