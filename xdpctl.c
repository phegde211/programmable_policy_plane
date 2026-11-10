// SPDX-License-Identifier: GPL-2.0
/* xdpctl.c - loader / control-plane skeleton for xdp_plane
 *
 *   xdpctl load  <ifname>                      attach + pin + event loop
 *   xdpctl deny  <sip> <dip> <sport> <dport> <tcp|udp> [ttl_sec]
 *   xdpctl block <ip> [prefixlen]
 *   xdpctl stats
 *
 * Author: Prabhat Hegde
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include "xdp_plane.skel.h"

#define PIN_DIR "/sys/fs/bpf/xdp_plane"

struct flow_key {
    __u32 saddr, daddr;
    __u16 sport, dport;
    __u8  proto, pad[3];
};
struct lpm_key   { __u32 prefixlen, addr; };
struct miss_event{ struct flow_key fk; __u64 ts_ns; };

static const char *cnt_names[] = {
    "pass", "drop_blocklist", "drop_rate", "drop_deny", "redirect", "miss",
};

static volatile sig_atomic_t stop;
static void on_int(int sig) { (void)sig; stop = 1; }

static __u64 mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);     /* matches bpf_ktime_get_ns */
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int on_event(void *c, void *data, size_t len)
{
    (void)c; (void)len;
    struct miss_event *ev = data;
    char s[32], d[32];
    inet_ntop(AF_INET, &ev->fk.saddr, s, sizeof(s));
    inet_ntop(AF_INET, &ev->fk.daddr, d, sizeof(d));
    printf("MISS  %s:%u -> %s:%u proto %u  (deferred to stack)\n",
           s, ntohs(ev->fk.sport), d, ntohs(ev->fk.dport), ev->fk.proto);
    return 0;
}

static int pinned(const char *name)
{
    char p[256];
    snprintf(p, sizeof(p), "%s/%s", PIN_DIR, name);
    int fd = bpf_obj_get(p);
    if (fd < 0)
        fprintf(stderr, "open %s failed (is 'xdpctl load' running?)\n", p);
    return fd;
}

static int cmd_load(const char *ifname)
{
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    struct xdp_plane_bpf *skel = xdp_plane_bpf__open();
    if (!skel) { fprintf(stderr, "skeleton open failed\n"); return 1; }
    /* tunables could be set here: skel->rodata->rate_pps = ...; */

    struct xdp_program *prog =
        xdp_program__from_bpf_obj(skel->obj, "xdp");
    if (!prog) { fprintf(stderr, "xdp_program failed\n"); return 1; }

    int err = xdp_program__attach(prog, ifindex, XDP_MODE_UNSPEC, 0);
    if (err) { fprintf(stderr, "attach failed: %d\n", err); return 1; }
    printf("attached to %s (mode auto: native if the driver supports it)\n",
           ifname);

    mkdir(PIN_DIR, 0700);
    bpf_map__pin(skel->maps.deny,      PIN_DIR "/deny");
    bpf_map__pin(skel->maps.blocklist, PIN_DIR "/blocklist");
    bpf_map__pin(skel->maps.counters,  PIN_DIR "/counters");

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ringbuf failed\n"); return 1; }

    signal(SIGINT, on_int);
    signal(SIGTERM, on_int);
    printf("event loop running; Ctrl-C detaches and exits\n");
    while (!stop)
        ring_buffer__poll(rb, 200 /* ms */);

    ring_buffer__free(rb);
    xdp_program__detach(prog, ifindex, XDP_MODE_UNSPEC, 0);
    xdp_program__close(prog);
    /* maps stay pinned so programmed verdicts survive; remove with:
     *   rm -rf /sys/fs/bpf/xdp_plane                                */
    return 0;
}

static int cmd_deny(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "deny needs 5 args\n"); return 1; }
    struct flow_key fk = {0};
    inet_pton(AF_INET, argv[0], &fk.saddr);
    inet_pton(AF_INET, argv[1], &fk.daddr);
    fk.sport = htons(atoi(argv[2]));
    fk.dport = htons(atoi(argv[3]));
    fk.proto = strcmp(argv[4], "udp") ? IPPROTO_TCP : IPPROTO_UDP;

    __u64 expiry = 0;                              /* 0 = permanent */
    if (argc > 5)
        expiry = mono_ns() + (__u64)atoi(argv[5]) * 1000000000ULL;

    int fd = pinned("deny");
    if (fd < 0) return 1;
    if (bpf_map_update_elem(fd, &fk, &expiry, BPF_ANY)) {
        perror("map update"); return 1;
    }
    printf("deny installed (packet #2 onward drops at XDP)\n");
    return 0;
}

static int cmd_block(int argc, char **argv)
{
    if (argc < 1) { fprintf(stderr, "block needs an ip\n"); return 1; }
    struct lpm_key k = { .prefixlen = argc > 1 ? atoi(argv[1]) : 32 };
    inet_pton(AF_INET, argv[0], &k.addr);
    __u8 one = 1;

    int fd = pinned("blocklist");
    if (fd < 0) return 1;
    if (bpf_map_update_elem(fd, &k, &one, BPF_ANY)) {
        perror("map update"); return 1;
    }
    printf("blocklist entry installed\n");
    return 0;
}

static int cmd_stats(void)
{
    int fd = pinned("counters");
    if (fd < 0) return 1;
    int ncpu = libbpf_num_possible_cpus();
    __u64 vals[ncpu];
    for (__u32 i = 0; i < 6; i++) {
        __u64 sum = 0;
        if (!bpf_map_lookup_elem(fd, &i, vals))
            for (int c = 0; c < ncpu; c++) sum += vals[c];
        printf("%-16s %llu\n", cnt_names[i], (unsigned long long)sum);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) goto usage;
    if (!strcmp(argv[1], "load")  && argc == 3)
        return cmd_load(argv[2]);
    if (!strcmp(argv[1], "deny"))
        return cmd_deny(argc - 2, argv + 2);
    if (!strcmp(argv[1], "block"))
        return cmd_block(argc - 2, argv + 2);
    if (!strcmp(argv[1], "stats"))
        return cmd_stats();
usage:
    fprintf(stderr,
        "usage: xdpctl load <ifname>\n"
        "       xdpctl deny <sip> <dip> <sport> <dport> <tcp|udp> [ttl_s]\n"
        "       xdpctl block <ip> [prefixlen]\n"
        "       xdpctl stats\n");
    return 1;
}
