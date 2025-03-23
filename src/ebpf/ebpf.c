#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>
#include <linux/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))

struct data_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  tcp_flags;
    u32 pkt_len;
    u64 timestamp;
};

BPF_PERF_OUTPUT(events);

BPF_HASH(pkt_count_map, u32, u64, 1024);
BPF_HASH(byte_count_map, u32, u64, 1024);
BPF_HASH(syn_count_map, u32, u64, 1024);

struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
};
BPF_HASH(flow_pkt_count_map, struct flow_key_t, u64, 2048);

SEC("xdp")
int xdp_monitor_tcp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    u32 pkt_len = data_end - data;
    u64 pkt_len64 = pkt_len;

    u32 saddr = ip->saddr;
    u32 daddr = ip->daddr;
    u16 sport = bpf_ntohs(tcp->source);
    u16 dport = bpf_ntohs(tcp->dest);
    u8 flags = ((__u8 *)tcp)[13];

    u64 one = 1, *val;

    val = pkt_count_map.lookup(&saddr);
    if (val) (*val)++;
    else pkt_count_map.update(&saddr, &one);

    val = byte_count_map.lookup(&saddr);
    if (val) (*val) += pkt_len64;
    else byte_count_map.update(&saddr, &pkt_len64);

    if (flags & 0x02) {
        val = syn_count_map.lookup(&saddr);
        if (val) (*val)++;
        else syn_count_map.update(&saddr, &one);
    }

    struct flow_key_t flow = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .proto = ip->protocol
    };
    val = flow_pkt_count_map.lookup(&flow);
    if (val) (*val)++;
    else flow_pkt_count_map.update(&flow, &one);

    struct data_t evt = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .tcp_flags = flags,
        .pkt_len = pkt_len,
        .timestamp = bpf_ktime_get_ns()
    };

    events.perf_submit(ctx, &evt, sizeof(evt));
    return XDP_PASS;
}
