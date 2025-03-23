#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct data_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  tcp_flags;
    __u32 pkt_len;
    __u64 timestamp;
};

// Maps for statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // saddr
    __type(value, __u64); // packet count
} pkt_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // saddr
    __type(value, __u64); // byte count
} byte_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // saddr
    __type(value, __u64); // SYN count
} syn_count_map SEC(".maps");

// Flow key = 5-tuple
struct flow_key_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct flow_key_t);
    __type(value, __u64); // packet count per flow
} flow_pkt_count_map SEC(".maps");

SEC("xdp")
int xdp_monitor_tcp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);
    __u8 flags = ((__u8 *)tcp)[13]; // grab TCP flags
    __u32 pkt_len = data_end - data;

    // Increment packet count per IP
    __u64 *pkt_cnt = bpf_map_lookup_elem(&pkt_count_map, &saddr);
    __u64 one = 1;
    if (pkt_cnt)
        __sync_fetch_and_add(pkt_cnt, 1);
    else
        bpf_map_update_elem(&pkt_count_map, &saddr, &one, BPF_ANY);

    // Increment byte count per IP
    __u64 *byte_cnt = bpf_map_lookup_elem(&byte_count_map, &saddr);
    if (byte_cnt)
        __sync_fetch_and_add(byte_cnt, pkt_len);
    else
        bpf_map_update_elem(&byte_count_map, &saddr, &pkt_len, BPF_ANY);

    // SYN flag counter
    if (flags & 0x02) {
        __u64 *syn_cnt = bpf_map_lookup_elem(&syn_count_map, &saddr);
        if (syn_cnt)
            __sync_fetch_and_add(syn_cnt, 1);
        else
            bpf_map_update_elem(&syn_count_map, &saddr, &one, BPF_ANY);
    }

    // Flow-level packet count
    struct flow_key_t flow_key = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .proto = ip->protocol,
    };

    __u64 *flow_cnt = bpf_map_lookup_elem(&flow_pkt_count_map, &flow_key);
    if (flow_cnt)
        __sync_fetch_and_add(flow_cnt, 1);
    else
        bpf_map_update_elem(&flow_pkt_count_map, &flow_key, &one, BPF_ANY);

    // Emit event to user-space
    struct data_t evt = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .tcp_flags = flags,
        .pkt_len = pkt_len,
        .timestamp = bpf_ktime_get_ns()
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
