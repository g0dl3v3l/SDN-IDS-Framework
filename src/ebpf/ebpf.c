#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct data_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);  // Must match number of CPUs or more
} events SEC(".maps");


// XDP program to monitor TCP packets
SEC("xdp")
int xdp_monitor_tcp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // TCP header
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Fill out packet data
    struct data_t pkt_data = {};
    pkt_data.saddr = ip->saddr;
    pkt_data.daddr = ip->daddr;
    pkt_data.sport = bpf_ntohs(tcp->source);
    pkt_data.dport = bpf_ntohs(tcp->dest);

    // Emit event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pkt_data, sizeof(pkt_data));

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
