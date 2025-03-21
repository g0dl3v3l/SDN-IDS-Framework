#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1024,
};

SEC("classifier")
int monitor_packets(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, sizeof(struct ethhdr));
    if (!eth) return 0;

    struct iphdr *ip = bpf_hdr_pointer(skb, sizeof(struct iphdr));
    if (!ip) return 0;

    u32 src_ip = ip->saddr;
    u32 *count = bpf_map_lookup_elem(&packet_count, &src_ip);
    u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&packet_count, &src_ip, &new_count, BPF_ANY);

    return BPF_OK;
}
