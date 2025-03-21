#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h> // For XDP flags

#define PERF_BUFFER_PAGES 64

static volatile bool exiting = false;

struct data_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct data_t *event = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &event->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &event->daddr, dst_ip, sizeof(dst_ip));

    printf("TCP packet: %s:%d → %s:%d\n", src_ip, event->sport, dst_ip, event->dport);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static void sig_handler(int sig) {
    exiting = true;
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    struct perf_buffer *pb = NULL;

    const char *iface = "s1-eth4"; // change as needed
    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("Invalid interface");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file("xdp_prog.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_monitor_tcp");
    if (!prog) {
        fprintf(stderr, "Program 'xdp_monitor_tcp' not found\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        return 1;
    }

    // ✅ Attach using bpf_xdp_attach instead of libxdp
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL) < 0) {
        perror("Failed to attach XDP program");
        return 1;
    }

    map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "Map 'events' not found\n");
        return 1;
    }

    int map_fd = bpf_map__fd(map);
    pb = perf_buffer__new(map_fd, PERF_BUFFER_PAGES, handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer\n");
        return 1;
    }

    printf("✅ Listening for TCP packets on %s... Press Ctrl+C to exit\n", iface);
    while (!exiting) {
        perf_buffer__poll(pb, 100);
    }

    printf("Detaching...\n");
    bpf_xdp_attach(ifindex, -1, XDP_FLAGS_DRV_MODE, NULL);
    perf_buffer__free(pb);
    bpf_object__close(obj);
    return 0;
}
