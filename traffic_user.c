// traffic_user.c
// Compile: clang -O2 -g traffic_user.c -o traffic_user -lbpf -lelf

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int running = 1;
void handle_sigint(int sig) { (void)sig; running = 0; }

struct key_t {
    uint8_t proto;
    uint8_t family;      // 4 = IPv4, 6 = IPv6
    uint16_t sport;
    uint16_t dport;
    uint8_t saddr[16];
    uint8_t daddr[16];
} __attribute__((packed));

struct val_t {
    uint64_t packets;
    uint64_t bytes;
    uint64_t last_seen_ns;
} __attribute__((aligned(8)));

typedef struct {
    uint64_t cnt;
    uint64_t bytes;
    struct key_t key;
} entry_t;

#define MAX_ENTRIES_LIMIT 65536
#define SCAN_THRESHOLD 50

static const char *default_iface = "eth0";

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-i iface] [-t interval] [-n top]\n", prog);
    exit(1);
}

int create_and_bind_raw_socket(const char *ifname) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return -1; }

    struct sockaddr_ll sll = { .sll_family = AF_PACKET };
    sll.sll_ifindex = if_nametoindex(ifname);
    if (sll.sll_ifindex == 0) {
        fprintf(stderr, "if_nametoindex failed for %s\n", ifname);
        close(sock); return -1;
    }
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); close(sock); return -1;
    }
    return sock;
}

static int cmp_entries(const void *a, const void *b) {
    const entry_t *ea = a, *eb = b;
    return (ea->cnt < eb->cnt) - (ea->cnt > eb->cnt);
}

static const char *proto_name(uint8_t proto) {
    switch (proto) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 1: return "ICMP";
        case 58: return "ICMPv6";
        default: return "OTHER";
    }
}

static void format_ip(char *buf, size_t len, const struct key_t *key, int is_src) {
    const void *addr = is_src ? key->saddr : key->daddr;
    if (key->family == 4)
        inet_ntop(AF_INET, (uint8_t *)addr + 12, buf, len); // IPv4 stored right-aligned
    else if (key->family == 6)
        inet_ntop(AF_INET6, addr, buf, len);
    else
        snprintf(buf, len, "?");
}

int main(int argc, char **argv) {
    const char *iface = default_iface;
    int interval = 5, topn = 10, opt;

    while ((opt = getopt(argc, argv, "i:t:n:")) != -1) {
        if (opt == 'i') iface = optarg;
        else if (opt == 't') interval = atoi(optarg);
        else if (opt == 'n') topn = atoi(optarg);
        else usage(argv[0]);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Must be run as root\n");
        return 1;
    }

    signal(SIGINT, handle_sigint);
    int sock = create_and_bind_raw_socket(iface);
    if (sock < 0) return 1;

    struct bpf_object *obj = bpf_object__open_file("traffic_kern.o", NULL);
    if (!obj) { fprintf(stderr, "Failed to open BPF object\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "Failed to load BPF object\n"); bpf_object__close(obj); return 1; }

    struct bpf_program *prog;
    int prog_fd = -1;
    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        if (sec && strcmp(sec, "socket") == 0) { prog_fd = bpf_program__fd(prog); break; }
    }
    if (prog_fd < 0) { fprintf(stderr, "No socket section found\n"); return 1; }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        perror("SO_ATTACH_BPF"); return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    if (map_fd < 0) { fprintf(stderr, "Map 'stats' not found\n"); return 1; }

    printf("Attached to %s; interval=%ds; top=%d\n", iface, interval, topn);
    printf("Press Ctrl-C to exit.\n");

    while (running) {
        sleep(interval);
        struct key_t key, next;
        struct val_t val;

        entry_t *arr = calloc(1024, sizeof(entry_t));
        size_t cnt = 0, cap = 1024;

        int res = bpf_map_get_next_key(map_fd, NULL, &key);
        while (res == 0) {
            if (bpf_map_lookup_elem(map_fd, &key, &val) == 0) {
                if (cnt >= cap) {
                    cap *= 2;
                    arr = realloc(arr, cap * sizeof(entry_t));
                }
                arr[cnt].cnt = val.packets;
                arr[cnt].bytes = val.bytes;
                arr[cnt].key = key;
                cnt++;
            }
            res = bpf_map_get_next_key(map_fd, &key, &next);
            key = next;
        }

        if (cnt == 0) { free(arr); continue; }

        qsort(arr, cnt, sizeof(entry_t), cmp_entries);

        uint64_t total_pkts = 0;
        for (size_t i = 0; i < cnt; ++i) total_pkts += arr[i].cnt;

        for (size_t i = 0; i < (size_t)topn && i < cnt; ++i) {
            char s_ip[INET6_ADDRSTRLEN], d_ip[INET6_ADDRSTRLEN];
            format_ip(s_ip, sizeof(s_ip), &arr[i].key, 1);
            format_ip(d_ip, sizeof(d_ip), &arr[i].key, 0);

            const char *pname = proto_name(arr[i].key.proto);
            double pps = (double)arr[i].cnt / interval;
            double bps = (double)arr[i].bytes / interval;
            double pct = total_pkts ? ((double)arr[i].cnt * 100.0 / total_pkts) : 0.0;

            printf("{\"src\":\"%s\",\"dst\":\"%s\",\"proto\":\"%s\",\"sport\":%u,\"dport\":%u,"
                   "\"pkts\":%llu,\"bytes\":%llu,\"pps\":%.2f,\"bps\":%.2f,\"pct\":%.2f}\n",
                   s_ip, d_ip, pname, ntohs(arr[i].key.sport), ntohs(arr[i].key.dport),
                   (unsigned long long)arr[i].cnt, (unsigned long long)arr[i].bytes,
                   pps, bps, pct);
        }
        fflush(stdout);

        // clear map
        struct key_t ktmp, knext;
        int r = bpf_map_get_next_key(map_fd, NULL, &ktmp);
        while (r == 0) {
            bpf_map_delete_elem(map_fd, &ktmp);
            r = bpf_map_get_next_key(map_fd, &ktmp, &knext);
            if (r == 0) ktmp = knext;
        }

        free(arr);
    }

    setsockopt(sock, SOL_SOCKET, SO_DETACH_BPF, &prog_fd, sizeof(prog_fd));
    bpf_object__close(obj);
    close(sock);
    return 0;
}
