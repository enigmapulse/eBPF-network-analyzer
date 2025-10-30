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

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// same as the kernel struct
struct key_t {
    uint8_t proto;
    uint8_t pad;
    uint16_t dport;   
    uint8_t daddr[4];
} __attribute__((packed));

// each entry here constitutes count of packets and their metadata
typedef struct {
    uint64_t cnt;
    struct key_t k;
} entry_t;

// default interface to connect to
static const char *default_iface = "eth0";

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-i iface] [-t interval] [-n top]\n", prog);
    exit(1);
}

int create_and_bind_raw_socket(const char *ifname) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_ll sll = {.sll_family = AF_PACKET};
    sll.sll_ifindex = if_nametoindex(ifname);
    if (sll.sll_ifindex == 0) {
        fprintf(stderr, "if_nametoindex failed for %s\n", ifname);
        close(sock);
        return -1;
    }
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    return sock;
}

// comparison function for qsort
static int cmp(const void *a, const void *b) {
    const entry_t *ea = a;
    const entry_t *eb = b;
    if (ea->cnt < eb->cnt) return 1;
    if (ea->cnt > eb->cnt) return -1;
    return 0;
}

int main(int argc, char **argv) {
    const char *iface = default_iface;
    int interval = 5;
    int topn = 10;
    int opt;

    while ((opt = getopt(argc, argv, "i:t:n:")) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 't': interval = atoi(optarg); break;
        case 'n': topn = atoi(optarg); break;
        default: usage(argv[0]);
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        return 1;
    }

    int sock = create_and_bind_raw_socket(iface);
    if (sock < 0) return 1;

    // loading the bpf object
    struct bpf_object *obj = bpf_object__open_file("traffic_kern.o", NULL);

    // error handling for object opening and loading
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        close(sock);
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        close(sock);
        return 1;
    }

    struct bpf_program *prog = NULL;
    int prog_fd = -1;

    // finds the section named socket and get its file descriptor
    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        if (sec && strcmp(sec, "socket") == 0) {
            prog_fd = bpf_program__fd(prog);
            break;
        }
    }

    if (prog_fd < 0) {
        fprintf(stderr, "Failed to find socket program in object\n");
        bpf_object__close(obj);
        close(sock);
        return 1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        perror("setsockopt(SO_ATTACH_BPF)");
        bpf_object__close(obj);
        close(sock);
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        setsockopt(sock, SOL_SOCKET, SO_DETACH_BPF, &prog_fd, sizeof(prog_fd));
        bpf_object__close(obj);
        close(sock);
        return 1;
    }

    printf("Attached to %s; interval=%ds; top=%d\n", iface, interval, topn);
    printf("Press Ctrl-C to exit.\n");

    while (1) {
        sleep(interval);

        struct key_t key, next;
        uint64_t value;
        size_t cap = 256, cnt = 0;
        entry_t *arr = malloc(cap * sizeof(entry_t));
        if (!arr) {
            perror("malloc");
            break;
        }

        int res = bpf_map_get_next_key(map_fd, NULL, &key);
        while (res == 0) {
            if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
                if (cnt >= cap) {
                    cap *= 2;
                    entry_t *tmp = realloc(arr, cap * sizeof(entry_t));
                    if (!tmp) { perror("realloc"); free(arr); arr = NULL; break; }
                    arr = tmp;
                }
                arr[cnt].cnt = value;
                arr[cnt].k = key;
                cnt++;
            }
            res = bpf_map_get_next_key(map_fd, &key, &next);
            if (res == 0) key = next;
        }

        if (!arr) continue; // realloc failed
        if (cnt == 0) {
            printf("[no traffic captured in last interval]\n");
        } else {
            qsort(arr, cnt, sizeof(entry_t), cmp);

            for (size_t i = 0; i < (size_t)topn && i < cnt; ++i) {
                char ipbuf[INET_ADDRSTRLEN];
                snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                        arr[i].k.daddr[0], arr[i].k.daddr[1],
                        arr[i].k.daddr[2], arr[i].k.daddr[3]);
                const char *pname = (arr[i].k.proto == 6 ? "TCP" :
                                    (arr[i].k.proto == 17 ? "UDP" : "-"));
                printf("{\"cnt\":%llu,\"proto\":\"%s\",\"ip\":\"%s\",\"dport\":%u}\n",
                    (unsigned long long)arr[i].cnt,
                    pname,
                    ipbuf,
                    ntohs(arr[i].k.dport));
            }
            fflush(stdout);

            // printf("%-10s %-6s %-18s %-6s\n", "COUNT", "PROTO", "DEST_IP", "DPORT");
            // for (size_t i = 0; i < (size_t)topn && i < cnt; ++i) {
            //     char ipbuf[INET_ADDRSTRLEN] = {0};
            //     snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
            //              arr[i].k.daddr[0], arr[i].k.daddr[1],
            //              arr[i].k.daddr[2], arr[i].k.daddr[3]);
            //     const char *pname = (arr[i].k.proto == 6 ? "TCP" :
            //                         (arr[i].k.proto == 17 ? "UDP" : "-"));
            //     printf("%-10llu %-6s %-18s %-6u\n",
            //            (unsigned long long)arr[i].cnt,
            //            pname,
            //            ipbuf,
            //            ntohs(arr[i].k.dport));
            // }
        }

        // Clear map
        struct key_t ktmp, knext;
        int r = bpf_map_get_next_key(map_fd, NULL, &ktmp);
        while (r == 0) {
            bpf_map_delete_elem(map_fd, &ktmp);
            r = bpf_map_get_next_key(map_fd, &ktmp, &knext);
            if (r == 0) ktmp = knext;
        }

        // printf("------------------------------------------------------------\n");
        free(arr);
    }

    setsockopt(sock, SOL_SOCKET, SO_DETACH_BPF, &prog_fd, sizeof(prog_fd));
    bpf_object__close(obj);
    close(sock);
    return 0;
}
