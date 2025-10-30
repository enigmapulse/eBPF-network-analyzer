// traffic_kern.c
// Compile: clang -O2 -g -target bpf -c traffic_kern.c -o traffic_kern.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct key_t {
    __u8 proto;
    __u8 family;      // 4 = IPv4, 6 = IPv6
    __u16 sport;      // network order
    __u16 dport;      // network order
    __u8 saddr[16];   // support both IPv4 & IPv6
    __u8 daddr[16];
} __attribute__((packed));

struct val_t {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
} __attribute__((aligned(8)));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct key_t);
    __type(value, struct val_t);
} stats SEC(".maps");

SEC("socket")
int packet_filter(struct __sk_buff *skb)
{
    __u8 eth12 = 0, eth13 = 0;
    if (bpf_skb_load_bytes(skb, 12, &eth12, 1) < 0) return 0;
    if (bpf_skb_load_bytes(skb, 13, &eth13, 1) < 0) return 0;

    __u16 eth_type = ((__u16)eth12 << 8) | eth13;

    struct key_t key = {};
    __u8 proto = 0;
    __u32 l4_off = 0;

    if (eth_type == 0x0800) {
        // IPv4
        key.family = 4;

        __u8 ihl = 0;
        if (bpf_skb_load_bytes(skb, 14, &ihl, 1) < 0) return 0;
        if (bpf_skb_load_bytes(skb, 14 + 9, &proto, 1) < 0) return 0;

        key.proto = proto;
        if (bpf_skb_load_bytes(skb, 14 + 12, &key.saddr[12], 4) < 0) return 0; // right align in 16 bytes
        if (bpf_skb_load_bytes(skb, 14 + 16, &key.daddr[12], 4) < 0) return 0;

        __u8 ip_hdr_len = (ihl & 0x0F) * 4;
        l4_off = 14 + ip_hdr_len;

    } else if (eth_type == 0x86DD) {
        // IPv6
        key.family = 6;

        if (bpf_skb_load_bytes(skb, 14 + offsetof(struct ipv6hdr, nexthdr), &proto, 1) < 0)
            return 0;
        key.proto = proto;

        if (bpf_skb_load_bytes(skb, 14 + offsetof(struct ipv6hdr, saddr), key.saddr, 16) < 0)
            return 0;
        if (bpf_skb_load_bytes(skb, 14 + offsetof(struct ipv6hdr, daddr), key.daddr, 16) < 0)
            return 0;

        l4_off = 14 + sizeof(struct ipv6hdr);
    } else {
        // non-IP traffic
        return 0;
    }

    if (proto == 6 || proto == 17) { // TCP or UDP
        __u16 sport = 0, dport = 0;
        if (bpf_skb_load_bytes(skb, l4_off, &sport, 2) < 0) return 0;
        if (bpf_skb_load_bytes(skb, l4_off + 2, &dport, 2) < 0) return 0;
        key.sport = sport;
        key.dport = dport;
    } else {
        key.sport = 0;
        key.dport = 0;
    }

    struct val_t zero = {};
    struct val_t *v = bpf_map_lookup_elem(&stats, &key);
    if (!v) {
        bpf_map_update_elem(&stats, &key, &zero, BPF_ANY);
        v = bpf_map_lookup_elem(&stats, &key);
        if (!v) return 0;
    }

    __sync_fetch_and_add(&v->packets, 1ULL);
    __sync_fetch_and_add(&v->bytes, (__u64)skb->len);
    v->last_seen_ns = bpf_ktime_get_ns();

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
