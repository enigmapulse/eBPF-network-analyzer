// traffic_kern.c
// Compile target: clang -O2 -g -target bpf -c traffic_kern.c -o traffic_kern.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // for bpf_ntohs / bpf_htons if needed
#include <linux/if_ether.h>
#include <linux/ip.h>

struct key_t {
    __u8 proto;
    __u8 pad;
    __u16 dport;    // network byte order as loaded from packet
    __u8 daddr[4];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct key_t);
    __type(value, __u64);
} stats SEC(".maps");

SEC("socket")
int packet_filter(struct __sk_buff *skb)
{
    // read ethertype (bytes 12-13)
    __u8 eth12 = 0, eth13 = 0;
    if (bpf_skb_load_bytes(skb, 12, &eth12, 1) < 0) return 0;
    if (bpf_skb_load_bytes(skb, 13, &eth13, 1) < 0) return 0;

    // accept only IPv4 (0x0800) or IPv6 (0x86DD) -- we'll handle IPv4 only below
    if (!((eth12 == 0x08 && eth13 == 0x00) || (eth12 == 0x86 && eth13 == 0xdd)))
        return 0;

    // read first byte of IP header (version + IHL)
    __u8 ihl = 0;
    if (bpf_skb_load_bytes(skb, 14, &ihl, 1) < 0) return 0;

    // read protocol (IP header byte offset 9)
    __u8 proto = 0;
    if (bpf_skb_load_bytes(skb, 14 + 9, &proto, 1) < 0) return 0;

    struct key_t key = {};
    key.proto = proto;

    // Only handle IPv4 for extracting IPv4 addresses (EtherType 0x0800)
    if (eth12 == 0x08 && eth13 == 0x00) {
        // destination IP at IP header offset 16 (i.e., frame offset 14 + 16)
        if (bpf_skb_load_bytes(skb, 14 + 16, &key.daddr, 4) < 0) return 0;
    } else {
        // For IPv6 we'd need different parsing; skip for now
        return 0;
    }

    // if TCP or UDP, load destination port
    if (proto == 6 || proto == 17) {
        __u8 ip_hdr_len = (ihl & 0x0f) * 4; // IHL in 32-bit words -> bytes
        __u32 port_off = 14 + ip_hdr_len + 2; // dest port is +2 within transport header
        __u16 dport = 0;
        if (bpf_skb_load_bytes(skb, port_off, &dport, 2) < 0) {
            key.dport = 0;
        } else {
            key.dport = dport; // keep in network order; userspace will ntohs()
        }
    } else {
        key.dport = 0;
    }

    __u64 zero = 0;
    __u64 *val = bpf_map_lookup_elem(&stats, &key);
    if (!val) {
        // insert initial zero, then lookup again
        bpf_map_update_elem(&stats, &key, &zero, BPF_ANY);
        val = bpf_map_lookup_elem(&stats, &key);
        if (!val) return 0;
    }
    // atomic increment
    __sync_fetch_and_add(val, 1ULL);

    // For socket filter, returning 0 is fine (we're not trying to redirect/capture bytes)
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
