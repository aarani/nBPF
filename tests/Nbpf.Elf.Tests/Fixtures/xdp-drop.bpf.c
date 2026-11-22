// Fixture for the XDP tests: drops UDP datagrams to one fixed port (PORT_TO_BLOCK)
// and counts them in a one-slot array map; everything else passes.
// Self-contained like the other fixtures: no vmlinux.h, no kernel headers.
// Regenerate with eng/gen-fixtures.sh — do not edit xdp-drop.bpf.o by hand. It is built
// with -mcpu=v2 so the counter increment stays a plain atomic add that 5.4 accepts.
//
// The parser walks Ethernet, up to two VLAN tags (802.1Q / 802.1ad), IPv4 with a
// variable header length, then UDP, bounds-checking against data_end before every
// header — the verifier rejects any packet read it can't prove is in range. Anything
// it doesn't understand (other EtherTypes, non-UDP, non-first fragments, truncated
// packets) is passed, never dropped.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

enum bpf_map_type
{
    BPF_MAP_TYPE_ARRAY = 2
};

struct xdp_md
{
    u32 data;
    u32 data_end;
};

#define ETH_ALEN 6 // octets in one Ethernet address

struct ethhdr
{
    unsigned char h_dest[ETH_ALEN];   // destination address
    unsigned char h_source[ETH_ALEN]; // source address
    unsigned short h_proto;           // EtherType, network byte order
};

struct iphdr
{
    // Bitfield order follows the target's byte order: the first declared field takes
    // the low bits, so on little-endian ihl must come first to land in the low nibble.
#if defined(__LITTLE_ENDIAN__)
    unsigned char ihl : 4,
        version : 4;
#elif defined(__BIG_ENDIAN__)
    unsigned char version : 4,
        ihl : 4;
#else
#error "unknown target byte order: neither __LITTLE_ENDIAN__ nor __BIG_ENDIAN__ is defined"
#endif
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

struct vlanhdr
{
    unsigned short tci;                // priority, DEI, VLAN id
    unsigned short encapsulated_proto; // the real EtherType
};

struct udphdr
{
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

enum xdp_action
{
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
};

// Helpers are ordinary function pointers at fixed helper ids, exactly as
// bpf_helper_defs.h declares them.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

#define ETH_P_8021Q 0x8100  // 802.1Q
#define ETH_P_8021AD 0x88A8 // 802.1ad (QinQ outer tag)
#define VLAN_MAX_DEPTH 2    // covers QinQ
#define ETH_P_IP 0x0800     // IPv4

#define PORT_TO_BLOCK 13131

struct
{
    int (*type)[2]; // BPF_MAP_TYPE_ARRAY
    u32 *key;
    u64 *value;
    int (*max_entries)[1];
} output_map __attribute__((section(".maps"), used));

__attribute__((section("xdp"), used)) int xdp_bad_udp(struct xdp_md *ctx)
{
    // Parse Ethernet Protocol
    struct ethhdr *eth = (struct ethhdr *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    void *cursor = (void *)(eth + 1);
    if (cursor > data_end) // bounds check, every hop
        return XDP_PASS;

    unsigned short proto = eth->h_proto; // still network byte order

#pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++)
    {
        if (proto != __builtin_bswap16(ETH_P_8021Q) &&
            proto != __builtin_bswap16(ETH_P_8021AD))
            break;
        struct vlanhdr *vh = cursor;
        if ((void *)(vh + 1) > data_end) // bounds check, every hop
            return XDP_PASS;
        proto = vh->encapsulated_proto;
        cursor = vh + 1;
    }
    if (proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;
    struct iphdr *ip = cursor;       // continue as before, from cursor
    if ((void *)(ip + 1) > data_end) // bounds check, every hop
        return XDP_PASS;
    if (ip->frag_off & __builtin_bswap16(0x1FFF)) // non-zero fragment offset
        return XDP_PASS;
    if (ip->ihl < 5) // invalid header length
        return XDP_PASS;
    if (ip->protocol != 17) // not UDP
        return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)((void *)ip + ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) // bounds check, every hop
        return XDP_PASS;

    if (__builtin_bswap16(PORT_TO_BLOCK) == udp->dest) // UDP dest port
    {
        int key = 0;
        void *value = bpf_map_lookup_elem(&output_map, &key);
        if (value != 0)
        {
            __sync_fetch_and_add((long long *)value, 1);
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
