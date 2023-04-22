#include <linux/if_ether.h> /* for struct ethhdr   */
#include <linux/ip.h>       /* for struct iphdr    */
#include <linux/ipv6.h>     /* for struct ipv6hdr  */
#include <linux/in.h>       /* for IPPROTO_UDP     */
#include <linux/tcp.h>      /* for struct tcphdr   */
#include <linux/udp.h>      /* for struct udphdr   */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define MAX_RULES               8000

#ifdef  DEBUG
# define dd(...)                bpf_printk(__VA_ARGS__)
#else
# define dd(...)
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)    ((void) __sync_fetch_and_add(ptr, val))
#endif

#define memcpy                  __builtin_memcpy


typedef __u8                    uint8_t;
typedef __u16                   uint16_t;
typedef __u32                   uint32_t;
typedef __u64                   uint64_t;


struct vlanhdr {
    uint16_t    tci;
    uint16_t    encap_proto;
};


struct cursor {
    void    *pos;
    void    *end;
};


struct lpm_v4_key {
    struct bpf_lpm_trie_key lpm;
    uint32_t                addr;
};


struct lpm_v6_key {
    struct bpf_lpm_trie_key lpm;
    struct in6_addr         addr;
};


// IPv4 map
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_RULES);
    __type(key, struct lpm_v4_key);
    __type(value, enum xdp_action);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_map SEC(".maps");


// IPv6 map
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_RULES);
    __type(key, struct lpm_v6_key);
    __type(value, enum xdp_action);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv6_map SEC(".maps");


static __always_inline
void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
    c->end = (void *)(long)ctx->data_end;
    c->pos = (void *)(long)ctx->data;
}


#define PARSE_FUNC_DECLARATION(STRUCT)              \
static __always_inline                              \
struct STRUCT *parse_ ## STRUCT (struct cursor *c)  \
{                                                   \
    struct STRUCT *ret = c->pos;                    \
    if (c->pos + sizeof(struct STRUCT) > c->end) {  \
        return NULL;                                \
    }                                               \
    c->pos += sizeof(struct STRUCT);                \
    return ret;                                     \
}


PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)


static __always_inline
struct ethhdr *parse_eth(struct cursor *c, uint16_t *eth_proto)
{
    struct vlanhdr  *vlan;
    struct ethhdr   *eth;

    eth = parse_ethhdr(c);
    if (eth == NULL) {
        return NULL;
    }

    *eth_proto = eth->h_proto;

    if (*eth_proto == bpf_htons(ETH_P_8021Q)
        || *eth_proto == bpf_htons(ETH_P_8021AD))
    {
        vlan = parse_vlanhdr(c);
        if (vlan == NULL) {
            return NULL;
        }

        *eth_proto = vlan->encap_proto;

        if (*eth_proto == bpf_htons(ETH_P_8021Q)
            || *eth_proto == bpf_htons(ETH_P_8021AD))
        {
            vlan = parse_vlanhdr(c);
            if (vlan == NULL) {
                return NULL;
            }

            *eth_proto = vlan->encap_proto;
        }
    }

    return eth;
}


#define LPM_MAP_LOOKUP_FUNC_DECLARATION(NAME, INADDR, LPMKEY)       \
static __always_inline                                              \
enum xdp_action NAME ## _map_lookup_value(void *map, INADDR addr)   \
{                                                                   \
    enum xdp_action     *action;                                    \
    LPMKEY               key;                                       \
    memcpy(key.lpm.data, &addr, sizeof(key.addr));                  \
    key.lpm.prefixlen = sizeof(INADDR) * 8;                         \
    action = bpf_map_lookup_elem(map, &key);                        \
    if (action) {                                                   \
        return *action;                                             \
    }                                                               \
    return XDP_PASS;                                                \
}


LPM_MAP_LOOKUP_FUNC_DECLARATION(ip,  uint32_t,        struct lpm_v4_key)
LPM_MAP_LOOKUP_FUNC_DECLARATION(ip6, struct in6_addr, struct lpm_v6_key)


SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    int                  rc;
    uint16_t             eth_proto;
    struct cursor        c;
    struct ethhdr       *eth;
    struct iphdr        *iph;
    struct ipv6hdr      *ip6h;

    rc = XDP_PASS;

    cursor_init(&c, ctx);

    // eth header
    eth = parse_eth(&c, &eth_proto);
    if (eth == NULL) {
        goto pass;
    }

    // ip header
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        iph = parse_iphdr(&c);
        if (iph == NULL) {
            goto pass;
        }

        rc = ip_map_lookup_value(&ipv4_map, iph->saddr);

    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = parse_ipv6hdr(&c);
        if (ip6h == NULL) {
            goto pass;
        }

        rc = ip6_map_lookup_value(&ipv6_map, ip6h->saddr);
    }

pass:

    return rc;
}


char LICENSE[] SEC("license") = "GPL";
