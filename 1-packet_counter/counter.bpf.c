// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define IPPROTO_TCP 6

struct ip_key {
    __u8 ip_version;       // 4 or 6
    union {
        __u32 ipv4;
        __u8 ipv6[16];
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ip_key);   // Source IP Address
    __type(value, __u64);         // Packet Count
} tcp_pkt_count SEC(".maps");

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    struct ip_key key = {};
    __u64 *count;

    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        if (ip->protocol != IPPROTO_TCP)
            return TC_ACT_OK;

        key.ip_version = 4;
        key.ipv4 = ip->saddr;
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;

        if (ip6->nexthdr != IPPROTO_TCP)
            return TC_ACT_OK;

        key.ip_version = 6;
        __builtin_memcpy(key.ipv6, ip6->saddr.s6_addr, 16);
    } else {
        return TC_ACT_OK;
    }

    count = bpf_map_lookup_elem(&tcp_pkt_count, &key);
if (count) {
    __sync_fetch_and_add(count, 1);
} else {
    __u64 initial = 1;
    bpf_map_update_elem(&tcp_pkt_count, &key, &initial, BPF_ANY);
}

// Logging with IP address
if (key.ip_version == 4) {
    __be32 ip = key.ipv4;
    bpf_printk("IPv4 TCP packet from %pI4, total count: %llu\n", &ip, count ? *count + 1 : 1);
} else if (key.ip_version == 6) {
    bpf_printk("IPv6 TCP packet from %pI6, total count: %llu\n", key.ipv6, count ? *count + 1 : 1);
}
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
