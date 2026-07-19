// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

struct delivered_key {
    __u64 socket_cookie;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u16 src_port;
    __u16 dst_port;
    __u8 family;
    __u8 ip_proto;
    __u16 pad;
};

struct delivered_value {
    __u64 packets;
    __u64 bytes;
    __u64 socket_inode;
    __u32 ifindex;
    __u32 pad;
};

struct fallback_socket_key {
    __u64 socket_address;
    __u64 socket_inode;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct delivered_key);
    __type(value, struct delivered_value);
} udp_delivered_counters SEC(".maps");

/* A kprobe program cannot call bpf_get_socket_cookie(). Keep a private cookie
 * for the selected struct sock instead. The kernel address never leaves this
 * map; delivered rows contain only the generated cookie. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fallback_socket_key);
    __type(value, __u64);
} udp_kprobe_cookies SEC(".maps");

static __always_inline __u64 socket_inode(struct sock *sk)
{
    struct socket *socket;
    struct file *file;
    struct inode *inode;

    socket = BPF_CORE_READ(sk, sk_socket);
    if (!socket)
        return 0;
    file = BPF_CORE_READ(socket, file);
    if (!file)
        return 0;
    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    return BPF_CORE_READ(inode, i_ino);
}

static __always_inline __u32 ingress_ifindex(struct sk_buff *skb)
{
    struct net_device *dev;
    __u32 ifindex = BPF_CORE_READ(skb, skb_iif);

    if (ifindex)
        return ifindex;
    dev = BPF_CORE_READ(skb, dev);
    return dev ? BPF_CORE_READ(dev, ifindex) : 0;
}

static __always_inline __u64 kprobe_socket_cookie(struct sock *sk, __u64 inode)
{
    struct fallback_socket_key key = {
        .socket_address = (__u64)(unsigned long)sk,
        .socket_inode = inode,
    };
    __u64 candidate;
    __u64 *cookie;

    cookie = bpf_map_lookup_elem(&udp_kprobe_cookies, &key);
    if (cookie)
        return *cookie;

    candidate = ((__u64)bpf_get_prandom_u32() << 32) |
                bpf_get_prandom_u32();
    candidate ^= bpf_ktime_get_ns();
    candidate |= 1;
    bpf_map_update_elem(&udp_kprobe_cookies, &key, &candidate, BPF_NOEXIST);
    cookie = bpf_map_lookup_elem(&udp_kprobe_cookies, &key);
    return cookie ? *cookie : 0;
}

static __always_inline int account_udp_delivery(
    struct sock *sk, struct sk_buff *skb, __u64 cookie, __u64 inode)
{
    unsigned char *head;
    __u16 network_header;
    __u16 transport_header;
    struct iphdr ip = {};
    struct udphdr udp = {};
    struct delivered_key key = {};
    struct delivered_value zero = {};
    struct delivered_value *value;
    __u16 udp_len;

    if (!sk || !skb)
        return 0;
    if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
        return 0;

    head = BPF_CORE_READ(skb, head);
    network_header = BPF_CORE_READ(skb, network_header);
    transport_header = BPF_CORE_READ(skb, transport_header);
    if (!head)
        return 0;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) < 0)
        return 0;
    if (ip.version != 4 || ip.protocol != IPPROTO_UDP)
        return 0;
    if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) < 0)
        return 0;

    key.socket_cookie = cookie;
    if (!key.socket_cookie)
        return 0;
    key.src_ip4 = ip.saddr;
    key.dst_ip4 = ip.daddr;
    key.src_port = bpf_ntohs(udp.source);
    key.dst_port = bpf_ntohs(udp.dest);
    key.family = AF_INET;
    key.ip_proto = IPPROTO_UDP;

    zero.socket_inode = inode;
    zero.ifindex = ingress_ifindex(skb);
    value = bpf_map_lookup_elem(&udp_delivered_counters, &key);
    if (!value) {
        bpf_map_update_elem(&udp_delivered_counters, &key, &zero, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&udp_delivered_counters, &key);
        if (!value)
            return 0;
    }

    udp_len = bpf_ntohs(udp.len);
    value->packets += 1;
    if (udp_len >= sizeof(udp))
        value->bytes += udp_len - sizeof(udp);
    if (!value->socket_inode)
        value->socket_inode = zero.socket_inode;
    if (!value->ifindex)
        value->ifindex = zero.ifindex;
    return 0;
}

SEC("fentry/udp_queue_rcv_skb")
int BPF_PROG(udp_recv_fentry, struct sock *sk, struct sk_buff *skb)
{
    return account_udp_delivery(
        sk, skb, bpf_get_socket_cookie(sk), socket_inode(sk));
}

SEC("kprobe/udp_queue_rcv_skb")
int BPF_KPROBE(udp_recv_kprobe, struct sock *sk, struct sk_buff *skb)
{
    __u64 inode = socket_inode(sk);

    return account_udp_delivery(sk, skb, kprobe_socket_cookie(sk, inode), inode);
}

char LICENSE[] SEC("license") = "GPL";
