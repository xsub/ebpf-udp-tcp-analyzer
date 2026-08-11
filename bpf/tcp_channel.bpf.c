// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

struct tcp_channel_key {
    __u64 socket_cookie;
    __u32 src_ip4;
    __u32 dst_ip4;
    __u16 src_port;
    __u16 dst_port;
    __u8 family;
    __u8 ip_proto;
    __u16 pad;
    __u64 cgroup_id;
};

struct tcp_channel_value {
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_calls;
    __u64 rx_calls;
    __u64 connections;
    __u64 start_ns;
    __u64 last_ns;
    __u32 pid;
    __u32 ifindex;
    __u32 state;
    __u32 pad;
};

/* LRU, not a plain hash: nothing ever DELETES entries here (no hook fires
 * reliably at close for our key, and userspace only reads). The hooks see
 * every TCP socket on the host, so with a plain PERCPU_HASH each reconnect
 * (new cookie + source port) is a permanent entry; at 65536 the map fills
 * and bpf_map_update_elem(BPF_NOEXIST) starts failing SILENTLY — new
 * streams simply stop being counted, with no error anywhere. That exact
 * failure mode is why udp_ingress grew a drops map. LRU evicts the oldest
 * dead flows instead, so long-lived streams keep their counters and new
 * ones are always admitted. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tcp_channel_key);
    __type(value, struct tcp_channel_value);
} tcp_channel_flows SEC(".maps");

static __always_inline int fill_tcp_key(struct sock *sk, struct tcp_channel_key *key)
{
    __u16 dport;

    if (!sk)
        return -1;
    if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
        return -1;

    __builtin_memset(key, 0, sizeof(*key));
    key->socket_cookie = bpf_get_socket_cookie(sk);
    if (!key->socket_cookie)
        return -1;

    dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key->src_ip4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key->dst_ip4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key->dst_port = bpf_ntohs(dport);
    key->family = AF_INET;
    key->ip_proto = IPPROTO_TCP;
    key->cgroup_id = bpf_get_current_cgroup_id();
    if (!key->src_port || !key->dst_port || !key->dst_ip4)
        return -1;
    return 0;
}

static __always_inline int account_tcp_flow(
    struct sock *sk,
    __u64 tx_bytes,
    __u64 rx_bytes,
    __u64 tx_calls,
    __u64 rx_calls,
    __u64 connections,
    __u32 state)
{
    struct tcp_channel_key key = {};
    struct tcp_channel_value zero = {};
    struct tcp_channel_value *value;
    __u64 now = bpf_ktime_get_ns();

    if (fill_tcp_key(sk, &key) < 0)
        return 0;

    zero.start_ns = now;
    zero.last_ns = now;
    zero.pid = bpf_get_current_pid_tgid() >> 32;
    zero.ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
    zero.state = state;

    value = bpf_map_lookup_elem(&tcp_channel_flows, &key);
    if (!value) {
        bpf_map_update_elem(&tcp_channel_flows, &key, &zero, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&tcp_channel_flows, &key);
        if (!value)
            return 0;
    }

    value->tx_bytes += tx_bytes;
    value->rx_bytes += rx_bytes;
    value->tx_calls += tx_calls;
    value->rx_calls += rx_calls;
    value->connections += connections;
    if (!value->start_ns)
        value->start_ns = now;
    value->last_ns = now;
    if (!value->pid)
        value->pid = zero.pid;
    if (!value->ifindex)
        value->ifindex = zero.ifindex;
    if (state)
        value->state = state;
    return 0;
}

static __always_inline int update_tcp_state(struct sock *sk, __u32 state)
{
    struct tcp_channel_key key = {};
    struct tcp_channel_value *value;

    if (fill_tcp_key(sk, &key) < 0)
        return 0;

    value = bpf_map_lookup_elem(&tcp_channel_flows, &key);
    if (!value)
        return 0;

    value->last_ns = bpf_ktime_get_ns();
    value->state = state;
    return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(tcp_v4_connect_exit,
             struct sock *sk,
             struct sockaddr *uaddr,
             int addr_len,
             int ret)
{
    (void)uaddr;
    (void)addr_len;
    if (ret == 0)
        return account_tcp_flow(sk, 0, 0, 0, 0, 1, 0);
    return 0;
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_exit,
             struct sock *sk,
             struct msghdr *msg,
             size_t size,
             int ret)
{
    (void)msg;
    (void)size;
    if (ret > 0)
        return account_tcp_flow(sk, (__u64)ret, 0, 1, 0, 0, 0);
    return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_exit,
             struct sock *sk,
             struct msghdr *msg,
             size_t len,
             int flags,
             int *addr_len,
             int ret)
{
    (void)msg;
    (void)len;
    (void)flags;
    (void)addr_len;
    if (ret > 0)
        return account_tcp_flow(sk, 0, (__u64)ret, 0, 1, 0, 0);
    return 0;
}

SEC("fentry/tcp_set_state")
int BPF_PROG(tcp_set_state_entry, struct sock *sk, int state)
{
    return update_tcp_state(sk, (__u32)state);
}

char LICENSE[] SEC("license") = "GPL";
