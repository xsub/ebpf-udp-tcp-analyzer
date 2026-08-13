// SPDX-License-Identifier: GPL-2.0
//
// Atrybucja UDP per-cgroup (multicast TV) — bliźniak tcp_channel.bpf.c, z trzema
// świadomymi różnicami:
//   1) JEDEN hook: fexit/udp_recvmsg (RX-only). Biegnie w kontekście PROCESU
//      (syscall recvmsg wątku ffmpega), więc bpf_get_current_cgroup_id()/pid_tgid()
//      zwracają WŁAŚCICIELA gniazda — nie kopiujemy softirq-owego udp_receive.
//   2) Guard ROZLUŹNIONY: multicast RX nie robi connect(), więc skc_daddr==0
//      (dst puste). Wymagamy tylko socket_cookie + AF_INET + src_port (port bind =
//      port kanału). Tcp-owy guard `!dst_ip4 || !dst_port` skasowałby cały multicast.
//   3) Guardy MSG_PEEK / MSG_ERRQUEUE: peek zwraca bajty, ale NIE konsumuje
//      datagramu (policzylibyśmy go dwa razy przy realnym odczycie); errqueue to
//      kolejka błędów, nie ruch. tcp_recvmsg tych guardów NIE ma — to latentny bug,
//      którego tu NIE powielamy.
//
// Layout klucza (32 B) i wartości (72 B) jest IDENTYCZNY z tcp_channel — parser
// struct po stronie Pythona jest re-używany 1:1. Pola tx_*/connections/state dla UDP
// zostają 0 (RX-only), sloty zachowane dla zgodności layoutu.
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

#ifndef MSG_PEEK
#define MSG_PEEK 2
#endif

#ifndef MSG_ERRQUEUE
#define MSG_ERRQUEUE 0x2000
#endif

struct udp_channel_key {
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

struct udp_channel_value {
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

/* LRU, jak w tcp_channel: nic nie KASUJE wpisów (brak pewnego hooka na close, a
 * userspace tylko czyta). Hook widzi KAŻDE gniazdo UDP hosta (churny DNS itd.), więc
 * plain PERCPU_HASH zapełniłby się i BPF_NOEXIST zacząłby po cichu odrzucać nowe
 * strumienie. LRU eksmituje najstarsze martwe wpisy — długie strumienie trzymają
 * liczniki, nowe zawsze wchodzą. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct udp_channel_key);
    __type(value, struct udp_channel_value);
} udp_channel_flows SEC(".maps");

static __always_inline int fill_udp_key(struct sock *sk, struct udp_channel_key *key)
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
    key->src_ip4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);  /* bind: grupa 239.x lub 0 */
    key->dst_ip4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);      /* 0 dla multicast bez connect */
    key->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);       /* bind port = port kanału */
    key->dst_port = bpf_ntohs(dport);                            /* 0 dla multicast bez connect */
    key->family = AF_INET;
    key->ip_proto = IPPROTO_UDP;
    key->cgroup_id = bpf_get_current_cgroup_id();                /* POPRAWNE: kontekst procesu */

    /* DIFF vs TCP: NIE wymagamy dst (multicast dst==0). Sam bind-port wystarcza —
     * atrybucja i tak idzie przez cgroup->unit, a endpoint do matchu userspace
     * bierze z bind (src) gdy dst puste. */
    if (!key->src_port)
        return -1;
    return 0;
}

static __always_inline int account_udp_flow(
    struct sock *sk,
    __u64 rx_bytes,
    __u64 rx_calls)
{
    struct udp_channel_key key = {};
    struct udp_channel_value zero = {};
    struct udp_channel_value *value;
    __u64 now = bpf_ktime_get_ns();

    if (fill_udp_key(sk, &key) < 0)
        return 0;

    zero.start_ns = now;
    zero.last_ns = now;
    zero.pid = bpf_get_current_pid_tgid() >> 32;
    zero.ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);

    value = bpf_map_lookup_elem(&udp_channel_flows, &key);
    if (!value) {
        bpf_map_update_elem(&udp_channel_flows, &key, &zero, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&udp_channel_flows, &key);
        if (!value)
            return 0;
    }

    value->rx_bytes += rx_bytes;
    value->rx_calls += rx_calls;
    if (!value->start_ns)
        value->start_ns = now;
    value->last_ns = now;
    if (!value->pid)
        value->pid = zero.pid;
    if (!value->ifindex)
        value->ifindex = zero.ifindex;
    return 0;
}

/* Sygnatura post-5.19: udp_recvmsg(sk, msg, len, flags, addr_len) -> ret.
 * Bramka userspace (refuse_pre519_udp_recvmsg) odrzuca jądra < 5.19, gdzie doszedłby
 * parametr `noblock` i slot `ret` czytałby wskaźnik addr_len (śmieci). */
SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recvmsg_exit,
             struct sock *sk,
             struct msghdr *msg,
             size_t len,
             int flags,
             int *addr_len,
             int ret)
{
    (void)msg;
    (void)len;
    (void)addr_len;

    /* peek nie konsumuje datagramu (policzylibyśmy go dwa razy); errqueue to
     * kolejka błędów, nie realny ruch — patrz nagłówek pliku. */
    if (flags & (MSG_PEEK | MSG_ERRQUEUE))
        return 0;

    /* recvmmsg woła udp_recvmsg RAZ NA DATAGRAM, więc ret = bajty jednego datagramu,
     * a rx_calls rośnie o 1 per datagram — granularność per-datagram za darmo. */
    if (ret > 0)
        return account_udp_flow(sk, (__u64)ret, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
