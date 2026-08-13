import socket
import struct
import unittest
from dataclasses import replace

from udp_analyzer.udp_channel import (
    UdpChannelCollector,
    UdpFlowEntry,
    UdpFlowKey,
    UdpFlowValue,
    kernel_udp_recvmsg_has_noblock,
    parse_udp_channel_loader_status,
    parse_udp_flow_entry,
    parse_udp_flow_key,
)


def _ip4(dotted: str) -> int:
    return struct.unpack("<I", socket.inet_aton(dotted))[0]


class UdpChannelParseTests(unittest.TestCase):
    def test_parse_raw_udp_flow_key_multicast_dst_zero(self):
        # multicast RX: bind = grupa (src), brak connect -> dst==0
        encoded = struct.pack(
            "<QIIHHBB2xQ", 0x1122334455667788,
            _ip4("239.239.16.2"), 0, 1234, 0, 2, 17, 555,
        )
        raw_key = [f"0x{b:02x}" for b in encoded]
        parsed = parse_udp_flow_key(raw_key)
        self.assertEqual(parsed.socket_cookie, 0x1122334455667788)
        self.assertEqual(parsed.src_ip, "239.239.16.2")
        self.assertEqual(parsed.dst_ip, "0.0.0.0")     # dst puste dla multicastu
        self.assertEqual(parsed.src_port, 1234)
        self.assertEqual(parsed.ip_proto, 17)
        self.assertEqual(parsed.cgroup_id, 555)

    def test_rejects_non_udp_key(self):
        with self.assertRaisesRegex(RuntimeError, "non-IPv4-UDP"):
            parse_udp_flow_key({
                "socket_cookie": 1, "src_ip4": _ip4("239.1.1.1"), "dst_ip4": 0,
                "src_port": 1234, "dst_port": 0, "family": 2,
                "ip_proto": 6, "cgroup_id": 7,   # TCP -> odrzucone
            })

    def test_per_cpu_counters_sum(self):
        entry = {
            "key": {"socket_cookie": 1, "src_ip4": _ip4("239.1.1.1"), "dst_ip4": 0,
                    "src_port": 1234, "dst_port": 0, "family": 2, "ip_proto": 17,
                    "cgroup_id": 7},
            "values": [
                {"cpu": 0, "value": {"tx_bytes": 0, "rx_bytes": 1000, "tx_calls": 0,
                    "rx_calls": 4, "connections": 0, "start_ns": 10, "last_ns": 20,
                    "pid": 9, "ifindex": 2, "state": 0}},
                {"cpu": 1, "value": {"tx_bytes": 0, "rx_bytes": 3000, "tx_calls": 0,
                    "rx_calls": 6, "connections": 0, "start_ns": 11, "last_ns": 30,
                    "pid": 9, "ifindex": 2, "state": 0}},
            ],
        }
        p = parse_udp_flow_entry(entry)
        self.assertEqual(p.value.rx_bytes, 4000)
        self.assertEqual(p.value.rx_calls, 10)
        self.assertEqual(p.value.start_ns, 10)
        self.assertEqual(p.value.last_ns, 30)

    def test_loader_status(self):
        self.assertEqual(parse_udp_channel_loader_status('{"map_id":88}').map_id, 88)
        with self.assertRaises(RuntimeError):
            parse_udp_channel_loader_status('{"map_id":0}')


class UdpRecvmsgNoblockGateTests(unittest.TestCase):
    """Bramka pre-5.19 dla UDP: parametr nazywa się 'noblock' (nie 'nonblock')."""

    def test_noblock_marker_by_type_id(self):
        # Wiązanie FUNC->FUNC_PROTO po type_id (jak w żywym BTF 6.8, type_id=52827).
        new = (
            "[52827] FUNC_PROTO '(anon)' ret_type_id=13 vlen=5\n"
            "\t'sk' type_id=700\n\t'msg' type_id=6066\n\t'len' type_id=46\n"
            "\t'flags' type_id=13\n\t'addr_len' type_id=92\n"
            "[85373] FUNC 'udp_recvmsg' type_id=52827 linkage=static\n"
        )
        old = (
            "[52827] FUNC_PROTO '(anon)' ret_type_id=13 vlen=6\n"
            "\t'sk' type_id=700\n\t'msg' type_id=6066\n\t'len' type_id=46\n"
            "\t'noblock' type_id=13\n\t'flags' type_id=13\n\t'addr_len' type_id=92\n"
            "[85373] FUNC 'udp_recvmsg' type_id=52827 linkage=static\n"
        )
        self.assertIs(kernel_udp_recvmsg_has_noblock(btf_text=old), True)
        self.assertIs(kernel_udp_recvmsg_has_noblock(btf_text=new), False)
        self.assertIsNone(kernel_udp_recvmsg_has_noblock(btf_text="[1] INT 'int'"))


class FakeReader:
    def __init__(self):
        self.entries = []

    def dump_entries(self):
        return list(self.entries)


def _mc_entry(cookie, pid, group="239.239.16.2", port=1234, rx=0, rxc=0):
    """Wpis multicast: bind = grupa (src), brak connect (dst==0)."""
    key = UdpFlowKey(socket_cookie=cookie, src_ip4=_ip4(group), dst_ip4=0,
                     src_port=port, dst_port=0, family=2, ip_proto=17, cgroup_id=7)
    value = UdpFlowValue(tx_bytes=0, rx_bytes=rx, tx_calls=0, rx_calls=rxc,
                         connections=0, start_ns=0, last_ns=0, pid=pid,
                         ifindex=0, state=0)
    return UdpFlowEntry(key=key, value=value)


class UdpChannelCollectorTests(unittest.TestCase):
    def _collector(self, group="239.239.16.2", port=1234):
        from udp_analyzer.channels import ChannelCatalog, channel_target_from_url
        target = channel_target_from_url("ffmpeg@tv-a.service", f"udp://@{group}:{port}")
        target = replace(target, addresses=(group,))   # udajemy resolve multicastu
        c = UdpChannelCollector(catalog=ChannelCatalog([target]), bucket_ms=1000,
                                attach=False, map_id=1)
        c.reader = FakeReader()
        c._unit_for_pid = lambda pid: "ffmpeg@tv-a.service" if pid == 1234 else ""
        return c

    def test_multicast_matched_from_bind_when_dst_zero(self):
        c = self._collector()
        c.reader.entries = [_mc_entry(1, 1234, rx=390000, rxc=227)]
        self.assertEqual(c.read_checkpoint(), [])           # warmup: sam baseline
        c.reader.entries = [_mc_entry(1, 1234, rx=780000, rxc=454)]
        s = c.read_checkpoint()
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0].status, "matched")            # dopasowany po BIND mimo dst==0
        self.assertEqual(s[0].channel, "ffmpeg@tv-a")
        self.assertEqual(s[0].dst_ip, "239.239.16.2")       # endpoint = grupa, nie 0.0.0.0
        self.assertEqual(s[0].dst_port, 1234)
        self.assertEqual(s[0].rx_bytes, 390000)             # delta, nie suma

    def test_ndjson_contract(self):
        c = self._collector()
        c.reader.entries = [_mc_entry(1, 1234, rx=1000, rxc=10)]
        c.read_checkpoint()
        c.reader.entries = [_mc_entry(1, 1234, rx=2000, rxc=15)]
        row = c.read_checkpoint()[0].to_dict()
        self.assertEqual(row["layer"], "udp_channel")
        self.assertEqual(row["ip_proto"], 17)
        self.assertIn("tcp_state", row)                     # nazwa klucza zachowana dla ELA
        self.assertEqual(row["tcp_state"], 0)
        self.assertEqual(row["packets"], 5)                 # rx_calls delta 10->15
        self.assertGreater(row["bytes"], 0)
        self.assertEqual(row["dst_ip"], "239.239.16.2")

    def test_counter_regression_clamps_and_survives(self):
        c = self._collector()
        c.reader.entries = [_mc_entry(1, 1234, rx=4000, rxc=20)]
        c.read_checkpoint()
        c.reader.entries = [_mc_entry(1, 1234, rx=500, rxc=2)]   # mapa przeładowana
        self.assertEqual(c.read_checkpoint(), [])               # clamp do 0, bez wyjątku
        c.reader.entries = [_mc_entry(1, 1234, rx=900, rxc=4)]
        self.assertEqual(c.read_checkpoint()[0].rx_bytes, 400)  # baseline odzyskany

    def test_unknown_unit_when_pid_not_ffmpeg(self):
        c = self._collector()
        c._unit_for_pid = lambda pid: ""                    # brak unitu (obcy proces)
        c.reader.entries = [_mc_entry(1, 999, rx=1000, rxc=10)]
        c.read_checkpoint()
        c.reader.entries = [_mc_entry(1, 999, rx=2000, rxc=20)]
        s = c.read_checkpoint()
        self.assertEqual(s[0].status, "unknown_unit")
        self.assertEqual(s[0].channel, "")


if __name__ == "__main__":
    unittest.main()
