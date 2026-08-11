import unittest
from pathlib import Path
from unittest import mock

from udp_analyzer.ebpf import (
    EbpfIngressCollector,
    parse_bpftool_delivered_entry,
)


def _delivered_entry(cookie, packets, bytes_):
    return {
        "key": {
            "socket_cookie": cookie,
            "src_ip4": 0x0A0200C0,
            "dst_ip4": 0x146433C6,
            "src_port": 40000,
            "dst_port": 5000,
            "family": 2,
            "ip_proto": 17,
        },
        "values": [
            {
                "cpu": 0,
                "value": {
                    "packets": packets,
                    "bytes": bytes_,
                    "socket_inode": 0,
                    "ifindex": 2,
                },
            }
        ],
    }


class _EmptyIngressReader:
    def __init__(self, runner=None):
        pass

    def refresh_map_id(self):
        return 1

    def dump_entries(self):
        return []


class _DeliveredReader:
    def __init__(self, map_id, runner=None):
        self.map_id = map_id
        self.batches = []

    def dump_entries(self):
        return [parse_bpftool_delivered_entry(row) for row in self.batches.pop(0)]


class ReceiveAttributionTests(unittest.TestCase):
    def test_same_port_and_tuple_are_separated_by_socket_cookie(self):
        delivered_reader = _DeliveredReader(map_id=77)
        with mock.patch(
            "udp_analyzer.ebpf.BpftoolMapReader", return_value=_EmptyIngressReader()
        ), mock.patch(
            "udp_analyzer.ebpf.BpftoolDeliveredMapReader",
            return_value=delivered_reader,
        ):
            collector = EbpfIngressCollector(
                ifname="eth0",
                object_path=Path("bpf/udp_ingress.bpf.o"),
                section="classifier/udp_ingress",
                pref=49152,
                bucket_ms=1000,
                attach=False,
                detach_on_close=False,
                delivery_attribution="cookie",
                receive_map_id=77,
            )

        delivered_reader.batches.append(
            [
                _delivered_entry(1001, 10, 1000),
                _delivered_entry(1002, 20, 2000),
            ]
        )
        self.assertEqual(collector.read_checkpoint(), [])

        delivered_reader.batches.append(
            [
                _delivered_entry(1001, 13, 1300),
                _delivered_entry(1002, 27, 2700),
            ]
        )
        rows = collector.read_checkpoint()

        self.assertEqual(len(rows), 2)
        self.assertEqual({row.socket_id for row in rows}, {1001, 1002})
        self.assertEqual(
            {row.socket_id: row.packets for row in rows}, {1001: 3, 1002: 7}
        )
        self.assertTrue(all(row.layer == "delivered" for row in rows))


if __name__ == "__main__":
    unittest.main()
