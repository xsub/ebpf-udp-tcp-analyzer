import struct
import unittest

from udp_analyzer.ebpf import (
    ipv4_from_bpf_int,
    parse_bpftool_delivered_entry,
    parse_bpftool_delivered_key,
    parse_bpftool_entry,
    parse_bpftool_key,
    parse_receive_loader_status,
)


class EbpfParserTests(unittest.TestCase):
    def test_parse_pretty_bpftool_entry_sums_per_cpu_values(self):
        entry = {
            "key": {
                "family": 2,
                "ip_proto": 17,
                "src_port": 40000,
                "dst_port": 5000,
                "ifindex": 2,
                "src_ip4": 0x0A0200C0,
                "dst_ip4": 0x146433C6,
            },
            "values": [
                {"cpu": 0, "value": {"packets": 5, "bytes": 500}},
                {"cpu": 1, "value": {"packets": 7, "bytes": 700}},
            ],
        }

        parsed = parse_bpftool_entry(entry)

        self.assertEqual(parsed.key.src_ip, "192.0.2.10")
        self.assertEqual(parsed.key.dst_ip, "198.51.100.20")
        self.assertEqual(parsed.key.src_port, 40000)
        self.assertEqual(parsed.key.dst_port, 5000)
        self.assertEqual(parsed.counters.packets, 12)
        self.assertEqual(parsed.counters.bytes, 1200)

    def test_parse_raw_bpftool_key(self):
        raw_key = [
            "0x02",
            "0x11",
            "0x40",
            "0x9c",
            "0x88",
            "0x13",
            "0x00",
            "0x00",
            "0x02",
            "0x00",
            "0x00",
            "0x00",
            "0xc0",
            "0x00",
            "0x02",
            "0x0a",
            "0xc6",
            "0x33",
            "0x64",
            "0x14",
        ]

        parsed = parse_bpftool_key(raw_key)

        self.assertEqual(parsed.family, 2)
        self.assertEqual(parsed.ip_proto, 17)
        self.assertEqual(parsed.src_port, 40000)
        self.assertEqual(parsed.dst_port, 5000)
        self.assertEqual(parsed.ifindex, 2)
        self.assertEqual(parsed.src_ip, "192.0.2.10")
        self.assertEqual(parsed.dst_ip, "198.51.100.20")

    def test_ipv4_from_bpf_int_uses_packet_byte_order(self):
        self.assertEqual(ipv4_from_bpf_int(0x0A0200C0), "192.0.2.10")

    def test_parse_delivered_entry_sums_cpus_and_keeps_socket_metadata(self):
        entry = {
            "key": {
                "socket_cookie": 0x123456789ABCDEF0,
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
                        "packets": 5,
                        "bytes": 500,
                        "socket_inode": 424242,
                        "ifindex": 2,
                    },
                },
                {
                    "cpu": 1,
                    "value": {
                        "packets": 7,
                        "bytes": 700,
                        "socket_inode": 424242,
                        "ifindex": 2,
                    },
                },
            ],
        }

        parsed = parse_bpftool_delivered_entry(entry)

        self.assertEqual(parsed.key.socket_cookie, 0x123456789ABCDEF0)
        self.assertEqual(parsed.key.src_ip, "192.0.2.10")
        self.assertEqual(parsed.key.dst_ip, "198.51.100.20")
        self.assertEqual(parsed.value.packets, 12)
        self.assertEqual(parsed.value.bytes, 1200)
        self.assertEqual(parsed.value.socket_inode, 424242)
        self.assertEqual(parsed.value.ifindex, 2)

    def test_parse_raw_delivered_key(self):
        encoded = struct.pack(
            "<QIIHHBB2x",
            0x123456789ABCDEF0,
            0x0A0200C0,
            0x146433C6,
            40000,
            5000,
            2,
            17,
        )
        raw_key = [f"0x{byte:02x}" for byte in encoded]

        parsed = parse_bpftool_delivered_key(raw_key)

        self.assertEqual(parsed.socket_cookie, 0x123456789ABCDEF0)
        self.assertEqual(parsed.src_port, 40000)
        self.assertEqual(parsed.dst_port, 5000)
        self.assertEqual(parsed.src_ip, "192.0.2.10")
        self.assertEqual(parsed.dst_ip, "198.51.100.20")

    def test_receive_loader_status_accepts_only_real_backends(self):
        status = parse_receive_loader_status('{"backend":"kprobe","map_id":77}')

        self.assertEqual(status.backend, "kprobe")
        self.assertEqual(status.map_id, 77)
        with self.assertRaises(RuntimeError):
            parse_receive_loader_status('{"backend":"legacy","map_id":77}')


if __name__ == "__main__":
    unittest.main()
