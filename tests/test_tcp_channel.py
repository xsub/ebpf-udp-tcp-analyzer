import struct
import unittest

from udp_analyzer.tcp_channel import (
    parse_tcp_channel_loader_status,
    parse_tcp_flow_entry,
    parse_tcp_flow_key,
    unit_from_cgroup_text,
)


class TcpChannelTests(unittest.TestCase):
    def test_parse_raw_tcp_flow_key(self):
        encoded = struct.pack(
            "<QIIHHBB2xQ",
            0x123456789ABCDEF0,
            0x0A00000A,
            0x0A7100CB,
            40000,
            443,
            2,
            6,
            12345,
        )
        raw_key = [f"0x{byte:02x}" for byte in encoded]

        parsed = parse_tcp_flow_key(raw_key)

        self.assertEqual(parsed.socket_cookie, 0x123456789ABCDEF0)
        self.assertEqual(parsed.src_ip, "10.0.0.10")
        self.assertEqual(parsed.dst_ip, "203.0.113.10")
        self.assertEqual(parsed.src_port, 40000)
        self.assertEqual(parsed.dst_port, 443)
        self.assertEqual(parsed.cgroup_id, 12345)

    def test_parse_tcp_flow_entry_sums_per_cpu_counters(self):
        entry = {
            "key": {
                "socket_cookie": 1234,
                "src_ip4": 0x0A00000A,
                "dst_ip4": 0x0A7100CB,
                "src_port": 40000,
                "dst_port": 443,
                "family": 2,
                "ip_proto": 6,
                "cgroup_id": 12345,
            },
            "values": [
                {
                    "cpu": 0,
                    "value": {
                        "tx_bytes": 100,
                        "rx_bytes": 1000,
                        "tx_calls": 1,
                        "rx_calls": 4,
                        "connections": 1,
                        "start_ns": 10,
                        "last_ns": 20,
                        "pid": 4242,
                        "ifindex": 2,
                        "state": 1,
                    },
                },
                {
                    "cpu": 1,
                    "value": {
                        "tx_bytes": 200,
                        "rx_bytes": 3000,
                        "tx_calls": 2,
                        "rx_calls": 6,
                        "connections": 0,
                        "start_ns": 11,
                        "last_ns": 30,
                        "pid": 4242,
                        "ifindex": 2,
                        "state": 1,
                    },
                },
            ],
        }

        parsed = parse_tcp_flow_entry(entry)

        self.assertEqual(parsed.value.tx_bytes, 300)
        self.assertEqual(parsed.value.rx_bytes, 4000)
        self.assertEqual(parsed.value.tx_calls, 3)
        self.assertEqual(parsed.value.rx_calls, 10)
        self.assertEqual(parsed.value.connections, 1)
        self.assertEqual(parsed.value.start_ns, 10)
        self.assertEqual(parsed.value.last_ns, 30)

    def test_rejects_non_tcp_key(self):
        with self.assertRaisesRegex(RuntimeError, "non-IPv4-TCP"):
            parse_tcp_flow_key(
                {
                    "socket_cookie": 1234,
                    "src_ip4": 0x0A00000A,
                    "dst_ip4": 0x0A7100CB,
                    "src_port": 40000,
                    "dst_port": 443,
                    "family": 2,
                    "ip_proto": 17,
                    "cgroup_id": 12345,
                }
            )

    def test_loader_status_accepts_positive_map_id(self):
        status = parse_tcp_channel_loader_status('{"map_id":77}')

        self.assertEqual(status.map_id, 77)
        with self.assertRaises(RuntimeError):
            parse_tcp_channel_loader_status('{"map_id":0}')

    def test_unit_from_user_cgroup_path_uses_leaf_service(self):
        text = (
            "0::/user.slice/user-1000.slice/user@1000.service/"
            "app.slice/channel-a.service\n"
        )

        self.assertEqual(unit_from_cgroup_text(text), "channel-a.service")


if __name__ == "__main__":
    unittest.main()
