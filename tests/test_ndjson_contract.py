"""Producer-side NDJSON contract for TCP channel rows.

The primary consumer (the ELA edge agent) parses each row and derives a
liveness rate from packets/interval, attributes by host_pid, and buckets by
bucket_start_ns/bucket_ms. This test pins exactly the fields that consumer
reads, so a rename or a hardcoded zero fails HERE instead of surfacing as
"every radio channel is not flowing" on a production dashboard — which is
precisely the bug this contract was written after.
"""
import unittest

from udp_analyzer.tcp_channel import ChannelTcpSample


class NdjsonContractTests(unittest.TestCase):
    def test_tcp_row_carries_the_fields_consumers_rate_on(self):
        row = ChannelTcpSample(
            bucket_start_ns=1_700_000_000_000_000_000,
            bucket_ms=1000,
            src_ip="10.0.0.10",
            dst_ip="203.0.113.10",
            src_port=40000,
            dst_port=80,
            socket_id=7,
            cgroup_id=9,
            tx_bytes=120,
            rx_bytes=17_000,
            tx_calls=2,
            rx_calls=11,
            connections=0,
            unit="ffmpeg@radio-a.service",
            channel="radio-a",
            host_pid=4242,
        ).to_dict()

        # identity + bucketing the consumer joins on
        self.assertEqual(row["dst_ip"], "203.0.113.10")
        self.assertIsInstance(row["dst_port"], int)
        self.assertEqual(row["bucket_start_ns"], 1_700_000_000_000_000_000)
        self.assertEqual(row["bucket_ms"], 1000)
        self.assertEqual(row["host_pid"], 4242)
        self.assertEqual(row["layer"], "tcp_channel")
        # volume + liveness: bytes for bitrate, packets for the flow-rate check.
        # packets MUST be positive while traffic moves — a hardcoded 0 reads as
        # "stream never flowing" downstream even with bytes climbing.
        self.assertEqual(row["bytes"], 17_120)
        self.assertEqual(row["packets"], 13)
        self.assertGreater(row["packets"], 0)


if __name__ == "__main__":
    unittest.main()
