import os
import tempfile
import unittest
from pathlib import Path

from udp_analyzer.models import UdpSample
from udp_analyzer.processes import (
    ProcessSocketEnricher,
    ProcessSocketInventory,
    parse_proc_address,
    parse_proc_net_udp,
)


PROC_NET_UDP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   7: 00000000:1388 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 424242 2 0000000000000000 0
"""


class ProcessParserTests(unittest.TestCase):
    def test_parse_proc_address_ipv4(self):
        self.assertEqual(parse_proc_address("0A0200C0:1388"), ("192.0.2.10", 5000))

    def test_parse_proc_net_udp(self):
        rows = parse_proc_net_udp(PROC_NET_UDP)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].local_ip, "0.0.0.0")
        self.assertEqual(rows[0].local_port, 5000)
        self.assertEqual(rows[0].socket_inode, 424242)

    def test_inventory_and_enricher_use_process_socket_inode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_root = Path(temp_dir)
            pid_root = proc_root / "123"
            (pid_root / "fd").mkdir(parents=True)
            (pid_root / "net").mkdir()
            (pid_root / "ns").mkdir()
            (pid_root / "comm").write_text("ffmpeg\n", encoding="utf-8")
            (pid_root / "cmdline").write_text(
                "ffmpeg\x00-i\x00udp://0.0.0.0:5000\x00", encoding="utf-8"
            )
            (pid_root / "status").write_text("NSpid:\t123\t7\n", encoding="utf-8")
            (pid_root / "cgroup").write_text(
                "0::/docker/"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                encoding="utf-8",
            )
            (pid_root / "net" / "udp").write_text(PROC_NET_UDP, encoding="utf-8")
            (pid_root / "net" / "udp6").write_text("", encoding="utf-8")
            os.symlink("socket:[424242]", pid_root / "fd" / "3")

            inventory = ProcessSocketInventory(proc_root=proc_root)
            sockets = inventory.scan(process_name="ffmpeg")

            self.assertEqual(len(sockets), 1)
            self.assertEqual(sockets[0].host_pid, 123)
            self.assertEqual(sockets[0].container_pid, 7)
            self.assertEqual(sockets[0].container_id, "a" * 64)

            sample = UdpSample(
                bucket_start_ns=1_000_000_000,
                bucket_ms=1000,
                src_ip="192.0.2.10",
                dst_ip="198.51.100.20",
                src_port=40000,
                dst_port=5000,
                ifindex=2,
                ifname="eth0",
                packets=1,
                bytes=1316,
            )
            enricher = ProcessSocketEnricher(process_name="ffmpeg", proc_root=proc_root)

            enriched = enricher.enrich(sample)

            self.assertEqual(len(enriched), 2)
            self.assertEqual(enriched[1].layer, "delivered")
            self.assertEqual(enriched[1].process_name, "ffmpeg")
            self.assertEqual(enriched[1].host_pid, 123)
            self.assertEqual(enriched[1].socket_id, 424242)

            exact_sample = UdpSample(
                bucket_start_ns=1_000_000_000,
                bucket_ms=1000,
                src_ip="192.0.2.10",
                dst_ip="198.51.100.20",
                src_port=40000,
                dst_port=5999,
                ifindex=2,
                ifname="eth0",
                packets=1,
                bytes=1316,
                layer="delivered",
            )
            exact = enricher.enrich_exact(
                exact_sample,
                socket_inode=424242,
                socket_cookie=0x123456789ABCDEF0,
            )

            self.assertEqual(len(exact), 1)
            self.assertEqual(exact[0].process_name, "ffmpeg")
            self.assertEqual(exact[0].host_pid, 123)
            self.assertEqual(exact[0].dst_port, 5999)
            self.assertEqual(exact[0].socket_id, 0x123456789ABCDEF0)


if __name__ == "__main__":
    unittest.main()
