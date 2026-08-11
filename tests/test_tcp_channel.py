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


class RecvmsgSignatureGateTests(unittest.TestCase):
    def test_pre519_signature_is_detected(self):
        from udp_analyzer.tcp_channel import kernel_tcp_recvmsg_has_nonblock

        # RAW `bpftool btf dump` format, verbatim from a live kernel: a FUNC
        # entry pointing at a FUNC_PROTO whose param names decide the answer.
        new = (
            "[53321] FUNC_PROTO '(anon)' ret_type_id=13 vlen=5\n"
            "\t'sk' type_id=700\n\t'msg' type_id=6066\n\t'len' type_id=46\n"
            "\t'flags' type_id=13\n\t'addr_len' type_id=92\n"
            "[86073] FUNC 'tcp_recvmsg' type_id=53321 linkage=static\n"
        )
        old = (
            "[53321] FUNC_PROTO '(anon)' ret_type_id=13 vlen=6\n"
            "\t'sk' type_id=700\n\t'msg' type_id=6066\n\t'len' type_id=46\n"
            "\t'nonblock' type_id=13\n\t'flags' type_id=13\n\t'addr_len' type_id=92\n"
            "[86073] FUNC 'tcp_recvmsg' type_id=53321 linkage=static\n"
        )
        self.assertIs(kernel_tcp_recvmsg_has_nonblock(btf_text=old), True)
        self.assertIs(kernel_tcp_recvmsg_has_nonblock(btf_text=new), False)
        self.assertIsNone(kernel_tcp_recvmsg_has_nonblock(btf_text="[1] INT 'int'"))


class FakeReader:
    def __init__(self):
        self.entries = []

    def dump_entries(self):
        return list(self.entries)


def _entry(cookie, pid, tx=0, rx=0, txc=0, rxc=0, conns=0):
    from udp_analyzer.tcp_channel import TcpFlowEntry, TcpFlowKey, TcpFlowValue
    key = TcpFlowKey(socket_cookie=cookie, src_ip4=0x0A00000A, dst_ip4=0x0A7100CB,
                     src_port=40000, dst_port=80, family=2, ip_proto=6,
                     cgroup_id=7)
    value = TcpFlowValue(tx_bytes=tx, rx_bytes=rx, tx_calls=txc, rx_calls=rxc,
                         connections=conns, start_ns=0, last_ns=0,
                         pid=pid, ifindex=0, state=1)
    return TcpFlowEntry(key=key, value=value)


class TcpChannelCollectorTests(unittest.TestCase):
    """The collector itself had ZERO tests before: warmup, deltas, counter
    regressions and the pid cache were all unverified."""

    def _collector(self, monkey_unit="ffmpeg@radio-a.service"):
        from udp_analyzer import tcp_channel as mod
        from udp_analyzer.channels import ChannelCatalog, channel_target_from_url

        target = channel_target_from_url("ffmpeg@radio-a.service",
                                         "http://radiostream.example/x.mp3")
        collector = mod.TcpChannelCollector(
            catalog=ChannelCatalog([target]), bucket_ms=1000,
            attach=False, map_id=1)
        collector.reader = FakeReader()
        self._units = {1234: monkey_unit}
        collector._unit_for_pid = lambda pid: self._units.get(pid, "")
        return collector

    def test_warmup_then_delta_then_regression_clamp(self):
        c = self._collector()
        c.reader.entries = [_entry(1, 1234, rx=1000, rxc=10)]
        self.assertEqual(c.read_checkpoint(), [])       # warmup: baseline only

        c.reader.entries = [_entry(1, 1234, rx=4000, rxc=20)]
        samples = c.read_checkpoint()
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].rx_bytes, 3000)     # delta, not cumulative
        self.assertEqual(samples[0].status, "matched")

        # counter REGRESSION (map reloaded): clamp to zero and survive —
        # the old code raised RuntimeError and the process died mid-run
        c.reader.entries = [_entry(1, 1234, rx=500, rxc=2)]
        self.assertEqual(c.read_checkpoint(), [])       # all deltas clamp to 0
        c.reader.entries = [_entry(1, 1234, rx=900, rxc=4)]
        samples = c.read_checkpoint()
        self.assertEqual(samples[0].rx_bytes, 400)      # baseline recovered

    def test_packets_field_reports_syscall_count_not_zero(self):
        c = self._collector()
        c.reader.entries = [_entry(1, 1234, rx=1000, rxc=10)]
        c.read_checkpoint()
        c.reader.entries = [_entry(1, 1234, rx=2000, rxc=15, txc=1, tx=10)]
        row = c.read_checkpoint()[0].to_dict()
        # downstream liveness divides packets by the interval; a hardcoded 0
        # made every TCP channel read as "not flowing" forever
        self.assertEqual(row["packets"], 6)
        self.assertGreater(row["bytes"], 0)

    def test_pid_unit_cache_is_dropped_every_checkpoint(self):
        from udp_analyzer import tcp_channel as mod
        from udp_analyzer.channels import ChannelCatalog

        c = mod.TcpChannelCollector(catalog=ChannelCatalog([]), bucket_ms=1000,
                                    attach=False, map_id=1)
        c.reader = FakeReader()
        calls = []
        mod_unit_for_pid = mod.unit_for_pid

        def counting(pid, proc_root=None):
            calls.append(pid)
            return "a.service"

        mod.unit_for_pid = counting
        try:
            c.reader.entries = [_entry(1, 99, rx=10, rxc=1)]
            c.read_checkpoint()                 # warmup: no sample, no lookup
            c.reader.entries = [_entry(1, 99, rx=20, rxc=2)]
            c.read_checkpoint()
            c.reader.entries = [_entry(1, 99, rx=30, rxc=3)]
            c.read_checkpoint()
            # pid resolved on EVERY emitting checkpoint: cache cleared per tick,
            # so pid reuse cannot inherit the previous owner's channel
            self.assertEqual(calls, [99, 99])
        finally:
            mod.unit_for_pid = mod_unit_for_pid


if __name__ == "__main__":
    unittest.main()
